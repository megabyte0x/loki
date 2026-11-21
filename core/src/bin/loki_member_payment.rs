//! CLI bridge from separately created vaults to the FROST signing session.
//! The shared directory is a local test courier; it is not a wallet relay or durable inbox.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

#[cfg(feature = "relay-communication")]
use loki_poc::signing_session::{NonceWitness, ReviewedPackage, WitnessPins};
use loki_poc::tx_finalize::finalized_sighash;
use loki_poc::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs},
    intent::{ChangePolicy, Intent},
    member_state::{self, MemberState, Roster},
    network::VaultNetwork,
    payment_manifest::{validate_roster, MAX_INPUTS},
    rpc::Rpc,
    scan,
    state::MemberDir,
    wallet_store::{lightwalletd_url, sync_member_wallet, VaultWallet},
    signing_session::{
        aggregate_and_apply, commitments_from_message, AttemptId, Mailbox, MessageKind,
        OpenedMessage, PackagePayload, SessionContext, SigningSession,
    },
    vault,
};
#[cfg(feature = "relay-communication")]
use loki_relay_client::{ClientStore, OwnerInbox, RelayHttp, RelayRuntime};
use incrementalmerkletree::frontier::NonEmptyFrontier;
use orchard::{keys::Scope, tree::MerkleHashOrchard, Address};
use reddsa_frost::frost::redpallas as frost;
use serde_json::json;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use zcash_client_backend::proto::service::{BlockId, Empty, RawTransaction, TxFilter};
use zcash_primitives::transaction::TxId;
use zcash_client_backend::wallet::LockOwner;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{consensus::Parameters, memo::MemoBytes, value::Zatoshis};
use zeroize::{Zeroize, Zeroizing};

fn signer_set_from_name(name: &str, threshold: u16) -> Result<Vec<u16>, String> {
    let signers = name.bytes().map(|label| match label {
        // Members 1 to 16 are letters A to P.
        b'A'..=b'P' => Ok(u16::from(label - b'A' + 1)),
        _ => Err("signer set must use member letters A through P".to_owned()),
    }).collect::<Result<Vec<_>, _>>()?;
    if signers.len() != usize::from(threshold) || signers.windows(2).any(|ids| ids[0] >= ids[1]) {
        return Err("select exactly the vault threshold in member order".into());
    }
    Ok(signers)
}

fn private_work(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| e.to_string())?;
        if fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("payment work directory must be owner-only (mode 0700)".into());
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    Ok(())
}

fn manifest(path: &Path, network: VaultNetwork) -> Result<(SessionContext, Intent), String> {
    loki_poc::payment_manifest::parse_for_network(
        &fs::read(path).map_err(|e| e.to_string())?,
        network,
    )
}

fn member_rpc(member: &MemberState) -> Result<Rpc, String> {
    match member.network {
        VaultNetwork::Regtest => Ok(Rpc::regtest()),
        VaultNetwork::Testnet => Rpc::testnet(),
    }
}

/// This member's wallet, first synced from lightwalletd when one is configured.
fn wallet(member: &MemberState, owner: &Path, pass: &str) -> Result<VaultWallet, String> {
    match lightwalletd_url(member.network) {
        Some(url) => Ok(runtime()?.block_on(sync_member_wallet(member, owner, pass, &url))?.0),
        None => VaultWallet::open_existing(
            &owner.join("wallet.sqlite"), member.network, &member.fvk, member.wallet_birth(), pass,
        ),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("start lightwalletd client: {e}"))
}

/// The wallet scan at the node's tip, checked against the node's own tree and block hash.
fn synced_wallet(
    member: &MemberState, owner: &Path, pass: &str, rpc: &Rpc,
) -> Result<(VaultWallet, u32, NonEmptyFrontier<MerkleHashOrchard>), String> {
    let wallet = wallet(member, owner, pass)?;
    let height = wallet.scanned_height()?.ok_or("wallet has not scanned any blocks")?;
    if rpc.json("getblockcount", "[]")?.as_u64() != Some(u64::from(height)) {
        return Err("wallet scan is behind the node; run loki_wallet_sync again".into());
    }
    let saved_hash = wallet.scanned_hash(BlockHeight::from_u32(height))?;
    let state = rpc.json("z_gettreestate", &format!("[\"{height}\"]"))?;
    let bytes = hex::decode(state["ironwood"]["commitments"]["finalState"]
        .as_str().ok_or("node has no Ironwood tree state")?)
        .map_err(|e| format!("Ironwood tree state: {e}"))?;
    let mut encoded = std::io::Cursor::new(&bytes);
    let tree = zcash_primitives::merkle_tree::read_commitment_tree::<MerkleHashOrchard, _, 32>(
        &mut encoded,
    ).map_err(|e| format!("Ironwood tree state: {e}"))?;
    if encoded.position() != bytes.len() as u64 {
        return Err("Ironwood tree state has trailing bytes".into());
    }
    let frontier = tree.to_frontier().value().cloned()
        .ok_or("scanned Ironwood tree is empty")?;
    let anchor = tree.root().to_bytes();
    if let Some(root) = state["ironwood"]["commitments"]["finalRoot"].as_str() {
        if hex::decode(root).ok().as_deref() != Some(&anchor) {
            return Err("node Ironwood tree disagrees with its anchor".into());
        }
    }
    if rpc.json("getblockhash", &format!("[{height}]"))?.as_str()
        != Some(saved_hash.as_str()) {
        return Err("wallet scan is on a different chain; run loki_wallet_sync again".into());
    }
    Ok((wallet, height, frontier))
}

fn check_manifest_roster(
    roster: &Roster,
    context: &SessionContext,
    intent: &Intent,
) -> Result<(), String> {
    if roster
        .birth_height
        .is_some_and(|birth| intent.created_height < birth)
    {
        return Err("payment predates the certified vault birth height".into());
    }
    validate_roster(
        roster.vault,
        roster.threshold,
        roster.members.keys().copied(),
        context,
        intent,
    )
}

fn state(args: &[String]) -> Result<(MemberState, PathBuf, Zeroizing<String>), String> {
    if args.len() < 4 {
        return Err("expected <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let owner = PathBuf::from(&args[0]);
    let loaded = member_state::open(&owner, Path::new(&args[1]), Path::new(&args[2]))?;
    let mut pass = fs::read_to_string(&args[1]).map_err(|e| e.to_string())?;
    let trimmed = Zeroizing::new(pass.trim_end_matches(['\r', '\n']).to_string());
    pass.zeroize();
    Ok((loaded, owner, trimmed))
}

fn own_wire_hashes(
    identity: &loki_poc::setup_transport::Identity,
    roster: &BTreeMap<u16, loki_poc::setup_transport::PublicIdentity>,
    context: &SessionContext,
    mailbox: &Path,
) -> Result<Vec<String>, String> {
    if roster.get(&identity.public().id) != Some(&identity.public()) {
        return Err("local identity differs from certified roster".into());
    }
    if !mailbox.exists() {
        return Ok(Vec::new());
    }
    let mut hashes = Vec::new();
    for entry in fs::read_dir(mailbox).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() != 64 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        if entry.metadata().map_err(|e| e.to_string())?.len() > 8 * 1024 * 1024 + 53 {
            continue;
        }
        let wire = fs::read(entry.path()).map_err(|e| e.to_string())?;
        if hex::encode(blake3::hash(&wire).as_bytes()) != name {
            continue;
        }
        if roster
            .values()
            .filter(|peer| peer.id != identity.public().id)
            .any(|peer| identity.open_sent_session(peer, context, &wire).is_ok())
        {
            hashes.push(name.to_owned());
        }
    }
    hashes.sort();
    Ok(hashes)
}

fn local_wires(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("local-wires <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, _, _) = state(args)?;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    let wires = own_wire_hashes(
        &member.identity,
        &member.roster.members,
        &context,
        &work.join("mailbox"),
    )?;
    println!("{}", json!({"wires": wires}));
    Ok(())
}

fn balance(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("balance <member-dir> <passphrase-file> <roster.json>".into());
    }
    let member = member_state::open(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )?;
    let pass = Zeroizing::new(fs::read_to_string(&args[1]).map_err(|e| e.to_string())?);
    let mut wallet = wallet(&member, Path::new(&args[0]), pass.trim_end_matches(['\r', '\n']))?;
    let height = wallet.scanned_height()?.ok_or("wallet has not scanned any blocks")?;
    println!(
        "{}",
        json!({"vault": hex::encode(member.vault), "network": member.network.label(),
               "height": height, "balance_zat": wallet.ironwood_balance_zat()?,
               "unspent_notes": wallet.ironwood_note_count(BlockHeight::from_u32(height))?,
               "max_spendable_zat": wallet.max_spendable(MAX_INPUTS)})
    );
    Ok(())
}

fn prepare(args: &[String], sweep: bool) -> Result<(), String> {
    if (sweep && args.len() != 6 && args.len() != 7)
        || (!sweep && args.len() != 7 && args.len() != 8)
    {
        return Err(if sweep {
            "prepare-sweep <member-dir> <passphrase-file> <roster.json> <work-dir> <recipient-UA> <memo> [selected member letters, e.g. AC or BCD]".into()
        } else {
            "prepare <member-dir> <passphrase-file> <roster.json> <work-dir> <recipient-UA> <amount-zat> <memo> [selected member letters, e.g. AC or BCD]".into()
        });
    }
    let (member, owner, pass) = state(args)?;
    let default = if member.roster.threshold == 2 { "AB" } else { "ABC" };
    let signers = signer_set_from_name(
        args.get(if sweep { 6 } else { 7 })
            .map(String::as_str)
            .unwrap_or(default),
        member.roster.threshold,
    )?;
    if signers
        .iter()
        .any(|id| !member.roster.members.contains_key(id))
    {
        return Err("payment signer set includes a member outside this vault".into());
    }
    let work = Path::new(&args[3]);
    private_work(work)?;
    let rpc = member_rpc(&member)?;
    let (mut wallet, tip, _) = synced_wallet(&member, &owner, &pass, &rpc)?;
    let recipient = vault::orchard_receiver_from_ua(&args[4], member.network.network_type())?;
    let memo_text = &args[if sweep { 5 } else { 6 }];
    let memo = MemoBytes::from_bytes(memo_text.as_bytes()).map_err(|e| format!("memo: {e:?}"))?;
    if memo_text.is_empty() {
        return Err("memo must be nonempty".into());
    }
    let expiry = tip
        .checked_add(match member.network {
            VaultNetwork::Regtest => 8_064,
            VaultNetwork::Testnet => 24_192, // roughly one week at Testnet's 25-second blocks
        })
        .ok_or("expiry overflow")?
        .div_ceil(1_152)
        .checked_mul(1_152)
        .ok_or("expiry overflow")?;
    let amount = if sweep {
        None
    } else {
        let amount_zat: u64 = args[5].parse().map_err(|_| "invalid amount")?;
        if amount_zat == 0 {
            return Err("amount must exceed zero".into());
        }
        Some(Zatoshis::from_u64(amount_zat).map_err(|e| format!("amount: {e:?}"))?)
    };
    let funding = wallet.propose(recipient, amount, memo)?;
    if funding.notes.len() > MAX_INPUTS {
        return Err(format!(
            "this payment needs {} vault notes, but one payment can spend at most {MAX_INPUTS}; send a smaller amount first",
            funding.notes.len()
        ));
    }
    let (amount_zat, fee_zat, change_zat) = (funding.amount_zat, funding.fee_zat, funding.change_zat);
    let intent = Intent {
        proposer: member.key.identifier().serialize(),
        created_height: tip,
        input_nullifiers: funding.notes.iter().map(|note| note.nullifier(&member.fvk).to_bytes()).collect(),
        recipient: recipient.to_raw_address_bytes().to_vec(),
        amount_zat,
        memo: memo_text.as_bytes().to_vec(),
        change_policy: ChangePolicy::VaultInternal,
        fee_zat,
        change_zat,
        expiry_height: expiry,
    };
    let payment = intent.proposal_id();
    let attempt = AttemptId::random();
    let mut value = json!({
        "version": if signers.len() == 2 { 1 } else { 2 }, "network": member.network.label(), "vault": hex::encode(member.vault),
        "payment": hex::encode(payment), "attempt": hex::encode(attempt.0),
        "proposer": hex::encode(&intent.proposer), "created_height": tip,
        "input_nullifiers": intent.input_nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
        "recipient": hex::encode(&intent.recipient), "amount_zat": amount_zat,
        "memo": hex::encode(&intent.memo), "change_policy": "vault_internal",
        "fee_zat": fee_zat, "change_zat": change_zat, "expiry_height": expiry
    });
    if signers.len() == 2 { value["pair"] = json!(signers); }
    else { value["signers"] = json!(signers); }
    let target = work.join("payment.json");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&target)
        .map_err(|e| format!("{}: {e}", target.display()))?;
    // Hold the inputs for this attempt so this member's next draft funds itself elsewhere.
    // Only a saved manifest can release them later, so undo both if either step fails.
    let owner = LockOwner::new(attempt.0);
    let saved = wallet
        .reserve_inputs(owner, &intent.input_nullifiers, expiry)
        .and_then(|()| {
            file.write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| {
                    let _ = wallet.release_inputs(owner, &intent.input_nullifiers);
                    format!("{}: {e}", target.display())
                })
        });
    if let Err(e) = saved {
        let _ = fs::remove_file(&target);
        return Err(e);
    }
    println!(
        "payment={} attempt={} inputs={} amount={} fee={} change={}",
        hex::encode(payment),
        hex::encode(attempt.0),
        intent.input_nullifiers.len(),
        amount_zat,
        fee_zat,
        change_zat
    );
    Ok(())
}

fn wait_message(
    mailbox: &Mailbox,
    member: &MemberState,
    context: &SessionContext,
    kind: MessageKind,
    sender: u16,
) -> Result<OpenedMessage, String> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(message) = mailbox
            .read_for(&member.identity, &member.roster.members, context)?
            .into_iter()
            .find(|message| message.kind() == kind && message.sender() == sender)
        {
            return Ok(message);
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for member {sender} {kind:?}"));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn candidate(
    member: &MemberState,
    owner: &Path,
    pass: &str,
    intent: &Intent,
    session: &SigningSession,
    context: &SessionContext,
    peers: &BTreeMap<u16, Vec<frost::round1::SigningCommitments>>,
) -> Result<PackagePayload, String> {
    let own = member.identity.public().id;
    if peers.keys().copied().collect::<Vec<_>>() != context.signers.iter().copied()
        .filter(|id| *id != own).collect::<Vec<_>>()
        || peers.values().any(|commitments| commitments.len() != session.commitments().len())
    {
        return Err("candidate needs one commitment batch from each selected peer".into());
    }
    let rpc = member_rpc(member)?;
    let (wallet, height, frontier) = synced_wallet(member, owner, pass, &rpc)?;
    let notes = wallet
        .ironwood_inputs_at(BlockHeight::from_u32(height), frontier, &intent.input_nullifiers)?
        .into_iter()
        .map(|(note, _)| note)
        .collect();
    let recipient = Address::from_raw_address_bytes(&intent.recipient.clone().try_into().unwrap())
        .into_option()
        .ok_or("invalid recipient")?;
    let inputs = CandidateInputs {
        vault_fvk: &member.fvk,
        notes,
        recipient,
        amount: Zatoshis::from_u64(intent.amount_zat).map_err(|e| format!("amount: {e:?}"))?,
        memo: MemoBytes::from_bytes(&intent.memo).map_err(|e| format!("memo: {e:?}"))?,
        change: Zatoshis::from_u64(intent.change_zat).map_err(|e| format!("change: {e:?}"))?,
        target_height: intent.created_height,
        expiry_height: intent.expiry_height,
    };
    if u64::from(quote_fee(&member.network, &inputs)?) != intent.fee_zat {
        return Err("ZIP 317 fee differs from approved intent".into());
    }
    let mut sets = Vec::new();
    let mut seeds = Vec::new();
    let mut alphas = Vec::new();
    for (index, own_commitment) in session.commitments().iter().enumerate() {
        let set = context.signers.iter().map(|id| {
            let commitment = if *id == own { own_commitment.clone() } else { peers[id][index].clone() };
            Ok((frost::Identifier::try_from(*id).map_err(|e| e.to_string())?, commitment))
        }).collect::<Result<BTreeMap<_, _>, String>>()?;
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            member.public.verifying_key(),
            &set,
            rand_core::OsRng,
        )
        .map_err(|e| format!("randomizer: {e}"))?;
        let bytes: [u8; 32] = params
            .randomizer()
            .serialize()
            .try_into()
            .map_err(|_| "alpha length")?;
        alphas.push(alpha_from_canonical_bytes(&bytes).ok_or("noncanonical alpha")?);
        seeds.push(seed.try_into().map_err(|_| "seed length")?);
        sets.push(set);
    }
    let built = build_candidate(
        &member.network,
        &inputs,
        &alphas,
        rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
    )?;
    let pczt =
        pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).ok_or("create PCZT")?;
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| format!("IO finalizer: {e:?}"))?;
    Ok(PackagePayload {
        candidate: pczt.serialize().map_err(|e| format!("serialize: {e:?}"))?,
        commitments: sets,
        seeds,
    })
}

fn confirm(
    intent: &Intent,
    summary: &loki_poc::signing_session::ReviewSummary,
    network: VaultNetwork,
) -> Result<(), String> {
    if summary.payment != intent.proposal_id()
        || summary.input_nullifiers != intent.input_nullifiers
    {
        return Err("review summary differs from local intent".into());
    }
    println!("Vault: {}", hex::encode(summary.vault));
    println!(
        "Recipient: {}",
        vault::unified_receiver(summary.recipient, network.network_type())
    );
    let memo = std::str::from_utf8(&summary.memo).map_err(|_| "memo is not UTF-8")?;
    println!("Amount: {} zat; memo: {memo:?}", summary.amount_zat);
    println!(
        "Fee: {} zat; change to vault: {} zat; expiry height: {}",
        summary.fee_zat, summary.change_zat, summary.expiry_height
    );
    println!(
        "Inputs: {}; candidate: {}",
        summary.input_nullifiers.len(),
        hex::encode(summary.candidate_hash)
    );
    println!("Type APPROVE {} to sign:", hex::encode(summary.payment));
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.trim() != format!("APPROVE {}", hex::encode(summary.payment)) {
        return Err("approval declined or did not match payment ID".into());
    }
    Ok(())
}

fn sign(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("sign <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, owner, pass) = state(args)?;
    let own = member.identity.public().id;
    let (context, intent) = manifest(&Path::new(&args[3]).join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    if !context.signers.contains(&own) {
        return Err("member is not in the selected signer set".into());
    }
    let peer_id = if own == context.signers[0] { context.signers[1] } else { context.signers[0] };
    let peer = member
        .roster
        .members
        .get(&peer_id)
        .ok_or("payment signer outside vault")?
        .clone();
    let finishers = member
        .roster
        .members
        .values()
        .filter(|person| person.id != own && person.id != peer_id)
        .cloned()
        .collect::<Vec<_>>();
    if !matches!(finishers.len(), 1 | 2) {
        return Err("payment roster has no supported finisher set".into());
    }
    private_work(Path::new(&args[3]))?;
    let mailbox = Mailbox::new(&Path::new(&args[3]).join("mailbox")).map_err(|e| e.to_string())?;
    let session_identity =
        loki_poc::setup_transport::Identity::from_secret_bytes(&member.identity.to_secret_bytes())?;
    let mut session = SigningSession::begin(
        &owner.join("signing"),
        context.clone(),
        &member.vault,
        intent.clone(),
        session_identity,
        member.key.clone(),
        member.public.clone(),
        member.fvk.clone(),
        intent.input_nullifiers.len(),
    )?;
    for &id in context.signers.iter().filter(|id| **id != own) {
        session.publish_commitments(&member.roster.members[&id], &mailbox)?;
    }
    let package_message = if own == context.signers[0] {
        let mut peers = BTreeMap::new();
        for &id in context.signers.iter().filter(|id| **id != own) {
            let commitment = wait_message(&mailbox, &member, &context, MessageKind::Commitment, id)?;
            peers.insert(id, commitments_from_message(&context, &commitment, intent.input_nullifiers.len())?);
        }
        let payload = candidate(&member, &owner, &pass, &intent, &session, &context, &peers)?;
        session.publish_package_to_roster(&member.roster.members, &payload, &mailbox, &pass)?;
        let wires =
            SigningSession::saved_package_wires(&owner.join("signing"), &context, own, &pass)?;
        member
            .identity
            .open_sent_session(&peer, &context, &wires[0])?
    } else {
        wait_message(
            &mailbox,
            &member,
            &context,
            MessageKind::Package,
            context.signers[0],
        )?
    };
    let reviewed = session.review_package(&package_message, &peer)?;
    confirm(&intent, reviewed.summary(), member.network)?;
    session.publish_approved(reviewed, &peer, &finishers, &mailbox, &pass)?;
    println!(
        "approved payment {} as member {}",
        hex::encode(context.payment),
        own
    );
    Ok(())
}

#[cfg(feature = "relay-communication")]
fn signing_inputs(
    args: &[String],
) -> Result<
    (
        MemberState,
        PathBuf,
        Zeroizing<String>,
        SessionContext,
        Intent,
        Mailbox,
    ),
    String,
> {
    if args.len() != 4 {
        return Err("<member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, owner, pass) = state(args)?;
    let (context, intent) = manifest(&Path::new(&args[3]).join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    if !context.signers.contains(&member.identity.public().id) {
        return Err("member is not an approver for this payment".into());
    }
    private_work(Path::new(&args[3]))?;
    let mailbox = Mailbox::new(&Path::new(&args[3]).join("mailbox")).map_err(|e| e.to_string())?;
    Ok((member, owner, pass, context, intent, mailbox))
}

#[cfg(feature = "relay-communication")]
fn commit(args: &[String]) -> Result<(), String> {
    let (member, owner, pass, context, intent, mailbox) = signing_inputs(args)?;
    let own = member.identity.public().id;
    let identity =
        loki_poc::setup_transport::Identity::from_secret_bytes(&member.identity.to_secret_bytes())?;
    let relays = two_relays(args, None)?;
    let session = SigningSession::begin_sealed(
        &owner.join("signing"),
        context.clone(),
        &member.vault,
        intent.clone(),
        identity,
        member.key.clone(),
        member.public.clone(),
        member.fvk.clone(),
        intent.input_nullifiers.len(),
        &pass,
        relays.pins(),
    )?;
    for &peer in context.signers.iter().filter(|id| **id != own) {
        session.publish_commitments(&member.roster.members[&peer], &mailbox)?;
    }
    println!(
        "commitments published for payment {}; approval pending",
        hex::encode(context.payment)
    );
    Ok(())
}

#[cfg(feature = "relay-communication")]
fn reopen_signer(
    member: &MemberState, owner: &Path, pass: &str, context: &SessionContext, intent: &Intent,
) -> Result<SigningSession, String> {
    let identity =
        loki_poc::setup_transport::Identity::from_secret_bytes(&member.identity.to_secret_bytes())?;
    SigningSession::reopen_sealed(
        &owner.join("signing"),
        context.clone(),
        &member.vault,
        intent.clone(),
        identity,
        member.key.clone(),
        member.public.clone(),
        member.fvk.clone(),
        pass,
    )
}

fn next_message(
    mailbox: &Mailbox,
    member: &MemberState,
    context: &SessionContext,
    kind: MessageKind,
    sender: u16,
) -> Result<OpenedMessage, String> {
    mailbox
        .read_for(&member.identity, &member.roster.members, context)?
        .into_iter()
        .find(|message| message.kind() == kind && message.sender() == sender)
        .ok_or_else(|| format!("waiting for member {sender} {kind:?}; sync relay inbox and retry"))
}

#[cfg(feature = "relay-communication")]
fn package(args: &[String]) -> Result<(), String> {
    let (member, owner, pass, context, intent, mailbox) = signing_inputs(args)?;
    let own = member.identity.public().id;
    if own != context.signers[0] {
        return Err("only the selected proposer builds this package".into());
    }
    if SigningSession::republish_saved_package(&owner.join("signing"), &context, own, &pass, &mailbox)? {
        println!("payment package published; members may review");
        return Ok(());
    }
    let session = reopen_signer(&member, &owner, &pass, &context, &intent)?;
    // Another process may have saved the package before we acquired the signing lock.
    if SigningSession::republish_saved_package(&owner.join("signing"), &context, own, &pass, &mailbox)? {
        println!("payment package published; members may review");
        return Ok(());
    }
    let mut peers = BTreeMap::new();
    for &peer_id in context.signers.iter().filter(|id| **id != own) {
        let commitment = next_message(&mailbox, &member, &context, MessageKind::Commitment, peer_id)?;
        peers.insert(peer_id, commitments_from_message(&context, &commitment, intent.input_nullifiers.len())?);
    }
    let payload = candidate(&member, &owner, &pass, &intent, &session, &context, &peers)?;
    session.publish_package_to_roster(&member.roster.members, &payload, &mailbox, &pass)?;
    println!("payment package published; members may review");
    Ok(())
}

#[cfg(feature = "relay-communication")]
struct TwoRelays {
    own: Vec<OwnerInbox>,
    identity: loki_relay_client::CommIdentity,
    vault: [u8; 32],
    http: RelayHttp,
    runtime: RelayRuntime,
}

#[cfg(feature = "relay-communication")]
impl NonceWitness for TwoRelays {
    fn pins(&self) -> loki_poc::signing_session::WitnessPins {
        [
            (
                &self.own[0].route.pin.key,
                &self.own[0].route.pin.run,
                &self.own[0].route.mailbox,
            ),
            (
                &self.own[1].route.pin.key,
                &self.own[1].route.pin.run,
                &self.own[1].route.mailbox,
            ),
        ]
        .map(|(key, run, mailbox)| (*key, *run, *mailbox))
    }
    fn claim(&mut self, cid: [u8; 32], wire: &[u8]) -> Result<(), String> {
        for inbox in &self.own[..2] {
            let created = self
                .runtime
                .block_on(self.http.claim_nonce(&inbox.route, cid, wire, |challenge| {
                    self.identity.nonce_claim_proof(self.vault, &inbox.route, cid, challenge, wire)
                }))
                .map_err(|e| format!("nonce relay claim: {e}"))?;
            if !created {
                return Err("nonce already claimed; start a new signing attempt".into());
            }
        }
        Ok(())
    }
}

#[cfg(feature = "relay-communication")]
fn two_relays(args: &[String], original: Option<WitnessPins>) -> Result<TwoRelays, String> {
    let root = Path::new(&args[0]);
    let loaded = loki_poc::relay_member::load(root, Path::new(&args[1]), Path::new(&args[2]))
        .map_err(|e| e.to_string())?;
    let config_store = loki_poc::relay_member::ConfigStore::open(root, Path::new(&args[1]))
        .map_err(|e| e.to_string())?;
    let db = ClientStore::open(
        &root.join("transport"),
        &loaded.roster,
        loaded.identity.public().id,
    )
    .map_err(|e| e.to_string())?;
    let mut configured = config_store
        .routing(&db, &loaded)
        .map_err(|e| e.to_string())?
        .own;
    if let Some(pins) = original {
        let mut exact = Vec::with_capacity(2);
        for (key, run, mailbox) in pins {
            let index = configured.iter().position(|inbox| {
                inbox.route.pin.key == key && inbox.route.pin.run == run && inbox.route.mailbox == mailbox
            }).ok_or("an original nonce witness is no longer configured; start a new signing attempt")?;
            exact.push(configured.swap_remove(index));
        }
        configured = exact;
    }
    let http = RelayHttp::new().map_err(|e| e.to_string())?;
    let runtime = RelayRuntime::new().map_err(|e| e.to_string())?;
    let mut own: Vec<OwnerInbox> = Vec::new();
    for inbox in configured {
        match runtime.block_on(http.authenticate_endpoint(&inbox.route.pin, &inbox.route.endpoint))
        {
            Ok(()) => own.push(inbox),
            Err(error) if original.is_some() => return Err(format!(
                "original nonce witness unavailable: {error}; start a new signing attempt"
            )),
            Err(loki_relay_client::ClientError::Transport) => continue,
            Err(error) => return Err(format!("nonce relay identity: {error}")),
        }
        if own.len() == 2 {
            break;
        }
    }
    if own.len() != 2
        || own[0].route.pin.key == own[1].route.pin.key
        || own[0].route.pin.run == own[1].route.pin.run
    {
        return Err("two distinct reachable configured relays required for nonce safety".into());
    }
    Ok(TwoRelays { own, identity: loaded.identity, vault: loaded.roster.vault, http, runtime })
}

#[cfg(feature = "relay-communication")]
fn reviewed_signer(
    args: &[String],
) -> Result<
    (
        MemberState,
        Zeroizing<String>,
        Mailbox,
        SigningSession,
        loki_poc::setup_transport::PublicIdentity,
        ReviewedPackage,
    ),
    String,
> {
    let (member, owner, pass, context, intent, mailbox) = signing_inputs(args)?;
    let session = reopen_signer(&member, &owner, &pass, &context, &intent)?;
    let own = member.identity.public().id;
    let peer_id = if own == context.signers[0] { context.signers[1] } else { context.signers[0] };
    let peer = member.roster.members[&peer_id].clone();
    let package_message = if own == context.signers[0] {
        let wires =
            SigningSession::saved_package_wires(&owner.join("signing"), &context, own, &pass)?;
        member
            .identity
            .open_sent_session(&peer, &context, &wires[0])?
    } else {
        next_message(&mailbox, &member, &context, MessageKind::Package, peer_id)?
    };
    let reviewed = session.review_package(&package_message, &peer)?;
    Ok((member, pass, mailbox, session, peer, reviewed))
}

#[cfg(feature = "relay-communication")]
fn review(args: &[String]) -> Result<(), String> {
    let (member, _, _, _, _, reviewed) = reviewed_signer(args)?;
    let summary = reviewed.summary();
    let mut result = json!({
            "vault": hex::encode(summary.vault),
            "payment": hex::encode(summary.payment),
            "attempt": hex::encode(summary.attempt.0),
            "recipient": vault::unified_receiver(summary.recipient, member.network.network_type()),
            "amount_zat": summary.amount_zat,
            "memo_hex": hex::encode(&summary.memo),
            "memo_utf8": std::str::from_utf8(&summary.memo).ok(),
            "fee_zat": summary.fee_zat,
            "change_zat": summary.change_zat,
            "expiry_height": summary.expiry_height,
            "input_nullifiers": summary.input_nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
            "candidate_hash": hex::encode(summary.candidate_hash),
            "sighash": hex::encode(summary.sighash),
            "review_token": hex::encode(reviewed.review_token()),
            "authorization_required": true,
        });
    if summary.signers.len() == 2 { result["pair"] = json!(summary.signers); }
    else { result["signers"] = json!(summary.signers); }
    println!("{result}");
    Ok(())
}

#[cfg(feature = "relay-communication")]
fn approve(args: &[String], reviewed_token: bool) -> Result<(), String> {
    // The caller must obtain explicit member consent to the displayed review; the token only binds bytes.
    if args.len() != if reviewed_token { 5 } else { 4 } {
        return Err(if reviewed_token {
            "approve-reviewed <member-dir> <passphrase-file> <roster.json> <work-dir> <review-token>"
                .into()
        } else {
            "approve <member-dir> <passphrase-file> <roster.json> <work-dir>".into()
        });
    }
    let token = if reviewed_token {
        Some(
            hex::decode(&args[4])
                .map_err(|_| "invalid review token")?
                .try_into()
                .map_err(|_| "review token must be 32 bytes")?,
        )
    } else {
        None
    };
    let (member, pass, mailbox, mut session, peer, reviewed) = reviewed_signer(&args[..4])?;
    if let Some(token) = token {
        reviewed.require_review_token(token)?;
    } else {
        let (_, intent) = manifest(&Path::new(&args[3]).join("payment.json"), member.network)?;
        confirm(&intent, reviewed.summary(), member.network)?;
    }
    let original = session.witness_pins().ok_or("missing original witnesses; start a new signing attempt")?;
    let mut relays = two_relays(args, Some(original))?;
    session.publish_approved_secured_to_roster(
        reviewed,
        &peer,
        &member.roster.members,
        &mailbox,
        &pass,
        &mut relays,
    )?;
    println!("signed locally; approval delivery pending relay storage");
    Ok(())
}

fn resend(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("resend <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, owner, pass) = state(args)?;
    let own = member.identity.public().id;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    if !context.signers.contains(&own) {
        return Err("only a selected signer can resend".into());
    }
    let mailbox = Mailbox::new(&work.join("mailbox")).map_err(|e| e.to_string())?;
    let root = owner.join("signing");
    let package = own == context.signers[0]
        && SigningSession::republish_saved_package(&root, &context, own, &pass, &mailbox)?;
    let what = if SigningSession::recover_share_if_saved(&root, &context, own, &pass, &mailbox)? {
        "approval"
    } else if package {
        "package"
    } else {
        return Err("no saved package or approval to resend".into());
    };
    println!("resent exact saved {what} for payment {}", hex::encode(context.payment));
    Ok(())
}

use loki_poc::tx_finalize::prove;

fn final_transaction_record(context: &SessionContext) -> (String, [u8; 32]) {
    let mut hash = blake3::Hasher::new_derive_key("loki standalone finalized transaction v1");
    hash.update(&context.vault).update(&context.payment).update(&context.attempt.0);
    for id in &context.signers {
        hash.update(&id.to_be_bytes());
    }
    (format!("final-{}.sealed", hex::encode(context.attempt.0)), *hash.finalize().as_bytes())
}

fn read_final_transaction(
    owner: &Path, context: &SessionContext, pass: &str,
) -> Result<Option<(Vec<u8>, TxId)>, String> {
    let (file, binding) = final_transaction_record(context);
    let body = match MemberDir::open(owner, "").read_sealed(&file, pass) {
        Ok(body) => body,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read saved transaction: {e}")),
    };
    if body.len() <= 64 || body[..32] != binding {
        return Err("saved transaction differs from the payment attempt".into());
    }
    let txid = TxId::from_bytes(body[32..64].try_into().unwrap());
    Ok(Some((body[64..].to_vec(), txid)))
}

fn collect_signed_candidate(
    member: &MemberState, owner: &Path, pass: &str, work: &Path,
    context: &SessionContext, intent: &Intent, wait: bool,
) -> Result<(pczt::Pczt, [u8; 32], Vec<usize>), String> {
    let mailbox = Mailbox::new(&work.join("mailbox")).map_err(|e| e.to_string())?;
    let own = member.identity.public().id;
    let peer = context.signers.contains(&own).then(||
        context.signers.iter().copied().find(|id| *id != own).unwrap());
    let read_message = |kind, sender| {
        if wait {
            wait_message(&mailbox, member, context, kind, sender)
        } else {
            next_message(&mailbox, member, context, kind, sender)
        }
    };
    let package = if own == context.signers[0] {
        let wires =
            SigningSession::saved_package_wires(&owner.join("signing"), context, own, pass)?;
        member.identity.open_sent_session(
            &member.roster.members[&peer.unwrap()],
            context,
            &wires[0],
        )?
    } else {
        read_message(MessageKind::Package, context.signers[0])?
    };
    let payload = PackagePayload::decode(context, package.body())?;
    let mut shares = Vec::new();
    if let Some(peer_id) = peer {
        let wires =
            SigningSession::saved_share_wires(&owner.join("signing"), context, own, pass)?;
        let own_share = member.identity.open_sent_session(
            &member.roster.members[&peer_id],
            context,
            &wires[0],
        )?;
        shares.push(own_share);
    }
    for &id in &context.signers {
        if id != own {
            shares.push(read_message(MessageKind::Share, id)?);
        }
    }
    aggregate_and_apply(
        context,
        intent,
        &member.vault,
        &member.public,
        &member.fvk,
        &payload,
        &shares,
    )
}

fn finish(args: &[String], broadcast: bool) -> Result<(), String> {
    if args.len() != 4 && !(broadcast && args.len() == 5) {
        return Err("finish <member-dir> <passphrase-file> <roster.json> <work-dir> [lightwalletd-url]".into());
    }
    let (member, owner, pass) = state(args)?;
    let url = args.get(4).cloned().or_else(|| lightwalletd_url(member.network));
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    if !broadcast {
        let (_, sighash, _) = collect_signed_candidate(&member, &owner, &pass, work, &context, &intent, false)?;
        println!(
            "aggregate verified payment={} sighash={}",
            hex::encode(context.payment),
            hex::encode(sighash)
        );
        return Ok(());
    }
    if member.network == VaultNetwork::Testnet && url.is_none() {
        return Err("Testnet finish requires a lightwalletd URL".into());
    }
    let saved = read_final_transaction(&owner, &context, &pass)?;
    let candidate = if saved.is_none() {
        Some(collect_signed_candidate(&member, &owner, &pass, work, &context, &intent, true)?)
    } else {
        None
    };
    let (mut wallet, height, frontier, lightwalletd) = match member.network {
        VaultNetwork::Regtest => {
            let (wallet, height, frontier) = synced_wallet(&member, &owner, &pass, &Rpc::regtest())?;
            (wallet, height, frontier, None)
        }
        VaultNetwork::Testnet => {
            let runtime = runtime()?;
            let url = url.ok_or("Testnet finish requires a lightwalletd URL")?;
            let (wallet, mut client) = runtime.block_on(sync_member_wallet(&member, &owner, &pass, &url))?;
            let height = wallet.scanned_height()?.ok_or("wallet has not scanned any blocks")?;
            let info = runtime.block_on(client.get_lightd_info(Empty {}))
                .map_err(|e| format!("lightwalletd info: {e}"))?.into_inner();
            if info.block_height != u64::from(height) {
                return Err("wallet scan is behind lightwalletd; finish again".into());
            }
            let tree_state = runtime.block_on(client.get_tree_state(BlockId {
                height: u64::from(height), hash: vec![],
            })).map_err(|e| format!("lightwalletd tree state: {e}"))?.into_inner();
            if tree_state.network != info.chain_name || tree_state.height != u64::from(height)
                || tree_state.hash != wallet.scanned_hash(BlockHeight::from_u32(height))?
            {
                return Err("wallet scan is on a different chain; finish again".into());
            }
            let tree = tree_state.ironwood_tree()
                .map_err(|e| format!("Ironwood tree state: {e}"))?;
            let frontier = tree.to_frontier().value().cloned()
                .ok_or("scanned Ironwood tree is empty")?;
            (wallet, height, frontier, Some((runtime, client)))
        }
    };
    let (raw, txid) = if let Some((signed, sighash, indices)) = candidate {
        let anchor = frontier.root(None).to_bytes();
        let witnesses = indices.into_iter().zip(
            wallet.ironwood_inputs_at(BlockHeight::from_u32(height), frontier, &intent.input_nullifiers)?
                .into_iter().map(|(_, path)| path),
        ).collect();
        let (raw, txid) = prove(signed, sighash, witnesses, anchor)?;
        let (file, binding) = final_transaction_record(&context);
        let record = [&binding[..], txid.as_ref(), &raw].concat();
        // A concurrent finisher cannot replace the first complete record.
        match MemberDir::open(&owner, "").write_sealed(&file, &record, &pass) {
            Ok(()) => (raw, txid),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                read_final_transaction(&owner, &context, &pass)?.ok_or("saved transaction disappeared")?
            }
            Err(e) => return Err(format!("save finalized transaction: {e}")),
        }
    } else {
        saved.unwrap()
    };
    // Sync the directory also when retrying a write interrupted just after publication.
    #[cfg(unix)]
    fs::File::open(&owner).and_then(|dir| dir.sync_all()).map_err(|e| e.to_string())?;
    if wallet.mined_height(txid)?.is_none() {
        wallet.reserve_broadcast_inputs(
            LockOwner::new(context.attempt.0), txid, &intent.input_nullifiers, intent.expiry_height,
        )?;
        let sent = if let Some((runtime, mut client)) = lightwalletd {
            let result = runtime.block_on(client.send_transaction(RawTransaction {
                data: raw.clone(), height: 0,
            })).map_err(|e| format!("lightwalletd send transaction: {e}")).and_then(|reply| {
                let reply = reply.into_inner();
                if reply.error_code == 0 { return Ok(()); }
                Err(format!("lightwalletd rejected transaction ({}): {}", reply.error_code, reply.error_message))
            });
            if result.is_err() && runtime.block_on(client.get_transaction(TxFilter {
                hash: txid.as_ref().to_vec(), ..Default::default()
            })).is_ok_and(|reply| reply.into_inner().data == raw) { Ok(()) } else { result }
        } else {
            let rpc = Rpc::regtest();
            let raw_hex = hex::encode(&raw);
            let result = rpc.json("sendrawtransaction", &format!("[\"{raw_hex}\"]")).and_then(|reply| {
                if reply.as_str() == Some(txid.to_string().as_str()) { Ok(()) }
                else { Err(format!("node returned a different txid: {reply}")) }
            });
            if result.is_err() && rpc.json("getrawtransaction", &format!("[\"{txid}\",0]"))
                .is_ok_and(|reply| reply.as_str() == Some(&raw_hex)) { Ok(()) } else { result }
        };
        // A rejection can follow an accepted send. Only a scan or expiry frees the inputs.
        sent.map_err(|e| format!("{e}; transaction {txid} saved, rerun finish to retry"))?;
    }
    let txid = txid.to_string();
    fs::write(work.join("final.hex"), hex::encode(&raw)).map_err(|e| e.to_string())?;
    println!(
        "broadcast txid={txid} payment={}",
        hex::encode(context.payment)
    );
    Ok(())
}

fn verify(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("verify <member-dir> <passphrase-file> <roster.json> <work-dir> <txid>".into());
    }
    let (member, owner, pass) = state(args)?;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let txid = &args[4];
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("txid must be 32 hexadecimal bytes".into());
    }
    let (context, intent) = manifest(&work.join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    let rpc = member_rpc(&member)?;
    let tx_json = rpc.json("getrawtransaction", &format!("[\"{txid}\",1]"))?;
    let confirmations = tx_json["confirmations"].as_u64().unwrap_or(0);
    if confirmations < 1 {
        return Err("transaction is not mined".into());
    }
    let raw_hex = rpc.json("getrawtransaction", &format!("[\"{txid}\",0]"))?;
    let raw = hex::decode(
        raw_hex
            .as_str()
            .ok_or("node returned no transaction bytes")?,
    )
    .map_err(|e| e.to_string())?;
    let tx = zcash_primitives::transaction::Transaction::read(
        &raw[..],
        zcash_protocol::consensus::BranchId::for_height(
            &member.network,
            zcash_protocol::consensus::BlockHeight::from_u32(intent.created_height),
        ),
    )
    .map_err(|e| format!("mined transaction parse: {e}"))?;
    if tx.txid().to_string() != *txid {
        return Err("mined transaction ID mismatch".into());
    }
    let wallet = wallet(&member, &owner, &pass)?;
    let height = wallet.mined_height(tx.txid())?
        .ok_or("payment confirmation is not in the wallet index; run loki_wallet_sync")?;
    let hash = wallet.scanned_hash(height)?;
    if tx_json["blockhash"].as_str() != Some(hash.as_str()) {
        return Err("payment confirmation was reorganized; run loki_wallet_sync".into());
    }
    let mailbox = Mailbox::new(&work.join("mailbox")).map_err(|e| e.to_string())?;
    let package_message = if member.identity.public().id == context.signers[0] {
        let wires = SigningSession::saved_package_wires(
            &owner.join("signing"),
            &context,
            context.signers[0],
            &pass,
        )?;
        member.identity.open_sent_session(
            &member.roster.members[&context.signers[1]],
            &context,
            &wires[0],
        )?
    } else {
        wait_message(
            &mailbox,
            &member,
            &context,
            MessageKind::Package,
            context.signers[0],
        )?
    };
    let payload = PackagePayload::decode(&context, package_message.body())?;
    let pczt =
        pczt::Pczt::parse(&payload.candidate).map_err(|e| format!("candidate parse: {e:?}"))?;
    let expected = loki_poc::verify::Expectations {
        input_nullifiers: intent.input_nullifiers.clone(),
        recipient: intent.recipient.clone().try_into().unwrap(),
        amount_zat: intent.amount_zat,
        memo: intent.memo.clone(),
        change_zat: intent.change_zat,
        fee_zat: intent.fee_zat,
        expiry_height: intent.expiry_height,
    };
    let checked = pczt::roles::verifier::Verifier::new(pczt)
        .with_ironwood::<loki_poc::verify::Refusal, _>(|bundle| {
            loki_poc::verify::check_candidate(bundle, &member.fvk, &expected)
                .map_err(pczt::roles::verifier::OrchardError::Custom)
        })
        .map_err(|e| format!("candidate verification: {e:?}"))?
        .finish();
    let approved_sighash = pczt::roles::signer::Signer::new(checked)
        .map_err(|e| format!("candidate sighash: {e:?}"))?
        .shielded_sighash();
    if finalized_sighash(&tx)? != approved_sighash {
        return Err("mined transaction effects differ from approved candidate".into());
    }
    let bundle = tx
        .ironwood_bundle()
        .ok_or("mined transaction has no Ironwood bundle")?;
    let actual_nfs = bundle
        .actions()
        .iter()
        .map(|a| a.nullifier().to_bytes())
        .collect::<Vec<_>>();
    if intent
        .input_nullifiers
        .iter()
        .any(|nf| !actual_nfs.contains(nf))
    {
        return Err("mined inputs differ from approved intent".into());
    }
    let fee: u64 = (*bundle.value_balance())
        .try_into()
        .map_err(|_| "invalid mined fee")?;
    if fee != intent.fee_zat {
        return Err("mined fee differs from approved intent".into());
    }
    let change_addr = member
        .fvk
        .address_at(0u64, Scope::Internal)
        .to_raw_address_bytes();
    let mut paid = None;
    let mut changed = None;
    let ivks = scan::vault_ivks(&member.fvk);
    let actions = tx_json["ironwood"]["actions"]
        .as_array()
        .ok_or("no mined Ironwood actions")?;
    for raw in scan::parse_actions(actions, txid)? {
        let Some((note, memo)) = ivks
            .iter()
            .find_map(|ivk| scan::try_decrypt_with_memo(ivk, &raw))
        else {
            continue;
        };
        let value = note.value().inner();
        let to = note.recipient().to_raw_address_bytes();
        if to == intent.recipient.as_slice() {
            if memo[..intent.memo.len()] != intent.memo
                || memo[intent.memo.len()..].iter().any(|byte| *byte != 0)
            {
                return Err("mined memo differs from approved intent".into());
            }
            if paid.replace(value).is_some() {
                return Err("duplicate payment output".into());
            }
        } else if to == change_addr {
            if changed.replace(value).is_some() {
                return Err("duplicate change output".into());
            }
        } else {
            return Err("mined transaction has an unexpected output".into());
        }
    }
    let self_payment = intent.recipient
        == member
            .fvk
            .address_at(0u64, Scope::External)
            .to_raw_address_bytes();
    if changed != Some(intent.change_zat)
        || paid.is_some_and(|value| value != intent.amount_zat)
        || (self_payment && paid != Some(intent.amount_zat))
    {
        return Err("mined amount or change differs from approved intent".into());
    }
    // Where it was mined, so a later recheck can ask only whether that block is still
    // on the chain (`chain-check`).
    // A node that does not report the block leaves the recheck to a full `verify`.
    let location = tx_json["blockhash"]
        .as_str()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .and_then(|block| {
            let height = rpc
                .json("getblock", &format!("[\"{block}\", 1]"))
                .ok()?["height"]
                .as_u64()?;
            Some(format!(" block={block} height={height}"))
        })
        .unwrap_or_default();
    println!(
        "verified mined txid={txid} confirmations={confirmations} amount={} fee={} change={} recipient_evidence={}{location}",
        intent.amount_zat, fee, intent.change_zat,
        if paid.is_some() { "decrypted" } else { "candidate-opening-and-mined-sighash" }
    );
    Ok(())
}

fn confirm_mined(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("confirm-mined <member-dir> <passphrase-file> <roster.json> <work-dir> <txid>".into());
    }
    let (member, owner, pass) = state(args)?;
    if member.network != VaultNetwork::Testnet {
        return Err("confirm-mined requires a Testnet wallet".into());
    }
    let requested = TxId::from_hex(&args[4]).ok_or("invalid txid")?;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    let (_, txid) = read_final_transaction(&owner, &context, &pass)?
        .ok_or("no sealed finalized transaction for this attempt; use verify for a discovered spend")?;
    if requested != txid {
        return Err("txid differs from the sealed finalized transaction".into());
    }
    let mut wallet = wallet(&member, &owner, &pass)?;
    let height = wallet.mined_height(txid)?.ok_or("transaction is not mined in this wallet")?;
    for input in &intent.input_nullifiers {
        if wallet.mined_spend(input)? != Some(txid) {
            return Err("the sealed transaction did not spend this payment's inputs on the scanned chain".into());
        }
    }
    let tip = wallet.scanned_height()?.ok_or("wallet has not scanned any blocks")?;
    let confirmations = tip.checked_sub(u32::from(height))
        .ok_or("wallet scan is behind the mined transaction")? + 1;
    println!("confirmed txid={txid} confirmations={confirmations} height={height}");
    Ok(())
}

/// Whether block `hash` is still the chain's block at `height` (`getblockhash` only).
fn chain_check(args: &[String]) -> Result<(), String> {
    let [network, height, hash] = args else {
        return Err("chain-check <regtest|testnet> <height> <block-hash>".into());
    };
    let rpc = match VaultNetwork::parse(network)? {
        VaultNetwork::Regtest => Rpc::regtest(),
        VaultNetwork::Testnet => Rpc::testnet()?,
    };
    let height: u64 = height.parse().map_err(|_| "chain-check height")?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("chain-check block hash must be 32 hexadecimal bytes".into());
    }
    let current = rpc.json("getblockhash", &format!("[{height}]"))?;
    if current.as_str() != Some(hash.to_ascii_lowercase().as_str()) {
        return Err("mined block is no longer on the chain".into());
    }
    println!("chain-check=ok height={height}");
    Ok(())
}

fn mined_spend_in_block(
    block: &serde_json::Value,
    inputs: &[[u8; 32]],
) -> Result<Option<String>, String> {
    if inputs.is_empty() {
        return Err("payment has no input nullifiers".into());
    }
    let transactions = block["tx"].as_array().ok_or("block has no tx array")?;
    for tx in transactions {
        let Some(actions) = tx["ironwood"]["actions"].as_array() else {
            continue;
        };
        let nullifiers = actions
            .iter()
            .map(|action| scan::hex32(action, "nullifier").ok_or("invalid mined nullifier"))
            .collect::<Result<Vec<_>, _>>()?;
        if inputs.iter().all(|input| nullifiers.contains(input)) {
            return tx["txid"]
                .as_str()
                .map(str::to_owned)
                .map(Some)
                .ok_or_else(|| "mined spend has no transaction ID".into());
        }
    }
    Ok(None)
}

/// Chain-derived txid discovery is a hint only. `verify` checks the exact
/// approved candidate against the mined transaction before the app confirms it.
fn find_mined(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("find-mined <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, _, _) = state(args)?;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"), member.network)?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    let rpc = member_rpc(&member)?;
    let tip = rpc.json("getblockcount", "[]")?.as_u64()
        .ok_or("getblockcount did not return a height")?;
    for height in u64::from(intent.created_height)..=tip {
        let block = rpc.json("getblock", &format!("[\"{height}\", 2]"))?;
        if let Some(txid) = mined_spend_in_block(&block, &intent.input_nullifiers)? {
            println!("mined txid={txid}");
            return Ok(());
        }
    }
    println!("not mined");
    Ok(())
}

fn receive(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("receive <recipient-member-dir> <passphrase-file> <roster.json> <payment-work-dir> <txid>".into());
    }
    let (recipient, _, _) = state(args)?;
    let (_, intent) = manifest(&Path::new(&args[3]).join("payment.json"), recipient.network)?;
    let txid = &args[4];
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("txid must be 32 hexadecimal bytes".into());
    }
    if recipient
        .fvk
        .address_at(0u64, Scope::External)
        .to_raw_address_bytes()
        .as_slice()
        != intent.recipient.as_slice()
    {
        return Err("this member does not control the payment recipient".into());
    }
    let rpc = member_rpc(&recipient)?;
    let tx = rpc.json("getrawtransaction", &format!("[\"{txid}\",1]"))?;
    let confirmations = tx["confirmations"].as_u64().unwrap_or(0);
    if confirmations < 1 {
        return Err("recipient payment is not mined".into());
    }
    let ivks = scan::vault_ivks(&recipient.fvk);
    let mut found = 0;
    let actions = tx["ironwood"]["actions"]
        .as_array()
        .ok_or("no mined Ironwood actions")?;
    for raw in scan::parse_actions(actions, txid)? {
        for ivk in &ivks {
            if let Some((note, memo)) = scan::try_decrypt_with_memo(ivk, &raw) {
                if note.recipient().to_raw_address_bytes().as_slice() == intent.recipient.as_slice()
                    && note.value().inner() == intent.amount_zat
                    && memo[..intent.memo.len()] == intent.memo
                    && memo[intent.memo.len()..].iter().all(|byte| *byte == 0)
                {
                    found += 1;
                }
            }
        }
    }
    if found != 1 {
        return Err(format!(
            "recipient decrypted {found} matching outputs, expected one"
        ));
    }
    println!(
        "recipient independently decrypted txid={txid} amount={} confirmations={confirmations}",
        intent.amount_zat
    );
    Ok(())
}

/// The node's block height only (`getblockcount`), for expiry checks that need no scan.
fn tip(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("tip".into());
    }
    let height = Rpc::regtest()
        .json("getblockcount", "[]")?
        .as_u64()
        .ok_or("getblockcount did not return a height")?;
    println!("{}", serde_json::json!({ "height": height }));
    Ok(())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("prepare") => prepare(&args[2..], false),
        Some("prepare-sweep") => prepare(&args[2..], true),
        Some("local-wires") => local_wires(&args[2..]),
        Some("balance") => balance(&args[2..]),
        Some("tip") => tip(&args[2..]),
        Some("chain-check") => chain_check(&args[2..]),
        #[cfg(feature = "relay-communication")]
        Some("features") => {
            println!("relay-backed-signing=1");
            Ok(())
        }
        #[cfg(feature = "relay-communication")]
        Some("commit") => commit(&args[2..]),
        #[cfg(feature = "relay-communication")]
        Some("package") => package(&args[2..]),
        #[cfg(feature = "relay-communication")]
        Some("review") => review(&args[2..]),
        #[cfg(feature = "relay-communication")]
        Some("approve") => approve(&args[2..], false),
        #[cfg(feature = "relay-communication")]
        Some("approve-reviewed") => approve(&args[2..], true),
        Some("sign") => sign(&args[2..]),
        Some("resend") => resend(&args[2..]),
        Some("finish") => finish(&args[2..], true),
        Some("finish-check") => finish(&args[2..], false),
        Some("find-mined") => find_mined(&args[2..]),
        Some("verify") => verify(&args[2..]),
        Some("confirm-mined") => confirm_mined(&args[2..]),
        Some("receive") => receive(&args[2..]),
        _ => Err(
            "loki_member_payment <balance|prepare|prepare-sweep|sign|resend|finish|verify|receive> ...".into(),
        ),
    };
    loki_poc::seal_kdf::report();
    if let Err(error) = result {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loki_poc::payment_manifest::{manifest_pair, proposer_id};

    #[test]
    fn local_wires_excludes_received_and_other_attempts() {
        use loki_poc::setup_transport::Identity;
        let own = Identity::new(1);
        let peer = Identity::new(2);
        let roster = [(1, own.public()), (2, peer.public())]
            .into_iter()
            .collect();
        let context = SessionContext {
            vault: [3; 32],
            payment: [4; 32],
            attempt: AttemptId([5; 32]),
            signers: vec![1, 2],
        };
        let path = std::env::temp_dir().join(format!(
            "loki-local-wires-{}-{}",
            process::id(),
            hex::encode(context.attempt.0)
        ));
        let mailbox = Mailbox::new(&path).unwrap();
        let outbound = own
            .seal_session(&peer.public(), &context, MessageKind::Commitment, b"own")
            .unwrap();
        let own_hash = mailbox.append(&outbound).unwrap();
        mailbox
            .append(
                &peer
                    .seal_session(&own.public(), &context, MessageKind::Commitment, b"peer")
                    .unwrap(),
            )
            .unwrap();
        let other = SessionContext {
            attempt: AttemptId([6; 32]),
            ..context.clone()
        };
        mailbox
            .append(
                &own.seal_session(&peer.public(), &other, MessageKind::Commitment, b"other")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            own_wire_hashes(&own, &roster, &context, &path).unwrap(),
            vec![hex::encode(own_hash)]
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(feature = "relay-communication")]
    #[test]
    fn reviewed_approval_rejects_malformed_token_before_opening_member_state() {
        let args = [
            "missing-member",
            "missing-pass",
            "missing-roster",
            "missing-work",
            "1234",
        ]
        .map(str::to_owned);
        assert_eq!(
            approve(&args, true),
            Err("review token must be 32 bytes".into())
        );
    }

    #[test]
    fn payment_pair_is_sorted_and_explicit() {
        assert_eq!(manifest_pair(&json!({})).unwrap(), [1, 2]);
        for (name, pair) in [
            ("AB", [1, 2]),
            ("AC", [1, 3]),
            ("AD", [1, 4]),
            ("BC", [2, 3]),
            ("BD", [2, 4]),
            ("CD", [3, 4]),
        ] {
            assert_eq!(signer_set_from_name(name, 2).unwrap(), pair);
            assert_eq!(manifest_pair(&json!({ "pair": pair })).unwrap(), pair);
        }
        for (name, signers) in [("ABC", [1, 2, 3]), ("ABD", [1, 2, 4]), ("ACD", [1, 3, 4]), ("BCD", [2, 3, 4])] {
            assert_eq!(signer_set_from_name(name, 3).unwrap(), signers);
        }
        for pair in [
            json!([2, 1]),
            json!([1, 1]),
            json!([16, 17]),
            json!([1]),
            json!("AC"),
        ] {
            assert!(manifest_pair(&json!({ "pair": pair })).is_err());
        }
    }

    #[test]
    fn any_roster_member_can_propose() {
        for id in 1..=4 {
            let bytes = frost::Identifier::try_from(id).unwrap().serialize();
            assert_eq!(proposer_id(&bytes).unwrap(), id);
        }
        assert_eq!(proposer_id(&frost::Identifier::try_from(16u16).unwrap().serialize()).unwrap(), 16);
        assert!(proposer_id(&frost::Identifier::try_from(17u16).unwrap().serialize()).is_err());
        assert!(proposer_id(&[0u8; 32]).is_err());
    }

    #[test]
    fn manifest_pair_and_proposer_must_belong_to_certified_roster() {
        let path = std::env::temp_dir().join(format!("loki-payment-roster-{}", process::id()));
        let members: Vec<_> = (1..=3)
            .map(|id| {
                let public = loki_poc::setup_transport::Identity::new(id).public();
                json!({"id": id, "signing": hex::encode(public.signing),
                       "encryption": hex::encode(public.encryption)})
            })
            .collect();
        fs::write(
            &path,
            json!({"vault": hex::encode([7u8; 32]),
                                "threshold": 2, "members": members})
            .to_string(),
        )
        .unwrap();
        let roster = Roster::load(&path).unwrap();
        fs::remove_file(path).unwrap();
        let context = SessionContext {
            vault: roster.vault,
            payment: [0; 32],
            attempt: AttemptId([1; 32]),
            signers: vec![1, 3],
        };
        let mut intent = Intent {
            proposer: frost::Identifier::try_from(2u16).unwrap().serialize(),
            created_height: 1,
            input_nullifiers: vec![[0; 32]],
            recipient: vec![0; 43],
            amount_zat: 1,
            memo: vec![1],
            change_policy: ChangePolicy::VaultInternal,
            fee_zat: 1,
            change_zat: 1,
            expiry_height: 2,
        };
        assert!(check_manifest_roster(&roster, &context, &intent).is_ok());
        let mut bad_pair = context.clone();
        bad_pair.signers = vec![1, 4];
        assert!(check_manifest_roster(&roster, &bad_pair, &intent).is_err());
        intent.proposer = frost::Identifier::try_from(4u16).unwrap().serialize();
        assert!(check_manifest_roster(&roster, &context, &intent).is_err());
    }
}
