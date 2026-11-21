//! Communication member commands. Arguments are paths and public identifiers.
//! Secret bytes stay in sealed files and are never written to stdout or stderr.

use loki_poc::relay_member::{
    load_with_signing_identity, ConfigStore, CourierImport, LoadedMember, MemberError, ProvisionTarget,
};
use loki_poc::{
    payment_manifest::{self, decode_proposal_for_network, encode_proposal_for_network},
    setup_transport::{Identity, PublicIdentity},
    signing_session::{Mailbox, MessageKind, OpenedMessage, SessionContext},
};
use loki_relay_client::{
    committed_readiness, open_descriptor, outbox_intent_digest, poll_once, prepare_outbox,
    received_status, upload_pending, AuthenticatedDescriptor, CandidateReadiness, ClientConfig,
    ClientError, ClientStore, DiagnosticSample, DownloadRejection, PendingDownload,
    RecoveryLogical, RecoveryUpload, RelayHttp, RelayRuntime, RouteCursor, Secret32,
    SourceRejection, ThirdPass,
};
use loki_relay_protocol::types::{
    roster_digest, Id32, LogicalKey, MessageBody, Payload, RelayPin, RelayRoute,
};
use rand_core::{OsRng, RngCore};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const PAGE: u16 = 100;
const ENTRY_LIMIT: u64 = 100;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const MAX_MANIFEST: usize = 8192;
const SWITCHES: &[&str] = &["--once", "--verify-relays", "--diagnostics"];
const DIAGNOSTIC_ROW_BOUND: usize = 400;

#[derive(Debug)]
enum Exit {
    Usage,
    Member(MemberError),
    Client(ClientError),
}

struct OwnInbox {
    route: RelayRoute,
    read: Secret32,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(Exit::Usage) => {
            eprintln!("member_arguments");
            2
        }
        Err(Exit::Member(error)) => {
            eprintln!("{}", error.code());
            1
        }
        Err(Exit::Client(error)) => {
            eprintln!("{}", error.code());
            1
        }
    };
    loki_poc::seal_kdf::report();
    std::process::exit(code);
}

fn run() -> Result<(), Exit> {
    let mut args = env::args_os().skip(1);
    let command = args.next().ok_or(Exit::Usage)?;
    let command = command.to_str().ok_or(Exit::Usage)?;
    let mut flags: Vec<(String, Option<std::ffi::OsString>)> = Vec::new();
    while let Some(raw) = args.next() {
        let name = raw.to_str().ok_or(Exit::Usage)?.to_owned();
        if !name.starts_with("--") || name.len() == 2 || name.contains('=') {
            return Err(Exit::Usage);
        }
        if flags.iter().any(|(seen, _)| seen == &name) {
            return Err(Exit::Usage);
        }
        if SWITCHES.contains(&name.as_str()) {
            flags.push((name, None));
        } else {
            let value = args.next().ok_or(Exit::Usage)?;
            if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
                return Err(Exit::Usage);
            }
            flags.push((name, Some(value)));
        }
    }
    let take = |name: &str| -> Result<PathBuf, Exit> {
        flags
            .iter()
            .find(|(flag, _)| flag == name)
            .and_then(|(_, value)| value.clone())
            .map(PathBuf::from)
            .ok_or(Exit::Usage)
    };
    let switched = |name: &str| flags.iter().any(|(flag, _)| flag == name);
    let common = || -> Result<(PathBuf, PathBuf, PathBuf), Exit> {
        Ok((
            take("--member-root")?,
            take("--passphrase-file")?,
            take("--roster")?,
        ))
    };
    let expect = |allowed: &[&str]| -> Result<(), Exit> {
        if flags
            .iter()
            .any(|(flag, _)| !allowed.contains(&flag.as_str()))
        {
            Err(Exit::Usage)
        } else {
            Ok(())
        }
    };
    match command {
        "provision" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--relay-manifest",
                "--provision-capability-files",
            ])?;
            let (root, pass, roster) = common()?;
            provision(
                &root,
                &pass,
                &roster,
                &take("--relay-manifest")?,
                &take("--provision-capability-files")?,
            )
        }
        "export-config" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--courier-directory",
            ])?;
            let (root, pass, roster) = common()?;
            export_config(&root, &pass, &roster, &take("--courier-directory")?)
        }
        "import-config" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--courier-file",
            ])?;
            let (root, pass, roster) = common()?;
            import_config(&root, &pass, &roster, &take("--courier-file")?)
        }
        "rotate-append" => {
            expect(&["--member-root", "--passphrase-file", "--roster"])?;
            let (root, pass, roster) = common()?;
            rotate_append(&root, &pass, &roster)
        }
        "send" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--payload-file",
                "--request-id",
            ])?;
            let (root, pass, roster) = common()?;
            let request = flags
                .iter()
                .find(|(flag, _)| flag == "--request-id")
                .and_then(|(_, value)| value.as_ref())
                .ok_or(Exit::Usage)?;
            let request = request.to_str().ok_or(Exit::Usage)?;
            send(
                &root,
                &pass,
                &roster,
                &take("--payload-file")?,
                parse_id(request)?,
            )
        }
        "send-signing" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--payload-file",
                "--work-dir",
                "--attempt",
            ])?;
            let (root, pass, roster) = common()?;
            let attempt = parse_id(take("--attempt")?.to_str().ok_or(Exit::Usage)?)?;
            let mut session = open_session(&root, &pass, &roster)?;
            let work = checked_work(&session, &root, &take("--work-dir")?, attempt)?;
            let payload = read_exact(&take("--payload-file")?, MAX_PAYLOAD, false)?;
            let request = *blake3::hash(&payload).as_bytes();
            let saved = save_signing(&mut session, &work, &payload, request)?;
            println!("request_id={}", hex_id(&request));
            print_logical(&session.db, &saved)
        }
        "send-proposal" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--proposal-file",
            ])?;
            let (root, pass, roster) = common()?;
            send_proposal(&root, &pass, &roster, &take("--proposal-file")?)
        }
        "import-proposals" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--payments-dir",
            ])?;
            let (root, pass, roster) = common()?;
            import_proposals(&root, &pass, &roster, &take("--payments-dir")?)
        }
        "export-signing" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--work-dir",
                "--attempt",
            ])?;
            let (root, pass, roster) = common()?;
            let attempt = parse_id(take("--attempt")?.to_str().ok_or(Exit::Usage)?)?;
            export_signing(&root, &pass, &roster, &take("--work-dir")?, attempt)
        }
        "upload" => {
            expect(&["--member-root", "--passphrase-file", "--roster"])?;
            let (root, pass, roster) = common()?;
            upload(&root, &pass, &roster)
        }
        "poll" => {
            expect(&["--member-root", "--passphrase-file", "--roster", "--once"])?;
            if !switched("--once") {
                return Err(Exit::Usage);
            }
            let (root, pass, roster) = common()?;
            poll(&root, &pass, &roster)
        }
        "status" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--verify-relays",
                "--diagnostics",
                "--attempt",
            ])?;
            let (root, pass, roster) = common()?;
            status(
                &root,
                &pass,
                &roster,
                switched("--verify-relays"),
                switched("--diagnostics"),
                if switched("--attempt") {
                    Some(parse_id(take("--attempt")?.to_str().ok_or(Exit::Usage)?)?)
                } else {
                    None
                },
            )
        }
        "payment-sync" => {
            expect(&["--member-root", "--passphrase-file", "--roster", "--plan"])?;
            let (root, pass, roster) = common()?;
            payment_sync(&root, &pass, &roster, &take("--plan")?)
        }
        "readiness" => {
            expect(&["--member-root", "--passphrase-file", "--roster"])?;
            let (root, pass, roster) = common()?;
            readiness(&root, &pass, &roster)
        }
        _ => Err(Exit::Usage),
    }
}

struct Session {
    member: LoadedMember,
    signing_identity: Identity,
    configs: ConfigStore,
    db: ClientStore,
}

fn open_session(root: &Path, pass: &Path, roster: &Path) -> Result<Session, Exit> {
    let (member, signing_identity) = load_with_signing_identity(root, pass, roster).map_err(Exit::Member)?;
    let configs = ConfigStore::open(root, pass).map_err(Exit::Member)?;
    // Transport state stays a direct child of the certified member root.
    let db = ClientStore::open(
        &root.join("transport"),
        &member.roster,
        member.identity.public().id,
    )
    .map_err(Exit::Client)?;
    Ok(Session {
        member,
        signing_identity,
        configs,
        db,
    })
}

fn provision(
    root: &Path,
    pass: &Path,
    roster: &Path,
    manifest_dir: &Path,
    capability_dir: &Path,
) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let (targets, capabilities) = provision_inputs(manifest_dir, capability_dir)?;
    let runtime = runtime()?;
    runtime.block_on(async {
        let http = RelayHttp::new().map_err(Exit::Client)?;
        for target in &targets {
            http.authenticate_endpoint(&target.pin, &target.endpoint)
                .await
                .map_err(Exit::Client)?;
        }
        session
            .configs
            .prepare_provision(&mut session.db, &session.member, &targets)
            .map_err(Exit::Member)?;
        session
            .configs
            .provision(&mut session.db, &session.member, &http, &capabilities)
            .await
            .map_err(Exit::Member)
    })?;
    print_reference(&session)?;
    print_authenticated_inboxes(&session)?;
    Ok(())
}

fn export_config(root: &Path, pass: &Path, roster: &Path, directory: &Path) -> Result<(), Exit> {
    let session = open_session(root, pass, roster)?;
    let paths = session
        .configs
        .publish_provision(&session.db, &session.member, directory)
        .map_err(Exit::Member)?;
    print_reference(&session)?;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Exit::Member(MemberError::Io))?;
        println!("courier={name}");
    }
    Ok(())
}

fn import_config(root: &Path, pass: &Path, roster: &Path, file: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let imported = CourierImport::read(&session.member, file).map_err(Exit::Member)?;
    let owner = imported.descriptor().body().owner;
    let revision = imported.descriptor().body().revision;
    let digest = *imported.descriptor().digest();
    session
        .configs
        .accept_peer(&mut session.db, &session.member, imported.wire())
        .map_err(Exit::Member)?;
    print_reference(&session)?;
    println!(
        "imported owner={owner} revision={revision} digest={}",
        hex_id(&digest)
    );
    Ok(())
}

fn rotate_append(root: &Path, pass: &Path, roster: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let runtime = runtime()?;
    runtime.block_on(async {
        prepare_selected_rotation(&mut session)?;
        session
            .configs
            .rotate(
                &mut session.db,
                &session.member,
                &RelayHttp::new().map_err(Exit::Client)?,
            )
            .await
            .map_err(Exit::Member)
    })?;
    print_reference(&session)?;
    Ok(())
}

fn send(
    root: &Path,
    pass: &Path,
    roster: &Path,
    payload_file: &Path,
    request_id: Id32,
) -> Result<(), Exit> {
    let payload = read_exact(payload_file, MAX_PAYLOAD, false)?;
    let mut session = open_session(root, pass, roster)?;
    let saved = save_payload(&mut session, &payload, request_id, None)?;
    println!("request_id={}", hex_id(&request_id));
    print_logical(&session.db, &saved)
}

/// Commit one outbox message (or find the one already saved for `request_id`).
fn save_payload(
    session: &mut Session,
    payload: &[u8],
    request_id: Id32,
    signing_attempt: Option<Id32>,
) -> Result<RecoveryLogical, Exit> {
    let digest =
        roster_digest(&session.member.roster).map_err(|_| Exit::Member(MemberError::Roster))?;
    let mut body = MessageBody {
        key: LogicalKey {
            vault: session.member.roster.vault,
            roster: digest,
            sender: session.member.identity.public().id,
            message: [0; 32],
        },
        audience: session
            .member
            .roster
            .members
            .iter()
            .map(|member| member.id)
            .collect(),
        session: signing_attempt,
        prerequisites: Vec::new(),
        // shortcut: kind 1 carries opaque inner signing envelopes until the relay protocol assigns an application kind.
        payload: Payload::Test(payload.to_vec()),
    };
    let intent = outbox_intent_digest(&body).map_err(|error| {
        wipe_test(&mut body);
        Exit::Client(error)
    });
    let saved = intent.and_then(|intent| {
        if let Some(existing) = session
            .db
            .lookup_outbox_request(&request_id, &intent)
            .map_err(Exit::Client)?
        {
            return Ok(existing);
        }
        OsRng
            .try_fill_bytes(&mut body.key.message)
            .map_err(|_| Exit::Member(MemberError::Io))?;
        let prepared = prepare_outbox(&session.member.identity, &session.member.roster, &body)
            .map_err(Exit::Client)?;
        // The caller binding and every recipient object are durable before any upload command.
        session
            .db
            .commit_outbox(
                &session.member.roster,
                &session.member.identity,
                &request_id,
                &prepared,
            )
            .map_err(Exit::Client)
    });
    wipe_test(&mut body);
    saved
}

fn send_proposal(root: &Path, pass: &Path, roster: &Path, proposal: &Path) -> Result<(), Exit> {
    let manifest = read_exact(proposal, payment_manifest::MAX_MANIFEST, false)?;
    let mut session = open_session(root, pass, roster)?;
    let (context, scope, saved) = save_proposal(&mut session, root, &manifest)?;
    println!("request_id={}", hex_id(&scope));
    print_logical(&session.db, &saved)?;
    println!("proposal={} attempt={} scope={}", hex_id(&context.payment), hex_id(&context.attempt.0), hex_id(&scope));
    Ok(())
}

fn checked_proposal(member: &LoadedMember, manifest: &[u8]) -> Result<(SessionContext, u16), Exit> {
    let (context, intent) =
        payment_manifest::parse_for_network(manifest, member.network)
            .map_err(|_| Exit::Member(MemberError::Markers))?;
    payment_manifest::validate_roster(
        member.roster.vault,
        member.threshold,
        member.roster.members.iter().map(|member| member.id),
        &context,
        &intent,
    )
    .map_err(|_| Exit::Member(MemberError::Roster))?;
    let proposer = payment_manifest::proposer_id(&intent.proposer)
        .map_err(|_| Exit::Member(MemberError::Identity))?;
    Ok((context, proposer))
}

fn proposal_scope(context: &SessionContext, proposer: u16) -> Id32 {
    blake3::Hasher::new_derive_key("Loki owned relay payment work v1")
        .update(&context.vault)
        .update(&proposer.to_be_bytes())
        .update(&context.payment)
        .update(&context.attempt.0)
        .finalize().into()
}

/// Check a local proposal, pin its work manifest and commit it to the outbox.
fn save_proposal(
    session: &mut Session,
    root: &Path,
    manifest: &[u8],
) -> Result<(SessionContext, Id32, RecoveryLogical), Exit> {
    let (context, proposer) = checked_proposal(&session.member, manifest)?;
    if proposer != session.member.identity.public().id {
        return Err(Exit::Member(MemberError::Identity));
    }
    let payload =
        Zeroizing::new(encode_proposal_for_network(manifest, session.member.network)
            .map_err(|_| Exit::Member(MemberError::Markers))?);
    let scope = proposal_scope(&context, proposer);
    let payments = payments_path(root, &root.join("payments"))?;
    create_private_dir(&payments)?;
    let work = payments.join(hex_id(&scope));
    create_private_dir(&work)?;
    create_private_file(&work.join("payment.json"), manifest)?;
    let saved = save_payload(session, &payload, scope, Some(context.attempt.0))?;
    Ok((context, scope, saved))
}

fn import_proposals(root: &Path, pass: &Path, roster: &Path, payments: &Path) -> Result<(), Exit> {
    let session = open_session(root, pass, roster)?;
    let (imported, rejected) = import_saved_proposals(&session, root, payments, true)?;
    println!("imported_proposals={imported}");
    println!("rejected_proposals={rejected}");
    Ok(())
}

fn payments_path(root: &Path, payments: &Path) -> Result<PathBuf, Exit> {
    let owner = fs::canonicalize(root).map_err(|_| Exit::Member(MemberError::Io))?;
    let parent = payments.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if payments.file_name().and_then(|name| name.to_str()) != Some("payments")
        || fs::canonicalize(parent).ok().as_deref() != Some(owner.as_path())
    {
        return Err(Exit::Member(MemberError::Permissions));
    }
    Ok(owner.join("payments"))
}

/// Write each authenticated proposal to `<root>/payments/<scope>/payment.json` once.
/// Leave legacy attempt-only directories untouched; proposals are reopened from the inbox.
fn import_saved_proposals(
    session: &Session,
    root: &Path,
    payments: &Path,
    print: bool,
) -> Result<(usize, usize), Exit> {
    let expected = payments_path(root, payments)?;
    create_private_dir(&expected)?;
    let mut imported = 0;
    let mut rejected = 0;
    visit_pages(
        |after| session.db.recover_incoming_originals(after, PAGE),
        |row| {
            if row.kind != 1 {
                return Ok(());
            }
            let Ok(opened) =
                session
                    .db
                    .open_incoming(&session.member.roster, &session.member.identity, &row)
            else {
                rejected += 1;
                return Ok(());
            };
            let body = opened.message().body();
            let Payload::Test(payload) = &body.payload else {
                return Ok(());
            };
            let manifest = match decode_proposal_for_network(payload, session.member.network) {
                Ok(Some(manifest)) => manifest,
                Ok(None) => return Ok(()),
                Err(_) => {
                    rejected += 1;
                    return Ok(());
                }
            };
            let Ok((context, proposer)) = checked_proposal(&session.member, manifest) else {
                rejected += 1;
                return Ok(());
            };
            if body.session != Some(context.attempt.0) || body.key.sender != proposer {
                rejected += 1;
                return Ok(());
            }
            let scope = proposal_scope(&context, proposer);
            let directory = expected.join(hex_id(&scope));
            create_private_dir(&directory)?;
            let path = directory.join("payment.json");
            match create_private_file(&path, manifest) {
                Ok(true) => imported += 1,
                Ok(false) => {}
                Err(Exit::Member(MemberError::Identity)) => {
                    rejected += 1;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            if print {
                println!(
                    "proposal={} attempt={} scope={}",
                    hex_id(&context.payment),
                    hex_id(&context.attempt.0),
                    hex_id(&scope)
                );
            }
            Ok(())
        },
    )?;
    Ok((imported, rejected))
}

fn create_private_dir(path: &Path) -> Result<(), Exit> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(Exit::Member(MemberError::Io)),
    }
    check_private_dir(path)
}

fn check_private_dir(path: &Path) -> Result<(), Exit> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Exit::Member(MemberError::Io))?;
    if !metadata.is_dir() {
        return Err(Exit::Member(MemberError::Permissions));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.uid() != effective_uid() {
            return Err(Exit::Member(MemberError::Permissions));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<bool, Exit> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or(Exit::Member(MemberError::Permissions))?;
    let mut suffix = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut suffix)
        .map_err(|_| Exit::Member(MemberError::Io))?;
    let staging = parent.join(format!(".proposal-{}", hex::encode(suffix)));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&staging)
            .map_err(|_| Exit::Member(MemberError::Io))?;
        file.write_all(bytes)
            .map_err(|_| Exit::Member(MemberError::Io))?;
        file.sync_all().map_err(|_| Exit::Member(MemberError::Io))?;
        match fs::hard_link(&staging, path) {
            Ok(()) => {
                fs::File::open(parent)
                    .and_then(|dir| dir.sync_all())
                    .map_err(|_| Exit::Member(MemberError::Io))?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let saved = read_exact(path, payment_manifest::MAX_MANIFEST, true)?;
                if saved.as_slice() == bytes {
                    Ok(false)
                } else {
                    Err(Exit::Member(MemberError::Identity))
                }
            }
            Err(_) => Err(Exit::Member(MemberError::Io)),
        }
    })();
    fs::remove_file(staging).map_err(|_| Exit::Member(MemberError::Io))?;
    result
}

#[cfg(test)]
mod proposal_tests {
    use super::*;

    #[test]
    fn imported_manifest_is_private_and_conflicting_replay_is_rejected() {
        let root = std::env::temp_dir().join(format!(
            "loki-proposals-{}-{}",
            std::process::id(),
            hex_id(blake3::hash(b"proposal-test").as_bytes())
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        create_private_dir(&root).unwrap();
        let payment = root.join("payment.json");
        assert!(create_private_file(&payment, b"one").unwrap());
        assert!(!create_private_file(&payment, b"one").unwrap());
        assert!(create_private_file(&payment, b"two").is_err());
        assert_eq!(fs::read(&payment).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&payment).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}

fn export_signing(
    root: &Path,
    pass: &Path,
    roster: &Path,
    work: &Path,
    attempt: Id32,
) -> Result<(), Exit> {
    let session = open_session(root, pass, roster)?;
    let work = checked_work(&session, root, work, attempt)?;
    let count = export_saved_signing(&session, &work)?;
    println!("exported_signing={count}");
    Ok(())
}

struct PaymentWork {
    path: PathBuf,
    context: SessionContext,
    scope: Id32,
}

fn checked_work(session: &Session, root: &Path, work: &Path, attempt: Id32) -> Result<PaymentWork, Exit> {
    let payments = payments_path(root, work.parent().ok_or(Exit::Usage)?)?;
    check_private_dir(&payments)?;
    let name = work.file_name().and_then(|name| name.to_str()).ok_or(Exit::Usage)?;
    let path = payments.join(name);
    check_private_dir(&path)?;
    let manifest = read_exact(&path.join("payment.json"), payment_manifest::MAX_MANIFEST, true)?;
    let (context, proposer) = checked_proposal(&session.member, &manifest)?;
    let scope = proposal_scope(&context, proposer);
    if name != hex_id(&scope) || context.attempt.0 != attempt {
        return Err(Exit::Member(MemberError::Permissions));
    }
    Ok(PaymentWork { path, context, scope })
}

fn signing_peer(member: &loki_relay_protocol::types::MemberPublic) -> PublicIdentity {
    PublicIdentity { id: member.id, signing: member.signing, encryption: member.encryption }
}

fn payment_wire(message: &OpenedMessage) -> bool {
    match message.kind() {
        MessageKind::Commitment | MessageKind::Share => true,
        MessageKind::Package => message.sender() == message.context().signers[0],
        _ => false,
    }
}

fn save_signing(session: &mut Session, work: &PaymentWork, wire: &[u8], request: Id32) -> Result<RecoveryLogical, Exit> {
    let valid = session.member.roster.members.iter().any(|member| {
        session.signing_identity.open_sent_session(&signing_peer(member), &work.context, wire)
            .is_ok_and(|message| payment_wire(&message))
    });
    if !valid {
        return Err(Exit::Member(MemberError::Identity));
    }
    save_payload(session, wire, request, Some(work.context.attempt.0))
}

/// Append only exact-context messages sealed by their outer author to this member.
fn export_saved_signing(session: &Session, work: &PaymentWork) -> Result<usize, Exit> {
    let mail = work.path.join("mailbox");
    let mailbox = Mailbox::new(&mail).map_err(|_| Exit::Member(MemberError::Io))?;
    // The signing CLI may have created this inside the already private work directory.
    if !fs::symlink_metadata(&mail).is_ok_and(|meta| meta.is_dir()) {
        return Err(Exit::Member(MemberError::Permissions));
    }
    let mut count = 0;
    visit_pages(
        |after| session.db.recover_incoming_originals(after, PAGE),
        |row| {
            // The old outer attempt tag is a search hint, never an authorization or work key.
            if row.session != Some(work.context.attempt.0) || row.kind != 1 {
                return Ok(());
            }
            let Ok(opened) =
                session
                    .db
                    .open_incoming(&session.member.roster, &session.member.identity, &row)
            else {
                return Ok(());
            };
            let body = opened.message().body();
            let Payload::Test(wire) = &body.payload else {
                return Ok(());
            };
            let Some(sender) = session.member.roster.members.iter().find(|m| m.id == body.key.sender) else {
                return Ok(());
            };
            if !session.signing_identity.open_session(&signing_peer(sender), &work.context, wire)
                .is_ok_and(|message| payment_wire(&message)) {
                return Ok(());
            }
            mailbox
                .append(wire)
                .map_err(|_| Exit::Member(MemberError::Io))?;
            count += 1;
            Ok(())
        },
    )?;
    Ok(count)
}

/// One payment sync in one session: what `send-proposal` for each queued proposal,
/// `send-signing` for each saved wire, `upload`, `poll --once`, `import-proposals`,
/// `export-signing` for each attempt and `status` did as separate processes.
///
/// The plan is a JSON file `{"proposals":[<payment.json>…], "signing":[{"attempt",
/// "work","wire"}…], "export":[{"attempt","work"}…], "import":bool}`. Every message is
/// committed before any request, then one poll uploads and receives. The report on
/// stdout is JSON: for each proposal and signing message its id and whether it is
/// stored on every member's relays, the imported and rejected proposal counts, and
/// the exported wire count. Report keys are the scoped work directory names.
fn payment_sync(root: &Path, pass: &Path, roster: &Path, plan: &Path) -> Result<(), Exit> {
    let raw = read_exact(plan, 1024 * 1024, false)?;
    let plan: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| Exit::Usage)?;
    let list = |name: &str| -> Result<Vec<serde_json::Value>, Exit> {
        match plan.get(name) {
            None => Ok(Vec::new()),
            Some(serde_json::Value::Array(items)) => Ok(items.clone()),
            Some(_) => Err(Exit::Usage),
        }
    };
    let text = |item: &serde_json::Value, name: &str| -> Result<String, Exit> {
        item.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(Exit::Usage)
    };
    let proposals = list("proposals")?
        .iter()
        .map(|item| item.as_str().map(PathBuf::from).ok_or(Exit::Usage))
        .collect::<Result<Vec<_>, _>>()?;
    let signing = list("signing")?;
    let exports = list("export")?;
    let import = match plan.get("import") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(_) => return Err(Exit::Usage),
    };
    let mut session = open_session(root, pass, roster)?;
    let mut sent_proposals = Vec::new();
    for path in &proposals {
        let manifest = read_exact(path, payment_manifest::MAX_MANIFEST, false)?;
        let (_, scope, saved) = save_proposal(&mut session, root, &manifest)?;
        sent_proposals.push((scope, saved));
    }
    let plan_work = |session: &Session, item: &serde_json::Value| {
        checked_work(session, root, Path::new(&text(item, "work")?), parse_id(&text(item, "attempt")?)?)
    };
    let exports = exports.iter().map(|item| plan_work(&session, item)).collect::<Result<Vec<_>, _>>()?;
    let mut sent_signing = Vec::new();
    for item in &signing {
        let work = plan_work(&session, item)?;
        let payload = read_exact(Path::new(&text(item, "wire")?), MAX_PAYLOAD, false)?;
        let request = *blake3::hash(&payload).as_bytes();
        let saved = save_signing(&mut session, &work, &payload, request)?;
        sent_signing.push((work.scope, saved));
    }
    let (config, self_route) = routed(&session)?;
    let now = now_ms()?;
    runtime()?
        .block_on(poll_once(
            &mut session.db,
            &RelayHttp::new().map_err(Exit::Client)?,
            &session.member.identity,
            &session.member.roster,
            &config,
            &self_route,
            now,
        ))
        .map_err(Exit::Client)?;
    let (imported, rejected) = if import {
        import_saved_proposals(&session, root, &root.join("payments"), false)?
    } else {
        (0, 0)
    };
    let mut exported = serde_json::Map::new();
    for work in &exports {
        let count = export_saved_signing(&session, work)?;
        exported.insert(hex_id(&work.scope), count.into());
    }
    let stored = |session: &mut Session, logical: &RecoveryLogical| -> Result<bool, Exit> {
        match session.db.delivery_report(
            &session.member.roster,
            &session.member.identity,
            logical,
            &config,
            &self_route,
        ) {
            Ok(report) => Ok(report.whole_vault()),
            Err(ClientError::Config) => Ok(false),
            Err(error) => Err(Exit::Client(error)),
        }
    };
    let mut proposal_report = serde_json::Map::new();
    for (scope, logical) in &sent_proposals {
        proposal_report.insert(
            hex_id(scope),
            serde_json::json!({"message": hex_id(&logical.key.message), "stored": stored(&mut session, logical)?}),
        );
    }
    let mut signing_report = serde_json::Map::new();
    for (scope, logical) in &sent_signing {
        let row = serde_json::json!({"message": hex_id(&logical.key.message), "stored": stored(&mut session, logical)?});
        let entry = signing_report
            .entry(hex_id(scope))
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let serde_json::Value::Array(items) = entry {
            items.push(row);
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "proposals": proposal_report,
            "signing": signing_report,
            "imported": imported,
            "rejected": rejected,
            "exported": exported,
        })
    );
    Ok(())
}

fn upload(root: &Path, pass: &Path, roster: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let (config, self_route) = routed(&session)?;
    let now = now_ms()?;
    let logicals = logical_page(&session.db)?;
    let runtime = runtime()?;
    let http = RelayHttp::new().map_err(Exit::Client)?;
    runtime.block_on(async {
        for logical in &logicals {
            let pass = upload_pending(
                &mut session.db,
                &http,
                logical,
                &session.member.roster,
                &session.member.identity,
                &config,
                &self_route,
                now,
                ThirdPass::StopAfterStored,
            )
            .await
            .map_err(Exit::Client)?;
            println!(
                "upload message={} digest={} needs_route={} stopped_third={}",
                hex_id(&logical.key.message),
                hex_id(&logical.digest),
                member_list(&pass.needs_route),
                u8::from(pass.stopped_third)
            );
        }
        Ok(())
    })
}

fn poll(root: &Path, pass: &Path, roster: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let (config, self_route) = routed(&session)?;
    let now = now_ms()?;
    let runtime = runtime()?;
    runtime
        .block_on(poll_once(
            &mut session.db,
            &RelayHttp::new().map_err(Exit::Client)?,
            &session.member.identity,
            &session.member.roster,
            &config,
            &self_route,
            now,
        ))
        .map_err(Exit::Client)?;
    println!("poll=ok");
    Ok(())
}

fn status(
    root: &Path,
    pass: &Path,
    roster: &Path,
    verify_relays: bool,
    diagnostics: bool,
    attempt: Option<Id32>,
) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    println!("section=local");
    println!("receipt_digest_alg=blake3");
    println!("member={}", session.member.identity.public().id);
    print_reference(&session)?;
    print_authenticated_inboxes(&session)?;
    let mut logicals = logical_page(&session.db)?;
    let mut incoming = page_rows(
        |after| session.db.recover_incoming_originals(after, PAGE),
        usize::MAX,
    )?;
    let mut acks = page_rows(
        |after| session.db.recover_ack_links(after, PAGE),
        usize::MAX,
    )?;
    if let Some(attempt) = attempt {
        logicals.retain(|record| record.session == Some(attempt));
        incoming.retain(|record| record.session == Some(attempt));
        acks.retain(|ack| {
            logicals
                .iter()
                .any(|record| record.key == ack.key && record.digest == ack.digest)
                || incoming
                    .iter()
                    .any(|record| record.key == ack.key && record.digest == ack.digest)
        });
    }
    println!("logical_count={}", logicals.len());
    println!("incoming_count={}", incoming.len());
    println!("ack_count={}", acks.len());
    println!(
        "pending_transfers={}",
        session.db.pending_transfer_count().map_err(Exit::Client)?
    );
    let routed = routed(&session);
    for logical in &logicals {
        print_message(&mut session, logical, routed.as_ref())?;
    }
    for record in &incoming {
        print_incoming(&session, record)?;
    }
    for ack in &acks {
        println!(
            "ack sender={} id={} digest={} author={} ack_message={} request={}",
            ack.key.sender,
            hex_id(&ack.key.message),
            hex_id(&ack.digest),
            ack.ack_author,
            hex_id(&ack.ack_message),
            hex_id(&ack.request_id)
        );
    }
    if !verify_relays {
        if diagnostics {
            print_diagnostics(&session)?;
        }
        return Ok(());
    }
    let local = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
        .ok_or(Exit::Member(MemberError::Sealed))?;
    if local.own.len() != 3 {
        return Err(Exit::Member(MemberError::Sealed));
    }
    let own = local
        .own
        .iter()
        .map(|inbox| OwnInbox {
            route: inbox.route.clone(),
            read: Secret32::from_bytes(*inbox.read.as_bytes()),
        })
        .collect::<Vec<_>>();
    drop(local);
    println!("section=remote");
    println!("receipt_digest_alg=blake3");
    let runtime = runtime()?;
    let http = RelayHttp::new().map_err(Exit::Client)?;
    let member_id = session.member.identity.public().id;
    // Read the owner's inboxes from cursor 0. Entries and object gets do not advance saved cursors.
    runtime.block_on(async {
        for inbox in &own {
            match verify_inbox(&http, inbox).await {
                Ok(snapshot) => println!(
                    "remote_inbox member={member_id} pin={} run={} mailbox={} entries={} failures={} result={}",
                    hex_id(&inbox.route.pin.key),
                    hex_id(&inbox.route.pin.run),
                    hex_id(&inbox.route.mailbox),
                    snapshot.entries,
                    snapshot.failures,
                    if snapshot.failures == 0 { "ok" } else { "partial" }
                ),
                Err(error) => println!(
                    "route_error pin={} run={} mailbox={} result=error code={}",
                    hex_id(&inbox.route.pin.key),
                    hex_id(&inbox.route.pin.run),
                    hex_id(&inbox.route.mailbox),
                    error.code()
                ),
            }
        }
        Ok(())
    })?;
    if diagnostics {
        print_diagnostics(&session)?;
    }
    Ok(())
}

fn readiness(root: &Path, pass: &Path, roster: &Path) -> Result<(), Exit> {
    let session = open_session(root, pass, roster)?;
    let Some(config) = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
    else {
        println!("inboxes=0 peers=0 live=0 routable=0");
        return Ok(());
    };
    let inboxes = config.own.len();
    let peers = config.peer_wires.len();
    let routable = inboxes == 3
        && peers == session.member.roster.members.len() - 1
        && session.configs.routing(&session.db, &session.member).is_ok();
    let http = RelayHttp::new().map_err(Exit::Client)?;
    let live = runtime()?.block_on(async {
        let mut live = 0;
        for inbox in &config.own {
            if http
                .entries(&inbox.route, &inbox.read, 0, Some(1))
                .await
                .is_ok()
            {
                live += 1;
            }
        }
        live
    });
    println!("inboxes={inboxes} peers={peers} live={live} routable={}", u8::from(routable));
    Ok(())
}

fn print_diagnostics(session: &Session) -> Result<(), Exit> {
    // Transport counters and capture metadata. They do not authenticate a message.
    let cursors = page_rows(
        |after| session.db.recover_route_cursors(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let pending = page_rows(
        |after| session.db.recover_pending_downloads(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let download_rejections = page_rows(
        |after| session.db.recover_download_rejections(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let source_rejections = page_rows(
        |after| session.db.recover_source_rejections(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let uploads = page_rows(
        |after| session.db.recover_uploads(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let samples = page_rows(
        |after| session.db.recover_diagnostic_samples(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let sample_bytes = samples.iter().try_fold(0u64, |total, sample| {
        total
            .checked_add(sample.sample_len)
            .ok_or(Exit::Client(ClientError::Capacity))
    })?;
    println!("section=diagnostics");
    println!("diagnostics_authority=transport");
    println!("route_cursor_count={}", cursors.len());
    println!("pending_download_count={}", pending.len());
    println!("download_rejection_count={}", download_rejections.len());
    println!("source_rejection_count={}", source_rejections.len());
    let upload_pending_count = uploads.iter().filter(|upload| !upload.acknowledged).count();
    println!("upload_work_count={}", uploads.len());
    println!("upload_pending_count={upload_pending_count}");
    println!("sample_count={}", samples.len());
    println!("sample_bytes={sample_bytes}");
    for cursor in &cursors {
        println!(
            "route_cursor pin={} run={} mailbox={} position={}",
            hex_id(&cursor.relay_key),
            hex_id(&cursor.run),
            hex_id(&cursor.mailbox),
            cursor.position
        );
    }
    for task in &pending {
        println!(
            "pending_download pin={} run={} mailbox={} hash={} length={} attempts={} retry_at={}",
            hex_id(&task.relay_key),
            hex_id(&task.run),
            hex_id(&task.mailbox),
            hex_id(&task.source_hash),
            task.wire_length,
            task.attempts,
            task.retry_at
        );
    }
    for rejection in &download_rejections {
        println!(
            "download_rejection pin={} run={} mailbox={} hash={} {}",
            hex_id(&rejection.relay_key),
            hex_id(&rejection.run),
            hex_id(&rejection.mailbox),
            hex_id(&rejection.source_hash),
            public_reason(&rejection.reason)
        );
    }
    for rejection in &source_rejections {
        println!(
            "source_rejection root={} {}",
            hex_id(&rejection.root_hash),
            public_reason(&rejection.reason)
        );
    }
    for upload in &uploads {
        println!(
            "upload_retry message={} recipient={} hash={} pin={} run={} mailbox={} acknowledged={} attempts={} retry_at={}",
            hex_id(&upload.key.message),
            upload.recipient,
            hex_id(&upload.hash),
            hex_id(&upload.relay_key),
            hex_id(&upload.run),
            hex_id(&upload.mailbox),
            u8::from(upload.acknowledged),
            upload.attempts,
            upload.retry_at
        );
    }
    for sample in &samples {
        println!(
            "diagnostic_sample pin={} run={} mailbox={} sequence={} length={}",
            hex_id(&sample.relay_key),
            hex_id(&sample.run),
            hex_id(&sample.mailbox),
            sample.sequence,
            sample.sample_len
        );
    }
    Ok(())
}

fn public_reason(reason: &str) -> String {
    // A stored reason is metadata. Only a short token is a status field.
    let token = !reason.is_empty()
        && reason.len() <= 64
        && reason.as_bytes()[0].is_ascii_lowercase()
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if token {
        format!("reason={reason}")
    } else {
        format!("reason=other length={}", reason.len())
    }
}

fn prepare_selected_rotation(session: &mut Session) -> Result<(), Exit> {
    let local = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
        .ok_or(Exit::Member(MemberError::Sealed))?;
    // Authenticated sealed state chooses the generation. A later command must not replay the first prepare.
    local.authenticated(&session.member).map_err(Exit::Member)?;
    if local.rotated.is_some() {
        session
            .configs
            .prepare_next_rotation(&mut session.db, &session.member)
            .map_err(Exit::Member)?;
    } else {
        session
            .configs
            .prepare_rotation(&mut session.db, &session.member)
            .map_err(Exit::Member)?;
    }
    Ok(())
}

fn print_incoming(
    session: &Session,
    record: &loki_relay_client::IncomingOriginal,
) -> Result<(), Exit> {
    let readiness = committed_readiness(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &record.key,
        &record.digest,
    )
    .map_err(Exit::Client)?;
    let received = received_status(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &record.key,
        &record.digest,
    )
    .map_err(Exit::Client)?;
    println!(
        "incoming sender={} id={} digest={} kind={} session={} readiness={} received_whole={} received_author={} root={}",
        record.key.sender,
        hex_id(&record.key.message),
        hex_id(&record.digest),
        kind_name(record.kind),
        session_text(record.session.as_ref()),
        readiness_name(readiness),
        u8::from(received.whole_vault()),
        u8::from(received.author_committed()),
        hex_id(&record.source_root)
    );
    for member in &session.member.roster.members {
        println!(
            "incoming_received_member sender={} id={} digest={} member={} value={}",
            record.key.sender,
            hex_id(&record.key.message),
            hex_id(&record.digest),
            member.id,
            u8::from(received.member_received(member.id))
        );
    }
    Ok(())
}

fn print_message(
    session: &mut Session,
    logical: &RecoveryLogical,
    routed: Result<&(ClientConfig, AuthenticatedDescriptor), &Exit>,
) -> Result<(), Exit> {
    let readiness = committed_readiness(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &logical.key,
        &logical.digest,
    )
    .map_err(Exit::Client)?;
    let received = received_status(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &logical.key,
        &logical.digest,
    )
    .map_err(Exit::Client)?;
    let report = match routed {
        Ok((config, self_route)) => match session.db.delivery_report(
            &session.member.roster,
            &session.member.identity,
            logical,
            config,
            self_route,
        ) {
            Ok(report) => Some(report),
            Err(ClientError::Config) => None,
            Err(error) => return Err(Exit::Client(error)),
        },
        Err(_) => None,
    };
    let recipients = session
        .db
        .recover_recipients(&logical.key)
        .map_err(Exit::Client)?;
    let needs_route = recipients
        .iter()
        .filter(|recipient| recipient.needs_route)
        .count();
    println!(
        "message sender={} id={} digest={} kind={} session={} readiness={} stored_whole={} received_whole={} received_author={} needs_route={}",
        logical.key.sender,
        hex_id(&logical.key.message),
        hex_id(&logical.digest),
        kind_name(logical.kind),
        session_text(logical.session.as_ref()),
        readiness_name(readiness),
        report.as_ref().map(|item| u8::from(item.whole_vault()).to_string()).unwrap_or_else(|| "unavailable".to_owned()),
        u8::from(received.whole_vault()),
        u8::from(received.author_committed()),
        needs_route
    );
    for member in &session.member.roster.members {
        println!(
            "received_member id={} value={}",
            member.id,
            u8::from(received.member_received(member.id))
        );
    }
    if let Some(report) = &report {
        for member in &session.member.roster.members {
            println!(
                "stored_member id={} value={}",
                member.id,
                u8::from(report.member_stored(member.id))
            );
            for (pin, run) in report.member_pins(member.id) {
                println!(
                    "stored_pin scope=member member={} pin={} run={}",
                    member.id,
                    hex_id(pin),
                    hex_id(run)
                );
            }
        }
        for (pin, run) in report.whole_pins() {
            println!(
                "stored_pin scope=whole member=- pin={} run={}",
                hex_id(pin),
                hex_id(run)
            );
        }
    }
    for recipient in &recipients {
        println!(
            "recipient id={} root={} needs_route={}",
            recipient.recipient,
            hex_id(&recipient.root_hash),
            u8::from(recipient.needs_route)
        );
        let mut after = None;
        loop {
            let page = session
                .db
                .recover_requirements(&logical.key, recipient.recipient, after.as_ref(), PAGE)
                .map_err(Exit::Client)?;
            if page.is_empty() {
                break;
            }
            let last = page.last().map(|item| item.hash);
            if last == after {
                return Err(Exit::Client(ClientError::Storage));
            }
            let short = page.len() < usize::from(PAGE);
            for object in &page {
                println!(
                    "object recipient={} ordinal={} hash={} length={}",
                    recipient.recipient,
                    object.ordinal,
                    hex_id(&object.hash),
                    object.length
                );
            }
            if short {
                break;
            }
            after = last;
        }
    }
    for upload in uploads_for(&session.db, &logical.key)? {
        let mut saved = session.db.saved_receipt(&upload).map_err(Exit::Client)?;
        let receipt_digest = saved.as_ref().map(|bytes| digest_hex(bytes));
        if let Some(bytes) = &mut saved {
            bytes.zeroize();
        }
        println!(
            "upload recipient={} hash={} pin={} run={} acknowledged={} receipt_digest={}",
            upload.recipient,
            hex_id(&upload.hash),
            hex_id(&upload.relay_key),
            hex_id(&upload.run),
            u8::from(upload.acknowledged),
            receipt_digest.unwrap_or_else(|| "-".to_owned())
        );
    }
    Ok(())
}

fn print_authenticated_inboxes(session: &Session) -> Result<(), Exit> {
    let Some(local) = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
    else {
        return Ok(());
    };
    match local.authenticated(&session.member) {
        Ok(config) => print_own_inboxes(session.member.identity.public().id, &config.own),
        Err(error) => println!("inbox_error={}", error.code()),
    }
    Ok(())
}

fn print_own_inboxes(member_id: u16, own: &[loki_relay_client::OwnerInbox]) {
    for inbox in own {
        println!(
            "inbox member={member_id} pin={} run={} mailbox={} append_revision={} endpoint={}",
            hex_id(&inbox.route.pin.key),
            hex_id(&inbox.route.pin.run),
            hex_id(&inbox.route.mailbox),
            inbox.route.append_revision,
            inbox.route.endpoint
        );
    }
}

struct RemoteSnapshot {
    entries: u64,
    failures: u64,
}

async fn verify_inbox(http: &RelayHttp, inbox: &OwnInbox) -> Result<RemoteSnapshot, ClientError> {
    let mut after = 0;
    let mut seen = Vec::new();
    let mut entries = 0u64;
    let mut failures = 0u64;
    loop {
        let page = http
            .entries(&inbox.route, &inbox.read, after, Some(ENTRY_LIMIT))
            .await?;
        for entry in page.entries() {
            entries = entries.saturating_add(1);
            let body = entry.receipt().body();
            match http.get(&inbox.route, &inbox.read, entry.hash()).await {
                Ok(mut object) => {
                    let retrieved_len = object.wire.len() as u64;
                    let retrieved_hash = object.hash;
                    object.wire.zeroize();
                    let agreed = retrieved_hash == body.hash
                        && retrieved_hash == *entry.hash()
                        && retrieved_len == body.wire_length
                        && retrieved_len == entry.wire_length();
                    if !agreed {
                        failures = failures.saturating_add(1);
                        println!(
                            "retrieval_error pin={} run={} mailbox={} sequence={} hash={} length={} receipt_digest={} retrieved_hash={} retrieved_length={} code={}",
                            hex_id(&body.pin.key),
                            hex_id(&body.pin.run),
                            hex_id(&body.mailbox),
                            body.sequence,
                            hex_id(&body.hash),
                            body.wire_length,
                            digest_hex(entry.receipt().bytes()),
                            hex_id(&retrieved_hash),
                            retrieved_len,
                            ClientError::Receipt.code()
                        );
                        continue;
                    }
                    println!(
                        "entry pin={} run={} mailbox={} sequence={} hash={} length={} receipt_digest={} retrieved_hash={} retrieved_length={}",
                        hex_id(&body.pin.key),
                        hex_id(&body.pin.run),
                        hex_id(&body.mailbox),
                        body.sequence,
                        hex_id(&body.hash),
                        body.wire_length,
                        digest_hex(entry.receipt().bytes()),
                        hex_id(&retrieved_hash),
                        retrieved_len
                    );
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    println!(
                        "retrieval_error pin={} run={} mailbox={} sequence={} hash={} length={} receipt_digest={} code={}",
                        hex_id(&body.pin.key),
                        hex_id(&body.pin.run),
                        hex_id(&body.mailbox),
                        body.sequence,
                        hex_id(&body.hash),
                        body.wire_length,
                        digest_hex(entry.receipt().bytes()),
                        error.code()
                    );
                }
            }
        }
        if page.next() == page.high_water() {
            return Ok(RemoteSnapshot { entries, failures });
        }
        if page.next() <= after || seen.contains(&page.next()) {
            return Err(ClientError::Cursor);
        }
        seen.push(page.next());
        after = page.next();
    }
}

fn provision_inputs(
    manifest_dir: &Path,
    capability_dir: &Path,
) -> Result<(Vec<ProvisionTarget>, Vec<Secret32>), Exit> {
    let mut targets = Vec::new();
    for root in child_directories(manifest_dir)? {
        let mut lines = read_text(&root.join("manifest"), MAX_MANIFEST)?;
        if lines.len() != 3 || lines.iter().any(|line| line.is_empty()) {
            return Err(Exit::Member(MemberError::Bounds));
        }
        let endpoint = lines.remove(0);
        if endpoint.len() > 2048 || endpoint.chars().any(char::is_whitespace) {
            return Err(Exit::Member(MemberError::Bounds));
        }
        let quota_text = read_text(&root.join("mailbox-bytes"), 32)?;
        if quota_text.len() != 1 {
            return Err(Exit::Member(MemberError::Bounds));
        }
        let quota = parse_quota(&quota_text[0])?;
        targets.push(ProvisionTarget {
            pin: RelayPin {
                run: parse_id(&lines[0])?,
                key: parse_id(&lines[1])?,
            },
            endpoint,
            quota,
        });
    }
    if targets.len() != 3 {
        return Err(Exit::Member(MemberError::Bounds));
    }
    targets.sort_by(|left, right| left.pin.key.cmp(&right.pin.key));
    if targets
        .windows(2)
        .any(|pair| pair[0].pin.key == pair[1].pin.key)
        || targets[0].pin.run == targets[1].pin.run
        || targets[0].pin.run == targets[2].pin.run
        || targets[1].pin.run == targets[2].pin.run
    {
        return Err(Exit::Member(MemberError::Bounds));
    }
    let mut names = child_files(capability_dir)?;
    if names.len() != 3 {
        return Err(Exit::Member(MemberError::Bounds));
    }
    names.sort();
    let mut capabilities = Vec::new();
    for target in &targets {
        let expected = hex_id(&target.pin.key);
        let path = names
            .iter()
            .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(expected.as_str()))
            .ok_or(Exit::Member(MemberError::Bounds))?;
        let mut bytes = read_exact(path, 32, true)?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(Exit::Member(MemberError::Bounds));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        bytes.zeroize();
        capabilities.push(Secret32::from_bytes(secret));
        secret.zeroize();
    }
    Ok((targets, capabilities))
}

fn routed(session: &Session) -> Result<(ClientConfig, AuthenticatedDescriptor), Exit> {
    let config = session
        .configs
        .routing(&session.db, &session.member)
        .map_err(Exit::Member)?;
    let local = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
        .ok_or(Exit::Member(MemberError::Sealed))?;
    let wire = local
        .self_wire
        .as_ref()
        .ok_or(Exit::Member(MemberError::Sealed))?;
    let self_route = open_descriptor(&session.member.identity, &session.member.roster, wire)
        .map_err(Exit::Client)?;
    Ok((config, self_route))
}

fn print_reference(session: &Session) -> Result<(), Exit> {
    match session.db.config_reference().map_err(Exit::Client)? {
        Some(reference) => {
            println!(
                "config revision={} hash={}",
                reference.revision(),
                hex_id(reference.hash())
            );
        }
        None => println!("config absent=1"),
    }
    Ok(())
}

fn print_logical(db: &ClientStore, logical: &RecoveryLogical) -> Result<(), Exit> {
    let recipients = db.recover_recipients(&logical.key).map_err(Exit::Client)?;
    let needs_route = recipients
        .iter()
        .filter(|recipient| recipient.needs_route)
        .count();
    println!(
        "request message={} digest={} needs_route={}",
        hex_id(&logical.key.message),
        hex_id(&logical.digest),
        needs_route
    );
    Ok(())
}

fn logical_page(db: &ClientStore) -> Result<Vec<RecoveryLogical>, Exit> {
    page_rows(|after| db.recover_logical(after, PAGE), usize::MAX)
}

fn uploads_for(db: &ClientStore, key: &LogicalKey) -> Result<Vec<RecoveryUpload>, Exit> {
    let rows = page_rows(|after| db.recover_uploads(after, PAGE), usize::MAX)?;
    Ok(rows
        .into_iter()
        .filter(|upload| upload.key == *key)
        .collect())
}

fn visit_pages<T>(
    mut page: impl FnMut(u64) -> Result<Vec<T>, ClientError>,
    mut visit: impl FnMut(T) -> Result<(), Exit>,
) -> Result<(), Exit>
where
    T: Cursor,
{
    let mut after = 0;
    loop {
        let batch = page(after).map_err(Exit::Client)?;
        if batch.is_empty() {
            return Ok(());
        }
        let next = batch.last().map(Cursor::cursor).unwrap_or(after);
        if next <= after {
            return Err(Exit::Client(ClientError::Storage));
        }
        let short = batch.len() < usize::from(PAGE);
        for row in batch {
            visit(row)?;
        }
        if short {
            return Ok(());
        }
        after = next;
    }
}

fn page_rows<T>(
    mut page: impl FnMut(u64) -> Result<Vec<T>, ClientError>,
    max_rows: usize,
) -> Result<Vec<T>, Exit>
where
    T: Cursor,
{
    let mut after = 0;
    let mut rows = Vec::new();
    loop {
        let batch = page(after).map_err(Exit::Client)?;
        if batch.is_empty() {
            break;
        }
        let next = batch.last().map(Cursor::cursor).unwrap_or(after);
        if next <= after {
            return Err(Exit::Client(ClientError::Storage));
        }
        if rows.len().saturating_add(batch.len()) > max_rows {
            return Err(Exit::Client(ClientError::Capacity));
        }
        let short = batch.len() < usize::from(PAGE);
        rows.extend(batch);
        if short {
            break;
        }
        after = next;
    }
    Ok(rows)
}

trait Cursor {
    fn cursor(&self) -> u64;
}

macro_rules! cursor_row {
    ($ty:ty) => {
        impl Cursor for $ty {
            fn cursor(&self) -> u64 {
                self.cursor
            }
        }
    };
}

cursor_row!(RecoveryLogical);
cursor_row!(loki_relay_client::IncomingOriginal);
cursor_row!(loki_relay_client::AckLink);
cursor_row!(RecoveryUpload);
cursor_row!(RouteCursor);
cursor_row!(PendingDownload);
cursor_row!(DownloadRejection);
cursor_row!(SourceRejection);

impl Cursor for DiagnosticSample {
    fn cursor(&self) -> u64 {
        u64::try_from(self.id).unwrap_or(0)
    }
}

fn child_directories(path: &Path) -> Result<Vec<PathBuf>, Exit> {
    let mut found = Vec::new();
    for entry in read_children(path)? {
        let metadata = fs::symlink_metadata(&entry).map_err(|_| Exit::Member(MemberError::Io))?;
        if metadata.is_dir() {
            found.push(entry);
        } else {
            return Err(Exit::Member(MemberError::Bounds));
        }
    }
    if found.len() != 3 {
        found.clear();
        return Err(Exit::Member(MemberError::Bounds));
    }
    Ok(found)
}

fn child_files(path: &Path) -> Result<Vec<PathBuf>, Exit> {
    let mut found = Vec::new();
    for entry in read_children(path)? {
        let metadata = fs::symlink_metadata(&entry).map_err(|_| Exit::Member(MemberError::Io))?;
        if !metadata.is_file() {
            return Err(Exit::Member(MemberError::Bounds));
        }
        private_file(&metadata)?;
        found.push(entry);
    }
    Ok(found)
}

fn read_children(path: &Path) -> Result<Vec<PathBuf>, Exit> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Exit::Member(MemberError::Io))?;
    if !metadata.is_dir() {
        return Err(Exit::Member(MemberError::Permissions));
    }
    let entries = fs::read_dir(path).map_err(|_| Exit::Member(MemberError::Io))?;
    entries
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|_| Exit::Member(MemberError::Io))
        })
        .collect()
}

fn read_text(path: &Path, max: usize) -> Result<Vec<String>, Exit> {
    let bytes = read_exact(path, max, false)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Exit::Member(MemberError::Bounds))?;
    if text.contains('\0') {
        return Err(Exit::Member(MemberError::Bounds));
    }
    Ok(text.lines().map(str::to_owned).collect())
}

fn read_exact(path: &Path, max: usize, private: bool) -> Result<zeroize::Zeroizing<Vec<u8>>, Exit> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Exit::Member(MemberError::Io))?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err(Exit::Member(if metadata.is_file() {
            MemberError::Bounds
        } else {
            MemberError::Permissions
        }));
    }
    if private {
        private_file(&metadata)?;
    }
    let mut file = fs::File::open(path).map_err(|_| Exit::Member(MemberError::Io))?;
    let mut bytes = vec![0; metadata.len() as usize];
    io::Read::read_exact(&mut file, &mut bytes).map_err(|_| Exit::Member(MemberError::Io))?;
    Ok(zeroize::Zeroizing::new(bytes))
}

fn private_file(metadata: &fs::Metadata) -> Result<(), Exit> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        extern "C" {
            fn geteuid() -> u32;
        }
        let uid = unsafe { geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(Exit::Member(MemberError::Permissions));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(Exit::Member(MemberError::Unsupported))
    }
}

fn parse_quota(text: &str) -> Result<u64, Exit> {
    let text = text.trim_end_matches(['\r', '\n']);
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Exit::Member(MemberError::Bounds));
    }
    let quota = text
        .parse::<u64>()
        .map_err(|_| Exit::Member(MemberError::Bounds))?;
    if quota == 0 || quota > i64::MAX as u64 {
        return Err(Exit::Member(MemberError::Bounds));
    }
    Ok(quota)
}

fn parse_id(text: &str) -> Result<Id32, Exit> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Exit::Member(MemberError::Bounds));
    }
    let mut id = [0u8; 32];
    hex::decode_to_slice(text, &mut id).map_err(|_| Exit::Member(MemberError::Bounds))?;
    Ok(id)
}

fn hex_id(id: &Id32) -> String {
    hex::encode(id)
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

fn wipe_test(body: &mut MessageBody) {
    if let Payload::Test(data) = &mut body.payload {
        data.zeroize();
    }
}

fn kind_name(kind: u8) -> String {
    match kind {
        1 => "test".to_owned(),
        2 => "received".to_owned(),
        other => other.to_string(),
    }
}

fn session_text(session: Option<&Id32>) -> String {
    session.map(hex_id).unwrap_or_else(|| "-".to_owned())
}

fn readiness_name(readiness: CandidateReadiness) -> &'static str {
    match readiness {
        CandidateReadiness::Ready => "ready",
        CandidateReadiness::Pending => "pending",
    }
}

fn member_list(ids: &[u16]) -> String {
    if ids.is_empty() {
        "-".to_owned()
    } else {
        ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn now_ms() -> Result<u64, Exit> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Exit::Member(MemberError::Io))?
        .as_millis();
    u64::try_from(millis).map_err(|_| Exit::Client(ClientError::Capacity))
}

fn runtime() -> Result<RelayRuntime, Exit> {
    RelayRuntime::new().map_err(|_| Exit::Member(MemberError::Io))
}

#[cfg(test)]
mod pagination_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn provisioning_rejects_duplicate_run_ids_before_creating_inboxes() {
        use std::os::unix::fs::PermissionsExt;

        let mut random = [0u8; 8];
        OsRng.try_fill_bytes(&mut random).unwrap();
        let root = env::temp_dir().join(format!(
            "loki-relay-runs-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        let manifests = root.join("manifests");
        let capabilities = root.join("capabilities");
        fs::create_dir_all(&manifests).unwrap();
        fs::create_dir(&capabilities).unwrap();
        for index in 1..=3u8 {
            let relay = manifests.join(index.to_string());
            fs::create_dir(&relay).unwrap();
            fs::write(
                relay.join("manifest"),
                format!(
                    "http://127.0.0.1:{}\n{}\n{}\n",
                    39000 + index as u16,
                    hex_id(&[if index == 3 { 3 } else { 1 }; 32]),
                    hex_id(&[index; 32]),
                ),
            )
            .unwrap();
            fs::write(relay.join("mailbox-bytes"), "1024\n").unwrap();
            let capability = capabilities.join(hex_id(&[index; 32]));
            fs::write(&capability, [index; 32]).unwrap();
            fs::set_permissions(&capability, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            provision_inputs(&manifests, &capabilities),
            Err(Exit::Member(MemberError::Bounds))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    fn sample(id: i64) -> DiagnosticSample {
        DiagnosticSample {
            id,
            relay_key: [0; 32],
            run: [0; 32],
            mailbox: [0; 32],
            sequence: 1,
            sample_len: 0,
        }
    }

    #[test]
    fn diagnostic_pagination_enforces_capacity() {
        for count in [399, 400, 401] {
            let rows = page_rows(
                |after| {
                    Ok(((after + 1)..=count.min(after + u64::from(PAGE)))
                        .map(|id| sample(id as i64))
                        .collect())
                },
                DIAGNOSTIC_ROW_BOUND,
            );
            if count <= 400 {
                assert_eq!(rows.ok().unwrap().len(), count as usize);
            } else {
                assert!(matches!(rows, Err(Exit::Client(ClientError::Capacity))));
            }
        }
    }

    #[test]
    fn diagnostic_pagination_rejects_invalid_or_stalled_cursors() {
        for id in [-1, 0] {
            let rows = page_rows(|_| Ok(vec![sample(id)]), DIAGNOSTIC_ROW_BOUND);
            assert!(matches!(rows, Err(Exit::Client(ClientError::Storage))));
        }
        let rows = page_rows(
            |_| Ok((1..=i64::from(PAGE)).map(sample).collect()),
            DIAGNOSTIC_ROW_BOUND,
        );
        assert!(matches!(rows, Err(Exit::Client(ClientError::Storage))));
    }

    #[test]
    fn incoming_pages_are_visited_without_collecting_the_whole_inbox() {
        let count = u64::from(PAGE) * 2 + 1;
        let mut seen = Vec::new();
        visit_pages(
            |after| {
                Ok(((after + 1)..=count.min(after + u64::from(PAGE)))
                    .map(|id| sample(id as i64))
                    .collect())
            },
            |row| {
                seen.push(row.id);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen.len(), count as usize);
        assert_eq!(seen[0], 1);
        assert_eq!(seen.last().copied(), Some(count as i64));
    }
}
