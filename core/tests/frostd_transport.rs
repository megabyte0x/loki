//! WS3 acceptance: the new signer's v2 DKG and a rerandomized signing round-trip carried
//! over a transport (`docs/product/ws3-transport.md` §7). Every member is a
//! storage-backed `LocalSigner`: the DKG runs inside it through the shared core, and its
//! app only moves the [`DkgWire`]s the signer returns. Members send to the coordinator,
//! which logs each wire in its `RelayLog` before forwarding it and redelivers from the log
//! after a restart. Signing moves typed `Outbound` values only: commitments, the
//! proposer's candidate sealed to the other signer, the signing package, the randomizer
//! seed and the shares.
//!
//! Round two is a v2 envelope sealed under the two members' one-setup fresh keys, so the
//! relay (and anyone who records its traffic) carries only ciphertext that the long-lived
//! identity keys cannot open later. The leak-closure attack test itself is
//! `signer::local::setup_tests::recorded_relay_traffic_cannot_rebuild_the_group_key`.
//!
//! The offline test runs over an in-memory relay with the same `Transport` contract. The
//! live test needs a running frostd: set `FROSTD_URL` (e.g. `http://127.0.0.1:2744`); if
//! unset it prints how to start one and returns. Real deployments MUST run frostd with
//! TLS; `--no-tls-very-insecure` is only for the test.
//!
//!   frostd --no-tls-very-insecure -p 2744
//!   FROSTD_URL=http://127.0.0.1:2744 cargo test --test frostd_transport -- --nocapture

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use loki_poc::setup_transport::{wire_kind, Identity};
use loki_poc::signing_session::{AttemptId, SessionContext};
use loki_poc::signer::backup::BackupArtifact;
use loki_poc::signer::coordination::{member_dkg_step, redeliver_dkg, relay_dkg};
use loki_poc::signer::local::{BackupDevice, DevicePrompts, LocalSigner, RosterDecision};
use loki_poc::signer::secure_element::SoftwareSecureElement;
use loki_poc::signer::{
    CandidateRef, DkgWireKind, Network, PublicPaymentParams, Session, Signer, VaultRef,
};
use loki_poc::transport::{
    FrostdLoginKey, FrostdTransport, Incoming, Outbound, Peer, RelayLog, SealedCandidate,
    Transport,
};
use reddsa_frost::frost::redpallas as frost;
use uuid::Uuid;
use zeroize::Zeroizing;

const ORIGIN: &str = "https://coordinator.test";

fn tempdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "loki-ws3-{tag}-{}-{}",
        std::process::id(),
        rand_core::RngCore::next_u64(&mut rand_core::OsRng)
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// An in-memory relay with frostd's contract: an empty recipient list goes to the
/// coordinator's mailbox, and `recv` drains the caller's mailbox. It records every
/// payload it carried.
#[derive(Clone, Default)]
struct MemoryRelay(Arc<Mutex<RelayState>>);

#[derive(Default)]
struct RelayState {
    coordinator: Option<Peer>,
    boxes: BTreeMap<(Vec<u8>, bool), Vec<Incoming>>,
    tape: Vec<Vec<u8>>,
}

impl MemoryRelay {
    /// The relay loses everything still queued for the members.
    fn drop_member_queues(&self) {
        self.0.lock().unwrap().boxes.retain(|(_, coordinator), _| *coordinator);
    }

    fn tape(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().tape.clone()
    }
}

struct MemoryTransport {
    relay: MemoryRelay,
    me: Peer,
}

impl Transport for MemoryTransport {
    type Error = String;
    type Channel = ();

    fn open(&mut self, _: &[Peer], _: u8) -> Result<(), String> {
        self.relay.0.lock().unwrap().coordinator = Some(self.me.clone());
        Ok(())
    }

    fn join(&mut self, _: Uuid) -> Result<(), String> {
        Ok(())
    }

    fn send(&self, _: &(), to: &[Peer], message: &Outbound) -> Result<(), String> {
        let message = message.to_bytes().map_err(|e| e.to_string())?;
        let mut state = self.relay.0.lock().unwrap();
        state.tape.push(message.clone());
        let incoming = Incoming {
            from: self.me.clone(),
            message,
        };
        if to.is_empty() {
            let coordinator = state.coordinator.clone().ok_or("no session")?;
            state
                .boxes
                .entry((coordinator.0.to_vec(), true))
                .or_default()
                .push(incoming);
        } else {
            for peer in to {
                state
                    .boxes
                    .entry((peer.0.to_vec(), false))
                    .or_default()
                    .push(incoming.clone());
            }
        }
        Ok(())
    }

    fn recv(&self, _: &(), as_coordinator: bool) -> Result<Vec<Incoming>, String> {
        let mut state = self.relay.0.lock().unwrap();
        Ok(state
            .boxes
            .remove(&(self.me.0.to_vec(), as_coordinator))
            .unwrap_or_default())
    }

    fn close(&self, _: ()) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Shelf(Arc<Mutex<Option<Vec<u8>>>>);

impl BackupDevice for Shelf {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new("backup words".into()))
    }
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(artifact.0.clone());
        Ok(())
    }
    fn load(&mut self) -> Result<BackupArtifact, String> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .map(BackupArtifact)
            .ok_or_else(|| "no backup".into())
    }
}

/// One member: the storage-backed signer plus the code its device showed.
struct Member {
    id: u16,
    dir: PathBuf,
    signer: LocalSigner<SoftwareSecureElement>,
    session: Session,
    codes: Arc<Mutex<Vec<String>>>,
    /// The roster identity the signer was created with, kept by the member's app.
    identity: Identity,
}

fn prompts(codes: Arc<Mutex<Vec<String>>>) -> DevicePrompts {
    DevicePrompts {
        connect: Box::new(|origin, _| origin == ORIGIN),
        roster: Box::new(move |code| {
            codes.lock().unwrap().push(code.to_owned());
            RosterDecision::Match
        }),
        roster_deadline: Duration::from_secs(60),
        backup: Box::new(Shelf::default()),
        approval: Box::new(|_| true),
    }
}

impl Member {
    fn create(id: u16, vault: [u8; 32]) -> Self {
        let dir = tempdir(&format!("m{id}"));
        let codes = Arc::new(Mutex::new(Vec::new()));
        let se = SoftwareSecureElement::persistent(&dir, "member pass").unwrap();
        let identity = Identity::new(id);
        let mut signer = LocalSigner::create_with_identity(
            &dir,
            se,
            Network::Regtest,
            vault,
            id,
            "ws3 vault".into(),
            prompts(codes.clone()),
            Identity::from_secret_bytes(&identity.to_secret_bytes()).unwrap(),
        )
        .unwrap();
        let session = signer.connect(ORIGIN, Network::Regtest, b"ws3").unwrap().session;
        Self {
            id,
            dir,
            signer,
            session,
            codes,
            identity,
        }
    }

    /// The member's device restarts: reopen the signer from its data directory.
    fn restart(&mut self) {
        let se = SoftwareSecureElement::persistent(&self.dir, "member pass").unwrap();
        self.signer =
            LocalSigner::open(&self.dir, se, "ws3 vault".into(), prompts(self.codes.clone()))
                .unwrap();
        self.session = self
            .signer
            .connect(ORIGIN, Network::Regtest, b"ws3-again")
            .unwrap()
            .session;
    }

    fn ready(&self) -> bool {
        self.signer.list_vaults(&self.session).unwrap()[0].ready
    }
}

/// Poll until `want` messages arrived (frostd is store-and-forward).
fn recv_until<T: Transport>(t: &T, ch: &T::Channel, coordinator: bool, want: usize) -> Vec<Incoming>
where
    T::Error: std::fmt::Debug,
{
    let mut got = Vec::new();
    for _ in 0..400 {
        got.extend(t.recv(ch, coordinator).expect("recv"));
        if got.len() >= want {
            return got;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("the relay did not deliver {want} messages (got {})", got.len());
}

/// A full 2-of-3 setup and a signed candidate over `T`. `restart_coordinator` reopens the
/// relay log mid-setup (after `lose_queues` dropped what the relay still held for the
/// members) and redelivers from it.
fn setup_and_sign<T>(
    members_tx: Vec<(T, T::Channel)>,
    member_peers: Vec<Peer>,
    coordinator_peer: Peer,
    coordinator: (T, T::Channel),
    lose_queues: impl Fn(),
) -> Vec<String>
where
    T: Transport,
    T::Error: std::fmt::Display + std::fmt::Debug,
{
    let (threshold, count, vault) = (2u16, 3u16, [0x5au8; 32]);
    let peers: BTreeMap<u16, Peer> = (1..=count).zip(member_peers).collect();
    let mut members: Vec<Member> = (1..=count).map(|id| Member::create(id, vault)).collect();
    let (coord, coord_ch) = coordinator;
    let log_dir = tempdir("relay-log");
    let mut log = RelayLog::open(&log_dir, count).unwrap();

    // The coordinator assembles the roster from what each signer's connect returned.
    let roster = serde_json::json!({
        "vault": hex::encode(vault),
        "threshold": threshold,
        "setup_version": 2,
        "members": members.iter_mut().map(|m| {
            let c = m.signer.connect(ORIGIN, Network::Regtest, b"roster").unwrap();
            m.session = c.session;
            serde_json::json!({
                "id": c.member.id,
                "signing": hex::encode(c.member.signing),
                "encryption": hex::encode(c.member.encryption),
            })
        }).collect::<Vec<_>>(),
    });
    let document = serde_json::to_vec(&roster).unwrap();
    let mut vault_ref: Option<VaultRef> = None;
    for m in members.iter_mut() {
        vault_ref = Some(m.signer.dkg_begin(&m.session, &document).unwrap());
    }
    let vault_ref = vault_ref.unwrap();
    let codes: Vec<String> = members.iter().map(|m| m.codes.lock().unwrap()[0].clone()).collect();
    assert!(codes.iter().all(|c| c == &codes[0] && c.len() == 29));

    let mut backed_up = vec![false; usize::from(count)];
    for pass in 0..12 {
        for (m, (t, ch)) in members.iter_mut().zip(&members_tx) {
            member_dkg_step(&mut m.signer, &m.session, &vault_ref, t, ch, &coordinator_peer).unwrap();
            if !backed_up[usize::from(m.id - 1)] {
                if let Ok(receipt) = m.signer.backup(&m.session) {
                    for wire in receipt {
                        t.send(ch, &[], &Outbound::Dkg(wire)).unwrap();
                    }
                    backed_up[usize::from(m.id - 1)] = true;
                }
            }
        }
        // Wait until the coordinator holds what the members just sent.
        std::thread::sleep(Duration::from_millis(50));
        relay_dkg(&mut log, &coord, &coord_ch, &peers).unwrap();
        if pass == 1 {
            // The coordinator restarts and the relay lost the queued deliveries: reopen the
            // log and redeliver everything. A member's device restarts too.
            lose_queues();
            drop(log);
            log = RelayLog::open(&log_dir, count).unwrap();
            assert!(!log.is_empty());
            redeliver_dkg(&log, &coord, &coord_ch, &peers).unwrap();
            members[2].restart();
        }
        std::thread::sleep(Duration::from_millis(50));
        if members.iter().all(Member::ready) {
            break;
        }
    }
    for m in &members {
        assert!(m.ready(), "member {} must be ready after every receipt", m.id);
    }
    // Every member derived the same vault secret, so the same group viewing key.
    let viewing: Vec<_> = members.iter().map(|m| m.signer.hosted_metadata().unwrap().1.to_bytes()).collect();
    assert!(viewing.iter().all(|fvk| *fvk == viewing[0]));
    // Active: the coordinator deletes its relay log.
    assert!(log.active());
    log.delete().unwrap();
    assert!(!log_dir.join("dkg-relay.log").exists());

    // Every member releases the same address; pay a note to it.
    let addresses: Vec<String> = members
        .iter_mut()
        .map(|m| m.signer.release_address(&m.session).unwrap().address)
        .collect();
    assert!(addresses.iter().all(|a| a == &addresses[0]));
    let recipient = loki_poc::vault::orchard_receiver_from_ua(
        &addresses[0],
        zcash_protocol::consensus::NetworkType::Regtest,
    )
    .unwrap();
    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let note = orchard::Note::from_parts(
        recipient,
        orchard::value::NoteValue::from_raw(625_000_000),
        rho,
        orchard::note::RandomSeed::from_bytes([2u8; 32], &rho).unwrap(),
        orchard::NoteVersion::V3,
    )
    .unwrap();
    let public = frost::keys::PublicKeyPackage::deserialize(
        members[0].signer.public_package_bytes().unwrap(),
    )
    .unwrap();

    // ---- Signing: members 1 and 2, every message typed ----
    let cand = CandidateRef {
        vault_id: vault,
        payment_id: [7; 32],
        attempt_id: [9; 32],
    };
    let quorum = [0usize, 1];
    let id_of = |peer: &Peer| *peers.iter().find(|(_, p)| *p == peer).unwrap().0;
    for &i in &quorum {
        let m = &mut members[i];
        m.signer.set_candidate_notes(vec![note]);
        let commitments = m.signer.sign_commit(&m.session, &cand).unwrap();
        let (t, ch) = &members_tx[i];
        t.send(ch, &[], &Outbound::Commitments(commitments)).unwrap();
    }
    let commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        recv_until(&coord, &coord_ch, true, 2)
            .into_iter()
            .map(|m| {
                (
                    frost::Identifier::try_from(id_of(&m.from)).unwrap(),
                    frost::round1::SigningCommitments::deserialize(&m.message).unwrap(),
                )
            })
            .collect();
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .unwrap();
    let alpha: [u8; 32] = params.randomizer().serialize().as_slice().try_into().unwrap();
    let intent = PublicPaymentParams {
        recipient,
        amount: zcash_protocol::value::Zatoshis::const_from_u64(40_000_000),
        memo: zcash_protocol::memo::MemoBytes::from_bytes(b"ws3").unwrap(),
        target_height: 700,
        expiry_height: 1_152,
    };
    // The proposer's app answers the build request with the signer's candidate.
    let candidate = members[0]
        .signer
        .build_candidate(&members[0].session, &cand, &intent, &[alpha])
        .unwrap();
    let sighash = pczt::roles::signer::Signer::new(pczt::Pczt::parse(candidate.as_bytes()).unwrap())
        .unwrap()
        .shielded_sighash();
    // The proposer seals the candidate to the other signer; it never crosses in the clear.
    let context = SessionContext {
        vault,
        payment: cand.payment_id,
        attempt: AttemptId(cand.attempt_id),
        signers: vec![members[0].id, members[1].id],
    };
    let sealed =
        SealedCandidate::seal(&members[0].identity, &members[1].identity.public(), &context, &candidate)
            .unwrap();
    let (t, ch) = &members_tx[0];
    t.send(ch, &[peers[&members[1].id].clone()], &Outbound::Candidate(sealed)).unwrap();
    let package = frost::SigningPackage::new(commitments, &sighash);
    let seed: [u8; 32] = seed.as_slice().try_into().unwrap();
    for &i in &quorum {
        let to = [peers[&members[i].id].clone()];
        coord.send(&coord_ch, &to, &Outbound::Package(package.clone())).unwrap();
        coord.send(&coord_ch, &to, &Outbound::RandomizerSeed(seed)).unwrap();
    }
    for &i in &quorum {
        let (t, ch) = &members_tx[i];
        let mut got = recv_until(t, ch, false, if i == 0 { 2 } else { 3 });
        let candidate_bytes = if i == 0 {
            candidate.as_bytes().to_vec()
        } else {
            let wire = got.remove(0).message;
            SealedCandidate::open(&members[1].identity, &members[0].identity.public(), &context, &wire)
                .unwrap()
        };
        let package = frost::SigningPackage::deserialize(&got[0].message).unwrap();
        let seed: [u8; 32] = got[1].message.clone().try_into().unwrap();
        let m = &mut members[i];
        let share = m
            .signer
            .sign_approve(&m.session, &cand, &intent, &candidate_bytes, &package, &seed)
            .unwrap();
        t.send(ch, &[], &Outbound::Share(share)).unwrap();
    }
    let shares: BTreeMap<_, _> = recv_until(&coord, &coord_ch, true, 2)
        .into_iter()
        .map(|m| {
            (
                frost::Identifier::try_from(id_of(&m.from)).unwrap(),
                frost::round2::SignatureShare::deserialize(&m.message).unwrap(),
            )
        })
        .collect();
    let signature = frost_rerandomized::aggregate(&package, &shares, &public, &params).unwrap();
    params
        .randomized_verifying_key()
        .verify(&sighash, &signature)
        .expect("the 2-of-3 signature verifies under the randomized group key");
    coord.close(coord_ch).ok();
    addresses
}

/// What crossed the relay: every setup message is a well-formed wire, every round-two
/// message is a v2 envelope, and none decodes as a plaintext round-two package.
fn audit(tape: &[Vec<u8>]) {
    let mut round2 = 0;
    let mut setup = 0;
    for payload in tape {
        assert!(pczt::Pczt::parse(payload).is_err(), "a plaintext candidate crossed the relay");
        let Some(kind) = wire_kind(payload) else { continue };
        setup += 1;
        if kind == DkgWireKind::Round2 {
            round2 += 1;
            assert_eq!(&payload[..8], b"LOKIDKG2", "round two crossed outside a v2 envelope");
            assert!(
                frost::keys::dkg::round2::Package::deserialize(payload).is_err(),
                "a plaintext round-two package crossed the relay"
            );
        }
    }
    // Six round-two envelopes, each sent once by its member and once by the coordinator.
    assert!(round2 >= 12, "round two crossed the relay ({round2} envelopes)");
    assert!(setup > round2);
}

#[test]
fn new_signer_setup_and_signing_over_an_in_memory_relay() {
    let relay = MemoryRelay::default();
    let login: Vec<FrostdLoginKey> = (0..4).map(|_| FrostdLoginKey::generate()).collect();
    let mut coordinator = MemoryTransport {
        relay: relay.clone(),
        me: login[3].peer(),
    };
    let member_peers: Vec<Peer> = login[..3].iter().map(FrostdLoginKey::peer).collect();
    coordinator.open(&member_peers, 255).unwrap();
    let members: Vec<(MemoryTransport, ())> = member_peers
        .iter()
        .map(|peer| {
            (
                MemoryTransport {
                    relay: relay.clone(),
                    me: peer.clone(),
                },
                (),
            )
        })
        .collect();
    let lose = relay.clone();
    setup_and_sign(members, member_peers, login[3].peer(), (coordinator, ()), move || {
        lose.drop_member_queues()
    });
    audit(&relay.tape());
}

#[test]
fn new_signer_setup_and_signing_over_real_frostd() {
    let url = match std::env::var("FROSTD_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!(
                "[WS3] FROSTD_URL unset — skipping live relay test.\n\
                 Start one: frostd --no-tls-very-insecure -p 2744\n\
                 Then:      FROSTD_URL=http://127.0.0.1:2744 cargo test --test frostd_transport -- --nocapture"
            );
            return;
        }
    };
    let login: Vec<FrostdLoginKey> = (0..4).map(|_| FrostdLoginKey::generate()).collect();
    let member_peers: Vec<Peer> = login[..3].iter().map(FrostdLoginKey::peer).collect();
    let coordinator_peer = login[3].peer();
    let mut login = login.into_iter();
    let members: Vec<FrostdTransport> = (0..3)
        .map(|_| FrostdTransport::new(&url, login.next().unwrap()).expect("member login"))
        .collect();
    let mut coordinator =
        FrostdTransport::new(&url, login.next().unwrap()).expect("coordinator login");
    let channel = coordinator.open(&member_peers, 255).expect("create_new_session");
    let session = channel.session_id();
    let members: Vec<_> = members
        .into_iter()
        .map(|mut t| {
            let ch = t.join(session).expect("join");
            (t, ch)
        })
        .collect();
    // frostd keeps queued messages across a coordinator restart, so nothing is lost.
    let addresses = setup_and_sign(
        members,
        member_peers,
        coordinator_peer,
        (coordinator, channel),
        || {},
    );
    eprintln!("[WS3] v2 DKG and 2-of-3 signing over frostd at {url}: vault {}", addresses[0]);
}
