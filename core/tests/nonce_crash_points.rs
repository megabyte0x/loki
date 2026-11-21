//! Crash drill for the signer nonce store (`signer::nonce`): a process killed at each
//! persistence point, then restarted on the same directory and device element, never signs two
//! messages with one nonce. A crash is modelled by the files that point leaves on disk; a restart
//! is a new `NonceStore` over that directory.
//!
//! Already covered elsewhere: the crash after the burn record is durable and before the nonce
//! file is removed, retried for the same message (`nonce.rs`
//! `crash_after_burn_leaves_no_stranded_or_duplicated_nonce`), and reuse for a different message
//! after a completed sign (`nonce.rs` `reuse_for_a_different_message_is_hard_refused`), which is
//! also the state a crash after the nonce is removed leaves.
use loki_poc::signer::{
    nonce::{NonceError, NonceState, NonceStore},
    secure_element::SoftwareSecureElement,
};
use reddsa_frost::frost::redpallas as frost;
use std::{collections::BTreeMap, fs, path::PathBuf};

struct Drill {
    dir: PathBuf,
    key: frost::keys::KeyPackage,
    peer: frost::round1::SigningCommitments,
}

impl Drill {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "loki-nonce-crash-{}",
            hex::encode(rand_core::RngCore::next_u64(&mut rand_core::OsRng).to_le_bytes())
        ));
        let (shares, _) = frost::keys::generate_with_dealer(
            2,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        let key = |id: u16| {
            frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(id).unwrap()].clone())
                .unwrap()
        };
        let peer = frost::round1::commit(key(2).signing_share(), &mut rand_core::OsRng).1;
        Self { dir, key: key(1), peer }
    }

    /// The process after a restart: a fresh store on the same directory, same device element.
    fn restart(&self) -> (NonceStore, SoftwareSecureElement) {
        (NonceStore::open(&self.dir, [1; 32], 1).unwrap(), SoftwareSecureElement::from_kek([7; 32]))
    }

    fn package(&self, own: frost::round1::SigningCommitments, msg: u8) -> frost::SigningPackage {
        let commitments = BTreeMap::from([
            (*self.key.identifier(), own),
            (frost::Identifier::try_from(2u16).unwrap(), self.peer),
        ]);
        frost::SigningPackage::new(commitments, &[msg; 32])
    }

    fn sign(&self, store: &NonceStore, se: &SoftwareSecureElement, own: frost::round1::SigningCommitments, msg: u8)
        -> Result<frost::round2::SignatureShare, NonceError> {
        store.sign_and_burn("n", se, &self.package(own, msg), &self.key, &[9; 32], None, &|| false)
    }
}

impl Drop for Drill {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Crash while the nonce is being written, before it is linked into place: only the temporary
/// file exists and no commitment left the process. The restart is a fresh round 1.
#[test]
fn crash_while_persisting_the_nonce_leaves_no_usable_nonce() {
    let d = Drill::new();
    fs::create_dir_all(&d.dir).unwrap();
    fs::write(d.dir.join(".n.nonce.tmp"), b"torn write").unwrap();
    let (store, se) = d.restart();
    assert_eq!(store.state("n"), NonceState::Fresh);
    let own = store.commit("n", &se, d.key.signing_share(), None).unwrap();
    d.sign(&store, &se, own, 1).unwrap();
    assert_eq!(d.sign(&store, &se, own, 2).unwrap_err(), NonceError::Reuse);
}

/// Crash after the nonce is durable but before its commitment was emitted: the restart emits
/// the SAME commitment for that id, never a second nonce, and that nonce signs only one message.
#[test]
fn crash_after_persist_before_emit_recovers_the_same_commitment() {
    let d = Drill::new();
    let (store, se) = d.restart();
    let first = store.commit("n", &se, d.key.signing_share(), None).unwrap();
    drop((store, se));
    let (store, se) = d.restart();
    assert_eq!(store.state("n"), NonceState::Committed);
    let again = store.commit("n", &se, d.key.signing_share(), None).unwrap();
    assert_eq!(again.serialize().unwrap(), first.serialize().unwrap());
    let share = d.sign(&store, &se, first, 1).unwrap();
    assert_eq!(d.sign(&store, &se, first, 2).unwrap_err(), NonceError::Reuse);
    assert_eq!(d.sign(&store, &se, first, 1).unwrap().serialize(), share.serialize());
}

/// Crash in round 2 after the share is computed but before the burn record is linked: the
/// partial never left the process. The restart still holds the committed nonce, signs once,
/// and refuses any second message.
#[test]
fn crash_before_burn_is_durable_signs_at_most_one_message() {
    let d = Drill::new();
    let (store, se) = d.restart();
    let own = store.commit("n", &se, d.key.signing_share(), None).unwrap();
    drop((store, se));
    fs::write(d.dir.join(".n.burn.tmp"), b"torn burn").unwrap();
    let (store, se) = d.restart();
    assert_eq!(store.state("n"), NonceState::Committed);
    let share = d.sign(&store, &se, own, 1).unwrap();
    assert_eq!(store.state("n"), NonceState::Burned);
    assert_eq!(d.sign(&store, &se, own, 2).unwrap_err(), NonceError::Reuse);
    assert_eq!(d.sign(&store, &se, own, 1).unwrap().serialize(), share.serialize());
}

/// Crash after the burn record is durable but before the nonce file is removed, then a retry
/// for a DIFFERENT message: the nonce file is still on disk, but the burn wins and the second
/// message is refused. (The same-message retry is covered in `nonce.rs`.)
#[test]
fn crash_after_burn_then_a_different_message_is_refused() {
    let d = Drill::new();
    let (store, se) = d.restart();
    let own = store.commit("n", &se, d.key.signing_share(), None).unwrap();
    let crashed = store.sign_and_burn("n", &se, &d.package(own, 1), &d.key, &[9; 32], None, &|| true);
    assert!(crashed.is_err());
    drop((store, se));
    let (store, se) = d.restart();
    assert!(d.dir.join("n.nonce").exists(), "the crash left the nonce file behind");
    assert_eq!(store.state("n"), NonceState::Burned);
    assert_eq!(d.sign(&store, &se, own, 2).unwrap_err(), NonceError::Reuse);
    assert_eq!(store.commit("n", &se, d.key.signing_share(), None).unwrap_err(), NonceError::Other("nonce id already burned".into()));
}
