//! Crash-safe single-use nonce state machine (ws1-signer §8).
//!
//! Persist the sealed nonce and its original witness pins before emitting a commitment.
//! The burn wins over a leftover nonce and permits only exact, authenticated replays.
//! Native processes serialize the whole transition; the browser holds exclusive OPFS handles
//! and a Web Lock. A torn or legacy record refuses signing rather than falling back.

use crate::signer::durable::{
    create_dir_all, file_exists, read_file, remove_file, sync_dir, write_durable,
};
use crate::signer::secure_element::{file_binding, SealedShare, SecureElement};
use crate::signing_session::{
    nonce_claim_id, nonce_claim_record, valid_witness_pins, NonceWitness, WitnessPins,
};
use reddsa_frost::frost::redpallas as frost;
use std::{
    io,
    path::{Path, PathBuf},
};

/// Hard error distinguishing a benign retry from a security-fatal reuse.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceError {
    /// The same nonce id was asked to sign a DIFFERENT package or randomizer than it burned for.
    /// FROST security breaks on nonce reuse; this is never recoverable.
    Reuse,
    /// A nonce committed under an earlier backup/nonce epoch was presented after a
    /// restore bumped the epoch (ws1-signer §8: "restore resets to a fresh nonce
    /// epoch and must not replay an old one"). Never recoverable — the member must
    /// re-commit under the current epoch.
    StaleEpoch,
    Io(String),
    Other(String),
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceError::Reuse => write!(f, "HARD REFUSE: nonce reuse for a different signing package or randomizer"),
            NonceError::StaleEpoch => write!(
                f,
                "HARD REFUSE: nonce from a pre-restore epoch; start a new signing attempt"
            ),
            NonceError::Io(e) => write!(f, "nonce io: {e}"),
            NonceError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for NonceError {
    fn from(e: io::Error) -> Self {
        NonceError::Io(e.to_string())
    }
}

/// A crash-safe store for one signing attempt's single-use nonces, under `dir`.
/// The secret nonce is sealed by the secure element exactly like the share at rest.
///
/// `epoch` is the current backup/nonce epoch. Every nonce is stamped with it when
/// committed (into the sealed blob's `backup_epoch`). A restore reconstructs the store
/// at a HIGHER epoch (see [`NonceStore::open_at_epoch`]); any nonce stamped with an
/// older epoch is hard-refused, so a nonce committed before the restore can never be
/// replayed afterwards (ws1-signer §8).
pub struct NonceStore {
    dir: PathBuf,
    epoch: u64,
    vault: [u8; 32],
    member: u16,
}

impl NonceStore {
    /// Open at epoch 0 (a store that was never restored).
    pub fn open(dir: &Path, vault: [u8; 32], member: u16) -> io::Result<Self> {
        Self::open_at_epoch(dir, 0, vault, member)
    }

    /// Open at an explicit epoch. A restore bumps the share's `backup_epoch` and opens the
    /// (fresh) nonce dir at that same epoch, so nonces stamped with any lower epoch are
    /// refused by [`NonceStore::sign_and_burn`].
    pub fn open_at_epoch(dir: &Path, epoch: u64, vault: [u8; 32], member: u16) -> io::Result<Self> {
        create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            epoch,
            vault,
            member,
        })
    }

    fn nonce_name(id: &str) -> String {
        format!("{id}.nonce")
    }
    fn burn_name(id: &str) -> String {
        format!("{id}.burn")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn lock(&self) -> io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(self.dir.join("nonce.lock"))?;
        file.lock()?;
        Ok(file)
    }

    fn binding(&self, name: &str) -> Vec<u8> {
        let mut binding = file_binding("signing-nonce-v1", &self.vault, self.member);
        binding.extend_from_slice(&self.epoch.to_be_bytes());
        binding.extend_from_slice(name.as_bytes());
        binding
    }

    fn pin_prefix(pins: Option<WitnessPins>) -> Result<Vec<u8>, NonceError> {
        let mut prefix = vec![u8::from(pins.is_some())];
        if let Some(pins) = pins {
            if !valid_witness_pins(pins) {
                return Err(NonceError::Other("two distinct nonce witnesses required".into()));
            }
            for (key, run, mailbox) in pins {
                prefix.extend_from_slice(&key);
                prefix.extend_from_slice(&run);
                prefix.extend_from_slice(&mailbox);
            }
        }
        Ok(prefix)
    }

    fn read_record(
        &self,
        name: &str,
        se: &impl SecureElement,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, NonceError> {
        let raw = match read_file(&self.dir, name) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let restart = || NonceError::Other("invalid or legacy nonce record; start a new signing attempt".into());
        let sealed = SealedShare::from_bytes(&raw).map_err(|_| restart())?;
        if sealed.backup_epoch != self.epoch {
            return Err(NonceError::StaleEpoch);
        }
        sealed.open_bound(se, &self.binding(name)).map(Some).map_err(|e| match e {
            crate::signer::secure_element::OpenError::Element(message) => NonceError::Other(message),
            _ => restart(),
        })
    }

    fn persist_record(
        &self,
        name: &str,
        se: &impl SecureElement,
        record: &[u8],
    ) -> Result<(), NonceError> {
        let sealed = SealedShare::seal_bound(se, self.epoch, record, &self.binding(name))
            .map_err(NonceError::Other)?.to_bytes();
        write_durable(&self.dir, name, &sealed)?;
        // A write-once collision or a short OPFS write must not release an unrecorded result.
        if read_file(&self.dir, name)? != sealed {
            return Err(NonceError::Other("nonce record did not persist; start a new signing attempt".into()));
        }
        Ok(())
    }

    fn check_pins<'a>(record: &'a [u8], prefix: &[u8]) -> Result<&'a [u8], NonceError> {
        record.strip_prefix(prefix).ok_or_else(|| NonceError::Other(
            "original nonce witnesses differ; start a new signing attempt".into(),
        ))
    }

    /// Round 1: generate a single-use nonce, PERSIST it (sealed + fsync'd), then return
    /// the public commitment. The persist happens before the caller may emit anything.
    pub fn commit(
        &self,
        id: &str,
        se: &impl SecureElement,
        signing_share: &frost::keys::SigningShare,
        pins: Option<WitnessPins>,
    ) -> Result<frost::round1::SigningCommitments, NonceError> {
        #[cfg(not(target_arch = "wasm32"))]
        let _lock = self.lock()?;
        match read_file(&self.dir, &Self::burn_name(id)) {
            Ok(_) => return Err(NonceError::Other("nonce id already burned".into())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        let name = Self::nonce_name(id);
        let mut record = zeroize::Zeroizing::new(Self::pin_prefix(pins)?);
        if let Some(saved) = self.read_record(&name, se)? {
            let nonces = Self::decode_nonce(&saved, &record)?;
            sync_dir(&self.dir)?;
            return Ok(frost::round1::SigningCommitments::from(&nonces));
        }
        let (nonces, commitment) =
            frost::round1::commit(signing_share, &mut rand_core::OsRng);
        // The serialized secret nonce is as sensitive as the share once a partial exists:
        // wipe it after sealing (`SigningNonces` itself zeroizes on drop).
        let serialized = zeroize::Zeroizing::new(
            nonces
                .serialize()
                .map_err(|e| NonceError::Other(e.to_string()))?,
        );
        drop(nonces);
        record.extend_from_slice(&serialized);
        self.persist_record(&name, se, &record)?;
        Ok(commitment)
    }

    fn decode_nonce(record: &[u8], prefix: &[u8]) -> Result<frost::round1::SigningNonces, NonceError> {
        frost::round1::SigningNonces::deserialize(Self::check_pins(record, prefix)?)
            .map_err(|e| NonceError::Other(e.to_string()))
    }

    // Browser network preflight: only claim the actual pending commitment at its original pair.
    pub(super) fn pending_commitment(
        &self,
        id: &str,
        se: &impl SecureElement,
        pins: WitnessPins,
    ) -> Result<frost::round1::SigningCommitments, NonceError> {
        let raw = self.read_record(&Self::nonce_name(id), se)?
            .ok_or_else(|| NonceError::Other("no pending nonce; start a new signing attempt".into()))?;
        let nonces = Self::decode_nonce(&raw, &Self::pin_prefix(Some(pins))?)?;
        Ok(frost::round1::SigningCommitments::from(&nonces))
    }

    /// Round 2: ATOMICALLY burn the nonce and emit the partial for this package and seed.
    ///
    /// The partial is written into `<id>.burn` (fsync'd) BEFORE `<id>.nonce` is removed.
    /// A crash mid-call therefore leaves the burn record present (safe: resent verbatim)
    /// or the nonce still present (safe: retried) — never a burned-and-lost nonce.
    ///
    /// `inject_crash_after_burn` returns `true` just after the burn record is durable but
    /// before the nonce file is removed, to exercise the crash boundary in a test.
    pub fn sign_and_burn(
        &self,
        id: &str,
        se: &impl SecureElement,
        signing_package: &frost::SigningPackage,
        key: &frost::keys::KeyPackage,
        seed: &[u8; 32],
        mut witness: Option<&mut (dyn NonceWitness + Send + 'static)>,
        inject_crash_after_burn: &dyn Fn() -> bool,
    ) -> Result<frost::round2::SignatureShare, NonceError> {
        #[cfg(not(target_arch = "wasm32"))]
        let _lock = self.lock()?;
        let burn = Self::burn_name(id);
        let mut record = Self::pin_prefix(witness.as_ref().map(|w| w.pins()))?;
        let message: [u8; 32] = signing_package
            .message()
            .as_slice()
            .try_into()
            .map_err(|_| NonceError::Other("signing package message is not 32 bytes".into()))?;

        let mut hash = blake3::Hasher::new();
        hash.update(b"Loki_nonce_burn_v1\0");
        hash.update(seed);
        hash.update(&signing_package.serialize().map_err(|e| NonceError::Other(e.to_string()))?);
        let digest = hash.finalize();
        if let Some(saved) = self.read_record(&burn, se)? {
            let saved = Self::check_pins(&saved, &record)?;
            let partial = saved.strip_prefix(digest.as_bytes()).ok_or(NonceError::Reuse)?;
            sync_dir(&self.dir)?;
            return frost::round2::SignatureShare::deserialize(partial)
                .map_err(|e| NonceError::Other(format!("recorded partial: {e}")));
        }

        let nonce = Self::nonce_name(id);
        let raw = self.read_record(&nonce, se)?
            .ok_or_else(|| NonceError::Other("no pending nonce; start a new signing attempt".into()))?;
        let nonces = Self::decode_nonce(&raw, &record)?;
        let commitment = frost::round1::SigningCommitments::from(&nonces);
        if signing_package.signing_commitments().get(key.identifier()) != Some(&commitment) {
            return Err(NonceError::Other("own commitment differs from the pending nonce".into()));
        }
        if let Some(witness) = witness.as_mut() {
            let cid = nonce_claim_id(&self.vault, key.identifier(), &commitment).map_err(NonceError::Other)?;
            witness.claim(cid, &nonce_claim_record(&cid, &message, seed))
                .map_err(|e| NonceError::Other(format!("nonce witness refused: {e}; start a new signing attempt if an original witness is unavailable")))?;
        }
        let share = frost_rerandomized::sign_with_randomizer_seed(signing_package, &nonces, key, seed)
            .map_err(|e| NonceError::Other(e.to_string()))?;

        // The authenticated winner is durable before this call can release the share.
        record.extend_from_slice(digest.as_bytes());
        record.extend_from_slice(&share.serialize());
        self.persist_record(&burn, se, &record)?;

        if inject_crash_after_burn() {
            // Simulate a power loss after the burn is durable but before the nonce file
            // is removed. The nonce file still exists; the burn file exists. Recovery
            // must treat this as burned (resend the partial), never reuse the nonce.
            return Err(NonceError::Other("crash injected after burn".into()));
        }

        // Only now remove the now-dead nonce; crash here is still safe (burn present).
        let _ = remove_file(&self.dir, &nonce);
        sync_dir(&self.dir)?;
        Ok(share)
    }

    /// State after a (possibly crashed) attempt, for tests and recovery.
    pub fn state(&self, id: &str) -> NonceState {
        let nonce = file_exists(&self.dir, &Self::nonce_name(id));
        let burn = file_exists(&self.dir, &Self::burn_name(id));
        match (nonce, burn) {
            (false, false) => NonceState::Fresh,
            (true, false) => NonceState::Committed,
            (_, true) => NonceState::Burned,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NonceState {
    Fresh,
    Committed,
    Burned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::secure_element::SoftwareSecureElement;
    use reddsa_frost::frost::redpallas as frost;
    use std::collections::BTreeMap;
    use std::fs;

    /// A 2-of-2 key set and a rerandomized signing package over `msg`, for one signer.
    fn fixture(
        msg: [u8; 32],
    ) -> (
        SoftwareSecureElement,
        frost::keys::KeyPackage,
        frost::round1::SigningNonces,
        frost::SigningPackage,
        [u8; 32],
    ) {
        let (shares, _pubkeys) = frost::keys::generate_with_dealer(
            2,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let id2 = frost::Identifier::try_from(2u16).unwrap();
        let kp1 =
            frost::keys::KeyPackage::try_from(shares.get(&id1).unwrap().clone()).unwrap();
        let kp2 =
            frost::keys::KeyPackage::try_from(shares.get(&id2).unwrap().clone()).unwrap();
        // Peer's commitment, needed to form a well-populated signing package.
        let (_n2, c2) = frost::round1::commit(kp2.signing_share(), &mut rand_core::OsRng);
        let (n1, c1) = frost::round1::commit(kp1.signing_share(), &mut rand_core::OsRng);
        let mut commitments = BTreeMap::new();
        commitments.insert(id1, c1);
        commitments.insert(id2, c2);
        let pkg = frost::SigningPackage::new(commitments, &msg);
        let se = SoftwareSecureElement::generate();
        (se, kp1, n1, pkg, [9u8; 32])
    }

    fn pkg_for(
        se_share: &frost::keys::KeyPackage,
        committed: &frost::round1::SigningCommitments,
        peer: &frost::round1::SigningCommitments,
        msg: [u8; 32],
    ) -> frost::SigningPackage {
        let mut commitments = BTreeMap::new();
        commitments.insert(*se_share.identifier(), *committed);
        commitments.insert(frost::Identifier::try_from(2u16).unwrap(), *peer);
        frost::SigningPackage::new(commitments, &msg)
    }

    #[test]
    fn crash_after_burn_leaves_no_stranded_or_duplicated_nonce() {
        let dir = tempdir("crash");
        let store = NonceStore::open(&dir, [1; 32], 1).unwrap();
        let msg = [1u8; 32];
        let (se, kp, _n1, pkg, seed) = fixture(msg);
        let peer = *pkg
            .signing_commitments()
            .get(&frost::Identifier::try_from(2u16).unwrap())
            .unwrap();

        // Round 1: persist-before-emit.
        let committed = store.commit("c0", &se, kp.signing_share(), None).unwrap();
        assert_eq!(store.state("c0"), NonceState::Committed);
        let pkg = pkg_for(&kp, &committed, &peer, msg);

        // Round 2 with a crash injected right after the burn record is durable.
        let err = store
            .sign_and_burn("c0", &se, &pkg, &kp, &seed, None, &|| true)
            .unwrap_err();
        assert!(matches!(err, NonceError::Other(_)));
        // The burn record exists; the state reads as Burned despite the nonce file
        // still being on disk (burn wins).
        assert_eq!(store.state("c0"), NonceState::Burned);

        // Recovery: retrying for the SAME message resends the recorded partial and
        // NEVER re-signs with the nonce. The guarantee is that the recovered partial is
        // stable across repeated calls (idempotent) — a stranded or re-generated nonce
        // would either fail or differ.
        let resent1 = store
            .sign_and_burn("c0", &se, &pkg, &kp, &seed, None, &|| false)
            .unwrap();
        let resent2 = store
            .sign_and_burn("c0", &se, &pkg, &kp, &seed, None, &|| false)
            .unwrap();
        assert_eq!(resent1.serialize(), resent2.serialize());
    }

    #[test]
    fn reuse_for_a_different_message_is_hard_refused() {
        let dir = tempdir("reuse");
        let store = NonceStore::open(&dir, [1; 32], 1).unwrap();
        let msg_a = [7u8; 32];
        let (se, kp, _n1, pkg_a, seed) = fixture(msg_a);
        let peer = *pkg_a
            .signing_commitments()
            .get(&frost::Identifier::try_from(2u16).unwrap())
            .unwrap();
        let committed = store.commit("r0", &se, kp.signing_share(), None).unwrap();
        let pkg_a = pkg_for(&kp, &committed, &peer, msg_a);
        store
            .sign_and_burn("r0", &se, &pkg_a, &kp, &seed, None, &|| false)
            .unwrap();

        // A second signing request binding the SAME nonce id to a different message.
        let msg_b = [8u8; 32];
        let pkg_b = pkg_for(&kp, &committed, &peer, msg_b);
        let err = store
            .sign_and_burn("r0", &se, &pkg_b, &kp, &seed, None, &|| false)
            .unwrap_err();
        assert_eq!(err, NonceError::Reuse);
    }

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-nonce-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }
}
