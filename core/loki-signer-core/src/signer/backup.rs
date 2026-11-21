//! Member share BACKUP / RESTORE (ws1-signer §2, §5, §8).
//!
//! A FROST share is NOT seed-derivable — it is one point of a dealerless DKG. The only
//! way a member recovers signing ability on a new device is to have backed up the sealed
//! material itself. This module produces a single portable artifact that carries exactly
//! what [`LocalSigner::with_sealed_share`] needs to sign again, and restores it onto a
//! fresh data root.
//!
//! Crypto reuse (no new primitives, ws1-signer §3): the artifact is sealed with the SAME
//! [`SealedShare`] / [`SecureElement`] hierarchy used at rest, except the KEK is derived
//! from the member's backup passphrase via the one project-wide Argon2id
//! ([`crate::seal_kdf`]) rather than a device-bound element — so the blob is portable to a
//! new device, which is the whole point of a backup. The on-disk/over-the-wire artifact is
//! therefore AEAD ciphertext under a passphrase-derived KEK; the plaintext share never
//! leaves memory unsealed.
//!
//! Nonce-epoch reset (ws1-signer §8): every artifact carries a `backup_epoch`. [`restore`]
//! reconstructs the signer at `backup_epoch + 1` and opens its (fresh) nonce store at that
//! bumped epoch, so any nonce committed before the restore is hard-refused afterwards
//! (see [`crate::signer::nonce`]).

use crate::seal_kdf;
use crate::signer::local::{ApprovalPolicy, LocalSigner, SignerError};
use crate::signer::nonce::NonceStore;
use crate::signer::secure_element::{SealedShare, SecureElement, SoftwareSecureElement};
use crate::signer::Network;
use crate::setup_transport::Identity;
use crate::zip2005;
use reddsa_frost::frost::redpallas as frost;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use zeroize::Zeroizing;

const BACKUP_MAGIC: &[u8; 8] = b"LOKIBAK2";
const LEGACY_RECOVERY_MAGIC: &[u8; 8] = b"LOKIRCV1";
const RECOVERY_BACKUP_MAGIC: &[u8; 8] = b"LOKIRCV2";
const RECOVERY_SIGNATURE_DOMAIN: &[u8] = b"loki recovery backup signature v2\0";

fn network_tag(n: Network) -> u8 {
    match n {
        Network::Regtest => 0,
        Network::Testnet => 1,
    }
}

fn network_from_tag(t: u8) -> Result<Network, String> {
    match t {
        0 => Ok(Network::Regtest),
        1 => Ok(Network::Testnet),
        _ => Err(format!("unknown network tag {t}")),
    }
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn take_bytes<'a>(raw: &'a [u8], at: &mut usize) -> Result<&'a [u8], String> {
    if *at + 4 > raw.len() {
        return Err("truncated backup field length".into());
    }
    let len = u32::from_be_bytes(raw[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    if *at + len > raw.len() {
        return Err("truncated backup field".into());
    }
    let slice = &raw[*at..*at + len];
    *at += len;
    Ok(slice)
}

/// Everything needed to rebuild a member's signer on a new device. The share plaintext
/// (`key_package`) lives here only transiently; the sealed artifact ([`BackupArtifact`])
/// is what crosses a disk/QR/cloud boundary.
pub struct BackupMaterial {
    pub member_id: u16,
    pub threshold: u16,
    pub members: u16,
    pub network: Network,
    pub vault_id: [u8; 32],
    pub label: String,
    /// The group's privately agreed ZIP-2005 viewing-key secret (`group_sk`), needed to
    /// re-derive the vault FVK on the new device. Public-to-the-group but vault-private.
    pub group_sk: [u8; 32],
    /// This member's FROST `KeyPackage`, serialized. The one non-seed-derivable secret.
    pub key_package: Zeroizing<Vec<u8>>,
    /// The group `PublicKeyPackage`, serialized. Public.
    pub public_package: Vec<u8>,
    /// The epoch this backup was taken at. [`restore`] bumps past it.
    pub backup_epoch: u64,
    /// The member's setup identity (`Identity::to_secret_bytes`), so a restored device
    /// holds an identity that is in its own roster. Empty for a bare-share backup.
    pub identity: Zeroizing<Vec<u8>>,
    /// The confirmed roster document. Empty for a bare-share backup.
    pub roster: Vec<u8>,
    /// Fingerprint of `roster`; all zero for a bare-share backup.
    pub roster_fingerprint: [u8; 32],
    /// The vault's birth height on Testnet.
    pub birth_height: Option<u32>,
}

impl BackupMaterial {
    /// The group verifying key (`ak`), read from the public package. The FVK is
    /// `frost_viewing_key(ak, group_sk)`.
    fn group_ak(&self) -> Result<[u8; 32], String> {
        let public = reddsa_frost::frost::redpallas::keys::PublicKeyPackage::deserialize(
            &self.public_package,
        )
        .map_err(|e| format!("public package: {e}"))?;
        public
            .verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "group verifying key is not 32 bytes".to_string())
    }

    fn encode_plaintext(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&self.member_id.to_be_bytes());
        out.extend_from_slice(&self.threshold.to_be_bytes());
        out.extend_from_slice(&self.members.to_be_bytes());
        out.push(network_tag(self.network));
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.group_sk);
        out.extend_from_slice(&self.backup_epoch.to_be_bytes());
        put_bytes(&mut out, self.label.as_bytes());
        put_bytes(&mut out, &self.key_package);
        put_bytes(&mut out, &self.public_package);
        put_bytes(&mut out, &self.identity);
        put_bytes(&mut out, &self.roster);
        out.extend_from_slice(&self.roster_fingerprint);
        match self.birth_height {
            Some(height) => {
                out.push(1);
                out.extend_from_slice(&height.to_be_bytes());
            }
            None => out.push(0),
        }
        out
    }

    fn decode_plaintext(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 2 + 2 + 2 + 1 + 32 + 32 + 8 {
            return Err("truncated backup plaintext".into());
        }
        let member_id = u16::from_be_bytes(raw[0..2].try_into().unwrap());
        let threshold = u16::from_be_bytes(raw[2..4].try_into().unwrap());
        let members = u16::from_be_bytes(raw[4..6].try_into().unwrap());
        let network = network_from_tag(raw[6])?;
        let vault_id: [u8; 32] = raw[7..39].try_into().unwrap();
        let group_sk: [u8; 32] = raw[39..71].try_into().unwrap();
        let backup_epoch = u64::from_be_bytes(raw[71..79].try_into().unwrap());
        let mut at = 79;
        let label = String::from_utf8(take_bytes(raw, &mut at)?.to_vec())
            .map_err(|_| "backup label is not utf-8")?;
        let key_package = Zeroizing::new(take_bytes(raw, &mut at)?.to_vec());
        let public_package = take_bytes(raw, &mut at)?.to_vec();
        let identity = Zeroizing::new(take_bytes(raw, &mut at)?.to_vec());
        let roster = take_bytes(raw, &mut at)?.to_vec();
        let roster_fingerprint: [u8; 32] = raw
            .get(at..at + 32)
            .ok_or("truncated backup fingerprint")?
            .try_into()
            .unwrap();
        at += 32;
        let birth_height = match raw.get(at) {
            Some(0) if raw.len() == at + 1 => None,
            Some(1) if raw.len() == at + 5 => Some(u32::from_be_bytes(
                raw[at + 1..at + 5].try_into().unwrap(),
            )),
            _ => return Err("invalid backup birth height".into()),
        };
        Ok(Self {
            member_id,
            threshold,
            members,
            network,
            vault_id,
            label,
            group_sk,
            key_package,
            public_package,
            backup_epoch,
            identity,
            roster,
            roster_fingerprint,
            birth_height,
        })
    }
}

/// The sealed, portable backup. `magic || SealedShare(plaintext, passphrase-KEK)`.
/// The share plaintext is never in these bytes — only AEAD ciphertext.
pub struct BackupArtifact(pub Vec<u8>);

impl BackupArtifact {
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(&self.0))
    }

    /// Compare with a fingerprint from the original signer or a known-good offline copy,
    /// not with a fingerprint supplied alongside an untrusted backup.
    pub fn check_fingerprint(&self, expected: &str) -> Result<(), String> {
        if hex::decode(expected.trim()).ok().as_deref() != Some(&Sha256::digest(&self.0)[..]) {
            return Err("backup does not match the independently saved SHA-256 fingerprint".into());
        }
        Ok(())
    }
}

/// Argon2id salt for the backup KEK: the vault id (stable, non-secret, vault-scoped).
fn backup_salt(vault_id: &[u8; 32]) -> &[u8] {
    vault_id
}

fn backup_element(passphrase: &str, vault_id: &[u8; 32]) -> Result<SoftwareSecureElement, String> {
    let kek =
        seal_kdf::derive(passphrase, backup_salt(vault_id)).map_err(|_| "backup KDF failed")?;
    Ok(SoftwareSecureElement::from_kek(*kek))
}

/// BACKUP: seal `material` under a KEK derived from `passphrase`. The returned artifact
/// is AEAD ciphertext and is safe to write to disk / show as a QR / store in the member's
/// own cloud; only the same passphrase (and the vault id) can reopen it.
pub fn create(material: &BackupMaterial, passphrase: &str) -> Result<BackupArtifact, String> {
    let se = backup_element(passphrase, &material.vault_id)?;
    let sealed = SealedShare::seal(&se, material.backup_epoch, &material.encode_plaintext())?;
    let mut out = Vec::with_capacity(8 + sealed.to_bytes().len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&sealed.to_bytes());
    Ok(BackupArtifact(out))
}

/// VERIFY (ws1-signer §9: "force the member to save and prove-load their recovery
/// artifact"): reopen the artifact with the passphrase and recover the material. A member
/// runs this right after [`create`] to prove the backup is loadable before the vault
/// activates. Also round-trips through the FROST deserializers so a corrupt share is
/// caught here, not at first signature.
pub fn verify(
    artifact: &BackupArtifact,
    passphrase: &str,
    vault_id: &[u8; 32],
) -> Result<BackupMaterial, String> {
    if artifact.0.len() < 8 || &artifact.0[..8] != BACKUP_MAGIC {
        return Err("not a Loki backup artifact".into());
    }
    let se = backup_element(passphrase, vault_id)?;
    let sealed = SealedShare::from_bytes(&artifact.0[8..])?;
    let plain = sealed.open(&se)?;
    let material = BackupMaterial::decode_plaintext(&plain)?;
    validate_material(material, vault_id)
}

/// Shared post-decode checks for any backup artifact, however it was sealed: it is for this
/// vault, its share + public package parse and derive a valid FVK, and (when present) its
/// identity is the one its own roster names.
fn validate_material(material: BackupMaterial, vault_id: &[u8; 32]) -> Result<BackupMaterial, String> {
    if &material.vault_id != vault_id {
        return Err("backup is for a different vault".into());
    }
    let share = frost::keys::KeyPackage::deserialize(&material.key_package)
        .map_err(|e| format!("backup share does not parse: {e}"))?;
    let public = frost::keys::PublicKeyPackage::deserialize(&material.public_package)
        .map_err(|e| format!("backup public package does not parse: {e}"))?;
    let id = frost::Identifier::try_from(material.member_id).map_err(|e| e.to_string())?;
    let verifying_share = frost::keys::VerifyingShare::from(*share.signing_share());
    if share.identifier() != &id || share.verifying_key() != public.verifying_key()
        || share.min_signers() != &material.threshold || public.min_signers() != Some(material.threshold)
        || public.verifying_shares().len() != usize::from(material.members)
        || share.verifying_share() != &verifying_share
        || public.verifying_shares().get(&id) != Some(&verifying_share) {
        return Err("backup share differs from its public vault metadata".into());
    }
    let ak = material.group_ak()?;
    zip2005::frost_viewing_key(&ak, &material.group_sk)
        .map_err(|e| format!("backup cannot derive the vault FVK: {e:?}"))?;
    if !material.roster.is_empty() {
        // The restored identity must be the one its own roster names.
        let roster = crate::member_state::Roster::from_bytes(&material.roster)?;
        let identity = crate::setup_transport::Identity::from_secret_bytes(&material.identity)?;
        if roster.fingerprint() != material.roster_fingerprint
            || roster.vault != material.vault_id
            || roster.birth_height != material.birth_height
            || roster.threshold != material.threshold
            || roster.members.len() != usize::from(material.members)
            || roster.network.label() != match material.network { Network::Regtest => "regtest", Network::Testnet => "testnet" }
            || roster.members.get(&material.member_id) != Some(&identity.public())
        {
            return Err("backup identity or roster does not match".into());
        }
    } else if !material.identity.is_empty() || material.roster_fingerprint != [0; 32] {
        return Err("backup identity without its roster".into());
    }
    Ok(material)
}

/// RESTORE to a fresh data root. Reconstructs a signing-ready [`LocalSigner`] from the
/// artifact, re-sealing the share under `se` (the NEW device's secure element) and opening
/// the nonce store at `backup_epoch + 1` — the fresh nonce epoch. Any nonce committed
/// before this restore is stamped with a lower epoch and is hard-refused (ws1-signer §8).
///
/// `nonce_dir` MUST be a fresh/empty directory on the new data root.
#[allow(clippy::too_many_arguments)]
pub fn restore<SE: SecureElement>(
    artifact: &BackupArtifact,
    passphrase: &str,
    vault_id: &[u8; 32],
    se: SE,
    nonce_dir: PathBuf,
    approval: ApprovalPolicy,
) -> Result<LocalSigner<SE>, SignerError> {
    let material = verify(artifact, passphrase, vault_id).map_err(SignerError::Other)?;
    rebuild_signer(material, se, nonce_dir, approval)
}

/// Reconstruct a signing-ready signer from already-validated material, re-sealing the share
/// under the NEW device's `se` and opening the nonce store at `backup_epoch + 1`. Shared by
/// the passphrase ([`restore`]) and recovery-words ([`restore_recovery`]) restore paths.
fn rebuild_signer<SE: SecureElement>(
    material: BackupMaterial,
    se: SE,
    nonce_dir: PathBuf,
    approval: ApprovalPolicy,
) -> Result<LocalSigner<SE>, SignerError> {
    let ak = material.group_ak().map_err(SignerError::Other)?;
    let fvk = zip2005::frost_viewing_key(&ak, &material.group_sk)
        .map_err(|e| SignerError::Other(format!("FVK derivation: {e:?}")))?;
    // Fresh nonce epoch: strictly greater than the backed-up epoch.
    let next_epoch = material.backup_epoch.checked_add(1)
        .ok_or_else(|| SignerError::Other("backup epoch overflow".into()))?;
    let nonces = NonceStore::open_at_epoch(&nonce_dir, next_epoch, material.vault_id, material.member_id)
        .map_err(|e| SignerError::Other(e.to_string()))?;
    let identity = if material.identity.is_empty() {
        None
    } else {
        Some(
            crate::setup_transport::Identity::from_secret_bytes(&material.identity)
                .map_err(SignerError::Other)?,
        )
    };
    LocalSigner::from_restored(
        material.member_id,
        material.threshold,
        material.members,
        material.vault_id,
        material.label.clone(),
        material.network,
        se,
        &material.key_package,
        material.public_package.clone(),
        fvk,
        next_epoch,
        nonces,
        approval,
        identity,
    )
}

/// RECOVERY BACKUP: seal `material` to a words-derived recovery PUBLIC key (RFC 9180 HPKE),
/// vault-scoped. Needs only the public key, so the signer makes a fresh backup for every new
/// vault without re-entering its recovery words; only the matching recovery key (the 24 words)
/// can reopen it. The service may hold this artifact — it is opaque ciphertext to anyone but
/// the words-holder. See [`crate::signer::recovery`].
pub fn create_to_recovery(
    material: &BackupMaterial,
    recovery_pub: &[u8; 32],
) -> Result<BackupArtifact, String> {
    if material.roster.is_empty() {
        return Err("this backup has no roster to authenticate its author".into());
    }
    let author = Identity::from_secret_bytes(&material.identity)?;
    let mut signed = Zeroizing::new(RECOVERY_SIGNATURE_DOMAIN.to_vec());
    signed.extend_from_slice(&material.encode_plaintext());
    let signature = author.sign_recovery_backup(&signed);
    signed.extend_from_slice(&signature);
    let blob = crate::signer::recovery::seal_backup(
        recovery_pub,
        &material.vault_id,
        &signed[RECOVERY_SIGNATURE_DOMAIN.len()..],
    )?;
    let mut out = Vec::with_capacity(8 + blob.len());
    out.extend_from_slice(RECOVERY_BACKUP_MAGIC);
    out.extend_from_slice(&blob);
    Ok(BackupArtifact(out))
}

/// Open and validate recovery material. V1 has no author signature. V2 proves that the
/// embedded member signed the payload, but does not establish that the member or vault is
/// trusted. Importers must independently authenticate the artifact before installing it.
pub fn verify_recovery(
    artifact: &BackupArtifact,
    recovery: &crate::signer::recovery::RecoveryKey,
    vault_id: &[u8; 32],
) -> Result<BackupMaterial, String> {
    let signed = match artifact.0.get(..8) {
        Some(magic) if magic == RECOVERY_BACKUP_MAGIC => true,
        Some(magic) if magic == LEGACY_RECOVERY_MAGIC => false,
        _ => return Err("not a Loki recovery backup artifact".into()),
    };
    let plain = recovery.open_backup(vault_id, &artifact.0[8..])?;
    let material = if signed {
        let (payload, sig) = plain.split_at(plain.len().checked_sub(64).ok_or("truncated recovery signature")?);
        let material = BackupMaterial::decode_plaintext(payload)?;
        let author = Identity::from_secret_bytes(&material.identity)?.public();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&author.signing).map_err(|e| e.to_string())?;
        let mut message = Zeroizing::new(RECOVERY_SIGNATURE_DOMAIN.to_vec());
        message.extend_from_slice(payload);
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(sig.try_into().unwrap()))
            .map_err(|_| "invalid recovery backup signature")?;
        material
    } else {
        BackupMaterial::decode_plaintext(&plain)?
    };
    if material.backup_epoch.checked_add(1).is_none() {
        return Err("backup epoch overflow".into());
    }
    validate_material(material, vault_id)
}

/// RESTORE from a recovery-sealed artifact onto a fresh data root (the new-phone path):
/// re-derive the recovery key from the 24 words, open the service-held backup, and rebuild a
/// signing-ready signer under this device's `se`. Mirrors [`restore`]; `nonce_dir` MUST be a
/// fresh/empty directory.
#[allow(clippy::too_many_arguments)]
pub fn restore_recovery<SE: SecureElement>(
    artifact: &BackupArtifact,
    recovery: &crate::signer::recovery::RecoveryKey,
    vault_id: &[u8; 32],
    expected_fingerprint: &str,
    se: SE,
    nonce_dir: PathBuf,
    approval: ApprovalPolicy,
) -> Result<LocalSigner<SE>, SignerError> {
    artifact.check_fingerprint(expected_fingerprint).map_err(SignerError::Other)?;
    let material = verify_recovery(artifact, recovery, vault_id).map_err(SignerError::Other)?;
    rebuild_signer(material, se, nonce_dir, approval)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::nonce::NonceState;
    use crate::signer::secure_element::SoftwareSecureElement;
    use crate::signer::{CandidateRef, Signer};
    use reddsa_frost::frost::redpallas as frost;

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-backup-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// A 2-of-3 dealer vault: member-1 share + public package + a fresh group_sk.
    fn fixture() -> (BackupMaterial, frost::keys::PublicKeyPackage) {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let kp1 = frost::keys::KeyPackage::try_from(shares.get(&id1).unwrap().clone()).unwrap();
        let material = BackupMaterial {
            member_id: 1,
            threshold: 2,
            members: 3,
            network: Network::Regtest,
            vault_id: [7u8; 32],
            label: "backup vault".into(),
            group_sk: [42u8; 32],
            key_package: Zeroizing::new(kp1.serialize().unwrap()),
            public_package: public.serialize().unwrap(),
            backup_epoch: 3,
            identity: Zeroizing::new(Vec::new()),
            roster: Vec::new(),
            roster_fingerprint: [0; 32],
            birth_height: None,
        };
        (material, public)
    }

    #[test]
    fn recovery_artifact_restores_a_signing_share_from_the_words() {
        use crate::signer::recovery::RecoveryKey;
        let (mut material, public) = fixture();
        let vault_id = material.vault_id;
        let ids: Vec<_> = (1..=3).map(Identity::new).collect();
        material.identity = Zeroizing::new(ids[0].to_secret_bytes().to_vec());
        material.roster = serde_json::to_vec(&serde_json::json!({
            "vault": hex::encode(vault_id), "threshold": 2, "setup_version": 2,
            "members": ids.iter().map(|i| serde_json::json!({
                "id": i.public().id, "signing": hex::encode(i.public().signing),
                "encryption": hex::encode(i.public().encryption),
            })).collect::<Vec<_>>(),
        })).unwrap();
        material.roster_fingerprint = crate::member_state::Roster::from_bytes(&material.roster).unwrap().fingerprint();

        // First launch: words + recovery key. Back up to the PUBLIC key only.
        let (words, key) = RecoveryKey::generate().unwrap();
        let art = create_to_recovery(&material, &key.public_bytes()).unwrap();
        drop(key);
        // The share plaintext never appears in the artifact bytes.
        assert!(!art
            .0
            .windows(material.key_package.len())
            .any(|w| w == material.key_package.as_slice()));

        // Wrong words cannot open it.
        let (other, _) = RecoveryKey::generate().unwrap();
        assert!(verify_recovery(&art, &RecoveryKey::from_words(&other).unwrap(), &vault_id).is_err());

        // New phone: re-derive from the SAME words, restore onto a clean root, and sign.
        let restored_key = RecoveryKey::from_words(&words).unwrap();
        let mut signer = restore_recovery(
            &art,
            &restored_key,
            &vault_id,
            &art.fingerprint(),
            SoftwareSecureElement::generate(),
            tempdir("recovery-nonces"),
            Box::new(|_v| true),
        )
        .unwrap();
        signer.adopt_restored_roster(&material.roster, Box::new(|_, _| true)).unwrap();

        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &material.group_sk).unwrap();
        let key1 = frost::keys::KeyPackage::deserialize(&material.key_package).unwrap();
        let cand = CandidateRef {
            vault_id,
            payment_id: [3u8; 32],
            attempt_id: [4u8; 32],
        };
        let session = signer
            .connect("http://coordinator.test", Network::Regtest, b"c")
            .unwrap()
            .session;
        let own = signer.sign_commit(&session, &cand).unwrap();
        let key2 = {
            let (shares, _p) = frost::keys::generate_with_dealer(
                3,
                2,
                frost::keys::IdentifierList::Default,
                &mut rand_core::OsRng,
            )
            .unwrap();
            frost::keys::KeyPackage::try_from(
                shares.get(&frost::Identifier::try_from(2u16).unwrap()).unwrap().clone(),
            )
            .unwrap()
        };
        let (pczt, pkg, seed) = crate::signer::local::tests::candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng).1,
            own,
            true,
        );
        let share = signer
            .sign_approve(&session, &cand, &crate::signer::local::tests::payment_params(&fvk), &pczt, &pkg, &seed)
            .expect("the words-restored share must sign a candidate for its group key");
        assert_eq!(share.serialize().len(), 32);
    }

    #[test]
    fn restored_signer_adopts_only_its_backup_roster() {
        use crate::setup_transport::Identity;
        let (mut material, _public) = fixture();
        let ids: Vec<Identity> = (1..=3).map(Identity::new).collect();
        let doc = |vault: [u8; 32]| {
            serde_json::to_vec(&serde_json::json!({
                "vault": hex::encode(vault), "threshold": 2, "setup_version": 2,
                "members": ids.iter().map(|i| serde_json::json!({
                    "id": i.public().id,
                    "signing": hex::encode(i.public().signing),
                    "encryption": hex::encode(i.public().encryption),
                })).collect::<Vec<_>>(),
            }))
            .unwrap()
        };
        let roster = doc(material.vault_id);
        material.identity = Zeroizing::new(ids[0].to_secret_bytes().to_vec());
        material.roster_fingerprint = crate::member_state::Roster::from_bytes(&roster).unwrap().fingerprint();
        material.roster = roster.clone();
        let art = create(&material, "pw").unwrap();
        let restore_one = || {
            restore(&art, "pw", &material.vault_id, SoftwareSecureElement::generate(), tempdir("adopt"), Box::new(|_v| true))
                .unwrap()
        };

        let connect = || -> crate::signer::local::ConnectApproval { Box::new(|_origin, _net| true) };
        let mut other = restore_one();
        assert!(other.adopt_restored_roster(&doc([8u8; 32]), connect()).is_err(), "a roster for another vault");
        let mut signer = restore_one();
        assert!(signer.confirmed_roster().is_none());
        // Without the adopted connect prompt a restored member's session is never approved.
        let unapproved = signer.connect("https://coordinator", Network::Regtest, b"before").unwrap().session;
        assert!(matches!(signer.release_address(&unapproved), Err(SignerError::ConnectRefused)));
        signer.adopt_restored_roster(&roster, connect()).unwrap();
        assert_eq!(signer.confirmed_roster().unwrap().members.len(), 3);
        assert!(signer.adopt_restored_roster(&roster, connect()).is_err(), "adopted once");

        // Restored, the member connects, releases the vault's address (from the FVK the backup
        // re-derives, as the DKG did) and can commit a signing nonce.
        let session = signer.connect("https://coordinator", Network::Regtest, b"after").unwrap().session;
        let released = signer.release_address(&session).unwrap();
        let fvk = zip2005::frost_viewing_key(&material.group_ak().unwrap(), &material.group_sk).unwrap();
        assert_eq!(released.vault_id, material.vault_id);
        assert_eq!(released.address, crate::vault::unified_address(&fvk, zcash_protocol::consensus::NetworkType::Regtest));
        let cand = CandidateRef { vault_id: material.vault_id, payment_id: [3; 32], attempt_id: [4; 32] };
        signer.sign_commit(&session, &cand).unwrap();
    }

    #[test]
    fn artifact_is_ciphertext_and_verifies_only_with_the_passphrase() {
        let (material, _public) = fixture();
        let art = create(&material, "correct horse").unwrap();
        // The share plaintext never appears in the artifact bytes.
        assert!(!art
            .0
            .windows(material.key_package.len())
            .any(|w| w == material.key_package.as_slice()));
        // Wrong passphrase fails; right one recovers the material.
        assert!(verify(&art, "wrong", &material.vault_id).is_err());
        let back = verify(&art, "correct horse", &material.vault_id).unwrap();
        assert_eq!(back.member_id, 1);
        assert_eq!(back.backup_epoch, 3);
        assert_eq!(&*back.key_package, &*material.key_package);
        assert_eq!(back.group_sk, material.group_sk);
    }

    // Acceptance (a): backup -> restore on a CLEAN data root yields a share that signs a
    // candidate for its group key. (b): a nonce committed BEFORE restore is hard-refused
    // after restore.
    #[test]
    fn restore_on_clean_root_signs_and_refuses_pre_restore_nonce() {
        let (material, public) = fixture();
        let vault_id = material.vault_id;
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &material.group_sk).unwrap();
        let key1 = frost::keys::KeyPackage::deserialize(&material.key_package).unwrap();

        // --- Pre-restore signer (epoch 3): commit a nonce, capturing its sealed file. ---
        let old_nonce_dir = tempdir("old-nonces");
        let pre = NonceStore::open_at_epoch(&old_nonce_dir, 3, vault_id, material.member_id).unwrap();
        let cand = CandidateRef {
            vault_id,
            payment_id: [1u8; 32],
            attempt_id: [2u8; 32],
        };
        let nonce_id = {
            let mut s = String::new();
            for b in cand.payment_id.iter().chain(cand.attempt_id.iter()) {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        let pre_se = SoftwareSecureElement::generate();
        pre.commit(&nonce_id, &pre_se, key1.signing_share(), None)
            .unwrap();
        assert_eq!(pre.state(&nonce_id), NonceState::Committed);

        // --- BACKUP then RESTORE onto a CLEAN data root (fresh dir, new element). ---
        let art = create(&material, "pw").unwrap();
        let fresh_nonce_dir = tempdir("fresh-nonces");
        let mut signer = restore(
            &art,
            "pw",
            &vault_id,
            SoftwareSecureElement::generate(),
            fresh_nonce_dir.clone(),
            Box::new(|_v| true),
        )
        .unwrap();

        // The restored signer signs a candidate for the group key (clean-root happy path).
        let session = signer
            .connect("http://coordinator.test", Network::Regtest, b"c")
            .unwrap()
            .session;
        let own = signer.sign_commit(&session, &cand).unwrap();
        let key2 = {
            // A stand-in peer commitment from a second dealer share of the same vault.
            // (We only need a well-formed package over the pczt's real sighash.)
            let (shares, _p) = frost::keys::generate_with_dealer(
                3,
                2,
                frost::keys::IdentifierList::Default,
                &mut rand_core::OsRng,
            )
            .unwrap();
            frost::keys::KeyPackage::try_from(
                shares
                    .get(&frost::Identifier::try_from(2u16).unwrap())
                    .unwrap()
                    .clone(),
            )
            .unwrap()
        };
        let (pczt, pkg, seed) = crate::signer::local::tests::candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng).1,
            own,
            true,
        );
        let share = signer
            .sign_approve(&session, &cand, &crate::signer::local::tests::payment_params(&fvk), &pczt, &pkg, &seed)
            .expect("restored share must sign a candidate for its group key");
        assert_eq!(share.serialize().len(), 32);

        // --- (b) The pre-restore nonce file, dropped into the restored store, is refused. ---
        // Copy the stale (epoch-3) nonce file into the fresh (epoch-4) store, as a
        // rollback/replay attacker would, and confirm the restored signer never signs it.
        let stale = std::fs::read(old_nonce_dir.join(format!("{nonce_id}.nonce"))).unwrap();
        let cand2 = CandidateRef {
            vault_id,
            payment_id: [9u8; 32],
            attempt_id: [9u8; 32],
        };
        let nonce_id2 = {
            let mut s = String::new();
            for b in cand2.payment_id.iter().chain(cand2.attempt_id.iter()) {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        std::fs::write(fresh_nonce_dir.join(format!("{nonce_id2}.nonce")), &stale).unwrap();
        let refused = signer.sign_approve(&session, &cand2, &crate::signer::local::tests::payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(
            matches!(&refused, Err(SignerError::Other(m)) if m.contains("pre-restore epoch")),
            "a pre-restore-epoch nonce must be hard-refused after restore, got {refused:?}"
        );
    }
}
