//! At-rest key hierarchy (ws1-signer §5).
//!
//! ```text
//! KEK  (SecureElement: Enclave/StrongBox/TPM, non-exportable)
//!   │ unwraps
//! DEK  (random, per sealed share)
//!   │ AEAD-decrypts
//! share bytes
//! ```
//!
//! The share on disk is ONLY ever ciphertext: a random DEK seals the share with
//! XChaCha20-Poly1305, and the DEK itself is wrapped by a KEK that lives behind the
//! [`SecureElement`] trait. The software fallback here wraps the DEK with its own
//! XChaCha20-Poly1305 key held in memory; Secure Enclave (iOS/macOS) and Android
//! StrongBox implement the SAME trait later, moving the KEK into non-exportable
//! hardware with biometric release. Nothing above the trait changes when they do.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// A DEK wrapped by the secure element's KEK. Opaque bytes; only a [`SecureElement`]
/// that holds the matching KEK can unwrap it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedDek(pub Vec<u8>);

#[derive(Debug)]
pub enum OpenError {
    WrongBinding(String),
    Element(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongBinding(message) | Self::Element(message) => f.write_str(message),
        }
    }
}

/// Platform secure element: holds a non-exportable KEK and wraps/unwraps data keys.
///
/// Real implementations (Secure Enclave, StrongBox, TPM) gate `unwrap_dek` behind a
/// biometric/passphrase unlock; the trait is identical so the share store is swappable
/// behind it (ws1-signer §4 "Hardware path"). A KEK never leaves the element — only
/// wrapped DEKs cross this boundary.
pub trait SecureElement {
    /// Wrap a freshly generated 32-byte DEK under the element's KEK.
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String>;
    /// Release the DEK after unlock. The caller must zeroize the result.
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, OpenError>;
}

/// Software fallback KEK (desktop without a TPM, ws1-signer §4 reduced-guarantee row).
/// The KEK sits in process memory; a real element keeps it non-exportable. The wrap
/// format is XChaCha20-Poly1305(KEK) over the DEK, so the on-disk DEK is ciphertext.
pub struct SoftwareSecureElement {
    kek: Zeroizing<[u8; 32]>,
}

impl SoftwareSecureElement {
    /// A random KEK. In production this handle is the element itself, not raw bytes.
    pub fn generate() -> Self {
        let mut kek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *kek);
        Self { kek }
    }

    /// Reconstruct from a persisted KEK (software fallback only; real elements never
    /// expose this). Used so a restarted process can unwrap DEKs it sealed before.
    pub fn from_kek(kek: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek),
        }
    }

    /// The persistent software KEK for a signer data directory (A5). The first call for a
    /// directory draws a random KEK and stores it once in `kek.sealed`, encrypted under the
    /// member passphrase (`MemberDir::write_sealed`: Argon2id, write-once, fsync'd); later
    /// calls reopen it. A Secure Enclave backend replaces this behind the same trait.
    pub fn persistent(dir: &std::path::Path, passphrase: &str) -> Result<Self, String> {
        if !dir.join(KEK_FILE).exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
                    .map_err(|e| format!("signer directory: {e}"))?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(dir).map_err(|e| format!("signer directory: {e}"))?;
        }
        let store = crate::state::MemberDir::open(dir, "");
        if !dir.join(KEK_FILE).exists() {
            let mut kek = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *kek);
            store
                .write_sealed(KEK_FILE, &*kek, passphrase)
                .map_err(|e| format!("signer KEK: {e}"))?;
        }
        let raw = Zeroizing::new(
            store
                .read_sealed(KEK_FILE, passphrase)
                .map_err(|_| "signer KEK: wrong passphrase or tampered file".to_string())?,
        );
        let kek: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "signer KEK is not 32 bytes".to_string())?;
        Ok(Self::from_kek(kek))
    }

    /// Derive the KEK straight from a passphrase over an explicit `salt` (Argon2id, the same
    /// stretch as the native `kek.sealed`). The in-browser signer owns its salt file in OPFS
    /// rather than the native `MemberDir` sealed-KEK layout, so this skips `std::fs` entirely
    /// while keeping the derivation identical. Pair with [`fresh_kek_salt`] on first create.
    pub fn from_passphrase(passphrase: &str, salt: &[u8]) -> Result<Self, String> {
        let kek = crate::seal_kdf::derive(passphrase, salt)
            .map_err(|_| "passphrase KEK derivation failed (salt too short?)".to_string())?;
        Ok(Self::from_kek(*kek))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&*self.kek).expect("32-byte KEK")
    }
}

/// A fresh 16-byte Argon2id salt for [`SoftwareSecureElement::from_passphrase`]. The
/// in-browser signer persists this beside the sealed share so a reload re-derives the KEK.
pub fn fresh_kek_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

const KEK_FILE: &str = "kek.sealed";

const WRAP_AAD: &[u8] = b"Loki_signer_dek_wrap_v1";

impl SecureElement for SoftwareSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        let mut nonce = XNonce::default();
        OsRng.fill_bytes(nonce.as_mut_slice());
        let ct = self
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: dek,
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| "DEK wrap failed".to_string())?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(WrappedDek(out))
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, OpenError> {
        if wrapped.0.len() < 24 {
            return Err(OpenError::WrongBinding("truncated wrapped DEK".into()));
        }
        let (nonce, ct) = wrapped.0.split_at(24);
        let mut plain = self
            .cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload { msg: ct, aad: WRAP_AAD },
            )
            .map_err(|_| OpenError::WrongBinding("DEK unwrap failed (wrong KEK or tampered)".into()))?;
        let dek: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| OpenError::WrongBinding("unwrapped DEK is not 32 bytes".into()))?;
        plain.zeroize();
        Ok(Zeroizing::new(dek))
    }
}

const SHARE_MAGIC: &[u8; 8] = b"LOKISHR1";
const SHARE_AAD: &[u8] = b"Loki_signer_share_seal_v1";

/// The associated data binding one signer file to its type, vault and member.
pub fn file_binding(kind: &str, vault: &[u8; 32], member: u16) -> Vec<u8> {
    let mut out = b"Loki_signer_file_v2".to_vec();
    out.push(kind.len() as u8);
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(vault);
    out.extend_from_slice(&member.to_be_bytes());
    out
}

/// A FROST share at rest: ciphertext under a DEK, DEK wrapped by the secure element.
/// The blob written to disk is `magic || backup_epoch || wrapped_dek || nonce || ct`.
/// There is no path that returns the plaintext share except [`SealedShare::open`],
/// which needs the matching [`SecureElement`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedShare {
    /// Rolls forward on restore-from-backup so a rolled-back store is detectable
    /// (ws1-signer §5, ties to nonce epoch in §8).
    pub backup_epoch: u64,
    wrapped_dek: WrappedDek,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl SealedShare {
    /// Seal `share` with a fresh random DEK wrapped by `se`. Plaintext never persists.
    pub fn seal(
        se: &impl SecureElement,
        backup_epoch: u64,
        share: &[u8],
    ) -> Result<Self, String> {
        Self::seal_with_aad(se, backup_epoch, share, SHARE_AAD)
    }

    /// Seal under a caller-supplied binding, so the blob opens only for the same binding.
    /// Signer storage binds each file to its type, vault and member ([`file_binding`]).
    pub fn seal_bound(
        se: &impl SecureElement,
        backup_epoch: u64,
        plaintext: &[u8],
        binding: &[u8],
    ) -> Result<Self, String> {
        Self::seal_with_aad(se, backup_epoch, plaintext, binding)
    }

    fn seal_with_aad(
        se: &impl SecureElement,
        backup_epoch: u64,
        share: &[u8],
        aad: &[u8],
    ) -> Result<Self, String> {
        let mut dek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *dek);
        let wrapped_dek = se.wrap_dek(&dek)?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&*dek).expect("32-byte DEK");
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload { msg: share, aad },
            )
            .map_err(|_| "share seal failed".to_string())?;
        Ok(Self {
            backup_epoch,
            wrapped_dek,
            nonce,
            ciphertext,
        })
    }

    /// Unwrap the DEK via `se`, then AEAD-decrypt the share. Caller zeroizes the result.
    pub fn open(&self, se: &impl SecureElement) -> Result<Zeroizing<Vec<u8>>, String> {
        self.open_bound(se, SHARE_AAD).map_err(|e| e.to_string())
    }

    /// Open a blob sealed with [`SealedShare::seal_bound`] under the same `binding`. A blob
    /// moved to another file type, vault or member fails authentication.
    pub fn open_bound(
        &self,
        se: &impl SecureElement,
        binding: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        let dek = se.unwrap_dek(&self.wrapped_dek)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*dek).expect("32-byte DEK");
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: binding,
                },
            )
            .map_err(|_| OpenError::WrongBinding("share open failed (wrong element or tampered blob)".into()))?;
        Ok(Zeroizing::new(plain))
    }

    /// The exact ciphertext blob to write to disk. Never contains the share plaintext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SHARE_MAGIC);
        out.extend_from_slice(&self.backup_epoch.to_be_bytes());
        out.extend_from_slice(&(self.wrapped_dek.0.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.wrapped_dek.0);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 8 + 8 + 4 || &raw[..8] != SHARE_MAGIC {
            return Err("not a sealed share blob".into());
        }
        let backup_epoch = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        let dek_len = u32::from_be_bytes(raw[16..20].try_into().unwrap()) as usize;
        let mut at = 20;
        if raw.len() < at + 24 || dek_len > raw.len() - at - 24 {
            return Err("truncated sealed share blob".into());
        }
        let wrapped_dek = WrappedDek(raw[at..at + dek_len].to_vec());
        at += dek_len;
        let nonce: [u8; 24] = raw[at..at + 24].try_into().unwrap();
        at += 24;
        Ok(Self {
            backup_epoch,
            wrapped_dek,
            nonce,
            ciphertext: raw[at..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_blob_is_ciphertext_and_roundtrips() {
        let se = SoftwareSecureElement::generate();
        let share = b"a FROST signing share worth forging";
        let sealed = SealedShare::seal(&se, 1, share).unwrap();
        let blob = sealed.to_bytes();
        // The plaintext share never appears in the on-disk bytes.
        assert!(!blob.windows(share.len()).any(|w| w == share));
        let reopened = SealedShare::from_bytes(&blob).unwrap();
        assert_eq!(reopened, sealed);
        assert_eq!(&**reopened.open(&se).unwrap(), share);
        assert_eq!(reopened.backup_epoch, 1);
    }

    #[test]
    fn passphrase_salt_element_round_trips_and_rejects_wrong_passphrase() {
        let salt = fresh_kek_salt();
        let se = SoftwareSecureElement::from_passphrase("correct horse battery staple", &salt);
        let se = se.unwrap();
        let sealed = SealedShare::seal(&se, 0, b"device identity secret").unwrap();
        // Same passphrase + same salt re-derive the KEK and reopen.
        let again =
            SoftwareSecureElement::from_passphrase("correct horse battery staple", &salt).unwrap();
        assert_eq!(
            &**SealedShare::from_bytes(&sealed.to_bytes())
                .unwrap()
                .open(&again)
                .unwrap(),
            b"device identity secret"
        );
        // Wrong passphrase derives a different KEK and cannot open.
        let wrong = SoftwareSecureElement::from_passphrase("wrong", &salt).unwrap();
        assert!(sealed.open(&wrong).is_err());
    }

    #[test]
    fn wrong_element_cannot_open() {
        let se = SoftwareSecureElement::generate();
        let other = SoftwareSecureElement::generate();
        let sealed = SealedShare::seal(&se, 0, b"share").unwrap();
        assert!(sealed.open(&other).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let se = SoftwareSecureElement::generate();
        let sealed = SealedShare::seal(&se, 0, b"share").unwrap();
        let mut blob = sealed.to_bytes();
        *blob.last_mut().unwrap() ^= 0xff;
        let tampered = SealedShare::from_bytes(&blob).unwrap();
        assert!(tampered.open(&se).is_err());
    }
}
