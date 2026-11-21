//! Apple Secure Enclave backend of [`SecureElement`] (ws1-signer §4 "Hardware path").
//!
//! The Enclave is P-256 only, so — exactly like the software fallback — it does not hold
//! the FROST share: it holds the KEK and wraps/unwraps the per-share DEK via ECIES
//! (`eciesEncryptionCofactorX963SHA256AESGCM`). The share seals under that DEK in
//! [`super::secure_element::SealedShare`]; nothing above the trait changes versus
//! [`super::secure_element::SoftwareSecureElement`].
//!
//! Key lifetimes (both expose the identical wrap/unwrap surface):
//! - [`AppleSecureElement::ephemeral`] — process-lifetime key, no keychain, no signing
//!   identity. Works unsigned and offline; this is what the FFI verifier exercises today.
//! - [`AppleSecureElement::open_persistent`] — `kSecAttrIsPermanent` + `kSecAttrApplicationTag`
//!   with biometric access control (`.biometryCurrentSet | .privateKeyUsage`), so
//!   `unwrap_dek` is gated behind Face/Touch ID and the key dies if enrolled biometrics
//!   change. **Requires the binary signed with an Apple Team ID** (a free personal team is
//!   enough); unsigned, key creation fails with `errSecMissingEntitlement` (-34018).
//!
//! The Swift side lives in `core/enclave-spike/se_backend.swift` (built to a dylib). Wiring
//! this module into the main crate build is the remaining non-crypto gate — see
//! `core/enclave-spike/BACKEND.md`.
//!
//! ponytail: this module compiles only on macOS behind `#[cfg(target_os = "macos")]` and
//! links `libse_backend`; the crate must declare that link (build.rs or `#[link]`) before
//! it is reachable from the main build. Until then it is verified standalone by
//! `core/enclave-spike/apple_ffi_verify.rs`.

use super::secure_element::{OpenError, SecureElement, WrappedDek};
use std::{ffi::{c_char, CString}, os::unix::ffi::OsStrExt, path::Path};
use zeroize::Zeroizing;

// C-ABI surface implemented in se_backend.swift. Lengths are `isize`-shaped `Int` on the
// Swift side; we pass `isize`. Negative returns are error codes (see se_backend.swift).
extern "C" {
    fn se_open_ephemeral(out_handle: *mut u64) -> isize;
    fn se_open_persistent(tag: *const u8, tag_len: isize, create_if_missing: i32, state_path: *const c_char, out_handle: *mut u64) -> isize;
    fn se_open_payment(tag: *const u8, tag_len: isize, state_path: *const c_char, reason: *const c_char, out_handle: *mut u64) -> isize;
    fn se_create_staged(tag: *const u8, tag_len: isize, state_path: *const c_char, out_handle: *mut u64) -> isize;
    fn se_confirm_staged_biometry(handle: u64, state_path: *const c_char) -> isize;
    fn se_discard_staged(tag: *const u8, tag_len: isize) -> isize;
    fn se_wrap(handle: u64, dek: *const u8, dek_len: isize, out: *mut u8, out_cap: isize) -> isize;
    fn se_unwrap(handle: u64, ct: *const u8, ct_len: isize, out: *mut u8, out_cap: isize) -> isize;
    fn se_sign(handle: u64, msg: *const u8, msg_len: isize, out: *mut u8, out_cap: isize) -> isize;
    fn se_public_key(handle: u64, out: *mut u8, out_cap: isize) -> isize;
    fn se_close(handle: u64);
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyFailure {
    Missing,
    Invalidated,
    Cancelled,
    AuthenticationFailed,
    AuthenticationFailedWithoutState,
    LockedOut,
    InteractionNotAllowed,
    BiometryUnavailable,
    BiometryNotEnrolled,
    BiometryDisconnected,
    BiometryNotPaired,
    RestoreEnrollmentChanged,
    Other,
}

const KEY_GONE: &str = "This LokiSigner key is missing or no longer usable. Set aside this profile, then choose “Restore from recovery words” with your recovery words and downloaded backup file.";

// Stable Swift ABI codes and fixed member copy. Unknown codes never cross into the UI.
const FAILURES: &[(isize, KeyFailure, &str)] = &[
    (-6, KeyFailure::Missing, KEY_GONE),
    (-17, KeyFailure::Invalidated, KEY_GONE),
    (-11, KeyFailure::Cancelled, "Touch ID was cancelled."),
    (-12, KeyFailure::AuthenticationFailed, "Touch ID did not verify your fingerprint. Try again."),
    (-20, KeyFailure::AuthenticationFailedWithoutState, "Touch ID did not verify your fingerprint. Try again. If you added or removed a fingerprint, restore using your recovery words and downloaded backup file on another Mac or in another macOS account."),
    (-13, KeyFailure::LockedOut, "Touch ID is locked out. Unlock your Mac with its password, then try again."),
    (-14, KeyFailure::InteractionNotAllowed, "Touch ID cannot prompt right now. Unlock your Mac and try again in LokiSigner."),
    (-15, KeyFailure::BiometryUnavailable, "Touch ID is not available right now. If you’re using a MacBook, open its lid and try again."),
    (-16, KeyFailure::BiometryNotEnrolled, "No fingerprint is enrolled for Touch ID. Add one in System Settings, then try again."),
    (-18, KeyFailure::BiometryDisconnected, "Your Touch ID accessory is disconnected. Reconnect it and try again."),
    (-19, KeyFailure::BiometryNotPaired, "No Touch ID accessory is paired. Pair it with this Mac and try again."),
    (-21, KeyFailure::RestoreEnrollmentChanged, "Touch ID enrollment changed during restore. Try restoring again."),
    (-4, KeyFailure::Other, "LokiSigner could not access its Secure Enclave key."),
];

impl KeyFailure {
    fn from_code(code: isize) -> Self {
        FAILURES.iter().find(|(value, _, _)| *value == code).map_or(Self::Other, |(_, kind, _)| *kind)
    }

    pub fn is_gone(self) -> bool {
        matches!(self, Self::Missing | Self::Invalidated)
    }

    pub fn message(self) -> &'static str {
        FAILURES.iter().find(|(_, kind, _)| *kind == self).unwrap().2
    }
}

impl std::fmt::Display for KeyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// Extract only fixed key errors for native surfaces that otherwise redact host errors.
/// SignerStore may have prepended a file label to the element error.
pub fn member_key_message(error: &str) -> Option<&'static str> {
    let text = error.rsplit(": ").next().unwrap_or(error);
    FAILURES.iter().map(|(_, _, message)| *message).find(|message| *message == text)
}

/// A live Secure Enclave KEK handle. Wraps/unwraps DEKs through the Enclave; the KEK never
/// crosses this boundary (`SecKeyCopyExternalRepresentation` refuses, proven in the spike).
pub struct AppleSecureElement {
    handle: u64,
}

impl AppleSecureElement {
    /// Open a fresh process-lifetime Enclave key. No signing identity required.
    pub fn ephemeral() -> Result<Self, String> {
        let mut handle = 0u64;
        let rc = unsafe { se_open_ephemeral(&mut handle) };
        if rc != 0 {
            return Err(format!("se_open_ephemeral failed (code {rc})"));
        }
        Ok(Self { handle })
    }

    /// Open the persistent, biometric-gated key without ever creating a replacement.
    pub fn open_persistent(tag: &[u8], state: Option<&Path>) -> Result<Self, KeyFailure> {
        Self::persistent(tag, state, false, None)
    }

    /// For new sealed data only: reuse a key for `tag` or create it if it is absent.
    pub fn create_persistent(tag: &[u8], state: Option<&Path>) -> Result<Self, KeyFailure> {
        Self::persistent(tag, state, true, None)
    }

    /// Create under a restore-only tag that the caller has already journaled for rollback.
    pub fn create_staged(tag: &[u8], state: &Path) -> Result<Self, KeyFailure> {
        let state = CString::new(state.as_os_str().as_bytes()).map_err(|_| KeyFailure::Other)?;
        let mut handle = 0;
        let rc = unsafe { se_create_staged(tag.as_ptr(), tag.len() as isize, state.as_ptr(), &mut handle) };
        if rc == 0 { Ok(Self { handle }) } else { Err(KeyFailure::from_code(rc)) }
    }

    /// Compare with the enrollment sampled at staging. After a successful private
    /// operation, pass its state path to record the verified enrollment before publication.
    pub fn confirm_staged_biometry(&self, state: Option<&Path>) -> Result<(), KeyFailure> {
        let state = state.map(|path| CString::new(path.as_os_str().as_bytes())).transpose().map_err(|_| KeyFailure::Other)?;
        let ptr = state.as_ref().map_or(std::ptr::null(), |path| path.as_ptr());
        let rc = unsafe { se_confirm_staged_biometry(self.handle, ptr) };
        if rc == 0 { Ok(()) } else { Err(KeyFailure::from_code(rc)) }
    }

    pub fn discard_staged(tag: &[u8]) -> Result<(), KeyFailure> {
        let rc = unsafe { se_discard_staged(tag.as_ptr(), tag.len() as isize) };
        if rc == 0 { Ok(()) } else { Err(KeyFailure::from_code(rc)) }
    }

    /// Authorize this existing vault key for one payment or one viewing-key open.
    /// Dropping the handle invalidates the context; it is never eligible for device login
    /// or returned to an app-wide cache.
    pub fn open_payment(tag: &[u8], state: Option<&Path>, reason: &str) -> Result<Self, KeyFailure> {
        let reason = CString::new(reason).map_err(|_| KeyFailure::Other)?;
        Self::persistent(tag, state, false, Some(&reason))
    }

    fn persistent(tag: &[u8], state: Option<&Path>, create_if_missing: bool, reason: Option<&std::ffi::CStr>) -> Result<Self, KeyFailure> {
        let mut handle = 0u64;
        let state = state.map(|path| CString::new(path.as_os_str().as_bytes())).transpose().map_err(|_| KeyFailure::Other)?;
        let ptr = state.as_ref().map_or(std::ptr::null(), |path| path.as_ptr());
        let rc = unsafe {
            match reason {
                Some(reason) => se_open_payment(tag.as_ptr(), tag.len() as isize, ptr, reason.as_ptr(), &mut handle),
                None => se_open_persistent(tag.as_ptr(), tag.len() as isize, i32::from(create_if_missing), ptr, &mut handle),
            }
        };
        if rc != 0 {
            return Err(KeyFailure::from_code(rc));
        }
        Ok(Self { handle })
    }
}

impl AppleSecureElement {
    /// Sign `msg` with the Enclave key (ECDSA/SHA-256, DER) — the device login-challenge
    /// signature. On a persistent biometric key this prompts Face/Touch ID; the private op
    /// stays inside the Enclave. Verified by [`crate::signer::device_auth::DeviceRegistry`].
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyFailure> {
        // A P-256 ECDSA DER signature is <= 72 bytes; 128 is a comfortable ceiling.
        let mut out = vec![0u8; 128];
        let n = unsafe {
            se_sign(self.handle, msg.as_ptr(), msg.len() as isize, out.as_mut_ptr(), out.len() as isize)
        };
        if n <= 0 {
            return Err(KeyFailure::from_code(n));
        }
        out.truncate(n as usize);
        Ok(out)
    }

    /// The Enclave key's PUBLIC point, X9.63 uncompressed (`04 || X || Y`, 65 bytes for P-256).
    /// This is what Loki enrolls as the device key; the private key never leaves the Enclave.
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, KeyFailure> {
        let mut out = vec![0u8; 128];
        let n = unsafe { se_public_key(self.handle, out.as_mut_ptr(), out.len() as isize) };
        if n <= 0 {
            return Err(KeyFailure::from_code(n));
        }
        out.truncate(n as usize);
        Ok(out)
    }
}

impl Drop for AppleSecureElement {
    fn drop(&mut self) {
        unsafe { se_close(self.handle) };
    }
}

// ECIES(P-256, X9.63-SHA256, AES-GCM) ciphertext of a 32-byte DEK is 113 bytes (measured
// in the spike); 256 is a comfortable ceiling. The unwrap output is exactly the 32-byte DEK.
const WRAP_OUT_CAP: usize = 256;

impl SecureElement for AppleSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        let mut out = vec![0u8; WRAP_OUT_CAP];
        let n = unsafe {
            se_wrap(self.handle, dek.as_ptr(), 32, out.as_mut_ptr(), out.len() as isize)
        };
        if n <= 0 {
            return Err(KeyFailure::from_code(n).to_string());
        }
        out.truncate(n as usize);
        Ok(WrappedDek(out))
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, OpenError> {
        let mut out = Zeroizing::new([0u8; 64]);
        let n = unsafe {
            se_unwrap(
                self.handle,
                wrapped.0.as_ptr(),
                wrapped.0.len() as isize,
                out.as_mut_ptr(),
                out.len() as isize,
            )
        };
        if n != 32 {
            return Err(OpenError::Element(KeyFailure::from_code(n).to_string()));
        }
        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&out[..32]);
        Ok(dek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enclave_failures_have_fixed_member_messages() {
        assert_eq!(KeyFailure::from_code(-6), KeyFailure::Missing);
        assert_eq!(KeyFailure::from_code(-17), KeyFailure::Invalidated);
        assert!(!KeyFailure::from_code(-11).is_gone(), "cancellation must not allow set-aside");
        for (code, expected) in [
            (-6, KEY_GONE),
            (-17, KEY_GONE),
            (-11, "Touch ID was cancelled."),
            (-12, "Touch ID did not verify your fingerprint. Try again."),
            (-20, "Touch ID did not verify your fingerprint. Try again. If you added or removed a fingerprint, restore using your recovery words and downloaded backup file on another Mac or in another macOS account."),
            (-13, "Touch ID is locked out. Unlock your Mac with its password, then try again."),
            (-14, "Touch ID cannot prompt right now. Unlock your Mac and try again in LokiSigner."),
            (-15, "Touch ID is not available right now. If you’re using a MacBook, open its lid and try again."),
            (-16, "No fingerprint is enrolled for Touch ID. Add one in System Settings, then try again."),
            (-18, "Your Touch ID accessory is disconnected. Reconnect it and try again."),
            (-19, "No Touch ID accessory is paired. Pair it with this Mac and try again."),
            (-34018, "LokiSigner could not access its Secure Enclave key."),
        ] {
            assert_eq!(KeyFailure::from_code(code).message(), expected);
            assert_eq!(member_key_message(&format!("signer share file: {expected}")), Some(expected));
        }
        assert_eq!(member_key_message("signer share file: se_unwrap failed (code -4)"), None);
    }

    // Exercises the REAL Secure Enclave through the FFI (ephemeral key — no signing
    // identity / keychain needed, so it runs in a bare test binary). Persistence +
    // biometrics need the provisioned app context (see core/signer-app/).
    #[test]
    fn apple_enclave_wraps_and_unwraps_a_dek() {
        let se = AppleSecureElement::ephemeral().expect("open ephemeral Secure Enclave");
        let dek = [7u8; 32];
        let wrapped = se.wrap_dek(&dek).expect("wrap_dek via the Enclave");
        assert!(wrapped.0.len() > 32, "ECIES ciphertext is larger than the DEK");
        let back = se.unwrap_dek(&wrapped).expect("unwrap_dek via the Enclave");
        assert_eq!(&*back, &dek, "DEK round-trips through the Secure Enclave");
    }
}
