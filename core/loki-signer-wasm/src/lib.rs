//! wasm-bindgen bindings for the in-browser FROST signer.
//!
//! Phase 3 slice: the trust-critical, persistence-free custody primitive, proven to run
//! in the browser — seal/open a FROST share under a WebAuthn-PRF-derived KEK (W2's
//! [`WebAuthnSecureElement`]). This is the piece the onboarding UX needs first: the share
//! is wrapped under the passkey's PRF secret (released by Touch/Face ID / security key /
//! phone) and persisted sealed; a reload re-derives the same KEK and reopens it.
//!
//! The full stateful `SignerModule` (web/wallet/src/lib/signer.ts) — `createSigner` →
//! sealed share in OPFS, DKG/signing over the frostd transport, `request(path, body)` —
//! builds on top of this once the synchronous OPFS store seam replaces `store.rs`'s
//! `std::fs` (the core stays synchronous; the signer runs in a Web Worker where OPFS
//! `createSyncAccessHandle` gives synchronous file I/O). See the Phase 3 report.

use loki_signer_core::setup_transport::{Identity, PublicIdentity};
use loki_signer_core::signer::backup::{self, BackupArtifact, BackupMaterial};
use loki_signer_core::signer::recovery::RecoveryKey;
use loki_signer_core::member_state::Roster;
use loki_signer_core::network::VaultNetwork;
use loki_signer_core::chain_scan::ChainScan;
use loki_signer_core::signer::local::{
    self, BackupDevice, DevicePrompts, LocalSigner, RosterDecision, SignerError,
};
use loki_signer_core::vault::orchard_receiver_from_ua;
use loki_signer_core::verify::{check_candidate, Expectations, Refusal};
use loki_signer_core::signer::PublicPaymentParams;
use loki_signer_core::signing_session::{
    nonce_claim_id, nonce_claim_record, valid_witness_pins, witness_fingerprint, NonceWitness,
    WitnessPins,
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use loki_signer_core::signer::secure_element::{
    fresh_kek_salt, SealedShare, SoftwareSecureElement,
};
use loki_signer_core::signer::secure_element_webauthn::{prf_kek, WebAuthnSecureElement};
use loki_signer_core::signer::{
    opfs_exists, opfs_get, opfs_put, CandidateRef, Network, Session, Signer as SignerTrait,
    VaultRef,
};
use loki_signer_core::signer::wysiwys::{describe_pczt, sighash_of_pczt};
use loki_signer_core::signer::DkgInput;
use loki_signer_core::signing_session::{AttemptId, MessageKind, SessionContext};
use loki_signer_core::transport::{Outbound, SealedPeer};
use loki_signer_core::frost;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// secp256k1 is pulled into this crate transitively (bip32 <- zakura-transparent, and pczt's
// `signer` feature forces `transparent`). The Orchard FROST signer performs no secp256k1
// CRYPTO, but `pczt::roles::signer::Signer` OWNS a `secp256k1::Secp256k1<All>` context, so the
// payment review/sighash path still CONSTRUCTS and DROPS one. Its C preallocated-context
// functions are left as `env` module imports by the wasm build (no WASI C toolchain compiles
// the C here), and a browser can't resolve a bare `env` specifier. Define them in-module so
// the linker is satisfied AND the context's construct→drop lifecycle is memory-safe: `size`
// and `clone_size` return the SAME non-zero value and `create` returns its own buffer, so
// secp256k1's `alloc(size)` / `dealloc(ctx, clone_size)` is a balanced round-trip. Earlier
// these returned size 0 / a null ctx, so `Drop` ran `dealloc(null, 0)` — a wasm "memory access
// out of bounds" the moment a candidate was reviewed. The context is never used for crypto
// (no secp256k1 op runs for our shielded-only candidates); a transparent-input tx would still
// need a real context, out of scope here.
//
// Only when the C library is NOT linked (build.rs `secp_c_unlinked`): secp256k1-sys does
// compile its C for wasm32, but archives it with the archiver `cc` finds. With `llvm-ar` (Linux
// toolchains) the archive is indexed, wasm-ld links the real C, and these stubs would be
// duplicate definitions. With Apple's `ar` the archive has no index, nothing is pulled from it,
// and these stubs are what resolves the symbols.
#[cfg(all(target_arch = "wasm32", secp_c_unlinked))]
mod secp256k1_link_stub {
    use core::ffi::{c_uint, c_void};
    // Arbitrary non-zero, aligned buffer size; only alloc/dealloc balance matters since the
    // context bytes are never read by a real secp256k1 operation.
    const CTX_SIZE: usize = 256;
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_size(_flags: c_uint) -> usize {
        CTX_SIZE
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_create(
        prealloc: *mut c_void,
        _flags: c_uint,
    ) -> *mut c_void {
        prealloc
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_destroy(_ctx: *mut c_void) {}
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_clone_size(_ctx: *const c_void) -> usize {
        CTX_SIZE
    }

    // secp256k1-sys's `sanity_checks_for_wasm()` (types.rs) runs when a context is constructed
    // — which the pczt transparent Signer/Verifier role does even for our shielded-only
    // candidate — and asserts each C ABI size/align against these `extern "C"` statics. The C
    // that defines them is not compiled here (see the note above), so without definitions they
    // read as garbage and the assert aborts with a bare "unreachable". Define them with the
    // real wasm32 ABI values (int/uint/size_t/ptr = 4 bytes, uchar = 1), so the check passes;
    // the context itself is still the never-operated-on null from the stubs above.
    #[no_mangle]
    pub static WASM32_INT_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_INT_ALIGN: u8 = 4;
    #[no_mangle]
    pub static WASM32_UNSIGNED_INT_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_UNSIGNED_INT_ALIGN: u8 = 4;
    #[no_mangle]
    pub static WASM32_SIZE_T_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_SIZE_T_ALIGN: u8 = 4;
    #[no_mangle]
    pub static WASM32_UNSIGNED_CHAR_SIZE: u8 = 1;
    #[no_mangle]
    pub static WASM32_UNSIGNED_CHAR_ALIGN: u8 = 1;
    #[no_mangle]
    pub static WASM32_PTR_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_PTR_ALIGN: u8 = 4;
}

// Runs once when the worker instantiates the module (wasm-bindgen `start`), so any later
// panic in a synchronous core call prints its real message + Rust location to the Worker
// console instead of a bare "unreachable" trap. console_error_panic_hook logs via
// `console.error`, which exists in a Web Worker.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn prf32(prf_secret: &[u8]) -> Result<[u8; 32], String> {
    prf_secret
        .try_into()
        .map_err(|_| "WebAuthn PRF secret must be exactly 32 bytes".to_string())
}

// Inner impls return String so the native `wasm-bindgen-test` can assert on them; the
// exported wrappers map the error to a JS exception.
fn seal_impl(prf_secret: &[u8], epoch: u64, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let se = WebAuthnSecureElement::from_prf_secret(&prf32(prf_secret)?);
    Ok(SealedShare::seal(&se, epoch, plaintext)?.to_bytes())
}

fn open_impl(prf_secret: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    let se = WebAuthnSecureElement::from_prf_secret(&prf32(prf_secret)?);
    Ok(SealedShare::from_bytes(sealed)?.open(&se)?.to_vec())
}

/// Seal a FROST share under a passkey: KEK = HKDF(PRF secret), then the proven
/// XChaCha20-Poly1305 share seal. Returns the sealed bytes the browser persists.
/// `epoch` is the share's backup epoch.
#[wasm_bindgen(js_name = sealShareUnderPasskey)]
pub fn seal_share_under_passkey(
    prf_secret: &[u8],
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    seal_impl(prf_secret, epoch, plaintext).map_err(|e| JsError::new(&e))
}

/// Reopen a share sealed by [`seal_share_under_passkey`] with the same passkey's PRF
/// secret. Fails if the secret is wrong, the bytes are corrupt, or they were sealed under
/// a different element.
#[wasm_bindgen(js_name = openShareWithPasskey)]
pub fn open_share_with_passkey(prf_secret: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsError> {
    open_impl(prf_secret, sealed).map_err(|e| JsError::new(&e))
}

/// Browser OPFS-store seam self-test: write bytes at `path` and read them back through
/// the signer's synchronous `durable` backend (OPFS sync handles in this Worker). The
/// Worker must `opfsPreopenWrite(path)` first. Proves wasm↔OPFS before the full store.
#[wasm_bindgen(js_name = opfsSelftest)]
pub fn opfs_selftest(path: &str, bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    loki_signer_core::signer::opfs_selftest(path, bytes).map_err(|e| JsError::new(&e))
}

// ─── Phase A: the stateful profile-lifecycle signer ──────────────────────────
//
// `Signer` is a stateful wasm-bindgen object: it holds the unlocked device `Identity` in
// memory between `unlock` and `lock`, and persists ONLY its sealed form to OPFS. The
// device identity is `Identity::new(1)` — slot 1 as a placeholder; it is re-stamped to the
// real vault slot later when the signer joins a vault (DKG, Phase B). The at-rest files are
// a fixed, deterministic set under `loki/device/`, so the Worker can pre-open exactly the
// paths each op touches before the synchronous call (OPFS sync handles are acquired async):
//
//   createSigner  writes: identity.sealed, profile.json, (passphrase) kek.salt
//   hasSigner     reads:  identity.sealed
//   unlock        reads:  identity.sealed, profile.json, (passphrase) kek.salt
//   lock          no I/O
//
// `request()` (DKG/payment) is NOT here — it stays `SignerPending` in the TS layer (Phase B/C).

/// Sealed device identity: `SealedShare(identity.to_secret_bytes())` under the selected SE.
pub const IDENTITY_PATH: &str = "loki/device/identity.sealed";
/// Public profile metadata (the display name). Non-secret, plaintext JSON.
pub const PROFILE_PATH: &str = "loki/device/profile.json";
/// Argon2id salt for the passphrase KEK (passphrase custody only).
pub const SALT_PATH: &str = "loki/device/kek.salt";
const WITNESS_PINS_PATH: &str = "loki/device/witness-pins.sealed";
const LEGACY_RECOVERY_PATH: &str = "loki/device/recovery.pub";
const RECOVERY_PATH: &str = "loki/device/recovery.sealed";
const RECOVERY_RECORD: &[u8] = b"loki browser recovery recipient v1\0";

/// The device file set the Worker pre-opens, as a JSON array, so the pre-open protocol has a
/// single source of truth shared with `signer-worker.js` instead of drifting constants.
#[wasm_bindgen(js_name = devicePaths)]
pub fn device_paths() -> String {
    serde_json::json!({
        "identity": IDENTITY_PATH,
        "profile": PROFILE_PATH,
        "salt": SALT_PATH,
        "witnessPins": WITNESS_PINS_PATH,
        "recovery": RECOVERY_PATH,
        "legacyRecovery": LEGACY_RECOVERY_PATH,
    })
    .to_string()
}

/// Re-derive the custody KEK. `create` draws and persists a fresh passphrase salt (first
/// create); otherwise the salt is read back. Passkey tiers take the JS-released PRF secret.
///
/// Both tiers reduce to the identical 32-byte KEK that backs [`SoftwareSecureElement`]
/// (`WebAuthnSecureElement` is `from_kek(prf_kek(..))`, passphrase is `from_kek(derive(..))`),
/// so the stateful signer holds the KEK and seals every file — the device identity AND the
/// per-vault DKG files — under `SoftwareSecureElement::from_kek`, byte-identical to the
/// original custody element. Holding the KEK (not the raw passphrase/PRF) is what lets the
/// vault signer re-seal its share after the custody secret has been dropped.
fn custody_kek(
    method: &str,
    passphrase: Option<String>,
    prf_secret: Option<Vec<u8>>,
    create: bool,
) -> Result<Zeroizing<[u8; 32]>, String> {
    match method {
        "passphrase" => {
            let pass = Zeroizing::new(passphrase.ok_or("passphrase required for passphrase custody")?);
            let salt = if create {
                let s = fresh_kek_salt();
                opfs_put(SALT_PATH, &s, false)?; // fresh salt on every create
                s.to_vec()
            } else {
                opfs_get(SALT_PATH)?.ok_or("no KEK salt — this signer is not passphrase-backed")?
            };
            Ok(loki_signer_core::seal_kdf::derive(&pass, &salt)
                .map_err(|_| "passphrase KEK derivation failed (salt too short?)".to_string())?)
        }
        "platform" | "roaming" => {
            let prf = Zeroizing::new(prf_secret.ok_or("WebAuthn PRF secret required for passkey custody")?);
            Ok(Zeroizing::new(prf_kek(&*Zeroizing::new(prf32(&prf)?))))
        }
        other => Err(format!("unknown custody method: {other}")),
    }
}

fn profile_json(identity: &Identity, name: &str) -> String {
    serde_json::json!({
        "id": hex::encode(identity.public().signing),
        "name": name,
    })
    .to_string()
}

/// Stateful in-browser signer. Holds the unlocked device identity (and the custody KEK that
/// seals every file) only while unlocked, plus the active vault's DKG signer once joined.
#[wasm_bindgen]
pub struct Signer {
    identity: Option<Identity>,
    kek: Option<Zeroizing<[u8; 32]>>,
    vault: Option<VaultState>,
    /// The sighash the member confirmed on the signer page for the next `signApprove`. The
    /// core's approval prompt takes it (one use) and approves only that exact sighash.
    approved: Arc<Mutex<Option<[u8; 32]>>>,
    /// Recovery public keys minted by `recoveryBegin`, written only once the member has
    /// re-typed some of the words (`recoveryConfirm`).
    pending_recovery: Option<Vec<u8>>,
    /// The two external nonce witnesses (pins) this signer claims at before every signature
    /// share. None: signing is refused, like a native member without --nonce-witnesses.
    witness_pins: Option<WitnessPins>,
    /// Claims both witnesses confirmed for this signature (cid, record), consumed by the core.
    claimed: Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>,
    /// The open vault's chain scan (storage path, vault id, network, scan state).
    scan: Option<(String, [u8; 32], VaultNetwork, ChainScan)>,
}

impl Default for Signer {
    fn default() -> Self {
        Self {
            identity: None,
            kek: None,
            vault: None,
            approved: Arc::new(Mutex::new(None)),
            pending_recovery: None,
            witness_pins: None,
            claimed: Arc::new(Mutex::new(Vec::new())),
            scan: None,
        }
    }
}

#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Signer {
        Signer::default()
    }

    /// True once a device identity is sealed in this browser → Unlock, not Create.
    /// The Worker must `opfsPreopenRead(IDENTITY_PATH)` first.
    #[wasm_bindgen(js_name = hasSigner)]
    pub fn has_signer(&self) -> bool {
        opfs_exists(IDENTITY_PATH)
    }

    /// Generate `Identity::new(1)`, seal it under the chosen custody element, and persist the
    /// sealed identity + profile (+ salt for passphrase) to OPFS. Returns the profile JSON
    /// `{id,name}`. The Worker must pre-open identity.sealed, profile.json (+ kek.salt) for
    /// write first. Refuses if a signer already exists here.
    #[wasm_bindgen(js_name = createSigner)]
    pub fn create_signer(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, JsError> {
        self.create_impl(method, name, passphrase, prf_secret)
            .map_err(|e| JsError::new(&e))
    }

    /// Re-derive the custody element, open the sealed identity, and hold it in the session.
    /// Returns the profile JSON `{id,name}`. The Worker must pre-open the same paths for read.
    #[wasm_bindgen(js_name = unlock)]
    pub fn unlock(
        &mut self,
        method: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, JsError> {
        self.unlock_impl(method, passphrase, prf_secret)
            .map_err(|e| JsError::new(&e))
    }

    /// Drop the in-memory identity, custody KEK and any active vault signer; the session
    /// ends. Each is wiped as it drops: the KEK is `Zeroizing`, the identity's Ed25519 and
    /// X25519 keys zeroize on drop, and the vault signer's element holds a `Zeroizing` KEK.
    /// The sealed files stay on disk.
    #[wasm_bindgen(js_name = lock)]
    pub fn lock(&mut self) {
        self.identity = None;
        self.kek = None;
        self.vault = None;
        self.pending_recovery = None;
        self.witness_pins = None;
        self.claimed.lock().unwrap().clear();
    }

    /// Whether an identity is currently held unlocked in memory.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.identity.is_some()
    }

    // ─── Recovery identity + independent vault backup ─────────────────────────
    //
    // Mirrors the native flow (core/src/host/recovery.rs): 24 words shown ONCE on the signer
    // page, only their public keys persisted. Every vault backup is also HPKE-sealed to the
    // recovery key (`recovery.backup`), which only the words open, so it is independent of
    // this browser. Joining a vault requires a recovery identity first.

    /// Whether the unlocked signer has an authenticated recovery recipient.
    #[wasm_bindgen(js_name = hasRecovery)]
    pub fn has_recovery(&self) -> bool {
        self.recovery_recipient().is_ok_and(|keys| keys.is_some())
    }

    #[wasm_bindgen(js_name = needsRecoveryMigration)]
    pub fn needs_recovery_migration(&self) -> bool {
        !self.has_recovery() && opfs_exists(LEGACY_RECOVERY_PATH)
    }

    /// Re-derive both keys from member-entered words, never authenticate the old bytes as-is.
    #[wasm_bindgen(js_name = recoveryMigrate)]
    pub fn recovery_migrate(&self, words: String) -> Result<(), JsError> {
        let words = Zeroizing::new(words);
        let migrate = || {
            if !self.needs_recovery_migration() {
                return Err("there is no legacy recovery record to migrate".into());
            }
            let keys = recovery_public_keys(&RecoveryKey::from_words(&words)?);
            if opfs_get(LEGACY_RECOVERY_PATH)?.as_deref() != Some(keys.as_slice()) {
                return Err("these words do not match the legacy recovery record; keep your existing backups".into());
            }
            self.write_recovery_recipient(&keys)
        };
        migrate().map_err(|e: String| JsError::new(&e))
    }

    /// Mint the 24 recovery words. Returns them for the signer page to show once; nothing is
    /// written until [`recovery_confirm`](Self::recovery_confirm). Refuses if one exists.
    #[wasm_bindgen(js_name = recoveryBegin)]
    pub fn recovery_begin(&mut self) -> Result<String, JsError> {
        if self.identity.is_none() {
            return Err(JsError::new("unlock the signer first"));
        }
        if opfs_exists(RECOVERY_PATH) || opfs_exists(LEGACY_RECOVERY_PATH) {
            return Err(JsError::new("this signer already has recovery words; they cannot be shown again"));
        }
        let (words, key) = RecoveryKey::generate().map_err(|e| JsError::new(&e))?;
        self.pending_recovery = Some(recovery_public_keys(&key));
        Ok(words.to_string())
    }

    /// Persist the public keys of the words `recoveryBegin` showed, after the member re-typed
    /// some of them. Pre-open `recovery` for write.
    #[wasm_bindgen(js_name = recoveryConfirm)]
    pub fn recovery_confirm(&mut self) -> Result<(), JsError> {
        let pubkeys = self
            .pending_recovery
            .as_ref()
            .ok_or_else(|| JsError::new("no recovery words are waiting to be confirmed"))?;
        self.write_recovery_recipient(pubkeys).map_err(|e| JsError::new(&e))?;
        self.pending_recovery = None;
        Ok(())
    }

    /// This vault's recovery backup (opaque HPKE ciphertext, safe to keep anywhere), for the
    /// member to export. Pre-open `vaultPaths(vaultHex)` first.
    #[wasm_bindgen(js_name = recoveryBackup)]
    pub fn recovery_backup(&self, vault_hex: &str) -> Result<Vec<u8>, JsError> {
        opfs_get(&format!("{}/recovery.backup", vault_dir(vault_hex)))
            .map_err(|e| JsError::new(&e))?
            .ok_or_else(|| JsError::new("this browser holds no recovery backup for that vault"))
    }

    /// Restore a vault member into a FRESH browser from its 24 words and exported recovery
    /// backup: the backup's member identity becomes this browser's signer, sealed under the
    /// chosen custody (as `createSigner`), and the vault reopens ready to sign. Returns
    /// `{profile, vault}`: the profile and the `vaultOpen` JSON. Pre-open the device paths
    /// and `vaultPaths(vaultHex)` for write.
    #[wasm_bindgen(js_name = restoreSigner)]
    #[allow(clippy::too_many_arguments)]
    pub fn restore_signer(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
        vault_hex: &str,
        words: String,
        blob: &[u8],
        fingerprint: String,
    ) -> Result<String, JsError> {
        let words = Zeroizing::new(words);
        self.restore_impl(method, name, passphrase, prf_secret, vault_hex, &words, blob, &fingerprint)
            .map_err(|e| JsError::new(&e))
    }

    // ─── Phase B: join-a-vault + DKG ─────────────────────────────────────────
    //
    // The audited DKG core (`Signer::dkg_begin/dkg_step/backup/release_address`) is
    // SYNCHRONOUS and message-in/out: it never owns a transport. These wasm methods drive a
    // real OPFS-backed `LocalSigner` through those four primitives; the async pump — frostd
    // fetch and the coordinator's roster HTTP — lives in the Worker (`signer-worker.js`),
    // which loops `vaultStep([])` ↔ frostd until `vaultReady()`. The device identity is
    // re-stamped to the vault slot on join (slot bytes overwritten, keys unchanged), exactly
    // like the native hosted `ceremony::identity` fix.

    /// This member's frostd relay address (X25519 public key, hex): the `encryption` key the
    /// coordinator enrolled for the slot. The browser transport is built from this alone.
    ///
    /// The login key IS the roster encryption key, exactly as on native members
    /// (core/src/host/payment.rs `relay`): the relay addresses a member by its roster key, so
    /// separating them is a protocol change across core + host, not a browser one. Its secret
    /// stays inside wasm — only [`frostd_sign_challenge`](Self::frostd_sign_challenge)'s
    /// signature leaves.
    #[wasm_bindgen(js_name = frostdPubkey)]
    pub fn frostd_pubkey(&self) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("unlock the signer first"))?;
        Ok(hex::encode(identity.public().encryption))
    }

    /// XEdDSA-sign a frostd login challenge (the UUID string `FrostdClient.challenge()`
    /// returned) with this member's relay key; returns the 64-byte signature (hex) for
    /// `FrostdClient.loginSigned`. Signs only a parsed UUID, so it cannot be used to sign
    /// arbitrary bytes.
    #[wasm_bindgen(js_name = frostdSignChallenge)]
    pub fn frostd_sign_challenge(&self, challenge: &str) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("unlock the signer first"))?;
        sign_challenge(identity, challenge).map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(js_name = relayRegistrationProof)]
    pub fn relay_registration_proof(&self, origin: &str, challenge: &str, key: &str) -> Result<String, JsError> {
        let identity = self.identity.as_ref().ok_or_else(|| JsError::new("unlock the signer first"))?;
        let mut nonce = [0; 32];
        let mut public = [0; 32];
        hex::decode_to_slice(challenge, &mut nonce).map_err(|_| JsError::new("invalid registration challenge"))?;
        hex::decode_to_slice(key, &mut public).map_err(|_| JsError::new("invalid coordinator relay challenge key"))?;
        identity.relay_registration_proof(origin, &nonce, &public).map(hex::encode).map_err(|e| JsError::new(&e))
    }

    /// This member's public enrollment identity for the coordinator's public roster:
    /// `signing_pubkey` (the Ed25519 member identity) and `relay_pubkey` (= the X25519 frostd
    /// login pubkey, this member's relay address). Hex JSON. The browser POSTs these, plus a
    /// browser device key, to the coordinator's `/api/members` — a frostd-only member with no
    /// `advertise_url`. Unlock the signer first.
    #[wasm_bindgen(js_name = enrollMaterial)]
    pub fn enroll_material(&self) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("unlock the signer first"))?;
        Ok(serde_json::json!({
            "signing_pubkey": hex::encode(identity.public().signing),
            "relay_pubkey": hex::encode(identity.public().encryption),
        })
        .to_string())
    }

    /// Authorize a browser device-login key (P-256 SEC1 uncompressed bytes, hex) with this
    /// member identity, using the same Ed25519 enrollment proof as the native self-registration
    /// (`Identity::authorize_device`). Returns the authorization signature (hex) the coordinator
    /// verifies before the device key's own signature over the registration transcript.
    #[wasm_bindgen(js_name = authorizeDevice)]
    pub fn authorize_device(&self, device_pub_hex: &str) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("unlock the signer first"))?;
        let device_pub = hex::decode(device_pub_hex).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(hex::encode(identity.authorize_device(&device_pub)))
    }

    #[wasm_bindgen(js_name = authorizeDeviceReplacement)]
    pub fn authorize_device_replacement(&self, origin: &str, device_pub_hex: &str, challenge_hex: &str, generation: u64) -> Result<String, JsError> {
        let identity = self.identity.as_ref().ok_or_else(|| JsError::new("unlock the signer first"))?;
        let mut device = [0; 65];
        hex::decode_to_slice(device_pub_hex, &mut device).map_err(|e| JsError::new(&e.to_string()))?;
        let mut challenge = [0; 32];
        hex::decode_to_slice(challenge_hex, &mut challenge).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(hex::encode(identity.authorize_device_replacement(origin, &device, &challenge, generation)))
    }

    /// Create-or-reopen this member's vault signer, confirm the coordinator's roster, and
    /// begin DKG. Returns the `VaultRef` JSON. The Worker must pre-open `vaultPaths(vaultHex)`
    /// for write first. `roster` is the coordinator's setup document (`setup_version: 2`).
    /// `confirmed_code` is the roster code the member confirmed on the signer page: the core's
    /// roster prompt answers Match only if the code it derives equals it.
    #[wasm_bindgen(js_name = vaultJoin)]
    pub fn vault_join(
        &mut self,
        vault_hex: &str,
        slot: u16,
        label: &str,
        network: &str,
        roster: &[u8],
        confirmed_code: &str,
    ) -> Result<String, JsError> {
        self.vault_join_impl(vault_hex, slot, label, network, roster, confirmed_code)
            .map_err(|e| JsError::new(&e))
    }

    /// The 24-digit roster code of a setup document, for the member to compare with every
    /// other member before `vaultJoin` (the same code the core's roster prompt is shown).
    #[wasm_bindgen(js_name = rosterCode)]
    pub fn roster_code(&self, roster: &[u8]) -> Result<String, JsError> {
        let roster = Roster::from_bytes(roster).map_err(|e| JsError::new(&e))?;
        Ok(local::roster_code(&roster.fingerprint()))
    }

    /// A fresh proof the member is present for one approval: the custody secret (a new passkey
    /// PRF output, or the passphrase typed again) must re-derive the KEK this session holds.
    #[wasm_bindgen(js_name = reauth)]
    pub fn reauth(
        &self,
        method: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<(), JsError> {
        self.reauth_check(method, passphrase, prf_secret).map_err(|e| JsError::new(&e))
    }

    /// Check a candidate PCZT (hex) against the payment terms the member approved (JSON: the
    /// proposer's announced intent plus `tx_expiry`, the expiry fixed at `start`), the same
    /// review a native co-signer runs (core/src/host/payment.rs `review_candidate`): network
    /// branch for the anchor height, the exact expiry, and — through `verify::check_candidate`
    /// with the vault viewing key — the one input note, recipient, amount, memo, change and
    /// fee. Refuses on any difference. Returns the review the member confirms:
    /// `paymentReview`'s fields plus `recipient_ua`, `memo_text` and `expiry_height`.
    #[wasm_bindgen(js_name = paymentCheck)]
    pub fn payment_check(&self, candidate_hex: &str, terms_json: &str) -> Result<String, JsError> {
        self.payment_check_impl(candidate_hex, terms_json).map_err(|e| JsError::new(&e))
    }

    /// Reopen this browser's signer for an existing vault, with no network input. Returns
    /// `{vault_id, slot, threshold, network, ready, members: [{id, signing, encryption}]}`
    /// from the roster this member confirmed at setup. The Worker must pre-open
    /// `vaultPaths(vaultHex)` first.
    #[wasm_bindgen(js_name = vaultOpen)]
    pub fn vault_open(&mut self, vault_hex: &str) -> Result<String, JsError> {
        self.vault_open_impl(vault_hex).map_err(|e| JsError::new(&e))
    }

    /// One DKG pass: feed the relayed peer wires (each hex `DkgWire` bytes the coordinator
    /// forwarded) into `dkg_step` and return this member's outgoing wires (hex), which the
    /// Worker sends to the coordinator. Call with `[]` on every poll tick to advance phases
    /// and re-emit saved outgoing bytes idempotently.
    #[wasm_bindgen(js_name = vaultStep)]
    pub fn vault_step(&mut self, in_wires: Vec<String>) -> Result<Vec<String>, JsError> {
        let vs = self
            .vault
            .as_mut()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        let inputs: Vec<DkgInput> = in_wires
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .filter_map(|b| DkgInput::from_relay(b).ok())
            .collect();
        let wires = vs
            .signer
            .dkg_step(&vs.session, &vs.vref, &inputs)
            .map_err(|e| JsError::new(&format!("dkg_step: {e}")))?;
        Ok(wires.iter().map(|w| hex::encode(w.as_bytes())).collect())
    }

    /// Run the on-device backup once every certificate has matched, and return this member's
    /// signed backup receipt wires (hex) for the coordinator. `[]` means the vault is not yet
    /// ready for backup — the Worker retries on the next tick.
    #[wasm_bindgen(js_name = vaultBackup)]
    pub fn vault_backup(&mut self) -> Result<Vec<String>, JsError> {
        let vs = self
            .vault
            .as_mut()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        match vs.signer.backup(&vs.session) {
            Ok(wires) => Ok(wires.iter().map(|w| hex::encode(w.as_bytes())).collect()),
            Err(SignerError::NotReady) => Ok(Vec::new()),
            Err(e) => Err(JsError::new(&format!("backup: {e}"))),
        }
    }

    /// The next block height the open vault's chain scan needs: the vault's birth height on a
    /// fresh scan, else one past the last block scanned. Starts the scan for this vault.
    #[wasm_bindgen(js_name = scanNext)]
    pub fn scan_next(&mut self) -> Result<u32, JsError> {
        self.scan_next_impl().map_err(|e| JsError::new(&e))
    }

    /// Resume only a scan built against this configured provider, returning its saved height.
    #[wasm_bindgen(js_name = scanStart)]
    pub fn scan_start(&mut self, source: &str) -> Result<Option<u32>, JsError> {
        self.scan_next()?;
        let birth = self.vault.as_ref().and_then(|vs| vs.signer.confirmed_roster())
            .ok_or_else(|| JsError::new("this vault has no confirmed roster"))?
            .birth_height.unwrap_or(1);
        let (_, _, _, scan) = self.scan.as_mut().ok_or_else(|| JsError::new("call scanNext first"))?;
        scan.use_source(source, birth);
        Ok(scan.height())
    }

    #[wasm_bindgen(js_name = scanMatchesCheckpoint)]
    pub fn scan_matches_checkpoint(&self, block: &[u8]) -> Result<bool, JsError> {
        let (_, _, _, scan) = self.scan.as_ref().ok_or_else(|| JsError::new("call scanNext first"))?;
        scan.matches_checkpoint(block).map_err(|e| JsError::new(&e))
    }

    /// Scan one complete range of compact block protobufs from lightwalletd atomically.
    #[wasm_bindgen(js_name = scanBlocks)]
    pub fn scan_blocks(&mut self, start: u32, end: u32, blocks: Vec<js_sys::Uint8Array>) -> Result<(), JsError> {
        let (_, _, _, scan) = self.scan.as_mut().ok_or_else(|| JsError::new("call scanNext first"))?;
        if start != scan.next_height() || end < start || blocks.len().checked_sub(1) != Some((end - start) as usize) {
            return Err(JsError::new("compact block range does not match this scan"));
        }
        scan.scan_batch(blocks.into_iter().map(|block| block.to_vec())).map_err(|e| JsError::new(&e))
    }

    /// Seal and save the scan state bound to its vault and network, so the next scan resumes here.
    /// Pre-open `vaultPaths(vaultHex)` for write first.
    #[wasm_bindgen(js_name = scanSave)]
    pub fn scan_save(&self) -> Result<(), JsError> {
        self.scan_save_impl().map_err(|e| JsError::new(&e))
    }

    /// Restart from vault birth without deleting the persisted snapshot before a replacement.
    #[wasm_bindgen(js_name = scanReset)]
    pub fn scan_reset(&mut self) -> Result<(), JsError> {
        let (_, _, _, scan) = self.scan.as_mut().ok_or_else(|| JsError::new("call scanNext first"))?;
        scan.reset();
        Ok(())
    }

    /// The transaction that spent the vault note with this nullifier (hex), as JSON
    /// `{txid, height}`, or `null` while the scan has not seen it spent.
    #[wasm_bindgen(js_name = scanSpentBy)]
    pub fn scan_spent_by(&self, nullifier_hex: &str) -> Result<String, JsError> {
        let (_, _, _, scan) = self.scan.as_ref().ok_or_else(|| JsError::new("call scanNext first"))?;
        let nf: [u8; 32] = hex::decode(nullifier_hex).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| JsError::new("invalid nullifier"))?;
        Ok(match scan.spent_by(&nf) {
            Some((txid, height)) => serde_json::json!({ "txid": txid, "height": height }),
            None => serde_json::Value::Null,
        }
        .to_string())
    }

    /// `{height, balance_zat, history}` from the blocks scanned so far.
    #[wasm_bindgen(js_name = scanResult)]
    pub fn scan_result(&self) -> Result<String, JsError> {
        let (_, _, _, scan) = self.scan.as_ref().ok_or_else(|| JsError::new("call scanNext first"))?;
        Ok(serde_json::json!({
            "height": scan.height(),
            "balance_zat": scan.balance_zat().to_string(),
            "history": scan.history(),
        })
        .to_string())
    }

    /// True once every member's backup receipt has arrived and the vault is active.
    #[wasm_bindgen(js_name = vaultReady)]
    pub fn vault_ready(&self) -> Result<bool, JsError> {
        let vs = self
            .vault
            .as_ref()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        let vaults = vs
            .signer
            .list_vaults(&vs.session)
            .map_err(|e| JsError::new(&format!("list_vaults: {e}")))?;
        Ok(vaults.first().map(|v| v.ready).unwrap_or(false))
    }

    /// The vault's receive address, once the vault is ready. Proves DKG completed: every
    /// member derives the identical address, which must match the coordinator's.
    #[wasm_bindgen(js_name = vaultAddress)]
    pub fn vault_address(&mut self) -> Result<String, JsError> {
        let vs = self
            .vault
            .as_mut()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        Ok(vs
            .signer
            .release_address(&vs.session)
            .map_err(|e| JsError::new(&format!("release_address: {e}")))?
            .address)
    }

    // ─── Phase C: review + approve a payment (NON-proposer signer) ───────────────
    //
    // The audited payment seam (`Signer::sign_commit/sign_approve`, `wysiwys::describe_pczt/
    // sighash_of_pczt`) is SYNCHRONOUS and message-in/out: it never owns a transport. These
    // wasm methods drive the active vault's `LocalSigner` through them; the async frostd pump
    // (`drivePayment` in signer-worker.js) carries the signing-round messages. The browser
    // member REVIEWS + APPROVES only — the proposer/builder assembles and seals the candidate
    // (out of scope here). WYSIWYS is enforced inside `signApprove`: it re-renders the
    // candidate, recomputes the sighash, and REFUSES unless the signing package commits to
    // that exact sighash, BEFORE the nonce/share is touched.

    /// WYSIWYS render of a candidate PCZT (hex): the facts this member would sign, derived
    /// from the bytes with the vault viewing key, plus the independently recomputed sighash.
    /// Releases NO secret and touches no nonce. Returns JSON
    /// `{recipient, amount_zat, fee_zat, change_zat, memo, network_branch_id, fee_verified,
    /// sighash}` (recipient/memo/sighash hex; amounts decimal strings). Reopen the vault
    /// (`vaultJoin`) first. Errors on an unparseable/invalid candidate.
    #[wasm_bindgen(js_name = paymentReview)]
    pub fn payment_review(&self, candidate_hex: &str) -> Result<String, JsError> {
        self.payment_review_impl(candidate_hex).map_err(|e| JsError::new(&e))
    }

    /// Round 1: the PUBLIC signing commitment for `attempt_hex` (hex). The secret nonce is
    /// persisted crash-safe to OPFS and never returned. The Worker must pre-open this attempt's
    /// `nonces/<id>.nonce` + `.burn` paths first. Reopen the vault first.
    #[wasm_bindgen(js_name = signCommit)]
    pub fn sign_commit(&mut self, attempt_hex: &str) -> Result<String, JsError> {
        self.sign_commit_impl(attempt_hex).map_err(|e| JsError::new(&e))
    }

    /// Open the expected sender's candidate, package, or seed for this hosted attempt.
    #[wasm_bindgen(js_name = openSigning)]
    pub fn open_signing(
        &self,
        signing_hex: &str,
        encryption_hex: &str,
        sender_id: u16,
        signers_csv: &str,
        attempt_hex: &str,
        wire_hex: &str,
    ) -> Result<String, JsError> {
        let open = || -> Result<String, String> {
            let (vs, context) = self.hosted_signing_context(attempt_hex, signers_csv)?;
            let sender = PublicIdentity { id: sender_id, signing: hex32(signing_hex)?, encryption: hex32(encryption_hex)? };
            let wire = hex::decode(wire_hex).map_err(|e| e.to_string())?;
            let opened = vs.signer.open_hosted_signing(&sender, &context, &wire).map_err(|e| e.to_string())?;
            let kind = match (sender_id, opened.kind()) {
                (0, MessageKind::HostedPackage) => "package",
                (0, MessageKind::HostedSeed) => "seed",
                (1.., MessageKind::Candidate) => "candidate",
                _ => return Err("unexpected hosted signing message kind".into()),
            };
            if !opened.kind().valid_hosted_body(&context, opened.body()) {
                return Err("invalid hosted signing message".into());
            }
            Ok(serde_json::json!({"kind": kind, "body": hex::encode(opened.body())}).to_string())
        };
        open().map_err(|e| JsError::new(&e))
    }

    /// Seal a commitment or share to the coordinator announced by the proposer.
    #[wasm_bindgen(js_name = sealSigning)]
    pub fn seal_signing(
        &self,
        signing_hex: &str,
        encryption_hex: &str,
        signers_csv: &str,
        attempt_hex: &str,
        body_hex: &str,
        share: bool,
    ) -> Result<String, JsError> {
        let seal = || -> Result<String, String> {
            let (vs, context) = self.hosted_signing_context(attempt_hex, signers_csv)?;
            let coordinator = PublicIdentity { id: 0, signing: hex32(signing_hex)?, encryption: hex32(encryption_hex)? };
            let body = hex::decode(body_hex).map_err(|e| e.to_string())?;
            let kind = if share { MessageKind::HostedShare } else { MessageKind::HostedCommitment };
            vs.signer.seal_hosted_signing(&coordinator, &context, kind, &body)
                .map(hex::encode).map_err(|e| e.to_string())
        };
        seal().map_err(|e| JsError::new(&e))
    }

    /// Open a message a vault member sealed to this one on a payment's frostd control session
    /// (`session_id`, a UUID). `from_hex` is the frostd sender; the sender's identity comes from
    /// the roster this member confirmed at setup, so a non-member's message is refused.
    /// Returns `{from, body}`: the sender's member id and the message body (JSON text).
    #[wasm_bindgen(js_name = openControl)]
    pub fn open_control(&self, session_id: &str, from_hex: &str, wire_hex: &str) -> Result<String, JsError> {
        self.open_control_impl(session_id, from_hex, wire_hex)
            .map_err(|e| JsError::new(&e))
    }

    /// Seal a control message (`body_json`) from this member to member `to` on the payment
    /// control session `session_id`, under the roster confirmed at setup. Returns the wire (hex)
    /// to send to that member's relay key.
    #[wasm_bindgen(js_name = sealControl)]
    pub fn seal_control(&self, session_id: &str, to: u16, body_json: &str) -> Result<String, JsError> {
        self.seal_control_impl(session_id, to, body_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Seal a join request (`body_json`) from this member, as `slot`, to the vault creator
    /// named in the invite (`creator_json`, `{id, signing, encryption}` hex) on the join
    /// session `session_id` the member opened. Returns the wire (hex) to send to the creator.
    #[wasm_bindgen(js_name = joinSeal)]
    pub fn join_seal(&self, vault_hex: &str, session_id: &str, slot: u16, creator_json: &str, body_json: &str) -> Result<String, JsError> {
        self.join_seal_impl(vault_hex, session_id, slot, creator_json, body_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Open the creator's reply to a join request on `session_id`; returns its body (JSON text).
    #[wasm_bindgen(js_name = joinOpen)]
    pub fn join_open(&self, vault_hex: &str, session_id: &str, slot: u16, creator_json: &str, wire_hex: &str) -> Result<String, JsError> {
        self.join_open_impl(vault_hex, session_id, slot, creator_json, wire_hex)
            .map_err(|e| JsError::new(&e))
    }

    /// Enable only a previously approved pair, or the pair whose independently obtained
    /// fingerprint the member just confirmed. The worker reauthenticates that consent.
    #[wasm_bindgen(js_name = setNonceWitnesses)]
    pub fn set_nonce_witnesses(&mut self, pins_json: &str, confirmation: Option<String>) -> Result<bool, JsError> {
        self.set_nonce_witnesses_impl(pins_json, confirmation.as_deref()).map_err(|e| JsError::new(&e))
    }

    /// The claim this signature needs at both witnesses: `{cid, record}` (hex), from the core
    /// derivations (`nonce_claim_id` over this member's own commitment in the package, and
    /// `nonce_claim_record` over the confirmed sighash and the randomizer seed). The Worker
    /// claims it at both witnesses, then reports `nonceClaimed`.
    #[wasm_bindgen(js_name = nonceClaim)]
    pub fn nonce_claim(&self, attempt_hex: &str, package_hex: &str, seed_hex: &str, sighash_hex: &str) -> Result<String, JsError> {
        self.nonce_claim_impl(attempt_hex, package_hex, seed_hex, sighash_hex).map_err(|e| JsError::new(&e))
    }

    /// Authorize this exact request inside the signer; the identity never leaves WASM.
    #[wasm_bindgen(js_name = nonceClaimProof)]
    pub fn nonce_claim_proof(&self, key: &str, run: &str, mailbox: &str, cid: &str, record: &str, challenge: &str) -> Result<String, JsError> {
        let proof = (|| -> Result<_, String> {
            let vs = self.vault.as_ref().ok_or("no active vault — call vaultOpen first")?;
            let pins = (hex32(key)?, hex32(run)?, hex32(mailbox)?);
            let record = hex::decode(record).map_err(|e| e.to_string())?;
            vs.signer.nonce_claim_proof(pins, hex32(cid)?, hex32(challenge)?, &record)
                .map_err(|e| e.to_string())
        })().map_err(|e| JsError::new(&e))?;
        Ok(hex::encode(proof.to_bytes()))
    }

    /// Both witnesses issued a FRESH, verified claim receipt for `{cid, record}`. The core's
    /// witness check inside `signApprove` accepts exactly this claim, once.
    #[wasm_bindgen(js_name = nonceClaimed)]
    pub fn nonce_claimed(&self, cid_hex: &str, record_hex: &str) -> Result<(), JsError> {
        let cid = hex32(cid_hex).map_err(|e| JsError::new(&e))?;
        let record = hex::decode(record_hex).map_err(|e| JsError::new(&e.to_string()))?;
        self.claimed.lock().map_err(|_| JsError::new("claim state poisoned"))?.push((cid, record));
        Ok(())
    }

    /// Round 2: the PUBLIC signature share for `attempt_hex` (hex). INDEPENDENTLY re-renders
    /// the candidate, recomputes its sighash, and REFUSES unless `package_hex` commits to that
    /// exact sighash — before the nonce/share is touched (WYSIWYS). `candidate_hex` is the
    /// opened candidate, `seed_hex` the 32-byte rerandomizer seed. `confirmed_sighash_hex` is
    /// the sighash the member confirmed on the signer page: the core's approval prompt approves
    /// only when its own recomputed sighash equals it. `terms_json` is the payment the member
    /// approved (the same terms `paymentCheck` took): the core refuses a candidate whose
    /// recipient, amount, memo, anchor or expiry differ from it. Reopen the vault first.
    #[wasm_bindgen(js_name = signApprove)]
    pub fn sign_approve(
        &mut self,
        attempt_hex: &str,
        candidate_hex: &str,
        package_hex: &str,
        seed_hex: &str,
        confirmed_sighash_hex: &str,
        terms_json: &str,
    ) -> Result<String, JsError> {
        self.sign_approve_impl(attempt_hex, candidate_hex, package_hex, seed_hex, confirmed_sighash_hex, terms_json)
            .map_err(|e| JsError::new(&e))
    }
}

/// The active vault's DKG signer, held while a join/DKG is in flight (and after, until lock).
struct VaultState {
    signer: LocalSigner<SoftwareSecureElement>,
    session: Session,
    vref: VaultRef,
    /// This member's slot (FROST identifier) in the vault.
    slot: u16,
    dir: String,
}

/// The vault signer's data directory in OPFS. The `LocalSigner` store owns
/// `signer.meta`/`identity`/`roster`/`setup`/`share.sealed` + `nonces/` here; `OpfsBackup`
/// owns `backup.sealed` beside them.
fn vault_dir(vault_hex: &str) -> String {
    format!("loki/vaults/{vault_hex}/signer")
}

enum StoredVault {
    Absent,
    Restored(BackupArtifact),
    Pending,
    Confirmed,
}

fn stored_vault(dir: &str) -> Result<StoredVault, String> {
    let meta = opfs_get(&format!("{dir}/signer.meta"))?.is_some();
    let share = opfs_get(&format!("{dir}/share.sealed"))?.is_some();
    if let Some(bytes) = opfs_get(&format!("{dir}/backup.sealed"))? {
        // DKG does not save a backup until it has a share. A same-ID join interrupted
        // before then may have left metadata beside the original restored backup.
        if !meta || !share {
            return Ok(StoredVault::Restored(BackupArtifact(bytes)));
        }
    }
    let roster = opfs_get(&format!("{dir}/roster.sealed"))?.is_some();
    if meta {
        return Ok(if roster { StoredVault::Confirmed } else { StoredVault::Pending });
    }
    for file in ["identity.sealed", "setup.sealed", "recovery.backup"] {
        if opfs_get(&format!("{dir}/{file}"))?.is_some() {
            return Err("incomplete vault data exists; preserve it before retrying setup".into());
        }
    }
    if roster || share {
        return Err("incomplete vault data exists; preserve it before retrying setup".into());
    }
    Ok(StoredVault::Absent)
}

/// The deterministic file set the Worker pre-opens (for write) before a DKG call, mirroring
/// `devicePaths()`. Write handles are read-capable too, so one set covers reads and writes.
#[wasm_bindgen(js_name = vaultPaths)]
pub fn vault_paths(vault_hex: &str) -> String {
    let dir = vault_dir(vault_hex);
    serde_json::json!([
        format!("{dir}/signer.meta"),
        format!("{dir}/identity.sealed"),
        format!("{dir}/roster.sealed"),
        format!("{dir}/setup.sealed"),
        format!("{dir}/share.sealed"),
        format!("{dir}/backup.sealed"),
        format!("{dir}/recovery.backup"),
        format!("{dir}/scan.sealed"),
    ])
    .to_string()
}

fn scan_binding(vault_id: &[u8; 32], network: VaultNetwork) -> String {
    format!("Loki_browser_scan_v1:{}:{}", network.label(), hex::encode(vault_id))
}

/// OPFS-backed [`BackupDevice`]: the in-ceremony backup `LocalSigner::backup` saves and
/// re-loads to prove it persisted. `backup.sealed` is sealed under a KEK-derived passphrase,
/// so it lives and dies with this browser; `save` therefore also seals the same material to
/// the member's recovery words (`recovery.backup`) and fails without them, so the core never
/// signs a backup receipt for a member with no independent backup.
struct OpfsBackup {
    path: String,
    recovery_path: String,
    pass: Zeroizing<String>,
    vault_id: [u8; 32],
    /// The recovery X25519 public key; `None` when this signer has no recovery identity.
    recovery: Option<[u8; 32]>,
}

impl BackupDevice for OpfsBackup {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(self.pass.clone())
    }
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        let recovery = self
            .recovery
            .ok_or("set up recovery words first: this vault would have no backup outside this browser")?;
        let sealed = seal_to_recovery(artifact, &self.pass, &self.vault_id, &recovery)?;
        if !opfs_exists(&self.path) {
            opfs_put(&self.path, &artifact.0, true)?;
        }
        // Replace, then read back: the stored recovery backup must be exactly what was sealed.
        // Opening it needs the words, which this browser never keeps.
        opfs_put(&self.recovery_path, &sealed.0, false)?;
        if opfs_get(&self.recovery_path)?.as_deref() != Some(&sealed.0[..]) {
            return Err("the recovery backup did not persist".into());
        }
        Ok(())
    }
    fn load(&mut self) -> Result<BackupArtifact, String> {
        Ok(BackupArtifact(
            opfs_get(&self.path)?.ok_or("no stored backup")?,
        ))
    }
}

/// The browser signer's device prompts for the vault in `dir`. The member answered on the
/// signer page before the synchronous core call (a sync callback cannot wait for a click), so
/// each prompt carries that answer and checks it against what the core actually shows:
/// `roster_code` is the code the member confirmed (None: no roster may be confirmed), and
/// `approved` holds the one sighash the member confirmed for the next signature. `recovery`
/// is the recovery public key the vault backup is also sealed to (`None`: backup refuses).
fn browser_prompts(
    dir: &str,
    kek: &[u8; 32],
    vault_id: [u8; 32],
    recovery: Option<[u8; 32]>,
    roster_code: Option<String>,
    approved: Arc<Mutex<Option<[u8; 32]>>>,
) -> DevicePrompts {
    DevicePrompts {
        connect: Box::new(|_origin, net| browser_network(net).is_ok()),
        roster: Box::new(move |code| match &roster_code {
            Some(confirmed) if confirmed == code => RosterDecision::Match,
            Some(_) => RosterDecision::NoMatch,
            None => RosterDecision::Cancelled,
        }),
        roster_deadline: Duration::from_secs(60),
        backup: Box::new(OpfsBackup {
            path: format!("{dir}/backup.sealed"),
            recovery_path: format!("{dir}/recovery.backup"),
            pass: Zeroizing::new(hex::encode(kek)),
            vault_id,
            recovery,
        }),
        approval: Box::new(move |request| {
            approved.lock().map(|mut slot| slot.take() == Some(request.sighash)).unwrap_or(false)
        }),
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "regtest" => browser_network(Network::Regtest),
        "testnet" => browser_network(Network::Testnet),
        other => Err(format!("browser signers are testnet-only; refused network: {other}")),
    }
}

/// Browser signers are TESTNET-ONLY (product decision). Every create/join/sign path routes
/// the network through here. The match is exhaustive with no wildcard on purpose: if core
/// `Network` ever gains a Mainnet variant, this crate stops compiling until that variant is
/// explicitly refused here, so the browser fails closed instead of silently signing for it.
fn browser_network(net: Network) -> Result<Network, String> {
    match net {
        Network::Regtest | Network::Testnet => Ok(net),
    }
}

fn sign_challenge(identity: &Identity, challenge: &str) -> Result<String, String> {
    let challenge = uuid::Uuid::parse_str(challenge).map_err(|e| e.to_string())?;
    let secret = Zeroizing::new(identity.to_secret_bytes());
    let relay: [u8; 32] = secret[34..66].try_into().expect("32-byte X25519 secret");
    let signing = xeddsa::xed25519::PrivateKey::from(&*Zeroizing::new(relay));
    let sig: [u8; 64] = xeddsa::Sign::sign(&signing, challenge.as_bytes(), rand::rng());
    Ok(hex::encode(sig))
}

/// The core nonce witness for a browser member. The core calls `claim` inside `sign_approve`,
/// after approval and the sighash binding and before the share is opened; a synchronous call
/// cannot wait on the network, so the Worker claims at both witness relays first (verified,
/// fresh receipts) and this accepts exactly a claim it was told both confirmed, once. Any
/// other claim (none made, refused, duplicate, or for other bytes) is a refusal, so the core
/// releases nothing and leaves the nonce unburned.
struct ClaimedAhead {
    pins: WitnessPins,
    claimed: Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>,
}

impl NonceWitness for ClaimedAhead {
    fn pins(&self) -> WitnessPins {
        self.pins
    }
    fn claim(&mut self, cid: [u8; 32], record: &[u8]) -> Result<(), String> {
        let mut claimed = self.claimed.lock().map_err(|_| "claim state poisoned")?;
        let at = claimed
            .iter()
            .position(|(c, r)| *c == cid && r == record)
            .ok_or("both nonce witnesses must first confirm a fresh claim for this signature")?;
        claimed.remove(at);
        Ok(())
    }
}

fn parse_witness_pins(json: &str) -> Result<WitnessPins, String> {
    #[derive(serde::Deserialize)]
    struct Pin { key: String, run: String, mailbox: String }
    let pins: [Pin; 2] = serde_json::from_str(json).map_err(|_| "nonce witnesses: expected two {key, run, mailbox}".to_string())?;
    let one = |p: &Pin| -> Result<([u8; 32], [u8; 32], [u8; 32]), String> { Ok((hex32(&p.key)?, hex32(&p.run)?, hex32(&p.mailbox)?)) };
    let pins = [one(&pins[0])?, one(&pins[1])?];
    if !valid_witness_pins(pins) {
        return Err("two distinct, nonzero nonce witnesses are required".into());
    }
    Ok(pins)
}

/// The payment terms a member approved, as the proposer announced them (payment.rs
/// `intent_json`), plus `tx_expiry`: the expiry fixed at `start`, else `expiry_height`.
#[derive(serde::Deserialize)]
struct Terms {
    recipient: String,
    amount_zat: u64,
    memo: String,
    fee_zat: u64,
    change_zat: u64,
    note_selection: Vec<String>,
    target_height: u32,
    tx_expiry: u32,
}

/// The consensus parameters of a browser signer's network (testnet-only gate included).
fn vault_network(net: Network) -> Result<VaultNetwork, String> {
    Ok(match browser_network(net)? {
        Network::Regtest => VaultNetwork::Regtest,
        Network::Testnet => VaultNetwork::Testnet,
    })
}

/// The reviewed request core `sign_approve` binds the candidate to, built from the terms the
/// member approved — never from the candidate (payment.rs builds it the same way).
fn payment_params(terms: &Terms, net: VaultNetwork) -> Result<PublicPaymentParams, String> {
    Ok(PublicPaymentParams {
        recipient: orchard_receiver_from_ua(&terms.recipient, net.network_type())?,
        amount: Zatoshis::from_u64(terms.amount_zat).map_err(|e| format!("amount: {e:?}"))?,
        memo: MemoBytes::from_bytes(terms.memo.as_bytes()).map_err(|e| format!("memo: {e:?}"))?,
        target_height: terms.target_height,
        expiry_height: terms.tx_expiry,
    })
}

/// The co-signer review of a candidate against approved terms (payment.rs `review_candidate`).
fn check_against_terms(
    bytes: &[u8],
    terms: &Terms,
    net: VaultNetwork,
    fvk: &orchard::keys::FullViewingKey,
) -> Result<(), String> {
    let parsed = pczt::Pczt::parse(bytes).map_err(|e| format!("candidate: {e:?}"))?;
    let branch = u32::from(BranchId::for_height(&net, BlockHeight::from_u32(terms.target_height)));
    if *parsed.global().consensus_branch_id() != branch || *parsed.global().expiry_height() != terms.tx_expiry {
        return Err("candidate network or expiry differs from the approved terms".into());
    }
    let [note] = terms.note_selection.as_slice() else {
        return Err("the approved terms must spend exactly one note".into());
    };
    let recipient = orchard_receiver_from_ua(&terms.recipient, net.network_type())?;
    let expected = Expectations {
        input_nullifiers: vec![hex32(note)?],
        recipient: recipient.to_raw_address_bytes(),
        amount_zat: terms.amount_zat,
        memo: terms.memo.as_bytes().to_vec(),
        change_zat: terms.change_zat,
        fee_zat: terms.fee_zat,
        expiry_height: terms.tx_expiry,
    };
    pczt::roles::verifier::Verifier::new(parsed)
        .with_ironwood::<Refusal, _>(|bundle| {
            check_candidate(bundle, fvk, &expected).map_err(pczt::roles::verifier::OrchardError::Custom)
        })
        .map_err(|e| format!("candidate differs from the approved terms: {e:?}"))?;
    Ok(())
}

/// Re-stamp a device identity to a vault slot: overwrite the 2 id bytes, keep the keys.
fn restamp(identity: &Identity, slot: u16) -> Result<Identity, String> {
    let mut secret = Zeroizing::new(identity.to_secret_bytes());
    secret[..2].copy_from_slice(&slot.to_be_bytes());
    Identity::from_secret_bytes(&secret[..])
}

/// The `recovery.pub` layout (native host `public_keys`): X25519 then Ed25519 public key.
fn recovery_public_keys(key: &RecoveryKey) -> Vec<u8> {
    [key.public_bytes(), key.signing_public()].concat()
}

fn recovery_record_prefix(identity: &Identity) -> Vec<u8> {
    [RECOVERY_RECORD, identity.public().signing.as_slice()].concat()
}

fn seal_recovery_record(identity: &Identity, kek: &[u8; 32], keys: &[u8]) -> Result<Vec<u8>, String> {
    let mut record = recovery_record_prefix(identity);
    record.extend_from_slice(keys);
    Ok(SealedShare::seal(&SoftwareSecureElement::from_kek(*kek), 0, &record)?.to_bytes())
}

/// Re-seal a KEK-sealed vault backup to the recovery public key, as the native host's
/// `seal_vault_backup` does: reopen it for its material, then HPKE-seal that to the words.
fn seal_to_recovery(
    artifact: &BackupArtifact,
    pass: &str,
    vault_id: &[u8; 32],
    recovery_pub: &[u8; 32],
) -> Result<BackupArtifact, String> {
    let material = backup::verify(artifact, pass, vault_id)?;
    backup::create_to_recovery(&material, recovery_pub)
}

/// Open a recovery backup with the words: it must be for this vault, carry the identity and
/// roster a signing member needs (native `restore_vault_from_backup`), and be for a network
/// browser signers serve.
fn restored_material(key: &RecoveryKey, blob: &[u8], vault_id: &[u8; 32]) -> Result<BackupMaterial, String> {
    let material = backup::verify_recovery(&BackupArtifact(blob.to_vec()), key, vault_id)?;
    if material.roster.is_empty() || material.identity.is_empty() {
        return Err("this backup has no roster, so it cannot rebuild a member that signs".into());
    }
    browser_network(material.network)?;
    Ok(material)
}

fn vault_ref_json(v: &VaultRef) -> String {
    serde_json::json!({
        "vault_id": hex::encode(v.vault_id),
        "label": v.label,
        "threshold": v.threshold,
        "members": v.members,
        "ready": v.ready,
    })
    .to_string()
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes of hex".to_string())
}

impl Signer {
    fn set_nonce_witnesses_impl(&mut self, pins_json: &str, confirmation: Option<&str>) -> Result<bool, String> {
        self.witness_pins = None;
        self.claimed.lock().map_err(|_| "claim state poisoned")?.clear();
        let pins = parse_witness_pins(pins_json)?;
        let fingerprint = witness_fingerprint(pins);
        let identity = self.identity.as_ref().ok_or("unlock the signer first")?.public();
        let binding = loki_signer_core::signer::secure_element::file_binding(
            "device-witness-pins", &identity.signing, identity.id,
        );
        let se = SoftwareSecureElement::from_kek(**self.kek.as_ref().ok_or("unlock the signer first")?);
        let approved = opfs_get(WITNESS_PINS_PATH)?
            .and_then(|raw| SealedShare::from_bytes(&raw).ok())
            .and_then(|sealed| sealed.open_bound(&se, &binding).ok());
        if approved.as_deref().map(Vec::as_slice) != Some(fingerprint.as_slice()) {
            let Some(confirmation) = confirmation else { return Ok(false) };
            if hex32(confirmation).ok() != Some(fingerprint) {
                return Err("the independently verified nonce witness fingerprint does not match this configuration".into());
            }
            let sealed = SealedShare::seal_bound(&se, 0, &fingerprint, &binding)?.to_bytes();
            opfs_put(WITNESS_PINS_PATH, &sealed, false)?;
            if opfs_get(WITNESS_PINS_PATH)?.as_deref() != Some(sealed.as_slice()) {
                return Err("nonce witness approval did not persist".into());
            }
        }
        self.witness_pins = Some(pins);
        Ok(true)
    }

    fn recovery_recipient(&self) -> Result<Option<[u8; 64]>, String> {
        let identity = self.identity.as_ref().ok_or("unlock the signer first")?;
        let kek = self.kek.as_ref().ok_or("unlock the signer first")?;
        let Some(sealed) = opfs_get(RECOVERY_PATH)? else { return Ok(None) };
        let record = SealedShare::from_bytes(&sealed)?.open(&SoftwareSecureElement::from_kek(**kek))?;
        let keys = record.strip_prefix(recovery_record_prefix(identity).as_slice())
            .and_then(|keys| keys.try_into().ok()).ok_or("invalid recovery recipient for this profile")?;
        Ok(Some(keys))
    }

    fn write_recovery_recipient(&self, keys: &[u8]) -> Result<(), String> {
        let identity = self.identity.as_ref().ok_or("unlock the signer first")?;
        let kek = self.kek.as_ref().ok_or("unlock the signer first")?;
        opfs_put(RECOVERY_PATH, &seal_recovery_record(identity, kek, keys)?, false)?;
        if self.recovery_recipient()?.as_ref().map(|k| k.as_slice()) != Some(keys) {
            return Err("recovery recipient did not persist".into());
        }
        Ok(())
    }

    /// This payment's candidate reference. The native host uses `payment_id == attempt_id ==
    /// attempt`, which also fixes the crash-safe nonce file name; mirror it.
    fn candidate_ref(&self, attempt_hex: &str) -> Result<(CandidateRef, [u8; 32]), String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultJoin first")?;
        browser_network(vs.signer.network())?;
        let attempt = hex32(attempt_hex)?;
        Ok((
            CandidateRef {
                vault_id: vs.vref.vault_id,
                payment_id: attempt,
                attempt_id: attempt,
            },
            vs.vref.vault_id,
        ))
    }

    fn payment_review_impl(&self, candidate_hex: &str) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultJoin first")?;
        let (_, fvk) = vs.signer.hosted_metadata().map_err(|e| e.to_string())?;
        let bytes = hex::decode(candidate_hex).map_err(|e| e.to_string())?;
        let view = describe_pczt(&bytes, &fvk)?;
        let sighash = sighash_of_pczt(&bytes, &fvk)?;
        let expiry = *pczt::Pczt::parse(&bytes).map_err(|e| format!("candidate: {e:?}"))?.global().expiry_height();
        Ok(serde_json::json!({
            "expiry_height": expiry,
            "recipient": hex::encode(view.to),
            "amount_zat": view.amount_zat.to_string(),
            "fee_zat": view.fee_zat.to_string(),
            "change_zat": view.change_zat.to_string(),
            "memo": hex::encode(view.memo),
            "network_branch_id": view.network_branch_id,
            "fee_verified": view.fee_verified,
            "sighash": hex::encode(sighash),
        })
        .to_string())
    }

    fn nonce_claim_impl(&self, attempt_hex: &str, package_hex: &str, seed_hex: &str, sighash_hex: &str) -> Result<String, String> {
        let (candidate, _) = self.candidate_ref(attempt_hex)?;
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultOpen first")?;
        let package = frost::SigningPackage::deserialize(&hex::decode(package_hex).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let sighash = hex32(sighash_hex)?;
        if package.message().as_slice() != sighash {
            return Err("signing package differs from the confirmed sighash".into());
        }
        let member = frost::Identifier::try_from(vs.slot).map_err(|e| e.to_string())?;
        let commitment = package.signing_commitments().get(&member).ok_or("own commitment absent")?;
        let pins = vs.signer.nonce_claim_pins(&candidate, commitment).map_err(|e| e.to_string())?;
        let cid = nonce_claim_id(&vs.vref.vault_id, &member, commitment)?;
        let record = nonce_claim_record(&cid, &sighash, &hex32(seed_hex)?);
        let pins = pins.map(|(key, run, mailbox)| serde_json::json!({
            "key": hex::encode(key), "run": hex::encode(run), "mailbox": hex::encode(mailbox),
        }));
        Ok(serde_json::json!({ "cid": hex::encode(cid), "record": hex::encode(record), "pins": pins }).to_string())
    }

    fn reauth_check(&self, method: &str, passphrase: Option<String>, prf_secret: Option<Vec<u8>>) -> Result<(), String> {
        let held = self.kek.as_ref().ok_or("unlock the signer first")?;
        let again = custody_kek(method, passphrase, prf_secret, false)?;
        let diff = held.iter().zip(again.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err("that does not unlock this signer".into());
        }
        Ok(())
    }

    fn payment_check_impl(&self, candidate_hex: &str, terms_json: &str) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultOpen first")?;
        let terms: Terms = serde_json::from_str(terms_json).map_err(|e| format!("payment terms: {e}"))?;
        let net = vault_network(vs.signer.network())?;
        let (_, fvk) = vs.signer.hosted_metadata().map_err(|e| e.to_string())?;
        let bytes = hex::decode(candidate_hex).map_err(|e| e.to_string())?;
        check_against_terms(&bytes, &terms, net, &fvk)?;
        let mut review: serde_json::Value =
            serde_json::from_str(&self.payment_review_impl(candidate_hex)?).map_err(|e| e.to_string())?;
        review["recipient_ua"] = terms.recipient.into();
        review["memo_text"] = terms.memo.into();
        Ok(review.to_string())
    }

    fn sign_commit_impl(&mut self, attempt_hex: &str) -> Result<String, String> {
        if self.witness_pins.is_none() {
            return Err("browser signing requires two approved nonce witnesses".into());
        }
        let (cand, _) = self.candidate_ref(attempt_hex)?;
        let vs = self.vault.as_mut().ok_or("no active vault — call vaultJoin first")?;
        let commit = vs.signer.sign_commit(&vs.session, &cand).map_err(|e| e.to_string())?;
        commit.serialize().map(hex::encode).map_err(|e| e.to_string())
    }

    fn hosted_signing_context(
        &self,
        attempt_hex: &str,
        signers_csv: &str,
    ) -> Result<(&VaultState, SessionContext), String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultJoin first")?;
        let mut signers: Vec<u16> = signers_csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u16>().map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        signers.sort_unstable();
        let attempt = hex32(attempt_hex)?;
        let context = SessionContext {
            vault: vs.vref.vault_id,
            payment: attempt,
            attempt: AttemptId(attempt),
            signers,
        };
        Ok((vs, context))
    }

    fn open_control_impl(&self, session_id: &str, from_hex: &str, wire_hex: &str) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultOpen first")?;
        let session = uuid::Uuid::parse_str(session_id).map_err(|e| e.to_string())?;
        let wire = hex::decode(wire_hex).map_err(|e| e.to_string())?;
        let (from, body) = vs
            .signer
            .open_control(session, &hex32(from_hex)?, &wire)
            .map_err(|e| e.to_string())?;
        let body = String::from_utf8(body).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "from": from, "body": body }).to_string())
    }

    fn seal_control_impl(&self, session_id: &str, to: u16, body_json: &str) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultOpen first")?;
        let session = uuid::Uuid::parse_str(session_id).map_err(|e| e.to_string())?;
        let sealed = vs
            .signer
            .seal_control(session, to, body_json.as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(hex::encode(sealed))
    }

    /// This member as `slot`, the creator, and the join exchange's context on `session_id`.
    fn join_parties(&self, vault_hex: &str, session_id: &str, slot: u16, creator_json: &str)
        -> Result<(Identity, PublicIdentity, SessionContext), String>
    {
        let identity = self.identity.as_ref().ok_or("unlock the signer first")?;
        let creator: serde_json::Value = serde_json::from_str(creator_json).map_err(|e| e.to_string())?;
        if creator["id"] != 1 {
            return Err("the invite's creator is not member 1".into());
        }
        let creator = PublicIdentity {
            id: 1,
            signing: hex32(creator["signing"].as_str().ok_or("creator signing key")?)?,
            encryption: hex32(creator["encryption"].as_str().ok_or("creator encryption key")?)?,
        };
        let session = uuid::Uuid::parse_str(session_id).map_err(|e| e.to_string())?;
        let context = SessionContext::control(hex32(vault_hex)?, session, 1, slot);
        Ok((restamp(identity, slot)?, creator, context))
    }

    fn join_seal_impl(&self, vault_hex: &str, session_id: &str, slot: u16, creator_json: &str, body_json: &str) -> Result<String, String> {
        let (me, creator, context) = self.join_parties(vault_hex, session_id, slot, creator_json)?;
        let sealed = SealedPeer::seal_join(&me, &creator, &context, body_json.as_bytes())?;
        Ok(hex::encode(Outbound::Peer(sealed).to_bytes().map_err(|e| e.to_string())?))
    }

    fn join_open_impl(&self, vault_hex: &str, session_id: &str, slot: u16, creator_json: &str, wire_hex: &str) -> Result<String, String> {
        let (me, creator, context) = self.join_parties(vault_hex, session_id, slot, creator_json)?;
        let opened = me.open_session(&creator, &context, &hex::decode(wire_hex).map_err(|e| e.to_string())?)?;
        if opened.kind() != MessageKind::PeerReply {
            return Err("not the creator's join reply".into());
        }
        String::from_utf8(opened.body().to_vec()).map_err(|e| e.to_string())
    }

    fn sign_approve_impl(
        &mut self,
        attempt_hex: &str,
        candidate_hex: &str,
        package_hex: &str,
        seed_hex: &str,
        confirmed_sighash_hex: &str,
        terms_json: &str,
    ) -> Result<String, String> {
        if self.witness_pins.is_none() {
            return Err("browser signing requires two nonce witnesses; none are configured".into());
        }
        let (cand, _) = self.candidate_ref(attempt_hex)?;
        let terms: Terms = serde_json::from_str(terms_json).map_err(|e| format!("payment terms: {e}"))?;
        let candidate = hex::decode(candidate_hex).map_err(|e| e.to_string())?;
        let package = frost::SigningPackage::deserialize(
            &hex::decode(package_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let seed = hex32(seed_hex)?;
        let vs = self.vault.as_mut().ok_or("no active vault — call vaultJoin first")?;
        let params = payment_params(&terms, vault_network(vs.signer.network())?)?;
        *self.approved.lock().map_err(|_| "approval state poisoned")? = Some(hex32(confirmed_sighash_hex)?);
        let share = vs
            .signer
            .sign_approve(&vs.session, &cand, &params, &candidate, &package, &seed)
            .map_err(|e| e.to_string())?;
        Ok(hex::encode(share.serialize()))
    }

    fn scan_save_impl(&self) -> Result<(), String> {
        let (path, id, network, scan) = self.scan.as_ref().ok_or("call scanNext first")?;
        let se = SoftwareSecureElement::from_kek(*self.kek.clone().ok_or("unlock the signer first")?);
        let binding = scan_binding(id, *network);
        let sealed = SealedShare::seal_bound(&se, 0, &scan.to_bytes(), binding.as_bytes())?;
        opfs_put(path, &sealed.to_bytes(), false)
    }

    fn scan_next_impl(&mut self) -> Result<u32, String> {
        let vs = self.vault.as_ref().ok_or("open the vault first")?;
        let path = format!("{}/scan.sealed", vs.dir);
        let id = vs.vref.vault_id;
        let roster = vs.signer.confirmed_roster().ok_or("this vault has no confirmed roster")?;
        let network = roster.network;
        if self.scan.as_ref().map(|(path, id, network, _)| (path, *id, *network)) != Some((&path, id, network)) {
            let (_, fvk) = vs.signer.hosted_metadata().map_err(|e| e.to_string())?;
            let se = SoftwareSecureElement::from_kek(*self.kek.clone().ok_or("unlock the signer first")?);
            let binding = scan_binding(&id, network);
            // Legacy or mismatched snapshots are rebuildable caches, not migration inputs.
            let saved = opfs_get(&path)?
                .and_then(|raw| SealedShare::from_bytes(&raw).ok())
                .and_then(|sealed| sealed.open_bound(&se, binding.as_bytes()).ok())
                .and_then(|plain| ChainScan::from_bytes(network, &fvk, &plain).ok());
            let scan = match saved {
                Some(scan) => scan,
                None => ChainScan::new(network, &fvk, roster.birth_height.unwrap_or(1))?,
            };
            self.scan = Some((path, id, network, scan));
        }
        let (_, _, _, scan) = self.scan.as_ref().expect("set above");
        Ok(scan.next_height())
    }

    fn vault_open_impl(&mut self, vault_hex: &str) -> Result<String, String> {
        let kek = self.kek.clone().ok_or("unlock the signer first")?;
        let me = self.identity.as_ref().ok_or("unlock the signer first")?.public().encryption;
        let dir = vault_dir(vault_hex);
        let vault_id = hex32(vault_hex)?;
        let prompts = browser_prompts(&dir, &kek, vault_id, None, None, self.approved.clone());
        let se = SoftwareSecureElement::from_kek(*kek);
        let mut signer = match stored_vault(&dir)? {
            StoredVault::Pending | StoredVault::Confirmed =>
                LocalSigner::open(std::path::Path::new(&dir), se, "vault".into(), prompts)
                    .map_err(|e| e.to_string())?,
            StoredVault::Restored(artifact) => {
                // Restore re-seals the backup under this browser's KEK. Rebuild with the
                // same nonce directory and restore epoch every time.
                let pass = hex::encode(*kek);
                let roster = backup::verify(&artifact, &pass, &vault_id)?.roster;
                let nonces = std::path::PathBuf::from(format!("{dir}/nonces"));
                let mut signer = backup::restore(&artifact, &pass, &vault_id, se, nonces, prompts.approval)
                    .map_err(|e| e.to_string())?;
                signer.adopt_restored_roster(&roster, prompts.connect).map_err(|e| e.to_string())?;
                signer
            }
            StoredVault::Absent => return Err("this browser holds no signer for that vault".into()),
        };
        let net = browser_network(signer.network())?;
        let session = signer
            .connect("https://coordinator", net, b"browser vault")
            .map_err(|e| e.to_string())?
            .session;
        let vref = signer
            .list_vaults(&session)
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("this vault's setup has not started")?;
        let roster = signer.confirmed_roster().ok_or("this vault has no confirmed roster")?;
        let slot = roster
            .members
            .values()
            .find(|m| m.encryption == me)
            .ok_or("this signer is not a member of that vault")?
            .id;
        let members: Vec<_> = roster
            .members
            .values()
            .map(|m| {
                serde_json::json!({
                    "id": m.id,
                    "signing": hex::encode(m.signing),
                    "encryption": hex::encode(m.encryption),
                })
            })
            .collect();
        let out = serde_json::json!({
            "vault_id": hex::encode(vref.vault_id),
            "slot": slot,
            "threshold": roster.threshold,
            "network": roster.network.label(),
            "ready": vref.ready,
            "members": members,
        })
        .to_string();
        if let Some(pins) = self.witness_pins {
            signer.set_nonce_witness(Box::new(ClaimedAhead { pins, claimed: self.claimed.clone() }));
        }
        self.vault = Some(VaultState { signer, session, vref, slot, dir });
        Ok(out)
    }

    fn vault_join_impl(
        &mut self,
        vault_hex: &str,
        slot: u16,
        label: &str,
        network: &str,
        roster: &[u8],
        confirmed_code: &str,
    ) -> Result<String, String> {
        let kek = self.kek.clone().ok_or("unlock the signer first")?;
        let identity = self.identity.as_ref().ok_or("unlock the signer first")?;
        let vault_id: [u8; 32] = hex::decode(vault_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "vault id must be 32 bytes of hex".to_string())?;
        let net = parse_network(network)?;
        let recovery = self.recovery_recipient()?.ok_or("confirm your recovery words before joining a vault")?;
        let stamped = restamp(identity, slot)?;
        let own = stamped.public();
        let dir = vault_dir(vault_hex);
        let se = SoftwareSecureElement::from_kek(*kek);
        let prompts = browser_prompts(
            &dir,
            &kek,
            vault_id,
            Some(recovery[..32].try_into().unwrap()),
            Some(confirmed_code.to_string()),
            self.approved.clone(),
        );
        let path = std::path::Path::new(&dir);
        let mut signer = match stored_vault(&dir)? {
            StoredVault::Restored(_) => return Err("this vault is already restored; open it instead of joining".into()),
            StoredVault::Pending | StoredVault::Confirmed => LocalSigner::open(path, se, label.to_string(), prompts),
            StoredVault::Absent => LocalSigner::create_with_identity(
                path,
                se,
                net,
                vault_id,
                slot,
                label.to_string(),
                prompts,
                stamped,
            ),
        }
        .map_err(|e| e.to_string())?;
        let connection = signer
            .connect("https://coordinator", net, b"browser dkg")
            .map_err(|e| e.to_string())?;
        if connection.member.id != slot || connection.member.signing != own.signing
            || connection.member.encryption != own.encryption
        {
            return Err("join request does not match this vault's local member".into());
        }
        let session = connection.session;
        let existing = signer.list_vaults(&session).map_err(|e| e.to_string())?;
        let vref = if existing.is_empty() {
            signer
                .dkg_begin(&session, roster)
                .map_err(|e| e.to_string())?
        } else {
            let vref = existing.into_iter().next().expect("non-empty");
            let stored = signer.confirmed_roster().ok_or("vault has no confirmed roster")?;
            let incoming = Roster::from_bytes(roster).map_err(|e| e.to_string())?;
            if vref.vault_id != vault_id || stored.fingerprint() != incoming.fingerprint()
                || local::roster_code(&stored.fingerprint()) != confirmed_code
            {
                return Err("join request does not match this vault's confirmed roster".into());
            }
            vref
        };
        let out = vault_ref_json(&vref);
        self.vault = Some(VaultState {
            signer,
            session,
            vref,
            slot,
            dir,
        });
        Ok(out)
    }

    fn create_impl(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, String> {
        if opfs_exists(IDENTITY_PATH) {
            return Err("a signer already exists in this browser".into());
        }
        let kek = custody_kek(method, passphrase, prf_secret, true)?;
        let se = SoftwareSecureElement::from_kek(*kek);
        let identity = Identity::new(1);
        let secret = Zeroizing::new(identity.to_secret_bytes());
        let sealed = SealedShare::seal(&se, 0, &secret[..])?;
        opfs_put(IDENTITY_PATH, &sealed.to_bytes(), true)?; // write-once
        opfs_put(PROFILE_PATH, profile_json(&identity, name).as_bytes(), false)?;
        let out = profile_json(&identity, name);
        self.kek = Some(kek);
        self.identity = Some(identity);
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_impl(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
        vault_hex: &str,
        words: &str,
        blob: &[u8],
        fingerprint: &str,
    ) -> Result<String, String> {
        if opfs_exists(IDENTITY_PATH) {
            return Err("restore into a fresh browser: this one already holds a signer".into());
        }
        let vault_id = hex32(vault_hex)?;
        let key = RecoveryKey::from_words(words)?;
        BackupArtifact(blob.to_vec()).check_fingerprint(fingerprint)?;
        let material = restored_material(&key, blob, &vault_id)?;
        let identity = Identity::from_secret_bytes(&material.identity)?;
        let dir = vault_dir(vault_hex);
        let recovery_path = format!("{dir}/recovery.backup");
        let existing = opfs_get(&recovery_path)?;
        if existing.as_deref().is_some_and(|bytes| bytes != blob) {
            return Err("a different recovery file already exists for this vault; preserve it before restoring another copy".into());
        }
        let kek = custody_kek(method, passphrase, prf_secret, true)?;
        let se = SoftwareSecureElement::from_kek(*kek);
        // The backup re-sealed under this browser's KEK is what `vaultOpen` rebuilds from; the
        // words stay this signer's recovery identity, so later backups seal to the same words.
        let local = backup::create(&material, &hex::encode(*kek))?;
        opfs_put(&format!("{dir}/backup.sealed"), &local.0, false)?;
        if existing.is_none() { opfs_put(&recovery_path, blob, true)?; }
        opfs_put(RECOVERY_PATH, &seal_recovery_record(&identity, &kek, &recovery_public_keys(&key))?, false)?;
        opfs_put(PROFILE_PATH, profile_json(&identity, name).as_bytes(), false)?;
        // The identity last: until it exists this browser still counts as fresh.
        let secret = Zeroizing::new(identity.to_secret_bytes());
        opfs_put(IDENTITY_PATH, &SealedShare::seal(&se, 0, &secret[..])?.to_bytes(), true)?;
        let profile = profile_json(&identity, name);
        self.kek = Some(kek);
        self.identity = Some(identity);
        let vault = self.vault_open_impl(vault_hex)?;
        Ok(format!(r#"{{"profile":{profile},"vault":{vault}}}"#))
    }

    fn unlock_impl(
        &mut self,
        method: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, String> {
        let kek = custody_kek(method, passphrase, prf_secret, false)?;
        let se = SoftwareSecureElement::from_kek(*kek);
        let raw = opfs_get(IDENTITY_PATH)?.ok_or("no signer in this browser — create one first")?;
        let secret = SealedShare::from_bytes(&raw)?.open(&se)?;
        let identity = Identity::from_secret_bytes(&secret)?;
        self.kek = Some(kek);
        let name = opfs_get(PROFILE_PATH)?
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "You".to_string());
        let out = profile_json(&identity, &name);
        self.identity = Some(identity);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // Repro of the browser approver's post-message signing path that panicked live: render +
    // recompute-sighash of a real candidate PCZT. Fixture dumped from a native dealer vault.
    const CANDIDATE_HEX: &str = "50435a54020000000698ed92c40ddbac94bd0301008009010000000100000000010000000000000000000000000000000000000000000000000000000000000000000102015c2b08f6b99c91e8e05bc36d9331c4b2e1bb76aba2c320e46274a826c09ab83b018183dc4afdfa1e06f2b949edf3c02bb83d546168327ea5d0f6a66ae20906a3220181ae52a0c6e38631987a4b019191de61179929706c0aa8a8754580563cd57e0d0001b4859a5cd871081c2e1f900b7602861cf689ec0e0e0dfa429228cbc14a221f3b6ed8d0c0c94b3a0a21959a01c0fc82aa02010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202016f5b47426a1736e8b211c04c923c7f87698a403412b9e7e6e3cca56035b4973f18c5cd0dcf61488eec0ce2981deaa3343f36606137da78739171664d4dde5e37ca728c87a618c1082ca7f43989c8a4c4260d212f706886e30f120b588018463a0001dd5eacc8e21a886a41ff31d2ba73f188c827f47fff093e51373b97a6390eb209000000016aaac0b071c902f81ad053322535a7394d44839a353c342d9ce33501815ef1089b723e9d7fb3102378fdde39f8e0ec5118f299f30d4c8ee707364eefc706fa8400c4049eb46b7f7866a1c6532ce4e464d08e278c78e3a127daa3e603ad5bb0f73a274361d6a6b0403947e78a6134679c1bddd987b808489f383639acd9fe10ddda8c9089b9c14a5aad080fbcf82e5b5334e393779ece9e4c90b39f67d16b44f4e1cf4ff1fecb224dda4bdd44b92d8b9cb4a40cdb37d237470d86e4724bec4b92788e1747634eaaf33370f658af7b99446d7489c0b9cd374b9978c7c8da9a890e89e5b05564106b142d6ad0b9f3cdb8b2bd34daa107a7bb5bbe70b8776f09b8fe22a4ada3b0781b246ade2992649513e8a93743a6fa741241b248a77c56f8f5d8967ab17db34a4ca070f84fde75730082429e2bb8c180538295b5b9b845edfa219c0e34fe2401fc716a47406fff539381a11890ae39e0fa71e725ed616487408adcbf90f8730536716e55ee07d801ac61857adcafd96671b8729a74dd8643cba69d5af927275bf67a58e3ae249c58011436a7ea1c55e789518bc88808e0b438263a58c0cc276868c8a13bb060123fcb08ed723ef7aca8cba056abe8ee8f7ab69e4728b892c69ba15607e2840a21da6770092d7375e757ac36ae238bd7f609d8b023983a5305e0eb18532b585e03917aadbc1ecc12ac5baf9263c517587d69783863a8b282e5012015f168a7f4b79c4ae3324b76ae755b3e73d7c2d40e77b32df2edb1c9829f67110c125f0cfb54318b07f51b821465f6941fb531e92314a1771e48d40ae4b0e517da53883f9d9cfa3d28ed350a2abc7b73ae14f846dfd27e8087d2faaa6998b23db2abb39542c4faa981e59bb357396b293964d9c6d047640524ab262ca9fce8c35001d57d337509d84dd3db799ad3d4c632407c94e6fcefced0eed856f7719e3e712847bf40c9391c22b47907cdc000a0443a178443e469806dcf34d4558109b0c93b7627de1919ec060b486938c568554a0132452ece66910908921f4a55e35dcb88d16257cbbd86d7a4ca3e554aad8afa84670a3a1cafc5638a89beb001b0faf896020117088f6c65a962f897a82129712a98a295a646adb533af9d3efc75cf70af2c3c0000000001cb5ead2f0b21c1e5afa6257ffd47594ea1d93569b07c81cc40645d9addb2ca2001af34cabeea8ef9c8a7d2b5bed819923163bc40f1378af8ab62ea2f91c048d73401dfb51768c5a344e46b7509e27dc9e3363913dbfb1993e3aebe5c7dd55088d00001cc81f56467d96b3bebf8aa8491c17a0677cd92ca7c1ba45cbb2c274e15ded08d01527a16cd43084f245f66b54642532ac4415dd70614b30d558dd66ab6716cd98fe945fbf14fb086466ca75daff959fa5771b633c70fb01ddc39688e422f28b9140110a413bf94a727fe6eb7b3595cf1cf58bc1316229e8ab0bda996dec4233f98f0a2e3ba849098f9915bd124010001a76e2245b2668050ef16f541cacb4fe415c7cacedcfdec7a4d7de5966173403701d12324a9a342980013e2e704c7ef18d69939dc885d94a6558af06b89a85839d8016685f198a38ba86b8ed39aabe8ae8e7cb6c5721eea72108bede1c6a6401c733c68868b870439da5569c46a6c1317e73948edf61d53319371bc018ed2d426e62b81d6c08cd18fa46f09673ec059a6df1b5bdb88946e12015234dd3eec4d549a3401e1d3b1cb05aac213a5554247f930ad7cf035cff899d20c7444d7914dba50534c19eaa06d1097622ce7d229a2c29404fcbc79d29a0f4557f58807d29458535c9ed5cf74e13faa91bde886412f6ff81049fd0fbca55868d777539b6cc04ce3bff39889be28234d6f245eb852f5e97286f06e881677f8de6cbd7e2a6654bbb1420f5112b5ac0e0e6c58b8500ba776754b561b3530f47f3dfbad30d5f6dbcf06d2fc97d31ea8221f01d8f48c69c6de2506fdf07c57ed04f3be543ae18173a66dad07c026a792043f87c235275ef14821e5592a8aa3d7825f9641cef63e59249199f7cef880570848e5391b72cc1763ea7a171754b95edeae02971e4365a7ab6e19cd7103f2aa3c99747eea7890376fdd40df7e359ccda78829898c2ffa35919be4476aedb2a82a11fd1e4f79dc39a6ba909716164b498e4b674586e8dc5a8ba9edfc3459e0ef0ea70959085d5d0738641e5f25fecbac293fead8b05e75680f1b0e510e3008471fa0b43d2efb24495c0d30f6309f0943be5e4c97079078b57a19040c82ff98e5252fdb13294a1d9b30a63298123882e999d0995303880622659557d523ea980f12c09e4fe24562baf552c9781979fc0ab16bb301772bc7aa6afa923279bf520f24bd8292e1192e1bde41e780e8310a2909171e487d182e1178eed42f7d8b2f9c267bf170839b58b900455f41ccca87f65c912eeba6d562aaaaaa2059569e53be09e5d607cd2ac28fbaa837368df67c4eaeb603bce36a5f30381b4c5aad0b98a407e0fbe00347c08b07d3e61a72aeaed2723d44afbf35d070f2ef49105fdbd73c3afd03943bf23d3d80ac52d1f1439eef01bde21295a13fb600f00481c8cba1eb0718a1ca9a66958f2f44628744b3dfb0e9e222b4ce8e3193235602b0b139c637187af8e972637da0c82a374e46eb6bf5a9176c3dbb2ac482d0d2eeef0d186f243cdfd8d14aae595048d2f2df335156981ff30a0594a74c71f7df21cbc79b574912f092498340ae1ee0f8315873c0f335f358879d95de92153db82679d6dbd5941368b431ee71297347f6f684fd9d2b8e34af348858f0ec2067b3849011b3c36f1db7e15d4e3c3652a452dc2db10b87e489287943efe67da12ab6510ddd6ef11a3d6c16d049c6539b53f05ef6840188f239dc1e5f2865e295e77af4033416ec930221016b89167d7f780e151b0995f3d742d348e3d6bdb566f6eb7ec9358e4df801ddd832eaf606e448188f6bee47ed37823306f2bb6319520d044d51f1effaa20bf465d19332e094facb71a9097fe9c8b9f45cd1bdc0ff1aac76c49c55590c591844dfd3d1ae94ddd0693138f92d89ed7baef6b01d973fae0404e2aa1b518e2f23c72ffcb8055713487417419e8af75e16ee70695943434fba69522bcc2af7bc3c19f1e2207ea5068ac7e1b9fdad92d2c18bf5553cab1990e9a9fea9e95788220e01f9f637460dc2859c171b9ccbf2e9d49744465174404441bc34af2449372c3f0600000001d85682fb8c88d5f6ae464fd5acc37c74a1d64960bcf6186201886adc98b1ea1c14841398177f00fb3278d90b0fe6b97ff1ff0df90ce22869240432d4c605120700c404ce98a0a8bfa21346d6ba9d4efa56d8763ba000ebe48b32110f8844b91a0113f4f35ca4059e5ee14a1a2e12b6522e9f291465a86cc596ae8e9438325d2b75d4e1cd04d20ebac9db3823541ac36baf0733e07c10c2860661bbdc7e65908820b94972688648db283b7044f1c1c49577801527f6dffed053095c7ddfe291168d80228c3aeb45598384cde6ebc6cd0d9fdbc31de34052e514dcaf2ca2668c9e323597064dae0a5ac2f8a86df62e48f52f475e3852315947386a2cb80abf66d281ee18c0dfb426093ace6a97b1b53de57489b84c777f52ef064bedfdc341ce5e7807a38022526e1881e384291eb1635674189f95404c3055a51341159bcc30ed6248befa852ef3d32e517b3df38a83801a854754dbc2f64882762ff66b449279f9d402cdb04776378bbbc197a33de4138c50704f0f2be738162185177335c17a21ac2baf31455566d81cc1793e022362408f13f3e4b10311db2e175a7cd082a213922d9e3868fb1c7293543e93aadd457792a8aa3a47d672e7593e6b0ff9d469c039b13569c6515878656e1dd7d6f259900f82d3fad904893f6f5c3d088351752458108d4242a5c6e8c046bf6dd7a9b3d1e259ffe7db7efb35e330a74e591274c8ef5f4b30921ce409ef889494dff5ade225f4cd80b617f1159635f9e375e489fa1b09602d47e614d778f09c75886997cc57e0ea4d208f7087e2eb04095d25023799bbebd7eb210405285913ab61d66244aecd3aea556b09ac7762abc86895458790f2450f4191322336071584f7de8c1deb873fca04646b55e9d1427caf16fbe04036dc36d15b506e6a998ad8510f92fe89ce68ae38e9a15d744ff1436375eddd4135e62810ee4c4b457916f5b9f5cf14d2ab940ec3f3bf141b80210aeac2b5ed6dd466519167eda9f0bf976e108492cc9ada2f4c3210c201e2d15cb4e254a54a1fa7eff6f7cded3b3aaefdade66050a6b340a25b611e1cf27a47fc4c608738eb2d70390180b489130131fb120b23f891b76f36c712463434f498487485c756d054bc13d7ef3d3e240600000000014db58c86ea90a5c93ecf5877654ab27ae0cf60bcd04165e422d2d94fec68e73307904e000001000117143ab6d4c61f2311cde9ec66f9c4a681a9962581bee6b0633637eac91bb214";
    const FVK_HEX: &str = "6f5b47426a1736e8b211c04c923c7f87698a403412b9e7e6e3cca56035b4973f18c5cd0dcf61488eec0ce2981deaa3343f36606137da78739171664d4dde5e37ca728c87a618c1082ca7f43989c8a4c4260d212f706886e30f120b588018463a";

    #[wasm_bindgen_test]
    fn repro_describe_and_sighash_candidate() {
        let cand = hex::decode(CANDIDATE_HEX).unwrap();
        let fvk_bytes: [u8; 96] = hex::decode(FVK_HEX).unwrap().try_into().unwrap();
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes).unwrap();
        let _ = describe_pczt(&cand, &fvk).unwrap();
        let _ = sighash_of_pczt(&cand, &fvk).unwrap();
    }

    #[wasm_bindgen_test]
    fn browser_signer_refuses_every_network_but_testnet_and_regtest() {
        assert_eq!(parse_network("testnet").unwrap(), Network::Testnet);
        assert_eq!(parse_network("regtest").unwrap(), Network::Regtest);
        for other in ["mainnet", "main", "Testnet", "", "testnet "] {
            assert!(parse_network(other).is_err(), "{other:?} must be refused");
        }
        // The connect prompt refuses through the same gate.
        let mut prompts = browser_prompts("loki/vaults/x/signer", &[0u8; 32], [1u8; 32], None, None, Arc::new(Mutex::new(None)));
        assert!((prompts.connect)("https://coordinator", Network::Testnet));
    }

    #[wasm_bindgen_test]
    fn frostd_challenge_is_signed_in_wasm_with_the_relay_key() {
        let identity = Identity::new(1);
        let relay = identity.public().encryption;
        let challenge = uuid::Uuid::from_bytes([9u8; 16]);
        let sig: [u8; 64] = hex::decode(sign_challenge(&identity, &challenge.to_string()).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        // Exactly what frostd checks: xed25519 over the 16 challenge bytes, by the relay pubkey.
        let public = xeddsa::xed25519::PublicKey::from(&x25519_dalek::PublicKey::from(relay));
        assert!(xeddsa::Verify::verify(&public, challenge.as_bytes(), &sig).is_ok());
        assert!(xeddsa::Verify::verify(&public, b"other bytes", &sig).is_err());
        assert!(sign_challenge(&identity, "not a uuid").is_err());
    }

    #[wasm_bindgen_test]
    fn lock_drops_identity_and_kek() {
        let mut signer = Signer::new();
        signer.identity = Some(Identity::new(1));
        signer.kek = Some(Zeroizing::new([5u8; 32]));
        signer.lock();
        assert!(signer.identity.is_none() && signer.kek.is_none() && signer.vault.is_none());
        assert!(!signer.is_unlocked());
    }

    #[wasm_bindgen_test]
    fn candidate_check_refuses_terms_it_does_not_match() {
        let cand = hex::decode(CANDIDATE_HEX).unwrap();
        let fvk_bytes: [u8; 96] = hex::decode(FVK_HEX).unwrap().try_into().unwrap();
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes).unwrap();
        let parsed = pczt::Pczt::parse(&cand).unwrap();
        let expiry = *parsed.global().expiry_height();
        let terms = |tx_expiry, notes: Vec<String>| Terms {
            recipient: "not checked first".into(), amount_zat: 1, memo: String::new(), fee_zat: 0, change_zat: 0,
            note_selection: notes, target_height: 1, tx_expiry,
        };
        // A different expiry than the candidate's is refused before anything else.
        let err = check_against_terms(&cand, &terms(expiry + 1, vec!["00".repeat(32)]), VaultNetwork::Regtest, &fvk).unwrap_err();
        assert!(err.contains("network or expiry"), "{err}");
        // So is a branch that is not the one for the approved anchor height.
        let err = check_against_terms(&cand, &terms(expiry, vec!["00".repeat(32)]), VaultNetwork::Testnet, &fvk).unwrap_err();
        assert!(err.contains("network or expiry"), "{err}");
    }

    #[wasm_bindgen_test]
    fn sign_params_come_only_from_valid_approved_terms() {
        let terms = |recipient: &str, amount_zat| Terms {
            recipient: recipient.into(), amount_zat, memo: "m".into(), fee_zat: 0, change_zat: 0,
            note_selection: vec![], target_height: 10, tx_expiry: 20,
        };
        assert!(payment_params(&terms("not an address", 1), VaultNetwork::Testnet).is_err());
        assert!(vault_network(Network::Testnet).is_ok() && vault_network(Network::Regtest).is_ok());
    }

    fn pins_json(a: u8, b: u8) -> String {
        let pin = |n: u8| serde_json::json!({ "key": hex::encode([n; 32]), "run": hex::encode([n + 1; 32]), "mailbox": hex::encode([n + 2; 32]) });
        serde_json::json!([pin(a), pin(b)]).to_string()
    }

    #[wasm_bindgen_test]
    fn signing_is_refused_without_two_nonce_witnesses() {
        let mut signer = Signer::new();
        let err = signer.sign_approve_impl(&"00".repeat(32), "", "", "", "", "{}").unwrap_err();
        assert!(err.contains("nonce witnesses"), "{err}");
        // Two distinct, nonzero witnesses only.
        assert!(parse_witness_pins(&pins_json(1, 1)).is_err(), "the same witness twice");
        assert!(parse_witness_pins(&pins_json(0, 5)).is_err(), "a zero pin");
        assert!(parse_witness_pins("[]").is_err());
        assert!(parse_witness_pins(&pins_json(1, 5)).is_ok());
    }

    #[wasm_bindgen_test]
    fn core_witness_accepts_only_a_claim_both_relays_confirmed_once() {
        let claimed = Arc::new(Mutex::new(Vec::new()));
        let mut witness = ClaimedAhead { pins: parse_witness_pins(&pins_json(1, 5)).unwrap(), claimed: claimed.clone() };
        let record = nonce_claim_record(&[7; 32], &[8; 32], &[9; 32]);
        // Not claimed at the relays (or refused there): the core gets a refusal, so it releases
        // no share and leaves the nonce unburned (core test
        // `nonce_witness_claim_gates_the_share_and_blocks_rolled_back_nonces`).
        assert!(witness.claim([7; 32], &record).is_err());
        claimed.lock().unwrap().push(([7; 32], record.clone()));
        // Other bytes for the same nonce are not the confirmed claim.
        assert!(witness.claim([7; 32], &nonce_claim_record(&[7; 32], &[1; 32], &[9; 32])).is_err());
        assert!(witness.claim([7; 32], &record).is_ok());
        // A second use of the same claim is a duplicate: refused.
        assert!(witness.claim([7; 32], &record).is_err(), "duplicate claim");
    }

    #[wasm_bindgen_test]
    fn prompts_answer_only_what_the_member_confirmed() {
        let approved = Arc::new(Mutex::new(None));
        let mut prompts = browser_prompts("d", &[0u8; 32], [1u8; 32], None, Some("1111 2222".into()), approved.clone());
        assert_eq!((prompts.roster)("1111 2222"), RosterDecision::Match);
        assert_eq!((prompts.roster)("1111 2223"), RosterDecision::NoMatch);
        let mut none = browser_prompts("d", &[0u8; 32], [1u8; 32], None, None, approved.clone());
        assert_eq!((none.roster)("1111 2222"), RosterDecision::Cancelled);

        let cand = CandidateRef { vault_id: [1; 32], payment_id: [2; 32], attempt_id: [2; 32] };
        let view = loki_signer_core::signer::wysiwys::PaymentView {
            to: [0; 43], amount_zat: 1, fee_zat: 1, change_zat: 0, memo: vec![], network_branch_id: 0, fee_verified: true, expiry_height: 0,
        };
        let ask = |sighash| local::ApprovalRequest { candidate: &cand, sighash, view: &view };
        // Nothing confirmed: refuse. Confirmed: approve that sighash once, never another.
        assert!(!(prompts.approval)(&ask([7; 32])));
        *approved.lock().unwrap() = Some([7; 32]);
        assert!(!(prompts.approval)(&ask([8; 32])));
        *approved.lock().unwrap() = Some([7; 32]);
        assert!((prompts.approval)(&ask([7; 32])));
        assert!(!(prompts.approval)(&ask([7; 32])), "one confirmation, one signature");
    }

    #[wasm_bindgen_test]
    fn reauth_needs_the_same_custody_secret() {
        let mut signer = Signer::new();
        signer.kek = Some(custody_kek("platform", None, Some(vec![3u8; 32]), false).unwrap());
        assert!(signer.reauth_check("platform", None, Some(vec![3u8; 32])).is_ok());
        assert!(signer.reauth_check("platform", None, Some(vec![4u8; 32])).is_err());
        assert!(signer.reauth_check("platform", None, None).is_err());
    }

    /// Member 1's backup of a 2-of-3 dealer vault, with its identity and roster.
    fn backup_material() -> BackupMaterial {
        use frost::keys::{generate_with_dealer, IdentifierList, KeyPackage};
        let (shares, public) = generate_with_dealer(3, 2, IdentifierList::Default, &mut rand_core::OsRng).unwrap();
        let ids: Vec<Identity> = (1..=3).map(Identity::new).collect();
        let vault_id = [7u8; 32];
        let roster = serde_json::to_vec(&serde_json::json!({
            "vault": hex::encode(vault_id), "threshold": 2, "setup_version": 2,
            "members": ids.iter().map(|i| serde_json::json!({
                "id": i.public().id,
                "signing": hex::encode(i.public().signing),
                "encryption": hex::encode(i.public().encryption),
            })).collect::<Vec<_>>(),
        }))
        .unwrap();
        let key = KeyPackage::try_from(shares[&frost::Identifier::try_from(1u16).unwrap()].clone()).unwrap();
        BackupMaterial {
            member_id: 1, threshold: 2, members: 3, network: Network::Regtest, vault_id,
            label: "v".into(), group_sk: [42u8; 32],
            key_package: Zeroizing::new(key.serialize().unwrap()),
            public_package: public.serialize().unwrap(),
            backup_epoch: 0,
            identity: Zeroizing::new(ids[0].to_secret_bytes().to_vec()),
            roster_fingerprint: Roster::from_bytes(&roster).unwrap().fingerprint(),
            roster,
            birth_height: None,
        }
    }

    #[wasm_bindgen_test]
    fn dkg_backup_seals_to_the_recovery_words_and_reopens_only_with_them() {
        let material = backup_material();
        let vault_id = material.vault_id;
        let pass = hex::encode([5u8; 32]);
        let local = backup::create(&material, &pass).unwrap();

        let (words, key) = RecoveryKey::generate().unwrap();
        let pubkeys = recovery_public_keys(&key);
        assert_eq!(pubkeys.len(), 64);
        let recovery_pub: [u8; 32] = pubkeys[..32].try_into().unwrap();
        drop(key); // sealing needs only the public key
        let sealed = seal_to_recovery(&local, &pass, &vault_id, &recovery_pub).unwrap();
        assert!(seal_to_recovery(&local, "wrong", &vault_id, &recovery_pub).is_err());

        // A fresh browser: the same words open it for this vault, and nothing else does.
        let back = restored_material(&RecoveryKey::from_words(&words).unwrap(), &sealed.0, &vault_id).unwrap();
        assert_eq!(&*back.key_package, &*material.key_package);
        assert_eq!(back.roster, material.roster);
        let (other, _) = RecoveryKey::generate().unwrap();
        assert!(restored_material(&RecoveryKey::from_words(&other).unwrap(), &sealed.0, &vault_id).is_err());
        assert!(restored_material(&RecoveryKey::from_words(&words).unwrap(), &sealed.0, &[8u8; 32]).is_err());

        // A bare-share backup cannot rebuild a signing member.
        let mut bare = backup_material();
        let bare_id = bare.vault_id;
        (bare.identity, bare.roster, bare.roster_fingerprint) = (Zeroizing::new(Vec::new()), Vec::new(), [0; 32]);
        let bare_local = backup::create(&bare, &pass).unwrap();
        let err = seal_to_recovery(&bare_local, &pass, &bare_id, &recovery_pub).err().unwrap();
        assert!(err.contains("no roster"), "{err}");
    }

    #[wasm_bindgen_test]
    fn backup_without_recovery_words_refuses_before_any_write() {
        // `LocalSigner::backup` signs its receipt only after `save` succeeds, so this refusal
        // is what keeps a member with no independent backup from reporting itself backed up.
        let material = backup_material();
        let pass = hex::encode([5u8; 32]);
        let mut prompts = browser_prompts("d", &[5u8; 32], material.vault_id, None, None, Arc::new(Mutex::new(None)));
        let err = prompts.backup.save(&backup::create(&material, &pass).unwrap()).unwrap_err();
        assert!(err.contains("recovery words"), "{err}");
    }

    #[wasm_bindgen_test]
    fn prf_seal_open_round_trips_and_rejects_wrong_secret() {
        let prf = [7u8; 32];
        let share = b"a FROST signing share worth forging";

        let sealed = seal_impl(&prf, 2, share).unwrap();
        // Same passkey re-derives the KEK and reopens byte-identical.
        assert_eq!(open_impl(&prf, &sealed).unwrap(), share);
        // A different PRF secret cannot open it.
        assert!(open_impl(&[8u8; 32], &sealed).is_err());
        // A short secret is rejected before any crypto.
        assert!(seal_impl(&[0u8; 16], 0, share).is_err());
    }
}
