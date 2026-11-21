//! C-ABI entry points for the native signer app (`core/signer-app/`, LokiSigner.app).
//!
//! The app is provisioned (Apple Team ID + profile), so — unlike a bare CLI — it is
//! allowed to create a PERSISTENT, biometric-capable Secure Enclave key. This selftest
//! runs the real signer sealing path through that key: it seals a stand-in FROST share
//! under a persistent Enclave KEK, drops everything, reopens the SAME Enclave key by tag,
//! and unseals — proving the share is held in the Enclave across "launches".

use crate::signer::secure_element::SealedShare;
use crate::signer::secure_element_apple::AppleSecureElement;

/// Returns 0 on success; small nonzero codes mark which step failed.
#[no_mangle]
pub extern "C" fn loki_signer_enclave_selftest() -> i32 {
    let tag = b"cash.loki.signer.share.v1";

    // Wallet init: open the persistent Enclave KEK and seal the member's share under it.
    let se = match AppleSecureElement::create_persistent(tag, None) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    let share = [0x9u8; 64];
    let sealed = match SealedShare::seal(&se, 0, &share) {
        Ok(s) => s,
        Err(_) => return 2,
    };
    let blob = sealed.to_bytes();
    drop(sealed);
    drop(se);

    // Next launch: reopen the SAME Enclave key by tag and unseal the share.
    let se2 = match AppleSecureElement::open_persistent(tag, None) {
        Ok(s) => s,
        Err(_) => return 3,
    };
    let parsed = match SealedShare::from_bytes(&blob) {
        Ok(s) => s,
        Err(_) => return 4,
    };
    let opened = match parsed.open(&se2) {
        Ok(o) => o,
        Err(_) => return 5,
    };
    if opened.as_slice() == &share[..] {
        0
    } else {
        6
    }
}

/// Full native-member lifecycle: a 2-of-3 vault created by REAL v2 DKG where every share is
/// generated and sealed under its own PERSISTENT, biometric-capable Secure Enclave key, then a
/// quorum signs a payment the prover accepts. This is the ephemeral `cargo test`
/// (`real_enclave_member_runs_dkg_and_signs`) with persistent keys — the share survives restart
/// and `unwrap` is Face-ID-gated. Returns 0 on success.
#[no_mangle]
pub extern "C" fn loki_signer_enclave_dkg_member_selftest() -> i32 {
    let tags: [&[u8]; 3] = [
        b"cash.loki.signer.dkg.m1.v1",
        b"cash.loki.signer.dkg.m2.v1",
        b"cash.loki.signer.dkg.m3.v1",
    ];
    let r = std::panic::catch_unwind(|| {
        crate::signer::native_member::prove_dkg_member(2, 3, |id| {
            AppleSecureElement::create_persistent(tags[(id - 1) as usize], None)
                .expect("open persistent Secure Enclave key")
        })
    });
    match r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("dkg-member selftest failed: {e}");
            1
        }
        Err(_) => {
            eprintln!("dkg-member selftest panicked (persistent Secure Enclave key open?)");
            2
        }
    }
}

/// Run the LIVE member-app signer (the axum coordinator + frostd DKG/payment loop) inside the
/// provisioned app, with the member's FROST share held in the Secure Enclave. This is the real
/// native signer: `LokiSigner serve --data <dir> --port <n> --frostd-url <url> --peer-port <n>
/// --advertise-url <origin> --peer <slot=url>...`. Reads the member args from its argv (skipping the
/// binary name and the `serve` verb), forces the Apple Enclave backend, and serves. Blocks.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub extern "C" fn loki_member_app_serve() -> i32 {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut config = match crate::host::config_from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("serve config: {e}");
            return 2;
        }
    };
    // The whole point of the native signer: the share lives in the Secure Enclave.
    config.secure_element = "apple".into();
    if let Err(e) = config.validate_secure_element().and_then(|_| crate::host::run(config)) {
        eprintln!("serve: {e}");
        return 1;
    }
    0
}

/// The native app's payment dialog: 1 approves, 2 timed out, everything else refuses.
/// The cancellation callback and its context are borrowed for this call only.
pub type NativeApprove = extern "C" fn(
    *const std::ffi::c_char,
    *const std::ffi::c_void,
    extern "C" fn(*const std::ffi::c_void) -> i32,
) -> i32;

fn native_approval(approve: NativeApprove) -> crate::host::LocalApproval {
    use crate::host::{ApprovalAnswer, ApprovalAttempt};
    extern "C" fn cancelled(context: *const std::ffi::c_void) -> i32 {
        i32::from(unsafe { &*context.cast::<ApprovalAttempt>() }.cancellation_code())
    }
    std::sync::Arc::new(move |summary, attempt| {
        match std::ffi::CString::new(summary).map(|summary| {
            approve(summary.as_ptr(), std::ptr::from_ref(attempt).cast(), cancelled)
        }) {
            Ok(1) => ApprovalAnswer::Approve,
            Ok(2) => ApprovalAnswer::Timeout,
            _ => ApprovalAnswer::Refuse,
        }
    })
}

#[cfg(feature = "relay-communication")]
pub type NativeConnect = extern "C" fn(
    *const std::ffi::c_char,
    *const std::ffi::c_char,
    *const std::ffi::c_void,
    extern "C" fn(*const std::ffi::c_void) -> i32,
) -> i32;

#[cfg(feature = "relay-communication")]
fn native_connect(ask: NativeConnect) -> crate::host::LocalConnect {
    extern "C" fn cancelled(context: *const std::ffi::c_void) -> i32 {
        // The attempt is borrowed for the whole synchronous call to Swift below.
        i32::from(unsafe { &*context.cast::<crate::host::ConnectAttempt>() }.cancelled())
    }
    std::sync::Arc::new(move |origin, code, attempt| {
        let (Ok(origin), Ok(code)) = (std::ffi::CString::new(origin), std::ffi::CString::new(code)) else { return false; };
        ask(origin.as_ptr(), code.as_ptr(), std::ptr::from_ref(attempt).cast(), cancelled) == 1
    })
}

/// Revoke every tab's grant without locking the local profile or stopping the app.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub extern "C" fn loki_member_app_disconnect_wallet_tabs() {
    crate::host::disconnect_wallet_tabs();
}

/// Native payment-approval selftest: a 2-of-3 vault created by real v2 DKG signs one payment,
/// and each quorum member's `sign_approve` asks the app's dialog through `approve`, exactly as
/// the live member does. Shares use the software element, so it runs without enrolled
/// biometrics. Returns 0 when signed, 3 when the member refused.
#[no_mangle]
pub extern "C" fn loki_signer_approval_selftest(approve: NativeApprove) -> i32 {
    use crate::host::{ApprovalAnswer, ApprovalAttempt, ApprovalEnd, LocalApproval};
    use std::{sync::Arc, time::Duration};
    let r = std::panic::catch_unwind(|| {
        let ask = native_approval(approve);
        let ask: LocalApproval = if std::env::args().any(|arg| arg == "--cancel-approval") {
            Arc::new(move |summary, attempt| {
                // This presentation-only fixture can never approve the underlying test payment.
                let mut summary: serde_json::Value = serde_json::from_str(summary).unwrap();
                summary["memo"] = "Rent for November\nRecipient: imitation\nAmount: 0.00000001 ZEC\u{202e}".into();
                std::thread::scope(|scope| {
                    let cancel = scope.spawn(|| {
                        std::thread::sleep(Duration::from_secs(10));
                        attempt.end(ApprovalEnd::Failed);
                    });
                    ask(&summary.to_string(), attempt);
                    cancel.join().unwrap();
                });
                // Leave the closed-request notice on screen briefly in the self-test.
                std::thread::sleep(Duration::from_secs(4));
                ApprovalAnswer::Refuse
            })
        } else {
            ask
        };
        crate::signer::native_member::prove_dkg_member_with(
            2,
            3,
            |_| crate::signer::secure_element::SoftwareSecureElement::generate(),
            |slot| Some(crate::host::approval_policy(Some(ask.clone()), crate::signer::Network::Regtest, slot,
                Some(Arc::new(ApprovalAttempt::named("Native vault".into()))))),
        )
    });
    match r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) if e.contains("member refused") => {
            eprintln!("approval selftest: the member refused; nothing was signed");
            3
        }
        Ok(Err(e)) => {
            eprintln!("approval selftest failed: {e}");
            1
        }
        Err(_) => 2,
    }
}

#[cfg(test)]
#[test]
fn native_approval_does_not_sign_after_cancellation() {
    use std::ffi::{c_char, c_void};
    use std::sync::atomic::{AtomicBool, Ordering};
    static SAW_END: AtomicBool = AtomicBool::new(false);
    extern "C" fn late(_: *const c_char, context: *const c_void, cancelled: extern "C" fn(*const c_void) -> i32) -> i32 {
        if cancelled(context) != 0 { return -1; }
        unsafe { &*context.cast::<crate::host::ApprovalAttempt>() }.end(crate::host::ApprovalEnd::Failed);
        // Simulate the member clicking just as the attempt ends, before Swift can close.
        SAW_END.store(cancelled(context) == 1, Ordering::Relaxed);
        1
    }
    assert_eq!(loki_signer_approval_selftest(late), 3);
    assert!(SAW_END.load(Ordering::Relaxed));
}

/// The native app's roster dialog: receives the roster summary JSON `/api/agree` derived and
/// returns 1 when the member chose "Codes match" and 2 when they chose "Codes differ".
/// Anything else (closed, timed out, unreadable) is no answer, and nothing is recorded.
pub type NativeConfirmRoster = extern "C" fn(*const std::ffi::c_char) -> i32;

#[cfg(feature = "relay-communication")]
fn native_roster_confirmation(confirm: NativeConfirmRoster) -> crate::host::LocalRosterConfirmation {
    std::sync::Arc::new(move |summary| {
        match std::ffi::CString::new(summary).map(|summary| confirm(summary.as_ptr())) {
            Ok(1) => crate::host::RosterAnswer::Match,
            Ok(2) => crate::host::RosterAnswer::Differ,
            _ => crate::host::RosterAnswer::NoAnswer,
        }
    })
}

#[cfg(feature = "relay-communication")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeLaunch { args: Vec<String>, pairing_url: Option<String>, restore_origin: Option<String> }

/// Answers one native query on `launch` (`{"args": [...], "pairing_url": "loki://pair?..."?}`)
/// as a JSON string, freed by [`loki_member_app_free`].
#[cfg(feature = "relay-communication")]
unsafe fn native_query(
    launch: *const std::ffi::c_char,
    query: impl FnOnce(NativeLaunch) -> Result<serde_json::Value, String>,
) -> *mut std::ffi::c_char {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if launch.is_null() { return Err("missing native launch".to_string()); }
        let launch = std::ffi::CStr::from_ptr(launch).to_str().map_err(|_| "invalid native launch")?;
        query(serde_json::from_str(launch).map_err(|_| "invalid native launch")?)
    }));
    let reply = match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => serde_json::json!({ "error": error }),
        Err(_) => serde_json::json!({ "error": "reading the signer configuration stopped unexpectedly" }),
    };
    std::ffi::CString::new(reply.to_string()).map_or(std::ptr::null_mut(), std::ffi::CString::into_raw)
}

/// Inspect this Mac's local profile. `action`: 0 inspect, 1 try to clean restore staging then
/// inspect at startup, 2 set aside a stopped, vault-free profile then inspect, 3 recover
/// after a positively missing or invalidated local key (may set aside a vault).
///
/// # Safety
/// `launch` must be a live NUL-terminated UTF-8 launch JSON string for this call.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_profile(launch: *const std::ffi::c_char, action: u32) -> *mut std::ffi::c_char {
    native_query(launch, |launch| {
        let config = crate::host::config_from_args(&launch.args)?;
        let data = config.data;
        match action {
            0 => {},
            1 => crate::host::native_clean_staging(&data),
            2 | 3 => crate::host::native_set_aside(&data, action == 3)?,
            _ => return Err("unknown profile action".into()),
        }
        let mut reply = serde_json::json!({ "profile": crate::host::native_profile_state(&data)? });
        if let Ok(paired) = crate::host::RegistrationConfig::resume(&data, config.development_http) {
            reply["slot"] = serde_json::json!(paired.slot);
            // Local only: binds a pending invite link to the pinned coordinator while locked.
            reply["coordinator"] = serde_json::json!(paired.coordinator);
        }
        Ok(reply)
    })
}

#[cfg(feature = "relay-communication")]
#[no_mangle]
pub extern "C" fn loki_member_app_stop() -> i32 {
    i32::from(crate::host::native_request_stop())
}

/// Install the native app's in-process sink for fixed diagnostic events only. The sink must
/// be callable on any thread for the lifetime of the app; its string is borrowed per call.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub extern "C" fn loki_member_app_set_log_sink(sink: extern "C" fn(*const std::ffi::c_char)) {
    crate::host::native_set_log_sink(sink);
}

/// Native status is local only. Call from a worker and free the JSON with `loki_member_app_free`.
/// # Safety
/// `launch` must be a live NUL-terminated UTF-8 launch JSON string for this call.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_status(launch: *const std::ffi::c_char) -> *mut std::ffi::c_char {
    native_query(launch, |launch| {
        let config = crate::host::native_config_from_args(&launch.args)?;
        Ok(serde_json::json!({ "status": crate::host::native_status(&config.data, config.development_http) }))
    })
}

/// The coordinator origin and slot a pairing link names, checked without any network request.
/// LokiSigner asks the member to confirm them before it contacts that coordinator. Returns
/// `{"target": {"coordinator": "...", "slot": n}}` or `{"error": "..."}`; free it with
/// [`loki_member_app_free`]. An already pinned origin or slot mismatch returns `different-pairing`.
///
/// # Safety
/// `launch` must be a live NUL-terminated UTF-8 string for this call.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_pairing_target(launch: *const std::ffi::c_char) -> *mut std::ffi::c_char {
    native_query(launch, |launch| {
        if let (None, Some(origin)) = (&launch.pairing_url, &launch.restore_origin) {
            let coordinator = crate::host::NativeConfig::recovery_origin(&launch.args, origin)
                .map_err(|_| "Enter the original coordinator’s HTTPS origin.")?;
            return Ok(serde_json::json!({ "target": { "coordinator": coordinator } }));
        }
        let link = launch.pairing_url.ok_or("missing pairing link")?;
        let (coordinator, slot) = crate::host::NativeConfig::pairing_target(&launch.args, &link)?;
        Ok(serde_json::json!({ "target": { "coordinator": coordinator, "slot": slot } }))
    })
}

/// Execute an allowlisted wallet request. `export` permits only the native backup save path.
///
/// # Safety
/// `path` and non-null `body` are live NUL-terminated UTF-8 strings; free the reply with
/// [`loki_member_app_free`]. Call from a native worker thread, not AppKit's main thread.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_wallet_request(path: *const std::ffi::c_char, body: *const std::ffi::c_char, export: i32) -> *mut std::ffi::c_char {
    let result = std::panic::catch_unwind(|| {
        let invalid = || serde_json::json!({ "status": 400, "data": { "error": "invalid wallet request" } });
        if path.is_null() { return invalid(); }
        let Ok(path) = std::ffi::CStr::from_ptr(path).to_str() else { return invalid(); };
        let body = if body.is_null() { None } else {
            let Ok(value) = serde_json::from_slice(std::ffi::CStr::from_ptr(body).to_bytes()) else { return invalid(); };
            Some(value)
        };
        crate::host::native_wallet_request(path, body, export == 1)
    });
    let reply = result.unwrap_or_else(|_| serde_json::json!({ "status": 500, "data": { "error": "wallet request failed" } }));
    std::ffi::CString::new(reply.to_string()).map_or(std::ptr::null_mut(), std::ffi::CString::into_raw)
}

/// The configuration a native launch would run with, for the member to review before pairing
/// or unlocking. For a pairing link, call it only after the member confirmed the link's
/// coordinator ([`loki_member_app_pairing_target`]): it asks that coordinator. Returns
/// `{"config": <NativeConfig>}` or `{"error": "..."}`; pass the config back unchanged to
/// [`loki_member_app_pair`]. Free the result with [`loki_member_app_free`].
///
/// # Safety
/// `launch` must be a live NUL-terminated UTF-8 string for this call.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_configuration(launch: *const std::ffi::c_char) -> *mut std::ffi::c_char {
    native_query(launch, |launch| {
        let config = match (&launch.pairing_url, &launch.restore_origin) {
            (None, Some(origin)) => crate::host::NativeConfig::preview_restore(&launch.args, origin)
                .map_err(|_| "LokiSigner could not read a valid configuration from the original coordinator.")?,
            _ => crate::host::NativeConfig::preview(&launch.args, launch.pairing_url.as_deref())?,
        };
        Ok(serde_json::json!({ "config": config }))
    })
}

/// Lists active vault receive addresses for the running native member, as `{"vaults": [...]}`
/// or `{"error": "..."}`. Call off the main thread: opening a signer may prompt for Touch ID.
/// Free the result (which may be null) with [`loki_member_app_free`].
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub extern "C" fn loki_member_app_vault_addresses() -> *mut std::ffi::c_char {
    let reply = match std::panic::catch_unwind(crate::host::native_vault_addresses) {
        Ok(Ok(vaults)) => serde_json::json!({ "vaults": vaults }),
        Ok(Err(error)) => serde_json::json!({ "error": error }),
        Err(_) => serde_json::json!({ "error": "LokiSigner could not list vaults." }),
    };
    std::ffi::CString::new(reply.to_string()).map_or(std::ptr::null_mut(), std::ffi::CString::into_raw)
}

#[cfg(feature = "relay-communication")]
#[no_mangle]
pub extern "C" fn loki_member_app_can_view_addresses() -> i32 {
    i32::from(crate::host::native_can_view_addresses())
}

/// Frees a string returned by one of the LokiSigner JSON entry points.
///
/// # Safety
/// `value` must be null or a pointer one of those functions returned, freed only once.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_free(value: *mut std::ffi::c_char) {
    if !value.is_null() { drop(std::ffi::CString::from_raw(value)); }
}

#[cfg(feature = "relay-communication")]
unsafe fn take_restore_secret(ptr: *mut u8, len: usize) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
    let error = crate::host::NATIVE_RESTORE_REFUSED;
    if ptr.is_null() { return Err(error); }
    let raw = std::slice::from_raw_parts_mut(ptr, len);
    let copy = (len <= 4096).then(|| zeroize::Zeroizing::new(raw.to_vec()));
    zeroize::Zeroize::zeroize(raw);
    copy.filter(|copy| !copy.is_empty()).ok_or(error)
}

#[cfg(feature = "relay-communication")]
const RESTORED_BUT_STOPPED: &str = "restored-but-stopped";

#[cfg(feature = "relay-communication")]
fn restore_reply(result: Result<(), &'static str>) -> *mut std::ffi::c_char {
    let reply = match result {
        Ok(()) => serde_json::json!({ "restored": true }),
        Err(error) if crate::signer::secure_element_apple::member_key_message(error).is_some() =>
            serde_json::json!({ "error": "key-error", "key_error": error }),
        Err(error) => serde_json::json!({ "error": error }),
    };
    std::ffi::CString::new(reply.to_string()).map_or(std::ptr::null_mut(), std::ffi::CString::into_raw)
}

/// Restore another vault through the running LokiSigner. Call from a worker and free the
/// JSON reply with [`loki_member_app_free`].
///
/// # Safety
/// `file` and `fingerprint` must be null or live NUL-terminated strings. `words` must be null or a writable
/// buffer of `len` bytes (not NUL-terminated); all `len` bytes are cleared.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_restore_vault(words: *mut u8, len: usize, file: *const std::ffi::c_char, fingerprint: *const std::ffi::c_char) -> *mut std::ffi::c_char {
    let error = crate::host::NATIVE_RESTORE_REFUSED;
    let result = std::panic::catch_unwind(|| {
        let words = take_restore_secret(words, len)?;
        if file.is_null() || fingerprint.is_null() { return Err(error); }
        let file = std::ffi::CStr::from_ptr(file).to_str().map_err(|_| error)?;
        let fingerprint = std::ffi::CStr::from_ptr(fingerprint).to_str().map_err(|_| error)?;
        crate::host::native_restore_running(words, std::path::Path::new(file), fingerprint)
    });
    restore_reply(result.unwrap_or(Err(error)))
}

/// Restore the first vault and run the native member. Like pairing, success continues into
/// the member loop; a refusal returns JSON, freed with [`loki_member_app_free`].
///
/// # Safety
/// `launch`, `file` and `fingerprint` must be null or live NUL-terminated UTF-8 strings. `words` and `pass`
/// must be null or disjoint writable buffers of the given lengths and are cleared. `notify`
/// and the decision callbacks follow the lifetime contract of [`loki_member_app_pair`].
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_restore_profile(
    launch: *const std::ffi::c_char,
    words: *mut u8, words_len: usize,
    pass: *mut u8, pass_len: usize,
    file: *const std::ffi::c_char,
    fingerprint: *const std::ffi::c_char,
    notify: NativeNotice,
    approve: NativeApprove,
    confirm_roster: NativeConfirmRoster,
    connect: NativeConnect,
) -> *mut std::ffi::c_char {
    let error = crate::host::NATIVE_RESTORE_REFUSED;
    let mut published = false;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let words = take_restore_secret(words, words_len);
        let pass = take_restore_secret(pass, pass_len);
        let words = words?;
        let pass = {
            let bytes = pass?;
            let text = std::str::from_utf8(&bytes).map_err(|_| error)?;
            if text.contains('\0') { return Err(error); }
            zeroize::Zeroizing::new(text.to_owned())
        };
        if launch.is_null() || file.is_null() || fingerprint.is_null() { return Err(error); }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Launch {
            args: Vec<String>, restore_origin: String, config: crate::host::NativeConfig,
            witness_confirmation: Option<String>,
            #[serde(default)] embedded: bool,
        }
        let launch: Launch = serde_json::from_slice(std::ffi::CStr::from_ptr(launch).to_bytes()).map_err(|_| error)?;
        let file = std::ffi::CStr::from_ptr(file).to_str().map_err(|_| error)?;
        let fingerprint = std::ffi::CStr::from_ptr(fingerprint).to_str().map_err(|_| error)?;
        let mut config = crate::host::native_config_from_args(&launch.args).map_err(|_| error)?;
        launch.config.verify_witness_confirmation(launch.witness_confirmation.as_deref()).map_err(|_| error)?;
        let fetched = launch.config.apply_restore(&mut config, &launch.args, &launch.restore_origin).map_err(|_| error)?;
        if launch.embedded { crate::host::NativeConfig::validate_wallet(&config).map_err(|_| error)?; }
        crate::host::native_restore_new(&mut config, &pass, words, std::path::Path::new(file), fingerprint, &launch.restore_origin, fetched.as_ref())?;
        published = true;
        let notice = native_notice(notify);
        crate::host::run_native(config, pass, notice, native_approval(approve),
            native_roster_confirmation(confirm_roster), (!launch.embedded).then(|| native_connect(connect)), fetched)
            .map_err(|e| crate::signer::secure_element_apple::member_key_message(&e).unwrap_or(RESTORED_BUT_STOPPED))
    }));
    restore_reply(result.unwrap_or(Err(if published { RESTORED_BUT_STOPPED } else { error })))
}

#[cfg(feature = "relay-communication")]
type NativeNotice = extern "C" fn(*const std::ffi::c_char, *const std::ffi::c_char) -> i32;

#[cfg(feature = "relay-communication")]
fn native_notice(notify: NativeNotice) -> crate::host::LocalNotice {
    std::sync::Arc::new(move |kind, message| {
        match (std::ffi::CString::new(kind), std::ffi::CString::new(message)) {
            (Ok(kind), Ok(message)) => notify(kind.as_ptr(), message.as_ptr()) == 1,
            _ => false,
        }
    })
}

/// Native UI entry point. Unlock material crosses only this in-process ABI, never HTTP,
/// argv, a file or stdout. `launch` is the launch given to [`loki_member_app_configuration`]
/// plus `"config"`, the configuration it returned and the member reviewed. `notify` presents
/// recovery words and startup notices, returning 1 only after the member has saved the words;
/// `approve` asks the member to approve each
/// payment before this device signs it; `confirm_roster` asks the member to compare a vault's
/// roster code before this device agrees to it; `connect` asks about a single wallet tab.
///
/// # Safety
/// `launch` and `pass` must be live NUL-terminated UTF-8 strings for this call. `pass`
/// must be writable: its bytes are zeroed immediately after copying into Rust. Callbacks must
/// remain callable until the member stops. Strings and the connect cancellation context are
/// borrowed only for their callback; never use them after it returns.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_pair(
    launch: *const std::ffi::c_char,
    pass: *mut std::ffi::c_char,
    notify: NativeNotice,
    approve: NativeApprove,
    confirm_roster: NativeConfirmRoster,
    connect: NativeConnect,
) -> i32 {
    let notice = native_notice(notify);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
        if launch.is_null() || pass.is_null() { return Err("missing native launch or unlock".into()); }
        let raw = std::ffi::CStr::from_ptr(pass).to_bytes();
        let secret = std::str::from_utf8(raw).map(|s| zeroize::Zeroizing::new(s.to_owned()));
        zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(pass, raw.len()));
        let pass = secret.map_err(|e| e.to_string())?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Launch {
            args: Vec<String>,
            pairing_url: Option<String>,
            profile_name: Option<String>,
            config: crate::host::NativeConfig,
            witness_confirmation: Option<String>,
            #[serde(default)] embedded: bool,
        }
        let launch: Launch = serde_json::from_str(std::ffi::CStr::from_ptr(launch).to_str().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let mut config = crate::host::native_config_from_args(&launch.args)?;
        if config.registration.is_some() { return Err("native pairing accepts registration only through its pairing link".into()); }
        config.validate_secure_element()?;
        // The values the member reviewed, checked again; never fetched a second time. A fetched
        // configuration is saved only after the profile unlocks.
        launch.config.verify_witness_confirmation(launch.witness_confirmation.as_deref())?;
        let fetched = launch.config.apply(&mut config, &launch.args, launch.pairing_url.as_deref())?;
        if launch.embedded { crate::host::NativeConfig::validate_wallet(&config)?; }
        let registration = match launch.pairing_url {
            Some(link) => {
                let mut registration = crate::host::RegistrationConfig::pairing(&link, config.development_http)?;
                if let Some(name) = launch.profile_name { registration.name = name; }
                registration
            }
            None => crate::host::RegistrationConfig::resume(&config.data, config.development_http)?,
        };
        config.registration = Some(registration);
        crate::host::run_native(config, pass, notice.clone(), native_approval(approve),
            native_roster_confirmation(confirm_roster), (!launch.embedded).then(|| native_connect(connect)), fetched)
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => match e.as_str() {
            "unlock" => 3,
            "device-key" => 4,
            "registration-refused" => 5,
            "registration-failed" => 6,
            text if crate::signer::secure_element_apple::member_key_message(text).is_some() => {
                use crate::signer::secure_element_apple::KeyFailure;
                notice(if text == KeyFailure::Missing.message() { "startup-key-gone" } else { "startup-key" }, text);
                7
            },
            "coordinator-roster-unreachable" => 8,
            "invalid-profile-name" => 9,
            "recovery-not-confirmed" => 10,
            _ => 1,
        },
        Err(_) => 2,
    }
}

#[cfg(all(test, feature = "relay-communication"))]
mod native_pairing_tests {
    extern "C" fn refuse_approval(_: *const std::ffi::c_char, _: *const std::ffi::c_void,
        _: extern "C" fn(*const std::ffi::c_void) -> i32) -> i32 { 0 }
    extern "C" fn refuse_connect(_: *const std::ffi::c_char, _: *const std::ffi::c_char,
        _: *const std::ffi::c_void, _: extern "C" fn(*const std::ffi::c_void) -> i32) -> i32 { 0 }

    #[test]
    fn native_restore_wipes_both_buffers_even_when_the_request_is_refused() {
        let mut words = b"not-valid-words\0never-echo-this".to_vec();
        let mut pass = b"not-valid-passphrase".to_vec();
        extern "C" fn notice(_: *const std::ffi::c_char, _: *const std::ffi::c_char) -> i32 { 0 }
        extern "C" fn refuse(_: *const std::ffi::c_char) -> i32 { 0 }
        let reply = unsafe { super::loki_member_app_restore_profile(std::ptr::null(),
            words.as_mut_ptr(), words.len(), pass.as_mut_ptr(), pass.len(), std::ptr::null(), std::ptr::null(), notice, refuse_approval, refuse, refuse_connect) };
        assert!(words.iter().chain(&pass).all(|&b| b == 0));
        let error: serde_json::Value = serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(reply) }.to_bytes()).unwrap();
        unsafe { super::loki_member_app_free(reply); }
        assert_eq!(error, serde_json::json!({"error": "restore-refused"}));

        let mut words = [b'X'; 4097];
        let reply = unsafe { super::loki_member_app_restore_vault(words.as_mut_ptr(), words.len(), std::ptr::null(), std::ptr::null()) };
        assert!(words.iter().all(|&b| b == 0));
        let refused: serde_json::Value = serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(reply) }.to_bytes()).unwrap();
        unsafe { super::loki_member_app_free(reply); }
        assert_eq!(refused, error);
    }

    #[test]
    fn native_restore_replies_distinguish_key_errors_from_saved_but_stopped() {
        use crate::signer::secure_element_apple::KeyFailure;
        use serde_json::{json, Value};
        let key_message = KeyFailure::Cancelled.message();
        for (error, expected) in [
            (key_message, json!({"error": "key-error", "key_error": key_message})),
            (super::RESTORED_BUT_STOPPED, json!({"error": "restored-but-stopped"})),
        ] {
            let reply = super::restore_reply(Err(error));
            let result: Value = serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(reply) }.to_bytes()).unwrap();
            unsafe { super::loki_member_app_free(reply); }
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn native_unlock_buffer_is_wiped_before_startup() {
        extern "C" fn notice(_: *const std::ffi::c_char, _: *const std::ffi::c_char) -> i32 { 0 }
        let launch = std::ffi::CString::new(r#"{"args":[]}"#).unwrap();
        extern "C" fn refuse(_: *const std::ffi::c_char) -> i32 { 0 }
        let mut pass = b"native passphrase\0".to_vec();
        let code = unsafe { super::loki_member_app_pair(launch.as_ptr(), pass.as_mut_ptr().cast(), notice, refuse_approval, refuse, refuse_connect) };
        assert_eq!(code, 1); // Invalid config fails before any Enclave operation.
        assert!(pass.iter().all(|b| *b == 0));
    }

    #[test]
    fn native_notice_requires_the_explicit_confirmation_reply() {
        use std::ffi::{c_char, CStr};
        extern "C" fn reply(kind: *const c_char, text: *const c_char) -> i32 {
            if unsafe { CStr::from_ptr(kind) }.to_bytes() != b"recovery" { return 0; }
            unsafe { CStr::from_ptr(text) }.to_str().unwrap().parse().unwrap()
        }
        let notice = super::native_notice(reply);
        assert!(notice("recovery", "1"));
        for other in ["0", "-1", "1000"] { assert!(!notice("recovery", other)); }
        assert!(!notice("pairing-claim-attempted", "1"));
    }

    #[test]
    fn a_launch_with_nothing_saved_reports_what_is_missing_instead_of_regtest_defaults() {
        let data = std::env::temp_dir().join(format!("loki-native-launch-{}", uuid::Uuid::new_v4()));
        let launch = serde_json::json!({ "args": ["--data", data, "--port", "0"] }).to_string();
        let launch = std::ffi::CString::new(launch).unwrap();
        let reply = unsafe { super::loki_member_app_configuration(launch.as_ptr()) };
        let text = unsafe { std::ffi::CStr::from_ptr(reply) }.to_str().unwrap().to_owned();
        unsafe { super::loki_member_app_free(reply) };
        let error = serde_json::from_str::<serde_json::Value>(&text).unwrap()["error"].as_str().unwrap().to_owned();
        assert!(error.contains("network, frostd URL, lightwalletd URL, nonce witnesses"), "{error}");
    }

    fn query(f: unsafe extern "C" fn(*const std::ffi::c_char) -> *mut std::ffi::c_char, launch: serde_json::Value) -> serde_json::Value {
        let launch = std::ffi::CString::new(launch.to_string()).unwrap();
        let reply = unsafe { f(launch.as_ptr()) };
        let value = serde_json::from_str(unsafe { std::ffi::CStr::from_ptr(reply) }.to_str().unwrap()).unwrap();
        unsafe { super::loki_member_app_free(reply) };
        value
    }

    /// Only the dialog's "Codes match" (1) agrees and only "Codes differ" (2) refuses the vault;
    /// any other value is no answer. The dialog receives the summary unchanged.
    #[test]
    fn the_roster_dialog_answers_map_to_match_differ_or_no_answer() {
        use crate::host::RosterAnswer;
        extern "C" fn answer(summary: *const std::ffi::c_char) -> i32 {
            let summary = unsafe { std::ffi::CStr::from_ptr(summary) }.to_str().unwrap();
            serde_json::from_str::<serde_json::Value>(summary).unwrap()["answer"].as_i64().unwrap() as i32
        }
        let confirm = super::native_roster_confirmation(answer);
        let ask = |value: i64| confirm(&serde_json::json!({ "answer": value }).to_string());
        assert_eq!(ask(1), RosterAnswer::Match);
        assert_eq!(ask(2), RosterAnswer::Differ);
        for other in [0, 3, -1, 257] {
            assert_eq!(ask(other), RosterAnswer::NoAnswer, "{other}");
        }
    }

    /// The member confirms the link's coordinator before LokiSigner contacts it: the target
    /// is read from the link alone (this origin is unreachable) and in its canonical form.
    #[test]
    fn a_pairing_target_is_checked_without_contacting_the_coordinator() {
        let data = std::env::temp_dir().join(format!("loki-native-target-{}", uuid::Uuid::new_v4()));
        let args = serde_json::json!(["--data", data, "--port", "0"]);
        let link = format!("loki://pair?origin=https%3A%2F%2F127.0.0.1%3A1&slot=7&challenge={}", "ab".repeat(32));
        let reply = query(super::loki_member_app_pairing_target, serde_json::json!({ "args": args, "pairing_url": link }));
        assert_eq!(reply, serde_json::json!({ "target": { "coordinator": "https://127.0.0.1:1", "slot": 7 } }));
        let hostile = link.replace("https%3A%2F%2F127.0.0.1%3A1", "https%3A%2F%2Fwallet.example%0AType%20your%20recovery%20words");
        let reply = query(super::loki_member_app_pairing_target, serde_json::json!({ "args": args, "pairing_url": hostile }));
        let error = reply["error"].as_str().unwrap();
        assert!(!error.contains("recovery"), "{error}");
        assert!(!data.exists());
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("paired-coordinator.json"), r#"{"origin":"https://127.0.0.1:1","slot":7}"#).unwrap();
        let wrong_slot = link.replace("slot=7", "slot=8");
        let reply = query(super::loki_member_app_pairing_target, serde_json::json!({ "args": args, "pairing_url": wrong_slot }));
        assert_eq!(reply, serde_json::json!({ "error": "different-pairing" }));
        std::fs::remove_dir_all(data).unwrap();
    }
}
