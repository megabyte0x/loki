//! In-process queries from LokiSigner, never from the loopback router.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use axum::{body::{to_bytes, Body}, http::{header, Method, Request, StatusCode}, Router};
use serde_json::{json, Value};
use tonic::codegen::Service;
use zeroize::Zeroizing;

use crate::network::VaultNetwork;
use super::{ceremony, custody::{is_legacy, SignerViewingKey}, state::Shared, ApprovalAnswer, ApprovalEnd, Config, FetchedConfig, LocalApproval, LocalNotice, LocalRosterConfirmation, vault_label};

const LOCKED: &str = "Unlock LokiSigner to view vault addresses.";
const LIST_ERROR: &str = "LokiSigner could not list vaults.";
const VAULT_ERROR: &str = "LokiSigner could not verify this vault’s receive address.";
const UPGRADE_VAULT: &str = "Open this vault in the wallet once to upgrade it.";

struct NativeMember {
    state: Shared,
    viewing_keys: Mutex<BTreeMap<(String, u16), (SignerViewingKey, VaultNetwork)>>,
    runtime: Option<tokio::runtime::Handle>,
    router: Router,
    notice: Option<LocalNotice>,
}

static RUNNING: Mutex<Option<Arc<NativeMember>>> = Mutex::new(None);
#[cfg(test)]
pub(super) static TEST_MEMBER: Mutex<()> = Mutex::new(());
// The UI may request recovery, but only a local key failure for this launch grants it.
static KEY_RECOVERY: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

struct NativeScope;

impl NativeScope {
    fn install(state: &Shared, notice: Option<LocalNotice>) -> Result<Self, String> {
        let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        if running.is_some() {
            return Err("LokiSigner is already running.".into());
        }
        KEY_RECOVERY.lock().map_err(|_| "LokiSigner could not access profile recovery.")?.take();
        *running = Some(Arc::new(NativeMember { state: state.clone(), viewing_keys: Mutex::default(),
            runtime: tokio::runtime::Handle::try_current().ok(),
            router: super::routes::router(state.clone()),
            notice,
        }));
        Ok(Self)
    }
}

impl Drop for NativeScope {
    fn drop(&mut self) {
        RUNNING.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

pub(crate) fn run_native(
    config: Config,
    pass: Zeroizing<String>,
    notice: LocalNotice,
    approval: LocalApproval,
    roster_confirmation: LocalRosterConfirmation,
    connect: Option<super::connect::LocalConnect>,
    fetched: Option<FetchedConfig>,
) -> Result<(), String> {
    struct ClearCache;
    impl Drop for ClearCache {
        fn drop(&mut self) { crate::seal_kdf::clear_session_cache(); }
    }
    let _cache = ClearCache;
    let stop = tokio::sync::watch::Sender::new(false);
    let payment_stop = stop.clone();
    let approval: LocalApproval = Arc::new(move |summary, attempt| {
        let mut answer = ApprovalAnswer::Refuse;
        if !*payment_stop.borrow() { answer = approval(summary, attempt); }
        if *payment_stop.borrow() {
            attempt.end(ApprovalEnd::Failed);
            answer = ApprovalAnswer::Refuse;
        }
        emit(if matches!(answer, ApprovalAnswer::Approve) && attempt.ended().is_none() {
            Event::PaymentApproved
        } else {
            Event::PaymentRefused
        });
        answer
    });
    let roster_stop = stop.clone();
    let roster_confirmation: LocalRosterConfirmation = Arc::new(move |summary| {
        if *roster_stop.borrow() { return super::RosterAnswer::NoAnswer; }
        let answer = roster_confirmation(summary);
        if *roster_stop.borrow() { super::RosterAnswer::NoAnswer } else { answer }
    });
    super::run_local_with(config, Some(pass), Some(notice.clone()), Some(approval), Some(roster_confirmation),
        fetched, false, Some(stop), connect, |state| NativeScope::install(state, Some(notice)))
}

pub(crate) fn request_stop() -> bool {
    RUNNING.lock().is_ok_and(|running| running.as_ref().is_some_and(|member| {
        member.state.stopping.send_replace(true);
        if let Some(tabs) = &member.state.wallet_tabs { tabs.close(); }
        true
    }))
}

pub(super) fn clear_addresses_on_lock(state: &Shared) {
    let member = RUNNING.lock().ok().and_then(|running| {
        running.as_ref().filter(|member| Arc::ptr_eq(&member.state, state)).cloned()
    });
    if let Some(member) = member {
        member.viewing_keys.lock().unwrap_or_else(|e| e.into_inner()).clear();
        if let Some(notice) = &member.notice { notice("locked", ""); }
    }
}

/// A main-thread check before displaying or copying a result. Never wait for a session writer.
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) fn can_view_addresses() -> bool {
    RUNNING.lock().is_ok_and(|running| running.as_ref().is_some_and(|member| {
        !member.state.is_stopping()
            && member.state.session.try_read().is_ok_and(|session| session.is_some())
    }))
}

pub(super) fn check_signing(state: &Shared, poll_control: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    let locked = || "LokiSigner is locked".to_owned();
    if !RUNNING.lock().is_ok_and(|running| running.as_ref().is_some_and(|member| Arc::ptr_eq(&member.state, state))) {
        return Err(locked());
    }
    let check_unlocked = || {
        let has_session = state.session.blocking_read().is_some();
        if !has_session || state.is_stopping() { Err(locked()) } else { Ok(()) }
    };
    check_unlocked()?;
    poll_control()?;
    // The final call before the share is sent must catch a lock during the relay poll.
    check_unlocked()
}

#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(super) fn authorize_key_recovery(data: &Path) {
    if let Ok(running) = RUNNING.lock() {
        if running.as_ref().is_some_and(|member| member.state.config.data == data) {
            if let Ok(mut recovery) = KEY_RECOVERY.lock() { *recovery = Some(data.to_owned()); }
        }
    }
}

#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(super) fn report_vault_key_gone(data: &Path) {
    let notice = RUNNING.lock().ok().and_then(|running| {
        let member = running.as_ref().filter(|member| member.state.config.data == data)?;
        let mut recovery = KEY_RECOVERY.lock().ok()?;
        if recovery.as_deref() == Some(data) { return None; }
        *recovery = Some(data.to_owned());
        member.notice.clone()
    });
    if let Some(notice) = notice {
        use crate::signer::secure_element_apple::KeyFailure;
        notice("registration-key-gone", KeyFailure::Missing.message());
    }
}

pub(crate) fn set_aside(data: &Path, recover: bool) -> Result<(), &'static str> {
    let running = RUNNING.lock().map_err(|_| super::native_recovery::REFUSED)?;
    if running.is_some() { return Err(super::native_recovery::REFUSED); }
    let mut evidence = KEY_RECOVERY.lock().map_err(|_| super::native_recovery::REFUSED)?;
    super::native_recovery::set_aside(data, recover && evidence.as_deref() == Some(data))?;
    evidence.take();
    Ok(())
}

pub(crate) fn disconnect_wallet_tabs() {
    if let Some(tabs) = RUNNING.lock().unwrap().as_ref().and_then(|m| m.state.wallet_tabs.as_ref()) {
        tabs.revoke_all();
    }
}

use super::diagnostics::{Event, Kind};

#[derive(Default)]
struct Diagnostics {
    sink: Option<extern "C" fn(*const std::ffi::c_char)>,
    last_error: Option<&'static str>,
    failing: [bool; 2],
}

impl Diagnostics {
    fn record(&mut self, event: Event) {
        let (message, kind) = event.describe();
        if let Some(condition) = event.condition() {
            // Polls repeat these every few seconds: log only the change.
            let failing = kind == Kind::Failing;
            if self.failing[condition] == failing { return; }
            self.failing[condition] = failing;
        }
        if kind == Kind::Error { self.last_error = Some(message); }
        if let Some(sink) = self.sink { sink(std::ffi::CString::new(message).unwrap().as_ptr()); }
    }
}

static DIAGNOSTICS: Mutex<Diagnostics> = Mutex::new(Diagnostics { sink: None, last_error: None, failing: [false; 2] });

pub(crate) fn set_log_sink(sink: extern "C" fn(*const std::ffi::c_char)) {
    DIAGNOSTICS.lock().unwrap().sink = Some(sink);
}

fn emit(event: Event) {
    DIAGNOSTICS.lock().unwrap().record(event);
}

pub(super) fn emit_for(state: &super::state::AppState, event: Event) {
    let running = RUNNING.lock().unwrap().as_ref().is_some_and(|member| std::ptr::eq(state, member.state.as_ref()));
    if running { emit(event); }
}

pub(crate) fn status(data: &Path, development_http: bool) -> Value {
    let saved = super::RegistrationConfig::resume(data, development_http).ok();
    let mut reply = json!({
        "unlocked": false, "registered": false, "wallet_tabs": 0, "vaults": null,
        "coordinator": saved.as_ref().map(|r| &r.coordinator),
        "slot": saved.and_then(|r| r.slot),
    });
    if let Ok(running) = with_running_member(|member| {
        let state = &member.state;
        let has_session = state.session.blocking_read().is_some();
        let registered_slot = state.registration.blocking_read().as_ref().map(|r| r.slot);
        let active = !state.is_stopping();
        let unlocked = has_session && active;
        let count = if unlocked { state.wallet_tabs.as_ref().map_or(0, |tabs| tabs.count()) } else { 0 };
        // Count on-disk vaults without opening shares or prompting for Touch ID.
        let vaults = unlocked.then(|| {
            match std::fs::read_dir(state.config.data.join("vaults")) {
                Ok(entries) => Some(entries.flatten().filter(|entry| {
                    entry.file_name().to_str().and_then(|name| ceremony::dir(&state.config.data, name).ok())
                        .is_some_and(|dir| dir.exists("vault.sealed"))
                }).count()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
                Err(_) => None,
            }
        }).flatten();
        let registration = state.config.registration.as_ref();
        Ok(json!({
            "unlocked": unlocked, "registered": active && registered_slot.is_some(), "wallet_tabs": count, "vaults": vaults,
            "coordinator": registration.map(|r| &r.coordinator),
            "slot": registered_slot.or_else(|| registration.and_then(|r| r.slot)),
        }))
    }) { reply = running; }
    reply["last_error"] = json!(DIAGNOSTICS.lock().unwrap().last_error);
    reply
}

pub(crate) fn restore_running(words: Zeroizing<Vec<u8>>, file: &Path, fingerprint: &str) -> Result<(), &'static str> {
    let member = RUNNING.lock().map_err(|_| super::native_recovery::REFUSED)?.clone()
        .filter(|member| !member.state.is_stopping())
        .ok_or(super::native_recovery::LOCKED)?;
    super::native_recovery::restore_running(&member.state, words, file, fingerprint)
}

/// Authenticates only a request constructed here, not a header or an HTTP caller.
#[derive(Clone)]
pub(super) struct InProcess(());

const REQUEST_LOCKED: (StatusCode, &str) = (StatusCode::UNAUTHORIZED, "profile is locked");
type RequestError = (StatusCode, &'static str);

fn request_route(path: &str, write: bool, export: bool) -> Result<&str, RequestError> {
    let (route, query) = path.split_once('?').map_or((path, None), |(route, query)| (route, Some(query)));
    let allowed = if export { !write && route == "recovery-backup" } else if write {
        matches!(route, "create" | "join" | "agree" | "balance" | "payment-draft" | "payment-publish"
            | "payment-review" | "payment-approve" | "payment-discard" | "payment-send" | "payment-replace" | "payment-verify"
            | "device-revoke")
    } else {
        matches!(route, "status" | "registration" | "payments" | "pending" | "payment-status" | "recovery-status")
    };
    if !allowed { return Err((StatusCode::NOT_FOUND, "unsupported wallet route")); }
    if let Some(query) = query {
        let mut seen = [false; 2];
        for pair in query.split('&') {
            let invalid = (StatusCode::BAD_REQUEST, "invalid wallet query");
            let (name, value) = pair.split_once('=').ok_or(invalid)?;
            let field = match (route, name) {
                ("status" | "payments" | "pending" | "payment-status" | "recovery-status" | "recovery-backup", "vault") => 0,
                ("payment-status", "attempt") => 1,
                _ => return Err(invalid),
            };
            if seen[field] || value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(invalid); }
            seen[field] = true;
        }
    }
    Ok(path)
}

/// Execute the same Axum handlers and validation on the member's own runtime, with no HTTP hop.
/// Dropping the runtime at lock drains any blocking library workers before the UI reopens it.
pub(crate) fn wallet_request(path: &str, body: Option<Value>, export: bool) -> Value {
    fn dispatch(path: &str, body: Option<Value>, export: bool) -> Result<(StatusCode, Value), RequestError> {
        let path = request_route(path, body.is_some(), export)?;
        let member = RUNNING.lock().map_err(|_| REQUEST_LOCKED)?.clone().ok_or(REQUEST_LOCKED)?;
        if member.state.is_stopping() { return Err(REQUEST_LOCKED); }
        let generation = member.state.session_generation();
        let runtime = member.runtime.as_ref().ok_or(REQUEST_LOCKED)?;
        let invalid = (StatusCode::BAD_REQUEST, "invalid wallet request");
        let mut builder = Request::builder().uri(format!("/api/{path}")).extension(InProcess(()));
        let body = match body {
            Some(body) if body.is_object() => {
                if path == "join" {
                    ceremony::embedded_invite_target(&member.state.config, &body)
                        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
                }
                builder = builder.method(Method::POST).header(header::CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            Some(_) => return Err(invalid),
            None => Body::empty(),
        };
        let request = builder.body(body).map_err(|_| invalid)?;
        let (active, mut router) = (member.clone(), member.router.clone());
        let task = runtime.spawn(async move {
            if active.state.session.read().await.is_none() || active.state.is_stopping()
                || active.state.session_generation() != generation {
                return Err(REQUEST_LOCKED);
            }
            let response = router.call(request).await.expect("Axum router is infallible");
            let status = response.status();
            let bad_reply = (StatusCode::INTERNAL_SERVER_ERROR, "invalid member reply");
            let raw = to_bytes(response.into_body(), 4 * 1024 * 1024).await.map_err(|_| bad_reply)?;
            let data = serde_json::from_slice::<Value>(&raw).ok().filter(Value::is_object)
                .or_else(|| (!status.is_success()).then(|| json!({ "error": status.canonical_reason().unwrap_or("request failed") })))
                .ok_or(bad_reply)?;
            Ok((status, data))
        });
        let result = runtime.block_on(task).map_err(|_| REQUEST_LOCKED)?;
        if member.state.is_stopping() || member.state.session_generation() != generation
            || !RUNNING.lock().is_ok_and(|running| running.as_ref().is_some_and(|current| Arc::ptr_eq(current, &member))) {
            return Err(REQUEST_LOCKED);
        }
        result
    }
    // TEMPORARY verbose diagnostics: route (without query), status, time and the error text.
    let started = std::time::Instant::now();
    let route = path.split('?').next().unwrap_or(path).to_owned();
    let (status, data) = dispatch(path, body, export).unwrap_or_else(|(status, message)| (status, json!({ "error": message })));
    if status.is_success() {
        eprintln!("[verbose] wallet {route} -> {} in {} ms", status.as_u16(), started.elapsed().as_millis());
    } else {
        eprintln!("[verbose] wallet {route} -> {} in {} ms: {} (code {})", status.as_u16(), started.elapsed().as_millis(),
            data["error"].as_str().unwrap_or("?"), data["code"].as_str().unwrap_or("-"));
    }
    json!({ "status": status.as_u16(), "data": data })
}

/// Snapshot the running member without keeping the process handle locked over a query. Discard
/// the result if its member stopped or was replaced while the worker was doing I/O.
fn with_running_member<T>(query: impl FnOnce(&NativeMember) -> Result<T, &'static str>) -> Result<T, &'static str> {
    let member = RUNNING.lock().map_err(|_| LIST_ERROR)?.clone().ok_or(LOCKED)?;
    if member.state.is_stopping() { return Err(LOCKED); }
    let result = query(&member);
    let running = RUNNING.lock().map_err(|_| LIST_ERROR)?;
    if member.state.is_stopping() || !running.as_ref().is_some_and(|current| Arc::ptr_eq(current, &member)) {
        return Err(LOCKED);
    }
    result
}

/// Called from a native worker thread, not a Tokio task or the app's main thread.
pub(crate) fn vault_addresses() -> Result<Vec<Value>, &'static str> {
    vault_addresses_with(|| {})
}

fn vault_addresses_with(after_list: impl FnOnce()) -> Result<Vec<Value>, &'static str> {
    with_running_member(|member| {
        let (data, passphrase, generation) = {
            let session = member.state.session.blocking_read();
            let session = session.as_ref().ok_or(LOCKED)?;
            if member.state.is_stopping() { return Err(LOCKED); }
            (session.data.clone(), session.passphrase.clone(), member.state.session_generation())
        };
        let rows = member.list(&data, &passphrase, generation);
        after_list();
        let session = member.state.session.blocking_read();
        if member.state.is_stopping() || session.is_none() || member.state.session_generation() != generation {
            return Err(LOCKED);
        }
        rows
    })
}

impl NativeMember {
    fn list(&self, data: &Path, pass: &str, generation: u64) -> Result<Vec<Value>, &'static str> {
        let entries = match std::fs::read_dir(data.join("vaults")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err(LIST_ERROR),
        };
        let mut entries = entries.collect::<Result<Vec<_>, _>>().map_err(|_| LIST_ERROR)?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut rows = Vec::new();
        for entry in entries {
            if self.state.session_generation() != generation || self.state.is_stopping() { return Err(LOCKED); }
            let name = entry.file_name();
            let Some(vault) = name.to_str() else { continue };
            let Ok(dir) = ceremony::dir(data, vault) else { continue };
            if !dir.exists("vault.sealed") {
                continue;
            }
            let Ok(c) = ceremony::load(data, pass, vault) else {
                rows.push(json!({ "vault": vault, "error": VAULT_ERROR }));
                continue;
            };
            let slot = c.my_slot;
            let label = vault_label(&c.name);
            let row = match self.address(data, pass, vault, slot, &c.name, generation) {
                Ok((network, address)) => json!({ "vault": vault, "name": label, "slot": slot, "network": network, "address": address }),
                Err(error) => json!({ "vault": vault, "name": label, "slot": slot, "error": error }),
            };
            rows.push(row);
        }
        Ok(rows)
    }

    fn address(&self, data: &Path, pass: &str, vault: &str, slot: u16, name: &str, generation: u64) -> Result<(&'static str, String), &'static str> {
        // Don't migrate from vault.sealed or hold any host/cache lock over the Enclave prompt.
        let id = (vault.to_owned(), slot);
        let cached = self.viewing_keys.lock().map_err(|_| VAULT_ERROR)?.get(&id).cloned();
        let opened = cached.map_or_else(|| {
            let reason = super::custody::vault_touch_id_reason(&self.state, "verify the receive address for", vault, Some(name));
            SignerViewingKey::open(&self.state, data, pass, vault, slot, reason.as_deref())
        }, Ok);
        // Read after any prompt, including when the store could not be opened for a legacy vault.
        let dir = ceremony::dir(data, vault).map_err(|_| VAULT_ERROR)?;
        let raw = Zeroizing::new(dir.read_sealed("vault.sealed", pass).map_err(|_| VAULT_ERROR)?);
        let sealed: Value = serde_json::from_slice(&raw).map_err(|_| VAULT_ERROR)?;
        if is_legacy(&sealed) {
            return Err(UPGRADE_VAULT);
        }
        let (key, network) = opened.map_err(|e| super::state::member_key_message(&e).unwrap_or(VAULT_ERROR))?;
        if sealed["vault"] != vault || sealed["my_frost_id"] != slot || sealed["network"] != network.label()
            || sealed["key_derivation"] != crate::zip2005::VERSION
        {
            return Err(VAULT_ERROR);
        }
        let address = key.checked_address(&sealed, network).map_err(|_| VAULT_ERROR)?;
        // Lock may have completed while Touch ID was open. Do not repopulate its cleared cache.
        let session = self.state.session.blocking_read();
        if session.is_none() || self.state.session_generation() != generation || self.state.is_stopping() {
            return Err(LOCKED);
        }
        self.viewing_keys.lock().map_err(|_| VAULT_ERROR)?.entry(id).or_insert((key, network));
        Ok((network.label(), address))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn repeating_failures_log_only_changes_and_never_set_the_last_error() {
        static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
        extern "C" fn capture(line: *const std::ffi::c_char) {
            LINES.lock().unwrap().push(unsafe { std::ffi::CStr::from_ptr(line) }.to_str().unwrap().to_owned());
        }
        let mut quiet = Diagnostics::default();
        quiet.record(Event::RelayUnavailable); // no sink: nothing to write, no panic
        let mut diagnostics = Diagnostics { sink: Some(capture), ..Diagnostics::default() };
        diagnostics.record(Event::RelayReachable);
        for _ in 0..3 { diagnostics.record(Event::RelayUnavailable); }
        diagnostics.record(Event::WalletSyncFailed);
        diagnostics.record(Event::RelayReachable);
        diagnostics.record(Event::RelayReachable);
        assert_eq!(*LINES.lock().unwrap(), [
            Event::RelayUnavailable.describe().0, Event::WalletSyncFailed.describe().0, Event::RelayReachable.describe().0,
        ]);
        assert_eq!(diagnostics.last_error, None);
        diagnostics.record(Event::RegistrationRefused(super::super::diagnostics::Refusal::ExpiredChallenge));
        assert!(diagnostics.last_error.is_some_and(|error| error.contains("pairing link expired")));
    }

    use super::*;
    use crate::{
        signer::{local::encode_share, store::{FileKind, SignerStore}, Network},
        state::MemberDir,
        vault, zip2005,
    };
    use reddsa_frost::frost::redpallas as frost;
    use zcash_protocol::consensus::NetworkType;

    const PASS: &str = "local test unlock";
    const SLOT: u16 = 2;

    fn config(data: &Path) -> Config {
        let mut settings = super::super::native_config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "0".into(),
            "--network".into(), "testnet".into(),
        ]).unwrap();
        settings.secure_element = "software".into();
        settings
    }

    #[test]
    fn lock_during_final_signing_poll_refuses_share_before_session_clears() {
        let _test = TEST_MEMBER.lock().unwrap();
        let state = Arc::new(super::super::state::AppState::new(config(Path::new("unused"))));
        *state.session.blocking_write() = Some(super::super::state::Session {
            data: "unused".into(), passphrase: Zeroizing::new(PASS.into()),
        });
        let _scope = NativeScope::install(&state, None).unwrap();
        assert_eq!(check_signing(&state, || Ok(())), Ok(()));

        assert_eq!(check_signing(&state, || {
            assert!(request_stop());
            // Shutdown has been requested, but the async runtime has not cleared the session.
            assert!(state.session.blocking_read().is_some());
            Ok(())
        }), Err("LokiSigner is locked".into()));
        assert!(check_signing(&state, || panic!("a stopped signer must not poll the relay")).is_err());
    }

    #[test]
    fn wallet_dispatch_requires_a_live_session_and_only_uses_wallet_routes() {
        let _test = TEST_MEMBER.lock().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut settings = config(Path::new("unused"));
        settings.registration = Some(super::super::RegistrationConfig::pairing(
            &format!("loki://pair?origin=https%3A%2F%2Fwallet.example&slot=7&challenge={}", "ab".repeat(32)), false,
        ).unwrap());
        let state = Arc::new(super::super::state::AppState::new(settings));
        let _scope = {
            let _runtime = runtime.enter();
            NativeScope::install(&state, None).unwrap()
        };
        let dispatch = |path, body, export| wallet_request(path, body, export)["status"].as_u64().unwrap();
        assert_eq!(dispatch("registration", None, false), 401);
        *state.session.blocking_write() = Some(super::super::state::Session { data: "unused".into(), passphrase: Zeroizing::new(PASS.into()) });
        assert_eq!(dispatch("registration", None, false), 409, "the underlying handler sees an unregistered member");
        assert_eq!(runtime.block_on(super::super::routes::router(state.clone()).call(
            Request::builder().uri("/api/registration").header("x-loki-token", "in-process").body(Body::empty()).unwrap(),
        )).unwrap().status(), StatusCode::UNAUTHORIZED);
        for path in ["/api/registration", "https://wallet.example/api/status", "//wallet.example/api/status", "status#other", "address", "recovery-backup",
            "recovery-setup", "recovery-restore", "device-login", "connect", "lock", "unlock", "enroll", "session"] {
            assert_eq!(dispatch(path, None, false), 404, "{path}");
            assert_eq!(dispatch(path, Some(json!({})), false), 404, "{path}");
        }
        assert_eq!(dispatch("status?origin=https://wallet.example", None, false), 400);
        assert_eq!(dispatch("registration", None, true), 404);
        assert_eq!(dispatch("recovery-backup", None, true), 400, "only the backup handler is available to export");
        let invite = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json!({ "vault": "ab".repeat(32), "slot": 2,
                "creator_base_url": "https://unapproved.example", "token": "unused", "members": 3, "threshold": 2, "name": "Test" }).to_string())
        };
        assert_eq!(dispatch("join", Some(json!({ "invite": invite })), false), 400);
        assert!(request_stop());
        assert_eq!(dispatch("registration", None, false), 401);
    }

    #[test]
    fn a_paired_native_app_runs_offline_and_only_sets_aside_after_stop() {
        let _test = TEST_MEMBER.lock().unwrap();
        static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
        extern "C" fn capture(line: *const std::ffi::c_char) {
            let line = unsafe { std::ffi::CStr::from_ptr(line) }.to_str().unwrap();
            LOG.lock().unwrap().push(line.to_owned());
        }
        set_log_sink(capture);
        let root = std::env::temp_dir().join(format!("loki-native-stop-{}", uuid::Uuid::new_v4()));
        let data = root.join("LokiSigner");
        crate::profile::create(&data, PASS, "Test member").unwrap();
        super::super::registration::save_coordinator(&data, "https://127.0.0.1:1", 7).unwrap();
        let mut settings = config(&data);
        settings.registration = Some(super::super::RegistrationConfig::resume(&data, false).unwrap());
        let before = status(&data, false);
        assert_eq!(before["unlocked"], false);
        assert_eq!(before["coordinator"], "https://127.0.0.1:1");
        assert_eq!(before["slot"], 7);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let (asked_tx, asked_rx) = std::sync::mpsc::channel();
        let (answer_tx, answer_rx) = std::sync::mpsc::channel();
        let answer_rx = Mutex::new(answer_rx);
        let worker = std::thread::spawn(move || {
            let notice: LocalNotice = Arc::new(move |kind, message| {
                if kind != "recovery" { ready_tx.send((kind.to_owned(), message.to_owned())).unwrap(); }
                true
            });
            let approve: LocalApproval = Arc::new(move |_, _| {
                asked_tx.send(()).unwrap();
                answer_rx.lock().unwrap().recv().unwrap()
            });
            stop_tx.send(run_native(settings, Zeroizing::new(PASS.into()), notice, approve,
                Arc::new(|_| crate::host::RosterAnswer::Differ), Some(Arc::new(|_, _, _| true)), None)).unwrap();
        });
        let timeout = std::time::Duration::from_secs(10);
        let events: BTreeMap<_, _> = (0..2).map(|_| ready_rx.recv_timeout(timeout).unwrap()).collect();
        assert_eq!(events["registration-warning"], "LokiSigner couldn’t reach the coordinator. Your profile is unlocked and LokiSigner will keep trying in the background.");
        assert_eq!(events["ready"], "", "native readiness does not expose a local pairing link");
        let offline = status(&data, false);
        assert_eq!(offline["unlocked"], true);
        assert_eq!(offline["registered"], false);
        assert_eq!(offline["vaults"], 0);
        assert_eq!(offline["last_error"], "LokiSigner couldn’t reach the coordinator. Check your connection.");
        let wallet = wallet_request("status", None, false);
        assert_eq!(wallet["status"], 200);
        assert_eq!(wallet["data"]["paired_coordinator"], "https://127.0.0.1:1", "offline does not change the pinned origin");
        assert!(vault_addresses().unwrap().is_empty(), "local features work while offline");

        // Fake only the coordinator's public registration reply. Use the real tab handshake.
        let state = RUNNING.lock().unwrap().as_ref().unwrap().state.clone();
        let endpoint = state.config.lokisigner_url().unwrap();
        let member = super::super::registration::PublicMember {
            slot: 7, signing_pubkey: "01".repeat(32), relay_pubkey: "02".repeat(32),
            advertise_url: "https://member.example".into(), lokisigner_url: Some(endpoint.clone()),
        };
        *state.registration.blocking_write() = Some(member.clone());
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let client = reqwest::Client::builder().timeout(timeout).no_proxy().build().unwrap();
        let connect = || runtime.block_on(async {
            let body = client.post(format!("{endpoint}/api/connect")).header("origin", "https://127.0.0.1:1")
                .json(&json!({"slot": 7, "signing_pubkey": member.signing_pubkey, "relay_pubkey": member.relay_pubkey}))
                .send().await.unwrap().error_for_status().unwrap().text().await.unwrap();
            serde_json::from_str::<Value>(body.lines().last().unwrap()).unwrap()["token"].as_str().unwrap().to_owned()
        });
        let access = |token: &str| runtime.block_on(async {
            client.get(format!("{endpoint}/api/registration")).header("origin", "https://127.0.0.1:1")
                .header("x-loki-token", token).send().await
        });
        let first = connect();
        assert_eq!(access(&first).unwrap().status(), 200);
        let connected = status(&data, false);
        assert_eq!(connected["registered"], true);
        assert_eq!(connected["wallet_tabs"], 1);
        disconnect_wallet_tabs();
        assert_eq!(status(&data, false)["wallet_tabs"], 0);
        assert_eq!(access(&first).unwrap().status(), 401);
        // A subsequent attempt still fails, but the modal warning is once per launch.
        assert_eq!(ready_rx.recv_timeout(std::time::Duration::from_secs(6)).unwrap_err(), std::sync::mpsc::RecvTimeoutError::Timeout);

        let second = connect();
        let approve = state.approval.clone().unwrap();
        let prompt = std::thread::spawn(move || approve(r#"{"memo":"test-private-payment-memo"}"#, &crate::host::ApprovalAttempt::default()));
        asked_rx.recv_timeout(timeout).unwrap();
        assert!(set_aside(&data, false).is_err());
        assert!(request_stop());
        assert_eq!(status(&data, false)["unlocked"], false);
        assert_eq!(status(&data, false)["wallet_tabs"], 0);
        assert!(!matches!(access(&second), Ok(response) if response.status().is_success()));
        answer_tx.send(ApprovalAnswer::Approve).unwrap();
        assert!(matches!(prompt.join().unwrap(), ApprovalAnswer::Refuse), "a late approval cannot override lock");
        stop_rx.recv_timeout(timeout).unwrap().unwrap();
        worker.join().unwrap();
        assert!(state.session.blocking_read().is_none(), "stop clears the retained session");
        let refused = "Payment approval was refused or not completed on this Mac.";
        assert_eq!(status(&data, false)["last_error"], refused);
        #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
        {
            let args = std::ffi::CString::new(json!({"args": ["--data", data, "--port", "0"]}).to_string()).unwrap();
            let ptr = unsafe { crate::enclave_ffi::loki_member_app_status(args.as_ptr()) };
            let reply: Value = serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_bytes()).unwrap();
            unsafe { crate::enclave_ffi::loki_member_app_free(ptr); }
            assert_eq!(reply, json!({"status": status(&data, false)}));
        }
        DIAGNOSTICS.lock().unwrap().sink = None;
        let messages = LOG.lock().unwrap().join("\n");
        assert!(messages.contains("LokiSigner couldn’t reach the coordinator. Check your connection."));
        assert!(messages.contains(refused));
        for secret in [PASS, &first, &second, "test-private-payment-memo", "127.0.0.1:1"] {
            assert!(!messages.contains(secret), "diagnostics must only contain fixed messages");
        }
        set_aside(&data, false).unwrap();
        assert!(!data.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    #[test]
    fn only_a_gone_vault_key_allows_archiving_vault_data_after_stop() {
        use crate::signer::secure_element_apple::KeyFailure;
        let _test = TEST_MEMBER.lock().unwrap();
        let root = std::env::temp_dir().join(format!("loki-native-key-gone-{}", uuid::Uuid::new_v4()));
        let data = root.join("LokiSigner");
        let share = "vaults/member-vault/signer/share.sealed";
        let key_dir = data.join(share).parent().unwrap().to_owned();
        std::fs::create_dir_all(&key_dir).unwrap();
        std::fs::write(data.join(share), b"existing sealed share").unwrap();
        let mut settings = config(&data);
        settings.secure_element = "apple".into();
        let state = Arc::new(crate::host::state::AppState::new(settings));
        let (tx, rx) = std::sync::mpsc::channel();
        let notice: LocalNotice = Arc::new(move |kind, text| { tx.send((kind.to_owned(), text.to_owned())).unwrap(); true });
        for failure in [KeyFailure::Cancelled, KeyFailure::LockedOut, KeyFailure::Missing] {
            let scope = NativeScope::install(&state, Some(notice.clone())).unwrap();
            let _fixture = super::super::state::apple_test::install(&data, move |_, _, create| {
                assert!(!create);
                Err(failure)
            });
            let opened = state.config.open_secure_element_with_reason(&key_dir, PASS, Some("open a vault"));
            assert_eq!(opened.err().as_deref(), Some(failure.message()));
            assert!(set_aside(&data, true).is_err(), "cannot archive a running profile");
            drop(scope);
            if !failure.is_gone() {
                assert!(rx.try_recv().is_err());
                assert_eq!(set_aside(&data, true), Err("vault"));
            }
        }
        assert_eq!(rx.try_recv().unwrap(), ("registration-key-gone".into(), KeyFailure::Missing.message().into()));
        assert_eq!(set_aside(&data, false), Err("vault"));
        set_aside(&data, true).unwrap();
        assert!(!data.exists());
        let archived = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(std::fs::read(archived.join(share)).unwrap(), b"existing sealed share");
        std::fs::remove_dir_all(root).unwrap();
    }

    fn write(dir: &MemberDir, file: &str, value: &Value) {
        if dir.exists(file) {
            std::fs::remove_file(dir.path().join(file)).unwrap();
        }
        dir.write_sealed(file, &serde_json::to_vec(value).unwrap(), PASS).unwrap();
    }

    fn ceremony(dir: &MemberDir, id: &str, name: &str) {
        write(dir, "ceremony.sealed", &json!({
            "vault": id, "name": name, "my_slot": SLOT, "threshold": 2, "members": 3,
            "creator_base_url": "http://127.0.0.1:3001", "frostd_url": "http://127.0.0.1:2744",
            "slots": {}, "agreed": [], "dkg_started": false,
        }));
    }

    #[test]
    fn addresses_require_the_signer_store_and_check_each_seal_even_after_caching() {
        use super::super::state::scope_test::{Fixture, Scope};
        use crate::signer::secure_element::SoftwareSecureElement;
        let _test = TEST_MEMBER.lock().unwrap();
        let data = std::env::temp_dir().join(format!("loki-addresses-{}", uuid::Uuid::new_v4()));
        let mut settings = config(&data);
        settings.secure_element = "apple".into();
        let state = Arc::new(crate::host::state::AppState::new(settings));
        let fixture = Fixture::install(&data);
        let _native = NativeScope::install(&state, None).unwrap();
        *state.session.blocking_write() = Some(crate::host::state::Session {
            passphrase: Zeroizing::new(PASS.into()), data: data.clone(),
        });
        assert!(vault_addresses().unwrap().is_empty());

        let pending = "10".repeat(32);
        let pending_dir = MemberDir::create(&data.join("vaults"), &pending).unwrap();
        ceremony(&pending_dir, &pending, "Pending vault");
        assert!(vault_addresses().unwrap().is_empty());

        let id = [43u8; 32];
        let id_hex = hex::encode(id);
        let dir = MemberDir::create(&data.join("vaults"), &id_hex).unwrap();
        ceremony(&dir, &id_hex, "Shared reserve");
        let (shares, public) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng,
        ).unwrap();
        let slot = frost::Identifier::try_from(SLOT).unwrap();
        let share = frost::keys::KeyPackage::try_from(shares[&slot].clone()).unwrap();
        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        let vs = [62; 32];
        let fvk = zip2005::frost_viewing_key(&ak, &vs).unwrap();
        let expected = vault::unified_receiver(vault::test_only_address(&fvk).to_raw_address_bytes(), NetworkType::Test);
        let sealed: Value = serde_json::from_slice(&super::super::ceremony::vault_sealed_bytes(
            &id_hex, SLOT, 2, 3, "fixture", &public, &fvk, 4465026, VaultNetwork::Testnet,
        ).unwrap()).unwrap();
        write(&dir, "vault.sealed", &sealed);
        let error_row = json!({ "vault": id_hex, "name": "Shared reserve", "slot": SLOT,
            "error": "LokiSigner could not verify this vault’s receive address." });
        assert_eq!(vault_addresses().unwrap(), vec![error_row.clone()], "a seal alone isn't enough");

        let mut legacy = sealed.clone();
        legacy["key_package"] = json!(hex::encode(share.serialize().unwrap()));
        legacy["vault_secret"] = json!(hex::encode(vs));
        write(&dir, "vault.sealed", &legacy);
        let upgrade_row = json!({ "vault": id_hex, "name": "Shared reserve", "slot": SLOT,
            "error": "Open this vault in the wallet once to upgrade it." });
        assert_eq!(vault_addresses().unwrap(), vec![upgrade_row.clone()], "legacy seal with no signer store");
        write(&dir, "vault.sealed", &sealed);

        let signer_dir = super::super::ceremony::signer_dir(&data, &id_hex).unwrap();
        let store = SignerStore::create(&signer_dir, Network::Testnet, id, SLOT).unwrap();
        let se = SoftwareSecureElement::persistent(&signer_dir, PASS).unwrap();
        let raw = encode_share(&share.serialize().unwrap(), &public.serialize().unwrap(), &vs);
        store.write(&se, FileKind::Share, 0, &raw).unwrap();
        let correct = json!({ "vault": id_hex, "name": "Shared reserve", "slot": SLOT, "network": "testnet", "address": expected });
        assert_eq!(vault_addresses().unwrap(), vec![correct.clone()]);
        #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
        {
            let reply = crate::enclave_ffi::loki_member_app_vault_addresses();
            assert!(!reply.is_null());
            let value: Value = serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(reply) }.to_bytes()).unwrap();
            unsafe { crate::enclave_ffi::loki_member_app_free(reply); }
            assert_eq!(value, json!({ "vaults": [correct] }));
        }

        write(&dir, "vault.sealed", &legacy);
        assert_eq!(vault_addresses().unwrap(), vec![upgrade_row], "legacy seal with a cached viewing key");

        let other_fvk = zip2005::frost_viewing_key(&ak, &[63; 32]).unwrap();
        let other_address = vault::unified_address(&other_fvk, NetworkType::Test);
        let (_, other_package) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng,
        ).unwrap();
        for (field, tampered) in [
            ("group_address", json!(other_address)),
            ("public_package", json!(hex::encode(other_package.serialize().unwrap()))),
            ("my_frost_id", json!(SLOT + 1)),
        ] {
            let mut invalid = sealed.clone();
            invalid[field] = tampered;
            write(&dir, "vault.sealed", &invalid);
            assert_eq!(vault_addresses().unwrap(), vec![error_row.clone()], "changed {field}");
        }
        // A consistent-looking address and network aren't evidence of the store's network.
        let mut wrong_network = sealed.clone();
        wrong_network["network"] = json!("regtest");
        wrong_network["group_address"] = json!(vault::regtest_unified_address(&fvk));
        write(&dir, "vault.sealed", &wrong_network);
        assert_eq!(vault_addresses().unwrap(), vec![error_row]);

        write(&dir, "vault.sealed", &sealed);
        for hidden in ['\n', '\u{0085}', '\u{2028}', '\u{202e}', '\u{001b}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'] {
            ceremony(&dir, &id_hex, &format!("Reserve{hidden}Copy this address instead"));
            let mut safe = correct.clone();
            safe["name"] = json!("Name hidden (unsupported characters)");
            assert_eq!(vault_addresses().unwrap(), vec![safe], "{hidden:?}");
        }
        let max_label = "é".repeat(80);
        assert_eq!(vault_label(&max_label), max_label);
        ceremony(&dir, &id_hex, &(max_label + "!"));
        let mut safe = correct;
        safe["name"] = json!("Name hidden (unsupported characters)");
        assert_eq!(vault_addresses().unwrap(), vec![safe]);

        let rows = vault_addresses_with(|| *state.session.blocking_write() = None);
        assert_eq!(rows, Err("Unlock LokiSigner to view vault addresses."), "profile locked during listing");
        assert_eq!(vault_addresses(), Err("Unlock LokiSigner to view vault addresses."));
        assert_eq!(fixture.scopes(), [Scope {
            reason: Some("verify the receive address for vault “Shared reserve”".into()), unwraps: 1, closed: true,
        }]);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn running_handle_refuses_second_install_and_discards_rows_after_replacement() {
        let _test = TEST_MEMBER.lock().unwrap();
        let state = Arc::new(crate::host::state::AppState::new(config(Path::new("unused"))));
        let scope = NativeScope::install(&state, None).unwrap();
        assert_eq!(NativeScope::install(&state, None).err().as_deref(), Some("LokiSigner is already running."));

        let mut replacement = None;
        let rows = with_running_member(|_| {
            drop(scope);
            replacement = Some(NativeScope::install(&state, None).unwrap());
            Ok(vec![json!({ "name": "Old member’s vault" })])
        });
        assert!(replacement.is_some());
        assert_eq!(rows, Err("Unlock LokiSigner to view vault addresses."));
        assert_eq!(with_running_member(|_| Ok(())), Ok(()));
    }

    #[test]
    fn only_native_startup_installs_the_handle_and_unwind_clears_it() {
        struct Ready;
        let _test = TEST_MEMBER.lock().unwrap();
        let data = Path::new("unused");
        for native in [false, true] {
            let notice: LocalNotice = Arc::new(move |kind, _| {
                assert_eq!(kind, "ready");
                assert_eq!(RUNNING.lock().unwrap().is_some(), native);
                // Only LokiSigner's entry attaches its roster dialog, and it is the one given.
                let roster = RUNNING.lock().unwrap().as_ref()
                    .and_then(|member| member.state.roster_confirmation.as_ref().map(|confirm| confirm("{}")));
                assert_eq!(roster, native.then_some(crate::host::RosterAnswer::Differ));
                assert_eq!(std::thread::spawn(vault_addresses).join().unwrap(), Err("Unlock LokiSigner to view vault addresses."));
                std::panic::panic_any(Ready); // Stop once startup reached ready, without leaving a listener running.
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if native {
                    run_native(config(data), Zeroizing::new(PASS.into()), notice, Arc::new(|_, _| crate::host::ApprovalAnswer::Refuse),
                        Arc::new(|_| crate::host::RosterAnswer::Differ), Some(Arc::new(|_, _, _| false)), None)
                } else {
                    let config = super::super::config_from_args(&["--data".into(), data.to_str().unwrap().into(),
                        "--port".into(), "0".into()]).unwrap();
                    super::super::run_local(config, None, Some(notice), None, None)
                }
            }));
            assert!(result.unwrap_err().is::<Ready>());
            assert_eq!(vault_addresses(), Err("Unlock LokiSigner to view vault addresses."));
        }
    }
}
