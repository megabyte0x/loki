//! The member-owned HTTP device (axum). One process per member, started locally by
//! that member. Profile unlock, custody, ceremony and payment signing stay here; the web
//! coordinator only publishes public artifacts. This process drives the audited library. All library calls run on `spawn_blocking` because the hosted relay
//! stack blocks on its own runtime (see `setup_relay::shared_runtime`).

/// Records a fixed diagnostic event in the native app's log. A no-op for other members and builds.
/// `$event` is only compiled where the native log exists.
macro_rules! native_event {
    ($st:expr, $event:expr) => {{
        let state: &crate::host::state::AppState = $st;
        if state.config.native {
            #[allow(unused_imports)]
            use crate::host::diagnostics::{DraftRefusal, Event, PaymentFailure};
            let event: Event = $event;
            #[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
            crate::host::native_member::emit_for(state, event);
            #[cfg(not(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))))]
            let _ = event;
        }
    }};
}

mod ceremony;
mod diagnostics;
mod connect;
mod custody;
mod device;
mod payment;
mod native_config;
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
mod native_member;
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
mod native_recovery;
mod nonce_witness;
mod recovery;
mod registration;
#[cfg(test)]
mod repair;
mod routes;
mod state;

pub use state::Config;
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use connect::{ConnectAttempt, LocalConnect};
pub use registration::RegistrationConfig;
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use registration::pairing_pending;
pub use native_config::{Deployment, FetchedConfig, NativeConfig};
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_member::{disconnect_wallet_tabs, run_native, request_stop as native_request_stop, set_aside as native_set_aside, vault_addresses as native_vault_addresses};
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_member::can_view_addresses as native_can_view_addresses;
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_member::restore_running as native_restore_running;
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_member::{set_log_sink as native_set_log_sink, status as native_status, wallet_request as native_wallet_request};
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_recovery::{clean_staging as native_clean_staging, profile_state as native_profile_state, restore_new as native_restore_new, REFUSED as NATIVE_RESTORE_REFUSED};
#[cfg(feature = "relay-communication")]
pub use nonce_witness::WitnessConfig;
pub use recovery::run_recovery_command;

/// Device-local UI notifications; never forwarded to the coordinator or a log.
/// Only recovery setup uses the result: true means the member confirmed saving the words.
pub type LocalNotice = std::sync::Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

#[derive(Default)]
pub struct ApprovalAttempt {
    vault_name: Option<String>,
    state: std::sync::Mutex<Option<ApprovalEnd>>,
    waiting: std::sync::atomic::AtomicBool,
}

/// Fixed status codes for the native approval's borrowed cancellation callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ApprovalEnd {
    Failed = 1,
    LocalTimeout = 2,
    PeerTimeout = 3,
    PeerRefused = 4,
    ShareDeadline = 5,
    LocalRefused = 6,
}

impl ApprovalAttempt {
    pub(crate) fn named(vault_name: String) -> Self {
        Self { vault_name: Some(vault_name), ..Self::default() }
    }

    pub(crate) fn end(&self, reason: ApprovalEnd) {
        self.state.lock().unwrap().get_or_insert(reason);
    }

    fn ended(&self) -> Option<ApprovalEnd> { *self.state.lock().unwrap() }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    pub(crate) fn cancellation_code(&self) -> u8 {
        self.ended().map_or(0, |reason| reason as u8)
    }
}

pub enum ApprovalAnswer { Approve, Refuse, Timeout }

/// The member's own decision on one payment, asked on this device (the native app's dialog).
/// Receives the signer-derived summary as JSON and the lifetime of this approval attempt.
/// Without one, every payment is refused: HTTP or relay requests never approve on their own.
pub type LocalApproval = std::sync::Arc<dyn Fn(&str, &ApprovalAttempt) -> ApprovalAnswer + Send + Sync>;

/// The member's answer when LokiSigner asks them to compare a vault's roster code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterAnswer {
    /// "Codes match": every member sees the same code.
    Match,
    /// "Codes differ": this vault is refused until the app restarts.
    Differ,
    /// The dialog closed or timed out, or the request could not be shown. A retry may ask again.
    NoAnswer,
}

/// The member's own comparison of a vault's roster code before key generation, asked on this
/// device. Receives the summary `/api/agree` derives from the setup document as JSON.
/// Only [`RosterAnswer::Match`] records agreement; no local answer means no agreement.
pub type LocalRosterConfirmation = std::sync::Arc<dyn Fn(&str) -> RosterAnswer + Send + Sync>;

fn terminal_roster_confirmation(summary: &str) -> RosterAnswer {
    #[cfg(unix)]
    {
        use rustix::{
            event::{poll, PollFd, PollFlags, Timespec}, process::getpgrp,
            termios::{tcflush, tcgetattr, tcgetpgrp, LocalModes, QueueSelector},
        };
        use std::io::{BufRead, Read, Write};
        let ask = || -> Option<RosterAnswer> {
            let facts: serde_json::Value = serde_json::from_str(summary).ok()?;
            let code = facts["roster_code"].as_str()?;
            let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
            if tcgetpgrp(&tty).ok()? != getpgrp()
                || !tcgetattr(&tty).ok()?.local_modes.contains(LocalModes::ICANON) { return None; }
            tcflush(&tty, QueueSelector::IFlush).ok()?;
            writeln!(tty, "\nLokiSigner — compare the roster on every signer's trusted screen or terminal.\n{summary}\nType the exact roster code if all codes match, or 'differ' if they do not:").ok()?;
            let mut fds = [PollFd::new(&tty, PollFlags::IN)];
            if poll(&mut fds, Some(&Timespec { tv_sec: 120, tv_nsec: 0 })).ok()? == 0 ||
                !fds[0].revents().contains(PollFlags::IN) || tcgetpgrp(&tty).ok()? != getpgrp() {
                return None;
            }
            let mut answer = String::new();
            std::io::BufReader::new(tty.take(64)).read_line(&mut answer).ok()?;
            if !answer.ends_with('\n') { return None; }
            match answer.trim() {
                text if text == code => Some(RosterAnswer::Match),
                "differ" => Some(RosterAnswer::Differ),
                _ => None,
            }
        };
        ask().unwrap_or(RosterAnswer::NoAnswer)
    }
    #[cfg(not(unix))]
    { let _ = summary; RosterAnswer::NoAnswer }
}

/// What a native window shows in place of a vault name it will not show.
pub(crate) const HIDDEN_VAULT_NAME: &str = "Name hidden (unsupported characters)";

/// The creator's vault name as LokiSigner shows it, in the roster dialog and in
/// "Vault addresses…". A name is shown as written or hidden whole, never cleaned: hidden when
/// it has no letter, is longer than 80 characters or holds a control character, whitespace other than a
/// space, a format character (Cf, such as bidi overrides and zero-width joiners), a default
/// ignorable character (such as variation selectors and U+034F), or a run of more than three
/// combining marks, which draw outside a one-line box.
pub(crate) fn vault_label(name: &str) -> &str {
    use icu_properties::{props::{DefaultIgnorableCodePoint, GeneralCategory, GeneralCategoryGroup}, CodePointMapData, CodePointSetData};
    let category = CodePointMapData::<GeneralCategory>::new();
    let ignorable = CodePointSetData::new::<DefaultIgnorableCodePoint>();
    let mut marks = 0;
    let mut has_letter = false;
    let unsupported = name.chars().count() > 80 || name.chars().any(|c| {
        let general = category.get(c);
        has_letter |= GeneralCategoryGroup::Letter.contains(general);
        marks = if matches!(general, GeneralCategory::NonspacingMark | GeneralCategory::EnclosingMark) { marks + 1 } else { 0 };
        c.is_control() || (c.is_whitespace() && c != ' ') || general == GeneralCategory::Format
            || ignorable.contains(c) || marks > 3
    });
    if unsupported || !has_letter { HIDDEN_VAULT_NAME } else { name }
}

/// The signer's [`ApprovalPolicy`](crate::signer::local::ApprovalPolicy): route each request
/// to the member's local decision, and refuse when no approval channel is attached.
pub fn approval_policy(
    approval: Option<LocalApproval>,
    network: crate::signer::Network,
    slot: u16,
    attempt: Option<std::sync::Arc<ApprovalAttempt>>,
) -> crate::signer::local::ApprovalPolicy {
    use std::sync::atomic::Ordering;
    let attempt = attempt.unwrap_or_default();
    Box::new(move |request| {
        let approved = approval.as_ref().is_some_and(|approve| {
            if attempt.ended().is_some() { return false; }
            let summary = approval_summary(request, network, slot, attempt.vault_name.as_deref());
            attempt.waiting.store(true, Ordering::Release);
            let answer = approve(&summary, &attempt);
            attempt.waiting.store(false, Ordering::Release);
            if attempt.ended().is_some() { return false; }
            match answer {
                ApprovalAnswer::Approve => true,
                ApprovalAnswer::Refuse | ApprovalAnswer::Timeout => {
                    if attempt.vault_name.is_some() {
                        attempt.end(if matches!(answer, ApprovalAnswer::Timeout) { ApprovalEnd::LocalTimeout }
                            else { ApprovalEnd::LocalRefused });
                    }
                    false
                }
            }
        });
        let id = hex::encode(request.candidate.attempt_id);
        let outcome = match attempt.ended() {
            Some(ApprovalEnd::LocalTimeout) => "timed out",
            Some(ApprovalEnd::LocalRefused) | None if !approved => "refused",
            Some(_) => "ended",
            None => "approved",
        };
        eprintln!("payment {id}: member {slot} approval {outcome}");
        approved
    })
}

/// A scripted reviewer in place of the native dialog (`loki_member_app --approve-from <file>`),
/// for test harnesses. Each request's summary is printed as an `approval-request <json>` line
/// on stderr; the member approves only when `approve <sighash>` for that request appears in
/// `file` within `timeout`. `refuse <sighash>`, no answer, or an unreadable summary refuse.
pub fn file_approval(file: std::path::PathBuf, timeout: std::time::Duration) -> LocalApproval {
    std::sync::Arc::new(move |summary, _| {
        let Some(sighash) = serde_json::from_str::<serde_json::Value>(summary)
            .ok()
            .and_then(|v| v["sighash"].as_str().map(str::to_owned))
        else {
            return ApprovalAnswer::Refuse;
        };
        eprintln!("approval-request {summary}");
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            for line in std::fs::read_to_string(&file).unwrap_or_default().lines() {
                match line.split_once(' ') {
                    Some(("approve", h)) if h == sighash => return ApprovalAnswer::Approve,
                    Some(("refuse", h)) if h == sighash => return ApprovalAnswer::Refuse,
                    _ => {}
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        ApprovalAnswer::Refuse
    })
}

/// What the member reviews: the payee, amounts and network the signer derived itself from the
/// PCZT bytes, and the candidate and sighash its consent binds to.
pub fn approval_summary(request: &crate::signer::local::ApprovalRequest<'_>, network: crate::signer::Network, slot: u16, vault_name: Option<&str>) -> String {
    use zcash_protocol::consensus::NetworkType;
    let (label, kind) = match network {
        crate::signer::Network::Regtest => ("regtest", NetworkType::Regtest),
        crate::signer::Network::Testnet => ("testnet", NetworkType::Test),
    };
    let view = request.view;
    let mut summary = serde_json::json!({
        "recipient": crate::vault::unified_receiver(view.to, kind),
        "amount_zat": view.amount_zat,
        "fee_zat": view.fee_zat,
        "fee_verified": view.fee_verified,
        "change_zat": view.change_zat,
        "memo": String::from_utf8_lossy(&view.memo).trim_end_matches('\0'),
        "network": label,
        "branch_id": format!("{:08x}", view.network_branch_id),
        "vault": hex::encode(request.candidate.vault_id),
        "member": slot,
        "payment": hex::encode(request.candidate.payment_id),
        "attempt": hex::encode(request.candidate.attempt_id),
        "sighash": hex::encode(request.sighash),
    });
    if let Some(name) = vault_name {
        summary["vault_name"] = vault_label(name).into();
        summary["expiry_height"] = view.expiry_height.into();
    }
    summary.to_string()
}

/// Parse member-app CLI args into a `Config`. Shared by the `loki_member_app` bin and the native
/// signer app's FFI `serve` entry point, so both build the member identically.
pub fn config_from_args(args: &[String]) -> Result<Config, String> {
    parse_config(args, false)
}

pub(crate) fn native_config_from_args(args: &[String]) -> Result<Config, String> {
    let mut config = parse_config(args, true)?;
    config.secure_element = "apple".into();
    Ok(config)
}

fn new_token() -> String {
    use base64::Engine;
    use rand_core::{OsRng, RngCore};
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
}

fn parse_config(args: &[String], native: bool) -> Result<Config, String> {
    use std::{collections::BTreeMap, path::PathBuf};
    let value = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    let flag = |name: &str| args.iter().any(|a| a == name);
    let data = value("--data").map(PathBuf::from).ok_or("--data <dir> is required")?;
    let port = value("--port").and_then(|p| p.parse::<u16>().ok()).ok_or("--port <n> is required")?;
    let bind = if flag("--bind") {
        value("--bind").and_then(|a| a.parse::<std::net::IpAddr>().ok()).ok_or("--bind requires an IP address")?
    } else {
        std::net::Ipv4Addr::LOCALHOST.into()
    };
    let peer_port = if flag("--peer-port") {
        Some(value("--peer-port").and_then(|p| p.parse::<u16>().ok()).filter(|&p| p != 0)
            .ok_or("--peer-port requires a nonzero port")?)
    } else { None };
    if flag("--secure-element") && value("--secure-element").is_none() {
        return Err("--secure-element requires <software|apple>".into());
    }
    let mut peers = BTreeMap::new();
    for (index, arg) in args.iter().enumerate() {
        if arg == "--peer" {
            let (slot, url) = args.get(index + 1).and_then(|s| s.split_once('=')).ok_or("--peer requires <slot=baseurl>")?;
            let slot = slot.parse::<u16>().map_err(|_| format!("invalid peer slot: {slot}"))?;
            if slot == 0 || !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(format!("invalid peer: {slot}={url}"));
            }
            peers.insert(slot, url.trim_end_matches('/').to_owned());
        }
    }
    let network = value("--network").unwrap_or_else(|| "regtest".into());
    crate::network::VaultNetwork::parse(&network)?;
    Ok(Config {
        data, port, bind, peer_port, native,
        registration: RegistrationConfig::from_args(args, flag("--development-http"))?,
        advertise_url: value("--advertise-url"),
        network,
        lightwalletd: value("--lightwalletd-url"),
        transport: value("--transport").unwrap_or_else(|| "local".into()),
        secure_element: value("--secure-element").unwrap_or_else(|| "software".into()),
        operator_bundle: value("--operator-bundle").map(PathBuf::from),
        nonce_witnesses: value("--nonce-witnesses").map(PathBuf::from),
        operator_key: value("--operator-key"),
        enrollment_issuer: value("--enrollment-issuer").map(PathBuf::from),
        development_http: flag("--development-http"),
        token: if native { String::new() } else { new_token() },
        frostd_url: value("--frostd-url").unwrap_or_else(|| "http://127.0.0.1:2744".into()),
        peers,
        loopback_peers: flag("--allow-loopback-peers"),
    })
}

/// Build the axum app and serve on the configured bind IP and port. Blocks.
pub fn run(config: Config) -> Result<(), String> {
    run_headless(config, None, false)
}

/// Serve the member CLI. `pairing_stdout` reserves stdout for a bare link on a private pipe.
pub fn run_headless(config: Config, approval: Option<LocalApproval>, pairing_stdout: bool) -> Result<(), String> {
    let confirm = std::sync::Arc::new(terminal_roster_confirmation);
    run_local_with(config, None, None, approval, Some(confirm), None, pairing_stdout, None, None, |_| Ok(()))
}

/// `fetched`: the native app's confirmed configuration snapshot. Fresh settings without
/// overrides are saved only after unlock. Without a local roster prompt this entry point
/// cannot agree. LokiSigner starts through `run_native`.
pub fn run_local(
    config: Config,
    pass: Option<zeroize::Zeroizing<String>>,
    notice: Option<LocalNotice>,
    approval: Option<LocalApproval>,
    fetched: Option<FetchedConfig>,
) -> Result<(), String> {
    run_local_with(config, pass, notice, approval, None, fetched, false, None, None, |_| Ok(()))
}

fn run_local_with<G>(
    mut config: Config,
    pass: Option<zeroize::Zeroizing<String>>,
    notice: Option<LocalNotice>,
    approval: Option<LocalApproval>,
    roster_confirmation: Option<LocalRosterConfirmation>,
    fetched: Option<FetchedConfig>,
    pairing_stdout: bool,
    stopping: Option<tokio::sync::watch::Sender<bool>>,
    connect: Option<connect::LocalConnect>,
    on_start: impl FnOnce(&state::Shared) -> Result<G, String>,
) -> Result<(), String> {
    if !config.bind.is_loopback() {
        return Err("the member HTTP API requires a loopback --bind; use a local TLS proxy to --peer-port for remote ceremony traffic".into());
    }
    match (config.peer_port, config.advertise_url.as_deref()) {
        (Some(_), Some(origin)) => { registration::plain_origin(origin, true)?; }
        (None, None) => {}
        _ => return Err("--peer-port and --advertise-url must be set together".into()),
    }
    // rustls has no default provider; install one before any relay/lightwalletd TLS.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // Peer origins must use TLS off loopback (preserved from main's hardening).
    for url in config.peers.values() {
        crate::transport::require_tls_off_loopback(url)?;
    }
    let _data_lock = if config.native { None } else { Some(recovery::lock_headless_data(&config.data)?) };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    let mut scope = None;
    let result = runtime.block_on(async {
        let addr = std::net::SocketAddr::new(config.bind, config.port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        config.port = addr.port();
        let peer_listener = if let Some(port) = config.peer_port {
            let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port);
            Some(tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("peer bind {addr}: {e}"))?)
        } else { None };
        let wallet_tabs = connect.zip(config.registration.as_ref()).map(|(ask, registration)| {
            let endpoint = config.lokisigner_url().ok_or("LokiSigner needs a loopback listener")?;
            Ok::<_, &str>(connect::WalletTabs::new(endpoint, registration.coordinator.clone(), ask))
        }).transpose()?;
        let native = stopping.is_some();
        let state = std::sync::Arc::new(state::AppState { approval, notice: notice.clone(), roster_confirmation,
            fetched_config: fetched, wallet_tabs, stopping: stopping.unwrap_or_else(|| tokio::sync::watch::Sender::new(false)),
            ..state::AppState::new(config) });
        scope = Some(on_start(&state)?);
        let serve = async {
            let ready = registration::start(&state, pass, notice.as_ref()).await?;
            if state.config.native {
                if let Some(notice) = notice { notice(ready, ""); }
            } else if let Some(notice) = notice {
                notice(ready, &format!("http://{addr}/#{}", state.config.token));
            } else if pairing_stdout {
                use std::io::Write;
                writeln!(std::io::stdout(), "http://{addr}/#{}", state.config.token)
                    .map_err(|e| format!("pairing output: {e}"))?;
            } else if let Some(launch) = &state.config.registration {
                println!("{} ({}) — Local pairing: http://{addr}/#{}", launch.name, state.config.data.display(), state.config.token);
            } else {
                println!("Signer: http://{addr}/#{}", state.config.token);
            }
            let local = async {
                axum::serve(listener, routes::router(state.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>()).await
            };
            let peers = async {
                if let Some(listener) = peer_listener {
                    axum::serve(listener, routes::peer_router(state.clone())).await?;
                }
                Ok(())
            };
            tokio::try_join!(local, peers).map(|_| ()).map_err(|e| format!("serve: {e}"))
        };
        if native {
            let result = tokio::select! {
                biased;
                _ = state.wait_for_stop() => Ok(()),
                result = serve => result,
            };
            state.stopping.send_replace(true);
            state.lock_session().await;
            result
        } else {
            serve.await
        }
    });
    // Keep the profile claimed until its blocking workers have drained.
    drop(runtime);
    drop(scope);
    result
}

#[cfg(test)]
mod tests {
    use super::{ApprovalAnswer, ApprovalAttempt};
    use crate::signer::{local::ApprovalRequest, wysiwys::PaymentView, CandidateRef, Network};
    use std::sync::{Arc, Mutex};

    #[test]
    fn payment_approval_fails_closed_and_asks_with_signer_derived_details() {
        let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let to = orchard::keys::FullViewingKey::from(&sk).address_at(0u64, orchard::keys::Scope::External);
        let view = PaymentView {
            to: to.to_raw_address_bytes(), amount_zat: 40_000_000, fee_zat: 15_000, change_zat: 5,
            memo: b"rent\nRecipient: fake\nAmount: 1 ZEC".to_vec(), expiry_height: 1_152, network_branch_id: 0x77190ad8, fee_verified: true,
        };
        let candidate = CandidateRef { vault_id: [1; 32], payment_id: [2; 32], attempt_id: [3; 32] };
        let request = ApprovalRequest { candidate: &candidate, sighash: [9; 32], view: &view };
        // No approval channel (headless serve): refused.
        assert!(!(super::approval_policy(None, Network::Testnet, 2, None))(&request));

        let asked = Arc::new(Mutex::new(Vec::new()));
        let decision = Arc::new(Mutex::new(false));
        let (log, answer) = (asked.clone(), decision.clone());
        let approve: super::LocalApproval = Arc::new(move |summary, _| {
            log.lock().unwrap().push(summary.to_owned());
            if *answer.lock().unwrap() { ApprovalAnswer::Approve } else { ApprovalAnswer::Refuse }
        });
        let policy = || super::approval_policy(Some(approve.clone()), Network::Testnet, 2,
            Some(Arc::new(ApprovalAttempt::named("Household".into()))));
        assert!(!policy()(&request), "the member's refusal refuses");
        *decision.lock().unwrap() = true;
        assert!(policy()(&request), "the member's approval approves");

        let asked = asked.lock().unwrap();
        assert_eq!(asked[0].lines().count(), 1, "a memo cannot add a summary line");
        let shown: serde_json::Value = serde_json::from_str(&asked[0]).unwrap();
        let recipient = shown["recipient"].as_str().unwrap();
        assert!(recipient.starts_with("utest1"), "{recipient}");
        let decoded = crate::vault::orchard_receiver_from_ua(recipient, zcash_protocol::consensus::NetworkType::Test).unwrap();
        assert_eq!(decoded.to_raw_address_bytes(), view.to);
        assert_eq!(shown["amount_zat"], 40_000_000);
        assert_eq!(shown["fee_zat"], 15_000);
        assert_eq!(shown["network"], "testnet");
        assert_eq!(shown["member"], 2);
        assert_eq!(shown["memo"], "rent\nRecipient: fake\nAmount: 1 ZEC");
        assert_eq!(shown["vault_name"], "Household");
        assert_eq!(shown["vault"], hex::encode([1; 32]));
        assert_eq!(shown["expiry_height"], 1_152);
        assert_eq!(shown["attempt"], hex::encode([3; 32]));
        assert_eq!(shown["sighash"], hex::encode([9; 32]));

        let hidden: serde_json::Value = serde_json::from_str(&super::approval_summary(
            &request, Network::Testnet, 2, Some("Household\nExpiry height: 999"))).unwrap();
        assert_eq!(hidden["vault_name"], super::HIDDEN_VAULT_NAME);
        let headless: serde_json::Value = serde_json::from_str(&super::approval_summary(
            &request, Network::Testnet, 2, None)).unwrap();
        assert!(headless.get("vault_name").is_none() && headless.get("expiry_height").is_none());
    }

    #[test]
    fn a_vault_name_is_shown_as_written_or_hidden_whole() {
        for shown in ["Household", "Friends’ vault", "Tiền nhà", "Tie\u{0323}\u{0302}n", "家族 🏠", "2026年", &"é".repeat(80)] {
            assert_eq!(super::vault_label(shown), shown, "{shown:?}");
        }
        let marks = |n: usize| format!("Rent{}", "\u{0301}".repeat(n));
        assert_eq!(super::vault_label(&marks(3)), marks(3));
        for hidden in [
            "1234 5678 9012 3456 7890 1234".into(), "１２３４".into(), "1234-5678".into(), "1234\u{05b0}".into(),
            "Rent\nChoose Codes match".to_owned(), "a\u{0085}b".into(), "a\u{2028}b".into(), "a\u{202e}b".into(),
            "a\u{001b}[2Jb".into(), "a\u{200b}b".into(), "a\u{feff}b".into(), "a\tb".into(),
            // Format and default ignorable characters the review found shown as written.
            "a\u{0600}b".into(), "a\u{13430}b".into(), "a\u{1bca0}b".into(), "a\u{1d173}b".into(),
            "a\u{e0100}b".into(), "a\u{034f}b".into(), "a\u{fe0f}b".into(), "a\u{3164}b".into(),
            // A base letter with 39 combining marks draws far outside its line.
            format!("a{}", "\u{0301}".repeat(39)), marks(4), "é".repeat(81),
        ] {
            assert_eq!(super::vault_label(&hidden), super::HIDDEN_VAULT_NAME, "{hidden:?}");
        }
    }

    #[test]
    fn file_approval_approves_only_its_own_sighash() {
        let file = std::env::temp_dir().join(format!("loki-approvals-{}", uuid::Uuid::new_v4()));
        let wait = std::time::Duration::from_millis(600);
        let scripted = super::file_approval(file.clone(), wait);
        let approve = |summary: &str| matches!(scripted(summary, &ApprovalAttempt::default()), ApprovalAnswer::Approve);
        let summary = |sighash: &str| serde_json::json!({ "sighash": sighash }).to_string();
        assert!(!approve(&summary("aa")), "no answer refuses");
        assert!(!approve("not json"), "an unreadable summary refuses");
        std::fs::write(&file, "approve bb\nrefuse cc\napprove aaa\n").unwrap();
        assert!(approve(&summary("bb")));
        assert!(!approve(&summary("cc")), "an explicit refusal refuses");
        assert!(!approve(&summary("aa")), "another sighash's approval does not approve this one");
        std::fs::remove_file(file).unwrap();
    }
}
