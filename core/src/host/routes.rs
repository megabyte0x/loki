use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    ceremony, connect, device, payment, recovery,
    state::{Session, Shared},
};

pub(super) type Reply = (StatusCode, Json<Value>);

pub(super) fn ok(v: Value) -> Reply {
    (StatusCode::OK, Json(v))
}

pub(super) fn err(code: StatusCode, message: impl Into<String>) -> Reply {
    let message = message.into();
    let mut body = json!({ "error": message });
    if let Some(code) = error_code(&message) { body["code"] = json!(code); }
    (code, Json(body))
}

/// A stable code for the host's own error sentences, so the wallet can show its own wording
/// instead of the text. Errors without a code are shown only after sanitizing.
pub(super) fn error_code(error: &str) -> Option<&'static str> {
    use payment::{ENOUGH_APPROVED, REPEATED_APPROVAL, TOO_MANY_NOTES};
    Some(match error {
        e if e.starts_with(crate::wallet_store::FUNDS_WAITING) => "funds_pending_confirmation",
        e if e == TOO_MANY_NOTES || e == "notes cannot cover amount and fee" => "too_many_notes",
        e if e.starts_with("fund payment:") => "insufficient_funds",
        e if e.starts_with("not a unified address") || e.starts_with("that address ")
            || e == "the Orchard receiver is not a valid address" => "invalid_address",
        "amount must exceed zero" | "invalid amount_zat" => "invalid_amount",
        "profile is locked" => "profile_locked",
        "Touch ID is required to open this vault." => "touch_id_required",
        e if e == ENOUGH_APPROVED => "enough_approved",
        e if e == REPEATED_APPROVAL => "approval_repeated",
        _ => return None,
    })
}

/// Run a blocking library call (which drives the relay runtime via `block_on`) off the
/// async worker threads — calling it inline would panic (runtime-within-runtime).
pub(super) async fn blocking<F>(f: F) -> Reply
where
    F: FnOnce() -> Result<Value, String> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => ok(v),
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, e),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("task join: {e}")),
    }
}

fn ceremony_routes() -> Router<Shared> {
    Router::new()
        .route("/api/enroll", post(ceremony::enroll))
        .route("/api/roster", post(ceremony::roster))
        .route("/api/agreed", post(ceremony::agreed))
        .route("/api/session", post(ceremony::session))
}

pub(super) fn peer_router(state: Shared) -> Router {
    ceremony_routes()
        .layer(middleware::from_fn_with_state(state.clone(), browser_origin))
        .with_state(state)
}

pub fn router(state: Shared) -> Router {
    let router = if state.wallet_tabs.is_some() {
        Router::new().route("/api/connect", post(connect::request))
    } else {
        Router::new()
    };
    router
        .route("/api/profile-create", post(profile_create))
        .route("/api/unlock", post(unlock))
        .route("/api/lock", post(lock))
        .route("/api/status", get(status))
        .route("/api/registration", get(registration))
        .route("/api/create", post(ceremony::create))
        .route("/api/join", post(ceremony::join))
        .route("/api/agree", post(ceremony::agree))
        .route("/api/address", get(ceremony::address))
        .route("/api/balance", post(payment::balance))
        .route("/api/payment-draft", post(payment::draft))
        .route("/api/payment-publish", post(payment::publish))
        .route("/api/payment-review", post(payment::review))
        .route("/api/payment-approve", post(payment::approve))
        .route("/api/payment-discard", post(payment::discard))
        .route("/api/payment-send", post(payment::send))
        .route("/api/payment-replace", post(payment::replace))
        .route("/api/payment-verify", post(payment::verify))
        .route("/api/payments", get(payment::payments))
        .route("/api/pending", get(payment::pending))
        .route("/api/payment-status", get(payment::status))
        .route("/api/recovery-setup", post(recovery::local_only))
        .route("/api/recovery-status", get(recovery::status))
        .route("/api/recovery-backup", get(recovery::fetch))
        .route("/api/recovery-restore", post(recovery::local_only))
        .route("/api/device-enroll", post(device::enroll))
        .route("/api/device-renewal", post(device::renewal))
        .route("/api/device-challenge", get(device::challenge))
        .route("/api/device-login", post(device::login))
        .route("/api/device-revoke", post(device::revoke))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .merge(ceremony_routes())
        .layer(middleware::from_fn_with_state(state.clone(), browser_origin))
        .with_state(state)
}

/// Only the explicitly paired browser origin can read this device's API. The process
/// capability is still required; CORS never authorizes a member action on its own.
async fn browser_origin(State(st): State<Shared>, req: Request, next: Next) -> Response {
    let origin = req.headers().get("origin").cloned();
    let route = req.extensions().get::<axum::extract::MatchedPath>().cloned();
    if req.uri().path() == "/api/connect" {
        let Some(tabs) = &st.wallet_tabs else { return StatusCode::NOT_FOUND.into_response(); };
        if !tabs.permits_request(&req) { return StatusCode::FORBIDDEN.into_response(); }
    }
    // The browser signer's join worker runs on a separate origin and needs CORS on these four
    // routes. Ceremony handlers check the invite token, not the local process token.
    let open_ceremony = matches!(
        req.uri().path(),
        "/api/enroll" | "/api/agreed" | "/api/roster" | "/api/session"
    );
    if let Some(origin) = &origin {
        if !open_ceremony {
            let allowed = st.config.registration.as_ref().map(|c| c.coordinator.as_str());
            if allowed.is_none() || origin.to_str().ok() != allowed {
                return err(StatusCode::FORBIDDEN, "browser origin is not paired").into_response();
            }
        }
    }
    let mut response = if req.method() == axum::http::Method::OPTIONS {
        let method = req.headers().get("access-control-request-method").and_then(|v| v.to_str().ok());
        let headers = req.headers().get("access-control-request-headers").and_then(|v| v.to_str().ok()).unwrap_or("");
        if origin.is_none() || !matches!(method, Some("GET" | "POST"))
            || headers.split(',').any(|h| !matches!(h.trim().to_ascii_lowercase().as_str(), "" | "content-type" | "x-loki-token")) {
            return err(StatusCode::FORBIDDEN, "unsupported browser request").into_response();
        }
        StatusCode::NO_CONTENT.into_response()
    } else { next.run(req).await };
    if response.status().is_client_error() || response.status().is_server_error() {
        if let Some(route) = route {
            eprintln!("member API {}: error status {}", route.as_str(), response.status().as_u16());
        }
    }
    if let Some(origin) = origin {
        let headers = response.headers_mut();
        headers.insert("access-control-allow-origin", origin);
        headers.insert("access-control-allow-methods", "GET, POST".parse().unwrap());
        headers.insert("access-control-allow-headers", "content-type, x-loki-token".parse().unwrap());
        headers.insert("access-control-allow-private-network", "true".parse().unwrap());
        headers.insert("vary", "Origin".parse().unwrap());
    }
    response.headers_mut().insert("cache-control", "no-store".parse().unwrap());
    response
}

async fn registration(State(st): State<Shared>) -> Reply {
    match st.registration.read().await.as_ref() {
        Some(member) => ok(json!(member)),
        None => match st.registration_error.read().await.as_ref() {
            Some(e) => err(StatusCode::CONFLICT, format!("device has not self-registered; retrying after: {e}")),
            None => err(StatusCode::CONFLICT, "device has not self-registered"),
        },
    }
}

/// Require a device capability except for the native connect handshake (which is origin-
/// and loopback-checked before reaching this middleware).
async fn auth(State(st): State<Shared>, req: Request, next: Next) -> Result<Response, Response> {
    if st.is_stopping() {
        return Err(err(StatusCode::UNAUTHORIZED, "profile is locked").into_response());
    }
    // Only the embedded dispatcher can create this typed extension, never an HTTP client.
    #[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
    if st.config.native && req.extensions().get::<super::native_member::InProcess>().is_some() {
        return Ok(next.run(req).await);
    }
    if req.uri().path() == "/api/connect" && st.wallet_tabs.is_some() {
        return Ok(next.run(req).await);
    }
    let presented = req
        .headers()
        .get("x-loki-token")
        .and_then(|v| v.to_str().ok());
    let authorized = presented.is_some_and(|token| match &st.wallet_tabs {
        Some(tabs) => tabs.authorizes(&req, token),
        None => !st.config.token.is_empty() && token == st.config.token,
    });
    if authorized {
        Ok(next.run(req).await)
    } else {
        Err(err(StatusCode::UNAUTHORIZED, "invalid process token").into_response())
    }
}

fn str_field(body: &Value, name: &str) -> Result<String, Reply> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, format!("missing {name}")))
}

async fn profile_create(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let generation = st.session_generation();
    let (name, pass) = match (str_field(&body, "name"), str_field(&body, "passphrase")) {
        (Ok(n), Ok(p)) => (n, p),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let data = st.config.data.clone();
    let passphrase = Zeroizing::new(pass);
    let for_block = passphrase.clone();
    let reply = blocking(move || crate::profile::create(&data, &for_block, &name)).await;
    if reply.0 == StatusCode::OK {
        // Creating a profile unlocks it (the prototype's behaviour).
        let session = Session { passphrase, data: st.config.data.clone() };
        if !st.activate_session(generation, session).await {
            return err(StatusCode::CONFLICT, "profile created but signer was locked; unlock again");
        }
    }
    reply
}

async fn unlock(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let generation = st.session_generation();
    let pass = match str_field(&body, "passphrase") {
        Ok(p) => p,
        Err(e) => return e,
    };
    let data = st.config.data.clone();
    let passphrase = Zeroizing::new(pass);
    let for_block = passphrase.clone();
    let unlocked = tokio::task::spawn_blocking(move || {
        let unlocked = Session::unlock(data.clone(), for_block.clone())?;
        recovery::seal_missing_backups_logged(&data, &for_block);
        Ok::<_, String>(unlocked)
    });
    match unlocked.await {
        Ok(Ok((session, profile))) => {
            if !st.activate_session(generation, session).await {
                return err(StatusCode::CONFLICT, "signer was locked; unlock again");
            }
            ok(json!({ "unlocked": true, "profile": profile }))
        }
        Ok(Err(e)) => err(StatusCode::UNAUTHORIZED, e),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("task join: {e}")),
    }
}

async fn lock(State(st): State<Shared>) -> Reply {
    st.lock_session().await;
    ok(json!({ "locked": true }))
}

async fn status(
    State(st): State<Shared>,
    axum::extract::Query(query): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> Reply {
    if let Some(vault) = query.get("vault") {
        return ceremony::status(st, vault.clone()).await;
    }
    let network = st.config.network.clone();
    let secure_element = &st.config.secure_element;
    let session = st.session.read().await;
    let Some(session) = session.as_ref() else {
        let phase = if crate::profile::exists(&st.config.data) {
            "locked"
        } else {
            "new_profile"
        };
        return ok(json!({ "phase": phase, "network": network, "secure_element": secure_element }));
    };
    // Unlocked: re-read the profile for its name/id and list the member's vaults.
    match crate::profile::open(&session.data, &session.passphrase) {
        Ok(profile) => {
            let vaults = match ceremony::vault_summaries(&session.data, &session.passphrase) {
                Ok(v) => v,
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
            let mut reply = json!({ "phase": "home", "network": network, "secure_element": secure_element, "profile": profile, "vaults": vaults });
            if st.config.native {
                // Report the running signer's pinned identity, not registration or relay health.
                if let (Some(active), Ok(pinned)) = (&st.config.registration, super::RegistrationConfig::resume(&session.data, false)) {
                    if active.coordinator == pinned.coordinator && active.slot == pinned.slot {
                        reply["paired_coordinator"] = json!(pinned.coordinator);
                    }
                }
            }
            ok(reply)
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
