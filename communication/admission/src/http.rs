use crate::{store::parse_package, AdmissionError, AdmissionStore};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use loki_http_ingress::PeerGate;
use loki_relay_protocol::{
    admission,
    canonical::{self, Value},
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, Semaphore};
use zeroize::Zeroizing;

const BODY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct Service {
    store: Arc<Mutex<AdmissionStore>>,
    ingress: PeerGate,
    gate: Arc<Semaphore>,
    deadline: Duration,
    provision: Arc<Notify>,
}
fn public_error(status: StatusCode, code: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(
            canonical::encode(&Value::Array(vec![Value::Text(code.into())])).unwrap_or_default(),
        ))
        .unwrap()
}
pub fn router(store: Arc<Mutex<AdmissionStore>>) -> Router {
    router_with_provisioning(
        store,
        Arc::new(Notify::new()),
        Arc::new(AtomicBool::new(true)),
    )
}
/// As `router`, waking `provision` after accepted mailbox and terminal commands.
/// `/health` reflects worker readiness.
pub fn router_with_provisioning(
    store: Arc<Mutex<AdmissionStore>>,
    provision: Arc<Notify>,
    ready: Arc<AtomicBool>,
) -> Router {
    let deadline = Duration::from_secs(
        store
            .lock()
            .map(|store| store.request_seconds())
            .unwrap_or(1),
    );
    let service = Service {
        store,
        deadline,
        ingress: PeerGate::new(16, 4),
        gate: Arc::new(Semaphore::new(16)),
        provision,
    };
    Router::new()
        .route(
            "/health",
            get(move || async move {
                if ready.load(Ordering::Relaxed) {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        )
        .route("/v1/setup", post(handle))
        .route("/v1/setup/{ceremony}", get(handle))
        .route("/v1/setup/{ceremony}/claims/{slot}", post(handle))
        .route("/v1/setup/{ceremony}/mailboxes", post(handle))
        .route("/v1/setup/{ceremony}/checkpoints/{slot}", post(handle))
        .route("/v1/setup/{ceremony}/terminal", post(handle))
        .route(
            "/v1/setup/{ceremony}/terminal-notices",
            get(handle).post(handle),
        )
        .with_state(service)
}
async fn handle(State(service): State<Service>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;
    if parts.uri.query().is_some()
        || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers.get_all(header::AUTHORIZATION).iter().count() > 1
        || headers.get_all(header::CONTENT_LENGTH).iter().count() > 1
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/cbor")
        || headers.contains_key(header::CONTENT_ENCODING)
        || headers.get(header::CONTENT_LENGTH).is_some_and(|value| {
            !matches!(value.to_str().ok().and_then(|v| v.parse::<usize>().ok()), Some(n) if n <= admission::MAX_REQUEST)
        })
    {
        return public_error(StatusCode::BAD_REQUEST, "malformed");
    }
    let credential = match headers.get(header::AUTHORIZATION) {
        None => None,
        Some(header) => {
            let decoded = (|| {
                let text = header.to_str().map_err(|_| AdmissionError::Malformed)?;
                if text.len() > 5500 {
                    return Err(AdmissionError::Malformed);
                }
                let token = text
                    .strip_prefix("Bearer ")
                    .ok_or(AdmissionError::Malformed)?;
                let decoded = Zeroizing::new(
                    URL_SAFE_NO_PAD
                        .decode(token)
                        .map_err(|_| AdmissionError::Malformed)?,
                );
                if decoded.len() > 4096 {
                    return Err(AdmissionError::Malformed);
                }
                Ok(decoded)
            })();
            match decoded {
                Ok(credential) => Some(credential),
                Err(error) => return public_error(StatusCode::BAD_REQUEST, error.code()),
            }
        }
    };
    let Some(ingress) = service.ingress.try_acquire(&parts.extensions) else {
        return public_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    let body = match tokio::time::timeout(
        BODY_TIMEOUT.min(service.deadline),
        to_bytes(body, admission::MAX_REQUEST),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return public_error(StatusCode::BAD_REQUEST, "malformed"),
        Err(_) => return public_error(StatusCode::GATEWAY_TIMEOUT, "unavailable"),
    };
    let request = match parse_package(&body) {
        Ok(request) => request,
        Err(error) => return public_error(StatusCode::BAD_REQUEST, error.code()),
    };
    let wakes_provisioner = matches!(
        request.command,
        admission::AdmissionCommand::Mailbox { .. } | admission::AdmissionCommand::Terminal { .. }
    );
    let (expected_method, path) = admission::request_target(&request.command);
    if parts.method.as_str() != expected_method || parts.uri.path() != path {
        return public_error(StatusCode::BAD_REQUEST, "malformed");
    }
    drop(ingress);
    let Ok(permit) = service.gate.clone().try_acquire_owned() else {
        return public_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    let provision = service.provision.clone();
    let deadline = service.deadline;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut store = service
            .store
            .lock()
            .map_err(|_| AdmissionError::Unavailable)?;
        let result = store.execute(&body, credential.as_ref().map(|c| c.as_slice()), || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|now| now.as_secs())
                .map_err(|_| AdmissionError::Unavailable)
        });
        drop(store);
        if wakes_provisioner && matches!(&result, Ok(reply) if reply.error.is_none()) {
            provision.notify_one();
        }
        result
    });
    let Ok(result) = tokio::time::timeout(deadline, result).await else {
        return public_error(StatusCode::GATEWAY_TIMEOUT, "unavailable");
    };
    match result {
        Ok(Ok(reply)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/cbor")
            .body(Body::from(reply.bytes))
            .unwrap(),
        Ok(Err(error)) => public_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
        Err(_) => public_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}
