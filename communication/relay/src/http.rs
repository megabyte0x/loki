use crate::{
    store::{HashPresence, PutClass},
    Capability, DbHandle, RelayError, RelayResult, Role,
};
use axum::{
    body::{Body, Bytes, HttpBody},
    extract::{
        rejection::BytesRejection, DefaultBodyLimit, Extension, FromRequest, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use loki_http_ingress::PeerGate;
use loki_relay_protocol::{
    envelope::MAX_WIRE_LEN,
    http::ErrorCode,
    nonce,
    types::{Id32, Object},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const REQUEST_CONCURRENCY: usize = 32;
const FRESH_REQUEST_LIMIT: usize = 30;
const RESERVED_REQUESTS: usize = 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const UNAUTHENTICATED_BODY_TIMEOUT: Duration = Duration::from_secs(3);
const RETRY_AFTER: HeaderValue = HeaderValue::from_static("1");

#[derive(Clone, Copy)]
enum AdmissionMark {
    Reserved,
    Denied,
}

#[derive(Clone)]
struct Gate {
    inner: Arc<Mutex<GateCounts>>,
    screening: PeerGate,
    rejected_body: PeerGate,
    witness_body: PeerGate,
    identity: PeerGate,
    db: DbHandle,
}
struct GateCounts {
    total: usize,
    fresh: usize,
}
struct RequestPermit {
    gate: Gate,
    fresh: bool,
}
impl Drop for RequestPermit {
    fn drop(&mut self) {
        let mut counts = self
            .gate
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        counts.total = counts.total.saturating_sub(1);
        if self.fresh {
            counts.fresh = counts.fresh.saturating_sub(1);
        }
    }
}
impl Gate {
    fn new(db: DbHandle) -> Self {
        Self {
            inner: Arc::new(Mutex::new(GateCounts { total: 0, fresh: 0 })),
            screening: PeerGate::new(64, REQUEST_CONCURRENCY),
            rejected_body: PeerGate::new(16, 4),
            witness_body: PeerGate::new(16, 4),
            identity: PeerGate::new(16, 8),
            db,
        }
    }

    fn fresh_available(counts: &GateCounts) -> bool {
        counts.total < REQUEST_CONCURRENCY && counts.fresh < FRESH_REQUEST_LIMIT
    }

    /// One of 30 fresh slots. Never the leftover reserved progress slots.
    fn try_acquire_fresh(&self) -> Option<RequestPermit> {
        let mut counts = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if !Self::fresh_available(&counts) {
            return None;
        }
        counts.fresh += 1;
        counts.total += 1;
        Some(RequestPermit {
            gate: self.clone(),
            fresh: true,
        })
    }

    /// A read, or a PUT whose committed hash is already present. Not a fresh body.
    fn try_acquire_progress(&self) -> Option<RequestPermit> {
        let mut counts = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if counts.total >= REQUEST_CONCURRENCY {
            return None;
        }
        let reserved_in_use = counts.total - counts.fresh;
        if counts.fresh >= FRESH_REQUEST_LIMIT && reserved_in_use >= RESERVED_REQUESTS {
            return None;
        }
        counts.total += 1;
        Some(RequestPermit {
            gate: self.clone(),
            fresh: false,
        })
    }
}

async fn deadline(request: Request, next: Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => error_response(RelayError::StorageUnavailable),
    }
}

async fn admit(State(gate): State<Gate>, request: Request, next: Next) -> Response {
    admit_checked(gate, request, next)
        .await
        .unwrap_or_else(error_response)
}

async fn admit_checked(gate: Gate, mut request: Request, next: Next) -> RelayResult<Response> {
    let headers = request.headers();
    let uri = request.uri();
    let method = request.method();
    if uri.path() == "/v1/identity" && matches!(*method, Method::GET | Method::HEAD) {
        bodyless(&request)?;
        id(single(headers, "x-loki-challenge")?.ok_or(RelayError::MalformedRequest)?)?;
        let _permit = gate
            .identity
            .try_acquire(request.extensions())
            .ok_or(RelayError::RateLimit)?;
        return Ok(next.run(request).await);
    }
    let write = *method == Method::PUT;
    let object = path(uri).ok();
    let (target, object_write) = if *method == Method::GET {
        let mailbox = match object {
            Some((mailbox, _)) => mailbox,
            None => page_path(uri)?.0,
        };
        request_headers(headers, method)?;
        bodyless(&request)?;
        (Some((mailbox, Role::Read)), None)
    } else if write {
        if let Some((mailbox, hash)) = object {
            request_headers(headers, method)?;
            (None, Some((mailbox, hash)))
        } else {
            let (mailbox, rotate) = control_path(uri)?;
            control_headers(headers)?;
            (rotate.then_some((mailbox, Role::Admin)), None)
        }
    } else {
        return Err(RelayError::MalformedRequest);
    };
    let capability = capability(headers)?;
    if write && object_write.is_none() && !Gate::fresh_available(&gate.inner.lock().unwrap()) {
        return Err(RelayError::RateLimit);
    }
    let screening = gate
        .screening
        .try_acquire(request.extensions())
        .ok_or(RelayError::RateLimit)?;
    let db = gate.db.clone();
    let screened = tokio::task::spawn_blocking(move || {
        let _screening = screening;
        if let Some((mailbox, hash)) = object_write {
            db.classify_hash(mailbox, hash, capability).map(Some)
        } else {
            db.authenticate(target, &capability).map(|()| None)
        }
    })
    .await
    .map_err(|_| RelayError::StorageUnavailable)?;
    let presence = match screened {
        Ok(presence) => presence,
        Err(RelayError::Capability) if write => {
            // Preserve PUT body errors without granting writer capacity.
            let _permit = gate
                .rejected_body
                .try_acquire(request.extensions())
                .ok_or(RelayError::RateLimit)?;
            request.extensions_mut().insert(AdmissionMark::Denied);
            return tokio::time::timeout(UNAUTHENTICATED_BODY_TIMEOUT, next.run(request))
                .await
                .map_err(|_| RelayError::StorageUnavailable);
        }
        Err(error) => return Err(error),
    };
    let _permit = if !write {
        gate.try_acquire_progress()
    } else if let Some(fresh) = gate.try_acquire_fresh() {
        Some(fresh)
    } else if matches!(presence, Some(HashPresence::Committed)) {
        request.extensions_mut().insert(AdmissionMark::Reserved);
        gate.try_acquire_progress()
    } else {
        None
    }
    .ok_or(RelayError::RateLimit)?;
    Ok(next.run(request).await)
}

fn bodyless(request: &Request) -> RelayResult<()> {
    let headers = request.headers();
    if request.body().size_hint().lower() > MAX_WIRE_LEN as u64 {
        return Err(RelayError::ObjectTooLarge);
    }
    if single(headers, "transfer-encoding")?.is_some()
        || single(headers, "content-length")?.is_some_and(|value| value.parse::<usize>() != Ok(0))
        || !request.body().is_end_stream()
    {
        return Err(RelayError::MalformedRequest);
    }
    Ok(())
}

async fn health(request: Request) -> Response {
    match bodyless(&request) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => error_response(error),
    }
}

/// The caller retains the DbWriter owner for the lifetime of this router.
pub fn router(db: DbHandle) -> Router {
    let gate = Gate::new(db.clone());
    Router::new()
        .route(
            "/v1/mailboxes/{mailbox}/objects/{hash}",
            put(object_route).get(object_route),
        )
        .route(
            "/v1/mailboxes/{mailbox}",
            put(control_route).layer(DefaultBodyLimit::max(MAX_CONTROL_LEN)),
        )
        .route(
            "/v1/mailboxes/{mailbox}/setup",
            put(control_route).layer(DefaultBodyLimit::max(MAX_CONTROL_LEN)),
        )
        .route(
            "/v1/mailboxes/{mailbox}/append-capability",
            put(control_route).layer(DefaultBodyLimit::max(MAX_CONTROL_LEN)),
        )
        .route("/v1/mailboxes/{mailbox}/entries", get(page_route))
        .route("/v1/identity", get(identity_route))
        .fallback(malformed)
        .method_not_allowed_fallback(malformed)
        .layer(DefaultBodyLimit::max(MAX_WIRE_LEN))
        .layer(middleware::from_fn_with_state(gate.clone(), admit))
        .layer(middleware::from_fn(deadline))
        .route(
            "/v1/mailboxes/{mailbox}/nonces/{cid}",
            put(nonce_route)
                .fallback(malformed)
                .route_layer(DefaultBodyLimit::max(nonce::MAX_RECORD))
                .route_layer(Extension(gate))
                .route_layer(middleware::from_fn(deadline)),
        )
        .route("/health", get(health).fallback(malformed))
        .with_state(db)
}

async fn malformed() -> Response {
    error_response(RelayError::MalformedRequest)
}

async fn identity_route(State(db): State<DbHandle>, headers: HeaderMap) -> Response {
    let result: RelayResult<Response> = async {
        let nonce = id(single(&headers, "x-loki-challenge")?.ok_or(RelayError::MalformedRequest)?)?;
        let body = db.challenge(nonce)?.receive().await?;
        Ok(binary(StatusCode::OK, "application/cbor", body))
    }
    .await;
    result.unwrap_or_else(error_response)
}

fn binary(status: StatusCode, media: &'static str, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, media.parse().unwrap());
    response
}

fn error_response(error: RelayError) -> Response {
    let code = ErrorCode::try_from(u64::from(error.code())).expect("defined relay error code");
    let mut response = binary(
        StatusCode::from_u16(code.status()).expect("defined HTTP error status"),
        "application/cbor",
        loki_relay_protocol::http::encode_error(code).expect("bounded error metadata"),
    );
    if error == RelayError::RateLimit {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, RETRY_AFTER);
    }
    response
}

fn id(raw: &str) -> RelayResult<Id32> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(RelayError::MalformedRequest);
    }
    let mut value = [0; 32];
    hex::decode_to_slice(raw, &mut value).map_err(|_| RelayError::MalformedRequest)?;
    Ok(value)
}

fn path(uri: &Uri) -> RelayResult<(Id32, Id32)> {
    // Inspect the raw URI rather than decoded Path extractor values.
    let mut segments = uri.path().split('/');
    let parts = std::array::from_fn::<_, 6, _>(|_| segments.next().unwrap_or(""));
    if uri.query().is_some()
        || segments.next().is_some()
        || parts[..3] != ["", "v1", "mailboxes"]
        || parts[4] != "objects"
    {
        return Err(RelayError::MalformedRequest);
    }
    Ok((id(parts[3])?, id(parts[5])?))
}

fn nonce_path(uri: &Uri) -> RelayResult<(Id32, Id32)> {
    let parts: Vec<_> = uri.path().split('/').collect();
    if uri.query().is_some()
        || parts.len() != 6
        || parts[..3] != ["", "v1", "mailboxes"]
        || parts[4] != "nonces"
    {
        return Err(RelayError::MalformedRequest);
    }
    Ok((id(parts[3])?, id(parts[5])?))
}

fn single<'a>(headers: &'a HeaderMap, name: &'static str) -> RelayResult<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(RelayError::MalformedRequest);
    }
    first
        .map(|v| v.to_str().map_err(|_| RelayError::MalformedRequest))
        .transpose()
}

fn capability(headers: &HeaderMap) -> RelayResult<Capability> {
    let raw = single(headers, "authorization")?.ok_or(RelayError::Capability)?;
    let token = raw.strip_prefix("Bearer ").ok_or(RelayError::Capability)?;
    if token.len() != 43 {
        return Err(RelayError::Capability);
    }
    let mut secret = [0; 32];
    let length = URL_SAFE_NO_PAD
        .decode_slice(token, &mut secret)
        .map_err(|_| RelayError::Capability)?;
    if length != 32 || URL_SAFE_NO_PAD.encode(secret) != token {
        return Err(RelayError::Capability);
    }
    Ok(Capability::new(secret))
}

fn request_headers(headers: &HeaderMap, method: &Method) -> RelayResult<Option<usize>> {
    let media = single(headers, "content-type")?;
    if (method == Method::PUT || media.is_some()) && media != Some("application/octet-stream") {
        return Err(RelayError::UnsupportedMediaType);
    }
    if single(headers, "content-encoding")?.is_some() {
        return Err(RelayError::UnsupportedMediaType);
    }
    let length = single(headers, "content-length")?
        .map(|s| {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RelayError::MalformedRequest);
            }
            s.parse::<usize>().map_err(|_| RelayError::MalformedRequest)
        })
        .transpose()?;
    if let Some(encoding) = single(headers, "transfer-encoding")? {
        if encoding != "chunked" || length.is_some() {
            return Err(RelayError::MalformedRequest);
        }
    }
    if length.is_some_and(|n| n > MAX_WIRE_LEN) {
        return Err(RelayError::ObjectTooLarge);
    }
    Ok(length)
}

async fn object_route(
    State(db): State<DbHandle>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    admission: Option<Extension<AdmissionMark>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    match object_request(db, uri, method, headers, body, admission.map(|mark| mark.0)).await {
        Ok(response) => response,
        Err(error) => error_response(error),
    }
}

async fn nonce_route(Extension(gate): Extension<Gate>, request: Request) -> Response {
    let result: RelayResult<Response> = async {
        let (mailbox, cid) = nonce_path(request.uri())?;
        let headers = request.headers();
        let token = single(headers, "authorization")?
            .and_then(|raw| raw.strip_prefix(nonce::CLAIM_SCHEME))
            .ok_or(RelayError::Capability)?;
        let mut raw = [0; nonce::CLAIM_PROOF_LEN];
        hex::decode_to_slice(token, &mut raw).map_err(|_| RelayError::Capability)?;
        let proof = nonce::ClaimProof::from_bytes(raw);
        let length = request_headers(headers, request.method())?;
        let challenge =
            id(single(headers, "x-loki-challenge")?.ok_or(RelayError::MalformedRequest)?)?;
        if challenge == [0; 32] {
            return Err(RelayError::MalformedRequest);
        }
        // The signature covers the record, so isolate the read and proof check from the writer.
        let ingress = gate
            .witness_body
            .try_acquire(request.extensions())
            .ok_or(RelayError::RateLimit)?;
        let wire = tokio::time::timeout(
            UNAUTHENTICATED_BODY_TIMEOUT,
            Bytes::from_request(request, &()),
        )
        .await
        .map_err(|_| RelayError::StorageUnavailable)?
        .map_err(|rejection| {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                RelayError::ObjectTooLarge
            } else {
                RelayError::MalformedRequest
            }
        })?;
        if wire.is_empty()
            || wire.len() > nonce::MAX_RECORD
            || length.is_some_and(|n| n != wire.len())
        {
            return Err(RelayError::MalformedRequest);
        }
        let db = gate.db.clone();
        let (wire, proof) = tokio::task::spawn_blocking(move || {
            let _ingress = ingress;
            db.authenticate_nonce(mailbox, cid, challenge, &wire, &proof)?;
            Ok::<_, RelayError>((wire, proof))
        })
        .await
        .map_err(|_| RelayError::StorageUnavailable)??;
        let _permit = gate.try_acquire_fresh().ok_or(RelayError::RateLimit)?;
        let (created, receipt) = gate
            .db
            .claim_nonce(mailbox, cid, challenge, wire.to_vec(), proof)?
            .receive()
            .await?;
        Ok(binary(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            "application/cbor",
            receipt,
        ))
    }
    .await;
    result.unwrap_or_else(error_response)
}

async fn enqueue_put(
    db: DbHandle,
    mailbox: Id32,
    object: Object,
    capability: Capability,
    reserved_only: bool,
) -> RelayResult<crate::DbReply<crate::StoredResult>> {
    tokio::task::spawn_blocking(move || {
        if reserved_only {
            let admission = db.classify_put(mailbox, object, capability)?;
            return match admission.class {
                Ok(PutClass::Fresh) => Err(RelayError::RateLimit),
                Ok(PutClass::Duplicate(_))
                | Err(RelayError::Conflict)
                | Err(RelayError::Capability) => {
                    db.put(mailbox, admission.object, admission.append)
                }
                Err(error) => Err(error),
            };
        }
        db.put(mailbox, object, capability)
    })
    .await
    .map_err(|_| RelayError::StorageUnavailable)?
}

async fn object_request(
    db: DbHandle,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    admission: Option<AdmissionMark>,
) -> RelayResult<Response> {
    let (mailbox, hash) = path(&uri)?;
    let capability = capability(&headers)?;
    let length = request_headers(&headers, &method)?;
    let body = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            RelayError::ObjectTooLarge
        } else {
            RelayError::MalformedRequest
        }
    })?;
    if length.is_some_and(|n| n != body.len()) {
        return Err(RelayError::MalformedRequest);
    }
    if method != Method::PUT && method != Method::GET {
        return Err(RelayError::MalformedRequest);
    }
    if method == Method::PUT {
        loki_relay_protocol::envelope::validate_wire(&body)?;
        if <Id32>::from(Sha256::digest(&body)) != hash {
            return Err(RelayError::MalformedRequest);
        }
        if matches!(admission, Some(AdmissionMark::Denied)) {
            return Err(RelayError::Capability);
        }
        // Classification and queue admission run off the HTTP worker.
        // The writer repeats validation, current auth, and the commit.
        let saved = enqueue_put(
            db,
            mailbox,
            Object {
                hash,
                wire: body.to_vec(),
            },
            capability,
            matches!(admission, Some(AdmissionMark::Reserved)),
        )
        .await?
        .receive()
        .await?;
        Ok(binary(
            if saved.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            "application/cbor",
            saved.receipt,
        ))
    } else {
        if !body.is_empty() {
            return Err(RelayError::MalformedRequest);
        }
        let wire = db.get(mailbox, hash, capability)?.receive().await?;
        Ok(binary(StatusCode::OK, "application/octet-stream", wire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn object_routes_bearer_shape() {
        let mut headers = HeaderMap::new();
        for secret in [vec![0; 31], vec![0; 33]] {
            headers.insert(
                "authorization",
                format!("Bearer {}", URL_SAFE_NO_PAD.encode(secret))
                    .parse()
                    .unwrap(),
            );
            assert!(capability(&headers).is_err());
        }
    }

    async fn mapping(error: RelayError, status: u16, code: u8) {
        let response = error_response(error);
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/cbor");
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 3)
                .await
                .unwrap()
                .as_ref(),
            [0x82, 1, code]
        );
    }

    macro_rules! mapping_test {
        ($name:ident, $error:ident, $status:literal, $code:literal) => {
            #[tokio::test]
            async fn $name() {
                mapping(RelayError::$error, $status, $code).await;
            }
        };
    }
    mapping_test!(object_routes_mapping_malformed, MalformedRequest, 400, 1);
    mapping_test!(object_routes_mapping_capability, Capability, 401, 2);
    mapping_test!(object_routes_mapping_missing, ObjectNotFound, 404, 3);
    mapping_test!(object_routes_mapping_conflict, Conflict, 409, 4);
    mapping_test!(object_routes_mapping_cursor, CursorAhead, 409, 5);
    mapping_test!(object_routes_mapping_size, ObjectTooLarge, 413, 6);
    mapping_test!(object_routes_mapping_media, UnsupportedMediaType, 415, 7);
    mapping_test!(object_routes_mapping_admission, RateLimit, 429, 8);
    mapping_test!(object_routes_mapping_storage, StorageUnavailable, 503, 9);
    mapping_test!(object_routes_mapping_quota, QuotaExhausted, 507, 10);
}

const MAX_CONTROL_LEN: usize = 4096;

fn control_path(uri: &Uri) -> RelayResult<(Id32, bool)> {
    // Control paths must retain their raw spelling, just like object paths.
    let parts: Vec<_> = uri.path().split('/').collect();
    if uri.query().is_some()
        || !(parts.len() == 4 || parts.len() == 5)
        || parts[..3] != ["", "v1", "mailboxes"]
        || (parts.len() == 5 && !matches!(parts[4], "append-capability" | "setup"))
    {
        return Err(RelayError::MalformedRequest);
    }
    Ok((
        id(parts[3])?,
        parts.len() == 5 && parts[4] == "append-capability",
    ))
}

fn control_headers(headers: &HeaderMap) -> RelayResult<Option<usize>> {
    if single(headers, "content-type")? != Some("application/cbor") {
        return Err(RelayError::UnsupportedMediaType);
    }
    if single(headers, "content-encoding")?.is_some() {
        return Err(RelayError::UnsupportedMediaType);
    }
    let length = single(headers, "content-length")?
        .map(|s| {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(RelayError::MalformedRequest);
            }
            s.parse::<usize>().map_err(|_| RelayError::MalformedRequest)
        })
        .transpose()?;
    if let Some(encoding) = single(headers, "transfer-encoding")? {
        if encoding != "chunked" || length.is_some() {
            return Err(RelayError::MalformedRequest);
        }
    }
    if length.is_some_and(|n| n > MAX_CONTROL_LEN) {
        return Err(RelayError::ObjectTooLarge);
    }
    Ok(length)
}

async fn control_route(
    State(db): State<DbHandle>,
    uri: Uri,
    headers: HeaderMap,
    admission: Option<Extension<AdmissionMark>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    match control_request(db, uri, headers, body, admission.map(|mark| mark.0)).await {
        Ok(response) => response,
        Err(error) => error_response(error),
    }
}

async fn control_request(
    db: DbHandle,
    uri: Uri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    admission: Option<AdmissionMark>,
) -> RelayResult<Response> {
    let (mailbox, rotate) = control_path(&uri)?;
    let capability = capability(&headers)?;
    // Invalid authority can get a body error, but never enqueue a write.
    let capability = (!matches!(admission, Some(AdmissionMark::Denied)))
        .then_some(capability)
        .ok_or(RelayError::Capability);
    let length = control_headers(&headers)?;
    let body = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            RelayError::ObjectTooLarge
        } else {
            RelayError::MalformedRequest
        }
    })?;
    if length.is_some_and(|n| n != body.len()) {
        return Err(RelayError::MalformedRequest);
    }
    if uri.path().ends_with("/setup") {
        loki_relay_protocol::http::decode_namespace_control(&body)?;
        let result = db
            .setup_control(mailbox, body.to_vec(), capability?)?
            .receive()
            .await?;
        Ok(binary(
            if result.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            "application/cbor",
            loki_relay_protocol::http::encode_creation_result(&mailbox, &result)?,
        ))
    } else if rotate {
        loki_relay_protocol::http::decode_append_update(&body)?;
        let revision = db
            .rotate(mailbox, body.to_vec(), capability?)?
            .receive()
            .await?;
        Ok(binary(
            StatusCode::OK,
            "application/cbor",
            loki_relay_protocol::http::encode_append_result(&mailbox, revision)?,
        ))
    } else {
        loki_relay_protocol::http::decode_creation(&body)?;
        let result = db
            .create(mailbox, body.to_vec(), capability?)?
            .receive()
            .await?;
        Ok(binary(
            if result.created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            "application/cbor",
            loki_relay_protocol::http::encode_creation_result(&mailbox, &result)?,
        ))
    }
}

fn decimal(raw: &str) -> RelayResult<u64> {
    if raw.is_empty()
        || !raw.bytes().all(|b| b.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(RelayError::MalformedRequest);
    }
    raw.parse().map_err(|_| RelayError::MalformedRequest)
}

fn page_path(uri: &Uri) -> RelayResult<(Id32, u64, u16)> {
    let parts: Vec<_> = uri.path().split('/').collect();
    if parts.len() != 5 || parts[..3] != ["", "v1", "mailboxes"] || parts[4] != "entries" {
        return Err(RelayError::MalformedRequest);
    }
    let mailbox = id(parts[3])?;
    let (mut after, mut limit) = (None, None);
    if let Some(query) = uri.query() {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').ok_or(RelayError::MalformedRequest)?;
            match key {
                "after" if after.is_none() => after = Some(decimal(value)?),
                "limit" if limit.is_none() => limit = Some(decimal(value)?),
                _ => return Err(RelayError::MalformedRequest),
            }
        }
    }
    let limit = loki_relay_protocol::http::validate_limit(limit)?;
    Ok((mailbox, after.unwrap_or(0), limit as u16))
}

async fn page_route(
    State(db): State<DbHandle>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    match page_request(db, uri, method, headers, body).await {
        Ok(response) => response,
        Err(error) => error_response(error),
    }
}

async fn page_request(
    db: DbHandle,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> RelayResult<Response> {
    if method != Method::GET {
        return Err(RelayError::MalformedRequest);
    }
    let (mailbox, after, limit) = page_path(&uri)?;
    let capability = capability(&headers)?;
    let length = request_headers(&headers, &Method::GET)?;
    let body = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            RelayError::ObjectTooLarge
        } else {
            RelayError::MalformedRequest
        }
    })?;
    if length.is_some_and(|n| n != body.len()) || !body.is_empty() {
        return Err(RelayError::MalformedRequest);
    }
    let page = db
        .page(mailbox, after, limit, capability)?
        .receive()
        .await?;
    Ok(binary(
        StatusCode::OK,
        "application/cbor",
        loki_relay_protocol::http::encode_page(&page)
            .map_err(|_| RelayError::StorageUnavailable)?,
    ))
}
