use crate::{ClientError, ClientResult, Secret32};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use loki_relay_protocol::{
    canonical::{self, Value},
    challenge, envelope,
    http::{
        decode_append_result, decode_append_update, decode_creation, decode_creation_result,
        decode_error, decode_page, validate_limit, ErrorCode, MAX_METADATA_LEN,
        MAX_PERSISTED_COUNTER,
    },
    nonce,
    receipt::{self, decode_body},
    types::{CreationResult, Id32, Object, Page, ReceiptBody, RelayPin, RelayRoute},
    WireError,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE},
    redirect::Policy,
    Client, Response,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_CONTROL: usize = 4096;

struct PublicDns;

impl reqwest::dns::Resolve for PublicDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let public: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?
                .filter(|addr| crate::operator_config::public_destination(addr.ip())).collect();
            if public.is_empty() {
                return Err(std::io::Error::other("relay DNS returned no public destination").into());
            }
            Ok(Box::new(public.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub struct RelayHttp {
    client: Client,
    development: bool,
}
impl RelayHttp {
    /// Check that the pinned signer is reachable; this does not authenticate later HTTP requests.
    pub async fn authenticate_endpoint(&self, pin: &RelayPin, endpoint: &str) -> ClientResult<()> {
        crate::validate_endpoint(endpoint, self.development)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| ClientError::Crypto)?;
        let url = format!("{}/v1/identity", endpoint.trim_end_matches('/'));
        let mut response = self
            .client
            .get(url)
            .header("x-loki-challenge", hex::encode(nonce))
            .send()
            .await?;
        let (status, raw) = finish(
            &mut response,
            "application/cbor",
            challenge::MAX_RESPONSE,
            None,
        )
        .await?;
        if status != 200 {
            return Err(ClientError::Transport);
        }
        verify_challenge(pin, endpoint, nonce, &raw)
    }

    /// Claims one CID once. Only a fresh, challenge-bound `created` receipt is usable
    /// for signing; an identical retry deliberately returns false.
    pub async fn claim_nonce(
        &self,
        route: &RelayRoute,
        cid: Id32,
        wire: &[u8],
        authorize: impl FnOnce(Id32) -> nonce::ClaimProof,
    ) -> ClientResult<bool> {
        crate::validate_endpoint(&route.endpoint, self.development)?;
        if wire.is_empty() || wire.len() > nonce::MAX_RECORD {
            return Err(ClientError::Config);
        }
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(|_| ClientError::Crypto)?;
        let proof = authorize(challenge);
        let url = format!(
            "{}/v1/mailboxes/{}/nonces/{}",
            route.endpoint.trim_end_matches('/'),
            hex::encode(route.mailbox),
            hex::encode(cid)
        );
        let mut response = self
            .client
            .put(url)
            .header(AUTHORIZATION, format!("{}{}", nonce::CLAIM_SCHEME, hex::encode(proof.to_bytes())))
            .header(CONTENT_TYPE, "application/octet-stream")
            .header("x-loki-challenge", hex::encode(challenge))
            .body(wire.to_vec())
            .send()
            .await?;
        let (status, raw) = finish(&mut response, "application/cbor", RECEIPT_CAP, None).await?;
        if status != 200 && status != 201 {
            return Err(ClientError::Transport);
        }
        verify_nonce_claim(route, cid, wire, challenge, status, &raw)
    }
    /// Existing local tooling explicitly permits literal loopback HTTP.
    pub fn new() -> ClientResult<Self> {
        Self::build(true)
    }

    /// Hosted requests require verified HTTPS on every request.
    pub fn hosted() -> ClientResult<Self> {
        Self::build(false)
    }

    pub(crate) fn development(&self) -> bool {
        self.development
    }
    pub fn for_setup(operators: &crate::OperatorSet, development: bool) -> ClientResult<Self> {
        Ok(Self {
            development,
            client: Self::client_builder()
                .timeout(std::time::Duration::from_secs(
                    operators.limits().request_seconds.min(10),
                ))
                .build()?,
        })
    }
    fn build(development: bool) -> ClientResult<Self> {
        Ok(Self {
            development,
            client: Self::client_builder().build()?,
        })
    }

    pub(crate) fn client_builder() -> reqwest::ClientBuilder {
        Client::builder()
            .redirect(Policy::none())
            // guard:proxy
            .no_proxy()
            // end:proxy
            .dns_resolver(std::sync::Arc::new(PublicDns))
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .timeout(Duration::from_secs(10))
    }
    async fn control(
        &self,
        route: &RelayRoute,
        secret: &Secret32,
        request: &[u8],
        suffix: &str,
    ) -> ClientResult<(u16, Vec<u8>)> {
        crate::validate_endpoint(&route.endpoint, self.development)?;
        if request.len() > MAX_CONTROL
            || route.append_revision == 0
            || route.append_revision > i64::MAX as u64
        {
            return Err(ClientError::Config);
        }
        let authorization = bearer(secret)?;
        let url = format!(
            "{}/v1/mailboxes/{}{}",
            route.endpoint.trim_end_matches('/'),
            hex::encode(route.mailbox),
            suffix
        );
        let mut response = self
            .client
            .put(url)
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, "application/cbor")
            .body(request.to_vec())
            .send()
            .await?;
        let status = response.status().as_u16();
        media(response.headers(), "application/cbor")?;
        let body = collect(&mut response, MAX_CONTROL).await?;
        if !(200..300).contains(&status) {
            let code = decode_error(&body).map_err(|_| ClientError::Transport)?;
            if code.status() != status {
                return Err(ClientError::Transport);
            }
            return Err(match code {
                ErrorCode::InvalidCapability => ClientError::Identity,
                ErrorCode::Conflict => ClientError::Conflict,
                ErrorCode::ObjectTooLarge
                | ErrorCode::AdmissionLimit
                | ErrorCode::QuotaExhausted => ClientError::Capacity,
                ErrorCode::StorageUnavailable => ClientError::Storage,
                ErrorCode::MalformedRequest
                | ErrorCode::ObjectNotFound
                | ErrorCode::CursorAhead
                | ErrorCode::UnsupportedMediaType => ClientError::Config,
            });
        }
        Ok((status, body))
    }
    pub async fn create(
        &self,
        route: &RelayRoute,
        provision: &Secret32,
        request: &[u8],
    ) -> ClientResult<CreationResult> {
        if request.len() > MAX_CONTROL {
            return Err(ClientError::Config);
        }
        let creation = decode_creation(request)?;
        if creation.quota == 0 {
            return Err(ClientError::Config);
        }
        let (status, body) = self.control(route, provision, request, "").await?;
        if status != 200 && status != 201 {
            return Err(ClientError::Transport);
        }
        let (mailbox, result) = decode_creation_result(&body, status == 201)?;
        if mailbox != route.mailbox
            || result.run != route.pin.run
            || result.quota != creation.quota
            || (result.created && result.append_revision != 1)
            || result.append_revision < route.append_revision
        {
            return Err(ClientError::Config);
        }
        Ok(result)
    }
    pub async fn setup_control(
        &self,
        route: &RelayRoute,
        provision: &Secret32,
        creation: &[u8],
        expires: u64,
        retire: bool,
    ) -> ClientResult<CreationResult> {
        use loki_relay_protocol::http::NamespaceAction;
        let action = if retire {
            NamespaceAction::RetireSetup
        } else {
            NamespaceAction::ReserveSetup
        };
        self.namespace_control(route, provision, creation, expires, action)
            .await
    }
    pub async fn namespace_control(
        &self,
        route: &RelayRoute,
        provision: &Secret32,
        creation: &[u8],
        expires: u64,
        action: loki_relay_protocol::http::NamespaceAction,
    ) -> ClientResult<CreationResult> {
        let request =
            loki_relay_protocol::http::encode_namespace_control(creation, expires, action)?;
        let creation = decode_creation(creation)?;
        let (status, body) = self.control(route, provision, &request, "/setup").await?;
        if status != 200 && status != 201 {
            return Err(ClientError::Transport);
        }
        let (mailbox, result) = decode_creation_result(&body, status == 201)?;
        if mailbox != route.mailbox
            || result.run != route.pin.run
            || result.quota != creation.quota
            || result.append_revision < route.append_revision
        {
            return Err(ClientError::Config);
        }
        Ok(result)
    }
    pub async fn rotate(
        &self,
        route: &RelayRoute,
        admin: &Secret32,
        request: &[u8],
    ) -> ClientResult<u64> {
        if request.len() > MAX_CONTROL {
            return Err(ClientError::Config);
        }
        let update = decode_append_update(request)?;
        if route.append_revision.checked_add(1) != Some(update.revision) {
            return Err(ClientError::Config);
        }
        let (status, body) = self
            .control(route, admin, request, "/append-capability")
            .await?;
        if status != 200 {
            return Err(ClientError::Transport);
        }
        let (mailbox, revision) = decode_append_result(&body)?;
        if mailbox != route.mailbox || revision != update.revision {
            return Err(ClientError::Config);
        }
        Ok(revision)
    }

    pub async fn put(
        &self,
        route: &RelayRoute,
        append: &Secret32,
        object: &Object,
    ) -> ClientResult<VerifiedReceipt> {
        // guard:endpoint_recheck
        crate::validate_endpoint(&route.endpoint, self.development)?;
        // end:endpoint_recheck
        // guard:framing
        envelope::validate_wire(&object.wire).map_err(|_| ClientError::Config)?;
        // end:framing
        // guard:sha256
        if <Id32>::from(Sha256::digest(&object.wire)) != object.hash {
            return Err(ClientError::Config);
        }
        // end:sha256
        let url = format!(
            "{}/v1/mailboxes/{}/objects/{}",
            route.endpoint.trim_end_matches('/'),
            hex::encode(route.mailbox),
            hex::encode(object.hash)
        );
        let mut response = self
            .client
            .put(url)
            .header(AUTHORIZATION, bearer(append)?)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(object.wire.clone())
            .send()
            .await?;
        let (status, body) = finish(&mut response, "application/cbor", RECEIPT_CAP, None).await?;
        // guard:put_status
        if status != 200 && status != 201 {
            return Err(ClientError::Transport);
        }
        // end:put_status
        verify_receipt(route, &body, object.hash, object.wire.len() as u64, None)
    }

    pub async fn get(
        &self,
        route: &RelayRoute,
        read: &Secret32,
        hash: &Id32,
    ) -> ClientResult<Object> {
        // guard:endpoint_recheck
        crate::validate_endpoint(&route.endpoint, self.development)?;
        // end:endpoint_recheck
        let url = format!(
            "{}/v1/mailboxes/{}/objects/{}",
            route.endpoint.trim_end_matches('/'),
            hex::encode(route.mailbox),
            hex::encode(hash)
        );
        let mut response = self
            .client
            .get(url)
            .header(AUTHORIZATION, bearer(read)?)
            .send()
            .await?;
        let (status, body) = finish(
            &mut response,
            "application/octet-stream",
            OBJECT_CAP,
            Some(*hash),
        )
        .await?;
        // guard:get_status
        if status != 200 {
            return Err(ClientError::Transport);
        }
        // end:get_status
        // guard:framing
        envelope::validate_wire(&body)?;
        // end:framing
        // guard:sha256
        if <Id32>::from(Sha256::digest(&body)) != *hash {
            return Err(ClientError::Transport);
        }
        // end:sha256
        Ok(Object {
            hash: *hash,
            wire: body,
        })
    }

    pub async fn entries(
        &self,
        route: &RelayRoute,
        read: &Secret32,
        after: u64,
        limit: Option<u64>,
    ) -> ClientResult<VerifiedPage> {
        // guard:endpoint_recheck
        crate::validate_endpoint(&route.endpoint, self.development)?;
        // end:endpoint_recheck
        let limit = validate_limit(limit)?;
        if after > MAX_PERSISTED_COUNTER {
            return Err(ClientError::Config);
        }
        let url = format!(
            "{}/v1/mailboxes/{}/entries?after={after}&limit={limit}",
            route.endpoint.trim_end_matches('/'),
            hex::encode(route.mailbox)
        );
        let mut response = self
            .client
            .get(url)
            .header(AUTHORIZATION, bearer(read)?)
            .send()
            .await?;
        let (status, body) = finish(&mut response, "application/cbor", PAGE_CAP, None).await?;
        // guard:entries_status
        if status != 200 {
            return Err(ClientError::Transport);
        }
        // end:entries_status
        let page = decode_page(&body).map_err(|error| match error {
            WireError::Bounds => ClientError::Wire(error),
            _ => ClientError::Transport,
        })?;
        // guard:page_mailbox
        if page.mailbox != route.mailbox {
            return Err(ClientError::Transport);
        }
        // end:page_mailbox
        // guard:page_after
        if page.after != after {
            return Err(ClientError::Transport);
        }
        // end:page_after
        let mut entries = Vec::with_capacity(page.entries.len());
        for entry in &page.entries {
            // guard:receipt_cap
            if entry.receipt.len() > RECEIPT_CAP {
                return Err(ClientError::Transport);
            }
            // end:receipt_cap
            let receipt = verify_receipt(
                route,
                &entry.receipt,
                entry.hash,
                entry.wire_length,
                Some(entry.sequence),
            )?;
            entries.push(VerifiedEntry {
                sequence: entry.sequence,
                hash: entry.hash,
                wire_length: entry.wire_length,
                receipt,
            });
        }
        // guard:page_expected_len
        let span = page
            .high_water
            .checked_sub(after)
            .ok_or(ClientError::Transport)?;
        let expected = span.min(limit);
        if page.entries.len() as u64 != expected {
            return Err(ClientError::Transport);
        }
        let next = after.checked_add(expected).ok_or(ClientError::Transport)?;
        if page.next != next {
            return Err(ClientError::Transport);
        }
        // end:page_expected_len
        Ok(VerifiedPage {
            mailbox: page.mailbox,
            after: page.after,
            next: page.next,
            high_water: page.high_water,
            entries,
        })
    }

    /// Mailbox page for capture. Invalid receipt bytes and object lengths remain on their entries.
    ///
    /// A malformed or gapped response is `PageRead::Invalid`. A connection or availability
    /// failure is `PageRead::Unavailable`. Neither variant changes a stored cursor.
    pub async fn capture_entries(
        &self,
        route: &RelayRoute,
        read: &Secret32,
        after: u64,
        limit: Option<u64>,
    ) -> ClientResult<PageRead> {
        crate::validate_endpoint(&route.endpoint, self.development)?;
        let limit = validate_limit(limit)?;
        if after > MAX_PERSISTED_COUNTER {
            return Err(ClientError::Config);
        }
        let url = format!(
            "{}/v1/mailboxes/{}/entries?after={after}&limit={limit}",
            route.endpoint.trim_end_matches('/'),
            hex::encode(route.mailbox)
        );
        let mut response = self
            .client
            .get(url)
            .header(AUTHORIZATION, bearer(read)?)
            .send()
            .await?;
        // An intermediary need not return Loki's error media type or Retry-After format.
        let reason = match response.status().as_u16() {
            429 => Some("capacity"),
            503 => Some("storage"),
            500 | 502 | 504 => Some("transport"),
            _ => None,
        };
        if let Some(reason) = reason {
            return Ok(PageRead::Unavailable { reason, sample: Vec::new() });
        }
        let held = hold_page(&mut response).await?;
        classify_page(route, after, limit, held)
    }

    /// Capped object body for a pending download. Framing and hash remain the caller's checks.
    pub async fn capture_object(
        &self,
        route: &RelayRoute,
        read: &Secret32,
        hash: &Id32,
    ) -> ClientResult<Vec<u8>> {
        crate::validate_endpoint(&route.endpoint, self.development)?;
        let url = format!(
            "{}/v1/mailboxes/{}/objects/{}",
            route.endpoint.trim_end_matches('/'),
            hex::encode(route.mailbox),
            hex::encode(hash)
        );
        let mut response = self
            .client
            .get(url)
            .header(AUTHORIZATION, bearer(read)?)
            .send()
            .await?;
        let status = response.status().as_u16();
        if status == 429 {
            retry_after(response.headers())?;
        }
        let expected = if (200..300).contains(&status) {
            "application/octet-stream"
        } else {
            "application/cbor"
        };
        media(response.headers(), expected)?;
        if !(200..300).contains(&status) {
            let body = collect(&mut response, OBJECT_CAP).await?;
            return Err(map_status(status, &body, Some(*hash)));
        }
        // A body past the object cap is a permanent bounds failure, not a dropped connection.
        let body = collect_bounded(&mut response, OBJECT_CAP).await?;
        if status != 200 {
            return Err(ClientError::Transport);
        }
        Ok(body)
    }
}

/// Immutable receipt bytes bound to the body that verified them.
///
/// ```compile_fail
/// fn change(receipt: &mut loki_relay_client::VerifiedReceipt) {
///     receipt.body().hash = [0; 32];
/// }
/// ```
/// ```compile_fail
/// fn change(receipt: &mut loki_relay_client::VerifiedReceipt) {
///     receipt.bytes()[0] = 0;
/// }
/// ```
/// ```compile_fail
/// fn forge(body: loki_relay_protocol::types::ReceiptBody, bytes: Vec<u8>) -> loki_relay_client::VerifiedReceipt {
///     loki_relay_client::VerifiedReceipt { body, bytes }
/// }
/// ```
/// ```compile_fail
/// fn debug<T: std::fmt::Debug>() {}
/// debug::<loki_relay_client::VerifiedReceipt>();
/// ```
pub struct VerifiedReceipt {
    body: ReceiptBody,
    bytes: Vec<u8>,
}
impl VerifiedReceipt {
    pub fn body(&self) -> &ReceiptBody {
        &self.body
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub struct VerifiedEntry {
    sequence: u64,
    hash: Id32,
    wire_length: u64,
    receipt: VerifiedReceipt,
}
impl VerifiedEntry {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn hash(&self) -> &Id32 {
        &self.hash
    }
    pub fn wire_length(&self) -> u64 {
        self.wire_length
    }
    pub fn receipt(&self) -> &VerifiedReceipt {
        &self.receipt
    }
}
pub struct VerifiedPage {
    mailbox: Id32,
    after: u64,
    next: u64,
    high_water: u64,
    entries: Vec<VerifiedEntry>,
}
impl VerifiedPage {
    pub fn mailbox(&self) -> &Id32 {
        &self.mailbox
    }
    pub fn after(&self) -> u64 {
        self.after
    }
    pub fn next(&self) -> u64 {
        self.next
    }
    pub fn high_water(&self) -> u64 {
        self.high_water
    }
    pub fn entries(&self) -> &[VerifiedEntry] {
        &self.entries
    }
}

/// Capture read of one mailbox page. Receipt checks stay on the strict `entries` path.
pub enum PageRead {
    Page(Page),
    /// The response itself is not a contiguous page. The cursor stays put.
    Invalid {
        reason: &'static str,
        sample: Vec<u8>,
    },
    /// The relay or the path was unavailable. The stream is retried, not isolated.
    Unavailable {
        reason: &'static str,
        sample: Vec<u8>,
    },
}

const OBJECT_CAP: usize = envelope::MAX_WIRE_LEN;
const PAGE_CAP: usize = MAX_METADATA_LEN;
const RECEIPT_CAP: usize = MAX_CONTROL;

struct HeldPage {
    status: u16,
    body: Vec<u8>,
    media_ok: bool,
    retry_ok: bool,
    capped: bool,
    dropped: bool,
}

fn sample_prefix(body: &[u8]) -> Vec<u8> {
    body[..body.len().min(4096)].to_vec()
}

fn as_counter(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(value) => u64::try_from(*value).ok(),
        _ => None,
    }
}

/// True when a decoded page body skips a sequence or disagrees with its own next cursor.
fn body_has_gap(body: &[u8]) -> bool {
    let Ok(value) = canonical::decode(body, PAGE_CAP) else {
        return false;
    };
    let Value::Array(fields) = value else {
        return false;
    };
    if fields.len() != 6 {
        return false;
    }
    let (Some(after), Some(next)) = (as_counter(&fields[2]), as_counter(&fields[3])) else {
        return false;
    };
    let Value::Array(entries) = &fields[5] else {
        return false;
    };
    let mut previous = after;
    for entry in entries {
        let Value::Array(fields) = entry else {
            return false;
        };
        let Some(sequence) = fields.first().and_then(as_counter) else {
            return false;
        };
        if previous.checked_add(1) != Some(sequence) {
            return true;
        }
        previous = sequence;
    }
    next != previous
}

fn invalid_page(reason: &'static str, body: &[u8]) -> PageRead {
    PageRead::Invalid {
        reason,
        sample: sample_prefix(body),
    }
}

fn classify_page(
    route: &RelayRoute,
    after: u64,
    limit: u64,
    held: HeldPage,
) -> ClientResult<PageRead> {
    if held.dropped {
        return Ok(PageRead::Unavailable {
            reason: "transport",
            sample: sample_prefix(&held.body),
        });
    }
    if !held.media_ok || !held.retry_ok || held.capped {
        return Ok(invalid_page("malformed", &held.body));
    }
    if !(200..300).contains(&held.status) {
        let error = map_status(held.status, &held.body, None);
        return match error {
            ClientError::Cursor => Ok(invalid_page("cursor", &held.body)),
            ClientError::Identity => Err(ClientError::Identity),
            ClientError::Storage => Ok(PageRead::Unavailable {
                reason: "storage",
                sample: sample_prefix(&held.body),
            }),
            ClientError::Capacity => Ok(PageRead::Unavailable {
                reason: "capacity",
                sample: sample_prefix(&held.body),
            }),
            ClientError::Config
            | ClientError::Conflict
            | ClientError::Wire(_)
            | ClientError::Receipt => Ok(invalid_page(
                if body_has_gap(&held.body) {
                    "gap"
                } else {
                    "malformed"
                },
                &held.body,
            )),
            _ => Ok(PageRead::Unavailable {
                reason: "transport",
                sample: sample_prefix(&held.body),
            }),
        };
    }
    if held.status != 200 {
        return Ok(invalid_page("malformed", &held.body));
    }
    match decode_page(&held.body) {
        Ok(page) => {
            if page.mailbox != route.mailbox || page.after != after {
                return Ok(invalid_page("malformed", &held.body));
            }
            let Some(span) = page.high_water.checked_sub(after) else {
                return Ok(invalid_page("gap", &held.body));
            };
            let expected = span.min(limit);
            let Some(next) = after.checked_add(expected) else {
                return Ok(invalid_page("gap", &held.body));
            };
            if page.entries.len() as u64 != expected || page.next != next {
                return Ok(invalid_page("gap", &held.body));
            }
            Ok(PageRead::Page(page))
        }
        Err(_) => Ok(invalid_page(
            if body_has_gap(&held.body) {
                "gap"
            } else {
                "malformed"
            },
            &held.body,
        )),
    }
}

async fn hold_page(response: &mut Response) -> ClientResult<HeldPage> {
    let status = response.status().as_u16();
    let retry_ok = retry_after(response.headers()).is_ok();
    let media_ok = media(response.headers(), "application/cbor").is_ok();
    if response.headers().contains_key(CONTENT_ENCODING) {
        return Ok(HeldPage {
            status,
            body: Vec::new(),
            media_ok: false,
            retry_ok,
            capped: false,
            dropped: false,
        });
    }
    if response
        .content_length()
        .is_some_and(|len| len > PAGE_CAP as u64)
    {
        return Ok(HeldPage {
            status,
            body: Vec::new(),
            media_ok,
            retry_ok,
            capped: true,
            dropped: false,
        });
    }
    let declared = response.content_length();
    let mut body = Vec::new();
    let mut capped = false;
    let mut dropped = false;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if chunk.len() > PAGE_CAP.saturating_sub(body.len()) {
                    capped = true;
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                dropped = true;
                break;
            }
        }
    }
    if !dropped && !capped && declared.is_some_and(|len| len != body.len() as u64) {
        capped = true;
    }
    Ok(HeldPage {
        status,
        body,
        media_ok,
        retry_ok,
        capped,
        dropped,
    })
}

fn bearer(secret: &Secret32) -> ClientResult<HeaderValue> {
    let mut token = Zeroizing::new(String::from("Bearer "));
    URL_SAFE_NO_PAD.encode_string(secret.as_bytes(), &mut token);
    let mut authorization = HeaderValue::from_str(&token).map_err(|_| ClientError::Config)?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

fn media(headers: &HeaderMap, expected: &str) -> ClientResult<()> {
    // guard:media
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(ClientError::Transport);
    };
    if values.next().is_some() || value.to_str().ok() != Some(expected) {
        return Err(ClientError::Transport);
    }
    // end:media
    Ok(())
}

fn retry_after(headers: &HeaderMap) -> ClientResult<()> {
    // guard:retry_after_integer
    let mut values = headers.get_all("retry-after").iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(ClientError::Transport);
    }
    let text = value.to_str().map_err(|_| ClientError::Transport)?;
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
        || text.parse::<u64>().map_err(|_| ClientError::Transport)? > MAX_PERSISTED_COUNTER
    {
        return Err(ClientError::Transport);
    }
    // end:retry_after_integer
    Ok(())
}

fn map_status(status: u16, body: &[u8], missing: Option<Id32>) -> ClientError {
    let Ok(code) = decode_error(body) else {
        return ClientError::Transport;
    };
    if code.status() != status {
        return ClientError::Transport;
    }
    match code {
        ErrorCode::InvalidCapability => ClientError::Identity,
        ErrorCode::Conflict => ClientError::Conflict,
        // guard:cursor_code
        ErrorCode::CursorAhead => ClientError::Cursor,
        // end:cursor_code
        ErrorCode::ObjectNotFound => match missing {
            Some(hash) => ClientError::MissingObjects(vec![hash]),
            None => ClientError::Config,
        },
        ErrorCode::ObjectTooLarge | ErrorCode::AdmissionLimit | ErrorCode::QuotaExhausted => {
            ClientError::Capacity
        }
        ErrorCode::StorageUnavailable => ClientError::Storage,
        ErrorCode::MalformedRequest | ErrorCode::UnsupportedMediaType => ClientError::Config,
    }
}

async fn collect_bounded(response: &mut Response, cap: usize) -> ClientResult<Vec<u8>> {
    // guard:content_encoding
    if response.headers().contains_key(CONTENT_ENCODING) {
        return Err(ClientError::Transport);
    }
    // end:content_encoding
    // guard:stream_cap
    if response
        .content_length()
        .is_some_and(|len| len > cap as u64)
    {
        return Err(ClientError::Wire(WireError::Bounds));
    }
    // end:stream_cap
    let declared = response.content_length();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        // guard:stream_cap
        if chunk.len() > cap.saturating_sub(body.len()) {
            return Err(ClientError::Wire(WireError::Bounds));
        }
        // end:stream_cap
        body.extend_from_slice(&chunk);
    }
    if declared.is_some_and(|len| len != body.len() as u64) {
        return Err(ClientError::Transport);
    }
    Ok(body)
}

async fn collect(response: &mut Response, cap: usize) -> ClientResult<Vec<u8>> {
    collect_bounded(response, cap)
        .await
        .map_err(|error| match error {
            ClientError::Wire(WireError::Bounds) => ClientError::Transport,
            other => other,
        })
}

async fn finish(
    response: &mut Response,
    success_media: &str,
    cap: usize,
    missing: Option<Id32>,
) -> ClientResult<(u16, Vec<u8>)> {
    let status = response.status().as_u16();
    if status == 429 {
        retry_after(response.headers())?;
    }
    let expected = if (200..300).contains(&status) {
        success_media
    } else {
        "application/cbor"
    };
    media(response.headers(), expected)?;
    let body = collect(response, cap).await?;
    if !(200..300).contains(&status) {
        return Err(map_status(status, &body, missing));
    }
    Ok((status, body))
}

fn verify_nonce_claim(
    route: &RelayRoute,
    cid: Id32,
    wire: &[u8],
    challenge: Id32,
    status: u16,
    raw: &[u8],
) -> ClientResult<bool> {
    let Value::Array(parts) =
        canonical::decode(&raw, RECEIPT_CAP).map_err(|_| ClientError::Receipt)?
    else {
        return Err(ClientError::Receipt);
    };
    let [Value::Bytes(body), Value::Bytes(signature)] = parts.as_slice() else {
        return Err(ClientError::Receipt);
    };
    let receipt = nonce::decode_body(body).map_err(|_| ClientError::Receipt)?;
    if nonce::encode_body(&receipt).map_err(|_| ClientError::Receipt)? != *body
        || receipt.pin != route.pin
        || receipt.mailbox != route.mailbox
        || receipt.cid != cid
        || receipt.challenge != challenge
        || receipt.record_hash != <Id32>::from(Sha256::digest(wire))
        || receipt.created != (status == 201)
    {
        return Err(ClientError::Receipt);
    }
    let key = VerifyingKey::from_bytes(&route.pin.key).map_err(|_| ClientError::Config)?;
    let signature = Signature::from_slice(signature).map_err(|_| ClientError::Receipt)?;
    key.verify_strict(
        &nonce::signature_input(body).map_err(|_| ClientError::Receipt)?,
        &signature,
    )
    .map_err(|_| ClientError::Receipt)?;
    Ok(receipt.created)
}

fn verify_challenge(pin: &RelayPin, endpoint: &str, nonce: Id32, raw: &[u8]) -> ClientResult<()> {
    let Value::Array(parts) =
        canonical::decode(raw, challenge::MAX_RESPONSE).map_err(|_| ClientError::Receipt)?
    else {
        return Err(ClientError::Receipt);
    };
    let [Value::Bytes(body), Value::Bytes(signature)] = parts.as_slice() else {
        return Err(ClientError::Receipt);
    };
    let response = challenge::decode_body(body).map_err(|_| ClientError::Receipt)?;
    if response.pin != *pin || response.endpoint != endpoint || response.challenge != nonce {
        return Err(ClientError::Receipt);
    }
    let key = VerifyingKey::from_bytes(&pin.key).map_err(|_| ClientError::Config)?;
    let signature = Signature::from_slice(signature).map_err(|_| ClientError::Receipt)?;
    key.verify_strict(
        &challenge::signature_input(body).map_err(|_| ClientError::Receipt)?,
        &signature,
    )
    .map_err(|_| ClientError::Receipt)
}

fn signature_input(body: &[u8]) -> ClientResult<Vec<u8>> {
    let length = u32::try_from(body.len()).map_err(|_| ClientError::Receipt)?;
    let mut input = Vec::with_capacity(25 + body.len());
    input.extend_from_slice(b"Loki_Relay_Stored_v1\0");
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}

fn verify_receipt(
    route: &RelayRoute,
    bytes: &[u8],
    hash: Id32,
    wire_length: u64,
    sequence: Option<u64>,
) -> ClientResult<VerifiedReceipt> {
    // guard:canonical_wrapper
    let value = canonical::decode(bytes, RECEIPT_CAP).map_err(|_| ClientError::Receipt)?;
    let fields = match &value {
        Value::Array(fields) if fields.len() == 2 => fields,
        _ => return Err(ClientError::Receipt),
    };
    // end:canonical_wrapper
    let body_bytes = match &fields[0] {
        Value::Bytes(body) => body.clone(),
        _ => return Err(ClientError::Receipt),
    };
    let signature = match &fields[1] {
        Value::Bytes(signature) if signature.len() == 64 => {
            Signature::from_slice(signature).map_err(|_| ClientError::Receipt)?
        }
        _ => return Err(ClientError::Receipt),
    };
    let body = decode_body(&body_bytes).map_err(|_| ClientError::Receipt)?;
    if receipt::encode_body(&body).map_err(|_| ClientError::Receipt)? != body_bytes {
        return Err(ClientError::Receipt);
    }
    // guard:signature_strict
    let pinned = VerifyingKey::from_bytes(&route.pin.key).map_err(|_| ClientError::Config)?;
    pinned
        .verify_strict(signature_input(&body_bytes)?.as_slice(), &signature)
        .map_err(|_| ClientError::Receipt)?;
    // end:signature_strict
    // guard:pin_key
    if body.pin.key != route.pin.key {
        return Err(ClientError::Config);
    }
    // end:pin_key
    // guard:pin_run
    if body.pin.run != route.pin.run {
        return Err(ClientError::Config);
    }
    // end:pin_run
    // guard:mailbox
    if body.mailbox != route.mailbox {
        return Err(ClientError::Receipt);
    }
    // end:mailbox
    // guard:hash
    if body.hash != hash {
        return Err(ClientError::Receipt);
    }
    // end:hash
    // guard:length
    if body.wire_length != wire_length {
        return Err(ClientError::Receipt);
    }
    // end:length
    // guard:entry_sequence
    if let Some(expected) = sequence {
        if body.sequence != expected {
            return Err(ClientError::Receipt);
        }
    }
    // end:entry_sequence
    Ok(VerifiedReceipt {
        body,
        bytes: bytes.to_vec(),
    })
}

/// Re-verifies one saved receipt against the recipient's current route.
/// The sequence stays inside the signed body; a caller cannot supply one.
pub(crate) fn verify_saved_receipt(
    route: &RelayRoute,
    bytes: &[u8],
    hash: Id32,
    wire_length: u64,
) -> ClientResult<VerifiedReceipt> {
    let receipt = verify_receipt(route, bytes, hash, wire_length, None)?;
    let body = receipt.body();
    if body.retention != 1 || body.sequence == 0 || body.sequence > i64::MAX as u64 {
        return Err(ClientError::Receipt);
    }
    Ok(receipt)
}

#[cfg(test)]
mod challenge_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_protocol::{challenge::ChallengeResponse, types::RelayPin};

    #[test]
    fn identity_challenge_rejects_wrong_pin_run_endpoint_and_replay() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let route = RelayRoute {
            pin: RelayPin {
                key: signing.verifying_key().to_bytes(),
                run: [8; 32],
            },
            endpoint: "http://127.0.0.1:8000".into(),
            mailbox: [9; 32],
            append_revision: 1,
        };
        let make = |response: ChallengeResponse| {
            let body = challenge::encode_body(&response).unwrap();
            let signature = signing.sign(&challenge::signature_input(&body).unwrap());
            canonical::encode(&Value::Array(vec![
                Value::Bytes(body),
                Value::Bytes(signature.to_bytes().to_vec()),
            ]))
            .unwrap()
        };
        let expected = ChallengeResponse {
            pin: route.pin.clone(),
            endpoint: route.endpoint.clone(),
            challenge: [10; 32],
        };
        let raw = make(expected.clone());
        assert_eq!(
            verify_challenge(&route.pin, &route.endpoint, expected.challenge, &raw),
            Ok(())
        );
        assert_eq!(
            verify_challenge(&route.pin, &route.endpoint, [11; 32], &raw),
            Err(ClientError::Receipt)
        );
        let mut changed = expected.clone();
        changed.pin.run = [12; 32];
        assert_eq!(
            verify_challenge(
                &route.pin,
                &route.endpoint,
                expected.challenge,
                &make(changed)
            ),
            Err(ClientError::Receipt)
        );
        let mut changed = expected.clone();
        changed.pin.key = [13; 32];
        assert_eq!(
            verify_challenge(
                &route.pin,
                &route.endpoint,
                expected.challenge,
                &make(changed)
            ),
            Err(ClientError::Receipt)
        );
        let other = SigningKey::from_bytes(&[9; 32]);
        let mut changed = expected.clone();
        changed.pin.key = other.verifying_key().to_bytes();
        let body = challenge::encode_body(&changed).unwrap();
        let signature = other.sign(&challenge::signature_input(&body).unwrap());
        let other_response = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
        .unwrap();
        assert_eq!(
            verify_challenge(
                &route.pin,
                &route.endpoint,
                expected.challenge,
                &other_response
            ),
            Err(ClientError::Receipt)
        );
        let mut changed = expected.clone();
        changed.endpoint = "http://127.0.0.1:8001".into();
        assert_eq!(
            verify_challenge(
                &route.pin,
                &route.endpoint,
                expected.challenge,
                &make(changed)
            ),
            Err(ClientError::Receipt)
        );
        let mut changed = raw;
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_challenge(&route.pin, &route.endpoint, expected.challenge, &changed),
            Err(ClientError::Receipt)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticates_a_live_empty_endpoint() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let signing = SigningKey::from_bytes(&[7; 32]);
        let route = RelayRoute {
            pin: RelayPin {
                key: signing.verifying_key().to_bytes(),
                run: [8; 32],
            },
            endpoint: endpoint.clone(),
            mailbox: [9; 32],
            append_revision: 1,
        };
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut chunk = [0; 2048];
                let size = socket.read(&mut chunk).unwrap();
                assert!(size > 0 && request.len() + size <= 4096);
                request.extend_from_slice(&chunk[..size]);
            }
            let request = std::str::from_utf8(&request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /v1/identity http/1.1"));
            let nonce = request
                .lines()
                .find_map(|line| line.strip_prefix("x-loki-challenge: "))
                .unwrap();
            let mut challenge_bytes = [0; 32];
            hex::decode_to_slice(nonce, &mut challenge_bytes).unwrap();
            let body = challenge::encode_body(&ChallengeResponse {
                pin: RelayPin {
                    key: signing.verifying_key().to_bytes(),
                    run: [8; 32],
                },
                endpoint,
                challenge: challenge_bytes,
            })
            .unwrap();
            let signature = signing.sign(&challenge::signature_input(&body).unwrap());
            let response = canonical::encode(&Value::Array(vec![
                Value::Bytes(body),
                Value::Bytes(signature.to_bytes().to_vec()),
            ]))
            .unwrap();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
            socket.write_all(&response).unwrap();
        });
        assert_eq!(
            RelayHttp::new()
                .unwrap()
                .authenticate_endpoint(&route.pin, &route.endpoint)
                .await,
            Ok(())
        );
        server.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn identity_request_never_follows_redirect() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", redirect.local_addr().unwrap());
        let location = format!("http://{}/v1/identity", target.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = redirect.accept().unwrap();
            let mut request = [0; 2048];
            assert!(socket.read(&mut request).unwrap() > 0);
            write!(socket, "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let route = RelayRoute {
            pin: RelayPin {
                key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
                run: [8; 32],
            },
            endpoint,
            mailbox: [9; 32],
            append_revision: 1,
        };
        assert!(RelayHttp::new()
            .unwrap()
            .authenticate_endpoint(&route.pin, &route.endpoint)
            .await
            .is_err());
        server.join().unwrap();
        assert!(target.accept().is_err());
    }
}

#[cfg(test)]
mod nonce_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_protocol::{nonce::NonceReceipt, types::RelayPin};

    #[test]
    fn nonce_receipt_binds_challenge_record_pin_and_first_write() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let route = RelayRoute {
            pin: RelayPin {
                key: signing.verifying_key().to_bytes(),
                run: [8; 32],
            },
            endpoint: "http://127.0.0.1:8000".into(),
            mailbox: [9; 32],
            append_revision: 1,
        };
        let wire = b"encrypted claim";
        let receipt = NonceReceipt {
            pin: route.pin.clone(),
            mailbox: route.mailbox,
            cid: [10; 32],
            record_hash: Sha256::digest(wire).into(),
            challenge: [11; 32],
            created: true,
        };
        let pack = |receipt: &NonceReceipt| {
            let body = nonce::encode_body(receipt).unwrap();
            let signature = signing.sign(&nonce::signature_input(&body).unwrap());
            canonical::encode(&Value::Array(vec![
                Value::Bytes(body),
                Value::Bytes(signature.to_bytes().to_vec()),
            ]))
            .unwrap()
        };
        let raw = pack(&receipt);
        assert_eq!(
            verify_nonce_claim(&route, receipt.cid, wire, receipt.challenge, 201, &raw),
            Ok(true)
        );
        assert!(verify_nonce_claim(&route, receipt.cid, wire, [12; 32], 201, &raw).is_err());
        assert!(verify_nonce_claim(
            &route,
            receipt.cid,
            b"different",
            receipt.challenge,
            201,
            &raw
        )
        .is_err());
        assert!(
            verify_nonce_claim(&route, receipt.cid, wire, receipt.challenge, 200, &raw).is_err()
        );
        let mut wrong_pin = route.clone();
        wrong_pin.pin.run = [13; 32];
        assert!(
            verify_nonce_claim(&wrong_pin, receipt.cid, wire, receipt.challenge, 201, &raw)
                .is_err()
        );
        let mut corrupt = raw.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            verify_nonce_claim(&route, receipt.cid, wire, receipt.challenge, 201, &corrupt)
                .is_err()
        );
        let duplicate = NonceReceipt {
            created: false,
            ..receipt
        };
        assert_eq!(
            verify_nonce_claim(
                &route,
                duplicate.cid,
                wire,
                duplicate.challenge,
                200,
                &pack(&duplicate)
            ),
            Ok(false)
        );
    }
}

#[cfg(test)]
#[path = "http/hosted_tests.rs"]
mod hosted_tests;
