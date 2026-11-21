//! W3: a browser transport to the audited ZF `frostd` relay, over the Fetch API,
//! async-native, no tokio runtime.
//!
//! `core/src/transport.rs`'s [`FrostdTransport`] speaks frostd's JSON-over-HTTP contract
//! with `reqwest::Client` driven by `self.runtime.block_on` — a tokio runtime that cannot
//! exist in a browser. This crate speaks the **same** contract (the 8 frostd endpoints,
//! the same hex-or-bin wire types, the same XEdDSA login) but `.await`s each request
//! directly: on `wasm32` the browser's Fetch API drives the futures with no runtime.
//!
//! Why a separate crate and not a `cfg(wasm32)` impl inside `core`: `loki-poc` pulls
//! orchard/tonic/rusqlite and does not compile to wasm; only the wire does. When the
//! signer core compiles to wasm (W1), this slots under the signer's transport seam. The
//! method set mirrors `transport::Transport` (open/join/send/recv/close) but is **async**
//! and takes **opaque bytes**: the typed `Outbound` / sealed-envelope layer lives above
//! transport (`Outbound::to_bytes` is what crosses the wire), so the browser boundary
//! moves exactly those bytes. See `sealed-envelope layer above transport is unchanged`.
//!
//! The sync `Transport` trait (`fn send(..) -> Result<..>`) cannot be implemented on wasm
//! as-is: there is no way to block on a future in the browser. Integration therefore needs
//! an async seam (an async trait, or the caller awaiting these methods). Flagged in the
//! W3 report.

use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

/// Only TLS, or plain HTTP to this machine, may carry relay traffic. Same rule as
/// `transport::require_tls_off_loopback` — a browser can only reach frostd over https,
/// but the check is identical so a native caller behaves the same.
pub fn require_tls_off_loopback(base_url: &str) -> Result<(), String> {
    tls_url(base_url).map(|_| ())
}

fn tls_url(base_url: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(base_url).map_err(|e| format!("{base_url}: {e}"))?;
    let host = url.host_str().unwrap_or_default();
    let loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(format!("{base_url} must use https:// unless it is on loopback")),
    }
}

fn relay_base_url(base_url: &str) -> Result<String, String> {
    let url = tls_url(base_url)?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err("invalid relay base URL".into());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn relay_client() -> Result<Client, String> {
    let builder = Client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder.redirect(reqwest::redirect::Policy::none());
    builder.build().map_err(|e| e.to_string())
}

const TIMEOUT_SECS: u32 = 30;
const ERROR_CAP: usize = 1024;

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_bounded(request: RequestBuilder, cap: usize) -> Result<(StatusCode, Vec<u8>), String> {
    let mut response = request.timeout(std::time::Duration::from_secs(TIMEOUT_SECS.into()))
        .send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    let cap = if status.is_success() { cap } else { ERROR_CAP };
    let body = async {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if chunk.len() > cap - body.len() {
                return Err(format!("response exceeds {cap} bytes"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }.await;
    Ok((status, if status.is_success() { body? } else { body.unwrap_or_default() }))
}

#[cfg(target_arch = "wasm32")]
async fn fetch_bounded(request: RequestBuilder, cap: usize) -> Result<(StatusCode, Vec<u8>), String> {
    use js_sys::{Array, Reflect, Uint8Array};
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{AbortController, AbortSignal, Headers, ReadableStreamDefaultReader, Request, RequestInit, RequestRedirect, Response, WorkerGlobalScope};

    let invalid = |_| "invalid relay request".to_string();
    let req = request.build().map_err(|e| e.to_string())?;
    let headers = Headers::new().map_err(invalid)?;
    for (name, value) in req.headers() {
        headers.append(name.as_str(), value.to_str().map_err(|e| e.to_string())?).map_err(invalid)?;
    }
    let controller = AbortController::new().map_err(invalid)?;
    let deadline = AbortSignal::timeout_with_u32(TIMEOUT_SECS * 1000);
    let signals = Array::new();
    signals.push(&controller.signal());
    signals.push(&deadline);
    let init = RequestInit::new();
    init.set_method(req.method().as_str());
    init.set_headers_headers(&headers);
    init.set_redirect(RequestRedirect::Error);
    init.set_signal(Some(&AbortSignal::any(&signals)));
    if let Some(body) = req.body().and_then(|body| body.as_bytes()) {
        init.set_body_opt_u8_array(Some(&Uint8Array::from(body)));
    }
    let request = Request::new_with_str_and_init(req.url().as_str(), &init).map_err(invalid)?;
    let fetch_error = |_| if deadline.aborted() { "relay request timed out" } else { "relay fetch failed" }.to_string();
    let worker: WorkerGlobalScope = js_sys::global().unchecked_into();
    let result = async {
        let response: Response = JsFuture::from(worker.fetch_with_request(&request)).await.map_err(fetch_error)?.unchecked_into();
        let status = StatusCode::from_u16(response.status()).map_err(|e| e.to_string())?;
        let cap = if status.is_success() { cap } else { ERROR_CAP };
        let body = async {
            let mut body = Vec::new();
            if let Some(stream) = response.body() {
                let reader: ReadableStreamDefaultReader = stream.get_reader().unchecked_into();
                loop {
                    let next = JsFuture::from(reader.read()).await.map_err(fetch_error)?;
                    if Reflect::get(&next, &"done".into()).map_err(fetch_error)?.is_truthy() {
                        break;
                    }
                    let chunk: Uint8Array = Reflect::get(&next, &"value".into()).map_err(fetch_error)?.unchecked_into();
                    let len = chunk.length() as usize;
                    let start = body.len();
                    if len > cap - start {
                        return Err(format!("response exceeds {cap} bytes"));
                    }
                    body.resize(start + len, 0);
                    chunk.copy_to(&mut body[start..]);
                }
            }
            Ok(body)
        }.await;
        Ok((status, if status.is_success() { body? } else { body.unwrap_or_default() }))
    }.await;
    // Stop the browser pulling an unread remainder after rejecting a response.
    controller.abort();
    result
}

#[derive(Debug)]
pub enum TransportError {
    Http(String),
    Server(String),
    Decode(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Http(e) => write!(f, "frostd http error: {e}"),
            TransportError::Server(e) => write!(f, "frostd server error: {e}"),
            TransportError::Decode(e) => write!(f, "frostd decode error: {e}"),
        }
    }
}
impl std::error::Error for TransportError {}

/// One inbound message: who sent it (sender frostd pubkey) and the opaque public bytes.
/// Mirrors `transport::Incoming`; the E2E seal/open is the layer above.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub from: [u8; 32],
    pub message: Vec<u8>,
}

// Wire types mirrored from `frost_client::api` exactly as `core/src/transport.rs` mirrors
// them (frostd serializes byte fields as lower-hex via `serdect`).
// Keep these client budgets in sync with the native transport.
const MAX_MSG_SIZE: usize = 65_535;
const MAX_RECEIVE_MESSAGES: usize = 1024;
const RECEIVE_CAP: usize = 8 * 1024 * 1024;
const LIST_CAP: usize = 256 * 1024;
const INFO_CAP: usize = 128 * 1024;
const CONTROL_CAP: usize = 4096;

#[derive(Deserialize)]
struct ChallengeOut {
    challenge: Uuid,
}
#[derive(Deserialize)]
struct LoginOut {
    access_token: Uuid,
}
#[derive(Deserialize)]
struct CreateOut {
    session_id: Uuid,
}
#[derive(Deserialize)]
struct ListSessionsOut {
    session_ids: Vec<Uuid>,
}
#[derive(Deserialize)]
struct SessionInfoOut {
    pubkeys: Vec<HexKey>,
    #[serde(default)]
    coordinator_pubkey: Option<HexKey>,
}
#[derive(Deserialize)]
struct WireMsg {
    sender: HexKey,
    #[serde(deserialize_with = "decode_message")]
    msg: Vec<u8>,
}
#[derive(Deserialize)]
struct ReceiveOut {
    msgs: Vec<WireMsg>,
}
#[derive(Deserialize)]
#[serde(transparent)]
struct HexKey(#[serde(deserialize_with = "decode_key")] [u8; 32]);

fn decode_key<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let mut key = [0; 32];
    hex::decode_to_slice(String::deserialize(d)?, &mut key).map_err(serde::de::Error::custom)?;
    Ok(key)
}

fn decode_message<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    if s.len() > 2 * MAX_MSG_SIZE {
        return Err(serde::de::Error::custom("relay message too large"));
    }
    hex::decode(s).map_err(serde::de::Error::custom)
}

/// A browser `frostd` client for one logged-in member. Addressed on the relay by the
/// public half of its X25519 login key. It never holds that key's secret: the key owner (the
/// wasm signer) signs the challenge and hands over only the signature
/// ([`login_signed`](Self::login_signed)).
/// Unlike [`FrostdTransport`](../core) it owns no tokio runtime — every method `.await`s.
pub struct WasmFrostdTransport {
    base_url: String,
    client: Client,
    me: [u8; 32],
    token: Option<Uuid>,
}

impl WasmFrostdTransport {
    /// `base_url` like `https://relay.example` (https off loopback). `me` is the X25519 login
    /// public key (the relay address). Log in before any session call.
    pub fn new(base_url: &str, me: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            base_url: relay_base_url(base_url).map_err(TransportError::Http)?,
            client: relay_client().map_err(TransportError::Http)?,
            me,
            token: None,
        })
    }

    async fn post<O: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: serde_json::Value,
        cap: usize,
    ) -> Result<O, TransportError> {
        let mut req = self.client.post(format!("{}/{path}", self.base_url)).json(&body);
        if let Some(t) = self.token {
            req = req.bearer_auth(t.to_string());
        }
        let (status, body) = fetch_bounded(req, cap).await.map_err(TransportError::Http)?;
        if !status.is_success() {
            return Err(TransportError::Server(format!("{status}: {}", String::from_utf8_lossy(&body))));
        }
        serde_json::from_slice(if body.is_empty() { b"null" } else { &body })
            .map_err(|e| TransportError::Decode(e.to_string()))
    }

    /// Fetch a login challenge. The key owner XEdDSA-signs its 16 UUID bytes and passes the
    /// signature to [`login_signed`](Self::login_signed).
    pub async fn challenge(&self) -> Result<Uuid, TransportError> {
        let ch: ChallengeOut = self.post("challenge", json!({}), CONTROL_CAP).await?;
        Ok(ch.challenge)
    }

    /// Present a signed challenge and cache the bearer token. Byte-for-byte the scheme frostd
    /// verifies (`frostd/src/functions.rs::login`), same as the native path.
    pub async fn login_signed(&mut self, challenge: Uuid, signature: [u8; 64]) -> Result<(), TransportError> {
        let out: LoginOut = self
            .post(
                "login",
                json!({
                    "challenge": challenge,
                    "pubkey": hex::encode(self.me),
                    "signature": hex::encode(signature),
                }),
                CONTROL_CAP,
            )
            .await?;
        self.token = Some(out.access_token);
        Ok(())
    }

    /// Coordinator-only: create a session for the full roster. Returns the session id
    /// (participants `join` it by id — frostd has no explicit join).
    pub async fn open(&self, peers: &[[u8; 32]], message_count: u8) -> Result<Uuid, TransportError> {
        let pubkeys: Vec<String> = peers.iter().map(hex::encode).collect();
        let out: CreateOut = self
            .post(
                "create_new_session",
                json!({ "pubkeys": pubkeys, "message_count": message_count }),
                CONTROL_CAP,
            )
            .await?;
        Ok(out.session_id)
    }

    /// Send one message to recipients. Empty `to` means "to the coordinator" (frostd
    /// convention). `message` is the opaque public bytes (`Outbound::to_bytes` upstream).
    pub async fn send(&self, session: Uuid, to: &[[u8; 32]], message: &[u8]) -> Result<(), TransportError> {
        if message.len() > MAX_MSG_SIZE {
            return Err(TransportError::Decode("relay message too large".into()));
        }
        let recipients: Vec<String> = to.iter().map(hex::encode).collect();
        self.post::<serde_json::Value>(
            "send",
            json!({
                "session_id": session,
                "recipients": recipients,
                "msg": hex::encode(message),
            }),
            CONTROL_CAP,
        )
        .await?;
        Ok(())
    }

    /// Drain this member's inbox for the session. `as_coordinator` selects the coordinator
    /// mailbox. frostd's `receive` returns whatever is queued immediately (not a long poll),
    /// so the browser caller polls this on a timer — no WebSocket needed.
    pub async fn recv(&self, session: Uuid, as_coordinator: bool) -> Result<Vec<Incoming>, TransportError> {
        let out: ReceiveOut = self
            .post(
                "receive",
                json!({ "session_id": session, "as_coordinator": as_coordinator }),
                RECEIVE_CAP,
            )
            .await?;
        if out.msgs.len() > MAX_RECEIVE_MESSAGES {
            return Err(TransportError::Decode("too many relay messages".into()));
        }
        Ok(out.msgs.into_iter().map(|m| Incoming { from: m.sender.0, message: m.msg }).collect())
    }

    /// Every session id this member is a participant/coordinator of (NAT-free discovery).
    pub async fn list_sessions(&self) -> Result<Vec<Uuid>, TransportError> {
        let out: ListSessionsOut = self.post("list_sessions", json!({}), LIST_CAP).await?;
        Ok(out.session_ids)
    }

    /// The participant pubkeys of one session, and the pubkey of the member who opened it.
    pub async fn session_info(&self, session: Uuid) -> Result<(Vec<[u8; 32]>, Option<[u8; 32]>), TransportError> {
        let out: SessionInfoOut = self
            .post("get_session_info", json!({ "session_id": session }), INFO_CAP)
            .await?;
        Ok((out.pubkeys.into_iter().map(|k| k.0).collect(), out.coordinator_pubkey.map(|k| k.0)))
    }

    /// Coordinator-only: close the session (frostd rejects non-coordinator closes).
    pub async fn close(&self, session: Uuid) -> Result<(), TransportError> {
        self.post::<serde_json::Value>("close_session", json!({ "session_id": session }), CONTROL_CAP)
            .await?;
        Ok(())
    }
}

/// One external nonce witness (a relay mailbox), as the operator provisions it for native
/// members (`core/src/host/nonce_witness.rs` `WitnessConfig`): the relay's pinned signing key
/// and run, and the mailbox.
pub struct NonceWitnessRoute {
    pub endpoint: String,
    pub key: [u8; 32],
    pub run: [u8; 32],
    pub mailbox: [u8; 32],
}

const RECEIPT_CAP: usize = 4096;

/// Claim `cid` once at one witness, the same request and receipt check as the native relay
/// client (`loki_relay_client::RelayHttp::claim_nonce`): PUT the record under a fresh
/// challenge, then accept only a canonical receipt signed by the PINNED relay key that binds
/// this mailbox, CID, record hash and challenge. `Ok(true)` is a fresh claim; `Ok(false)` an
/// existing one (a duplicate, which a signer must treat as a refusal).
pub async fn claim_nonce(
    route: &NonceWitnessRoute,
    cid: [u8; 32],
    record: &[u8],
    challenge: [u8; 32],
    proof: [u8; loki_relay_protocol::nonce::CLAIM_PROOF_LEN],
) -> Result<bool, String> {
    use loki_relay_protocol::{canonical::{self, Value}, nonce};
    use sha2::Digest;
    let endpoint = relay_base_url(&route.endpoint)?;
    if record.is_empty() || record.len() > nonce::MAX_RECORD {
        return Err("nonce witness record size".into());
    }
    let token = format!("{}{}", nonce::CLAIM_SCHEME, hex::encode(proof));
    let url = format!(
        "{endpoint}/v1/mailboxes/{}/nonces/{}",
        hex::encode(route.mailbox),
        hex::encode(cid)
    );
    let request = relay_client()?
        .put(url)
        .header("authorization", token)
        .header("content-type", "application/octet-stream")
        .header("x-loki-challenge", hex::encode(challenge))
        .body(record.to_vec());
    let (status, raw) = fetch_bounded(request, RECEIPT_CAP).await.map_err(|e| format!("nonce witness: {e}"))?;
    let status = status.as_u16();
    if status != 200 && status != 201 {
        return Err(format!("nonce witness refused the claim ({status})"));
    }
    let bad = || "nonce witness receipt does not verify".to_string();
    let Value::Array(parts) = canonical::decode(&raw, RECEIPT_CAP).map_err(|_| bad())? else {
        return Err(bad());
    };
    let [Value::Bytes(body), Value::Bytes(signature)] = parts.as_slice() else {
        return Err(bad());
    };
    let receipt = nonce::decode_body(body).map_err(|_| bad())?;
    if nonce::encode_body(&receipt).map_err(|_| bad())? != *body
        || receipt.pin.key != route.key
        || receipt.pin.run != route.run
        || receipt.mailbox != route.mailbox
        || receipt.cid != cid
        || receipt.challenge != challenge
        || receipt.record_hash != <[u8; 32]>::from(sha2::Sha256::digest(record))
        || receipt.created != (status == 201)
    {
        return Err(bad());
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&route.key).map_err(|_| bad())?;
    let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|_| bad())?;
    key.verify_strict(&nonce::signature_input(body).map_err(|_| bad())?, &signature)
        .map_err(|_| bad())?;
    Ok(receipt.created)
}

/// JS bindings (W1G): the signer Worker drives DKG by pumping these async methods between
/// the synchronous wasm `Signer` and frostd. A thin wrapper over [`WasmFrostdTransport`] that
/// holds the one session id the coordinator published, so the Worker passes only opaque hex.
#[cfg(target_arch = "wasm32")]
mod wasm_api {
    use super::*;
    use loki_relay_protocol::nonce;
    use wasm_bindgen::prelude::*;

    fn je<E: std::fmt::Display>(e: E) -> JsError {
        JsError::new(&e.to_string())
    }
    fn hex32(s: &str) -> Result<[u8; 32], JsError> {
        let mut value = [0; 32];
        hex::decode_to_slice(s, &mut value).map_err(je)?;
        Ok(value)
    }

    /// Claim a nonce at one external witness: `true` only for a fresh claim whose receipt the
    /// pinned relay key signed (see [`claim_nonce`]); `false` for an existing claim. Hex args.
    #[wasm_bindgen(js_name = claimNonce)]
    pub async fn claim_nonce_js(
        endpoint: String,
        key_hex: String,
        run_hex: String,
        mailbox_hex: String,
        cid_hex: String,
        record_hex: String,
        challenge_hex: String,
        proof_hex: String,
    ) -> Result<bool, JsError> {
        let route = NonceWitnessRoute {
            endpoint,
            key: hex32(&key_hex)?,
            run: hex32(&run_hex)?,
            mailbox: hex32(&mailbox_hex)?,
        };
        if record_hex.len() > 2 * nonce::MAX_RECORD {
            return Err(JsError::new("nonce witness record size"));
        }
        let record = hex::decode(record_hex).map_err(je)?;
        let mut proof = [0; nonce::CLAIM_PROOF_LEN];
        hex::decode_to_slice(proof_hex, &mut proof).map_err(je)?;
        claim_nonce(&route, hex32(&cid_hex)?, &record, hex32(&challenge_hex)?, proof).await.map_err(je)
    }

    /// A logged-in browser frostd client bound to one DKG session. Addressed on the relay by
    /// the member's X25519 login pubkey (the `encryption` key enrolled for its slot).
    #[wasm_bindgen]
    pub struct FrostdClient {
        inner: WasmFrostdTransport,
        session: Option<Uuid>,
    }

    #[wasm_bindgen]
    impl FrostdClient {
        /// `base_url` is the TLS frostd (https off loopback). `pubkey_hex` is the member's
        /// X25519 login public key, from the wasm signer's `frostdPubkey()`. No secret here.
        #[wasm_bindgen(constructor)]
        pub fn new(base_url: &str, pubkey_hex: &str) -> Result<FrostdClient, JsError> {
            let inner = WasmFrostdTransport::new(base_url, hex32(pubkey_hex)?).map_err(je)?;
            Ok(Self { inner, session: None })
        }

        /// A fresh login challenge (UUID string) for the wasm signer's `frostdSignChallenge`.
        pub async fn challenge(&self) -> Result<String, JsError> {
            Ok(self.inner.challenge().await.map_err(je)?.to_string())
        }

        /// Log in with the challenge and the signer's XEdDSA signature (hex), caching the token.
        #[wasm_bindgen(js_name = loginSigned)]
        pub async fn login_signed(&mut self, challenge: &str, signature_hex: &str) -> Result<(), JsError> {
            let challenge = Uuid::parse_str(challenge).map_err(je)?;
            let mut sig = [0; 64];
            hex::decode_to_slice(signature_hex, &mut sig).map_err(je)?;
            self.inner.login_signed(challenge, sig).await.map_err(je)
        }

        /// Every session id this member participates in (NAT-free discovery), as hex strings.
        pub async fn list_sessions(&self) -> Result<Vec<String>, JsError> {
            Ok(self.inner.list_sessions().await.map_err(je)?.iter().map(Uuid::to_string).collect())
        }

        /// Bind the coordinator's published session id; send/recv address it.
        #[wasm_bindgen(js_name = useSession)]
        pub fn use_session(&mut self, session_id: &str) -> Result<(), JsError> {
            self.session = Some(Uuid::parse_str(session_id).map_err(je)?);
            Ok(())
        }

        fn session(&self) -> Result<Uuid, JsError> {
            self.session.ok_or_else(|| JsError::new("no session bound — call useSession first"))
        }

        /// Open a session of these participants (hex pubkeys) and bind it; returns its id. A
        /// joiner opens one with the vault creator for each join request.
        #[wasm_bindgen(js_name = openSession)]
        pub async fn open_session(&mut self, peers: Vec<String>) -> Result<String, JsError> {
            let peers = peers.iter().map(|p| hex32(p)).collect::<Result<Vec<_>, _>>()?;
            let session = self.inner.open(&peers, 2).await.map_err(je)?;
            self.session = Some(session);
            Ok(session.to_string())
        }

        /// Close the bound session this member opened.
        pub async fn close(&self) -> Result<(), JsError> {
            self.inner.close(self.session()?).await.map_err(je)
        }

        /// The bound session's participants and the member who opened it (its coordinator), as
        /// JSON `{participants: [hex], coordinator: hex | null}`.
        #[wasm_bindgen(js_name = sessionInfo)]
        pub async fn session_info(&self) -> Result<String, JsError> {
            let (participants, owner) = self.inner.session_info(self.session()?).await.map_err(je)?;
            Ok(serde_json::json!({
                "participants": participants.iter().map(hex::encode).collect::<Vec<_>>(),
                "coordinator": owner.map(hex::encode),
            })
            .to_string())
        }

        /// Send one DKG wire (hex) to the coordinator (frostd empty-recipient convention).
        #[wasm_bindgen(js_name = sendToCoordinator)]
        pub async fn send_to_coordinator(&self, msg_hex: &str) -> Result<(), JsError> {
            if msg_hex.len() > 2 * MAX_MSG_SIZE {
                return Err(JsError::new("relay message too large"));
            }
            let msg = hex::decode(msg_hex).map_err(je)?;
            self.inner.send(self.session()?, &[], &msg).await.map_err(je)
        }

        /// Send one message (hex) to a single peer (hex pubkey) on the bound session — the
        /// explicit-recipient path the native host uses for control messages (`&[Peer(..)]`).
        #[wasm_bindgen(js_name = sendToPeer)]
        pub async fn send_to_peer(&self, peer_hex: &str, msg_hex: &str) -> Result<(), JsError> {
            if msg_hex.len() > 2 * MAX_MSG_SIZE {
                return Err(JsError::new("relay message too large"));
            }
            let msg = hex::decode(msg_hex).map_err(je)?;
            self.inner.send(self.session()?, &[hex32(peer_hex)?], &msg).await.map_err(je)
        }

        /// Drain this member's inbox; returns a JSON array of `{from, message}` (both hex).
        /// The Worker keeps only messages whose `from` is the coordinator peer.
        pub async fn recv(&self) -> Result<String, JsError> {
            let msgs = self.inner.recv(self.session()?, false).await.map_err(je)?;
            let out: Vec<serde_json::Value> = msgs
                .into_iter()
                .map(|m| serde_json::json!({ "from": hex::encode(m.from), "message": hex::encode(m.message) }))
                .collect();
            Ok(serde_json::Value::Array(out).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_rule_matches_native() {
        for ok in ["https://relay.example:2744", "http://127.0.0.1:2744", "http://localhost:2744/", "http://[::1]:2744"] {
            assert!(require_tls_off_loopback(ok).is_ok(), "{ok}");
        }
        for bad in ["http://relay.example:2744", "http://10.0.0.5:2744", "http://127.0.0.1.evil.example", "ws://127.0.0.1:2744", "not a url"] {
            assert!(require_tls_off_loopback(bad).is_err(), "{bad}");
        }
    }

    // The request/response shaping is the wire contract; prove it serializes/deserializes
    // exactly as frostd speaks it (lower-hex byte fields), independent of any network.
    #[test]
    fn wire_shapes_match_frostd_contract() {
        // receive response → Incoming, sender+msg are lower-hex.
        let raw = json!({
            "msgs": [
                { "sender": "aa".repeat(32), "msg": hex::encode([1u8, 2, 3]) }
            ]
        })
        .to_string();
        let out: ReceiveOut = serde_json::from_str(&raw).unwrap();
        let incoming: Vec<Incoming> = out
            .msgs
            .into_iter()
            .map(|m| Incoming {
                from: m.sender.0,
                message: m.msg,
            })
            .collect();
        assert_eq!(incoming, vec![Incoming { from: [0xaa; 32], message: vec![1, 2, 3] }]);

        // session info response → raw pubkeys.
        let raw = json!({ "pubkeys": ["bb".repeat(32)] }).to_string();
        let info: SessionInfoOut = serde_json::from_str(&raw).unwrap();
        let keys: Vec<[u8; 32]> = info.pubkeys.into_iter().map(|k| k.0).collect();
        assert_eq!(keys, vec![[0xbb; 32]]);

        // challenge / login / create / list_sessions decode.
        let c: ChallengeOut = serde_json::from_value(json!({ "challenge": Uuid::nil() })).unwrap();
        assert_eq!(c.challenge, Uuid::nil());
        let _: LoginOut = serde_json::from_value(json!({ "access_token": Uuid::nil() })).unwrap();
        let _: CreateOut = serde_json::from_value(json!({ "session_id": Uuid::nil() })).unwrap();
        let l: ListSessionsOut = serde_json::from_value(json!({ "session_ids": [Uuid::nil()] })).unwrap();
        assert_eq!(l.session_ids.len(), 1);
    }
}

/// Live round-trip against a frostd reachable on loopback (ssh -N -L 2744:localhost:2744
/// omarchy). Ignored by default — run with `--ignored` when the tunnel is up. Exercises
/// the full fetch wire: challenge → login → create → send → receive → close.
#[cfg(test)]
mod live {
    use super::*;

    fn gen_login() -> ([u8; 32], [u8; 32]) {
        // The relay address is the X25519 public half of the login secret, derived exactly
        // as the native transport does (`PublicKey::from(&StaticSecret)`).
        let secret = [7u8; 32];
        let pubkey = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
        (secret, pubkey)
    }

    /// Live: two dev witness relays enrolled for the fixture identity, named by
    /// `LOKI_NONCE_TEST_WITNESSES` (the native `[WitnessConfig; 2]` JSON). A fresh claim is accepted
    /// at each; the same claim again is a duplicate; a receipt from an unpinned key is refused.
    #[tokio::test]
    #[ignore = "needs two enrolled dev witness relays (LOKI_NONCE_TEST_WITNESSES)"]
    async fn witnesses_accept_a_claim_once_and_refuse_a_duplicate() {
        use ed25519_dalek::{Signer, SigningKey};
        use loki_relay_protocol::{nonce::{self, Claimant, ClaimProof}, types::RelayPin};
        #[derive(serde::Deserialize)]
        struct Config { endpoint: String, key: [u8; 32], run: [u8; 32], mailbox: [u8; 32] }
        let path = std::env::var("LOKI_NONCE_TEST_WITNESSES").expect("LOKI_NONCE_TEST_WITNESSES");
        let configs: [Config; 2] = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut cid = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut cid);
        let key = SigningKey::from_bytes(&[7; 32]);
        let claimant = Claimant { vault: [8; 32], slot: 1, key: key.verifying_key().to_bytes() };
        for c in configs {
            let route = NonceWitnessRoute { endpoint: c.endpoint, key: c.key, run: c.run, mailbox: c.mailbox };
            let pin = RelayPin { key: c.key, run: c.run };
            let proof = |n| ClaimProof {
                claimant,
                signature: key.sign(&nonce::claim_input(claimant, &pin, c.mailbox, cid, [n; 32], b"first use")).to_bytes(),
            }.to_bytes();
            assert!(claim_nonce(&route, cid, b"first use", [1; 32], proof(1)).await.unwrap(), "fresh claim");
            assert!(!claim_nonce(&route, cid, b"first use", [2; 32], proof(2)).await.unwrap(), "duplicate is not fresh");
            let forged = NonceWitnessRoute { key: [9; 32], ..route };
            assert!(claim_nonce(&forged, cid, b"first use", [3; 32], proof(3)).await.is_err(), "unpinned key");
        }
    }

    #[tokio::test]
    #[ignore = "needs a frostd on http://127.0.0.1:2744"]
    async fn round_trip_over_fetch_wire() {
        let (secret, me) = gen_login();
        let mut t = WasmFrostdTransport::new("http://127.0.0.1:2744", me).unwrap();
        let challenge = t.challenge().await.expect("challenge");
        let signing = xeddsa::xed25519::PrivateKey::from(&secret);
        let sig: [u8; 64] = xeddsa::Sign::sign(&signing, challenge.as_bytes(), rand::rng());
        t.login_signed(challenge, sig).await.expect("login");
        // One-member session with self as the only participant: create, send to coordinator,
        // drain the coordinator mailbox, close.
        let session = t.open(&[me], 1).await.expect("create");
        t.send(session, &[], b"hello frostd over fetch").await.expect("send");
        let msgs = t.recv(session, true).await.expect("receive");
        assert_eq!(msgs, vec![Incoming { from: me, message: b"hello frostd over fetch".to_vec() }]);
        let sessions = t.list_sessions().await.expect("list");
        assert!(sessions.contains(&session));
        // Members tell a payment's control session from its signing session by who opened it.
        assert_eq!(t.session_info(session).await.expect("info"), (vec![me], Some(me)));
        t.close(session).await.expect("close");
    }
}
