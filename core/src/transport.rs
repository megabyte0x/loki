//! WS3 transport, `frostd` implementation. The stable [`Transport`] trait and the public
//! message set ([`Outbound`], [`Incoming`], [`Peer`], [`RelayLog`], …) live in
//! `loki-signer-core` (dependency-clean, wasm-compilable); this module re-exports them and
//! adds [`FrostdTransport`], the reqwest/tokio `frostd` client that `loki-poc` owns.
//!
//! `frostd` is an honest-but-curious JSON-over-HTTP(S) relay: it queues opaque bytes keyed
//! by session + recipient pubkey and hands them back on `receive`. [`FrostdTransport`]
//! speaks its JSON contract directly; login proves possession of the [`FrostdLoginKey`]
//! secret via XEdDSA over the server challenge (`frostd/src/functions.rs::login`).

use std::{future::{pending, Future}, time::Duration};

use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use tokio::{runtime::Runtime, sync::watch, time::Instant};
use uuid::Uuid;

pub use loki_signer_core::transport::*;

/// Only TLS, or plain HTTP to this machine, may carry relay or peer traffic.
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

pub(crate) async fn read_bounded(response: &mut reqwest::Response, cap: usize) -> Result<Vec<u8>, String> {
    let too_large = || format!("response exceeds {cap} bytes");
    if response.content_length().is_some_and(|len| len > cap as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if chunk.len() > cap - body.len() {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// An open frostd session for one logged-in member.
#[derive(Clone, Debug)]
pub struct FrostdChannel {
    pub session: Uuid,
    me: Peer,
}

impl FrostdChannel {
    pub fn session_id(&self) -> Uuid {
        self.session
    }
    pub fn me(&self) -> &Peer {
        &self.me
    }
}

/// `frostd` client for one member's app or the coordinator. Owns its own tokio runtime
/// (same block-on pattern as `setup_relay`) and a logged-in bearer token. Its address is
/// the public half of its [`FrostdLoginKey`], whose secret only XEdDSA-signs the login
/// challenge.
pub struct FrostdTransport {
    base_url: String,
    client: Client,
    runtime: Runtime,
    me: Peer,
    login: FrostdLoginKey,
    token: Option<Uuid>,
    stop: Option<watch::Receiver<bool>>,
    deadline: Option<Instant>,
}

// Wire types mirrored from `frost_client::api` (frostd speaks these). Kept local so core
// does not take the version-conflicting `frost-client` crate as a dependency (ADOPTION
// §2: core is on frost-core 3.0.0, frost-client on 2.x — embedding it would duplicate the
// crypto crates). The audited relay binary is unchanged; only its JSON contract is here.
// Keep these client budgets in sync with wasm-transport. MAX_MSG_SIZE is frostd's send limit;
// receive also needs a batch budget because frostd drains the entire pending queue at once.
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

// frostd serializes byte fields as lower-hex strings (`serdect` hex-or-bin). Mirror that.
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

impl FrostdTransport {
    /// `base_url` like `http://127.0.0.1:2744` (or `https://…` with TLS in production,
    /// ws3 §6). Logs in with `login`.
    pub fn new(base_url: &str, login: FrostdLoginKey) -> Result<Self, TransportError> {
        Self::with_limits(base_url, login, None, None)
    }

    pub(crate) fn with_limits(
        base_url: &str,
        login: FrostdLoginKey,
        stop: Option<watch::Receiver<bool>>,
        deadline: Option<Instant>,
    ) -> Result<Self, TransportError> {
        let url = tls_url(base_url).map_err(TransportError::Http)?;
        if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            return Err(TransportError::Http("invalid relay base URL".into()));
        }
        let runtime = Runtime::new().map_err(|e| TransportError::Http(e.to_string()))?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let mut t = Self {
            base_url: url.as_str().trim_end_matches('/').to_string(),
            client,
            runtime,
            me: login.peer(),
            login,
            token: None,
            stop,
            deadline,
        };
        t.login()?;
        Ok(t)
    }

    fn run<T>(&self, request: impl Future<Output = Result<T, TransportError>>) -> Result<T, TransportError> {
        self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = async {
                    if let Some(mut stop) = self.stop.clone() {
                        let _ = stop.wait_for(|stopped| *stopped).await;
                    } else { pending::<()>().await; }
                } => Err(TransportError::Http("profile is locked".into())),
                _ = async {
                    if let Some(deadline) = self.deadline {
                        tokio::time::sleep_until(deadline).await;
                    } else { pending::<()>().await; }
                } => Err(TransportError::Http("failure notice deadline elapsed".into())),
                result = request => result,
            }
        })
    }

    async fn post<O: for<'de> Deserialize<'de>>(
        client: &Client,
        url: String,
        token: Option<Uuid>,
        body: serde_json::Value,
        cap: usize,
    ) -> Result<O, TransportError> {
        let mut req = client.post(&url).json(&body);
        if let Some(t) = token {
            req = req.bearer_auth(t.to_string());
        }
        let mut resp = req
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = read_bounded(&mut resp, 1024).await.unwrap_or_default();
            return Err(TransportError::Server(format!("{status}: {}", String::from_utf8_lossy(&detail))));
        }
        let body = read_bounded(&mut resp, cap).await.map_err(TransportError::Http)?;
        serde_json::from_slice(if body.is_empty() { b"null" } else { &body })
            .map_err(|e| TransportError::Decode(e.to_string()))
    }

    /// `challenge` → XEdDSA-sign it with the X25519 secret → `login`, caching the token.
    /// This is exactly what frostd verifies in `functions.rs::login`.
    fn login(&mut self) -> Result<(), TransportError> {
        let base = self.base_url.clone();
        let client = self.client.clone();
        let secret = self.login.to_secret_bytes();
        let me = self.me.0;
        let token = self.run(async move {
            let ch: ChallengeOut =
                Self::post(&client, format!("{base}/challenge"), None, json!({}), CONTROL_CAP).await?;
            let signing = xeddsa::xed25519::PrivateKey::from(&*secret);
            // xeddsa 1.1.0's `CryptoRng` is the rand 0.10 trait shape; `rand_zp::rng()`
            // (the OS-seeded ThreadRng, a `CryptoRng`) satisfies it. core aliases rand 0.10
            // as `rand_zp`. XEdDSA uses it only to randomize the challenge signature.
            let sig: [u8; 64] =
                xeddsa::Sign::sign(&signing, ch.challenge.as_bytes(), rand_zp::rng());
            let out: LoginOut = Self::post(
                &client,
                format!("{base}/login"),
                None,
                json!({
                    "challenge": ch.challenge,
                    "pubkey": hex::encode(me),
                    "signature": hex::encode(sig),
                }),
                CONTROL_CAP,
            )
            .await?;
            Ok::<_, TransportError>(out.access_token)
        })?;
        self.token = Some(token);
        Ok(())
    }

    /// Every session id this logged-in member is a participant or coordinator of. A member
    /// behind NAT uses this to find the signing session a proposer enlisted it in without
    /// any inbound reachability (the relay keys sessions by participant pubkey).
    pub fn list_sessions(&self) -> Result<Vec<Uuid>, TransportError> {
        let out: ListSessionsOut = self.run(Self::post(
            &self.client,
            format!("{}/list_sessions", self.base_url),
            self.token,
            json!({}),
            LIST_CAP,
        ))?;
        Ok(out.session_ids)
    }

    /// The participant pubkeys of one session, so a member can tell a payment quorum from
    /// an unrelated session before it drains the mailbox.
    pub fn session_info(&self, session: Uuid) -> Result<Vec<[u8; 32]>, TransportError> {
        Ok(self.session_details(session)?.0)
    }

    pub fn session_details(&self, session: Uuid) -> Result<(Vec<[u8; 32]>, Option<[u8; 32]>), TransportError> {
        let out: SessionInfoOut = self.run(Self::post(
            &self.client,
            format!("{}/get_session_info", self.base_url),
            self.token,
            json!({ "session_id": session }),
            INFO_CAP,
        ))?;
        Ok((out.pubkeys.into_iter().map(|k| k.0).collect(), out.coordinator_pubkey.map(|k| k.0)))
    }

    pub(crate) fn recv_control_bounded(&self, session: Uuid, timeout: Duration) -> Result<Vec<Incoming>, TransportError> {
        self.receive(session, false, timeout)
    }

    fn receive(&self, session: Uuid, as_coordinator: bool, timeout: Duration) -> Result<Vec<Incoming>, TransportError> {
        let out: ReceiveOut = self.run(async {
            tokio::time::timeout(timeout, Self::post(
                &self.client,
                format!("{}/receive", self.base_url),
                self.token,
                json!({ "session_id": session, "as_coordinator": as_coordinator }),
                RECEIVE_CAP,
            )).await.map_err(|_| TransportError::Http("relay receive timed out".into()))?
        })?;
        if out.msgs.len() > MAX_RECEIVE_MESSAGES {
            return Err(TransportError::Decode("too many relay messages".into()));
        }
        Ok(out.msgs.into_iter().map(|m| Incoming { from: Peer(m.sender.0), message: m.msg }).collect())
    }
}

impl Transport for FrostdTransport {
    type Error = TransportError;
    type Channel = FrostdChannel;

    fn open(&mut self, peers: &[Peer], message_count: u8) -> Result<FrostdChannel, TransportError> {
        let base = self.base_url.clone();
        let client = self.client.clone();
        let token = self.token;
        let pubkeys: Vec<String> = peers.iter().map(|p| hex::encode(p.0)).collect();
        let out: CreateOut = self.run(Self::post(
            &client,
            format!("{base}/create_new_session"),
            token,
            json!({ "pubkeys": pubkeys, "message_count": message_count }),
            CONTROL_CAP,
        ))?;
        Ok(FrostdChannel {
            session: out.session_id,
            me: self.me.clone(),
        })
    }

    fn join(&mut self, session: Uuid) -> Result<FrostdChannel, TransportError> {
        // frostd has no explicit join: a participant is already in the session (the
        // coordinator listed its pubkey at create time). The channel is just the id.
        Ok(FrostdChannel {
            session,
            me: self.me.clone(),
        })
    }

    fn send(&self, channel: &FrostdChannel, to: &[Peer], message: &Outbound) -> Result<(), TransportError> {
        let message = message.to_bytes()?;
        if message.len() > MAX_MSG_SIZE {
            return Err(TransportError::Decode("relay message too large".into()));
        }
        let base = self.base_url.clone();
        let client = self.client.clone();
        let token = self.token;
        let recipients: Vec<String> = to.iter().map(|p| hex::encode(p.0)).collect();
        self.run(Self::post::<serde_json::Value>(
            &client,
            format!("{base}/send"),
            token,
            json!({
                "session_id": channel.session,
                "recipients": recipients,
                "msg": hex::encode(message),
            }),
            CONTROL_CAP,
        ))?;
        Ok(())
    }

    fn recv(&self, channel: &FrostdChannel, as_coordinator: bool) -> Result<Vec<Incoming>, TransportError> {
        self.receive(channel.session, as_coordinator, Duration::from_secs(30))
    }

    fn close(&self, channel: FrostdChannel) -> Result<(), TransportError> {
        let base = self.base_url.clone();
        let client = self.client.clone();
        let token = self.token;
        self.run(Self::post::<serde_json::Value>(
            &client,
            format!("{base}/close_session"),
            token,
            json!({ "session_id": channel.session }),
            CONTROL_CAP,
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_relay_login_obeys_stop_or_the_cleanup_deadline() {
        let stall = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", stall.local_addr().unwrap());
        for cancel in [true, false] {
            let (stop, listen) = watch::channel(false);
            let cancel = cancel.then(|| std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                stop.send_replace(true);
            }));
            let start = Instant::now();
            let transport = FrostdTransport::with_limits(&url, FrostdLoginKey::from_secret_bytes([7; 32]),
                cancel.as_ref().map(|_| listen), cancel.is_none().then(|| start + Duration::from_millis(150)));
            assert!(start.elapsed() < Duration::from_secs(2));
            let expected = if let Some(worker) = cancel {
                worker.join().unwrap();
                "profile is locked"
            } else {
                "failure notice deadline elapsed"
            };
            assert!(transport.err().unwrap().to_string().contains(expected));
        }
    }

    #[test]
    fn relay_url_needs_tls_off_loopback() {
        for ok in ["https://relay.example:2744", "http://127.0.0.1:2744", "http://localhost:2744/", "http://[::1]:2744"] {
            assert!(require_tls_off_loopback(ok).is_ok(), "{ok}");
        }
        for bad in ["http://relay.example:2744", "http://10.0.0.5:2744", "http://127.0.0.1.evil.example", "ws://127.0.0.1:2744", "not a url"] {
            assert!(require_tls_off_loopback(bad).is_err(), "{bad}");
        }
    }
}
