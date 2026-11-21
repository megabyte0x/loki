//! One explicit local decision per browser response. There is no launch-wide GUI token.
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{rejection::JsonRejection, ConnectInfo, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::{stream, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;

use super::{new_token, state::Shared};

// Leave a margin below the browser's response timeout, even if the main thread is busy.
const DEADLINE: Duration = Duration::from_secs(110);
const COOLDOWN: Duration = Duration::from_secs(5);
// The wallet polls every 1.5 s. Allow for browsers throttling background timers to one minute.
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
const RECENT_ACTIVITY: Duration = Duration::from_secs(90);

pub(crate) type LocalConnect = Arc<dyn Fn(&str, &str, &ConnectAttempt) -> bool + Send + Sync>;

pub(crate) struct ConnectAttempt {
    cancelled: AtomicBool,
    deadline: Instant,
}

impl ConnectAttempt {
    pub(crate) fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
}

// The body owns this guard, not the worker. A dropped HTTP stream closes the native prompt
// even while the worker is in AppKit. The worker can never mint a token on its own.
struct ResponseAttempt(Arc<ConnectAttempt>);

impl Drop for ResponseAttempt {
    fn drop(&mut self) { self.0.cancelled.store(true, Ordering::Release); }
}

#[derive(Default)]
struct Grants {
    pending: Weak<ConnectAttempt>,
    last_prompt: Option<Instant>,
    tokens: HashMap<String, Instant>,
    closed: bool,
}

pub(super) struct WalletTabs {
    endpoint: String,
    origin: String,
    ask: LocalConnect,
    grants: Mutex<Grants>,
    deadline: Duration,
    cooldown: Duration,
}

impl WalletTabs {
    pub(super) fn new(endpoint: String, origin: String, ask: LocalConnect) -> Self {
        Self { endpoint, origin, ask, grants: Mutex::default(), deadline: DEADLINE, cooldown: COOLDOWN }
    }

    pub(super) fn permits_request(&self, request: &Request) -> bool {
        let mut origins = request.headers().get_all(header::ORIGIN).iter();
        let authority = self.endpoint.strip_prefix("http://").unwrap();
        let host = request.uri().authority().map(|a| a.as_str())
            .or_else(|| request.headers().get(header::HOST)?.to_str().ok());
        request.extensions().get::<ConnectInfo<SocketAddr>>().is_some_and(|peer| peer.0.ip().is_loopback())
            && (host == Some(authority) || host.is_some_and(|h| authority.strip_suffix(":80") == Some(h)))
            && origins.next().and_then(|v| v.to_str().ok()) == Some(self.origin.as_str())
            && origins.next().is_none()
    }

    pub(super) fn authorizes(&self, request: &Request, token: &str) -> bool {
        if !self.permits_request(request) { return false; }
        let mut grants = self.grants.lock().unwrap();
        let Some(last_seen) = grants.tokens.get_mut(token) else { return false; };
        *last_seen = Instant::now();
        true
    }

    #[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
    pub(super) fn count(&self) -> usize {
        let grants = self.grants.lock().unwrap();
        let now = Instant::now();
        grants.tokens.values().filter(|&&last_seen| now - last_seen < RECENT_ACTIVITY).count()
    }

    pub(super) fn revoke_all(&self) {
        self.clear(false);
    }

    #[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
    pub(super) fn close(&self) {
        self.clear(true);
    }

    fn clear(&self, close: bool) {
        let mut grants = self.grants.lock().unwrap();
        grants.closed |= close;
        grants.tokens.clear();
        if let Some(attempt) = grants.pending.upgrade() {
            attempt.cancelled.store(true, Ordering::Release);
        }
    }

    fn begin(&self) -> Option<Arc<ConnectAttempt>> {
        let mut grants = self.grants.lock().unwrap();
        let now = Instant::now();
        if grants.closed || grants.pending.strong_count() != 0 || grants.last_prompt.is_some_and(|last| now - last < self.cooldown) {
            return None;
        }
        let attempt = Arc::new(ConnectAttempt { cancelled: AtomicBool::new(false), deadline: now + self.deadline });
        grants.last_prompt = Some(now);
        grants.pending = Arc::downgrade(&attempt);
        Some(attempt)
    }

    fn issue(&self, attempt: &ConnectAttempt) -> Option<String> {
        let mut grants = self.grants.lock().unwrap();
        if attempt.cancelled() { return None; }
        let token = new_token();
        grants.tokens.insert(token.clone(), Instant::now());
        Some(token)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Member {
    slot: u32,
    signing_pubkey: String,
    relay_pubkey: String,
}

pub(super) async fn request(State(st): State<Shared>, member: Result<Json<Member>, JsonRejection>) -> Response {
    let (Some(tabs), Ok(Json(member))) = (&st.wallet_tabs, member) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let registered = st.registration.read().await.as_ref().is_some_and(|r|
        member.slot == r.slot && member.signing_pubkey == r.signing_pubkey && member.relay_pubkey == r.relay_pubkey);
    if !registered { return StatusCode::TOO_EARLY.into_response(); }
    // Lock must either cancel this attempt or prevent it from starting.
    let session = st.session.read().await;
    if session.is_none() { return StatusCode::FORBIDDEN.into_response(); }
    let Some(attempt) = tabs.begin() else { return StatusCode::TOO_MANY_REQUESTS.into_response(); };
    drop(session);
    // A short code is for human comparison, not an HTTP credential or a lookup key.
    let code = format!("{:06}", (OsRng.next_u64() % 1_000_000));
    let worker = {
        let (ask, origin, code, attempt) = (tabs.ask.clone(), tabs.origin.clone(), code.clone(), attempt.clone());
        tokio::task::spawn_blocking(move || !attempt.cancelled() && ask(&origin, &code, &attempt))
    };
    let line = |value| Ok::<_, Infallible>(format!("{value}\n"));
    let first = stream::once(std::future::ready(line(json!({ "code": code }))));
    let response_attempt = ResponseAttempt(attempt);
    let last = stream::once(async move {
        let attempt = &response_attempt.0;
        let approved = matches!(tokio::time::timeout_at(attempt.deadline.into(), worker).await, Ok(Ok(true)));
        let token = approved.then(|| st.wallet_tabs.as_ref().unwrap().issue(attempt)).flatten();
        // Retain the drop guard even if the stream is discarded without polling this future.
        drop(response_attempt);
        line(token.map_or_else(|| json!({ "refused": true }), |token| json!({ "token": token })))
    });
    ([(header::CONTENT_TYPE, "application/x-ndjson")], Body::from_stream(first.chain(last))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{config_from_args, native_config_from_args, registration::PublicMember, routes, state::{AppState, Session}};
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ORIGIN: &str = "https://wallet.example";

    struct Host {
        state: Shared,
        client: reqwest::Client,
        endpoint: String,
        serve: tokio::task::JoinHandle<()>,
    }

    impl Drop for Host {
        fn drop(&mut self) { self.serve.abort(); }
    }

    impl Host {
        async fn start(ask: Option<LocalConnect>, deadline: Duration, cooldown: Duration) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let endpoint = format!("http://{addr}");
            let args = ["--data", "unused", "--port", "0", "--registration-slot", "7", "--coordinator-url", ORIGIN,
                "--local-passphrase-file", "unused"].map(str::to_owned);
            let mut config = if ask.is_some() { native_config_from_args(&args) } else { config_from_args(&args) }.unwrap();
            config.port = addr.port();
            let mut st = AppState::new(config);
            if let Some(ask) = ask {
                assert!(st.config.token.is_empty(), "a GUI launch never creates a reusable process token");
                assert_eq!(st.config.lokisigner_url().as_deref(), Some(endpoint.as_str()));
                let mut tabs = WalletTabs::new(endpoint.clone(), ORIGIN.into(), ask);
                tabs.deadline = deadline;
                tabs.cooldown = cooldown;
                st.wallet_tabs = Some(tabs);
                *st.session.write().await = Some(Session { data: "unused".into(), passphrase: zeroize::Zeroizing::new("unused".into()) });
            }
            let state = Arc::new(st);
            let app = routes::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
            let serve = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
            let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap();
            Self { state, client, endpoint, serve }
        }

        async fn registered(&self) {
            *self.state.registration.write().await = Some(PublicMember {
                slot: 7, signing_pubkey: "01".repeat(32), relay_pubkey: "02".repeat(32),
                advertise_url: "https://peer.example".into(), lokisigner_url: self.state.config.lokisigner_url(),
            });
        }

        fn member() -> Value {
            json!({"slot": 7, "signing_pubkey": "01".repeat(32), "relay_pubkey": "02".repeat(32)})
        }

        fn connect(&self) -> reqwest::RequestBuilder {
            self.client.post(format!("{}/api/connect", self.endpoint)).json(&Self::member())
        }

        async fn try_token(&self, origin: Option<&str>, token: &str) -> reqwest::Response {
            let req = self.client.get(format!("{}/api/registration", self.endpoint)).header("x-loki-token", token);
            let req = if let Some(origin) = origin { req.header("origin", origin) } else { req };
            req.send().await.unwrap()
        }

        fn tabs(&self) -> &WalletTabs { self.state.wallet_tabs.as_ref().unwrap() }
    }

    async fn empty(response: reqwest::Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert!(response.bytes().await.unwrap().is_empty());
    }

    async fn token(response: reqwest::Response) -> String {
        let text = response.text().await.unwrap();
        let grant: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        let token = grant["token"].as_str().unwrap();
        assert_eq!(token.len(), 43);
        assert_eq!(grant, json!({ "token": token }));
        token.to_owned()
    }

    #[tokio::test]
    async fn the_origin_and_one_explicit_allow_gate_each_tab_and_each_launch() {
        let (shown, mut prompts) = tokio::sync::mpsc::unbounded_channel();
        let (decide, decisions) = std::sync::mpsc::channel();
        let decisions = Arc::new(Mutex::new(decisions));
        let ask: LocalConnect = Arc::new(move |origin, code, _| {
            shown.send((origin.to_owned(), code.to_owned())).unwrap();
            decisions.lock().unwrap().recv_timeout(Duration::from_secs(2)).unwrap_or(false)
        });
        let app = Host::start(Some(ask), Duration::from_secs(3), Duration::ZERO).await;
        empty(app.connect().send().await.unwrap(), StatusCode::FORBIDDEN).await;
        empty(app.connect().header("origin", "https://other.example").send().await.unwrap(), StatusCode::FORBIDDEN).await;
        empty(app.connect().header("origin", ORIGIN).header("origin", ORIGIN).send().await.unwrap(), StatusCode::FORBIDDEN).await;
        empty(app.connect().header("origin", ORIGIN).header("host", "localhost").send().await.unwrap(), StatusCode::FORBIDDEN).await;
        empty(app.connect().header("origin", ORIGIN).send().await.unwrap(), StatusCode::TOO_EARLY).await;
        assert!(prompts.try_recv().is_err());
        app.registered().await;

        let mut response = app.connect().header("origin", ORIGIN).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["access-control-allow-origin"], ORIGIN);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let (origin, code) = prompts.recv().await.unwrap();
        assert_eq!(origin, ORIGIN);
        let first: Value = serde_json::from_slice(&response.chunk().await.unwrap().unwrap()).unwrap();
        assert_eq!(first, json!({ "code": code }));
        assert_eq!(code.len(), 6);
        assert!(app.tabs().grants.lock().unwrap().tokens.is_empty());
        empty(app.connect().header("origin", ORIGIN).send().await.unwrap(), StatusCode::TOO_MANY_REQUESTS).await;
        assert!(prompts.try_recv().is_err());
        decide.send(true).unwrap();
        let first_token = token(response).await;
        assert_eq!(app.try_token(Some(ORIGIN), &first_token).await.status(), StatusCode::OK);
        for (origin, status) in [(None, StatusCode::UNAUTHORIZED), (Some("https://other.example"), StatusCode::FORBIDDEN)] {
            let reply = app.try_token(origin, &first_token).await;
            assert_eq!(reply.status(), status);
            assert!(!reply.text().await.unwrap().contains(&first_token));
        }
        assert_eq!(app.try_token(Some(ORIGIN), "").await.status(), StatusCode::UNAUTHORIZED);

        decide.send(true).unwrap();
        let second_token = token(app.connect().header("origin", ORIGIN).send().await.unwrap()).await;
        assert!(prompts.try_recv().is_ok());
        assert_ne!(first_token, second_token);
        for token in [&first_token, &second_token] {
            assert_eq!(app.try_token(Some(ORIGIN), token).await.status(), StatusCode::OK);
        }
        let reply = app.client.post(format!("{}/api/lock", app.endpoint)).header("origin", ORIGIN)
            .header("x-loki-token", &first_token).send().await.unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.json::<Value>().await.unwrap(), json!({"locked": true}));
        for token in [&first_token, &second_token] {
            assert_eq!(app.try_token(Some(ORIGIN), token).await.status(), StatusCode::UNAUTHORIZED);
            for path in ["status", "recovery-backup", "unlock"] {
                let url = format!("{}/api/{path}", app.endpoint);
                let request = if path == "unlock" { app.client.post(url).json(&json!({"passphrase": "unused"})) }
                    else { app.client.get(url) };
                let reply = request.header("origin", ORIGIN).header("x-loki-token", token).send().await.unwrap();
                assert_eq!(reply.status(), StatusCode::UNAUTHORIZED, "{path}");
                assert_eq!(reply.json::<Value>().await.unwrap(), json!({"error": "invalid process token"}));
            }
        }
        // The registration still matches, but a locked profile cannot start a fresh dialog.
        empty(app.connect().header("origin", ORIGIN).send().await.unwrap(), StatusCode::FORBIDDEN).await;
        assert!(prompts.try_recv().is_err());

        let restarted = Host::start(Some(Arc::new(|_, _, _| true)), Duration::from_secs(3), Duration::ZERO).await;
        restarted.registered().await;
        assert_eq!(restarted.try_token(Some(ORIGIN), &first_token).await.status(), StatusCode::UNAUTHORIZED);
        let after_restart = token(restarted.connect().header("origin", ORIGIN).send().await.unwrap()).await;
        assert_ne!(after_restart, first_token);
        assert_eq!(restarted.try_token(Some(ORIGIN), &after_restart).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_counts_recent_tabs_without_expiring_their_grants() {
        let app = Host::start(Some(Arc::new(|_, _, _| true)), Duration::from_secs(3), Duration::ZERO).await;
        app.registered().await;
        let first = token(app.connect().header("origin", ORIGIN).send().await.unwrap()).await;
        let second = token(app.connect().header("origin", ORIGIN).send().await.unwrap()).await;
        assert_eq!(app.tabs().count(), 2);

        let mut grants = app.tabs().grants.lock().unwrap();
        let now = Instant::now();
        *grants.tokens.get_mut(&first).unwrap() = now - Duration::from_secs(91);
        *grants.tokens.get_mut(&second).unwrap() = now - Duration::from_secs(60);
        drop(grants);
        assert_eq!(app.tabs().count(), 1);
        assert_eq!(app.try_token(Some("https://other.example"), &first).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(app.tabs().count(), 1);
        assert_eq!(app.try_token(Some(ORIGIN), &first).await.status(), StatusCode::OK);
        assert_eq!(app.tabs().count(), 2);
    }

    #[test]
    fn a_valid_host_and_origin_still_require_a_loopback_peer() {
        let tabs = WalletTabs::new("http://127.0.0.1:3601".into(), ORIGIN.into(), Arc::new(|_, _, _| false));
        for (peer, allowed) in [("127.0.0.1:40100", true), ("192.0.2.4:40100", false)] {
            let request = axum::http::Request::builder().uri("/api/connect").header("host", "127.0.0.1:3601").header("origin", ORIGIN)
                .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap())).body(Body::empty()).unwrap();
            assert_eq!(tabs.permits_request(&request), allowed, "{peer}");
        }
    }

    #[test]
    fn a_dropped_response_cannot_issue_a_grant_even_on_allow() {
        let tabs = WalletTabs::new("http://127.0.0.1:3601".into(), ORIGIN.into(), Arc::new(|_, _, _| true));
        let attempt = tabs.begin().unwrap();
        drop(ResponseAttempt(attempt.clone()));
        assert!(tabs.issue(&attempt).is_none());
        assert!(tabs.grants.lock().unwrap().tokens.is_empty());
    }

    #[tokio::test]
    async fn disconnect_all_refuses_an_open_request_even_if_allow_arrives_later() {
        let (shown, mut prompts) = tokio::sync::mpsc::unbounded_channel();
        let (allow, decisions) = std::sync::mpsc::channel();
        let decisions = Mutex::new(decisions);
        let ask = Arc::new(move |_: &str, code: &str, _: &ConnectAttempt| {
            shown.send(code.to_owned()).unwrap();
            decisions.lock().unwrap().recv_timeout(Duration::from_secs(2)).unwrap_or(false)
        });
        let app = Host::start(Some(ask), Duration::from_secs(3), Duration::ZERO).await;
        app.registered().await;
        let response = app.connect().header("origin", ORIGIN).send().await.unwrap();
        let code = tokio::time::timeout(Duration::from_secs(1), prompts.recv()).await.unwrap().unwrap();
        app.tabs().revoke_all(); // The same operation the LokiSigner menu invokes.
        allow.send(true).unwrap();
        let frames: Vec<Value> = response.text().await.unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(frames, [json!({"code": code}), json!({"refused": true})]);
        assert!(app.tabs().grants.lock().unwrap().tokens.is_empty());
    }

    #[tokio::test]
    async fn refusal_and_timeout_have_the_same_empty_grant_and_enforce_cooldown() {
        for ask in [Arc::new(|_: &str, _: &str, _: &ConnectAttempt| false) as LocalConnect,
            Arc::new(|_, _, attempt| {
                while !attempt.cancelled() { std::thread::sleep(Duration::from_millis(5)); }
                true // An answer after the deadline may not issue anything.
            })] {
            let app = Host::start(Some(ask), Duration::from_millis(100), Duration::from_secs(5)).await;
            app.registered().await;
            let response = app.connect().header("origin", ORIGIN).send().await.unwrap();
            let text = response.text().await.unwrap();
            let frames: Vec<Value> = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
            assert_eq!(frames.len(), 2);
            assert_eq!(frames[0].as_object().unwrap().len(), 1);
            assert!(frames[0]["code"].is_string());
            assert_eq!(frames[1], json!({"refused": true}));
            assert!(app.tabs().grants.lock().unwrap().tokens.is_empty());
            empty(app.connect().header("origin", ORIGIN).send().await.unwrap(), StatusCode::TOO_MANY_REQUESTS).await;
        }
    }

    #[tokio::test]
    async fn closing_the_connection_cancels_the_open_dialog_and_discards_late_allow() {
        let (event, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let ask = Arc::new(move |_: &str, _: &str, attempt: &ConnectAttempt| {
            event.send("shown").unwrap();
            while !attempt.cancelled() { std::thread::sleep(Duration::from_millis(5)); }
            event.send("cancelled").unwrap();
            true
        });
        let app = Host::start(Some(ask), Duration::from_secs(5), Duration::ZERO).await;
        app.registered().await;
        let address = app.endpoint.strip_prefix("http://").unwrap();
        let mut tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let body = Host::member().to_string();
        tcp.write_all(format!("POST /api/connect HTTP/1.1\r\nHost: {address}\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !response.windows(7).any(|bytes| bytes == b"\"code\":") {
                let mut buffer = [0; 1024];
                let n = tcp.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                response.extend_from_slice(&buffer[..n]);
            }
        }).await.unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), seen.recv()).await.unwrap(), Some("shown"));
        drop(tcp);
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), seen.recv()).await
            .expect("the body drop cancels before the deadline"), Some("cancelled"));
        assert!(app.tabs().grants.lock().unwrap().tokens.is_empty());
    }

    #[tokio::test]
    async fn headless_keeps_its_link_capability_and_has_no_connect_route() {
        let app = Host::start(None, Duration::ZERO, Duration::ZERO).await;
        app.registered().await;
        let printed = format!("{}/#{}", app.endpoint, app.state.config.token);
        let capability = reqwest::Url::parse(&printed).unwrap().fragment().unwrap().to_owned();
        assert_eq!(capability.len(), 43);
        for origin in [None, Some(ORIGIN)] {
            assert_eq!(app.try_token(origin, &capability).await.status(), StatusCode::OK);
        }
        assert_eq!(app.client.post(format!("{}/api/lock", app.endpoint)).header("x-loki-token", &capability)
            .send().await.unwrap().status(), StatusCode::OK);
        assert_eq!(app.try_token(None, &capability).await.status(), StatusCode::OK);
        empty(app.connect().header("origin", ORIGIN).header("x-loki-token", capability).send().await.unwrap(), StatusCode::NOT_FOUND).await;
    }
}
