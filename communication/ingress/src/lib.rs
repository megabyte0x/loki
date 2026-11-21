use axum::{extract::ConnectInfo, http::Extensions, serve::Listener, Extension, Router};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

const MAX_CONNECTIONS: usize = 128;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve(mut listener: TcpListener, app: Router, shutdown: impl Future<Output = ()>) {
    tokio::pin!(shutdown);
    let (stop, stopped) = watch::channel(());
    let mut connections = JoinSet::new();
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_header_size(16 * 1024);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            (socket, peer) = Listener::accept(&mut listener), if connections.len() < MAX_CONNECTIONS => {
                let app = TowerToHyperService::new(app.clone().layer(Extension(ConnectInfo(peer))));
                let connection = http.serve_connection(TokioIo::new(socket), app);
                let mut stopped = stopped.clone();
                connections.spawn(async move {
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = stopped.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    drop(stop);
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
}

/// Count only outstanding work, by actual socket peer (never forwarded headers).
#[derive(Clone)]
pub struct PeerGate {
    total: Arc<Semaphore>,
    peers: Arc<Mutex<HashMap<Option<IpAddr>, usize>>>,
    per_peer: usize,
}

impl PeerGate {
    pub fn new(total: usize, per_peer: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            per_peer,
        }
    }

    pub fn try_acquire(&self, extensions: &Extensions) -> Option<PeerPermit> {
        let permit = self.total.clone().try_acquire_owned().ok()?;
        let peer = extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip().to_canonical());
        let mut peers = self.peers.lock().unwrap();
        let count = peers.entry(peer).or_default();
        if *count >= self.per_peer {
            return None;
        }
        *count += 1;
        Some(PeerPermit {
            _permit: permit,
            peers: self.peers.clone(),
            peer,
        })
    }
}

pub struct PeerPermit {
    _permit: OwnedSemaphorePermit,
    peers: Arc<Mutex<HashMap<Option<IpAddr>, usize>>>,
    peer: Option<IpAddr>,
}

impl Drop for PeerPermit {
    fn drop(&mut self) {
        let mut peers = self.peers.lock().unwrap();
        let count = peers.get_mut(&self.peer).unwrap();
        *count -= 1;
        if *count == 0 {
            peers.remove(&self.peer);
        }
    }
}
