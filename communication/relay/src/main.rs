use loki_relay_protocol::nonce::Claimant;
use loki_relay_server::{
    capability::provisioning_verifier, http::router, DbHandle, Limits, RelayError, RelayResult,
    RelayStore,
};
use rusqlite::{Connection, OpenFlags};
use std::{
    env, fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

fn main() {
    if let Err(error) = dispatch(env::args().skip(1)) {
        eprintln!("relay_error_{}", error.code());
        std::process::exit(1);
    }
}

fn dispatch(args: impl Iterator<Item = String>) -> RelayResult<()> {
    match Cli::parse(args)? {
        Cli::Init(args) => init(args),
        Cli::Serve(args) => serve(args),
        Cli::EnrollNonce { root, mailbox, claimant, quota } => {
            let limits = persisted_limits(&root)?;
            RelayStore::open(&root, limits)?.enroll_nonce_claimant(mailbox, claimant, quota)
        }
    }
}

enum Cli {
    Init(InitArgs),
    Serve(ServeArgs),
    EnrollNonce { root: PathBuf, mailbox: [u8; 32], claimant: Claimant, quota: u64 },
}

struct InitArgs {
    root: PathBuf,
    provision: PathBuf,
    limits: Limits,
    listen: SocketAddr,
    public_origin: Option<String>,
}

struct ServeArgs {
    root: PathBuf,
    listen: SocketAddr,
}

impl Cli {
    fn parse(args: impl Iterator<Item = String>) -> RelayResult<Self> {
        let mut args = args.peekable();
        let command = args.next().ok_or(RelayError::MalformedRequest)?;
        let mut flags = Vec::<(String, String)>::new();
        while let Some(flag) = args.next() {
            if !flag.starts_with("--") || flag.len() == 2 {
                return Err(RelayError::MalformedRequest);
            }
            let Some(value) = args.next() else {
                return Err(RelayError::MalformedRequest);
            };
            if value.starts_with("--") || flags.iter().any(|(name, _)| name == &flag) {
                return Err(RelayError::MalformedRequest);
            }
            flags.push((flag, value));
        }
        let take = |name: &str| -> RelayResult<String> {
            flags
                .iter()
                .find(|(flag, _)| flag == name)
                .map(|(_, value)| value.clone())
                .ok_or(RelayError::MalformedRequest)
        };
        match command.as_str() {
            "init" => {
                if flags.len() != 6 && flags.len() != 7 {
                    return Err(RelayError::MalformedRequest);
                }
                Ok(Self::Init(InitArgs {
                    root: PathBuf::from(take("--root")?),
                    provision: PathBuf::from(take("--provision-capability-file")?),
                    limits: Limits {
                        total_bytes: decimal(&take("--total-bytes")?)?,
                        mailbox_bytes: decimal(&take("--mailbox-bytes")?)?,
                        mailbox_count: decimal(&take("--mailbox-count")?)?,
                    },
                    listen: parse_listen(&take("--listen")?)?,
                    public_origin: if flags.len() == 7 {
                        let origin = take("--public-origin")?;
                        loki_relay_server::validate_public_origin(&origin)?;
                        Some(origin)
                    } else {
                        None
                    },
                }))
            }
            "serve" => {
                if flags.len() != 2 {
                    return Err(RelayError::MalformedRequest);
                }
                Ok(Self::Serve(ServeArgs {
                    root: PathBuf::from(take("--root")?),
                    listen: parse_listen(&take("--listen")?)?,
                }))
            }
            "enroll-nonce" if flags.len() == 6 => {
                let id = |name| {
                    let mut bytes = [0; 32];
                    hex::decode_to_slice(take(name)?, &mut bytes).map_err(|_| RelayError::MalformedRequest)?;
                    Ok::<_, RelayError>(bytes)
                };
                Ok(Self::EnrollNonce {
                    root: PathBuf::from(take("--root")?),
                    mailbox: id("--mailbox")?,
                    claimant: Claimant {
                        vault: id("--vault")?,
                        slot: decimal(&take("--slot")?)?.try_into().map_err(|_| RelayError::MalformedRequest)?,
                        key: id("--signing-key")?,
                    },
                    quota: decimal(&take("--quota-bytes")?)?,
                })
            }
            _ => Err(RelayError::MalformedRequest),
        }
    }
}

fn decimal(raw: &str) -> RelayResult<u64> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RelayError::MalformedRequest);
    }
    raw.parse().map_err(|_| RelayError::MalformedRequest)
}

fn parse_listen(raw: &str) -> RelayResult<SocketAddr> {
    let address = raw
        .parse::<SocketAddr>()
        .map_err(|_| RelayError::MalformedRequest)?;
    let loopback = match address.ip() {
        IpAddr::V4(ip) => ip == Ipv4Addr::LOCALHOST,
        IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
    };
    if !loopback {
        return Err(RelayError::MalformedRequest);
    }
    // Descriptor clients reject a selected port of 0. Binding would replace it
    // with an ephemeral port and persist a URL the client cannot use.
    if address.port() == 0 {
        return Err(RelayError::MalformedRequest);
    }
    Ok(address)
}

fn relay_url(address: SocketAddr) -> String {
    match address.ip() {
        IpAddr::V4(ip) => format!("http://{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("http://[{ip}]:{}", address.port()),
    }
}

fn init(args: InitArgs) -> RelayResult<()> {
    let mut bytes = fs::read(&args.provision)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(RelayError::MalformedRequest);
    }
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&bytes);
    bytes.zeroize();
    let mut run_id = [0u8; 32];
    getrandom::fill(&mut run_id).map_err(|_| RelayError::StorageUnavailable)?;
    let store = RelayStore::init(
        &args.root,
        run_id,
        &args.public_origin.unwrap_or_else(|| relay_url(args.listen)),
        &secret,
        provisioning_verifier(run_id, &secret),
        args.limits,
    )?;
    drop(store);
    Ok(())
}

fn serve(args: ServeArgs) -> RelayResult<()> {
    let manifest = manifest_url(&args.root)?;
    if manifest.starts_with("https://") {
        loki_relay_server::validate_public_origin(&manifest)?;
    } else if manifest != relay_url(args.listen) {
        return Err(RelayError::MalformedRequest);
    }
    let limits = persisted_limits(&args.root)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RelayError::StorageUnavailable)?;
    runtime.block_on(async move {
        let (db, owner) = DbHandle::open(args.root, limits).await?;
        let listener = tokio::net::TcpListener::bind(args.listen)
            .await
            .map_err(|_| RelayError::StorageUnavailable)?;
        let bound = listener
            .local_addr()
            .map_err(|_| RelayError::StorageUnavailable)?;
        let cleanup_db = db.clone();
        let cleanup = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|n| n.as_secs())
                    .unwrap_or(0);
                if now == 0 {
                    continue;
                }
                let result = match cleanup_db.cleanup_setup(now) {
                    Ok(reply) => reply.receive().await,
                    Err(error) => Err(error),
                };
                if let Err(error) = result {
                    eprintln!("relay_cleanup_error_{}", error.code());
                }
            }
        });
        let app = router(db);
        println!("{}", relay_url(bound));
        io::stdout()
            .flush()
            .map_err(|_| RelayError::StorageUnavailable)?;
        loki_http_ingress::serve(listener, app, shutdown_signal()).await;
        cleanup.abort();
        let _ = cleanup.await;
        owner.shutdown().await
    })
}

fn manifest_url(root: &Path) -> RelayResult<String> {
    let manifest = fs::read_to_string(root.join("manifest"))?;
    manifest
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .ok_or(RelayError::StorageUnavailable)
}

fn persisted_limits(root: &Path) -> RelayResult<Limits> {
    let path = root.join("relay.sqlite3");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() {
        return Err(RelayError::StorageUnavailable);
    }
    let connection = Connection::open_with_flags(
        path.canonicalize()?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", "ON")?;
    let (total, mailbox, count): (i64, i64, i64) = connection.query_row(
        "SELECT total_bytes,mailbox_bytes,mailbox_count FROM metadata WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if total < 0 || mailbox < 0 || count < 0 {
        return Err(RelayError::StorageUnavailable);
    }
    Ok(Limits {
        total_bytes: total as u64,
        mailbox_bytes: mailbox as u64,
        mailbox_count: count as u64,
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
