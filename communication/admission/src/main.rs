use ed25519_dalek::SigningKey;
use loki_relay_client::{OperatorSet, Secret32};
use loki_setup_admission::{
    http::router_with_provisioning, AdmissionError as Error, AdmissionResult as Result,
    AdmissionStore, EnrollmentVerifier, OwnedProvisioner,
};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
fn main() {
    if let Err(error) = dispatch() {
        eprintln!("admission_error_{}", error.code());
        std::process::exit(1);
    }
}
struct Args {
    root: PathBuf,
    files: BTreeMap<String, PathBuf>,
    listen: SocketAddr,
    development: bool,
}
impl Args {
    fn parse() -> Result<Self> {
        let mut args = std::env::args().skip(1);
        if args.next().as_deref() != Some("serve") {
            return Err(Error::Malformed);
        }
        let mut values = BTreeMap::new();
        let mut development = false;
        while let Some(flag) = args.next() {
            if flag == "--development" {
                if development {
                    return Err(Error::Malformed);
                }
                development = true;
                continue;
            }
            if !matches!(
                flag.as_str(),
                "--root"
                    | "--bundle-file"
                    | "--config-key-file"
                    | "--signing-key-file"
                    | "--issuer-key-file"
                    | "--relay-1-provision-file"
                    | "--relay-2-provision-file"
                    | "--relay-3-provision-file"
                    | "--listen"
            ) {
                return Err(Error::Malformed);
            }
            let value = args.next().ok_or(Error::Malformed)?;
            if value.starts_with("--") || values.insert(flag, value).is_some() {
                return Err(Error::Malformed);
            }
        }
        let root = PathBuf::from(values.remove("--root").ok_or(Error::Malformed)?);
        let listen: SocketAddr = values
            .remove("--listen")
            .ok_or(Error::Malformed)?
            .parse()
            .map_err(|_| Error::Malformed)?;
        if !matches!(listen.ip(),IpAddr::V4(ip) if ip==Ipv4Addr::LOCALHOST)
            && !matches!(listen.ip(),IpAddr::V6(ip) if ip==Ipv6Addr::LOCALHOST)
        {
            return Err(Error::Malformed);
        }
        if listen.port() == 0 {
            return Err(Error::Malformed);
        }
        for name in [
            "--bundle-file",
            "--config-key-file",
            "--signing-key-file",
            "--relay-1-provision-file",
            "--relay-2-provision-file",
            "--relay-3-provision-file",
        ] {
            if !values.contains_key(name) {
                return Err(Error::Malformed);
            }
        }
        Ok(Self {
            root,
            files: values
                .into_iter()
                .map(|(k, v)| (k, PathBuf::from(v)))
                .collect(),
            listen,
            development,
        })
    }
    fn file(&self, name: &str) -> Result<&Path> {
        self.files
            .get(name)
            .map(PathBuf::as_path)
            .ok_or(Error::Malformed)
    }
}
fn read_public(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}
fn read_secret(path: &Path, root: &Path) -> Result<Zeroizing<[u8; 32]>> {
    if path.canonicalize()? != path {
        return Err(Error::Storage);
    }
    let md = fs::symlink_metadata(path)?;
    if !md.is_file() {
        return Err(Error::Storage);
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = fs::metadata(root)?.uid();
        if md.permissions().mode() & 0o777 != 0o600
            || md.uid() != owner
            || md.nlink() != 1
            || md.dev() != opened.dev()
            || md.ino() != opened.ino()
        {
            return Err(Error::Storage);
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(33).read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        return Err(Error::Malformed);
    }
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&bytes);
    Ok(secret)
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs())
        .map_err(|_| Error::Unavailable)
}
fn dispatch() -> Result<()> {
    let args = Args::parse()?;
    let root = args.root.canonicalize()?;
    let trusted_key: [u8; 32] = read_public(args.file("--config-key-file")?, 32)?
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let bundle = read_public(args.file("--bundle-file")?, 16384)?;
    let operators = if args.development {
        OperatorSet::verify_development(&bundle, &trusted_key)
    } else {
        OperatorSet::verify(&bundle, &trusted_key)
    }
    .map_err(|_| Error::Identity)?;
    if args.development
        && operators.admission_origin().trim_end_matches('/') != format!("http://{}", args.listen)
    {
        return Err(Error::Identity);
    }
    let signing = read_secret(args.file("--signing-key-file")?, &root)?;
    let enrollment = EnrollmentVerifier::new(
        args.files
            .get("--issuer-key-file")
            .map(|path| {
                read_public(path, 32).and_then(|v| v.try_into().map_err(|_| Error::Malformed))
            })
            .transpose()?,
    );
    let mut credentials = Vec::new();
    for name in [
        "--relay-1-provision-file",
        "--relay-2-provision-file",
        "--relay-3-provision-file",
    ] {
        let seed = read_secret(args.file(name)?, &root)?;
        credentials.push(Secret32::from_bytes(*seed));
    }
    let credentials: [Secret32; 3] = credentials.try_into().map_err(|_| Error::Malformed)?;
    let provisioner = if args.development {
        OwnedProvisioner::development(&operators, credentials)
    } else {
        OwnedProvisioner::new(&operators, credentials)
    }?;
    let store = Arc::new(Mutex::new(AdmissionStore::open(
        &root,
        &operators,
        enrollment,
        SigningKey::from_bytes(&signing),
    )?));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| Error::Unavailable)?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(args.listen)
            .await
            .map_err(|_| Error::Unavailable)?;
        let provision = Arc::new(tokio::sync::Notify::new());
        let ready = Arc::new(AtomicBool::new(true));
        let app = router_with_provisioning(store.clone(), provision.clone(), ready.clone());
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut retry = Duration::from_secs(1);
            loop {
                // A new mailbox command wakes the provisioner at once; the 1 s tick
                // remains the fallback for retries and cleanup.
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = provision.notified() => {}
                }
                let pass = async {
                    let db = store.clone();
                    tokio::task::spawn_blocking(move || {
                        db.lock().map_err(|_| Error::Storage)?.cleanup(now()?)
                    })
                    .await
                    .map_err(|_| Error::Storage)??;
                    provisioner.drive_once(&store, now()?).await?;
                    Ok(())
                };
                match pass.await {
                    Ok(()) => retry = Duration::from_secs(1),
                    Err(Error::StorageBusy) => {
                        eprintln!(
                            "admission_worker_storage_busy: retrying in {}s",
                            retry.as_secs()
                        );
                        tokio::time::sleep(retry).await;
                        retry = (retry * 2).min(Duration::from_secs(30));
                    }
                    Err(error) => {
                        ready.store(false, Ordering::Relaxed);
                        eprintln!("admission_worker_stopped_{}", error.code());
                        break;
                    }
                }
            }
        });
        loki_http_ingress::serve(listener, app, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
        Ok(())
    })
}
