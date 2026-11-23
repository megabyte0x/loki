//! Provision persistent nonce witnesses with the existing Loki relay protocol.
use loki_poc::host::WitnessConfig;
use loki_relay_client::{RelayHttp, Secret32};
use loki_relay_protocol::{http::encode_creation, types::{Creation, RelayPin, RelayRoute}};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const QUOTA: u64 = 64 * 1024 * 1024;
const HELP: &str = "Usage: provision_nonce_witnesses --relay-root DIR --relay-root DIR --out witnesses.json [--development-http]
Each existing Loki relay root supplies manifest (endpoint, run, key) and provision.secret.
The two relays must have distinct keys and run IDs. Production requires independently
operated relays in separate rollback domains. --development-http permits loopback HTTP.
Existing output is checked and reused; an interrupted provisioning resumes from OUT.pending.
This uses Loki's /v1/mailboxes API, not the frostd session API.";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    witnesses: [ProvisionedWitness; 2],
    requests: [Vec<u8>; 2],
}

// The provisioning tool alone keeps the read capability to verify an existing mailbox.
#[derive(serde::Serialize, serde::Deserialize)]
struct ProvisionedWitness {
    #[serde(flatten)]
    config: WitnessConfig,
    read: [u8; 32],
}

impl Drop for ProvisionedWitness {
    fn drop(&mut self) { self.read.zeroize(); }
}

fn read_private(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?.take(16_385).read_to_end(&mut bytes)?;
    if bytes.len() > 16_384 { return Err("witness input too large".into()); }
    Ok(bytes)
}

fn write_private(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let raw = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    let result = (|| -> Result<()> {
        file.write_all(&raw)?;
        file.sync_all()?;
        fs::hard_link(&temp, path)?; // Publish complete bytes without replacing existing pins.
        File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
        Ok(())
    })();
    fs::remove_file(temp)?;
    result
}

fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(bytes)
}

fn verifier(mailbox: [u8; 32], role: u8, secret: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"Loki_Relay_Capability_v1\0");
    hash.update([role]);
    hash.update(mailbox);
    hash.update(secret);
    hash.finalize().into()
}

fn fresh(routes: &[RelayRoute; 2]) -> Result<Pending> {
    let mut witnesses = Vec::new();
    let mut requests = Vec::new();
    for route in routes {
        let mailbox = random()?;
        let read = Zeroizing::new(random()?);
        let append = Zeroizing::new(random()?);
        let admin = Zeroizing::new(random()?);
        requests.push(encode_creation(&Creation {
            read_verifier: verifier(mailbox, 1, &read),
            append_verifier: verifier(mailbox, 2, &append),
            admin_verifier: verifier(mailbox, 3, &admin), quota: QUOTA,
        })?);
        witnesses.push(ProvisionedWitness {
            config: WitnessConfig {
                endpoint: route.endpoint.clone(), key: route.pin.key, run: route.pin.run, mailbox,
            },
            read: *read,
        });
    }
    Ok(Pending {
        witnesses: witnesses.try_into().map_err(|_| "two witnesses required")?,
        requests: requests.try_into().map_err(|_| "two requests required")?,
    })
}

fn bind(routes: &mut [RelayRoute; 2], witnesses: &[ProvisionedWitness; 2]) -> Result<()> {
    if witnesses[0].config.mailbox == witnesses[1].config.mailbox { return Err("distinct mailboxes required".into()); }
    for (route, ProvisionedWitness { config: witness, read }) in routes.iter_mut().zip(witnesses) {
        if witness.endpoint != route.endpoint || witness.key != route.pin.key || witness.run != route.pin.run
            || witness.mailbox == [0; 32] || *read == [0; 32]
        {
            return Err("saved witnesses do not match relay roots; refusing to replace pins".into());
        }
        route.mailbox = witness.mailbox;
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut roots = Vec::new();
    let mut output = None;
    let mut development = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => { println!("{HELP}"); return Ok(()); }
            "--development-http" => development = true,
            "--relay-root" => roots.push(PathBuf::from(args.next().ok_or("--relay-root needs a directory")?)),
            "--out" if output.is_none() => output = Some(PathBuf::from(args.next().ok_or("--out needs a path")?)),
            _ => return Err(HELP.into()),
        }
    }
    let roots: [PathBuf; 2] = roots.try_into().map_err(|_| HELP)?;
    let output = output.ok_or(HELP)?;
    let mut routes = Vec::new();
    let mut credentials = Vec::new();
    for root in roots {
        let raw = read_private(&root.join("manifest"))?;
        let fields: Vec<_> = std::str::from_utf8(&raw)?.lines().collect();
        if fields.len() != 3 { return Err("invalid relay manifest".into()); }
        loki_relay_client::validate_endpoint(fields[0], development)?;
        let id = |s| -> Result<[u8; 32]> { hex::decode(s)?.try_into().map_err(|_| "invalid relay pin".into()) };
        routes.push(RelayRoute {
            endpoint: fields[0].into(), pin: RelayPin { run: id(fields[1])?, key: id(fields[2])? },
            mailbox: [0; 32], append_revision: 1,
        });
        credentials.push(Secret32::from_bytes(read_private(&root.join("provision.secret"))?.as_slice()
            .try_into().map_err(|_| "provision.secret must contain exactly 32 raw bytes")?));
    }
    let mut routes: [RelayRoute; 2] = routes.try_into().map_err(|_| HELP)?;
    if routes[0].pin.key == routes[1].pin.key || routes[0].pin.run == routes[1].pin.run
        || routes.iter().any(|r| r.pin.key == [0; 32] || r.pin.run == [0; 32])
    {
        return Err("two distinct nonzero relay keys and run IDs required".into());
    }
    let http = if development { RelayHttp::new()? } else { RelayHttp::hosted()? };
    for route in &routes { http.authenticate_endpoint(&route.pin, &route.endpoint).await?; }
    let mut lock_name = output.as_os_str().to_owned();
    lock_name.push(".lock");
    let _lock = OpenOptions::new().write(true).create(true).truncate(false).open(lock_name)?;
    _lock.try_lock().map_err(|e| format!("lock witness output: {e}"))?;
    if output.try_exists()? {
        let witnesses: [ProvisionedWitness; 2] = serde_json::from_slice(&read_private(&output)?)?;
        bind(&mut routes, &witnesses)?;
        for (route, witness) in routes.iter().zip(&witnesses) {
            http.entries(route, &Secret32::from_bytes(witness.read), 0, Some(1)).await?;
        }
    } else {
        let pending_path = output.with_file_name(format!("{}.pending", output.file_name().ok_or("invalid output path")?.to_str().ok_or("invalid output path")?));
        let pending: Pending = if pending_path.try_exists()? {
            serde_json::from_slice(&read_private(&pending_path)?)?
        } else {
            let pending = fresh(&routes)?;
            write_private(&pending_path, &pending)?;
            pending
        };
        bind(&mut routes, &pending.witnesses)?;
        for ((route, credential), request) in routes.iter().zip(&credentials).zip(&pending.requests) {
            http.create(route, credential, request).await?;
        }
        write_private(&output, &pending.witnesses)?;
        fs::remove_file(pending_path)?;
    }
    println!("{}", fs::canonicalize(output)?.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_provisioning_preserves_mailboxes_requests_and_private_output() {
        let mut routes = [1, 2].map(|n| RelayRoute {
            endpoint: format!("http://127.0.0.1:3910{n}"),
            pin: RelayPin { key: [n; 32], run: [n + 2; 32] }, mailbox: [0; 32], append_revision: 1,
        });
        let pending = fresh(&routes).unwrap();
        let path = std::env::temp_dir().join(format!("witnesses-{}.json", uuid::Uuid::new_v4()));
        write_private(&path, &pending).unwrap();
        let saved: Pending = serde_json::from_slice(&read_private(&path).unwrap()).unwrap();
        assert_eq!(saved.requests, pending.requests);
        bind(&mut routes, &saved.witnesses).unwrap();
        assert_ne!(routes[0].mailbox, routes[1].mailbox);
        assert_ne!(saved.witnesses[0].read, saved.witnesses[1].read);
        for (witness, request) in saved.witnesses.iter().zip(&saved.requests) {
            let creation = loki_relay_protocol::http::decode_creation(request).unwrap();
            let mut input = b"Loki_Relay_Capability_v1\0\x01".to_vec();
            input.extend_from_slice(&witness.config.mailbox);
            input.extend_from_slice(&witness.read);
            assert_eq!(creation.read_verifier, <[u8; 32]>::from(Sha256::digest(input)));
        }
        assert!(write_private(&path, &fresh(&routes).unwrap()).is_err());
        assert_eq!(read_private(&path).unwrap().as_slice(), serde_json::to_vec_pretty(&pending).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        routes[0].pin.run = [9; 32];
        assert!(bind(&mut routes, &saved.witnesses).is_err());
        fs::remove_file(path).unwrap();
    }
}
