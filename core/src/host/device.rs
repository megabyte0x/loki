//! Member-local wiring for device authentication (the daily-login half of the recovery flow).
//!
//! A device holds a P-256 login key (the Secure Enclave key in the native signer). Loki
//! recognises it by challenge/response: `GET /api/device-challenge` issues a random nonce, the
//! device signs it, `POST /api/device-login` verifies the signature against the device's
//! enrolled public key — Loki never sees a private key. A device is enrolled only once the
//! recovery identity (the 24 words) has authorized it (`POST /api/device-enroll`), which is how
//! a new phone registers; `POST /api/device-revoke` drops a compromised device.
//!
//! The [`DeviceRegistry`](crate::signer::device_auth::DeviceRegistry) is the audited protocol
//! core; this module only persists enrolled devices (so they survive a restart) and exposes
//! the registry over HTTP. Enrollments are re-verified against the recovery key on reload, so
//! a tampered `devices.json` cannot inject a device the recovery words never signed.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use axum::{extract::State, http::HeaderMap, Json};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::routes::{err, ok, Reply};
use super::state::Shared;
use crate::signer::device_auth::{device_id, DeviceRegistry};
use axum::http::StatusCode;

/// One persisted enrolled device: its SEC1 P-256 public key, the recovery authorization that
/// admitted it (re-verified on load), and whether it is still active.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDevice {
    device_pub: String,
    authorization: String,
    active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_generation: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewal_generation: Option<[u8; 32]>,
}

pub(super) struct DeviceState {
    registry: DeviceRegistry,
    stored: Vec<StoredDevice>,
    // A second member process must not cache an independent registry for this profile.
    _lock: fs::File,
}

fn load_stored(data: &Path) -> Result<Vec<StoredDevice>, String> {
    match fs::read(data.join("devices.json")) {
        Ok(raw) => {
            serde_json::from_slice(&raw).map_err(|e| format!("invalid device registry: {e}"))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("could not read device registry: {e}")),
    }
}

fn save_stored(data: &Path, devices: &[StoredDevice]) -> Result<(), String> {
    let raw = serde_json::to_vec_pretty(devices).map_err(|e| e.to_string())?;
    let temp = data.join(format!(".devices.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|e| e.to_string())?;
    let result = file.write_all(&raw).and_then(|_| file.sync_all());
    drop(file);
    let result = result.and_then(|_| fs::rename(&temp, data.join("devices.json")));
    #[cfg(unix)]
    let result = result.and_then(|_| fs::File::open(data)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|e| e.to_string())
}

/// Rebuild the registry from disk: bind it to the recovery device-authorization key and
/// re-enroll each persisted device (which re-verifies its authorization), then re-apply
/// revocations. Errors if no recovery identity has been established yet.
fn build_registry(data: &Path, stored: &[StoredDevice]) -> Result<DeviceRegistry, String> {
    let authz = super::recovery::read_authz_pubkey(data)
        .ok_or("no recovery identity yet — run recovery setup first")?;
    let mut registry = DeviceRegistry::new(authz);
    let mut keys = std::collections::BTreeSet::new();
    for d in stored {
        let device_pub = hex::decode(&d.device_pub).map_err(|e| e.to_string())?;
        if !keys.insert(device_id(&device_pub)?) || (d.active && d.renewal_generation.is_some()) {
            return Err("inconsistent device registry".into());
        }
        let authorization: [u8; 64] = hex::decode(&d.authorization)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "stored authorization is not 64 bytes")?;
        match d.proof_generation {
            Some(generation) => {
                registry.enroll_renewal(&device_pub, &generation, &authorization)?
            }
            None => registry.enroll(&device_pub, &authorization)?,
        }
        if !d.active {
            registry.revoke(&device_pub);
        }
    }
    Ok(registry)
}

impl DeviceState {
    fn open(data: &Path) -> Result<Self, String> {
        let lock = fs::File::open(data).map_err(|e| e.to_string())?;
        lock.try_lock().map_err(|e| e.to_string())?;
        let stored = load_stored(data)?;
        let registry = build_registry(data, &stored)?;
        Ok(Self {
            registry,
            stored,
            _lock: lock,
        })
    }

    fn find(&self, device: &[u8]) -> Option<usize> {
        self.stored.iter().position(|d| {
            hex::decode(&d.device_pub)
                .ok()
                .and_then(|pubkey| device_id(&pubkey).ok())
                .as_deref()
                == Some(device)
        })
    }
}

fn hex_field(body: &Value, name: &str) -> Result<Vec<u8>, Reply> {
    body.get(name)
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                format!("missing or invalid hex {name}"),
            )
        })
}

/// Run `f` against the in-process registry, lazily building it from disk on first use. The
/// guard is held only for the synchronous closure (no `.await` inside), so it never blocks a
/// worker across a yield point.
fn with_registry<F>(st: &Shared, f: F) -> Reply
where
    F: FnOnce(&mut DeviceState) -> Reply,
{
    let mut guard = st.device_auth.lock().unwrap();
    if guard.is_none() {
        match DeviceState::open(&st.config.data) {
            Ok(r) => *guard = Some(r),
            Err(e) => return err(StatusCode::CONFLICT, e),
        }
    }
    let reply = f(guard.as_mut().unwrap());
    // A post-rename sync failure may leave the new snapshot visible. Never keep serving a
    // cached version after an ambiguous write; the next request reloads disk under the lock.
    if reply.0 == StatusCode::INTERNAL_SERVER_ERROR {
        *guard = None;
    }
    reply
}

/// POST /api/device-enroll { device_pub, authorization } — enroll a recovery-authorized device.
pub(super) async fn enroll(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let device_pub = match hex_field(&body, "device_pub") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let authorization: [u8; 64] = match hex_field(&body, "authorization").map(TryInto::try_into) {
        Ok(Ok(a)) => a,
        Ok(Err(_)) => return err(StatusCode::BAD_REQUEST, "authorization must be 64 bytes"),
        Err(e) => return e,
    };
    let id = match device_id(&device_pub) {
        Ok(id) => id,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    with_registry(&st, |state| {
        let index = state.find(&id);
        let device_hex = hex::encode(&device_pub);
        let proof_hex = hex::encode(authorization);
        let mut registry = state.registry.clone();
        let generation = match index.map(|i| &state.stored[i]) {
            Some(d) if d.active => {
                if (d.device_pub != device_hex || d.authorization != proof_hex)
                    && registry.enroll(&device_pub, &authorization).is_err()
                {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "device authorization does not verify",
                    );
                }
                return ok(json!({ "enrolled": true }));
            }
            Some(d) => match d.renewal_generation {
                Some(generation) => Some(generation),
                None => {
                    return err(
                        StatusCode::CONFLICT,
                        "request the current device renewal generation first",
                    )
                }
            },
            None => None,
        };
        let result = match generation {
            Some(generation) => registry.enroll_renewal(&device_pub, &generation, &authorization),
            None => registry.enroll(&device_pub, &authorization),
        };
        if let Err(e) = result {
            return err(StatusCode::BAD_REQUEST, e);
        }
        let row = StoredDevice {
            device_pub: device_hex,
            authorization: proof_hex,
            active: true,
            proof_generation: generation,
            renewal_generation: None,
        };
        let mut stored = state.stored.clone();
        if let Some(i) = index {
            stored[i] = row;
        } else {
            stored.push(row);
        }
        if let Err(e) = save_stored(&st.config.data, &stored) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, e);
        }
        state.stored = stored;
        state.registry = registry;
        ok(json!({ "enrolled": true }))
    })
}

/// POST /api/device-renewal { device_pub } — get the current generation for a revoked key.
pub(super) async fn renewal(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let id = match hex_field(&body, "device_pub") {
        Ok(v) => match device_id(&v) {
            Ok(id) => id,
            Err(e) => return err(StatusCode::BAD_REQUEST, e),
        },
        Err(e) => return e,
    };
    with_registry(&st, |state| {
        let Some(i) = state.find(&id).filter(|&i| !state.stored[i].active) else {
            return err(StatusCode::CONFLICT, "device is not revoked");
        };
        let generation = match state.stored[i].renewal_generation {
            Some(g) => g,
            None => {
                // A legacy revoked record has no renewal generation until its first request.
                let mut generation = [0; 32];
                OsRng.fill_bytes(&mut generation);
                let mut stored = state.stored.clone();
                stored[i].renewal_generation = Some(generation);
                if let Err(e) = save_stored(&st.config.data, &stored) {
                    return err(StatusCode::INTERNAL_SERVER_ERROR, e);
                }
                state.stored = stored;
                generation
            }
        };
        ok(json!({ "generation": hex::encode(generation) }))
    })
}

/// GET /api/device-challenge — issue a one-time random login challenge.
pub(super) async fn challenge(State(st): State<Shared>, headers: HeaderMap) -> Reply {
    let Some(token) = headers.get("x-loki-token") else {
        return err(StatusCode::UNAUTHORIZED, "missing device grant");
    };
    let grant = *blake3::hash(token.as_bytes()).as_bytes();
    with_registry(&st, |state| match state.registry.issue_challenge(grant) {
        Some(challenge) => ok(json!({ "challenge": hex::encode(challenge) })),
        None => err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many device challenges; retry in two minutes",
        ),
    })
}

/// POST /api/device-login { device_pub, challenge, signature } — verify a device's response.
pub(super) async fn login(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (device_pub, challenge, signature) = match (
        hex_field(&body, "device_pub"),
        hex_field(&body, "challenge"),
        hex_field(&body, "signature"),
    ) {
        (Ok(d), Ok(c), Ok(s)) => (d, c, s),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return e,
    };
    let challenge: [u8; 32] = match challenge.try_into() {
        Ok(c) => c,
        Err(_) => return err(StatusCode::BAD_REQUEST, "challenge must be 32 bytes"),
    };
    with_registry(&st, |state| {
        match state
            .registry
            .verify_login(&device_pub, &challenge, &signature)
        {
            Ok(()) => ok(json!({ "logged_in": true })),
            Err(e) => err(StatusCode::UNAUTHORIZED, e),
        }
    })
}

/// POST /api/device-revoke { device_pub } — revoke a compromised device's login.
pub(super) async fn revoke(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let device_pub = match hex_field(&body, "device_pub") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let id = match device_id(&device_pub) {
        Ok(id) => id,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    with_registry(&st, |state| {
        if let Some(i) = state.find(&id).filter(|&i| state.stored[i].active) {
            let mut generation = [0; 32];
            OsRng.fill_bytes(&mut generation);
            let mut stored = state.stored.clone();
            stored[i].active = false;
            stored[i].renewal_generation = Some(generation);
            if let Err(e) = save_stored(&st.config.data, &stored) {
                return err(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
            state.stored = stored;
            state.registry.revoke(&device_pub);
        }
        ok(json!({ "revoked": true }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::recovery::RecoveryKey;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use std::path::PathBuf;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-device-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // Write a recovery identity's public keys where build_registry expects them.
    fn write_recovery_pub(data: &Path, key: &RecoveryKey) {
        let mut pubkeys = Vec::new();
        pubkeys.extend_from_slice(&key.public_bytes());
        pubkeys.extend_from_slice(&key.signing_public());
        fs::write(data.join("recovery.pub"), pubkeys).unwrap();
    }

    #[test]
    fn enrolled_device_survives_a_rebuild_and_revocation_sticks() {
        let data = tempdir();
        let (_words, recovery) = RecoveryKey::generate().unwrap();
        write_recovery_pub(&data, &recovery);

        // Enroll a device: persist its recovery authorization.
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let device_pub = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let authorization = recovery.authorize_device(&device_pub);
        save_stored(
            &data,
            &[StoredDevice {
                device_pub: hex::encode(&device_pub),
                authorization: hex::encode(authorization),
                active: true,
                proof_generation: None,
                renewal_generation: None,
            }],
        )
        .unwrap();

        // Rebuild from disk (restart): the device logs in.
        let mut state = DeviceState::open(&data).unwrap();
        let challenge = state.registry.issue_challenge([0; 32]).unwrap();
        let sig: Signature = sk.sign(&challenge);
        state
            .registry
            .verify_login(&device_pub, &challenge, &sig.to_der().as_bytes().to_vec())
            .expect("reloaded device logs in");
        drop(state);

        // A tampered devices.json whose authorization is for a DIFFERENT recovery key is
        // refused on rebuild (re-verification), so it cannot inject an unauthorized device.
        let (_w2, other) = RecoveryKey::generate().unwrap();
        save_stored(
            &data,
            &[StoredDevice {
                device_pub: hex::encode(&device_pub),
                authorization: hex::encode(other.authorize_device(&device_pub)),
                active: true,
                proof_generation: None,
                renewal_generation: None,
            }],
        )
        .unwrap();
        assert!(
            DeviceState::open(&data).is_err(),
            "forged authorization is rejected on reload"
        );

        // A revoked device stays revoked across a rebuild.
        save_stored(
            &data,
            &[StoredDevice {
                device_pub: hex::encode(&device_pub),
                authorization: hex::encode(authorization),
                active: false,
                proof_generation: None,
                renewal_generation: None,
            }],
        )
        .unwrap();
        let mut state = DeviceState::open(&data).unwrap();
        let challenge = state.registry.issue_challenge([0; 32]).unwrap();
        let sig: Signature = sk.sign(&challenge);
        assert!(
            state
                .registry
                .verify_login(&device_pub, &challenge, &sig.to_der().as_bytes().to_vec())
                .is_err(),
            "a revoked device must not log in after reload"
        );
    }
}
