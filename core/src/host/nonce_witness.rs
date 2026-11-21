//! Hosted signing uses the same fresh, signed nonce claims as standalone signing.
//! The operator supplies two independently managed, pre-provisioned relay mailboxes.

use std::{io::Read, path::Path};
use loki_relay_client::RelayHttp;
use loki_relay_protocol::types::{RelayPin, RelayRoute};
use crate::setup_transport::Identity;
use crate::signing_session::{NonceWitness, WitnessPins};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
// Ignore the retired `read` field in old files; never serialize or use it.
pub struct WitnessConfig {
    pub endpoint: String,
    pub key: [u8; 32],
    pub run: [u8; 32],
    pub mailbox: [u8; 32],
}

pub(super) struct RelayWitness {
    attempt: String,
    routes: [RelayRoute; 2],
    claimant: Option<([u8; 32], Identity)>,
    http: RelayHttp,
    runtime: tokio::runtime::Runtime,
}

/// Read a `--nonce-witnesses` file: two [`WitnessConfig`] entries.
pub(super) fn read(path: &Path) -> Result<[WitnessConfig; 2], String> {
    let mut raw = Zeroizing::new(Vec::new());
    std::fs::File::open(path).map_err(|e| format!("nonce witnesses: {e}"))?
        .take(16_385).read_to_end(&mut raw).map_err(|e| format!("nonce witnesses: {e}"))?;
    if raw.len() > 16_384 { return Err("nonce witness configuration too large".into()); }
    serde_json::from_slice(&raw).map_err(|_| "invalid nonce witness configuration".into())
}

/// What every witness configuration passes before hosted signing uses it: two distinct,
/// nonzero witness identities at valid relay endpoints (HTTPS, or loopback HTTP in development).
pub(super) fn check(config: &[WitnessConfig; 2], development: bool) -> Result<(), String> {
    if !crate::signing_session::valid_witness_pins(std::array::from_fn(|i| (config[i].key, config[i].run, config[i].mailbox))) {
        return Err("two distinct nonzero nonce witnesses required".into());
    }
    for witness in config {
        loki_relay_client::validate_endpoint(&witness.endpoint, development)
            .map_err(|_| "a nonce witness endpoint is not a plain HTTPS origin; loopback HTTP requires --development-http")?;
    }
    Ok(())
}

pub(super) fn fingerprint(config: &[WitnessConfig; 2]) -> String {
    hex::encode(crate::signing_session::witness_fingerprint(
        config.each_ref().map(|w| (w.key, w.run, w.mailbox)),
    ))
}

impl RelayWitness {
    /// LokiSigner's approved launch snapshot, or the headless `--nonce-witnesses` file.
    pub(super) fn for_member(st: &super::state::AppState, attempt: &str) -> Result<Self, String> {
        let development = st.config.development_http;
        match (&st.config.nonce_witnesses, &st.fetched_config) {
            (None, Some(fetched)) => Self::from_config(fetched.witnesses(), development, attempt),
            (path, _) => Self::open(path.as_deref(), development, attempt),
        }
    }

    pub(super) fn open(path: Option<&Path>, development: bool, attempt: &str) -> Result<Self, String> {
        Self::from_config(read(path.ok_or("hosted signing requires --nonce-witnesses <file>")?)?, development, attempt)
    }

    fn from_config(config: [WitnessConfig; 2], development: bool, attempt: &str) -> Result<Self, String> {
        check(&config, development)?;
        let routes = config.map(|c| RelayRoute {
            pin: RelayPin { key: c.key, run: c.run }, endpoint: c.endpoint,
            mailbox: c.mailbox, append_revision: 1,
        });
        Ok(Self {
            attempt: attempt.to_owned(),
            routes,
            claimant: None,
            http: if development { RelayHttp::new() } else { RelayHttp::hosted() }
                .map_err(|e| e.to_string())?,
            runtime: tokio::runtime::Builder::new_current_thread().enable_all().build()
                .map_err(|e| e.to_string())?,
        })
    }

    pub(super) fn authorize(mut self, vault: [u8; 32], identity: &Identity) -> Result<Self, String> {
        let secret = Zeroizing::new(identity.to_secret_bytes());
        self.claimant = Some((vault, Identity::from_secret_bytes(&secret[..])?));
        Ok(self)
    }
}

impl NonceWitness for RelayWitness {
    fn pins(&self) -> WitnessPins {
        std::array::from_fn(|i| {
            let route = &self.routes[i];
            (route.pin.key, route.pin.run, route.mailbox)
        })
    }

    fn claim(&mut self, cid: [u8; 32], record: &[u8]) -> Result<(), String> {
        let (vault, identity) = self.claimant.as_ref().ok_or("nonce witness has no vault identity")?;
        for (index, route) in self.routes.iter().enumerate() {
            let (attempt, witness) = (&self.attempt, index + 1);
            eprintln!("payment {attempt}: relay sending nonce claim to witness {witness}");
            let created = self.runtime.block_on(self.http.claim_nonce(route, cid, record, |challenge| {
                identity.nonce_claim_proof(*vault, &route.pin, route.mailbox, cid, challenge, record)
            }))
                .map_err(|e| {
                    eprintln!("payment {attempt}: relay nonce claim error from witness {witness}");
                    format!("nonce witness claim: {e}")
                })?;
            eprintln!("payment {attempt}: relay received nonce claim response from witness {witness}: {}", if created { "accepted" } else { "duplicate" });
            if !created { return Err("nonce already claimed; start a new signing attempt".into()); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_signing_requires_external_witness_configuration() {
        assert!(RelayWitness::open(None, false, "test").err().unwrap().contains("--nonce-witnesses"));
    }

    #[test]
    fn provisioned_witness_json_round_trips_into_hosted_signing() {
        let config = [1, 5].map(|n| WitnessConfig {
            endpoint: "http://127.0.0.1:39101".into(), key: [n; 32],
            run: [n + 1; 32], mailbox: [n + 2; 32],
        });
        let raw = Zeroizing::new(serde_json::to_vec_pretty(&config).unwrap());
        let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 2);
        for (entry, n) in json.as_array().unwrap().iter().zip([1, 5]) {
            assert_eq!(entry.as_object().unwrap().len(), 4);
            for (field, value) in [("key", n), ("run", n + 1), ("mailbox", n + 2)] {
                assert_eq!(entry[field], serde_json::json!(vec![value; 32]));
            }
        }
        let decoded: [WitnessConfig; 2] = serde_json::from_slice(&raw).unwrap();
        assert!(decoded == config);
        let path = std::env::temp_dir().join(format!("loki-witness-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&path, &*raw).unwrap();
        let witness = RelayWitness::open(Some(&path), true, "test").unwrap();
        assert_eq!(witness.pins(), [([1; 32], [2; 32], [3; 32]), ([5; 32], [6; 32], [7; 32])]);
        assert!(RelayWitness::open(Some(&path), false, "test").is_err());
        std::fs::remove_file(path).unwrap();
    }

    /// Live: two dev relays enrolled for the fixture identity, named by
    /// `LOKI_NONCE_TEST_WITNESSES`. A fresh claim is accepted by both; the same claim again is
    /// refused, which is what blocks a rolled-back nonce from signing twice.
    #[test]
    fn provisioned_relays_accept_a_claim_once_and_refuse_a_duplicate() {
        let Some(path) = std::env::var_os("LOKI_NONCE_TEST_WITNESSES") else { return };
        let mut secret = [7; 66];
        secret[..2].copy_from_slice(&1u16.to_be_bytes());
        let identity = Identity::from_secret_bytes(&secret).unwrap();
        let mut witness = RelayWitness::open(Some(Path::new(&path)), true, "test").unwrap()
            .authorize([8; 32], &identity).unwrap();
        let mut cid = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut cid);
        witness.claim(cid, b"first use").unwrap();
        let again = witness.claim(cid, b"first use").unwrap_err();
        assert!(again.contains("already claimed"), "{again}");
        let other = witness.claim(cid, b"another use").unwrap_err();
        assert!(other.contains("already claimed") || other.contains("nonce witness claim"), "{other}");
    }

    #[test]
    fn witness_configuration_requires_two_distinct_identities() {
        let path = std::env::temp_dir().join(format!("loki-witness-{}.json", uuid::Uuid::new_v4()));
        let entry = |n: u8| serde_json::json!({
            "endpoint": "https://example.invalid", "key": ([n; 32].to_vec()),
            "run": ([n + 1; 32].to_vec()), "mailbox": ([n + 2; 32].to_vec()), "read": ([n + 3; 32].to_vec())
        });
        std::fs::write(&path, serde_json::to_vec(&[entry(1), entry(1)]).unwrap()).unwrap();
        assert!(RelayWitness::open(Some(&path), false, "test").is_err());
        std::fs::write(&path, serde_json::to_vec(&[entry(1), entry(5)]).unwrap()).unwrap();
        let witness = RelayWitness::open(Some(&path), false, "test").unwrap();
        assert_eq!(witness.pins(), [([1; 32], [2; 32], [3; 32]), ([5; 32], [6; 32], [7; 32])]);
        std::fs::remove_file(path).unwrap();
    }
}
