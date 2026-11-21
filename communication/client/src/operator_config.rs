use crate::{ClientError, ClientResult};
use loki_relay_protocol::WireError;
use std::net::IpAddr;

// Conservative Internet-unicast allowlist; mapped and transition IPv6 are not accepted.
pub(crate) fn public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || matches!((a, b), (100, 64..=127) | (169, 254) | (172, 16..=31) | (192, 168) | (198, 18..=19))
                || matches!((a, b, c), (192, 0, 0 | 2) | (192, 88, 99) | (198, 51, 100) | (203, 0, 113)))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (0x2000..=0x3fff).contains(&a)
                && !((a == 0x2001 && (b < 0x0200 || b == 0x0db8)) || matches!(a, 0x2002 | 0x3fff))
        }
    }
}

/// Signed descriptors still have to pass local destination policy. DNS answers are checked
/// by the transport when it connects, not assumed safe merely because a name passed import.
pub fn validate_peer_destination(raw: &str, development: bool) -> ClientResult<()> {
    let url = checked_url(raw, development)?;
    let name = url.host_str().ok_or(ClientError::Config)?;
    if name.trim_matches(['[', ']']).parse::<IpAddr>().is_err() {
        let name = name.trim_end_matches('.');
        if !name.contains('.') || [".localhost", ".local", ".internal", ".home.arpa"]
            .iter().any(|suffix| name.ends_with(suffix)) || name == "home.arpa" {
            return Err(ClientError::Config);
        }
    }
    Ok(())
}

pub fn validate_endpoint(raw: &str, development: bool) -> ClientResult<()> {
    checked_url(raw, development).map(|_| ())
}

fn checked_url(raw: &str, development: bool) -> ClientResult<reqwest::Url> {
    if raw.len() > 2048 {
        return Err(WireError::Bounds.into());
    }
    if !raw.is_ascii()
        || raw
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(ClientError::Config);
    }
    let (scheme, rest) = raw.split_once("://").ok_or(ClientError::Config)?;
    if scheme != "https" && !(scheme == "http" && development) {
        return Err(ClientError::Config);
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || !path.is_empty() || authority.contains(['@', '?', '#', '\\', '%']) {
        return Err(ClientError::Config);
    }
    let port = if authority.starts_with('[') {
        let (_, suffix) = authority.split_once(']').ok_or(ClientError::Config)?;
        if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or(ClientError::Config)?)
        }
    } else {
        authority.split_once(':').map(|(_, port)| port)
    };
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|p| *p != 0).is_none()
        {
            return Err(ClientError::Config);
        }
    }
    if scheme == "http" && !(authority.starts_with("127.0.0.1:") || authority.starts_with("[::1]:"))
    {
        return Err(ClientError::Config);
    }
    let url = reqwest::Url::parse(raw).map_err(|_| ClientError::Config)?;
    if url.scheme() != scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ClientError::Config);
    }
    let address = url.host_str().and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok());
    if let Some(address) = address {
        if !public_destination(address) && !(development && scheme == "http" && address.is_loopback()) {
            return Err(ClientError::Config);
        }
    }
    Ok(url)
}

use ed25519_dalek::{Signature, VerifyingKey};
use loki_relay_protocol::{
    canonical::{self, Value},
    types::{Id32, RelayPin, RelayRoute},
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const BUNDLE_LIMIT: usize = 16384;
const CONFIG_DOMAIN: &[u8] = b"Loki_Operator_Config_v1\0";

pub struct OperatorSet {
    relays: [RelayRoute; 3],
    admission_origin: String,
    admission_key: Id32,
    setup_versions: Vec<u16>,
    limits: ServiceLimits,
    digest: Id32,
}

pub struct ServiceLimits {
    pub first_claim_seconds: u64,
    pub ceremony_seconds: u64,
    pub payload_bytes: u64,
    pub storage_bytes_per_relay: u64,
    pub request_seconds: u64,
    pub retry_min_seconds: u64,
    pub retry_max_seconds: u64,
}

fn fields(value: &Value, count: usize) -> ClientResult<&[Value]> {
    match value {
        Value::Array(values) if values.len() == count => Ok(values),
        _ => Err(ClientError::Config),
    }
}

fn bytes(value: &Value) -> ClientResult<&[u8]> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(ClientError::Config),
    }
}

fn id(value: &Value) -> ClientResult<Id32> {
    bytes(value)?.try_into().map_err(|_| ClientError::Config)
}

fn number(value: &Value) -> ClientResult<u64> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| ClientError::Config),
        _ => Err(ClientError::Config),
    }
}

fn origin(value: &Value, development: bool) -> ClientResult<String> {
    let raw = std::str::from_utf8(bytes(value)?).map_err(|_| ClientError::Config)?;
    validate_endpoint(raw, development)?;
    Ok(raw.to_owned())
}

impl OperatorSet {
    pub fn verify(bundle: &[u8], trusted_config_key: &Id32) -> ClientResult<Self> {
        Self::verify_mode(bundle, trusted_config_key, false)
    }
    pub fn verify_development(bundle: &[u8], trusted_config_key: &Id32) -> ClientResult<Self> {
        Self::verify_mode(bundle, trusted_config_key, true)
    }
    fn verify_mode(
        bundle: &[u8],
        trusted_config_key: &Id32,
        development: bool,
    ) -> ClientResult<Self> {
        let package = canonical::decode(bundle, BUNDLE_LIMIT)?;
        let signed = fields(&package, 2)?;
        let body = bytes(&signed[0])?;
        let mut input = Vec::with_capacity(CONFIG_DOMAIN.len() + 4 + body.len());
        input.extend_from_slice(CONFIG_DOMAIN);
        input.extend_from_slice(&(body.len() as u32).to_be_bytes());
        input.extend_from_slice(body);
        VerifyingKey::from_bytes(trusted_config_key)?
            .verify_strict(&input, &Signature::from_slice(bytes(&signed[1])?)?)?;
        let value = canonical::decode(body, BUNDLE_LIMIT)?;
        let config = fields(&value, 5)?;
        if number(&config[0])? != 1 {
            return Err(WireError::Version.into());
        }
        let routes = fields(&config[1], 3)?;
        let relays = routes
            .iter()
            .map(|value| {
                let route = fields(value, 3)?;
                let key = id(&route[0])?;
                VerifyingKey::from_bytes(&key)?;
                let run = id(&route[1])?;
                if key == [0; 32] || run == [0; 32] {
                    return Err(ClientError::Config);
                }
                Ok(RelayRoute {
                    pin: RelayPin { key, run },
                    endpoint: origin(&route[2], development)?,
                    mailbox: [0; 32],
                    append_revision: 1,
                })
            })
            .collect::<ClientResult<Vec<_>>>()?;
        if relays
            .windows(2)
            .any(|pair| pair[0].pin.key >= pair[1].pin.key)
            || relays
                .iter()
                .map(|relay| relay.pin.run)
                .collect::<HashSet<_>>()
                .len()
                != relays.len()
        {
            return Err(ClientError::Config);
        }
        let admission = fields(&config[2], 2)?;
        let admission_origin = origin(&admission[0], development)?;
        let admission_key = id(&admission[1])?;
        VerifyingKey::from_bytes(&admission_key)?;
        if admission_key == [0; 32] {
            return Err(ClientError::Config);
        }
        let versions = fields(&config[3], 1)?;
        if number(&versions[0])? != u64::from(loki_relay_protocol::setup::SETUP_VERSION) {
            return Err(WireError::Version.into());
        }
        let policy = fields(&config[4], 7)?;
        let values = policy
            .iter()
            .map(number)
            .collect::<ClientResult<Vec<_>>>()?;
        let maxima = [86400, 2592000, 1048576, 67108864, 30, 60, 60];
        if values
            .iter()
            .zip(maxima)
            .any(|(value, max)| *value == 0 || *value > max)
            || values[0] > values[1]
            || values[2] > values[3]
            || values[5] > values[6]
        {
            return Err(ClientError::Config);
        }
        Ok(Self {
            relays: relays.try_into().map_err(|_| ClientError::Config)?,
            admission_origin,
            admission_key,
            setup_versions: vec![loki_relay_protocol::setup::SETUP_VERSION],
            limits: ServiceLimits {
                first_claim_seconds: values[0],
                ceremony_seconds: values[1],
                payload_bytes: values[2],
                storage_bytes_per_relay: values[3],
                request_seconds: values[4],
                retry_min_seconds: values[5],
                retry_max_seconds: values[6],
            },
            digest: Sha256::digest(bundle).into(),
        })
    }

    pub fn relay_routes(&self) -> &[RelayRoute] {
        &self.relays
    }
    pub fn admission_origin(&self) -> &str {
        &self.admission_origin
    }
    pub fn admission_key(&self) -> &Id32 {
        &self.admission_key
    }
    pub fn setup_versions(&self) -> &[u16] {
        &self.setup_versions
    }
    pub fn limits(&self) -> &ServiceLimits {
        &self.limits
    }
    pub fn digest(&self) -> &Id32 {
        &self.digest
    }
}
