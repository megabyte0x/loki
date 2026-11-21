//! HTTP enrollment and frostd DKG for one sealed member vault.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use base64::Engine;
use rand_core::{OsRng, RngCore};
use reddsa_frost::frost::redpallas as frost;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use zcash_protocol::consensus::Parameters;
use zeroize::Zeroizing;

use super::{
    routes::{blocking, err},
    state::{Config, Shared},
};
use crate::{
    frost_roster::FrostRoster,
    network::{VaultNetwork, TESTNET_NU7_BIRTH},
    setup_transport::{Identity, PublicIdentity},
    signer::{
        backup::BackupArtifact,
        coordination::{member_dkg_step, redeliver_dkg, relay_dkg},
        local::{roster_code, ApprovalPolicy, BackupDevice, DevicePrompts, LocalSigner, RosterDecision, SignerError},
        Network, Signer,
    },
    signing_session::{MessageKind, SessionContext},
    state::MemberDir,
    transport::{FrostdLoginKey, FrostdTransport, Outbound, Peer, RelayLog, SealedPeer, Transport},
    vault, zip2005,
};

type Reply = (StatusCode, Json<Value>);

struct HostedBackup {
    dir: PathBuf,
    pass: Zeroizing<String>,
}

impl BackupDevice for HostedBackup {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(self.pass.clone())
    }
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        let store = MemberDir::open(&self.dir, "");
        if store.exists("backup.sealed") {
            return Ok(());
        }
        store.write_sealed("backup.sealed", &artifact.0, &self.pass)
            .map_err(|e| e.to_string())
    }
    fn load(&mut self) -> Result<BackupArtifact, String> {
        MemberDir::open(&self.dir, "")
            .read_sealed("backup.sealed", &self.pass)
            .map(BackupArtifact)
            .map_err(|e| e.to_string())
    }
}

/// The hosted member's device prompts. The hosted flow already required the member's roster
/// agreement, and payment approval goes to `approval` (the member's native decision).
pub(super) fn hosted_prompts(signer_dir: &Path, pass: &str, approval: ApprovalPolicy) -> DevicePrompts {
    DevicePrompts {
        connect: Box::new(|_, _| true),
        // Only the hosted DKG compares a roster code (`roster_decision`); every other open refuses.
        roster: Box::new(|_| RosterDecision::NoMatch),
        roster_deadline: Duration::from_secs(60),
        backup: Box::new(HostedBackup { dir: signer_dir.to_owned(), pass: Zeroizing::new(pass.to_owned()) }),
        approval,
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct WireIdentity {
    id: u16,
    signing: String,
    encryption: String,
}

impl WireIdentity {
    pub(super) fn from_public(p: PublicIdentity) -> Self {
        Self {
            id: p.id,
            signing: hex::encode(p.signing),
            encryption: hex::encode(p.encryption),
        }
    }

    pub(super) fn public(&self, slot: u16) -> Result<PublicIdentity, String> {
        if self.id != slot {
            return Err("identity slot mismatch".into());
        }
        let signing: [u8; 32] = hex::decode(&self.signing)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "signing key must be 32 bytes")?;
        let encryption: [u8; 32] = hex::decode(&self.encryption)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "encryption key must be 32 bytes")?;
        ed25519_dalek::VerifyingKey::from_bytes(&signing).map_err(|e| e.to_string())?;
        if encryption == [0; 32] {
            return Err("invalid encryption key".into());
        }
        Ok(PublicIdentity {
            id: slot,
            signing,
            encryption,
        })
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Slot {
    identity: Option<WireIdentity>,
    pending_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Ceremony {
    vault: String,
    pub(super) name: String,
    members: u16,
    threshold: u16,
    pub(super) my_slot: u16,
    creator_base_url: String,
    frostd_url: String,
    slots: BTreeMap<u16, Slot>,
    fingerprint: Option<String>,
    agreed: BTreeSet<u16>,
    session_id: Option<Uuid>,
    #[serde(default)]
    coordinator_peer: Option<String>,
    #[serde(default)]
    vs_session_id: Option<Uuid>,
    dkg_started: bool,
    error: Option<String>,
    // The creator's testnet birth height, published to joiners so their setup document
    // matches the creator's byte-for-byte (joiners must not reconstruct it from a guess).
    #[serde(default)]
    birth_height: Option<u32>,
    // Do not resume from older agreement records, which may have come from HTTP alone.
    #[serde(default, rename = "locally_confirmed_roster_code")]
    roster_code: Option<String>,
    // A joiner's copy of the creator's identity from the invite: requests go to it over frostd.
    #[serde(default)]
    creator: Option<WireIdentity>,
}

#[derive(Serialize, Deserialize)]
struct Invite {
    vault: String,
    slot: u16,
    creator_base_url: String,
    token: String,
    members: u16,
    threshold: u16,
    name: String,
    // The creator's identity and relay: a joiner reaches the creator over frostd, not HTTP.
    #[serde(default)]
    creator: Option<WireIdentity>,
    #[serde(default)]
    frostd_url: Option<String>,
}

/// The embedded wallet's join precheck, before the shared `join` handler runs. A relay invite
/// must carry a valid creator identity: it joins through this member's own frostd, never the
/// relay or HTTP endpoint the invite names, so its `creator_base_url` (often loopback) is not
/// checked. Only an invite with no relay fields is a legacy HTTP invite, and its creator must be
/// the paired coordinator, an allowed peer or this signer; `join` then applies the peer checks.
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
pub(super) fn embedded_invite_target(config: &super::Config, body: &Value) -> Result<(), &'static str> {
    const INVALID: &str = "invalid invite";
    let raw: Value = body["invite"].as_str().filter(|s| s.len() <= 4096)
        .and_then(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .filter(Value::is_object).ok_or(INVALID)?;
    let relay = !raw["creator"].is_null() || !raw["frostd_url"].is_null();
    let invite: Invite = serde_json::from_value(raw).map_err(|_| INVALID)?;
    if relay {
        invite.creator.as_ref().ok_or("relay invite has no creator identity")?
            .public(1).map_err(|_| "relay invite has an invalid creator identity")?;
        return crate::transport::require_tls_off_loopback(&config.frostd_url)
            .map_err(|_| "this signer has no usable relay for a relay invite");
    }
    let url = invite.creator_base_url.as_str();
    if config.registration.as_ref().is_some_and(|paired| paired.coordinator == url)
        || config.peers.values().any(|peer| peer == url)
        || config.lokisigner_url().as_deref() == Some(url)
    {
        Ok(())
    } else {
        Err("invite does not name the paired coordinator or an allowed peer")
    }
}

/// Shared roster policy, including the member cap.
use crate::member_state::valid_policy;

fn vault_bytes(vault: &str) -> Result<[u8; 32], String> {
    hex::decode(vault)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "vault must be 32 bytes of hex".into())
}

pub(super) fn dir(data: &Path, vault: &str) -> Result<MemberDir, String> {
    let canonical = hex::encode(vault_bytes(vault)?);
    let parent = data.join("vaults");
    let entries = match std::fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(MemberDir::open(&parent, &canonical)),
        Err(e) => return Err(e.to_string()),
    };
    // Use a unique legacy spelling in place: renaming it could orphan path-bound keys.
    let mut existing = None;
    for entry in entries {
        let name = entry.map_err(|e| e.to_string())?.file_name();
        if let Some(name) = name.to_str().filter(|name| name.eq_ignore_ascii_case(&canonical)) {
            if existing.replace(name.to_owned()).is_some() {
                return Err("multiple directories for this vault; preserve both and resolve the conflict before restoring".into());
            }
        }
    }
    Ok(MemberDir::open(&parent, existing.as_deref().unwrap_or(&canonical)))
}

pub(super) fn load(data: &Path, pass: &str, vault: &str) -> Result<Ceremony, String> {
    let raw = dir(data, vault)?
        .read_sealed("ceremony.sealed", pass)
        .map_err(|e| e.to_string())?;
    let c: Ceremony = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if vault_bytes(&c.vault)? != vault_bytes(vault)? {
        return Err("ceremony vault mismatch".into());
    }
    Ok(c)
}

fn save(data: &Path, pass: &str, c: &Ceremony) -> Result<(), String> {
    let path = dir(data, &c.vault)?;
    let d = MemberDir::create(path.path(), "").map_err(|e| e.to_string())?;
    save_to(&d, pass, c)
}

fn save_to(d: &MemberDir, pass: &str, c: &Ceremony) -> Result<(), String> {
    let temp = format!("ceremony.{}.sealed", Uuid::new_v4());
    d.write_sealed(
        &temp,
        &serde_json::to_vec(c).map_err(|e| e.to_string())?,
        pass,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(d.path().join(&temp), d.path().join("ceremony.sealed"))
        .map_err(|e| e.to_string())
}

/// Summaries of every vault this member belongs to, for the home screen. Best-effort: a vault
/// whose ceremony file won't open (or isn't a 32-byte id) is skipped, not fatal to the list.
pub(super) fn vault_summaries(data: &Path, pass: &str) -> Result<Vec<Value>, String> {
    let root = data.join("vaults");
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(vault) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if vault_bytes(&vault).is_err() {
            continue;
        }
        if let Ok(c) = load(data, pass, &vault) {
            // `active` lets the home screen route a still-setting-up vault back to the
            // ceremony flow instead of the (unavailable) wallet view.
            let active = dir(data, &vault).map(|d| d.exists("vault.sealed")).unwrap_or(false);
            out.push(json!({
                "vault": c.vault,
                "name": c.name,
                "members": c.members,
                "threshold": c.threshold,
                "policy": format!("{}-of-{}", c.threshold, c.members),
                "active": active,
            }));
        }
    }
    Ok(out)
}

pub(super) fn identity(data: &Path, pass: &str, slot: u16) -> Result<Identity, String> {
    if !(1..=crate::member_state::MAX_MEMBERS).contains(&slot) {
        return Err("invalid member slot".into());
    }
    let d = MemberDir::create(data, ".").map_err(|e| e.to_string())?;
    match d.read_sealed("identity.sealed", pass) {
        Ok(raw) => {
            let mut raw = Zeroizing::new(raw);
            if raw.len() != 66 {
                return Err("invalid DKG identity length".into());
            }
            // Keys belong to the profile; the FROST slot belongs to each vault.
            raw[..2].copy_from_slice(&slot.to_be_bytes());
            Identity::from_secret_bytes(&raw)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = Identity::new(slot);
            let secret = Zeroizing::new(id.to_secret_bytes());
            d.write_sealed("identity.sealed", &secret[..], pass)
                .map_err(|e| e.to_string())?;
            Ok(id)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn roster_of(c: &Ceremony) -> Result<FrostRoster, String> {
    if c.slots.len() != usize::from(c.members) {
        return Err("roster pending".into());
    }
    let mut members = Vec::new();
    let mut addresses = BTreeSet::new();
    for slot in 1..=c.members {
        let wire = c
            .slots
            .get(&slot)
            .and_then(|s| s.identity.as_ref())
            .ok_or("roster pending")?;
        let public = wire.public(slot)?;
        if !addresses.insert(public.encryption) {
            return Err("duplicate relay address".into());
        }
        members.push((
            frost::Identifier::try_from(slot).map_err(|e| e.to_string())?,
            public,
        ));
    }
    Ok(FrostRoster::from_identities(
        vault_bytes(&c.vault)?,
        c.threshold,
        members,
    ))
}

fn invitations(c: &Ceremony) -> Result<Vec<Value>, String> {
    (2..=c.members)
        .map(|slot| {
            let s = c.slots.get(&slot).ok_or("missing invite slot")?;
            let token = s.pending_token.as_ref().ok_or("missing invite token")?;
            let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Invite {
                    vault: c.vault.clone(),
                    slot,
                    creator_base_url: c.creator_base_url.clone(),
                    token: token.clone(),
                    members: c.members,
                    threshold: c.threshold,
                    name: c.name.clone(),
                    creator: c.slots.get(&1).and_then(|s| s.identity.clone()),
                    frostd_url: Some(c.frostd_url.clone()),
                })
                .map_err(|e| e.to_string())?,
            );
            Ok(json!({"slot":slot,"code":code,"joined":s.identity.is_some()}))
        })
        .collect()
}

enum PeerRequestError {
    Unavailable(String),
    Rejected(String),
}

impl PeerRequestError {
    fn message(self) -> String {
        match self {
            Self::Unavailable(message) | Self::Rejected(message) => message,
        }
    }
}

/// A joiner's request `op` (enroll, roster, agreed or session) to the creator: sealed over
/// frostd when the invite named the creator, otherwise to the creator's HTTP route.
fn ask_creator(config: &Config, data: &Path, pass: &str, c: &Ceremony, op: &str) -> Result<Value, PeerRequestError> {
    let mut body = joiner_auth(c).map_err(PeerRequestError::Rejected)?;
    let Some(creator) = &c.creator else {
        if op == "enroll" {
            body["identity"] = json!(c.slots.get(&c.my_slot).and_then(|s| s.identity.as_ref()));
        }
        return peer_request_result(config, &c.creator_base_url, &format!("/api/{op}"), body);
    };
    body["op"] = json!(op);
    let me = identity(data, pass, c.my_slot).map_err(PeerRequestError::Rejected)?;
    let creator = creator.public(1).map_err(PeerRequestError::Rejected)?;
    relay_request(&c.frostd_url, &me, &creator, &c.vault, &body)
}

/// The sealed-envelope context of one join exchange between the creator (slot 1) and a joiner.
fn join_context(vault: &str, session: Uuid, slot: u16) -> Result<SessionContext, String> {
    Ok(SessionContext::control(vault_bytes(vault)?, session, 1, slot))
}

/// One join request over frostd: the joiner opens a session of itself and the creator, seals
/// `body` to the creator, and waits for the creator's sealed reply on that session.
fn relay_request(url: &str, me: &Identity, creator: &PublicIdentity, vault: &str, body: &Value)
    -> Result<Value, PeerRequestError>
{
    use PeerRequestError::{Rejected, Unavailable};
    let mut tx = super::payment::relay(me, url).map_err(Unavailable)?;
    let ch = tx.open(&[Peer(me.public().encryption), Peer(creator.encryption)], 2)
        .map_err(|e| Unavailable(e.to_string()))?;
    let context = join_context(vault, ch.session_id(), me.public().id).map_err(Rejected)?;
    let sealed = SealedPeer::seal_join(me, creator, &context, &serde_json::to_vec(body).map_err(|e| Rejected(e.to_string()))?)
        .map_err(Rejected)?;
    let reply = (|| {
        tx.send(&ch, &[Peer(creator.encryption)], &Outbound::Peer(sealed))
            .map_err(|e| Unavailable(e.to_string()))?;
        // The creator polls frostd about once a second.
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(250));
            for msg in tx.recv(&ch, false).map_err(|e| Unavailable(e.to_string()))? {
                let Ok(opened) = me.open_session(creator, &context, &msg.message) else { continue };
                if msg.from.0 != creator.encryption || opened.kind() != MessageKind::PeerReply {
                    continue;
                }
                let reply: Value = serde_json::from_slice(opened.body()).map_err(|e| Rejected(e.to_string()))?;
                return match reply["error"].as_str() {
                    Some(e @ ("roster pending" | "session pending")) => Err(Unavailable(e.into())),
                    Some(e) => Err(Rejected(e.into())),
                    None => Ok(reply),
                };
            }
        }
        Err(Unavailable("the creator did not answer over frostd".into()))
    })();
    let _ = tx.close(ch);
    reply
}

// Allow global unicast only, excluding special-use and transition ranges.
fn public_peer_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !matches!(ip.octets(),
            [0 | 10 | 127 | 224..=255, ..]
            | [100, 64..=127, ..] | [169, 254, ..] | [172, 16..=31, ..] | [192, 168, ..]
            | [192, 0, 0 | 2, _] | [192, 88, 99, _] | [198, 18 | 19, ..]
            | [198, 51, 100, _] | [203, 0, 113, _]),
        IpAddr::V6(ip) => matches!(ip.segments(), [0x2000..=0x3fff, ..])
            && !matches!(ip.segments(), [0x2001, 0..=0x1ff | 0xdb8, ..] | [0x2002, ..]
                | [0x3fff, 0..=0xfff, ..]),
    }
}

fn peer_request_result(config: &Config, base: &str, route: &str, body: Value) -> Result<Value, PeerRequestError> {
    use PeerRequestError::{Rejected, Unavailable};
    let mut url = config.validate_peer_url(base).map_err(Rejected)?;
    url.set_path(route);
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| Unavailable(e.to_string()))?;
    runtime.block_on(async {
        let mut client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        let refused = || Rejected("creator origin must use public addresses outside local development".into());
        let host = url.host_str().ok_or_else(refused)?;
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            // The origin policy only admits these two literals in local development.
            if !matches!(host, "127.0.0.1" | "[::1]") && !public_peer_address(ip) {
                return Err(refused());
            }
        } else {
            let port = url.port_or_known_default().ok_or_else(refused)?;
            let addresses: Vec<_> = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host, port)))
                .await.map_err(|_| Unavailable("creator DNS lookup timed out".into()))?
                .map_err(|e| Unavailable(format!("creator DNS lookup failed: {e}")))?
                .collect();
            if addresses.is_empty() {
                return Err(Unavailable("creator DNS returned no addresses".into()));
            }
            if addresses.iter().any(|address| !public_peer_address(address.ip())) {
                return Err(refused());
            }
            // Dial only the checked answers; retain the configured hostname for TLS.
            client = client.resolve_to_addrs(host, &addresses);
        }
        let client = client.build().map_err(|e| Unavailable(e.to_string()))?;
        let response = client.post(url).json(&body).send().await.map_err(|e| Unavailable(e.to_string()))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(Rejected("creator redirected the ceremony request".into()));
        }
        let value: Value = response.json().await.map_err(|e| Unavailable(e.to_string()))?;
        if !status.is_success() {
            let message = value["error"]
                .as_str()
                .unwrap_or("peer request failed")
                .to_owned();
            return Err(if status.is_server_error() || matches!(status.as_u16(), 401 | 404 | 408 | 429) {
                Unavailable(message)
            } else {
                Rejected(message)
            });
        }
        Ok(value)
    })
}

async fn unlocked(st: &Shared) -> Result<(std::path::PathBuf, Zeroizing<String>), Reply> {
    let session = st.session.read().await;
    let s = session
        .as_ref()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "profile is locked"))?;
    Ok((s.data.clone(), s.passphrase.clone()))
}

pub(super) async fn create(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let name = body["name"].as_str().unwrap_or("").trim().to_owned();
    let members = body["members"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0);
    let threshold = body["threshold"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0);
    if name.is_empty() || name.len() > 80 {
        return err(StatusCode::BAD_REQUEST, "name must be 1 to 80 bytes");
    }
    if !valid_policy(threshold, usize::from(members)) {
        return err(StatusCode::BAD_REQUEST, "use 2 <= t < n <= 16");
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let me = identity(&data, &pass, 1)?;
        let mut vault = [0u8; 32];
        OsRng.fill_bytes(&mut vault);
        let mut slots = BTreeMap::new();
        slots.insert(
            1,
            Slot {
                identity: Some(WireIdentity::from_public(me.public())),
                pending_token: None,
            },
        );
        for slot in 2..=members {
            let mut token = [0u8; 32];
            OsRng.fill_bytes(&mut token);
            slots.insert(
                slot,
                Slot {
                    identity: None,
                    pending_token: Some(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token),
                    ),
                },
            );
        }
        let c = Ceremony {
            vault: hex::encode(vault),
            name,
            members,
            threshold,
            my_slot: 1,
            creator_base_url: st
                .config
                .peers
                .get(&1)
                .cloned()
                .unwrap_or_else(|| st.config.base_url()),
            frostd_url: st.config.frostd_url.clone(),
            slots,
            fingerprint: None,
            agreed: BTreeSet::new(),
            session_id: None,
            coordinator_peer: None,
            vs_session_id: None,
            dkg_started: false,
            error: None,
            birth_height: None,
            roster_code: None,
            creator: None,
        };
        save(&data, &pass, &c)?;
        spawn_join_relay(&st);
        Ok(json!({"vault":c.vault,"invites":invitations(&c)?}))
    })
    .await
}

pub(super) async fn join(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let Some(code) = body["invite"].as_str() else {
        return err(StatusCode::BAD_REQUEST, "missing invite");
    };
    let invite: Invite = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(code)
        .map_err(|e| e.to_string())
        .and_then(|raw| serde_json::from_slice(&raw).map_err(|e| e.to_string()))
    {
        Ok(i) => i,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    if vault_bytes(&invite.vault).is_err()
        || !valid_policy(invite.threshold, usize::from(invite.members))
        || !(2..=invite.members).contains(&invite.slot)
        || invite.name.trim().is_empty()
        || invite.name.len() > 80
        || !base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&invite.token)
            .is_ok_and(|bytes| bytes.len() == 32)
    {
        return err(StatusCode::BAD_REQUEST, "invalid invite");
    }
    if let Some(creator) = &invite.creator {
        if let Err(e) = creator.public(1) {
            return err(StatusCode::BAD_REQUEST, e);
        }
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let me = identity(&data, &pass, invite.slot)?;
        let wire = WireIdentity::from_public(me.public());
        let mut slots = BTreeMap::new();
        slots.insert(
            invite.slot,
            Slot {
                identity: Some(wire),
                pending_token: Some(invite.token.clone()),
            },
        );
        let c = Ceremony {
            vault: invite.vault.clone(),
            name: invite.name,
            members: invite.members,
            threshold: invite.threshold,
            my_slot: invite.slot,
            creator_base_url: invite.creator_base_url,
            frostd_url: st.config.frostd_url.clone(),
            slots,
            fingerprint: None,
            agreed: BTreeSet::new(),
            session_id: None,
            coordinator_peer: None,
            vs_session_id: None,
            dkg_started: false,
            error: None,
            birth_height: None,
            roster_code: None,
            creator: invite.creator,
        };
        let exists = dir(&data, &c.vault)?.exists("ceremony.sealed");
        if exists {
            let old = load(&data, &pass, &c.vault)?;
            if old.my_slot != c.my_slot
                || old.creator_base_url != c.creator_base_url
                || old.creator != c.creator
                || old
                    .slots
                    .get(&c.my_slot)
                    .and_then(|s| s.pending_token.as_ref())
                    != c.slots
                        .get(&c.my_slot)
                        .and_then(|s| s.pending_token.as_ref())
                || old.slots.get(&c.my_slot).and_then(|s| s.identity.as_ref())
                    != c.slots.get(&c.my_slot).and_then(|s| s.identity.as_ref())
            {
                return Err("existing ceremony does not match invite".into());
            }
        }
        ask_creator(&st.config, &data, &pass, &c, "enroll").map_err(PeerRequestError::message)?;
        if !exists {
            save(&data, &pass, &c)?;
        }
        Ok(json!({"vault":invite.vault}))
    })
    .await
}

pub(super) async fn enroll(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (vault, slot, token, wire): (String, u16, String, WireIdentity) = match (
        body["vault"].as_str(),
        body["slot"].as_u64().and_then(|n| u16::try_from(n).ok()),
        body["token"].as_str(),
        serde_json::from_value(body["identity"].clone()),
    ) {
        (Some(v), Some(s), Some(t), Ok(w)) => (v.into(), s, t.into(), w),
        _ => return err(StatusCode::BAD_REQUEST, "invalid enrollment"),
    };
    if let Err(e) = wire.public(slot) {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || enroll_member(&st, &data, &pass, &vault, slot, &token, wire)).await
}

/// The creator records `wire` in `slot` for the holder of that slot's invite token.
fn enroll_member(st: &Shared, data: &Path, pass: &str, vault: &str, slot: u16, token: &str, wire: WireIdentity)
    -> Result<Value, String>
{
    wire.public(slot)?;
    let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
    let mut c = load(data, pass, vault)?;
    if c.my_slot != 1 {
        return Err("only creator can enroll".into());
    }
    let target = c.slots.get_mut(&slot).ok_or("unknown slot")?;
    let expected = target.pending_token.as_ref().ok_or("missing slot token")?;
    if !token_eq(expected, token) {
        return Err("invalid invite token".into());
    }
    if let Some(existing) = &target.identity {
        if existing != &wire {
            return Err("slot already enrolled".into());
        }
    } else {
        target.identity = Some(wire);
    }
    if c.slots.values().all(|s| s.identity.is_some()) {
        c.fingerprint = Some(hex::encode(roster_of(&c)?.fingerprint()));
        // Fixed with the roster so every member can show the roster code before agreeing.
        let network = VaultNetwork::parse(&st.config.network)?;
        if network == VaultNetwork::Testnet && c.birth_height.is_none() {
            c.birth_height = Some(setup_birth_height(network, 1, None, || testnet_tip(st, network))?);
        }
    }
    save(data, pass, &c)?;
    Ok(json!({"ok":true}))
}

fn token_eq(expected: &str, given: &str) -> bool {
    if expected.len() != given.len() {
        return false;
    }
    expected
        .bytes()
        .zip(given.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

/// The creator's ceremony, opened for an enrolled joiner that proves its slot with its
/// invite token. Every failure is the same error, so it does not reveal which vaults exist.
fn for_joiner(data: &Path, pass: &str, body: &Value) -> Result<Ceremony, String> {
    const DENIED: &str = "invalid member token";
    let (Some(vault), Some(slot), Some(token)) = (
        body["vault"].as_str(),
        body["slot"].as_u64().and_then(|n| u16::try_from(n).ok()),
        body["token"].as_str(),
    ) else {
        return Err(DENIED.into());
    };
    let c = load(data, pass, vault).map_err(|_| DENIED)?;
    let enrolled = c.slots.get(&slot).filter(|s| s.identity.is_some() && slot != c.my_slot);
    match enrolled.and_then(|s| s.pending_token.as_deref()) {
        Some(expected) if c.my_slot == 1 && token_eq(expected, token) => Ok(c),
        _ => Err(DENIED.into()),
    }
}

/// What a joiner presents to the creator's `for_joiner` endpoints.
fn joiner_auth(c: &Ceremony) -> Result<Value, String> {
    let token = c
        .slots
        .get(&c.my_slot)
        .and_then(|s| s.pending_token.as_ref())
        .ok_or("missing invite token")?;
    Ok(json!({"vault":c.vault,"slot":c.my_slot,"token":token}))
}

fn query_vault(query: &BTreeMap<String, String>) -> Result<String, Reply> {
    let vault = query
        .get("vault")
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing vault"))?;
    vault_bytes(vault).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    Ok(vault.clone())
}

pub(super) async fn roster(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let reply = blocking(move || roster_reply(&data, &pass, &body)).await;
    if reply.1 .0["error"] == "roster pending" {
        err(StatusCode::NOT_FOUND, "roster pending")
    } else {
        reply
    }
}

fn roster_reply(data: &Path, pass: &str, body: &Value) -> Result<Value, String> {
    let c = for_joiner(data, pass, body)?;
    let fingerprint = c.fingerprint.ok_or("roster pending")?;
    let roster: BTreeMap<_, _> = c
        .slots
        .into_iter()
        .map(|(slot, s)| (slot, s.identity))
        .collect();
    Ok(json!({"fingerprint":fingerprint,"roster":roster,"birth_height":c.birth_height}))
}

fn refresh_roster(config: &Config, data: &Path, pass: &str, c: &mut Ceremony) -> Result<(), String> {
    if c.my_slot == 1 {
        return Ok(());
    }
    let remote = ask_creator(config, data, pass, c, "roster").map_err(PeerRequestError::message)?;
    let fingerprint = remote["fingerprint"]
        .as_str()
        .ok_or("missing roster fingerprint")?;
    let roster: BTreeMap<u16, WireIdentity> =
        serde_json::from_value(remote["roster"].clone()).map_err(|e| e.to_string())?;
    let own = c
        .slots
        .get(&c.my_slot)
        .and_then(|s| s.identity.as_ref())
        .ok_or("missing own identity")?;
    if roster.get(&c.my_slot) != Some(own) {
        return Err("creator roster changed this member's identity".into());
    }
    c.slots = roster
        .into_iter()
        .map(|(slot, wire)| {
            (
                slot,
                Slot {
                    identity: Some(wire),
                    pending_token: if slot == c.my_slot {
                        c.slots.get(&slot).and_then(|s| s.pending_token.clone())
                    } else {
                        None
                    },
                },
            )
        })
        .collect();
    let actual = hex::encode(roster_of(c)?.fingerprint());
    if actual != fingerprint {
        return Err("roster fingerprint mismatch".into());
    }
    c.fingerprint = Some(actual);
    c.birth_height = remote["birth_height"].as_u64().and_then(|n| u32::try_from(n).ok());
    Ok(())
}

pub(super) async fn status(st: Shared, vault: String) -> Reply {
    if let Err(e) = vault_bytes(&vault) {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let waiting_st = st.clone();
    let waiting_data = data.clone();
    let waiting_pass = pass.clone();
    let waiting_vault = vault.clone();
    let reply = blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let mut c = load(&data, &pass, &vault)?;
        if c.my_slot != 1 && c.fingerprint.is_none() {
            if refresh_roster(&st.config, &data, &pass, &mut c).is_ok() {
                save(&data, &pass, &c)?;
            }
        }
        let active = dir(&data, &vault)?.exists("vault.sealed");
        let local_agreed = c.agreed.contains(&c.my_slot);
        let confirmed = local_agreed && (active || c.roster_code.is_some());
        let confirmations = c.agreed.len() - usize::from(local_agreed && !confirmed);
        let running_here = st.active_dkgs.lock().map_err(|e| e.to_string())?.contains(&vault);
        let phase = if active {
            "active"
        } else if c.error.is_some() || (c.dkg_started && !running_here) {
            "setup_interrupted"
        } else if c.dkg_started || (c.my_slot == 1 && confirmations == usize::from(c.members)) {
            "creating_keys"
        } else if c.fingerprint.is_some() {
            "compare_roster"
        } else {
            "waiting_for_members"
        };
        let mut value = json!({"phase":phase,"members":c.members,"threshold":c.threshold,
            "confirmations":confirmations,"confirmed":confirmed,
            "fingerprint":c.fingerprint,"secure_element":st.config.secure_element});
        if c.fingerprint.is_some() {
            value["roster_code"] = json!(setup_roster_code(&c, VaultNetwork::parse(&st.config.network)?).ok());
        }
        // LokiSigner asks the member to compare the code; the page shows where that stands.
        if st.config.native && st.roster_confirmation.is_some() {
            let open = st.roster_asking.lock().map_err(|e| e.to_string())?.as_deref() == Some(vault.as_str());
            let differ = st.roster_refused.lock().map_err(|e| e.to_string())?.contains(&vault);
            value["roster_dialog"] = if differ { json!("codes_differ") } else if open { json!("open") } else { Value::Null };
        }
        if c.my_slot == 1 && matches!(phase, "waiting_for_members" | "compare_roster") {
            value["invites"] = json!(invitations(&c)?);
            if !active {
                spawn_join_relay(&st);
            }
        }
        if let Some(error) = c.error {
            value["error"] = json!(error);
        } else if phase == "setup_interrupted" {
            value["error"] = json!("DKG interrupted; create a fresh vault");
        }
        Ok(value)
    })
    .await;
    if reply.0 == StatusCode::OK
        && reply.1 .0["confirmed"] == true
        && matches!(reply.1 .0["phase"].as_str(), Some("compare_roster" | "creating_keys"))
    {
        spawn_dkg(waiting_st, waiting_vault, waiting_data, waiting_pass);
    }
    reply
}

fn spawn_dkg(st: Shared, vault: String, data: std::path::PathBuf, pass: Zeroizing<String>) {
    let Ok(mut active) = st.active_dkgs.lock() else { return; };
    if !active.insert(vault.clone()) { return; }
    drop(active);
    tokio::spawn(async move {
        let running = st.clone();
        let finished_vault = vault.clone();
        let result = blocking(move || run_background(st, &data, &pass, &vault)).await;
        if let Ok(mut active) = running.active_dkgs.lock() {
            active.remove(&finished_vault);
        }
        if result.0 != StatusCode::OK {
            eprintln!("ceremony DKG: {}", result.1 .0);
        }
    });
}

/// `POST /api/agree`: this member agrees to the roster whose fingerprint and 24-digit code the
/// request names, once setup has not started, the roster is fresh and both match.
///
/// The request only opens a local prompt (LokiSigner or the foreground terminal).
/// Without an affirmative answer, it never records this member's agreement.
pub(super) async fn agree(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (Some(vault), Some(fingerprint), Some(roster_code)) =
        (body["vault"].as_str(), body["fingerprint"].as_str(), body["roster_code"].as_str())
    else {
        return err(StatusCode::BAD_REQUEST, "missing vault, fingerprint or roster_code");
    };
    let (vault, fingerprint, roster_code) = (vault.to_owned(), fingerprint.to_owned(), roster_code.to_owned());
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let work_data = data.clone();
    let work_pass = pass.clone();
    let work_vault = vault.clone();
    let work_st = st.clone();
    let reply = blocking(move || {
        let (st, data, pass, vault) = (&work_st, &work_data, &work_pass, &work_vault);
        let network = VaultNetwork::parse(&st.config.network)?;
        let confirm = st.roster_confirmation.as_ref().ok_or(ROSTER_NOT_CONFIRMED)?;
        let _asking = RosterAsking::claim(st, vault)?;
        let summary = {
            let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
            let (c, code) = agreement(&st.config, data, pass, vault, &fingerprint, &roster_code, network)?;
            roster_summary(&c, network, &code)
        };
        // The member may take minutes to compare codes by phone: other requests need the
        // ceremony lock meanwhile, so it is not held while LokiSigner asks.
        let answer = confirm(&summary);
        eprintln!("roster code: member {answer:?}");
        match answer {
            super::RosterAnswer::Match => {}
            super::RosterAnswer::Differ => {
                st.roster_refused.lock().map_err(|e| e.to_string())?.insert(vault.clone());
                return Err(ROSTER_CODES_DIFFER.into());
            }
            super::RosterAnswer::NoAnswer => return Err(ROSTER_NOT_CONFIRMED.into()),
        }
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        if st.session.blocking_read().is_none() {
            return Err(format!("{ROSTER_CHANGED}: profile is locked"));
        }
        // Everything is checked again: the member confirmed the code of the roster shown, and
        // the request names that same code, so any change to the roster or the setup refuses.
        let (c, code) = agreement(&st.config, data, pass, vault, &fingerprint, &roster_code, network)
            .map_err(|e| format!("{ROSTER_CHANGED}: {e}"))?;
        record_agreement(&st.config, data, pass, c, code)
    })
    .await;
    if reply.0 == StatusCode::OK {
        spawn_dkg(st, vault, data, pass);
    }
    reply
}

/// The member chose "Codes differ" in LokiSigner; it refuses this vault until it restarts.
const ROSTER_CODES_DIFFER: &str = "roster codes differ: LokiSigner refuses this vault until it restarts";
/// No local prompt was available or the member did not answer; a new request can ask again.
const ROSTER_NOT_CONFIRMED: &str = "roster code not confirmed locally";
/// LokiSigner already shows a roster dialog.
const ROSTER_ASKING: &str = "LokiSigner is already asking about a roster code";
/// The setup changed while LokiSigner asked; nothing was recorded.
const ROSTER_CHANGED: &str = "the vault setup changed while LokiSigner was asking; nothing was recorded";

/// Marks the one roster dialog LokiSigner shows, for as long as it is open.
struct RosterAsking<'a>(&'a super::state::AppState);

impl<'a> RosterAsking<'a> {
    /// Claims the dialog for `vault`, unless one is open or the member said its codes differ.
    /// Both are checked under the `roster_asking` lock: a "Codes differ" is recorded before its
    /// dialog's claim is released, so no request can open another dialog for that vault.
    fn claim(st: &'a super::state::AppState, vault: &str) -> Result<Self, String> {
        let mut asking = st.roster_asking.lock().map_err(|e| e.to_string())?;
        if st.roster_refused.lock().map_err(|e| e.to_string())?.contains(vault) {
            return Err(ROSTER_CODES_DIFFER.into());
        }
        if asking.is_some() {
            return Err(ROSTER_ASKING.into());
        }
        *asking = Some(vault.to_owned());
        Ok(Self(st))
    }
}

impl Drop for RosterAsking<'_> {
    fn drop(&mut self) {
        if let Ok(mut asking) = self.0.roster_asking.lock() {
            *asking = None;
        }
    }
}

/// `agree`'s checks, under the ceremony lock: setup has not started, the roster is refreshed
/// from the creator, and the request's fingerprint and code are this roster's. Returns the
/// ceremony and the code of its setup document.
fn agreement(
    config: &Config, data: &Path, pass: &str, vault: &str, fingerprint: &str, roster_code: &str, network: VaultNetwork,
) -> Result<(Ceremony, String), String> {
    let mut c = load(data, pass, vault)?;
    if c.dkg_started || c.error.is_some() {
        return Err("DKG interrupted or already running; create a fresh vault if interrupted".into());
    }
    refresh_roster(config, data, pass, &mut c)?;
    if c.fingerprint.as_deref() != Some(fingerprint) {
        return Err("roster fingerprint mismatch".into());
    }
    let code = setup_roster_code(&c, network)?;
    if code != roster_code {
        return Err("roster code mismatch".into());
    }
    Ok((c, code))
}

/// Tells the creator (a joiner only) and records this member's agreement and confirmed code.
fn record_agreement(config: &Config, data: &Path, pass: &str, mut c: Ceremony, code: String) -> Result<Value, String> {
    if c.my_slot != 1 {
        ask_creator(config, data, pass, &c, "agreed").map_err(PeerRequestError::message)?;
    }
    c.agreed.insert(c.my_slot);
    c.roster_code = Some(code);
    save(data, pass, &c)?;
    Ok(json!({"ok":true}))
}

/// What LokiSigner shows the member before they agree: the code of the setup document
/// `dkg_begin` receives, and the vault it is for. The name comes from the creator's invite, so
/// it is shown as written or hidden, by the same rule as "Vault addresses…".
fn roster_summary(c: &Ceremony, network: VaultNetwork, code: &str) -> String {
    json!({
        "vault_name": super::vault_label(&c.name),
        "threshold": c.threshold,
        "members": c.members,
        "member": c.my_slot,
        "network": network.label(),
        "roster_code": code,
    })
    .to_string()
}

pub(super) async fn agreed(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (Some(vault), Some(slot)) = (
        body["vault"].as_str(),
        body["slot"].as_u64().and_then(|n| u16::try_from(n).ok()),
    ) else {
        return err(StatusCode::BAD_REQUEST, "invalid agreement");
    };
    let vault = vault.to_owned();
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let work_data = data.clone();
    let work_pass = pass.clone();
    let work_st = st.clone();
    let reply = blocking(move || agreed_member(&work_st, &work_data, &work_pass, &body, slot)).await;
    if reply.0 == StatusCode::OK {
        spawn_dkg(st, vault, data, pass);
    }
    reply
}

fn agreed_member(st: &Shared, data: &Path, pass: &str, body: &Value, slot: u16) -> Result<Value, String> {
    let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
    let mut c = for_joiner(data, pass, body)?;
    if c.fingerprint.is_none() {
        return Err("roster pending".into());
    }
    c.agreed.insert(slot);
    save(data, pass, &c)?;
    Ok(json!({"ok":true}))
}

pub(super) async fn session(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let reply = blocking(move || session_reply(&data, &pass, &body)).await;
    if reply.1 .0["error"] == "session pending" {
        err(StatusCode::NOT_FOUND, "session pending")
    } else {
        reply
    }
}

fn session_reply(data: &Path, pass: &str, body: &Value) -> Result<Value, String> {
    let c = for_joiner(data, pass, body)?;
    if let Some(error) = c.error {
        return Err(format!("Creator setup failed: {error}"));
    }
    if c.agreed.len() != usize::from(c.members) {
        return Err("session pending".into());
    }
    Ok(json!({
        "session_id": c.session_id.ok_or("session pending")?,
        "coordinator_peer": c.coordinator_peer,
        "vs_session_id": c.vs_session_id,
        "birth_height": c.birth_height,
    }))
}

/// Starts the creator's loop that answers joiners over frostd, unless it runs. It holds the
/// app state weakly and stops once the profile locks or no ceremony it created is still setting up.
pub(super) fn spawn_join_relay(st: &Shared) {
    if st.join_relay.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let weak = std::sync::Arc::downgrade(st);
    tokio::task::spawn_blocking(move || {
        let mut relay = None;
        while let Some(st) = weak.upgrade() {
            match serve_joins(&st, &mut relay) {
                Ok(true) => {}
                Ok(false) => {
                    st.join_relay.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }
                Err(e) => {
                    eprintln!("join relay: {e}");
                    relay = None;
                }
            }
            drop(st);
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

/// Vaults this member created whose members are still joining.
pub(super) fn waiting_for_joiners(data: &Path, pass: &str) -> Vec<String> {
    std::fs::read_dir(data.join("vaults")).into_iter().flatten().flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|vault| dir(data, vault).is_ok_and(|d| !d.exists("vault.sealed")))
        .filter(|vault| load(data, pass, vault).is_ok_and(|c| c.my_slot == 1 && c.slots.get(&1).is_some_and(|s| s.identity.is_some())))
        .collect()
}

/// One pass of the creator's join relay: every two-member session a joiner opened with the
/// creator is drained, and each request sealed to the creator for a ceremony it is still
/// setting up is answered on that session. Returns whether there is still a ceremony to serve.
fn serve_joins(st: &Shared, relay: &mut Option<FrostdTransport>) -> Result<bool, String> {
    let Some((data, pass)) = st.session.blocking_read().as_ref().map(|s| (s.data.clone(), s.passphrase.clone())) else {
        return Ok(false);
    };
    let waiting = waiting_for_joiners(&data, &pass);
    if waiting.is_empty() {
        return Ok(false);
    }
    let me = identity(&data, &pass, 1)?;
    let mine = me.public().encryption;
    let tx = match relay {
        Some(tx) => tx,
        None => relay.insert(super::payment::member_relay(st, &me)?),
    };
    for session in tx.list_sessions().map_err(|e| e.to_string())? {
        let Ok((participants, Some(owner))) = tx.session_details(session) else { continue };
        // Payment and DKG sessions have every member, or an owner outside them.
        if participants.len() != 2 || owner == mine || !participants.contains(&mine) || !participants.contains(&owner) {
            continue;
        }
        let ch = tx.join(session).map_err(|e| e.to_string())?;
        for msg in tx.recv_control_bounded(session, Duration::from_secs(5)).map_err(|e| e.to_string())? {
            let Some((joiner, context, body)) = open_join(&me, &waiting, session, &msg.from.0, &msg.message) else {
                continue;
            };
            let reply = answer_join(st, &data, &pass, &joiner, body).unwrap_or_else(|e| json!({"error": e}));
            let sealed = SealedPeer::seal(&me, &joiner, &context, MessageKind::PeerReply,
                &serde_json::to_vec(&reply).map_err(|e| e.to_string())?)?;
            tx.send(&ch, &[Peer(joiner.encryption)], &Outbound::Peer(sealed)).map_err(|e| e.to_string())?;
        }
    }
    Ok(true)
}

/// A join request relay sender `from` sealed to the creator `me` for one of the `waiting`
/// vaults on `session`: the joiner's identity, the context to answer under, and the request.
fn open_join(me: &Identity, waiting: &[String], session: Uuid, from: &[u8; 32], wire: &[u8])
    -> Option<(PublicIdentity, SessionContext, Value)>
{
    let (joiner, sealed) = SealedPeer::join_sender(from, wire).ok()?;
    waiting.iter().find_map(|vault| {
        let context = join_context(vault, session, joiner.id).ok()?;
        let opened = me.open_session(&joiner, &context, sealed).ok()?;
        let body: Value = serde_json::from_slice(opened.body()).ok()?;
        if opened.kind() != MessageKind::PeerRequest || body["vault"] != vault.as_str() || body["slot"] != joiner.id {
            return None;
        }
        Some((joiner.clone(), context, body))
    })
}

/// The creator's answer to one joiner request: the same logic as the HTTP routes.
fn answer_join(st: &Shared, data: &Path, pass: &str, joiner: &PublicIdentity, body: Value) -> Result<Value, String> {
    let vault = body["vault"].as_str().ok_or("missing vault")?.to_owned();
    let token = body["token"].as_str().ok_or("missing token")?;
    match body["op"].as_str() {
        Some("enroll") => enroll_member(st, data, pass, &vault, joiner.id, token, WireIdentity::from_public(joiner.clone())),
        Some("roster") => roster_reply(data, pass, &body),
        Some("agreed") => {
            let reply = agreed_member(st, data, pass, &body, joiner.id)?;
            spawn_dkg(st.clone(), vault, data.to_owned(), Zeroizing::new(pass.to_owned()));
            Ok(reply)
        }
        Some("session") => session_reply(data, pass, &body),
        _ => Err("unknown join request".into()),
    }
}

pub(super) async fn address(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let vault = match query_vault(&query) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let raw = dir(&data, &vault)?
            .read_sealed("vault.sealed", &pass)
            .map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let address = value["group_address"]
            .as_str()
            .ok_or("sealed vault has no address")?;
        Ok(json!({"address":address}))
    })
    .await
}

fn setup_birth_height(
    network: VaultNetwork,
    slot: u16,
    published: Option<u32>,
    fetch_tip: impl FnOnce() -> Result<u32, String>,
) -> Result<u32, String> {
    if network == VaultNetwork::Regtest {
        return Ok(2);
    }
    let height = match published {
        Some(height) => height,
        None if slot == 1 => fetch_tip()?,
        None => return Err("creator did not publish a testnet birth height".into()),
    };
    if height < TESTNET_NU7_BIRTH {
        return Err("creator birth height precedes testnet NU7".into());
    }
    Ok(height)
}

fn testnet_tip(st: &Shared, network: VaultNetwork) -> Result<u32, String> {
    let url = st.config.lightwalletd.as_deref().ok_or("Testnet vault requires a lightwalletd URL")?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let channel = runtime.block_on(crate::wallet_store::lightwalletd_endpoint(url)?.connect())
        .map_err(|e| format!("connect to lightwalletd: {e}"))?;
    let mut client = crate::wallet_store::Lightwalletd::new(channel);
    let info = runtime.block_on(client.get_lightd_info(zcash_client_backend::proto::service::Empty {}))
        .map_err(|e| format!("lightwalletd info: {e}"))?.into_inner();
    if info.chain_name != "test"
        || Some(info.sapling_activation_height) != network.activation_height(zcash_protocol::consensus::NetworkUpgrade::Sapling).map(u64::from) {
        return Err("lightwalletd serves another chain".into());
    }
    u32::try_from(info.block_height).map_err(|_| "chain height overflow".into())
}

/// The setup document `dkg_begin` receives, and its birth height. `agree`, `status` and
/// `run_background` all use these bytes, so the code a member confirms is the code the signer shows.
fn setup_document(c: &Ceremony, network: VaultNetwork) -> Result<(Vec<u8>, u32), String> {
    // The creator fixes the testnet birth height in `enroll`, when the roster completes.
    let birth_height = setup_birth_height(network, c.my_slot, c.birth_height,
        || Err("testnet birth height is not fixed yet".into()))?;
    let roster = roster_of(c)?;
    let mut document = json!({
        "vault": c.vault, "threshold": c.threshold, "setup_version": 2,
        "network": network.label(),
        "members": roster.members.values().map(|p| json!({
            "id": p.id, "signing": hex::encode(p.signing),
            "encryption": hex::encode(p.encryption),
        })).collect::<Vec<_>>(),
    });
    if network == VaultNetwork::Testnet {
        document["birth_height"] = json!(birth_height);
    }
    Ok((serde_json::to_vec(&document).map_err(|e| e.to_string())?, birth_height))
}

fn setup_roster_code(c: &Ceremony, network: VaultNetwork) -> Result<String, String> {
    let (document, _) = setup_document(c, network)?;
    Ok(roster_code(&crate::member_state::Roster::from_bytes(&document)?.fingerprint()))
}

/// The signer's roster prompt: only the code this member confirmed matches.
fn roster_decision(confirmed: Option<&str>, code: &str) -> RosterDecision {
    if confirmed == Some(code) { RosterDecision::Match } else { RosterDecision::NoMatch }
}

fn setup_signer_element(config: &super::state::Config, dir: &Path, pass: &str, published: Option<&Path>, profile: &Path)
    -> Result<(super::state::HostedSecureElement, bool), String>
{
    let existing = super::custody::has_signer_data(dir)?;
    let element = if existing { config.open_secure_element(dir, pass)? }
    else { config.create_secure_element(dir, pass, published, profile)? };
    Ok((element, existing))
}

fn run_background(st: Shared, data: &Path, pass: &str, vault_id: &str) -> Result<Value, String> {
    let mut c = {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let c = load(data, pass, vault_id)?;
        if c.dkg_started || c.error.is_some() || dir(data, vault_id)?.exists("vault.sealed") {
            return Ok(json!({"ok":true}));
        }
        if c.roster_code.is_none() || !c.agreed.contains(&c.my_slot)
            || (c.my_slot == 1 && c.agreed.len() != usize::from(c.members))
        {
            return Ok(json!({"ok":true}));
        }
        c
    };
    let outcome: Result<Value, String> = (|| {
        if c.my_slot != 1 {
            loop {
                if st.session.blocking_read().is_none() {
                    return Ok(json!({"ok":true}));
                }
                match ask_creator(&st.config, data, pass, &c, "session") {
                    Ok(response) => {
                        let id = response["session_id"].as_str()
                            .and_then(|id| Uuid::parse_str(id).ok()).ok_or("invalid creator session")?;
                        let peer = response["coordinator_peer"].as_str()
                            .and_then(|peer| hex::decode(peer).ok())
                            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                            .ok_or("invalid creator relay identity")?;
                        c.session_id = Some(id);
                        c.coordinator_peer = Some(hex::encode(peer));
                        if st.config.network == "testnet"
                            && response["birth_height"].as_u64() != c.birth_height.map(u64::from) {
                            return Err("creator session birth height differs from the agreed roster".into());
                        }
                        break;
                    }
                    // Human confirmation has no key-generation deadline. The creator only
                    // publishes a session after every member has confirmed the roster.
                    Err(PeerRequestError::Unavailable(_)) => std::thread::sleep(Duration::from_secs(1)),
                    Err(PeerRequestError::Rejected(error)) => return Err(format!("Waiting for creator: {error}")),
                }
            }
        }
        {
            let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
            c.dkg_started = true;
            save(data, pass, &c)?;
        }
        let me = identity(data, pass, c.my_slot)?;
        let roster = roster_of(&c)?;
        let network = VaultNetwork::parse(&st.config.network)?;
        let (document, birth_height) = setup_document(&c, network)?;
        let peers: BTreeMap<u16, Peer> = roster.members.values()
            .map(|identity| (identity.id, Peer(identity.encryption))).collect();
        let identity_secret = Zeroizing::new(me.to_secret_bytes());
        let secret: [u8; 32] = identity_secret[34..]
            .try_into().map_err(|_| "identity secret length")?;
        let mut transport = FrostdTransport::new(
            &c.frostd_url, FrostdLoginKey::from_secret_bytes(secret),
        ).map_err(|e| e.to_string())?;
        let (session_id, coordinator, coordinator_peer) = if c.my_slot == 1 {
            // frostd requires a distinct session opener; id 0 is not a DKG member.
            let coord = Identity::new(0);
            let raw = Zeroizing::new(coord.to_secret_bytes());
            let coord_secret: [u8; 32] = raw[34..].try_into()
                .map_err(|_| "coordinator secret length")?;
            let mut coord_tx = FrostdTransport::new(
                &c.frostd_url, FrostdLoginKey::from_secret_bytes(coord_secret),
            ).map_err(|e| e.to_string())?;
            let coord_ch = coord_tx.open(&roster.peer_list(), 255)
                .map_err(|e| e.to_string())?;
            let id = coord_ch.session_id();
            let peer = Peer(coord.public().encryption);
            c.session_id = Some(id);
            c.coordinator_peer = Some(hex::encode(peer.0));
            {
                let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
                save(data, pass, &c)?;
            }
            (id, Some((coord_tx, coord_ch)), peer)
        } else {
            let id = c.session_id.ok_or("creator session missing")?;
            let peer: [u8; 32] = hex::decode(c.coordinator_peer.as_deref().ok_or("creator relay identity missing")?)
                .map_err(|e| e.to_string())?.try_into().map_err(|_| "invalid creator relay identity")?;
            (id, None, Peer(peer))
        };
        let channel = transport.join(session_id).map_err(|e| e.to_string())?;
        let signer_dir = dir(data, vault_id)?.path().join("signer");
        // The share is born in the store under the configured element: the Secure Enclave
        // for `--secure-element apple`, so it never exists under the passphrase alone.
        let (se, existing) = setup_signer_element(&st.config, &signer_dir, pass, None, data)?;
        let signer_network = match network {
            VaultNetwork::Regtest => Network::Regtest,
            VaultNetwork::Testnet => Network::Testnet,
        };
        // DKG never signs a payment; any request still goes to the member, or is refused.
        let mut prompts = hosted_prompts(&signer_dir, pass, super::approval_policy(st.approval.clone(), signer_network, c.my_slot, None));
        // Matches only the code this member confirmed in `agree`.
        let confirmed = c.roster_code.clone();
        prompts.roster = Box::new(move |code| roster_decision(confirmed.as_deref(), code));
        let mut signer = if existing {
            LocalSigner::open(&signer_dir, se, c.name.clone(), prompts)
        } else {
            LocalSigner::create_with_identity(
                &signer_dir, se, signer_network, roster.vault_id, c.my_slot,
                c.name.clone(), prompts, Identity::from_secret_bytes(&identity_secret[..])?,
            )
        }.map_err(|e| e.to_string())?;
        let connection = signer.connect(&c.creator_base_url, signer_network, b"hosted DKG")
            .map_err(|e| e.to_string())?;
        if connection.member.encryption != me.public().encryption {
            return Err("signer identity differs from enrolled member".into());
        }
        let session = connection.session;
        let vault_ref = if signer.list_vaults(&session).map_err(|e| e.to_string())?.is_empty() {
            signer.dkg_begin(&session, &document)
                .map_err(|e| e.to_string())?
        } else {
            signer.list_vaults(&session).map_err(|e| e.to_string())?.remove(0)
        };
        let mut log = if c.my_slot == 1 {
            Some(RelayLog::open(&dir(data, vault_id)?.path().join("dkg-relay"), c.members)
                .map_err(|e| e.to_string())?)
        } else { None };
        if let (Some((coord_tx, coord_ch)), Some(log)) = (&coordinator, &log) {
            redeliver_dkg(log, coord_tx, coord_ch, &peers)?;
        }
        let mut backed_up = false;
        let mut ready = false;
        for _ in 0..1200 {
            if let (Some((coord_tx, coord_ch)), Some(log)) = (&coordinator, &mut log) {
                relay_dkg(log, coord_tx, coord_ch, &peers)?;
            }
            member_dkg_step(&mut signer, &session, &vault_ref, &transport, &channel, &coordinator_peer)?;
            if !backed_up {
                match signer.backup(&session) {
                    Ok(wires) => {
                        for wire in wires {
                            transport.send(&channel, &[], &Outbound::Dkg(wire))
                                .map_err(|e| e.to_string())?;
                        }
                        backed_up = true;
                    }
                    Err(SignerError::NotReady) => {}
                    Err(e) => return Err(format!("backup: {e}")),
                }
            }
            if let (Some((coord_tx, coord_ch)), Some(log)) = (&coordinator, &mut log) {
                relay_dkg(log, coord_tx, coord_ch, &peers)?;
            }
            ready = signer.list_vaults(&session).map_err(|e| e.to_string())?[0].ready;
            if ready { break; }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !ready { return Err("DKG receipts did not complete".into()); }
        if let Some(log) = log {
            if log.active() { log.delete().map_err(|e| e.to_string())?; }
        }
        // Keep the frostd session open until the relay's TTL; peers may still be finishing.
        // vault.sealed records public metadata only; the share stays in the signer store.
        let (public, fvk) = signer.hosted_metadata().map_err(|e| e.to_string())?;
        let sealed = vault_sealed_bytes(
            &c.vault, c.my_slot, c.threshold, c.members,
            c.fingerprint.as_deref().ok_or("roster fingerprint missing at activation")?,
            &public, &fvk, birth_height, network,
        )?;
        dir(data, vault_id)?
            .write_sealed("vault.sealed", &sealed, pass)
            .map_err(|e| e.to_string())?;
        // The vault is now active: seal this member's recovery backup (share HPKE-sealed to its
        // recovery words) so a lost device can restore the share from the words. Without a
        // recovery identity yet, recovery setup or the next unlock seals it instead.
        super::recovery::seal_vault_backup(data, &signer_dir, &roster.vault_id, pass)?;
        Ok(json!({"ok":true}))
    })();
    if let Err(ref error) = outcome {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        c.error = Some(error.clone());
        save(data, pass, &c)?;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::state::{AppState, Config, Session};

    #[test]
    fn testnet_joiner_uses_creator_birth_height_when_tip_advances() {
        let published = TESTNET_NU7_BIRTH + 100;
        assert_eq!(setup_birth_height(VaultNetwork::Testnet, 2, Some(published), || Ok(published + 1)).unwrap(), published);
        assert_eq!(setup_birth_height(VaultNetwork::Testnet, 3, Some(published), || Err("joiner must not fetch its own tip".into())).unwrap(), published);
    }

    #[test]
    fn testnet_birth_height_requires_a_valid_creator_checkpoint() {
        let height = TESTNET_NU7_BIRTH + 100;
        assert_eq!(setup_birth_height(VaultNetwork::Testnet, 1, None, || Ok(height)).unwrap(), height);
        assert!(setup_birth_height(VaultNetwork::Testnet, 2, None, || Ok(height)).is_err());
        assert!(setup_birth_height(VaultNetwork::Testnet, 2, Some(TESTNET_NU7_BIRTH - 1), || Ok(height)).is_err());
    }

    #[test]
    fn roster_requires_every_valid_distinct_member() {
        let mut slots = BTreeMap::new();
        for slot in 1..=3 {
            slots.insert(
                slot,
                Slot {
                    identity: Some(WireIdentity::from_public(Identity::new(slot).public())),
                    pending_token: None,
                },
            );
        }
        let mut c = Ceremony {
            vault: hex::encode([7u8; 32]),
            name: "test".into(),
            members: 3,
            threshold: 2,
            my_slot: 1,
            creator_base_url: String::new(),
            frostd_url: String::new(),
            slots,
            fingerprint: None,
            agreed: BTreeSet::new(),
            session_id: None,
            coordinator_peer: None,
            vs_session_id: None,
            dkg_started: false,
            error: None,
            birth_height: None,
            roster_code: None,
            creator: None,
        };
        let fingerprint = roster_of(&c).unwrap().fingerprint();
        assert_eq!(fingerprint, roster_of(&c).unwrap().fingerprint());
        c.slots.get_mut(&2).unwrap().identity = None;
        assert!(roster_of(&c).is_err());
        assert!(token_eq("secret", "secret"));
        assert!(!token_eq("secret", "secreu"));
    }

    #[tokio::test]
    async fn interrupted_dkg_cannot_be_restarted_by_agreeing_again() {
        let data = std::env::temp_dir().join(format!("loki-interrupted-dkg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let vault = hex::encode([8u8; 32]);
        let slots = (1..=3)
            .map(|slot| (slot, Slot { identity: Some(WireIdentity::from_public(Identity::new(slot).public())), pending_token: None }))
            .collect();
        let mut ceremony = Ceremony {
            vault: vault.clone(), name: "test".into(), members: 3, threshold: 2,
            my_slot: 1, creator_base_url: String::new(), frostd_url: String::new(),
            slots, fingerprint: None, agreed: BTreeSet::from([1, 2, 3]),
            session_id: None, coordinator_peer: None, vs_session_id: None,
            dkg_started: true, error: None, birth_height: None, roster_code: None, creator: None,
        };
        let fingerprint = hex::encode(roster_of(&ceremony).unwrap().fingerprint());
        let code = setup_roster_code(&ceremony, VaultNetwork::Regtest).unwrap();
        ceremony.fingerprint = Some(fingerprint.clone());
        ceremony.roster_code = Some(code.clone());
        save(&data, "pass", &ceremony).unwrap();
        let st = std::sync::Arc::new(AppState {
            roster_confirmation: Some(std::sync::Arc::new(|_| panic!("interrupted setup must not open a local prompt"))),
            ..AppState::new(test_config(&data, 3001))
        });
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("pass".into()), data: data.clone(),
        });

        let reply = status(st.clone(), vault.clone()).await;
        assert_eq!(reply.1 .0["phase"], "setup_interrupted");
        let reply = agree(State(st.clone()), agree_body(&vault, &fingerprint, &code)).await;
        assert_eq!(reply.0, StatusCode::BAD_REQUEST);
        assert!(reply.1 .0["error"].as_str().unwrap().contains("interrupted"));
        assert!(st.active_dkgs.lock().unwrap().is_empty());
        let saved = load(&data, "pass", &vault).unwrap();
        assert!(saved.dkg_started);
        assert_eq!(saved.agreed, ceremony.agreed);
        assert_eq!(saved.roster_code, ceremony.roster_code);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn creator_enrolls_three_members_and_publishes_roster() {
        let data = std::env::temp_dir().join(format!("loki-ceremony-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let st = std::sync::Arc::new(AppState::new(Config {
            data: data.clone(), native: false,
            port: 3001,
            network: "regtest".into(),
            lightwalletd: None,
            transport: "local".into(),
            operator_bundle: None,
            operator_key: None,
            enrollment_issuer: None,
            development_http: false,
            token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(),
            registration: None,
            bind: "127.0.0.1".parse().unwrap(),
            peer_port: None,
            advertise_url: None,
            secure_element: "software".into(),
            nonce_witnesses: None,
            loopback_peers: false,
        }));
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("test passphrase".into()),
            data: data.clone(),
        });
        let created = create(
            State(st.clone()),
            Json(json!({"name":"test","members":3,"threshold":2})),
        )
        .await;
        assert_eq!(created.0, StatusCode::OK, "{}", created.1 .0);
        let vault = created.1 .0["vault"].as_str().unwrap().to_owned();
        let mut tokens = BTreeMap::new();
        for slot in 2..=3 {
            let code = created.1 .0["invites"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["slot"] == slot)
                .unwrap()["code"]
                .as_str()
                .unwrap();
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(code)
                .unwrap();
            let fields: Value = serde_json::from_slice(&decoded).unwrap();
            assert!(fields.get("vault_secret").is_none());
            eprintln!(
                "invite {slot} fields: {:?}",
                fields.as_object().unwrap().keys().collect::<Vec<_>>()
            );
            let invite: Invite = serde_json::from_slice(&decoded).unwrap();
            tokens.insert(slot, invite.token.clone());
            let wire = WireIdentity::from_public(Identity::new(slot).public());
            let refused = enroll(
                State(st.clone()),
                Json(json!({"vault":vault,"slot":slot,"token":"wrong","identity":wire})),
            )
            .await;
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            let reply = enroll(
                State(st.clone()),
                Json(json!({
                    "vault":vault,"slot":slot,"token":invite.token,
                    "identity":wire
                })),
            )
            .await;
            assert_eq!(reply.0, StatusCode::OK);
        }
        let status = status(st.clone(), vault.clone()).await;
        assert_eq!(status.1 .0["phase"], "compare_roster");
        // Only an enrolled joiner with its own invite token may read the roster.
        for body in [
            json!({"vault":vault}),
            json!({"vault":vault,"slot":2,"token":tokens[&3]}),
            json!({"vault":vault,"slot":1,"token":tokens[&2]}),
        ] {
            let refused = roster(State(st.clone()), Json(body)).await;
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            assert_eq!(refused.1 .0["error"], "invalid member token");
        }
        let response =
            roster(State(st), Json(json!({"vault":vault,"slot":2,"token":tokens[&2]}))).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1 .0["fingerprint"], status.1 .0["fingerprint"]);
        eprintln!("PASS: emitted invite codes contain no vault_secret");
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn create_names_the_field_it_refuses() {
        let st = std::sync::Arc::new(AppState::new(Config {
            data: std::env::temp_dir(), port: 3001, network: "regtest".into(), native: false,
            lightwalletd: None, transport: "local".into(), operator_bundle: None,
            operator_key: None, enrollment_issuer: None, development_http: false,
            token: "test".into(), frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(),
            registration: None, bind: "127.0.0.1".parse().unwrap(), peer_port: None, advertise_url: None,
            secure_element: "software".into(), nonce_witnesses: None, loopback_peers: false,
        }));
        for (name, members, threshold, error) in [
            ("".to_owned(), 3, 2, "name must be 1 to 80 bytes"),
            ("x".repeat(81), 3, 2, "name must be 1 to 80 bytes"),
            ("Friends".to_owned(), 3, 3, "use 2 <= t < n <= 16"),
            ("Friends".to_owned(), 17, 2, "use 2 <= t < n <= 16"),
        ] {
            let body = json!({"name":name,"members":members,"threshold":threshold});
            let (status, Json(reply)) = create(State(st.clone()), Json(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(reply["error"], error, "{members} {threshold}");
        }
    }

    #[tokio::test]
    async fn invites_carry_the_advertised_url() {
        let data = std::env::temp_dir().join(format!("loki-advertise-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let config = Config { advertise_url: Some("https://creator.example/".into()), ..test_config(&data, 3001) };
        let st = std::sync::Arc::new(AppState::new(config));
        *st.session.write().await = Some(Session { passphrase: Zeroizing::new("pass".into()), data: data.clone() });
        let created = create(State(st), Json(json!({"name":"test","members":3,"threshold":2}))).await;
        for item in created.1 .0["invites"].as_array().unwrap() {
            let invite: Invite = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(item["code"].as_str().unwrap()).unwrap()).unwrap();
            assert_eq!(invite.creator_base_url, "https://creator.example");
        }
        std::fs::remove_dir_all(data).unwrap();
    }

    /// The creator answers only a join request sealed by the identity it names, for a vault it
    /// is setting up, and only with that slot's invite token.
    #[tokio::test]
    async fn a_forged_or_wrong_token_join_request_is_refused() {
        let data = std::env::temp_dir().join(format!("loki-join-forged-{}", Uuid::new_v4()));
        let st = member(&data, 3601, None).await;
        let created = create(State(st.clone()), Json(json!({"name":"test","members":3,"threshold":2}))).await;
        let vault = created.1 .0["vault"].as_str().unwrap().to_owned();
        let invite: Invite = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(created.1 .0["invites"][0]["code"].as_str().unwrap()).unwrap()).unwrap();
        let creator = identity(&data, "pass", 1).unwrap();
        assert!(invite.creator == Some(WireIdentity::from_public(creator.public())));
        let (joiner, attacker) = (Identity::new(2), Identity::new(2));
        let session = Uuid::new_v4();
        let context = join_context(&vault, session, 2).unwrap();
        let body = json!({"op":"enroll","vault":vault,"slot":2,"token":invite.token});
        let wire = |own: &Identity, context: &SessionContext, body: &Value| {
            Outbound::Peer(SealedPeer::seal_join(own, &creator.public(), context, &serde_json::to_vec(body).unwrap()).unwrap())
                .to_bytes().unwrap()
        };
        let from = joiner.public().encryption;
        let honest = wire(&joiner, &context, &body);
        assert!(open_join(&creator, &[vault.clone()], session, &from, &honest).is_some());

        // Sealed by another key than the relay sender's, signed by another key than the one it
        // names, unsealed, for another session, or naming another slot: none opens.
        let mut renamed = wire(&attacker, &context, &body);
        renamed[2..34].copy_from_slice(&joiner.public().signing);
        let mut unsealed = honest[..34].to_vec();
        unsealed.extend(serde_json::to_vec(&body).unwrap());
        let mut other_slot = honest.clone();
        other_slot[..2].copy_from_slice(&3u16.to_be_bytes());
        for (from, forged) in [
            (from, wire(&attacker, &context, &body)),
            (attacker.public().encryption, renamed),
            (from, unsealed),
            (from, wire(&joiner, &join_context(&vault, Uuid::new_v4(), 2).unwrap(), &body)),
            (from, other_slot),
        ] {
            assert!(open_join(&creator, &[vault.clone()], session, &from, &forged).is_none());
        }
        assert!(open_join(&creator, &[hex::encode([1u8; 32])], session, &from, &honest).is_none());

        let (joiner_public, _, _) = open_join(&creator, &[vault.clone()], session, &from, &honest).unwrap();
        for (op, error) in [("enroll", "invalid invite token"), ("roster", "invalid member token"), ("session", "invalid member token")] {
            let wrong = json!({"op":op,"vault":vault,"slot":2,"token":tokens_other(&invite.token)});
            assert_eq!(answer_join(&st, &data, "pass", &joiner_public, wrong).unwrap_err(), error);
        }
        assert!(load(&data, "pass", &vault).unwrap().slots[&2].identity.is_none());
        assert_eq!(answer_join(&st, &data, "pass", &joiner_public, body).unwrap(), json!({"ok":true}));
        assert!(load(&data, "pass", &vault).unwrap().slots[&2].identity == Some(WireIdentity::from_public(joiner.public())));
        *st.session.write().await = None;
        std::fs::remove_dir_all(data).unwrap();
    }

    /// A token of the same length that differs in its last byte.
    fn tokens_other(token: &str) -> String {
        format!("{}{}", &token[..token.len() - 1], if token.ends_with('A') { 'B' } else { 'A' })
    }

    /// Two joiners on their own data dirs join, agree and finish DKG with the creator over
    /// frostd alone: the invite's HTTP URL is a closed port. Needs `FROSTD_URL`.
    #[tokio::test(flavor = "multi_thread")]
    async fn unlocking_a_creator_mid_setup_restarts_its_join_loop() {
        let data = std::env::temp_dir().join(format!("loki-join-unlock-{}", Uuid::new_v4()));
        let st = member(&data, 3001, None).await;
        let created = create(State(st.clone()), Json(json!({"name":"test","members":3,"threshold":2}))).await;
        assert_eq!(created.0, StatusCode::OK, "{}", created.1 .0);
        let running = |st: &Shared| st.join_relay.load(std::sync::atomic::Ordering::SeqCst);
        assert!(running(&st));
        st.lock_session().await;
        for _ in 0..50 {
            if !running(&st) { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!running(&st), "the loop stops when the profile locks");
        let session = Session { passphrase: Zeroizing::new("pass".into()), data: data.clone() };
        assert!(st.activate_session(st.session_generation(), session).await);
        assert!(running(&st), "unlock restarts the loop without a status call");
        st.lock_session().await;
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_join_completes_over_frostd_without_the_creators_http_routes() {
        let Ok(url) = std::env::var("FROSTD_URL") else {
            eprintln!("FROSTD_URL unset; skipped");
            return;
        };
        let root = std::env::temp_dir().join(format!("loki-join-relay-{}", Uuid::new_v4()));
        let mut members = Vec::new();
        let mut dialogs = Vec::new();
        for name in ["creator", "joiner2", "joiner3"] {
            let data = root.join(name);
            std::fs::create_dir_all(&data).unwrap();
            let config = Config { frostd_url: url.clone(), advertise_url: Some("http://127.0.0.1:9".into()), ..test_config(&data, 3601) };
            let (confirm, dialog) = Dialog::new();
            let st = std::sync::Arc::new(AppState { roster_confirmation: Some(confirm), ..AppState::new(config) });
            *st.session.write().await = Some(Session { passphrase: Zeroizing::new("pass".into()), data });
            members.push(st);
            dialogs.push(dialog);
        }
        // Locking ends every member's waits, so the runtime stops even when an assertion fails.
        struct LockOnDrop(Vec<Shared>);
        impl Drop for LockOnDrop {
            fn drop(&mut self) {
                for st in &self.0 {
                    if let Ok(mut session) = st.session.try_write() { *session = None; }
                }
            }
        }
        let _lock = LockOnDrop(members.clone());
        let created = create(State(members[0].clone()), Json(json!({"name":"relay","members":3,"threshold":2}))).await;
        assert_eq!(created.0, StatusCode::OK, "{}", created.1 .0);
        let vault = created.1 .0["vault"].as_str().unwrap().to_owned();
        for slot in 2..=3usize {
            let code = created.1 .0["invites"].as_array().unwrap().iter()
                .find(|item| item["slot"] == slot).unwrap()["code"].as_str().unwrap();
            let invite: Invite = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(code).unwrap()).unwrap();
            assert_eq!(invite.creator_base_url, "http://127.0.0.1:9");
            let reply = join(State(members[slot - 1].clone()), Json(json!({"invite":code}))).await;
            assert_eq!(reply.0, StatusCode::OK, "{}", reply.1 .0);
        }
        for (st, dialog) in members.iter().zip(dialogs) {
            let (fingerprint, code, signer_code) = compare(st, &vault).await;
            let request = tokio::spawn(agree(State(st.clone()), agree_body(&vault, &fingerprint, &code)));
            assert_eq!(dialog.open()["roster_code"], signer_code.as_str());
            dialog.answer.send(crate::host::RosterAnswer::Match).unwrap();
            let reply = request.await.unwrap();
            assert_eq!(reply.0, StatusCode::OK, "{}", reply.1 .0);
        }
        let mut addresses = BTreeSet::new();
        for st in &members {
            let deadline = std::time::Instant::now() + Duration::from_secs(180);
            loop {
                let reply = status(st.clone(), vault.clone()).await.1 .0;
                if reply["phase"] == "active" { break; }
                assert!(reply.get("error").is_none() && std::time::Instant::now() < deadline, "{reply}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let query = BTreeMap::from([("vault".to_owned(), vault.clone())]);
            addresses.insert(address(State(st.clone()), Query(query)).await.1 .0["address"].as_str().unwrap().to_owned());
        }
        assert_eq!(addresses.len(), 1, "{addresses:?}");
        drop(_lock);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn roster_prompt_matches_only_the_confirmed_code() {
        let code = "1234 5678 9012 3456 7890 1234";
        assert!(matches!(roster_decision(Some(code), code), RosterDecision::Match));
        assert!(matches!(roster_decision(Some(code), "1234 5678 9012 3456 7890 1235"), RosterDecision::NoMatch));
        assert!(matches!(roster_decision(None, code), RosterDecision::NoMatch));
    }

    #[tokio::test]
    async fn agree_requires_the_roster_code_the_signer_will_show() {
        let data = std::env::temp_dir().join(format!("loki-roster-code-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let st = std::sync::Arc::new(AppState::new(Config {
            data: data.clone(), port: 3001, network: "regtest".into(), native: false,
            lightwalletd: None, transport: "local".into(), operator_bundle: None,
            operator_key: None, enrollment_issuer: None, development_http: false,
            token: "test".into(), frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(),
            registration: None, bind: "127.0.0.1".parse().unwrap(), peer_port: None, advertise_url: None,
            secure_element: "software".into(), nonce_witnesses: None, loopback_peers: false,
        }));
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("pass".into()), data: data.clone(),
        });
        let created = create(State(st.clone()), Json(json!({"name":"test","members":3,"threshold":2}))).await;
        let vault = created.1 .0["vault"].as_str().unwrap().to_owned();
        for slot in 2..=3u16 {
            let code = created.1 .0["invites"].as_array().unwrap().iter()
                .find(|item| item["slot"] == slot).unwrap()["code"].as_str().unwrap();
            let invite: Invite = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(code).unwrap()).unwrap();
            let wire = WireIdentity::from_public(Identity::new(slot).public());
            let reply = enroll(State(st.clone()),
                Json(json!({"vault":vault,"slot":slot,"token":invite.token,"identity":wire}))).await;
            assert_eq!(reply.0, StatusCode::OK);
        }
        let status = status(st.clone(), vault.clone()).await.1 .0;
        assert!(status.get("roster_dialog").is_none(), "a headless member has no roster dialog");
        let fingerprint = status["fingerprint"].as_str().unwrap().to_owned();
        let code = status["roster_code"].as_str().unwrap().to_owned();
        // The code the signer derives in `dkg_begin` from the document `run_background` hands it.
        let c = load(&data, "pass", &vault).unwrap();
        let (document, _) = setup_document(&c, VaultNetwork::Regtest).unwrap();
        let validated = crate::member_state::ValidatedRoster::new(
            crate::member_state::Roster::from_bytes(&document).unwrap()).unwrap();
        assert_eq!(code, roster_code(&validated.fingerprint()));
        assert_eq!(code.len(), 29);

        let wrong = format!("{}{}", &code[..28], if code.ends_with('0') { '1' } else { '0' });
        for body in [
            json!({"vault":vault,"fingerprint":fingerprint}),
            json!({"vault":vault,"fingerprint":fingerprint,"roster_code":wrong}),
        ] {
            let refused = agree(State(st.clone()), Json(body)).await;
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            let c = load(&data, "pass", &vault).unwrap();
            assert!(c.agreed.is_empty() && c.roster_code.is_none());
        }
        let reply = agree(State(st.clone()),
            Json(json!({"vault":vault,"fingerprint":fingerprint,"roster_code":code}))).await;
        assert_eq!(reply.1 .0["error"], ROSTER_NOT_CONFIRMED);
        let c = load(&data, "pass", &vault).unwrap();
        assert!(c.agreed.is_empty() && c.roster_code.is_none());

        // On Testnet the code covers the birth height fixed with the roster.
        let mut c = c;
        assert!(setup_roster_code(&c, VaultNetwork::Testnet).is_err());
        c.birth_height = Some(TESTNET_NU7_BIRTH + 1);
        let testnet = setup_roster_code(&c, VaultNetwork::Testnet).unwrap();
        c.birth_height = Some(TESTNET_NU7_BIRTH + 2);
        assert_ne!(testnet, setup_roster_code(&c, VaultNetwork::Testnet).unwrap());
        std::fs::remove_dir_all(data).unwrap();
    }

    fn test_config(data: &Path, port: u16) -> Config {
        Config {
            data: data.to_owned(), port, network: "regtest".into(), native: false,
            lightwalletd: None, transport: "local".into(), operator_bundle: None,
            operator_key: None, enrollment_issuer: None, development_http: false,
            token: "test".into(), frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(),
            registration: None, bind: "127.0.0.1".parse().unwrap(), peer_port: None, advertise_url: None,
            secure_element: "software".into(), nonce_witnesses: None, loopback_peers: false,
        }
    }

    #[tokio::test]
    async fn status_reports_the_configured_secure_element() {
        let client = reqwest::Client::new();
        for element in ["apple", "software"] {
            let data = std::env::temp_dir().join(format!("loki-storage-status-{}", Uuid::new_v4()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = Config { secure_element: element.into(), ..test_config(&data, addr.port()) };
            // Status describes the configuration; no platform key is needed to report it.
            let st = std::sync::Arc::new(AppState::new(config));
            let router = crate::host::routes::router(st.clone());
            tokio::spawn(async move { axum::serve(listener, router).await });
            let status = |query: &str| client.get(format!("http://{addr}/api/status{query}"))
                .header("x-loki-token", "test");
            let read = |response: reqwest::RequestBuilder| async move {
                response.send().await.unwrap().error_for_status().unwrap().json::<Value>().await.unwrap()
            };

            let new_profile = read(status("")).await;
            assert_eq!(new_profile["phase"], "new_profile");
            assert_eq!(new_profile["secure_element"], element);

            crate::profile::create(&data, "pass", "test").unwrap();
            *st.session.write().await = Some(Session { passphrase: Zeroizing::new("pass".into()), data: data.clone() });
            let created = create(State(st), Json(json!({"name":"test","members":3,"threshold":2}))).await;
            assert_eq!(created.0, StatusCode::OK, "{}", created.1 .0);
            let vault = created.1 .0["vault"].as_str().unwrap();

            let home = read(status("")).await;
            assert_eq!(home["phase"], "home");
            assert_eq!(home["secure_element"], element);
            let setup = read(status(&format!("?vault={vault}"))).await;
            assert_eq!(setup["phase"], "waiting_for_members");
            assert_eq!(setup["secure_element"], element);
            std::fs::remove_dir_all(data).unwrap();
        }
    }

    /// An unlocked member on `data`, with LokiSigner's roster dialog when `dialog` is given.
    async fn member(data: &Path, port: u16, dialog: Option<crate::host::LocalRosterConfirmation>) -> Shared {
        std::fs::create_dir_all(data).unwrap();
        let config = Config { native: dialog.is_some(), ..test_config(data, port) };
        let st = std::sync::Arc::new(AppState { roster_confirmation: dialog, ..AppState::new(config) });
        *st.session.write().await = Some(Session { passphrase: Zeroizing::new("pass".into()), data: data.to_owned() });
        st
    }

    /// LokiSigner's roster dialog, scripted: each summary it is asked about arrives on
    /// `asked`, and it waits for the test's answer on `answer`.
    struct Dialog {
        asked: std::sync::mpsc::Receiver<String>,
        answer: std::sync::mpsc::Sender<crate::host::RosterAnswer>,
    }

    impl Dialog {
        fn new() -> (crate::host::LocalRosterConfirmation, Self) {
            let (asked_tx, asked) = std::sync::mpsc::channel();
            let (answer, answer_rx) = std::sync::mpsc::channel();
            let answer_rx = std::sync::Mutex::new(answer_rx);
            let confirm: crate::host::LocalRosterConfirmation = std::sync::Arc::new(move |summary: &str| {
                asked_tx.send(summary.to_owned()).unwrap();
                answer_rx.lock().unwrap().recv().unwrap_or(crate::host::RosterAnswer::NoAnswer)
            });
            (confirm, Self { asked, answer })
        }

        /// The summary of the dialog now open.
        fn open(&self) -> Value {
            serde_json::from_str(&self.asked.recv_timeout(Duration::from_secs(30)).expect("LokiSigner was not asked")).unwrap()
        }

        fn not_asked(&self) {
            assert!(self.asked.try_recv().is_err(), "LokiSigner was asked");
        }
    }

    /// A creator's 2-of-3 vault named `name` whose roster is complete. Returns the vault and
    /// each joiner slot's invite.
    async fn complete_roster(creator: &Shared, name: &str, joiner: Option<&Shared>) -> (String, BTreeMap<u16, String>) {
        let created = create(State(creator.clone()), Json(json!({"name":name,"members":3,"threshold":2}))).await;
        assert_eq!(created.0, StatusCode::OK, "{}", created.1 .0);
        let vault = created.1 .0["vault"].as_str().unwrap().to_owned();
        let mut invites = BTreeMap::new();
        for slot in 2..=3u16 {
            let code = created.1 .0["invites"].as_array().unwrap().iter()
                .find(|item| item["slot"] == slot).unwrap()["code"].as_str().unwrap().to_owned();
            invites.insert(slot, code.clone());
            let reply = match (slot, joiner) {
                // An invite without the creator's identity: the joiner reaches the creator over
                // HTTP, so the test needs no relay.
                (2, Some(joiner)) => {
                    let mut fields: Value = serde_json::from_slice(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&code).unwrap()).unwrap();
                    fields.as_object_mut().unwrap().remove("creator");
                    let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fields.to_string());
                    join(State(joiner.clone()), Json(json!({"invite":code}))).await
                }
                _ => {
                    let invite: Invite = serde_json::from_slice(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&code).unwrap()).unwrap();
                    let wire = WireIdentity::from_public(Identity::new(slot).public());
                    enroll(State(creator.clone()),
                        Json(json!({"vault":vault,"slot":slot,"token":invite.token,"identity":wire}))).await
                }
            };
            assert_eq!(reply.0, StatusCode::OK, "{}", reply.1 .0);
        }
        (vault, invites)
    }

    /// The fingerprint and code `/api/status` gives the page, and the code the signer derives
    /// in `dkg_begin` from the setup document `run_background` hands it.
    async fn compare(st: &Shared, vault: &str) -> (String, String, String) {
        let status = status(st.clone(), vault.to_owned()).await.1 .0;
        assert_eq!(status["phase"], "compare_roster", "{status}");
        let c = load(&st.config.data, "pass", vault).unwrap();
        let (document, _) = setup_document(&c, VaultNetwork::Regtest).unwrap();
        let validated = crate::member_state::ValidatedRoster::new(
            crate::member_state::Roster::from_bytes(&document).unwrap()).unwrap();
        (status["fingerprint"].as_str().unwrap().to_owned(), status["roster_code"].as_str().unwrap().to_owned(),
            roster_code(&validated.fingerprint()))
    }

    fn agree_body(vault: &str, fingerprint: &str, code: &str) -> Json<Value> {
        Json(json!({"vault":vault,"fingerprint":fingerprint,"roster_code":code}))
    }

    fn unrecorded(st: &Shared, vault: &str) {
        let c = load(&st.config.data, "pass", vault).unwrap();
        assert!(c.agreed.is_empty() && c.roster_code.is_none(), "agreement recorded: {:?}", c.agreed);
    }

    /// A joiner with LokiSigner attached agrees only through the dialog: a correct request the
    /// member does not confirm records nothing here and tells the creator nothing. The dialog
    /// shows the code of the setup document, and the creator's vault name as one line.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_native_joiner_agrees_only_when_the_member_confirms_the_code_in_lokisigner() {
        use crate::host::RosterAnswer;
        let root = std::env::temp_dir().join(format!("loki-native-roster-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let creator = member(&root.join("creator"), listener.local_addr().unwrap().port(), None).await;
        let router = crate::host::routes::router(creator.clone());
        tokio::spawn(async move { axum::serve(listener, router).await });
        let (dialog, lokisigner) = Dialog::new();
        let joiner = member(&root.join("joiner"), 3602, Some(dialog)).await;
        // An agreement starts the joiner's wait for the creator's session; locking ends it, so
        // the test runtime can stop even when an assertion fails.
        struct LockOnDrop(Shared);
        impl Drop for LockOnDrop {
            fn drop(&mut self) {
                if let Ok(mut session) = self.0.session.try_write() { *session = None; }
            }
        }
        let _lock = LockOnDrop(joiner.clone());
        let hostile = "Rent\nChoose Codes match now\r\u{7}\u{1b}[2J\u{202e}hctam\u{2028}x\u{200b}";
        let (vault, _) = complete_roster(&creator, hostile, Some(&joiner)).await;
        let (fingerprint, code, signer_code) = compare(&joiner, &vault).await;
        assert_eq!(code, signer_code);
        let creator_heard = || load(&creator.config.data, "pass", &vault).unwrap().agreed.contains(&2);

        // A wrong code is refused before any dialog.
        let wrong = format!("{}{}", &code[..28], if code.ends_with('0') { '1' } else { '0' });
        let reply = agree(State(joiner.clone()), agree_body(&vault, &fingerprint, &wrong)).await;
        assert_eq!(reply.1 .0["error"], "roster code mismatch");
        lokisigner.not_asked();

        for (answer, error) in [(RosterAnswer::NoAnswer, ROSTER_NOT_CONFIRMED), (RosterAnswer::Match, "")] {
            let request = tokio::spawn(agree(State(joiner.clone()), agree_body(&vault, &fingerprint, &code)));
            let shown = lokisigner.open();
            assert_eq!(shown["roster_code"], signer_code.as_str());
            assert_eq!((shown["threshold"].as_u64(), shown["members"].as_u64(), shown["member"].as_u64()), (Some(2), Some(3), Some(2)));
            assert_eq!(shown["network"], "regtest");
            assert_eq!(shown["vault_name"], crate::host::HIDDEN_VAULT_NAME, "the creator's text reached the dialog");
            let keys: Vec<_> = shown.as_object().unwrap().keys().cloned().collect();
            assert_eq!(keys, ["member", "members", "network", "roster_code", "threshold", "vault_name"]);
            lokisigner.answer.send(answer).unwrap();
            let reply = request.await.unwrap();
            if answer == RosterAnswer::Match {
                assert_eq!(reply.0, StatusCode::OK, "{}", reply.1 .0);
            } else {
                assert_eq!(reply.1 .0["error"], error);
                unrecorded(&joiner, &vault);
                assert!(!creator_heard(), "the creator heard of an agreement the member did not confirm");
            }
        }
        let c = load(&joiner.config.data, "pass", &vault).unwrap();
        assert!(c.agreed.contains(&2));
        assert_eq!(c.roster_code.as_deref(), Some(signer_code.as_str()));
        assert!(creator_heard());
        drop(_lock);
        std::fs::remove_dir_all(root).ok();
    }

    /// While LokiSigner asks, the ceremony lock is free and a second request is refused without
    /// a second dialog. A roster that changes while the dialog is open is refused even when
    /// the member confirms the code shown.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_roster_dialog_holds_no_lock_asks_once_and_refuses_a_changed_roster() {
        let data = std::env::temp_dir().join(format!("loki-roster-dialog-{}", Uuid::new_v4()));
        let (dialog, lokisigner) = Dialog::new();
        let st = member(&data, 3601, Some(dialog)).await;
        let (vault, _) = complete_roster(&st, "Household", None).await;
        let (fingerprint, code, _) = compare(&st, &vault).await;

        let request = tokio::spawn(agree(State(st.clone()), agree_body(&vault, &fingerprint, &code)));
        lokisigner.open();
        assert!(st.ceremony.try_lock().is_ok(), "the ceremony lock is held while the member decides");
        assert_eq!(status(st.clone(), vault.clone()).await.1 .0["roster_dialog"], "open");
        let second = tokio::time::timeout(Duration::from_secs(10), agree(State(st.clone()), agree_body(&vault, &fingerprint, &code)))
            .await.expect("a second request waited for a second dialog");
        assert_eq!(second.1 .0["error"], ROSTER_ASKING);
        lokisigner.not_asked();
        // Slot 3's identity changes while the dialog is open.
        let mut c = load(&data, "pass", &vault).unwrap();
        c.slots.get_mut(&3).unwrap().identity = Some(WireIdentity::from_public(Identity::new(3).public()));
        save(&data, "pass", &c).unwrap();
        lokisigner.answer.send(crate::host::RosterAnswer::Match).unwrap();
        let reply = request.await.unwrap();
        assert!(reply.1 .0["error"].as_str().unwrap().starts_with(ROSTER_CHANGED), "{}", reply.1 .0);
        unrecorded(&st, &vault);
        assert!(status(st.clone(), vault.clone()).await.1 .0["roster_dialog"].is_null());
        std::fs::remove_dir_all(data).unwrap();
    }

    /// After "Codes differ" the vault is refused without asking until LokiSigner restarts; a
    /// restarted LokiSigner asks again.
    #[tokio::test(flavor = "multi_thread")]
    async fn codes_differ_refuses_the_vault_until_lokisigner_restarts() {
        let data = std::env::temp_dir().join(format!("loki-roster-differ-{}", Uuid::new_v4()));
        let (dialog, lokisigner) = Dialog::new();
        let st = member(&data, 3601, Some(dialog)).await;
        let (vault, _) = complete_roster(&st, "Household", None).await;
        let (fingerprint, code, _) = compare(&st, &vault).await;
        let request = tokio::spawn(agree(State(st.clone()), agree_body(&vault, &fingerprint, &code)));
        lokisigner.open();
        lokisigner.answer.send(crate::host::RosterAnswer::Differ).unwrap();
        assert_eq!(request.await.unwrap().1 .0["error"], ROSTER_CODES_DIFFER);
        let again = tokio::time::timeout(Duration::from_secs(10), agree(State(st.clone()), agree_body(&vault, &fingerprint, &code)))
            .await.expect("the refused vault opened a dialog again");
        assert_eq!(again.1 .0["error"], ROSTER_CODES_DIFFER);
        lokisigner.not_asked();
        unrecorded(&st, &vault);
        assert_eq!(status(st.clone(), vault.clone()).await.1 .0["roster_dialog"], "codes_differ");

        let (dialog, lokisigner) = Dialog::new();
        let restarted = member(&data, 3601, Some(dialog)).await;
        let request = tokio::spawn(agree(State(restarted.clone()), agree_body(&vault, &fingerprint, &code)));
        lokisigner.open();
        lokisigner.answer.send(crate::host::RosterAnswer::Match).unwrap();
        assert_eq!(request.await.unwrap().0, StatusCode::OK);
        assert_eq!(load(&data, "pass", &vault).unwrap().roster_code.as_deref(), Some(code.as_str()));
        std::fs::remove_dir_all(data).unwrap();
    }

    /// A request that reaches the claim after another request's "Codes differ" opens no
    /// dialog: the refusal is checked under the same lock as the open dialog.
    #[tokio::test]
    async fn a_refused_vault_cannot_claim_the_dialog() {
        let data = std::env::temp_dir().join(format!("loki-roster-claim-{}", Uuid::new_v4()));
        let (dialog, _lokisigner) = Dialog::new();
        let st = member(&data, 3601, Some(dialog)).await;
        let vault = hex::encode([4u8; 32]);
        drop(RosterAsking::claim(&st, &vault).expect("an open vault claims the dialog"));
        st.roster_refused.lock().unwrap().insert(vault.clone());
        assert_eq!(RosterAsking::claim(&st, &vault).err().as_deref(), Some(ROSTER_CODES_DIFFER));
        assert!(st.roster_asking.lock().unwrap().is_none(), "a refused claim left the dialog marked open");
        assert!(RosterAsking::claim(&st, &hex::encode([5u8; 32])).is_ok(), "another vault may still ask");
        std::fs::remove_dir_all(data).ok();
    }

    /// A profile locked while LokiSigner asks records nothing, even when the member then
    /// chooses "Codes match".
    #[tokio::test(flavor = "multi_thread")]
    async fn a_profile_locked_while_lokisigner_asks_records_nothing() {
        let data = std::env::temp_dir().join(format!("loki-roster-locked-{}", Uuid::new_v4()));
        let (dialog, lokisigner) = Dialog::new();
        let st = member(&data, 3601, Some(dialog)).await;
        let (vault, _) = complete_roster(&st, "Household", None).await;
        let (fingerprint, code, _) = compare(&st, &vault).await;
        let request = tokio::spawn(agree(State(st.clone()), agree_body(&vault, &fingerprint, &code)));
        lokisigner.open();
        *st.session.write().await = None;
        lokisigner.answer.send(crate::host::RosterAnswer::Match).unwrap();
        let reply = request.await.unwrap();
        assert!(reply.1 .0["error"].as_str().unwrap().starts_with(ROSTER_CHANGED), "{}", reply.1 .0);
        unrecorded(&st, &vault);
        std::fs::remove_dir_all(data).unwrap();
    }

    /// Recovery WORDS loop (ship-blocker fix): the vault seals a per-vault recovery backup at
    /// activation, and a member whose local state is destroyed restores its signing share from
    /// the 24 words alone. Reproduces the post-DKG state (`recovery.pub` + `backup.sealed`) and
    /// drives the real host seal (`recovery::seal_vault_backup`) and restore
    /// (`restore_vault_from_backup`) paths — the loop QA could not run because nothing sealed the
    /// backup.
    #[test]
    fn recovery_backup_seals_at_activation_and_restores_the_share_from_words() {
        use crate::signer::recovery::RecoveryKey;
        use crate::signer::secure_element::SoftwareSecureElement;
        use crate::signer::store::{FileKind, SignerStore};

        let data = std::env::temp_dir().join(format!("loki-recovery-words-{}", Uuid::new_v4()));
        let vault = [9u8; 32];
        let vault_hex = hex::encode(vault);
        let pass = "pass";

        // Registration establishes the recovery identity (words shown once; only pubkeys stored).
        let (words, rkey) = RecoveryKey::generate().unwrap();
        MemberDir::create(&data, "").unwrap();
        let mut pubkeys = Vec::with_capacity(64);
        pubkeys.extend_from_slice(&rkey.public_bytes());
        pubkeys.extend_from_slice(&rkey.signing_public());
        crate::host::recovery::adopt_recovery(&data, &rkey, pass).unwrap();
        drop(rkey);

        let (material, shares, public) = dealer_vault(&data, vault, pass);
        let share_bytes = material.key_package.to_vec();
        let sdir = signer_dir(&data, &vault_hex).unwrap();

        // Activation seals the recovery backup — the wiring under test.
        crate::host::recovery::seal_vault_backup(&data, &sdir, &vault, pass).unwrap();
        let blob = std::fs::read(crate::host::recovery::backup_file(&sdir)).unwrap();
        let fingerprint = BackupArtifact(blob.clone()).fingerprint();
        assert!(
            !blob.windows(share_bytes.len()).any(|w| w == share_bytes.as_slice()),
            "the recovery backup is HPKE ciphertext, never the share plaintext",
        );

        // DESTROY the device: wipe the entire data root (share store, backups, identity, pubkeys).
        // The new device starts empty; the member brings only the exported blob and the words.
        std::fs::remove_dir_all(&data).unwrap();
        let sdir = signer_dir(&data, &vault_hex).unwrap();

        let make_config = || Config {
            registration: None, native: false,
            data: data.clone(),
            port: 3001,
            bind: "127.0.0.1".parse().unwrap(),
            peer_port: None,
            advertise_url: None,
            network: "regtest".into(),
            lightwalletd: None,
            transport: "local".into(),
            secure_element: "software".into(),
            operator_bundle: None,
            nonce_witnesses: None,
            operator_key: None,
            enrollment_issuer: None,
            development_http: false,
            token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(),
            loopback_peers: false,
        };
        let config = make_config();

        // Wrong words cannot open the backup, and restore needs the exported blob here.
        let (other, _) = RecoveryKey::generate().unwrap();
        assert!(restore_vault_from_backup(&data, &vault_hex, &other, Some(&blob), Some(&fingerprint), pass, &config).is_err());
        assert!(restore_vault_from_backup(&data, &vault_hex, &words, None, Some(&fingerprint), pass, &config).is_err());
        // A profile that already holds another member identity is never overwritten.
        let root = MemberDir::create(&data, "").unwrap();
        root.write_sealed("identity.sealed", &Identity::new(1).to_secret_bytes(), pass).unwrap();
        let conflict = restore_vault_from_backup(&data, &vault_hex, &words, Some(&blob), Some(&fingerprint), pass, &config);
        assert!(conflict.unwrap_err().contains("different member identity"));
        assert!(!dir(&data, &vault_hex).unwrap().exists("vault.sealed"));
        std::fs::remove_dir_all(&data).unwrap();
        // A profile whose recovery identity is another set of words is refused before any write.
        let other_key = RecoveryKey::from_words(&other).unwrap();
        let mut other_pub = other_key.public_bytes().to_vec();
        other_pub.extend_from_slice(&other_key.signing_public());
        MemberDir::create(&data, "").unwrap();
        std::fs::write(data.join("recovery.pub"), &other_pub).unwrap();
        let conflict = restore_vault_from_backup(&data, &vault_hex, &words, Some(&blob), Some(&fingerprint), pass, &config);
        assert!(conflict.unwrap_err().contains("different recovery words"));
        assert!(!dir(&data, &vault_hex).unwrap().exists("vault.sealed"));
        assert!(!data.join("identity.sealed").exists());
        assert_eq!(std::fs::read(data.join("recovery.pub")).unwrap(), other_pub);
        std::fs::remove_dir_all(&data).unwrap();

        // The real words restore a member the payment path can open and sign with.
        restore_vault_from_backup(&data, &vault_hex, &words, Some(&blob), Some(&fingerprint), pass, &config).unwrap();
        crate::host::payment::load_vault(&AppState::new(make_config()), &data, pass, &vault_hex)
            .expect("the restored member opens for signing");
        // Restore brings the recovery identity: `recovery.pub` holds both public keys of these
        // words, so a later start or recovery setup does not mint a second set.
        assert_eq!(std::fs::read(data.join("recovery.pub")).unwrap(), pubkeys);
        assert!(crate::host::recovery::exists(&data));

        // `vault.sealed` is public metadata only. The restored member completes a rerandomized
        // FROST round with member 2 using the key package from the signer store, read through
        // the configured element as the payment path does; the aggregate verifies.
        let sealed: Value = serde_json::from_slice(&dir(&data, &vault_hex).unwrap().read_sealed("vault.sealed", pass).unwrap()).unwrap();
        assert!(sealed.get("key_package").is_none() && sealed.get("vault_secret").is_none());
        let element = config.open_secure_element(&sdir, pass).unwrap();
        let (_, stored) = SignerStore::open(&sdir).unwrap().read(&element, FileKind::Share).unwrap().unwrap();
        let restored = frost::keys::KeyPackage::deserialize(&crate::signer::local::decode_share(&stored).unwrap().0).unwrap();
        let group = frost::keys::PublicKeyPackage::deserialize(&hex::decode(sealed["public_package"].as_str().unwrap()).unwrap()).unwrap();
        let peer = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(2u16).unwrap()].clone()).unwrap();
        let message = b"restored member signs";
        let (n1, c1) = frost::round1::commit(restored.signing_share(), &mut OsRng);
        let (n2, c2) = frost::round1::commit(peer.signing_share(), &mut OsRng);
        let commitments = BTreeMap::from([(*restored.identifier(), c1), (*peer.identifier(), c2)]);
        let package = frost::SigningPackage::new(commitments.clone(), message);
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(group.verifying_key(), &commitments, OsRng).unwrap();
        let shares_out = BTreeMap::from([
            (*restored.identifier(), frost_rerandomized::sign_with_randomizer_seed(&package, &n1, &restored, &seed).unwrap()),
            (*peer.identifier(), frost_rerandomized::sign_with_randomizer_seed(&package, &n2, &peer, &seed).unwrap()),
        ]);
        let signature = frost_rerandomized::aggregate(&package, &shares_out, &group, &params)
            .expect("the restored member's share aggregates");
        params.randomized_verifying_key().verify(message, &signature)
            .expect("the aggregate signature verifies under the vault's randomized group key");
        assert_eq!(group.verifying_key(), public.verifying_key());
        assert_eq!(std::fs::read(crate::host::recovery::backup_file(&sdir)).unwrap(), blob);
        assert!(
            restore_vault_from_backup(&data, &vault_hex, &words, Some(&blob), Some(&fingerprint), pass, &config).is_err(),
            "never replace an existing vault",
        );

        // Read the restored share back through the real store + device element (the production
        // signing path) and prove it is byte-identical to the original and derives the vault's
        // viewing key — i.e. it signs for this group.
        let se = SoftwareSecureElement::persistent(&sdir, pass).unwrap();
        let (_epoch, raw) = SignerStore::open(&sdir)
            .unwrap()
            .read(&se, FileKind::Share)
            .unwrap()
            .unwrap();
        let (restored_key, restored_public, restored_vs) =
            crate::signer::local::decode_share(&raw).unwrap();
        assert_eq!(&*restored_key, &share_bytes, "restored share matches the original key package");
        assert_eq!(restored_vs, material.group_sk);
        assert_eq!(restored_public, material.public_package);
        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        zip2005::frost_viewing_key(&ak, &restored_vs)
            .expect("the restored share derives the vault FVK — it can sign for this group");

        // A vault written before device-bound custody carried the share and `vs` in
        // `vault.sealed`, with a passphrase-sealed `backup.sealed` beside the store.
        let vdir = dir(&data, &vault_hex).unwrap();
        let write_legacy = |legacy: &Value| {
            std::fs::remove_file(vdir.path().join("vault.sealed")).unwrap();
            vdir.write_sealed("vault.sealed", &serde_json::to_vec(legacy).unwrap(), pass).unwrap();
        };
        let mut legacy = sealed.clone();
        legacy["vault_secret"] = json!(hex::encode(material.group_sk));
        legacy["key_package"] = json!(hex::encode(peer.serialize().unwrap()));
        write_legacy(&legacy);
        MemberDir::open(&sdir, "").write_sealed("backup.sealed", b"passphrase copy", pass).unwrap();
        // A share in vault.sealed that differs from the store's stops migration, changing nothing.
        let refused = crate::host::payment::load_vault(&AppState::new(make_config()), &data, pass, &vault_hex);
        assert!(refused.err().unwrap().contains("different share"));
        let unchanged: Value = serde_json::from_slice(&vdir.read_sealed("vault.sealed", pass).unwrap()).unwrap();
        assert_eq!(unchanged, legacy);
        assert!(sdir.join("backup.sealed").exists());
        // The same share migrates once: vault.sealed keeps exactly its public metadata, the
        // unusable passphrase copy is not trusted for conversion, and the member still opens.
        legacy["key_package"] = json!(hex::encode(restored.serialize().unwrap()));
        write_legacy(&legacy);
        crate::host::payment::load_vault(&AppState::new(make_config()), &data, pass, &vault_hex)
            .expect("the migrated member opens for signing");
        let migrated: Value = serde_json::from_slice(&vdir.read_sealed("vault.sealed", pass).unwrap()).unwrap();
        assert_eq!(migrated, sealed);
        assert!(sdir.join("backup.sealed").exists());
        assert_eq!(std::fs::read(crate::host::recovery::backup_file(&sdir)).unwrap(), blob);
        crate::host::payment::load_vault(&AppState::new(make_config()), &data, pass, &vault_hex).unwrap();

        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        {
            use crate::signer::secure_element_apple::KeyFailure;
            let mut config = make_config();
            config.secure_element = "apple".into();
            let st = AppState::new(config);
            for may_create in [true, false] {
                let _keychain = crate::host::state::apple_test::install(&data, move |_, _, create| {
                    assert_eq!(create, may_create);
                    Err(KeyFailure::Cancelled)
                });
                assert_eq!(crate::host::custody::migrate(&st, &data, pass, &vault_hex, 1, &legacy).unwrap_err(),
                    KeyFailure::Cancelled.message());
                if may_create { std::fs::remove_file(sdir.join("kek.sealed")).unwrap(); }
            }
        }
        std::fs::remove_dir_all(&data).unwrap();
    }

    /// An active 2-of-3 dealer vault where this member is slot 1: `backup.sealed` written exactly
    /// as the signer does during DKG (`HostedBackup::save`), and a `vault.sealed` marker.
    fn dealer_vault(
        data: &Path,
        vault: [u8; 32],
        pass: &str,
    ) -> (
        crate::signer::backup::BackupMaterial,
        BTreeMap<frost::Identifier, frost::keys::SecretShare>,
        frost::keys::PublicKeyPackage,
    ) {
        use crate::signer::backup::{self, BackupMaterial};
        let vault_hex = hex::encode(vault);
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let kp1 = frost::keys::KeyPackage::try_from(shares[&id1].clone()).unwrap();
        // The DKG roster names every member's relay identity, which signing needs.
        let ids: Vec<_> = (1..=3).map(Identity::new).collect();
        let roster = serde_json::to_vec(&json!({
            "vault": vault_hex, "threshold": 2, "setup_version": 2, "network": "regtest",
            "members": ids.iter().map(|i| {
                let p = i.public();
                json!({"id": p.id, "signing": hex::encode(p.signing), "encryption": hex::encode(p.encryption)})
            }).collect::<Vec<_>>(),
        }))
        .unwrap();
        let material = BackupMaterial {
            member_id: 1,
            threshold: 2,
            members: 3,
            network: Network::Regtest,
            vault_id: vault,
            label: "recovery vault".into(),
            group_sk: [42u8; 32],
            key_package: Zeroizing::new(kp1.serialize().unwrap()),
            public_package: public.serialize().unwrap(),
            backup_epoch: 0,
            identity: Zeroizing::new(ids[0].to_secret_bytes().to_vec()),
            roster_fingerprint: crate::member_state::Roster::from_bytes(&roster).unwrap().fingerprint(),
            roster,
            birth_height: None,
        };
        MemberDir::create(&signer_dir(data, &vault_hex).unwrap(), "")
            .unwrap()
            .write_sealed("backup.sealed", &backup::create(&material, pass).unwrap().0, pass)
            .unwrap();
        // Only its presence marks the vault active for the backup sweep.
        dir(data, &vault_hex).unwrap().write_sealed("vault.sealed", b"{}", pass).unwrap();
        (material, shares, public)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[test]
    fn dkg_opens_an_existing_signer_and_only_creates_for_a_fresh_store() {
        use crate::signer::secure_element_apple::KeyFailure;
        let data = std::env::temp_dir().join(format!("loki-apple-dkg-{}", Uuid::new_v4()));
        let dir = data.join("signer");
        std::fs::create_dir_all(&dir).unwrap();
        let config = crate::host::config_from_args(&["--data".into(), data.to_str().unwrap().into(),
            "--port".into(), "3601".into(), "--secure-element".into(), "apple".into()]).unwrap();
        for fresh in [true, false] {
            if !fresh { std::fs::write(dir.join("share.sealed"), b"existing seal without metadata").unwrap(); }
            let _keychain = crate::host::state::apple_test::install(&data, move |_, _, create| {
                assert_eq!(create, fresh);
                Err(KeyFailure::Cancelled)
            });
            assert_eq!(setup_signer_element(&config, &dir, "unused", None, &config.data).err().as_deref(), Some(KeyFailure::Cancelled.message()));
        }
        std::fs::remove_dir_all(&data).unwrap();
    }

    fn setup_recovery_locally(data: &Path, pass: &str) -> String {
        let words = std::sync::Arc::new(std::sync::Mutex::new(None));
        let displayed = words.clone();
        let notice: crate::host::LocalNotice = std::sync::Arc::new(move |_, phrase| {
            *displayed.lock().unwrap() = Some(phrase.to_owned());
            true
        });
        super::super::recovery::confirm_recovery(data, pass, &notice).unwrap();
        super::super::recovery::seal_missing_backups(data, pass).unwrap();
        drop(notice);
        std::sync::Arc::try_unwrap(words).unwrap().into_inner().unwrap().unwrap()
    }

    /// A vault that became active before the member set up recovery still gets its recovery
    /// backup: right after local setup, and at the next unlock if it is missing.
    #[tokio::test(flavor = "multi_thread")]
    async fn recovery_backup_is_sealed_for_an_already_active_vault_at_setup_and_unlock() {
        use crate::signer::recovery::RecoveryKey;
        let data = std::env::temp_dir().join(format!("loki-recovery-late-{}", Uuid::new_v4()));
        let vault = [7u8; 32];
        let vault_hex = hex::encode(vault);
        let pass = "late pass";
        crate::profile::create(&data, pass, "Late").unwrap();
        let (material, _, _) = dealer_vault(&data, vault, pass);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = crate::host::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
        ]).unwrap();
        let token = config.token.clone();
        let st: Shared = std::sync::Arc::new(AppState::new(config));
        tokio::spawn(async move { axum::serve(listener, crate::host::routes::router(st)).await });
        let client = reqwest::Client::new();
        let call = |method: reqwest::Method, path: &str, body: Value| {
            client.request(method, format!("{base}{path}")).header("x-loki-token", &token).json(&body).send()
        };
        let status = || async {
            call(reqwest::Method::GET, &format!("/api/recovery-status?vault={vault_hex}"), json!({}))
                .await.unwrap().json::<Value>().await.unwrap()
        };
        let backup = signer_dir(&data, &vault_hex).unwrap().join("recovery.backup");

        assert!(call(reqwest::Method::POST, "/api/unlock", json!({"passphrase": pass})).await.unwrap().status().is_success());
        assert_eq!(status().await, json!({"recovery_identity": false, "recovery_backup": false}));
        let words = setup_recovery_locally(&data, pass);
        assert_eq!(status().await, json!({"recovery_identity": true, "recovery_backup": true}));
        let key = RecoveryKey::from_words(&words).unwrap();
        let opened = crate::signer::backup::verify_recovery(&BackupArtifact(std::fs::read(&backup).unwrap()), &key, &vault).unwrap();
        assert_eq!(opened.member_id, 1);

        // Sealing it deleted the passphrase-only copy of the share.
        assert!(!signer_dir(&data, &vault_hex).unwrap().join("backup.sealed").exists());

        // Recovery set up while the backup could not be sealed: the next unlock seals it.
        std::fs::remove_file(&backup).unwrap();
        MemberDir::open(&signer_dir(&data, &vault_hex).unwrap(), "")
            .write_sealed("backup.sealed", &crate::signer::backup::create(&material, pass).unwrap().0, pass)
            .unwrap();
        assert_eq!(status().await["recovery_backup"], false);
        call(reqwest::Method::POST, "/api/lock", json!({})).await.unwrap();
        assert!(call(reqwest::Method::POST, "/api/unlock", json!({"passphrase": pass})).await.unwrap().status().is_success());
        assert_eq!(status().await, json!({"recovery_identity": true, "recovery_backup": true}));
        crate::signer::backup::verify_recovery(&BackupArtifact(std::fs::read(&backup).unwrap()), &key, &vault).unwrap();
        std::fs::remove_dir_all(data).unwrap();
    }

    /// A host serving `data` on a loopback port: its base URL and API token.
    async fn spawn_host(data: &Path) -> (String, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = crate::host::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
        ]).unwrap();
        let token = config.token.clone();
        let st: Shared = std::sync::Arc::new(AppState::new(config));
        tokio::spawn(async move { axum::serve(listener, crate::host::routes::router(st)).await });
        (base, token)
    }

    /// Restore-on-new-device drill: the old device exports its recovery backup, a CLEAN data dir
    /// restores it locally, the payment path opens its signer (`custody::open_signer`), and it
    /// signs through the store's nonce dir at the restored epoch. A nonce the old device
    /// committed before the restore, and a package carrying that old commitment, are both
    /// refused afterwards.
    #[tokio::test(flavor = "multi_thread")]
    async fn local_restore_on_new_device_signs_and_refuses_pre_restore_nonce() {
        use crate::signer::nonce::NonceStore;
        use crate::signer::secure_element::SoftwareSecureElement;
        let root = std::env::temp_dir().join(format!("loki-restore-drill-{}", Uuid::new_v4()));
        let (old, new) = (root.join("old"), root.join("new"));
        let vault = [5u8; 32];
        let vault_hex = hex::encode(vault);
        let pass = "drill pass";
        let client = reqwest::Client::new();
        let call = |base: &str, token: &str, method: reqwest::Method, path: &str, body: Value| {
            client.request(method, format!("{base}{path}")).header("x-loki-token", token).json(&body).send()
        };

        // Old device: an active vault, recovery set up, backup exported over the route.
        crate::profile::create(&old, pass, "Old").unwrap();
        let (_material, shares, public) = dealer_vault(&old, vault, pass);
        let words = setup_recovery_locally(&old, pass);
        let (old_base, old_token) = spawn_host(&old).await;
        assert!(call(&old_base, &old_token, reqwest::Method::POST, "/api/unlock", json!({"passphrase": pass})).await.unwrap().status().is_success());
        let backup = call(&old_base, &old_token, reqwest::Method::GET, &format!("/api/recovery-backup?vault={vault_hex}"), json!({}))
            .await.unwrap().json::<Value>().await.unwrap()["backup"].as_str().unwrap().to_owned();

        // Before the restore the old device commits a nonce for an attempt (epoch 0, its own
        // element, id = payment || attempt).
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let id2 = frost::Identifier::try_from(2u16).unwrap();
        let old_key = frost::keys::KeyPackage::try_from(shares[&id1].clone()).unwrap();
        let peer = frost::keys::KeyPackage::try_from(shares[&id2].clone()).unwrap();
        let stale_id = hex::encode([[3u8; 32], [3u8; 32]].concat());
        let old_nonces = signer_dir(&old, &vault_hex).unwrap().join("nonces");
        let old_commitment = NonceStore::open(&old_nonces, vault, 1).unwrap()
            .commit(&stale_id, &SoftwareSecureElement::generate(), old_key.signing_share(), None).unwrap();

        // New device: a clean data dir restores the backup pinned on the old signer.
        crate::profile::create(&new, pass, "New").unwrap();
        let config = crate::host::config_from_args(&[
            "--data".into(), new.to_str().unwrap().into(), "--port".into(), "3601".into(),
        ]).unwrap();
        let backup = BackupArtifact(hex::decode(&backup).unwrap());
        restore_vault_from_backup(&new, &vault_hex, &words, Some(&backup.0), Some(&backup.fingerprint()), pass, &config).unwrap();
        let (new_base, new_token) = spawn_host(&new).await;
        assert!(call(&new_base, &new_token, reqwest::Method::POST, "/api/unlock", json!({"passphrase": pass})).await.unwrap().status().is_success());
        let status = call(&new_base, &new_token, reqwest::Method::GET, &format!("/api/recovery-status?vault={vault_hex}"), json!({}))
            .await.unwrap().json::<Value>().await.unwrap();
        assert_eq!(status, json!({"recovery_identity": true, "recovery_backup": true}));

        // The restored member signs: the payment path opens its signer from the store (a
        // restored store opens through `LocalSigner::from_restored`), the store's nonce dir at
        // the restored share epoch emits a share, and the share aggregates with member 2's into
        // a signature under the group key.
        let sdir = signer_dir(&new, &vault_hex).unwrap();
        let new_nonces = sdir.join("nonces");
        assert!(!new_nonces.exists(), "a clean device starts with no nonces");
        let st = AppState::new(config);
        let signer = crate::host::custody::open_signer(&st, &new, pass, &vault_hex, 1, Box::new(|_| false))
            .expect("the restored member opens for signing");
        let (group, _) = signer.hosted_metadata().unwrap();
        assert_eq!(group.verifying_key(), public.verifying_key());
        let se = st.config.open_secure_element(&sdir, pass).unwrap();
        let (epoch, raw) = crate::signer::store::SignerStore::open(&sdir).unwrap()
            .read(&se, crate::signer::store::FileKind::Share).unwrap().expect("the restored store holds the share");
        assert!(epoch > 0, "a restore bumps the share epoch");
        let key = frost::keys::KeyPackage::deserialize(&crate::signer::local::decode_share(&raw).unwrap().0).unwrap();
        let store = NonceStore::open_at_epoch(&new_nonces, epoch, vault, 1).unwrap();
        let fresh_id = hex::encode([[4u8; 32], [4u8; 32]].concat());
        let c1 = store.commit(&fresh_id, &se, key.signing_share(), None).unwrap();
        let (n2, c2) = frost::round1::commit(peer.signing_share(), &mut OsRng);
        let package_with = |own| {
            let commitments = BTreeMap::from([(id1, own), (id2, c2)]);
            let package = frost::SigningPackage::new(commitments.clone(), &[6u8; 32]);
            let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(public.verifying_key(), &commitments, OsRng).unwrap();
            (package, params, <[u8; 32]>::try_from(seed).unwrap())
        };
        let (package, params, seed) = package_with(c1);
        let own = store.sign_and_burn(&fresh_id, &se, &package, &key, &seed, None, &|| false).unwrap();
        let theirs = frost_rerandomized::sign_with_randomizer_seed(&package, &n2, &peer, &seed).unwrap();
        let signature = frost_rerandomized::aggregate(&package, &BTreeMap::from([(id1, own), (id2, theirs)]), &group, &params)
            .expect("the restored member's share aggregates");
        params.randomized_verifying_key().verify(&[6u8; 32], &signature).unwrap();

        // The old device's nonce file, replayed into the new device, never signs and is never
        // replaced by a fresh nonce for that id.
        std::fs::copy(old_nonces.join(format!("{stale_id}.nonce")), new_nonces.join(format!("{stale_id}.nonce"))).unwrap();
        let (package, _, seed) = package_with(old_commitment);
        assert!(store.sign_and_burn(&stale_id, &se, &package, &key, &seed, None, &|| false).is_err());
        assert!(store.commit(&stale_id, &se, key.signing_share(), None).is_err());
        assert!(!new_nonces.join(format!("{stale_id}.burn")).exists(), "no share was released");
        // A package carrying the pre-restore commitment is refused against the new nonce.
        let retry_id = hex::encode([[3u8; 32], [8u8; 32]].concat());
        store.commit(&retry_id, &se, key.signing_share(), None).unwrap();
        assert!(store.sign_and_burn(&retry_id, &se, &package, &key, &seed, None, &|| false).is_err());
        assert!(!new_nonces.join(format!("{retry_id}.burn")).exists(), "no share was released");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn native_recovery_publishes_only_a_matching_profile_and_resumes_registration_without_words() {
        use crate::host::{native_recovery, registration, state::NATIVE_KEY_SCOPE, RegistrationConfig};
        use crate::signer::{backup, recovery::RecoveryKey};
        use axum::{routing::{get, post}, Json, Router};
        use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        use std::sync::atomic::AtomicBool;

        let root = std::env::temp_dir().join(format!("loki-native-restore-{}", Uuid::new_v4()));
        let data = root.join("restored");
        let pass = "native restore fixture passphrase";
        let vault = [9; 32];
        let vault_hex = hex::encode(vault);
        let (material, _, public) = dealer_vault(&root.join("old"), vault, pass);
        let (words, key) = RecoveryKey::generate().unwrap();
        let (other_words, other_key) = RecoveryKey::generate().unwrap();
        let exported = |m: &backup::BackupMaterial| json!({
            "vault": hex::encode(m.vault_id), "backup": hex::encode(backup::create_to_recovery(m, &key.public_bytes()).unwrap().0),
        });
        let file = root.join("recovery.json");
        let document = exported(&material);
        let fingerprint_of = |doc: &Value| backup::BackupArtifact(hex::decode(doc["backup"].as_str().unwrap()).unwrap()).fingerprint();
        let anchor = fingerprint_of(&document);
        let identity = Identity::from_secret_bytes(&material.identity).unwrap().public();
        let signing = hex::encode(identity.signing);
        let relay = hex::encode(identity.encryption);
        // Coordinator slot deliberately differs from the backup's FROST member id.
        let entry = json!({"slot": 11, "signing_pubkey": signing, "relay_pubkey": relay, "advertise_url": "http://127.0.0.1:10000"});
        let mut wrong_relay = entry.clone();
        wrong_relay["relay_pubkey"] = json!(hex::encode([78; 32]));
        let roster = Arc::new(Mutex::new(vec![wrong_relay.clone()]));
        let roster_reads = Arc::new(AtomicUsize::new(0));
        let enrollment = Arc::new(Mutex::new(Vec::new()));
        let (r, reads, received) = (roster.clone(), roster_reads.clone(), enrollment.clone());
        let app = Router::new()
            .route("/api/members", get(move || {
                reads.fetch_add(1, Ordering::SeqCst);
                let result = json!({"slots": *r.lock().unwrap()});
                async move { Json(result) }
            }).post(|Json(body): Json<Value>| async move {
                Json(json!({"member": {"slot": body["slot"], "signing_pubkey": body["signing_pubkey"],
                    "relay_pubkey": body["relay_pubkey"], "advertise_url": body["advertise_url"],
                    "lokisigner_url": body["lokisigner_url"]}}))
            }))
            .route("/api/members/challenge", post(move |Json(body): Json<Value>| {
                let slot = body["slot"].as_u64();
                received.lock().unwrap().push(body);
                async move {
                    use axum::http::StatusCode;
                    if slot != Some(14) {
                        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "registered identity cannot change slot"}))));
                    }
                    Ok(Json(json!({"challenge": "ab".repeat(32), "relay_challenge_pubkey": registration::TEST_RELAY_CHALLENGE_KEY})))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        let config = || {
            let mut config = crate::host::native_config_from_args(&[
                "--data".into(), data.to_str().unwrap().into(), "--port".into(), "10001".into(), "--development-http".into(),
            ]).unwrap();
            config.secure_element = "software".into();
            config
        };

        let mut settings = config();
        let mut wrong_vault = document.clone();
        wrong_vault["vault"] = json!(hex::encode([8; 32]));
        let refused = "restore-refused";
        let bad_file = "invalid-backup";
        let mismatch = "roster-mismatch";
        let secret = |words: &str| Zeroizing::new(words.as_bytes().to_vec());
        let restore_new = |settings: &mut Config, words: &str, origin: &str| {
            native_recovery::restore_new(settings, pass, secret(words), &file, &anchor, origin, None)
        };
        tokio::task::block_in_place(|| {
            // A legitimate but different export of the very same material must not match.
            std::fs::write(&file, exported(&material).to_string()).unwrap();
            assert_eq!(restore_new(&mut settings, &words, &origin), Err("backup-fingerprint-mismatch"));
            assert!(!data.exists());
            for (contents, input, expected) in [
                (document.to_string(), other_words.as_str(), refused),
                (wrong_vault.to_string(), words.as_str(), refused),
                (format!("{}!", document), words.as_str(), bad_file),
                (format!("{document}{}", " ".repeat(256 * 1024)), words.as_str(), bad_file),
                (format!(r#"{{"vault":"{vault_hex}","vault":"{vault_hex}","backup":{}}}"#, document["backup"]), words.as_str(), bad_file),
            ] {
                std::fs::write(&file, contents).unwrap();
                assert_eq!(restore_new(&mut settings, input, &origin), Err(expected));
                assert!(!data.exists());
            }
            assert_eq!(roster_reads.load(Ordering::SeqCst), 0, "invalid backups never reach the roster lookup");
            std::fs::write(&file, document.to_string()).unwrap();
            assert_eq!(restore_new(&mut settings, &words, &format!("{origin}/wallet")),
                Err("roster-unavailable"));
            assert_eq!(restore_new(&mut settings, &words, &origin), Err(mismatch));
            assert!(!data.exists());
            *roster.lock().unwrap() = vec![entry.clone(), entry.clone()];
            assert_eq!(restore_new(&mut settings, &words, &origin), Err("roster-unavailable"));
            assert!(!data.exists());
            *roster.lock().unwrap() = vec![entry];
            settings.secure_element = "invalid fixture backend".into();
            assert_eq!(restore_new(&mut settings, &words, &origin), Err(refused));
            assert!(!data.exists(), "even a failure during installation must not publish the profile");
            settings.secure_element = "software".into();
            crate::profile::create(&data, pass, "Mistaken new member").unwrap();
            assert!(restore_new(&mut settings, &words, &origin).is_err());
            native_recovery::set_aside(&data, false).unwrap();
            std::fs::create_dir_all(data.join("signer")).unwrap();
            std::fs::write(data.join("signer/share.sealed"), b"unrecognised data").unwrap();
            assert_eq!(restore_new(&mut settings, &words, &origin),
                Err("profile-not-fresh"));
            assert_eq!(std::fs::read(data.join("signer/share.sealed")).unwrap(), b"unrecognised data");
            std::fs::remove_dir_all(data.join("signer")).unwrap();
            std::fs::create_dir_all(data.join("profile")).unwrap();
            std::fs::write(data.join(NATIVE_KEY_SCOPE), b"interrupted write").unwrap();
            restore_new(&mut settings, &words, &origin).unwrap();
            let archives: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().path())
                .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("restored-set-aside-")).collect();
            assert_eq!(archives.len(), 2);
            assert!(archives.iter().any(|p| crate::profile::open(p, pass).is_ok()));
            assert!(archives.iter().any(|p| std::fs::read(p.join(NATIVE_KEY_SCOPE)).ok().as_deref() == Some(b"interrupted write")));
        });
        let old_pub = std::fs::read(data.join("recovery.pub")).unwrap();
        assert_eq!(old_pub, [key.public_bytes(), key.signing_public()].concat());
        assert!(crate::host::state::read_native_key_scope(&data).unwrap().is_some());
        assert_eq!(settings.registration.as_ref().unwrap().slot, Some(11));
        let state = Arc::new(AppState::new(settings));
        let notice: crate::host::LocalNotice = Arc::new(|_, _| panic!("restored profile must never mint new words"));
        let unlock = || Some(Zeroizing::new(pass.into()));
        assert!(data.join(registration::RESTORE_PENDING).exists());
        assert!(crate::profile::exists(&data));
        assert!(state.registration.read().await.is_none());

        let s = state.clone();
        tokio::task::block_in_place(|| {
            let restore_running = |fingerprint: &str| native_recovery::restore_running(&s, secret(&words), &file, fingerprint);
            assert_eq!(restore_running(&anchor), Err("profile-locked"));
            *s.session.blocking_write() = Some(crate::host::state::Session::unlock(data.clone(), Zeroizing::new(pass.into())).unwrap().0);
            assert_eq!(restore_running(""), Err("backup-fingerprint-mismatch"));
            assert_eq!(restore_running(&anchor), Err("vault-exists"));
            let signer = crate::host::custody::open_signer(&s, &data, pass, &vault_hex, 1, Box::new(|_| false)).unwrap();
            assert_eq!(signer.hosted_metadata().unwrap().0.verifying_key(), public.verifying_key());

            // Same words with another member's valid backup must not install into a running profile.
            let (other_member, _, _) = dealer_vault(&root.join("other"), [7; 32], pass);
            let other_export = exported(&other_member);
            let other_anchor = fingerprint_of(&other_export);
            std::fs::write(&file, other_export.to_string()).unwrap();
            let wrong_profile = "wrong-profile";
            assert_eq!(restore_running(&other_anchor), Err(wrong_profile));
            assert!(!dir(&data, &hex::encode([7; 32])).unwrap().path().exists());

            // Another vault for the same member: change the vault-bound roster and fingerprint.
            let mut another_vault = material;
            another_vault.vault_id = [6; 32];
            let another_hex = hex::encode(another_vault.vault_id);
            let mut vault_roster: Value = serde_json::from_slice(&another_vault.roster).unwrap();
            vault_roster["vault"] = json!(another_hex);
            another_vault.roster = serde_json::to_vec(&vault_roster).unwrap();
            another_vault.roster_fingerprint = crate::member_state::Roster::from_bytes(&another_vault.roster).unwrap().fingerprint();
            let another_export = exported(&another_vault);
            let another_anchor = fingerprint_of(&another_export);
            std::fs::write(&file, another_export.to_string()).unwrap();
            let other_pub = [other_key.public_bytes(), other_key.signing_public()].concat();
            std::fs::write(data.join("recovery.pub"), &other_pub).unwrap();
            assert_eq!(restore_running(&another_anchor), Err(wrong_profile));
            assert_eq!(std::fs::read(data.join("recovery.pub")).unwrap(), other_pub);
            assert!(!dir(&data, &another_hex).unwrap().path().exists());
            std::fs::write(data.join("recovery.pub"), &old_pub).unwrap();
            restore_running(&another_anchor).unwrap();
            assert!(dir(&data, &another_hex).unwrap().exists("vault.sealed"));
        });

        // If the coordinator still gives the old slot, keep the restored app usable.
        assert_eq!(registration::start(&state, unlock(), Some(&notice)).await.unwrap(), "restore-pending");
        assert_eq!(state.registration_error.read().await.as_deref(), Some("Vault restored. LokiSigner could not reconnect to the coordinator yet; it will retry without your recovery words."));
        assert!(data.join(registration::RESTORE_PENDING).exists());

        // Restart from disk. Its saved coordinator/slot and local passphrase are enough.
        let mut resumed = config();
        resumed.registration = Some(RegistrationConfig::resume(&data, true).unwrap());
        let resumed = Arc::new(AppState::new(resumed));
        roster.lock().unwrap().iter_mut().filter(|m| m["relay_pubkey"] == relay).for_each(|m| m["slot"] = json!(14));
        assert_eq!(registration::start(&resumed, unlock(), Some(&notice)).await.unwrap(), "restore-ready");
        let registered = resumed.registration.read().await.clone().unwrap();
        assert_eq!(registered.slot, 14);
        assert_eq!(RegistrationConfig::resume(&data, true).unwrap().slot, Some(14));
        assert_eq!(registered.signing_pubkey, signing);
        assert_eq!(registered.relay_pubkey, relay);
        assert!(!data.join(registration::RESTORE_PENDING).exists());

        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        {
            use crate::signer::secure_element_apple::KeyFailure;
            let root = root.canonicalize().unwrap();
            let mut apple = config();
            apple.data = root.join("apple-restored");
            apple.secure_element = "apple".into();
            let tags = Arc::new(Mutex::new(Vec::new()));
            let accesses = tags.clone();
            let block_device = Arc::new(AtomicBool::new(true));
            let blocked = block_device.clone();
            let _keychain = crate::host::state::apple_test::install(&root, move |path, tag, create| {
                let device = path.ends_with("device-auth");
                accesses.lock().unwrap().push((device, create, tag.to_vec()));
                if device && blocked.load(Ordering::SeqCst) { Err(KeyFailure::Cancelled) } else { Ok(()) }
            });
            std::fs::write(&file, document.to_string()).unwrap();
            tokio::task::block_in_place(|| {
                assert_eq!(restore_new(&mut apple, &words, &origin),
                    Err(KeyFailure::Cancelled.message()));
                assert!(!apple.data.exists());
                block_device.store(false, Ordering::SeqCst);
                restore_new(&mut apple, &words, &origin).unwrap();
            });
            assert!(!apple.data.join("device-registration-confirmed").exists());
            assert!(registration::DeviceKey::open(&apple, pass).is_ok());
            let restored = apple.data.clone();
            let moved = restored.with_extension("moved");
            std::fs::rename(&restored, &moved).unwrap();
            apple.data = moved.clone();
            assert!(registration::DeviceKey::open(&apple, pass).is_ok());
            crate::host::custody::open_signer(&AppState::new(apple), &moved, pass, &vault_hex, 1, Box::new(|_| false)).unwrap();
            let actual = tags.lock().unwrap();
            let restored = std::fs::read_to_string(moved.join("vaults").join(&vault_hex).join("signer/native-restored-key")).unwrap();
            let vault = format!("cash.loki.member.kek.restore.v1:{restored}:signer").into_bytes();
            let device = format!("cash.loki.member.kek.restore.v1:{restored}:device-auth").into_bytes();
            assert_ne!(actual[0].2, vault, "a failed restore does not reuse its Keychain tags");
            assert_ne!(actual[1].2, device);
            assert_eq!(actual[2..], [
                (false, true, vault.clone()), (true, true, device.clone()), (false, false, vault.clone()),
                (true, false, device.clone()), (true, false, device), (false, false, vault),
            ]);
        }
        let sent = enrollment.lock().unwrap();
        assert_eq!(sent.iter().map(|request| request["slot"].as_u64().unwrap()).collect::<Vec<_>>(), [11, 11, 14]);
        for request in sent.iter() {
            assert_eq!(request.as_object().unwrap().keys().collect::<Vec<_>>(), ["advertise_url", "authorization", "device_pubkey", "lokisigner_url", "relay_pubkey", "signing_pubkey", "slot"]);
            assert_eq!(request["lokisigner_url"], "http://127.0.0.1:10001");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn native_http_never_extracts_recovery_words_and_keeps_the_ciphertext_routes() {
        use std::sync::Arc;

        const ORIGIN: &str = "https://wallet.example";
        let data = std::env::temp_dir().join(format!("loki-native-routes-{}", Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let mut state = AppState::new(crate::host::native_config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "0".into(),
            "--coordinator-url".into(), ORIGIN.into(), "--local-passphrase-file".into(), "unused".into(),
        ]).unwrap());
        state.wallet_tabs = Some(super::super::connect::WalletTabs::new(base.clone(), ORIGIN.into(), Arc::new(|_, _, _| true)));
        let member = super::super::registration::PublicMember {
            slot: 7, signing_pubkey: "01".repeat(32), relay_pubkey: "02".repeat(32),
            advertise_url: base.clone(), lokisigner_url: Some(base.clone()),
        };
        let body = json!({"slot": member.slot, "signing_pubkey": member.signing_pubkey, "relay_pubkey": member.relay_pubkey});
        *state.registration.write().await = Some(member);
        *state.session.write().await = Some(Session { data: data.clone(), passphrase: Zeroizing::new("test".into()) });
        let vault = hex::encode([61; 32]);
        let signer_dir = signer_dir(&data, &vault).unwrap();
        std::fs::create_dir_all(&signer_dir).unwrap();
        std::fs::write(crate::host::recovery::backup_file(&signer_dir), [8; 16]).unwrap();
        let router = crate::host::routes::router(Arc::new(state)).into_make_service_with_connect_info::<std::net::SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, router).await });
        let client = reqwest::Client::new();
        let grant = client.post(format!("{base}/api/connect")).header("origin", ORIGIN).json(&body)
            .send().await.unwrap().error_for_status().unwrap().text().await.unwrap();
        let frame: Value = serde_json::from_str(grant.lines().last().unwrap()).unwrap();
        let token = frame["token"].as_str().unwrap();
        for (path, body) in [
            ("recovery-setup", "{}"),
            ("recovery-restore", r#"{"vault":"ignored","words":"UNIQUE-RECOVERY-SECRET"}"#),
            ("recovery-restore", r#"{"words":"UNIQUE-RECOVERY-SECRET"!}"#),
        ] {
            let response = client.post(format!("{base}/api/{path}")).header("origin", ORIGIN).header("x-loki-token", token)
                .header("content-type", "application/json").body(body).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
            assert_eq!(response.json::<Value>().await.unwrap(), json!({"error": "Manage recovery words and restore vaults in LokiSigner."}));
        }
        for (path, expected) in [
            ("recovery-status", json!({"recovery_identity": false, "recovery_backup": true, "recovery_in_app": true})),
            ("recovery-backup", json!({"vault": vault, "backup": "08".repeat(16)})),
        ] {
            assert_eq!(client.get(format!("{base}/api/{path}?vault={vault}")).header("origin", ORIGIN).header("x-loki-token", token)
                .send().await.unwrap().json::<Value>().await.unwrap(), expected);
        }
        assert!(!data.join("recovery.pub").exists());
        std::fs::remove_dir_all(data).unwrap();
    }

}

// ---- self-custody helpers ported from the speedmaster host (device pairing + recovery restore) ----
pub(super) fn signer_dir(data: &Path, vault: &str) -> Result<PathBuf, String> {
    Ok(dir(data, vault)?.path().join("signer"))
}

/// Build the passphrase-sealed `vault.sealed` payload that `payment::load_vault` reads. DKG
/// completion and recovery restore both write it through here. It holds public vault metadata
/// only: the share and the vault secret stay in the signer store under the configured secure
/// element (`super::custody`), and the viewing key is never written here.
#[allow(clippy::too_many_arguments)]
pub(super) fn vault_sealed_bytes(
    vault: &str,
    slot: u16,
    threshold: u16,
    members: u16,
    roster_fingerprint: &str,
    public: &frost::keys::PublicKeyPackage,
    fvk: &orchard::keys::FullViewingKey,
    birth_height: u32,
    network: VaultNetwork,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "group key length")?;
    let group_address = vault::unified_address(fvk, network.network_type());
    let sealed = json!({
        "vault": vault, "threshold": threshold, "members": members,
        "roster_fingerprint": roster_fingerprint,
        "public_package": hex::encode(public.serialize().map_err(|e| e.to_string())?),
        "my_frost_id": slot, "group_address": group_address,
        "group_ak": hex::encode(ak),
        "birth_height": birth_height, "key_derivation": zip2005::VERSION,
        "network": network.label(),
    });
    serde_json::to_vec(&sealed).map(Zeroizing::new).map_err(|e| e.to_string())
}

/// Recovery restore: rebuild this member's vault from a recovery backup opened with the
/// member's 24 words, so the payment path can re-open the vault and sign exactly as after the
/// original ceremony. `backup` is the exported blob (`GET /api/recovery-backup`) a member
/// brings to a new device; without it the blob stored beside the signer is used.
pub(super) fn restore_vault_from_backup(
    data: &Path,
    vault: &str,
    words: &str,
    backup: Option<&[u8]>,
    fingerprint: Option<&str>,
    pass: &str,
    config: &super::Config,
) -> Result<(), String> {
    let key = crate::signer::recovery::RecoveryKey::from_words(words)?;
    let dir = dir(data, vault)?;
    let local = super::recovery::backup_file(&dir.path().join("signer"));
    let blob = match backup {
        Some(blob) => blob.to_vec(),
        None => std::fs::read(&local)
            .map_err(|_| "no recovery backup for this vault; supply the exported backup".to_string())?,
    };
    let artifact = BackupArtifact(blob);
    if let Some(fingerprint) = fingerprint {
        artifact.check_fingerprint(fingerprint)?;
    } else if !dir.exists("vault.sealed") {
        return Err("a fresh restore needs the independently saved SHA-256 fingerprint of the backup".into());
    }
    restore_opened_backup(RecoveryBackup::open(vault, key, artifact.0)?, data, &dir, pass, config, None)
}

pub(super) struct RecoveryBackup {
    pub(super) material: crate::signer::backup::BackupMaterial,
    pub(super) key: crate::signer::recovery::RecoveryKey,
    blob: Vec<u8>,
    vault: String,
}

impl RecoveryBackup {
    pub(super) fn open(vault: &str, key: crate::signer::recovery::RecoveryKey, blob: Vec<u8>) -> Result<Self, String> {
        let artifact = BackupArtifact(blob);
        let vault_id = vault_bytes(vault)?;
        let material = crate::signer::backup::verify_recovery(&artifact, &key, &vault_id)?;
        Ok(Self { material, key, blob: artifact.0, vault: hex::encode(vault_id) })
    }
}

pub(super) fn restore_opened_backup(backup: RecoveryBackup, data: &Path, dest: &MemberDir, pass: &str, config: &super::Config, published_key_dir: Option<&Path>) -> Result<(), String> {
    let RecoveryBackup { material, key, blob, vault } = backup;
    let vault = vault.as_str();
    let vault_id = material.vault_id;
    let sdir = dest.path().join("signer");
    let local = super::recovery::backup_file(&sdir);
    let pp = frost::keys::PublicKeyPackage::deserialize(&material.public_package)
        .map_err(|e| e.to_string())?;
    // Signing needs every member's relay identity, which only the backup's roster carries.
    // `verify_recovery` already bound that roster to this vault and to the backup's identity.
    if material.roster.is_empty() || material.identity.is_empty() {
        return Err("this backup has no roster, so it cannot rebuild a member that signs".into());
    }
    let roster = crate::member_state::Roster::from_bytes(&material.roster)?;
    let network = match material.network {
        Network::Regtest => VaultNetwork::Regtest,
        Network::Testnet => VaultNetwork::Testnet,
    };
    if network.label() != config.network {
        return Err("recovery backup is for a different network".into());
    }
    // The profile's identity serves every vault it holds, so restore never replaces one.
    let root = MemberDir::open(data, ".");
    let write_identity = match root.read_sealed("identity.sealed", pass) {
        Ok(existing) => {
            let existing = Zeroizing::new(existing);
            if existing.len() != material.identity.len() || existing[2..] != material.identity[2..] {
                return Err("this profile already has a different member identity; restore into a \
                    profile created without --coordinator-url that holds no other vaults".into());
            }
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => return Err(e.to_string()),
    };
    // The words that open this backup become the profile's recovery identity, so a later start
    // or recovery setup never mints a second, unrelated set the backup is not sealed to.
    let write_recovery = super::recovery::check_recovery(data, &key)?;
    if dest.exists("vault.sealed") {
        // Repair only the export of an already restored headless vault; never touch its
        // live share or epoch. The unlocked device store is the independent trust anchor.
        if published_key_dir.is_some() || write_identity || write_recovery
            || std::fs::read(&local).is_ok_and(|prior| prior == blob) {
            return Err("vault already exists; restore into a fresh device profile".into());
        }
        let installed = load(data, pass, vault)?;
        let installed_roster = roster_of(&installed)?;
        if installed.birth_height != material.birth_height || installed_roster.threshold != roster.threshold
            || !installed_roster.members.values().eq(roster.members.values()) {
            return Err("recovery backup does not match this vault's installed roster".into());
        }
        let store = crate::signer::store::SignerStore::open(&sdir)?;
        let se = config.open_secure_element(&sdir, pass)?;
        let expected = crate::signer::local::encode_share(&material.key_package, &material.public_package, &material.group_sk);
        if store.vault() != vault_id || store.member() != material.member_id || store.network() != material.network
            || !store.read(&se, crate::signer::store::FileKind::Share)?
                .is_some_and(|(_, share)| share.as_slice() == expected.as_slice()) {
            return Err("recovery backup does not match this vault's installed share".into());
        }
        return super::recovery::install_backup(&sdir, &blob);
    }
    let mut ceremony = Ceremony {
        vault: vault.to_owned(),
        name: material.label.clone(),
        members: material.members,
        threshold: material.threshold,
        my_slot: material.member_id,
        creator_base_url: String::new(),
        frostd_url: config.frostd_url.clone(),
        slots: roster.members.values().map(|m| (m.id, Slot {
            identity: Some(WireIdentity::from_public(m.clone())),
            pending_token: None,
        })).collect(),
        fingerprint: None,
        agreed: roster.members.keys().copied().collect(),
        session_id: None,
        coordinator_peer: None,
        vs_session_id: None,
        dkg_started: true,
        error: None,
        birth_height: material.birth_height,
        roster_code: None,
        creator: None,
    };
    // The ceremony records the relay roster's fingerprint, not the setup document's.
    let fingerprint = hex::encode(roster_of(&ceremony)?.fingerprint());
    ceremony.fingerprint = Some(fingerprint.clone());
    let ak: [u8; 32] = pp.verifying_key().serialize().map_err(|e| e.to_string())?
        .try_into().map_err(|_| "group key length")?;
    let fvk = zip2005::frost_viewing_key(&ak, &material.group_sk)
        .map_err(|e| format!("group viewing key: {e:?}"))?;
    let bytes = vault_sealed_bytes(
        vault, material.member_id, material.threshold, material.members, &fingerprint,
        &pp, &fvk,
        // Regtest vaults are born at height 2 (`setup_birth_height`); Testnet backups carry theirs.
        material.birth_height.unwrap_or(2), network,
    )?;
    let (se, existing) = setup_signer_element(config, &sdir, pass, published_key_dir, data)?;
    let store = if existing {
        crate::signer::store::SignerStore::open(&sdir)?
    } else {
        crate::signer::store::SignerStore::create(&sdir, material.network, vault_id, material.member_id)?
    };
    if store.vault() != vault_id || store.member() != material.member_id || store.network() != material.network {
        return Err("recovery backup belongs to another signer".into());
    }
    let previous_epoch = store.read(&se, crate::signer::store::FileKind::Share)?
        .map(|(epoch, _)| epoch).unwrap_or(0);
    let epoch = material.backup_epoch.max(previous_epoch).checked_add(1).ok_or("backup epoch overflow")?;
    store.write(&se, crate::signer::store::FileKind::Share, epoch,
        &crate::signer::local::encode_share(&material.key_package, &material.public_package, &material.group_sk))?;
    if write_identity {
        root.write_sealed("identity.sealed", &material.identity, pass)
            .map_err(|e| e.to_string())?;
    }
    if write_recovery {
        super::recovery::adopt_recovery(data, &key, pass)?;
    }
    // Keep the backup on the new device so it can be exported again.
    super::recovery::install_backup(&sdir, &blob)?;
    save_to(dest, pass, &ceremony)?;
    // Written last: `vault.sealed` is what marks the vault active.
    dest.write_sealed("vault.sealed", &bytes, pass)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Re-derive a vault's FROST roster from stored ceremony state, verifying it still matches the
/// recorded fingerprint. Used by the repair flow to rebuild roster-dependent artifacts.
pub(super) fn repair_roster(data: &Path, pass: &str, vault: &str) -> Result<FrostRoster, String> {
    let c = load(data, pass, vault)?;
    let roster = roster_of(&c)?;
    if c.fingerprint.as_deref() != Some(hex::encode(roster.fingerprint()).as_str()) {
        return Err("stored roster fingerprint mismatch".into());
    }
    Ok(roster)
}
