use crate::{member_state, network::VaultNetwork, setup_transport::Identity, zip2005};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use loki_relay_client::CommIdentity;
use loki_relay_protocol::types::{roster_digest, MemberPublic, Roster};
use serde_json::Value;
use std::{
    fmt,
    fs::{self, File},
    io::Read,
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_SEALED: usize = 1024 * 1024;
const MAX_JSON: usize = 1024 * 1024;
const MAX_PASS: usize = 4096;
const MAX_DEPTH: usize = 16;
const SEAL_MAGIC: &[u8; 9] = b"LOKISEAL\x01";
const SEAL_HEADER: usize = 49;

pub struct LoadedMember {
    pub identity: CommIdentity,
    pub roster: Roster,
    pub threshold: u16,
    pub network: VaultNetwork,
}
pub type MemberResult<T> = Result<T, MemberError>;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MemberError {
    Io,
    Permissions,
    Bounds,
    Sealed,
    Json,
    Markers,
    Roster,
    Vault,
    Fingerprint,
    Identity,
    Unsupported,
}
impl MemberError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "member_io",
            Self::Permissions => "member_permissions",
            Self::Bounds => "member_bounds",
            Self::Sealed => "member_sealed",
            Self::Json => "member_json",
            Self::Markers => "member_markers",
            Self::Roster => "member_roster",
            Self::Vault => "member_vault",
            Self::Fingerprint => "member_fingerprint",
            Self::Identity => "member_identity",
            Self::Unsupported => "member_unsupported",
        }
    }
}
impl fmt::Display for MemberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl fmt::Debug for MemberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for MemberError {}

#[cfg(unix)]
fn private_metadata(metadata: &fs::Metadata) -> MemberResult<()> {
    use std::os::unix::fs::MetadataExt;
    extern "C" {
        fn geteuid() -> u32;
    }
    // geteuid has no arguments or failure condition; only the effective file owner is accepted.
    let uid = unsafe { geteuid() };
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(MemberError::Permissions);
    }
    Ok(())
}
#[cfg(not(unix))]
fn private_metadata(_: &fs::Metadata) -> MemberResult<()> {
    Err(MemberError::Unsupported)
}

fn member_root(path: &Path) -> MemberResult<()> {
    let m = fs::symlink_metadata(path).map_err(|_| MemberError::Io)?;
    if !m.is_dir() {
        return Err(MemberError::Permissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        extern "C" {
            fn geteuid() -> u32;
        }
        // Setup may use a public parent directory; its private secrets directory protects sealed files.
        let uid = unsafe { geteuid() };
        if m.uid() != uid || m.mode() & 0o022 != 0 {
            return Err(MemberError::Permissions);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(MemberError::Unsupported)
    }
}

fn private_directory(path: &Path) -> MemberResult<()> {
    let m = fs::symlink_metadata(path).map_err(|_| MemberError::Io)?;
    if !m.is_dir() {
        return Err(MemberError::Permissions);
    }
    private_metadata(&m)
}
fn bounded_read(path: &Path, limit: usize, private: bool) -> MemberResult<Zeroizing<Vec<u8>>> {
    let before = fs::symlink_metadata(path).map_err(|_| MemberError::Io)?;
    if !before.is_file() {
        return Err(MemberError::Permissions);
    }
    let file = File::open(path).map_err(|_| MemberError::Io)?;
    let after = file.metadata().map_err(|_| MemberError::Io)?;
    if !after.is_file() {
        return Err(MemberError::Permissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(MemberError::Permissions);
        }
    }
    if private {
        private_metadata(&after)?;
    }
    if after.len() > limit as u64 {
        return Err(MemberError::Bounds);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| MemberError::Io)?;
    if bytes.len() > limit {
        return Err(MemberError::Bounds);
    }
    Ok(bytes)
}
fn sealed(path: &Path, pass: &str) -> MemberResult<Zeroizing<Vec<u8>>> {
    // Decrypt the same LOKISEAL format from one bounded handle, avoiding read_sealed's unbounded reopen.
    let raw = bounded_read(path, MAX_SEALED, true)?;
    if raw.len() < SEAL_HEADER + 16 || &raw[..9] != SEAL_MAGIC {
        return Err(MemberError::Sealed);
    }
    let key = crate::seal_kdf::derive(pass, &raw[9..25]).map_err(|_| MemberError::Sealed)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| MemberError::Sealed)?;
    cipher
        .decrypt(
            XNonce::from_slice(&raw[25..49]),
            Payload {
                msg: &raw[49..],
                aad: &raw[..49],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| MemberError::Sealed)
}
struct SecretJson(Value);
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                Value::Object(o) => {
                    for (mut k, mut v) in std::mem::take(o) {
                        k.zeroize();
                        wipe(&mut v);
                    }
                }
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
fn json(bytes: &[u8]) -> MemberResult<SecretJson> {
    if bytes.len() > MAX_JSON {
        return Err(MemberError::Bounds);
    }
    let (mut depth, mut string, mut escape) = (0usize, false, false);
    for b in bytes {
        if string {
            if escape {
                escape = false;
            } else if *b == b'\\' {
                escape = true;
            } else if *b == b'"' {
                string = false;
            }
        } else {
            match b {
                b'"' => string = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(MemberError::Bounds);
                    }
                }
                b']' | b'}' => {
                    depth = depth.checked_sub(1).ok_or(MemberError::Json)?;
                }
                _ => {}
            }
        }
    }
    serde_json::from_slice(bytes)
        .map(SecretJson)
        .map_err(|_| MemberError::Json)
}
fn hex32(value: &Value) -> MemberResult<[u8; 32]> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value.as_str().ok_or(MemberError::Roster)?, &mut bytes)
        .map_err(|_| MemberError::Roster)?;
    Ok(bytes)
}
fn roster(value: &Value) -> MemberResult<Roster> {
    let vault = hex32(&value["vault"])?;
    let entries = value["members"].as_array().ok_or(MemberError::Roster)?;
    let threshold = value.get("threshold").map(Value::as_u64).unwrap_or(Some(2));
    let threshold = threshold
        .and_then(|t| u16::try_from(t).ok())
        .ok_or(MemberError::Roster)?;
    if !member_state::valid_policy(threshold, entries.len()) {
        return Err(MemberError::Roster);
    }
    let mut members = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = u16::try_from(entry["id"].as_u64().ok_or(MemberError::Roster)?)
            .map_err(|_| MemberError::Roster)?;
        let signing = hex32(&entry["signing"])?;
        let encryption = hex32(&entry["encryption"])?;
        ed25519_dalek::VerifyingKey::from_bytes(&signing).map_err(|_| MemberError::Roster)?;
        members.push(MemberPublic {
            id,
            signing,
            encryption,
        });
    }
    members.sort_by_key(|m| m.id);
    if members.iter().enumerate().any(|(index, member)| member.id != index as u16 + 1) {
        return Err(MemberError::Roster);
    }
    Ok(Roster { vault, members })
}
pub fn load(root: &Path, pass_file: &Path, roster_path: &Path) -> MemberResult<LoadedMember> {
    load_with_signing_identity(root, pass_file, roster_path).map(|(member, _)| member)
}

pub fn load_with_signing_identity(
    root: &Path,
    pass_file: &Path,
    roster_path: &Path,
) -> MemberResult<(LoadedMember, Identity)> {
    member_root(root)?;
    private_directory(&root.join("secrets"))?;
    let pass_bytes = bounded_read(pass_file, MAX_PASS, true)?;
    let mut pass = Zeroizing::new(
        std::str::from_utf8(&pass_bytes)
            .map_err(|_| MemberError::Json)?
            .to_owned(),
    );
    let pass_len = pass.trim_end_matches(['\r', '\n']).len();
    pass.truncate(pass_len);
    if pass.is_empty() {
        return Err(MemberError::Sealed);
    }
    crate::seal_kdf::enable_session_cache(&pass);
    let identity_bytes = sealed(&root.join("secrets/identity.sealed"), &pass)?;
    let mut identity_raw = Zeroizing::new([0u8; 66]);
    if identity_bytes.len() != identity_raw.len() {
        return Err(MemberError::Identity);
    }
    identity_raw.copy_from_slice(&identity_bytes);
    let state_bytes = sealed(&root.join("secrets/vault.sealed"), &pass)?;
    let state = json(&state_bytes)?;
    if state.0["version"].as_u64() != Some(2)
        || state.0["network"]
            .as_str()
            .is_none_or(|value| VaultNetwork::parse(value).is_err())
        || state.0["key_derivation"].as_str() != Some(zip2005::VERSION)
    {
        return Err(MemberError::Markers);
    }
    let mut embedded = Zeroizing::new([0u8; 66]);
    hex::decode_to_slice(
        state.0["identity_secret"]
            .as_str()
            .ok_or(MemberError::Identity)?,
        embedded.as_mut(),
    )
    .map_err(|_| MemberError::Identity)?;
    if *embedded != *identity_raw {
        return Err(MemberError::Identity);
    }
    let roster_bytes = bounded_read(roster_path, MAX_JSON, false)?;
    let parsed_roster = json(&roster_bytes)?;
    let roster = roster(&parsed_roster.0)?;
    let certified =
        member_state::Roster::from_bytes(&roster_bytes).map_err(|_| MemberError::Roster)?;
    if state.0["network"].as_str() != Some(certified.network.label())
        || state.0.get("birth_height").and_then(Value::as_u64)
            != certified.birth_height.map(u64::from)
        || !member_state::valid_policy(certified.threshold, certified.members.len())
        || certified.vault != roster.vault
        || certified.members.len() != roster.members.len()
        || roster.members.iter().any(|member| {
            certified.members.get(&member.id).is_none_or(|saved| {
                saved.signing != member.signing || saved.encryption != member.encryption
            })
        })
    {
        return Err(MemberError::Roster);
    }
    if hex32(&state.0["vault"])? != roster.vault {
        return Err(MemberError::Vault);
    }
    if hex32(&state.0["roster_fingerprint"])? != certified.fingerprint() {
        return Err(MemberError::Fingerprint);
    }
    if state.0.get("threshold").map(Value::as_u64).unwrap_or(Some(2)) != Some(u64::from(certified.threshold))
        || state.0.get("members").is_some_and(|value| value.as_u64() != Some(roster.members.len() as u64))
    {
        return Err(MemberError::Roster);
    }
    let identity =
        CommIdentity::from_serialized(&identity_raw).map_err(|_| MemberError::Identity)?;
    let signing_identity = Identity::from_secret_bytes(identity_raw.as_ref())
        .map_err(|_| MemberError::Identity)?;
    let legacy = signing_identity.public();
    let own = identity.public();
    if own.id != legacy.id
        || own.signing != legacy.signing
        || own.encryption != legacy.encryption
        || roster.members.iter().find(|m| m.id == own.id) != Some(&own)
    {
        return Err(MemberError::Identity);
    }
    roster_digest(&roster).map_err(|_| MemberError::Roster)?;
    Ok((LoadedMember { identity, roster, threshold: certified.threshold, network: certified.network }, signing_identity))
}

pub mod config;
pub mod exchange;
pub use config::{ConfigStore, LocalConfig, PendingRequest, ProvisionTarget};
pub use exchange::{CourierFile, CourierImport};

#[cfg(test)]
mod roster_tests {
    use super::*;

    fn document(threshold: u16, count: u16) -> Value {
        let members: Vec<Value> = (1..=count)
            .map(|id| {
                let public = Identity::new(id).public();
                serde_json::json!({
                    "id": id,
                    "signing": hex::encode(public.signing),
                    "encryption": hex::encode(public.encryption),
                })
            })
            .collect();
        serde_json::json!({"vault": hex::encode([7u8; 32]), "threshold": threshold, "members": members})
    }

    #[test]
    fn roster_accepts_every_general_policy_and_nothing_else() {
        for (threshold, count) in [(2, 3), (3, 4), (2, 5), (3, 5), (15, 16)] {
            let parsed = roster(&document(threshold, count)).unwrap();
            assert_eq!(parsed.members.len(), usize::from(count));
        }
        for (threshold, count) in [(1, 3), (3, 3), (5, 5), (2, 17)] {
            assert!(roster(&document(threshold, count)).is_err(), "{threshold}-of-{count}");
        }
    }
}
