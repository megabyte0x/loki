use super::{LoadedMember, MemberError, MemberResult};
use loki_relay_client::{
    accept_descriptor, open_descriptor, ClientConfig, ConfigReference, OwnerInbox, Secret32,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    http::{decode_append_update, decode_creation},
    types::{roster_digest, Id32, RelayPin, RelayRoute},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_CONFIG: usize = super::MAX_SEALED - super::SEAL_HEADER - 16;

pub enum PendingRequest {
    Create {
        relay: u16,
        request: Zeroizing<Vec<u8>>,
    },
    Rotate {
        relay: u16,
        append: Secret32,
        request: Zeroizing<Vec<u8>>,
    },
}
pub struct LocalConfig {
    pub provisioned: Option<Vec<u64>>,
    /// Verified append revisions for the active rotation generation. Zero means that generation is prepared and not yet verified.
    pub rotated: Option<Vec<u64>>,
    pub own: Vec<OwnerInbox>,
    pub self_wire: Option<Vec<u8>>,
    pub peer_wires: Vec<Vec<u8>>,
    pub pending: Vec<PendingRequest>,
    pub operation: Option<Id32>,
    pub predecessor: Option<ConfigReference>,
    pub couriers: Vec<super::CourierFile>,
}
struct SecretValue(Value);
impl Drop for SecretValue {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::Bytes(b) => b.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                _ => (),
            }
        }
        wipe(&mut self.0);
    }
}
fn error<T>(_: T) -> MemberError {
    MemberError::Sealed
}

pub(super) fn check_peer_destinations(member: &LoadedMember, descriptor: &loki_relay_client::AuthenticatedDescriptor) -> MemberResult<()> {
    let development = member.network == crate::network::VaultNetwork::Regtest;
    for relay in &descriptor.body().relays {
        loki_relay_client::validate_peer_destination(&relay.route.endpoint, development).map_err(error)?;
    }
    Ok(())
}

fn array(v: &Value, len: usize) -> MemberResult<&[Value]> {
    match v {
        Value::Array(a) if a.len() == len => Ok(a),
        _ => Err(MemberError::Sealed),
    }
}
fn list(v: &Value, max: usize) -> MemberResult<&[Value]> {
    match v {
        Value::Array(a) if a.len() <= max => Ok(a),
        _ => Err(MemberError::Bounds),
    }
}
fn bytes(v: &Value) -> MemberResult<&[u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(MemberError::Sealed),
    }
}
fn id(v: &Value) -> MemberResult<Id32> {
    bytes(v)?.try_into().map_err(error)
}
fn number(v: &Value) -> MemberResult<u64> {
    match v {
        Value::Integer(n) => u64::try_from(*n).map_err(error),
        _ => Err(MemberError::Sealed),
    }
}
fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}
fn blob(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}
fn counter(n: u64) -> MemberResult<()> {
    if n == 0 || n > i64::MAX as u64 {
        Err(MemberError::Bounds)
    } else {
        Ok(())
    }
}

impl LocalConfig {
    pub fn empty() -> Self {
        Self {
            provisioned: None,
            rotated: None,
            own: vec![],
            self_wire: None,
            peer_wires: vec![],
            pending: vec![],
            operation: None,
            predecessor: None,
            couriers: vec![],
        }
    }
    pub fn authenticated(&self, member: &LoadedMember) -> MemberResult<ClientConfig> {
        let digest = roster_digest(&member.roster).map_err(error)?;
        if !member.roster.members.contains(&member.identity.public()) {
            return Err(MemberError::Identity);
        }
        if self.own.len() != 0 && self.own.len() != 3 {
            return Err(MemberError::Bounds);
        }
        let pending_limit = if self.rotated.is_some() { 6 } else { 3 };
        if self.own.is_empty() != self.self_wire.is_none()
            || self.peer_wires.len() > member.roster.members.len() - 1
            || self.pending.len() > pending_limit
            || (self.pending.is_empty() != self.operation.is_none())
            || (self.rotated.is_some() && self.provisioned.is_none())
        {
            return Err(MemberError::Sealed);
        }
        if let Some(wire) = &self.self_wire {
            let auth = open_descriptor(&member.identity, &member.roster, wire).map_err(error)?;
            if auth.body().owner != member.identity.public().id
                || auth.body().vault != member.roster.vault
                || auth.body().roster != digest
            {
                return Err(MemberError::Identity);
            }
            for (inbox, relay) in self.own.iter().zip(&auth.body().relays) {
                if inbox.route != relay.route || inbox.append.as_bytes() != relay.append.as_bytes()
                {
                    return Err(MemberError::Identity);
                }
            }
        }
        if !self.couriers.is_empty()
            && self.couriers.len() != member.roster.members.len() - 1
        {
            return Err(MemberError::Bounds);
        }
        if !self.couriers.is_empty() {
            let own = open_descriptor(
                &member.identity,
                &member.roster,
                self.self_wire.as_ref().ok_or(MemberError::Identity)?,
            )
            .map_err(error)?;
            let mut peers = Vec::new();
            for courier in &self.couriers {
                if peers.contains(&courier.peer()) || courier.digest() != own.digest() {
                    return Err(MemberError::Identity);
                }
                super::CourierFile::restore(member, &own, courier.peer(), courier.wire())?;
                peers.push(courier.peer());
            }
        }
        let mut secrets: Vec<&Id32> = Vec::new();
        for inbox in &self.own {
            secrets.extend([
                inbox.read.as_bytes(),
                inbox.append.as_bytes(),
                inbox.admin.as_bytes(),
            ]);
        }
        if secrets
            .iter()
            .enumerate()
            .any(|(i, s)| secrets[..i].contains(s))
        {
            return Err(MemberError::Sealed);
        }
        let mut peers = Vec::new();
        for wire in &self.peer_wires {
            let auth = open_descriptor(&member.identity, &member.roster, wire).map_err(error)?;
            check_peer_destinations(member, &auth)?;
            if auth.body().owner == member.identity.public().id
                || peers
                    .iter()
                    .any(|p: &loki_relay_client::AuthenticatedDescriptor| {
                        p.body().owner == auth.body().owner
                    })
            {
                return Err(MemberError::Identity);
            }
            peers.push(auth);
        }
        let mut created = Vec::new();
        let mut rotated_relays = Vec::new();
        let mut replacements = Vec::new();
        for pending in &self.pending {
            let index = match pending {
                PendingRequest::Create { relay, .. } | PendingRequest::Rotate { relay, .. } => {
                    *relay as usize
                }
            };
            if index >= self.own.len() {
                return Err(MemberError::Sealed);
            }
            match pending {
                PendingRequest::Create { request, .. } => {
                    if created.contains(&index) {
                        return Err(MemberError::Sealed);
                    }
                    created.push(index);
                    let c = decode_creation(request).map_err(error)?;
                    let inbox = &self.own[index];
                    let rotated_away = inbox.route.append_revision > 1;
                    if c.quota == 0
                        || !verifier_matches(
                            c.read_verifier,
                            role_verifier(&inbox.route, 1, &inbox.read)?,
                        )
                        || !verifier_matches(
                            c.admin_verifier,
                            role_verifier(&inbox.route, 3, &inbox.admin)?,
                        )
                        || (!rotated_away
                            && (inbox.route.append_revision != 1
                                || !verifier_matches(
                                    c.append_verifier,
                                    role_verifier(&inbox.route, 2, &inbox.append)?,
                                )))
                        || (rotated_away
                            && verifier_matches(
                                c.append_verifier,
                                role_verifier(&inbox.route, 2, &inbox.append)?,
                            ))
                    {
                        return Err(MemberError::Sealed);
                    }
                }
                PendingRequest::Rotate {
                    append, request, ..
                } => {
                    if rotated_relays.contains(&index) {
                        return Err(MemberError::Sealed);
                    }
                    rotated_relays.push(index);
                    let update = decode_append_update(request).map_err(error)?;
                    let inbox = &self.own[index];
                    let installed = inbox.append.as_bytes() == append.as_bytes()
                        && inbox.route.append_revision == update.revision;
                    let prepared = inbox.append.as_bytes() != append.as_bytes()
                        && inbox.route.append_revision.checked_add(1) == Some(update.revision);
                    if (!installed && !prepared)
                        || (!installed
                            && (secrets.contains(&append.as_bytes())
                                || replacements.contains(&append.as_bytes())))
                        || (installed && replacements.contains(&append.as_bytes()))
                        || !verifier_matches(
                            update.verifier,
                            role_verifier(&inbox.route, 2, append)?,
                        )
                    {
                        return Err(MemberError::Sealed);
                    }
                    if let Some(counters) = &self.rotated {
                        let counter = *counters.get(index).ok_or(MemberError::Sealed)?;
                        if counter > i64::MAX as u64
                            || (counter != 0 && counter != update.revision)
                            || (counter == 0 && installed)
                        {
                            return Err(MemberError::Sealed);
                        }
                    } else if installed {
                        return Err(MemberError::Sealed);
                    }
                    replacements.push(append.as_bytes());
                }
            }
        }
        if let Some(results) = &self.provisioned {
            if results.len() != 3
                || self.own.len() != 3
                || created.len() != 3
                || (0..3).any(|i| !created.contains(&i))
                || results.iter().any(|r| *r > i64::MAX as u64)
                || (!self.couriers.is_empty() && results.iter().any(|r| *r != 1))
            {
                return Err(MemberError::Sealed);
            }
            match &self.rotated {
                None => {
                    if !rotated_relays.is_empty() {
                        return Err(MemberError::Sealed);
                    }
                }
                Some(counters) => {
                    if counters.len() != 3
                        || rotated_relays.len() != 3
                        || (0..3).any(|i| !rotated_relays.contains(&i))
                    {
                        return Err(MemberError::Sealed);
                    }
                }
            }
            let mut values: Vec<&Id32> = Vec::new();
            for inbox in &self.own {
                for value in [
                    &inbox.route.mailbox,
                    inbox.read.as_bytes(),
                    inbox.append.as_bytes(),
                    inbox.admin.as_bytes(),
                ] {
                    if values.contains(&value) {
                        return Err(MemberError::Sealed);
                    }
                    values.push(value);
                }
            }
        }
        Ok(ClientConfig {
            own: self
                .own
                .iter()
                .map(|i| OwnerInbox {
                    route: i.route.clone(),
                    read: Secret32::from_bytes(*i.read.as_bytes()),
                    append: Secret32::from_bytes(*i.append.as_bytes()),
                    admin: Secret32::from_bytes(*i.admin.as_bytes()),
                })
                .collect(),
            peers,
        })
    }
    pub fn import(&mut self, member: &LoadedMember, wire: &[u8]) -> MemberResult<()> {
        let next = open_descriptor(&member.identity, &member.roster, wire).map_err(error)?;
        check_peer_destinations(member, &next)?;
        if next.body().owner == member.identity.public().id {
            return Err(MemberError::Identity);
        }
        for saved in &mut self.peer_wires {
            let prior = open_descriptor(&member.identity, &member.roster, saved).map_err(error)?;
            if prior.body().owner == next.body().owner {
                accept_descriptor(&prior, &next).map_err(error)?;
                if prior.digest() != next.digest() {
                    *saved = wire.to_vec();
                }
                return Ok(());
            }
        }
        if self.peer_wires.len() >= member.roster.members.len() - 1 {
            return Err(MemberError::Bounds);
        }
        self.peer_wires.push(wire.to_vec());
        Ok(())
    }
    pub fn encode(&self, member: &LoadedMember, revision: u64) -> MemberResult<Zeroizing<Vec<u8>>> {
        counter(revision)?;
        self.authenticated(member)?;
        if let Some(prior) = &self.predecessor {
            if prior.revision() >= revision {
                return Err(MemberError::Sealed);
            }
        }
        let mut value = SecretValue(Value::Array(vec![
            uint(if self.rotated.is_some() {
                3
            } else if self.provisioned.is_some() {
                2
            } else {
                1
            }),
            blob(&member.roster.vault),
            blob(&roster_digest(&member.roster).map_err(error)?),
            uint(member.identity.public().id.into()),
            uint(revision),
            self.predecessor
                .as_ref()
                .map(|r| Value::Array(vec![uint(r.revision()), blob(r.hash())]))
                .unwrap_or(Value::Null),
            self.operation
                .as_ref()
                .map(|o| blob(o))
                .unwrap_or(Value::Null),
            Value::Array(
                self.own
                    .iter()
                    .map(|i| {
                        Value::Array(vec![
                            blob(&i.route.pin.key),
                            blob(i.route.endpoint.as_bytes()),
                            blob(&i.route.pin.run),
                            blob(&i.route.mailbox),
                            uint(i.route.append_revision),
                            blob(i.read.as_bytes()),
                            blob(i.append.as_bytes()),
                            blob(i.admin.as_bytes()),
                        ])
                    })
                    .collect(),
            ),
            self.self_wire
                .as_ref()
                .map(|w| blob(w))
                .unwrap_or(Value::Null),
            Value::Array(self.peer_wires.iter().map(|w| blob(w)).collect()),
            Value::Array(
                self.pending
                    .iter()
                    .map(|p| match p {
                        PendingRequest::Create { relay, request } => Value::Array(vec![
                            uint(1),
                            uint((*relay).into()),
                            Value::Null,
                            blob(request),
                        ]),
                        PendingRequest::Rotate {
                            relay,
                            append,
                            request,
                        } => Value::Array(vec![
                            uint(2),
                            uint((*relay).into()),
                            blob(append.as_bytes()),
                            blob(request),
                        ]),
                    })
                    .collect(),
            ),
            Value::Array(
                self.couriers
                    .iter()
                    .map(|c| {
                        Value::Array(vec![
                            uint(c.peer().into()),
                            blob(c.digest()),
                            blob(c.wire()),
                        ])
                    })
                    .collect(),
            ),
        ]));
        if let (Some(results), Value::Array(fields)) = (&self.provisioned, &mut value.0) {
            fields.push(Value::Array(results.iter().map(|r| uint(*r)).collect()));
        }
        if let (Some(results), Value::Array(fields)) = (&self.rotated, &mut value.0) {
            fields.push(Value::Array(results.iter().map(|r| uint(*r)).collect()));
        }
        let encoded = Zeroizing::new(canonical::encode(&value.0).map_err(error)?);
        if encoded.len() > MAX_CONFIG {
            return Err(MemberError::Bounds);
        }
        Ok(encoded)
    }
    pub fn decode(member: &LoadedMember, revision: u64, encoded: &[u8]) -> MemberResult<Self> {
        roster_digest(&member.roster).map_err(error)?;
        let peer_count = member.roster.members.len() - 1;
        let v = SecretValue(canonical::decode(encoded, MAX_CONFIG).map_err(error)?);
        let fields = match &v.0 {
            Value::Array(f) => f,
            _ => return Err(MemberError::Sealed),
        };
        let version = number(fields.first().ok_or(MemberError::Sealed)?)?;
        let f = array(
            &v.0,
            match version {
                1 => 12,
                2 => 13,
                3 => 14,
                _ => return Err(MemberError::Sealed),
            },
        )?;
        if id(&f[1])? != member.roster.vault
            || id(&f[2])? != roster_digest(&member.roster).map_err(error)?
            || number(&f[3])? != u64::from(member.identity.public().id)
            || number(&f[4])? != revision
        {
            return Err(MemberError::Identity);
        }
        let predecessor = if f[5] == Value::Null {
            None
        } else {
            let p = array(&f[5], 2)?;
            Some(ConfigReference::new(number(&p[0])?, id(&p[1])?).map_err(error)?)
        };
        let operation = if f[6] == Value::Null {
            None
        } else {
            Some(id(&f[6])?)
        };
        let own = list(&f[7], 3)?
            .iter()
            .map(|v| {
                let i = array(v, 8)?;
                Ok(OwnerInbox {
                    route: RelayRoute {
                        pin: RelayPin {
                            key: id(&i[0])?,
                            run: id(&i[2])?,
                        },
                        endpoint: std::str::from_utf8(bytes(&i[1])?)
                            .map_err(error)?
                            .to_owned(),
                        mailbox: id(&i[3])?,
                        append_revision: number(&i[4])?,
                    },
                    read: Secret32::from_bytes(id(&i[5])?),
                    append: Secret32::from_bytes(id(&i[6])?),
                    admin: Secret32::from_bytes(id(&i[7])?),
                })
            })
            .collect::<MemberResult<Vec<_>>>()?;
        let self_wire = if f[8] == Value::Null {
            None
        } else {
            Some(bytes(&f[8])?.to_vec())
        };
        let peer_wires = list(&f[9], peer_count)?
            .iter()
            .map(|v| Ok(bytes(v)?.to_vec()))
            .collect::<MemberResult<Vec<_>>>()?;
        let pending = list(&f[10], 6)?
            .iter()
            .map(|v| {
                let p = array(v, 4)?;
                let relay = u16::try_from(number(&p[1])?).map_err(error)?;
                let request = Zeroizing::new(bytes(&p[3])?.to_vec());
                match number(&p[0])? {
                    1 if p[2] == Value::Null => Ok(PendingRequest::Create { relay, request }),
                    2 => Ok(PendingRequest::Rotate {
                        relay,
                        append: Secret32::from_bytes(id(&p[2])?),
                        request,
                    }),
                    _ => Err(MemberError::Sealed),
                }
            })
            .collect::<MemberResult<Vec<_>>>()?;
        let couriers = if list(&f[11], peer_count)?.is_empty() {
            vec![]
        } else {
            let auth = open_descriptor(
                &member.identity,
                &member.roster,
                self_wire.as_ref().ok_or(MemberError::Identity)?,
            )
            .map_err(error)?;
            list(&f[11], peer_count)?
                .iter()
                .map(|v| {
                    let c = array(v, 3)?;
                    if id(&c[1])? != *auth.digest() {
                        return Err(MemberError::Identity);
                    }
                    super::CourierFile::restore(
                        member,
                        &auth,
                        u16::try_from(number(&c[0])?).map_err(error)?,
                        bytes(&c[2])?,
                    )
                })
                .collect::<MemberResult<Vec<_>>>()?
        };
        let provisioned = if version >= 2 {
            Some(
                array(&f[12], 3)?
                    .iter()
                    .map(number)
                    .collect::<MemberResult<Vec<_>>>()?,
            )
        } else {
            None
        };
        let rotated = if version == 3 {
            Some(
                array(&f[13], 3)?
                    .iter()
                    .map(number)
                    .collect::<MemberResult<Vec<_>>>()?,
            )
        } else {
            None
        };
        let config = Self {
            provisioned,
            rotated,
            own,
            self_wire,
            peer_wires,
            pending,
            operation,
            predecessor,
            couriers,
        };
        if config.encode(member, revision)?.as_slice() != encoded {
            return Err(MemberError::Sealed);
        }
        Ok(config)
    }
}

use super::{
    bounded_read, member_root, private_directory, MAX_PASS, MAX_SEALED, SEAL_HEADER, SEAL_MAGIC,
};
use crate::state::MemberDir;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use loki_relay_client::ClientStore;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

pub struct ConfigStore {
    root: PathBuf,
    pass: Zeroizing<String>,
}

fn has_persisted_nonces(root: &Path) -> MemberResult<bool> {
    let payments = match fs::read_dir(root.join("signing")) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(error(err)),
    };
    for payment in payments {
        let payment = payment.map_err(error)?;
        if !payment.file_type().map_err(error)?.is_dir() {
            return Err(MemberError::Sealed);
        }
        for attempt in fs::read_dir(payment.path()).map_err(error)? {
            let attempt = attempt.map_err(error)?;
            if !attempt.file_type().map_err(error)?.is_dir() {
                return Err(MemberError::Sealed);
            }
            match fs::symlink_metadata(attempt.path().join("nonces.sealed")) {
                Ok(_) => return Ok(true),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(error(err)),
            }
        }
    }
    Ok(false)
}
fn unseal(raw: &[u8], pass: &str) -> MemberResult<Zeroizing<Vec<u8>>> {
    // Use the existing sealed format on the same bounded bytes that were hashed.
    if raw.len() < SEAL_HEADER + 16 || raw.len() > MAX_SEALED || &raw[..9] != SEAL_MAGIC {
        return Err(MemberError::Sealed);
    }
    let key = crate::seal_kdf::derive(pass, &raw[9..25]).map_err(|_| MemberError::Sealed)?;
    XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(error)?
        .decrypt(
            XNonce::from_slice(&raw[25..49]),
            Payload {
                msg: &raw[49..],
                aad: &raw[..49],
            },
        )
        .map(Zeroizing::new)
        .map_err(error)
}
impl ConfigStore {
    pub fn open(root: &Path, pass_file: &Path) -> MemberResult<Self> {
        member_root(root)?;
        private_directory(&root.join("secrets"))?;
        let raw = bounded_read(pass_file, MAX_PASS, true)?;
        let mut pass = Zeroizing::new(std::str::from_utf8(&raw).map_err(error)?.to_owned());
        let length = pass.trim_end_matches(['\r', '\n']).len();
        pass.truncate(length);
        Self::open_with_passphrase(root, &pass)
    }
    pub fn open_with_passphrase(root: &Path, passphrase: &str) -> MemberResult<Self> {
        member_root(root)?;
        private_directory(&root.join("secrets"))?;
        if passphrase.is_empty() {
            return Err(MemberError::Sealed);
        }
        if passphrase.len() > MAX_PASS {
            return Err(MemberError::Bounds);
        }
        Ok(Self {
            root: root.to_owned(),
            pass: Zeroizing::new(passphrase.to_owned()),
        })
    }
    // The hosted adapter must validate scoped admission receipts before activation.
    // This storage step preserves the exact certified configuration across a pointer crash.
    pub(crate) fn install_scoped_configuration(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
        config: &LocalConfig,
    ) -> MemberResult<ConfigReference> {
        db.check_association(&member.roster, member.identity.public().id).map_err(error)?;
        let verified = config.authenticated(member)?;
        if verified.own.len() != 3
            || verified.peers.len() != member.roster.members.len() - 1
            || config.couriers.len() != member.roster.members.len() - 1
            || config.self_wire.is_none()
            || !config.pending.is_empty()
            || config.operation.is_some()
            || config.provisioned.is_some()
            || config.rotated.is_some()
            || config.predecessor.is_some()
        {
            return Err(MemberError::Sealed);
        }
        let encoded = config.encode(member, 1)?;
        if let Some(reference) = db.config_reference().map_err(error)? {
            if reference.revision() != 1
                || self.read(member, &reference)?.encode(member, 1)?.as_slice() != encoded.as_slice()
            {
                return Err(MemberError::Sealed);
            }
            return Ok(reference);
        }
        let provisional = ConfigReference::new(1, [0; 32]).map_err(error)?;
        let path = self.root.join(provisional.file_name());
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.save_revision(db, member, 1, config)
            }
            Err(_) => Err(MemberError::Io),
            Ok(_) => {
                private_directory(&self.root.join("secrets"))?;
                let ciphertext = bounded_read(&path, MAX_SEALED, true)?;
                let reference = ConfigReference::from_ciphertext(1, &ciphertext).map_err(error)?;
                if self.read(member, &reference)?.encode(member, 1)?.as_slice() != encoded.as_slice() {
                    return Err(MemberError::Sealed);
                }
                File::open(&path).and_then(|file| file.sync_all()).map_err(error)?;
                File::open(self.root.join("secrets"))
                    .and_then(|directory| directory.sync_all()).map_err(error)?;
                db.record_config_revision(&reference).map_err(error)?;
                Ok(reference)
            }
        }
    }
    fn read(
        &self,
        member: &LoadedMember,
        reference: &ConfigReference,
    ) -> MemberResult<LocalConfig> {
        private_directory(&self.root.join("secrets"))?;
        let raw = bounded_read(&self.root.join(reference.file_name()), MAX_SEALED, true)?;
        let actual = ConfigReference::from_ciphertext(reference.revision(), &raw).map_err(error)?;
        if actual != *reference {
            return Err(MemberError::Sealed);
        }
        LocalConfig::decode(member, reference.revision(), &unseal(&raw, &self.pass)?)
    }
    pub fn load(
        &self,
        db: &ClientStore,
        member: &LoadedMember,
    ) -> MemberResult<Option<LocalConfig>> {
        db.check_association(&member.roster, member.identity.public().id)
            .map_err(error)?;
        db.config_reference()
            .map_err(error)?
            .map(|reference| self.read(member, &reference))
            .transpose()
    }
    pub fn save_revision(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
        revision: u64,
        config: &LocalConfig,
    ) -> MemberResult<ConfigReference> {
        db.check_association(&member.roster, member.identity.public().id)
            .map_err(error)?;
        let bytes = config.encode(member, revision)?;
        let current = db.config_reference().map_err(error)?;
        let same_revision = current.as_ref().is_some_and(|r| r.revision() == revision);
        if let Some(reference) = &current {
            let prior = self.read(member, reference)?;
            if revision < reference.revision()
                || (!same_revision && reference.revision().checked_add(1) != Some(revision))
            {
                return Err(MemberError::Sealed);
            }
            if same_revision {
                if prior.encode(member, revision)?.as_slice() != bytes.as_slice() {
                    return Err(MemberError::Sealed);
                }
            } else {
                if config.predecessor.as_ref() != Some(reference) {
                    return Err(MemberError::Sealed);
                }
                validate_successor(member, &prior, config)?;
            }
        } else if config.predecessor.is_some() || revision != 1 {
            return Err(MemberError::Sealed);
        }
        let provisional = ConfigReference::new(revision, [0; 32]).map_err(error)?;
        let path = self.root.join(provisional.file_name());
        private_directory(&self.root.join("secrets"))?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let raw = bounded_read(&path, MAX_SEALED, true)?;
                if unseal(&raw, &self.pass)?.as_slice() != bytes.as_slice() {
                    return Err(MemberError::Sealed);
                }
                if !same_revision {
                    // Adopt only the next file whose operation and exact requests authorize it.
                    if config.operation.is_none() {
                        return Err(MemberError::Sealed);
                    }
                    if let Some(reference) = &current {
                        let prior = self.read(member, reference)?;
                        if !orphan_authority(member, &prior, config) {
                            return Err(MemberError::Sealed);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(MemberError::Io)?;
                MemberDir::open(&self.root, "secrets")
                    .write_sealed(filename, &bytes, &self.pass)
                    .map_err(error)?;
            }
            Err(_) => return Err(MemberError::Io),
        }
        File::open(&path)
            .and_then(|f| f.sync_all())
            .map_err(error)?;
        File::open(self.root.join("secrets"))
            .and_then(|f| f.sync_all())
            .map_err(error)?;
        let raw = bounded_read(&path, MAX_SEALED, true)?;
        if unseal(&raw, &self.pass)?.as_slice() != bytes.as_slice() {
            return Err(MemberError::Sealed);
        }
        let reference = ConfigReference::from_ciphertext(revision, &raw).map_err(error)?;
        #[cfg(test)]
        checkpoint(1);
        db.record_config_revision(&reference).map_err(error)?;
        #[cfg(test)]
        checkpoint(2);
        Ok(reference)
    }
}
fn validate_successor(
    member: &LoadedMember,
    prior: &LocalConfig,
    next: &LocalConfig,
) -> MemberResult<()> {
    if let Some(previous) = &prior.provisioned {
        let results = next.provisioned.as_ref().ok_or(MemberError::Sealed)?;
        if prior.operation != next.operation
            || !creation_and_rotation_authority(member, prior, next)
            || !rotation_transition_ok(member, prior, next)
            || previous.iter().zip(results).any(|(a, b)| *b < *a)
        {
            return Err(MemberError::Sealed);
        }
    }
    let old = prior.authenticated(member)?;
    let new = next.authenticated(member)?;
    for peer in old.peers {
        let successor = new
            .peers
            .iter()
            .find(|p| p.body().owner == peer.body().owner)
            .ok_or(MemberError::Identity)?;
        accept_descriptor(&peer, successor).map_err(error)?;
    }
    if let Some(wire) = &prior.self_wire {
        let previous = open_descriptor(&member.identity, &member.roster, wire).map_err(error)?;
        let replacement = open_descriptor(
            &member.identity,
            &member.roster,
            next.self_wire.as_ref().ok_or(MemberError::Identity)?,
        )
        .map_err(error)?;
        accept_descriptor(&previous, &replacement).map_err(error)?;
        for (index, (a, b)) in prior.own.iter().zip(&next.own).enumerate() {
            if a.read.as_bytes() != b.read.as_bytes()
                || a.admin.as_bytes() != b.admin.as_bytes()
                || a.route.pin != b.route.pin
                || a.route.mailbox != b.route.mailbox
                || a.route.endpoint != b.route.endpoint
                || b.route.append_revision < a.route.append_revision
            {
                return Err(MemberError::Identity);
            }
            if a.append.as_bytes() != b.append.as_bytes()
                || a.route.append_revision != b.route.append_revision
            {
                let update = rotate_update(next, index)?;
                if b.append.as_bytes() != update.append.as_bytes()
                    || b.route.append_revision != update.revision
                    || prior
                        .rotated
                        .as_ref()
                        .and_then(|counters| counters.get(index))
                        .copied()
                        != Some(update.revision)
                {
                    return Err(MemberError::Sealed);
                }
            }
        }
    }
    Ok(())
}

fn role_verifier(route: &RelayRoute, role: u8, capability: &Secret32) -> MemberResult<Id32> {
    let mut input = Zeroizing::new(Vec::with_capacity(128));
    input.extend_from_slice(b"Loki_Relay_Capability_v1\0");
    input.push(role);
    input.extend_from_slice(&route.mailbox);
    input.extend_from_slice(capability.as_bytes());
    Ok(*ConfigReference::from_ciphertext(1, &input)
        .map_err(error)?
        .hash())
}

#[cfg(test)]
thread_local! {
    static CRASH_POINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static FAIL_COMMIT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn checkpoint(point: u8) {
    if point == 1 {
        FAIL_COMMIT.with(|p| { if let Some(path)=p.borrow_mut().take() {
            let status=std::process::Command::new("python3").args(["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"CREATE TRIGGER config_test_failure BEFORE INSERT ON config_versions BEGIN SELECT RAISE(ABORT,'synthetic failure'); END\"); c.commit()"]).arg(path).status().unwrap();
            assert!(status.success());
        }});
    }
    CRASH_POINT.with(|p| {
        if p.get() == point {
            std::process::abort();
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    fn member() -> LoadedMember {
        member_with_count(3)
    }
    fn member_with_count(count: u16) -> LoadedMember {
        let identities: Vec<_> = (1..=count)
            .map(|id| {
                let mut raw = Zeroizing::new([id as u8; 66]);
                raw[..2].copy_from_slice(&id.to_be_bytes());
                loki_relay_client::CommIdentity::from_serialized(&raw).unwrap()
            })
            .collect();
        let roster = loki_relay_protocol::types::Roster {
            vault: [81; 32],
            members: identities.iter().map(|i| i.public()).collect(),
        };
        LoadedMember {
            identity: identities.into_iter().next().unwrap(),
            roster,
            threshold: 2,
            network: crate::network::VaultNetwork::Regtest,
        }
    }
    #[test]
    fn every_owner_persists_all_certified_peer_descriptors_for_both_policies() {
        use loki_relay_client::{seal_descriptor, CommIdentity, Descriptor, DescriptorRelay};
        for count in [3u16, 4] {
            let keys = Zeroizing::new(
                (1..=count)
                    .map(|id| crate::setup_transport::Identity::new(id).to_secret_bytes())
                    .collect::<Vec<_>>(),
            );
            let identities: Vec<_> = keys
                .iter()
                .map(|raw| CommIdentity::from_serialized(raw).unwrap())
                .collect();
            let roster = loki_relay_protocol::types::Roster {
                vault: [81; 32],
                members: identities.iter().map(CommIdentity::public).collect(),
            };
            for owner in &identities {
                let member = LoadedMember {
                    identity: CommIdentity::from_serialized(
                        &keys[usize::from(owner.public().id - 1)],
                    )
                    .unwrap(),
                    roster: roster.clone(),
                    threshold: 2,
                    network: crate::network::VaultNetwork::Regtest,
                };
                let mut config = LocalConfig::empty();
                for peer in &identities {
                    if peer.public().id == owner.public().id {
                        continue;
                    }
                    let descriptor = Descriptor::new(
                        roster.vault,
                        roster_digest(&roster).unwrap(),
                        peer.public().id,
                        1,
                        (1..=3u8)
                            .map(|i| DescriptorRelay {
                                route: RelayRoute {
                                    pin: RelayPin {
                                        key: [i; 32],
                                        run: [i + 10; 32],
                                    },
                                    endpoint: format!("http://127.0.0.1:{}", 3100 + u16::from(i)),
                                    mailbox: [i + 20; 32],
                                    append_revision: 1,
                                },
                                append: Secret32::from_bytes([i + 30; 32]),
                            })
                            .collect(),
                    );
                    let wire = seal_descriptor(peer, &roster, &descriptor, &owner.public())
                        .unwrap()
                        .wire;
                    config.import(&member, &wire).unwrap();
                    config.import(&member, &wire).unwrap();
                }
                let encoded = config.encode(&member, 1).unwrap();
                let reopened = LocalConfig::decode(&member, 1, &encoded).unwrap();
                let verified = reopened.authenticated(&member).unwrap();
                assert_eq!(verified.peers.len(), usize::from(count - 1));
                assert_eq!(
                    reopened.encode(&member, 1).unwrap().as_slice(),
                    encoded.as_slice()
                );
            }
        }
    }

    #[test]
    fn every_owner_reopens_all_saved_descriptor_copies_for_both_policies() {
        use loki_relay_client::{seal_descriptor, CommIdentity, Descriptor, DescriptorRelay};
        for count in [3u16, 4] {
            let keys = Zeroizing::new(
                (1..=count)
                    .map(|id| crate::setup_transport::Identity::new(id).to_secret_bytes())
                    .collect::<Vec<_>>(),
            );
            let identities: Vec<_> = keys.iter()
                .map(|raw| CommIdentity::from_serialized(raw).unwrap()).collect();
            let roster = loki_relay_protocol::types::Roster {
                vault: [81; 32],
                members: identities.iter().map(CommIdentity::public).collect(),
            };
            for owner in &identities {
                let member = LoadedMember {
                    identity: CommIdentity::from_serialized(
                        &keys[usize::from(owner.public().id - 1)],
                    ).unwrap(),
                    roster: roster.clone(),
                    threshold: 2,
                    network: crate::network::VaultNetwork::Regtest,
                };
                let mut config = LocalConfig::empty();
                config.own = (1..=3u8).map(|i| OwnerInbox {
                    route: RelayRoute {
                        pin: RelayPin { key: [i; 32], run: [i + 10; 32] },
                        endpoint: format!("http://127.0.0.1:{}", 3100 + u16::from(i)),
                        mailbox: [i + 20; 32],
                        append_revision: 1,
                    },
                    read: Secret32::from_bytes([i + 40; 32]),
                    append: Secret32::from_bytes([i + 30; 32]),
                    admin: Secret32::from_bytes([i + 50; 32]),
                }).collect();
                let descriptor = Descriptor::new(
                    roster.vault, roster_digest(&roster).unwrap(), owner.public().id, 1,
                    config.own.iter().map(|inbox| DescriptorRelay {
                        route: inbox.route.clone(),
                        append: Secret32::from_bytes(*inbox.append.as_bytes()),
                    }).collect(),
                );
                let self_wire = seal_descriptor(owner, &roster, &descriptor, &owner.public())
                    .unwrap().wire;
                let authenticated = open_descriptor(owner, &roster, &self_wire).unwrap();
                config.self_wire = Some(self_wire);
                config.couriers = roster.members.iter()
                    .filter(|peer| peer.id != owner.public().id)
                    .map(|peer| super::super::CourierFile::prepare(&member, &authenticated, peer).unwrap())
                    .collect();
                let wires = config.couriers.iter().map(|copy| copy.wire().to_vec()).collect::<Vec<_>>();
                let encoded = config.encode(&member, 1).unwrap();
                let reopened = LocalConfig::decode(&member, 1, &encoded).unwrap();
                assert_eq!(reopened.couriers.len(), usize::from(count - 1));
                for (copy, saved) in reopened.couriers.iter().zip(wires) {
                    assert_eq!(copy.wire(), saved);
                    let peer = &identities[usize::from(copy.peer() - 1)];
                    assert_eq!(open_descriptor(peer, &roster, copy.wire()).unwrap().body().owner,
                        owner.public().id);
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn sealed_revision_process_child() {
        let root = PathBuf::from(std::env::var_os("LOKI_54_TEST_ROOT").unwrap());
        let stage = std::env::var("LOKI_54_TEST_STAGE")
            .unwrap()
            .parse::<u8>()
            .unwrap();
        let member = member();
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        CRASH_POINT.with(|p| p.set(stage));
        store
            .save_revision(&mut db, &member, 1, &LocalConfig::empty())
            .unwrap();
        panic!("crash barrier was not reached");
    }
    fn crash(stage: u8) {
        let root = std::env::temp_dir().join(format!(
            "relay-54-crash-{}-{stage}-{}",
            std::process::id(),
            hex::encode(crate::setup_transport::Identity::new(1).public().signing)
        ));
        MemberDir::create(&root, "secrets").unwrap();
        let root = root.canonicalize().unwrap();
        std::fs::write(root.join("pass"), b"synthetic").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.join("pass"), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "relay_member::config::tests::sealed_revision_process_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("LOKI_54_TEST_ROOT", &root)
            .env("LOKI_54_TEST_STAGE", stage.to_string())
            .output()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(6));
        }
        let member = member();
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let path = root.join("secrets/relay-config-0000000000000001.sealed");
        let raw = bounded_read(&path, MAX_SEALED, true).unwrap();
        LocalConfig::decode(&member, 1, &unseal(&raw, "synthetic").unwrap()).unwrap();
        if stage == 1 {
            assert!(db.config_reference().unwrap().is_none());
            assert!(store.load(&db, &member).unwrap().is_none());
        } else {
            assert_eq!(
                db.config_reference().unwrap(),
                Some(ConfigReference::from_ciphertext(1, &raw).unwrap())
            );
            assert!(store.load(&db, &member).unwrap().is_some());
        }
    }
    #[test]
    fn sealed_revision_pointer_commit_error_is_not_exposed() {
        let root = std::env::temp_dir().join(format!(
            "relay54-commit-failure-{}-{}",
            std::process::id(),
            hex::encode(crate::setup_transport::Identity::new(1).public().signing)
        ));
        MemberDir::create(&root, "secrets").unwrap();
        let root = root.canonicalize().unwrap();
        fs::write(root.join("pass"), b"synthetic").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("pass"), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let member = member();
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        FAIL_COMMIT.with(|p| *p.borrow_mut() = Some(root.join("transport/client.sqlite3")));
        assert!(store
            .save_revision(&mut db, &member, 1, &LocalConfig::empty())
            .is_err());
        assert!(db.config_reference().unwrap().is_none());
        let raw = bounded_read(
            &root.join("secrets/relay-config-0000000000000001.sealed"),
            MAX_SEALED,
            true,
        )
        .unwrap();
        LocalConfig::decode(&member, 1, &unseal(&raw, "synthetic").unwrap()).unwrap();
    }
    #[test]
    fn sealed_revision_process_crash_after_file_before_pointer() {
        crash(1);
    }
    #[test]
    fn sealed_revision_process_crash_after_commit_before_exposure() {
        crash(2);
    }

    #[test]
    #[ignore]
    fn owner_provision_process_child() {
        let root = PathBuf::from(std::env::var_os("LOKI_55_TEST_ROOT").unwrap());
        let stage = std::env::var("LOKI_55_TEST_STAGE")
            .unwrap()
            .parse::<u8>()
            .unwrap();
        let member = member();
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let runtime = loki_relay_client::RelayRuntime::new().unwrap();
        let http = loki_relay_client::RelayHttp::new().unwrap();
        let caps: Vec<_> = (0..3).map(|i| Secret32::from_bytes([91 + i; 32])).collect();
        CRASH_POINT.with(|p| p.set(stage));
        runtime
            .block_on(store.provision(&mut db, &member, &http, &caps))
            .unwrap();
        panic!("provision crash barrier was not reached");
    }
    fn provision_crash(stage: u8) {
        use std::io::{Read, Write};
        let root = std::env::temp_dir().join(format!(
            "relay55-crash-{}-{stage}-{}",
            std::process::id(),
            hex::encode(crate::setup_transport::Identity::new(1).public().signing)
        ));
        MemberDir::create(&root, "secrets").unwrap();
        let root = root.canonicalize().unwrap();
        fs::write(root.join("pass"), b"synthetic").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("pass"), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let member = member();
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let targets: Vec<_> = (1..=3u8)
            .map(|i| ProvisionTarget {
                pin: RelayPin {
                    key: [i; 32],
                    run: [i + 10; 32],
                },
                endpoint: format!("http://127.0.0.1:{}", if i == 1 { port } else { 1 }),
                quota: 4096,
            })
            .collect();
        let initial = store.prepare_provision(&mut db, &member, &targets).unwrap();
        drop(db);
        let server = std::thread::spawn(move || {
            let (mut stream, text) = loop {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut byte = [0; 1];
                let mut raw = Vec::new();
                while !raw.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    raw.push(byte[0]);
                }
                let text = String::from_utf8(raw).unwrap();
                if text.starts_with("HEAD / HTTP/1.1") {
                    write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
                    continue;
                }
                break (stream, text);
            };
            let length: usize = text
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            let mailbox_hex = text
                .split_whitespace()
                .nth(1)
                .unwrap()
                .strip_prefix("/v1/mailboxes/")
                .unwrap();
            let mut mailbox = [0; 32];
            hex::decode_to_slice(mailbox_hex, &mut mailbox).unwrap();
            let body = loki_relay_protocol::http::encode_creation_result(
                &mailbox,
                &loki_relay_protocol::types::CreationResult {
                    created: true,
                    run: [11; 32],
                    quota: 4096,
                    append_revision: 1,
                },
            )
            .unwrap();
            write!(stream,"HTTP/1.1 201 Created\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
        });
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "relay_member::config::tests::owner_provision_process_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("LOKI_55_TEST_ROOT", &root)
            .env("LOKI_55_TEST_STAGE", stage.to_string())
            .output()
            .unwrap();
        server.join().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                output.status.signal(),
                Some(6),
                "child did not abort at expected barrier"
            );
        }
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let raw = bounded_read(
            &root.join("secrets/relay-config-0000000000000002.sealed"),
            MAX_SEALED,
            true,
        )
        .unwrap();
        let candidate =
            LocalConfig::decode(&member, 2, &unseal(&raw, "synthetic").unwrap()).unwrap();
        assert_eq!(candidate.provisioned, Some(vec![1, 0, 0]));
        assert!(candidate.operation.is_some());
        assert_eq!(candidate.pending.len(), 3);
        if stage == 1 {
            assert_eq!(db.config_reference().unwrap(), Some(initial));
            assert_eq!(
                store.load(&db, &member).unwrap().unwrap().provisioned,
                Some(vec![0; 3])
            );
        } else {
            assert_eq!(
                db.config_reference().unwrap(),
                Some(ConfigReference::from_ciphertext(2, &raw).unwrap())
            );
            assert_eq!(
                store.load(&db, &member).unwrap().unwrap().provisioned,
                Some(vec![1, 0, 0])
            );
        }
        assert!(store.routing(&db, &member).is_err());
        store.recover_provision(&mut db, &member).unwrap();
        assert_eq!(
            db.config_reference().unwrap(),
            Some(ConfigReference::from_ciphertext(2, &raw).unwrap())
        );
    }
    #[test]
    fn owner_provision_process_crash_after_network_file_before_pointer() {
        provision_crash(1);
    }
    #[test]
    fn owner_provision_process_crash_after_pointer_before_exposure() {
        provision_crash(2);
    }

    fn finish_provision(root: &Path, endpoint: &str) -> LoadedMember {
        finish_provision_with_count(root, endpoint, 3)
    }
    fn finish_provision_with_count(root: &Path, endpoint: &str, count: u16) -> LoadedMember {
        let member = member_with_count(count);
        let store = ConfigStore::open(root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let targets: Vec<_> = (1..=3u8)
            .map(|i| ProvisionTarget {
                pin: loki_relay_protocol::types::RelayPin {
                    key: [i; 32],
                    run: [i + 10; 32],
                },
                endpoint: if i == 1 {
                    endpoint.to_owned()
                } else {
                    "http://127.0.0.1:1".to_owned()
                },
                quota: 4096,
            })
            .collect();
        let reference = store.prepare_provision(&mut db, &member, &targets).unwrap();
        let mut config = store.load(&db, &member).unwrap().unwrap();
        let auth = loki_relay_client::open_descriptor(
            &member.identity,
            &member.roster,
            config.self_wire.as_ref().unwrap(),
        )
        .unwrap();
        config.couriers = member
            .roster
            .members
            .iter()
            .filter(|peer| peer.id != member.identity.public().id)
            .map(|peer| super::super::CourierFile::prepare(&member, &auth, peer).unwrap())
            .collect();
        config.provisioned = Some(vec![1; 3]);
        config.predecessor = Some(reference);
        store.save_revision(&mut db, &member, 2, &config).unwrap();
        member
    }
    #[test]
    fn saved_provisioning_and_rotation_keep_the_complete_roster_audience() {
        for count in [3u16, 4] {
            let root = rotation_root("relay-hosted-roster-rotation");
            let member = finish_provision_with_count(&root, "http://127.0.0.1:1", count);
            let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
            let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
            let routing = store.routing(&db, &member).unwrap();
            assert_eq!(routing.own.len(), 3);
            let courier_dir = MemberDir::create(&root, "outbound").unwrap();
            assert_eq!(store.publish_provision(&db, &member, courier_dir.path()).unwrap().len(),
                usize::from(count - 1));
            let reference = store.prepare_rotation(&mut db, &member).unwrap();
            let prepared = store.load(&db, &member).unwrap().unwrap();
            let pending_bytes = prepared.encode(&member, reference.revision()).unwrap();
            assert!(store.routing(&db, &member).is_err());
            drop(db);
            let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
            assert_eq!(store.prepare_rotation(&mut db, &member).unwrap(), reference);
            assert_eq!(store.load(&db, &member).unwrap().unwrap()
                .encode(&member, reference.revision()).unwrap().as_slice(), pending_bytes.as_slice());
            let mut config = store.load(&db, &member).unwrap().unwrap();
            let missing = config.couriers.pop().unwrap();
            assert!(config.encode(&member, reference.revision()).is_err());
            config.couriers.push(missing);
            for index in 0..3 {
                let revision = super::rotate_update(&config, index).unwrap().revision;
                config.rotated.as_mut().unwrap()[index] = revision;
            }
            config.predecessor = db.config_reference().unwrap();
            save_next(&store, &mut db, &member, &config).unwrap();
            assert!(super::install_rotation(&member, &mut config).unwrap());
            config.predecessor = db.config_reference().unwrap();
            save_next(&store, &mut db, &member, &config).unwrap();
            assert_eq!(config.couriers.len(), usize::from(count - 1));
            assert!(store.routing(&db, &member).is_ok());
            let next = store.prepare_next_rotation(&mut db, &member).unwrap();
            assert_eq!(store.prepare_next_rotation(&mut db, &member).unwrap(), next);
            assert!(store.routing(&db, &member).is_err());
            drop(db);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn unlocked_configuration_reopens_without_exporting_a_passphrase_file() {
        for count in [3u16, 4] {
            let root = rotation_root("relay-hosted-unlocked-config");
            let member = finish_provision_with_count(&root, "http://127.0.0.1:1", count);
            let db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
            let legacy = ConfigStore::open(&root, &root.join("pass")).unwrap();
            let reference = db.config_reference().unwrap().unwrap();
            let prior = legacy.load(&db, &member).unwrap().unwrap()
                .encode(&member, reference.revision()).unwrap();
            fs::remove_file(root.join("pass")).unwrap();
            assert!(ConfigStore::open(&root, &root.join("pass")).is_err());
            let unlocked = ConfigStore::open_with_passphrase(&root, "synthetic").unwrap();
            assert_eq!(unlocked.load(&db, &member).unwrap().unwrap()
                .encode(&member, reference.revision()).unwrap().as_slice(), prior.as_slice());
            assert!(ConfigStore::open_with_passphrase(&root, "wrong").unwrap()
                .load(&db, &member).is_err());
            assert!(ConfigStore::open_with_passphrase(&root, "").is_err());
            assert!(ConfigStore::open_with_passphrase(&root, &"x".repeat(4097)).is_err());
            assert!(!root.join("pass").exists());
            assert_eq!(db.config_reference().unwrap().unwrap(), reference);
            drop(db);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn scoped_install_adopts_only_the_exact_complete_saved_configuration() {
        use loki_relay_client::{seal_descriptor, CommIdentity, Descriptor, DescriptorRelay};
        for count in [3u16, 4] {
            let source = rotation_root("relay-scoped-source");
            let member = finish_provision_with_count(&source, "http://127.0.0.1:1", count);
            let source_store = ConfigStore::open_with_passphrase(&source, "synthetic").unwrap();
            let source_db = ClientStore::open(&source.join("transport"), &member.roster, 1).unwrap();
            let mut config = source_store.load(&source_db, &member).unwrap().unwrap();
            config.pending.clear();
            config.operation = None;
            config.provisioned = None;
            config.predecessor = None;
            for slot in 2..=count {
                let mut raw = Zeroizing::new([slot as u8; 66]);
                raw[..2].copy_from_slice(&slot.to_be_bytes());
                let peer = CommIdentity::from_serialized(&raw).unwrap();
                let descriptor = Descriptor::new(
                    member.roster.vault, roster_digest(&member.roster).unwrap(), slot, 1,
                    config.own.iter().map(|inbox| DescriptorRelay {
                        route: RelayRoute { mailbox: [slot as u8 + inbox.route.pin.key[0] + 60; 32],
                            ..inbox.route.clone() },
                        append: Secret32::from_bytes([slot as u8 + inbox.route.pin.key[0] + 80; 32]),
                    }).collect(),
                );
                config.import(&member, &seal_descriptor(&peer, &member.roster,
                    &descriptor, &member.identity.public()).unwrap().wire).unwrap();
            }
            let target = rotation_root("relay-scoped-target");
            let store = ConfigStore::open_with_passphrase(&target, "synthetic").unwrap();
            let mut db = ClientStore::open(&target.join("transport"), &member.roster, 1).unwrap();
            let prepared = config.encode(&member, 1).unwrap();
            let filename = "relay-config-0000000000000001.sealed";
            MemberDir::open(&target, "secrets").write_sealed(filename, &prepared, "synthetic").unwrap();
            let saved_ciphertext = fs::read(target.join("secrets").join(filename)).unwrap();
            let expected = ConfigReference::from_ciphertext(1, &saved_ciphertext).unwrap();
            let missing = config.peer_wires.pop().unwrap();
            assert!(store.install_scoped_configuration(&mut db, &member, &config).is_err());
            assert!(db.config_reference().unwrap().is_none());
            config.peer_wires.push(missing);
            let old_read = *config.own[0].read.as_bytes();
            config.own[0].read = Secret32::from_bytes([199; 32]);
            assert!(store.install_scoped_configuration(&mut db, &member, &config).is_err());
            assert!(db.config_reference().unwrap().is_none());
            config.own[0].read = Secret32::from_bytes(old_read);
            assert_eq!(store.install_scoped_configuration(&mut db, &member, &config).unwrap(), expected);
            assert_eq!(store.install_scoped_configuration(&mut db, &member, &config).unwrap(), expected);
            assert_eq!(fs::read(target.join("secrets").join(filename)).unwrap(), saved_ciphertext);
            assert_eq!(store.routing(&db, &member).unwrap().peers.len(), usize::from(count - 1));
            config.own[0].read = Secret32::from_bytes([199; 32]);
            assert!(store.install_scoped_configuration(&mut db, &member, &config).is_err());
            assert_eq!(db.config_reference().unwrap().unwrap(), expected);
            config.own[0].read = Secret32::from_bytes(old_read);
            drop(db);
            let mut db = ClientStore::open(&target.join("transport"), &member.roster, 1).unwrap();
            assert_eq!(store.install_scoped_configuration(&mut db, &member, &config).unwrap(), expected);
            drop(db);
            let fresh = rotation_root("relay-scoped-fresh");
            let store = ConfigStore::open_with_passphrase(&fresh, "synthetic").unwrap();
            let mut db = ClientStore::open(&fresh.join("transport"), &member.roster, 1).unwrap();
            let installed = store.install_scoped_configuration(&mut db, &member, &config).unwrap();
            assert_eq!(installed.revision(), 1);
            assert_eq!(store.install_scoped_configuration(&mut db, &member, &config).unwrap(), installed);
            assert_eq!(store.load(&db, &member).unwrap().unwrap().encode(&member, 1).unwrap().as_slice(),
                prepared.as_slice());
            drop(db);
            drop(source_db);
            fs::remove_dir_all(fresh).unwrap();
            fs::remove_dir_all(target).unwrap();
            fs::remove_dir_all(source).unwrap();
        }
    }

    fn rotation_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "{label}-{}-{}",
            std::process::id(),
            hex::encode(crate::setup_transport::Identity::new(1).public().signing)
        ));
        MemberDir::create(&root, "secrets").unwrap();
        let root = root.canonicalize().unwrap();
        fs::write(root.join("pass"), b"synthetic").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("pass"), fs::Permissions::from_mode(0o600)).unwrap();
        }
        root
    }
    #[test]
    #[ignore]
    fn partial_rotation_prepare_process_child() {
        let root = PathBuf::from(std::env::var_os("LOKI_56_TEST_ROOT").unwrap());
        let stage = std::env::var("LOKI_56_TEST_STAGE")
            .unwrap()
            .parse::<u8>()
            .unwrap();
        let member = member();
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        CRASH_POINT.with(|p| p.set(stage));
        store.prepare_rotation(&mut db, &member).unwrap();
        panic!("rotation prepare barrier was not reached");
    }
    #[test]
    fn partial_rotation_process_crash_prepare_file_before_pointer() {
        let root = rotation_root("relay56-prepare-crash");
        let member = finish_provision(&root, "http://127.0.0.1:1");
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "relay_member::config::tests::partial_rotation_prepare_process_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("LOKI_56_TEST_ROOT", &root)
            .env("LOKI_56_TEST_STAGE", "1")
            .output()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(6));
        }
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let before = db.config_reference().unwrap().unwrap();
        assert_eq!(before.revision(), 2);
        let path = root.join("secrets/relay-config-0000000000000003.sealed");
        let raw = bounded_read(&path, MAX_SEALED, true).unwrap();
        let sealed = LocalConfig::decode(&member, 3, &unseal(&raw, "synthetic").unwrap()).unwrap();
        assert_eq!(sealed.rotated, Some(vec![0; 3]));
        assert_eq!(
            sealed.operation,
            store.load(&db, &member).unwrap().unwrap().operation
        );
        let adopted = store.prepare_rotation(&mut db, &member).unwrap();
        assert_eq!(adopted.revision(), 3);
        let saved = store.load(&db, &member).unwrap().unwrap();
        assert_eq!(saved.pending.len(), 6);
        for index in 0..3 {
            match (&sealed.pending[index + 3], &saved.pending[index + 3]) {
                (
                    PendingRequest::Rotate {
                        append: sealed_append,
                        request: sealed_request,
                        ..
                    },
                    PendingRequest::Rotate {
                        append: saved_append,
                        request: saved_request,
                        ..
                    },
                ) => {
                    assert_eq!(sealed_append.as_bytes(), saved_append.as_bytes());
                    assert_eq!(sealed_request.as_slice(), saved_request.as_slice());
                }
                _ => panic!("missing saved rotation request"),
            }
            assert_eq!(
                saved.own[index].append.as_bytes(),
                sealed.own[index].append.as_bytes()
            );
        }
        assert_eq!(store.prepare_rotation(&mut db, &member).unwrap(), adopted);
    }
    #[test]
    #[ignore]
    fn partial_rotation_process_child() {
        let root = PathBuf::from(std::env::var_os("LOKI_56_TEST_ROOT").unwrap());
        let stage = std::env::var("LOKI_56_TEST_STAGE")
            .unwrap()
            .parse::<u8>()
            .unwrap();
        let member = member();
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let runtime = loki_relay_client::RelayRuntime::new().unwrap();
        let http = loki_relay_client::RelayHttp::new().unwrap();
        CRASH_POINT.with(|p| p.set(stage));
        runtime
            .block_on(store.rotate(&mut db, &member, &http))
            .unwrap();
        panic!("rotation crash barrier was not reached");
    }
    fn rotation_network_crash(stage: u8) {
        use std::io::{Read, Write};
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let root = rotation_root(&format!("relay56-rotate-crash-{stage}"));
        let member = finish_provision(&root, &format!("http://127.0.0.1:{port}"));
        {
            let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
            let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
            store.prepare_rotation(&mut db, &member).unwrap();
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            while !stop_server.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                            .unwrap();
                        let mut raw = Vec::new();
                        let mut byte = [0; 1];
                        while !raw.ends_with(b"\r\n\r\n") {
                            stream.read_exact(&mut byte).unwrap();
                            raw.push(byte[0]);
                        }
                        let text = String::from_utf8(raw.clone()).unwrap();
                        if text.starts_with("HEAD / HTTP/1.1") {
                            write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
                            continue;
                        }
                        let length: usize = text
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(str::to_owned)
                            })
                            .unwrap()
                            .parse()
                            .unwrap();
                        let mut body = vec![0; length];
                        stream.read_exact(&mut body).unwrap();
                        raw.extend(body);
                        let mailbox_hex = text
                            .split_whitespace()
                            .nth(1)
                            .unwrap()
                            .strip_prefix("/v1/mailboxes/")
                            .unwrap()
                            .trim_end_matches("/append-capability");
                        let mut mailbox = [0; 32];
                        hex::decode_to_slice(mailbox_hex, &mut mailbox).unwrap();
                        recorded.lock().unwrap().push(raw);
                        let response =
                            loki_relay_protocol::http::encode_append_result(&mailbox, 2).unwrap();
                        write!(stream, "HTTP/1.1 200 Control\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                        stream.write_all(&response).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "relay_member::config::tests::partial_rotation_process_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("LOKI_56_TEST_ROOT", &root)
            .env("LOKI_56_TEST_STAGE", stage.to_string())
            .output()
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(6));
        }
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let path = root.join("secrets/relay-config-0000000000000004.sealed");
        let raw = bounded_read(&path, MAX_SEALED, true).unwrap();
        let sealed = LocalConfig::decode(&member, 4, &unseal(&raw, "synthetic").unwrap()).unwrap();
        assert_eq!(sealed.rotated, Some(vec![2, 0, 0]));
        assert!(sealed.operation.is_some());
        assert_eq!(super::creation_requests(&sealed).len(), 3);
        if stage == 1 {
            assert_eq!(db.config_reference().unwrap().unwrap().revision(), 3);
        } else {
            assert_eq!(
                db.config_reference().unwrap(),
                Some(ConfigReference::from_ciphertext(4, &raw).unwrap())
            );
        }
        let http = loki_relay_client::RelayHttp::new().unwrap();
        assert!(loki_relay_client::RelayRuntime::new()
            .unwrap()
            .block_on(store.rotate(&mut db, &member, &http))
            .is_err());
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
        let saved = store.load(&db, &member).unwrap().unwrap();
        assert_eq!(saved.rotated, Some(vec![2, 0, 0]));
        assert_eq!(saved.operation, sealed.operation);
        assert_eq!(
            saved.own[0].append.as_bytes(),
            sealed.own[0].append.as_bytes()
        );
        assert_eq!(saved.own[0].route.append_revision, 1);
        assert_eq!(db.config_reference().unwrap().unwrap().revision(), 4);
    }
    #[test]
    fn partial_rotation_completed_prepare_reuses_saved_generation() {
        let root = rotation_root("relay56-completed-prepare");
        let member = finish_provision(&root, "http://127.0.0.1:1");
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let prepared = store.prepare_rotation(&mut db, &member).unwrap();
        assert_eq!(
            store.prepare_next_rotation(&mut db, &member).unwrap(),
            prepared
        );
        let mut config = store.load(&db, &member).unwrap().unwrap();
        let revisions: Vec<u64> = (0..3)
            .map(|index| super::rotate_update(&config, index).unwrap().revision)
            .collect();
        for (index, revision) in revisions.into_iter().enumerate() {
            config.rotated.as_mut().unwrap()[index] = revision;
        }
        config.predecessor = Some(prepared.clone());
        let verified = prepared.revision() + 1;
        store
            .save_revision(&mut db, &member, verified, &config)
            .unwrap();
        let during = store.prepare_rotation(&mut db, &member).unwrap();
        assert_eq!(during.revision(), verified);
        assert_eq!(
            store.prepare_next_rotation(&mut db, &member).unwrap(),
            during
        );
        let mut config = store.load(&db, &member).unwrap().unwrap();
        assert!(super::install_rotation(&member, &mut config).unwrap());
        config.predecessor = db.config_reference().unwrap();
        let installed = verified + 1;
        store
            .save_revision(&mut db, &member, installed, &config)
            .unwrap();
        let completed = store.load(&db, &member).unwrap().unwrap();
        let again = store.prepare_rotation(&mut db, &member).unwrap();
        assert_eq!(again.revision(), installed);
        assert_eq!(
            store.load(&db, &member).unwrap().unwrap().self_wire,
            completed.self_wire
        );
        let next = store.prepare_next_rotation(&mut db, &member).unwrap();
        assert_ne!(next, again);
        assert_eq!(store.prepare_rotation(&mut db, &member).unwrap(), next);
        assert_eq!(store.prepare_next_rotation(&mut db, &member).unwrap(), next);
        let advanced = store.load(&db, &member).unwrap().unwrap();
        assert_eq!(advanced.rotated, Some(vec![0; 3]));
        assert_eq!(advanced.operation, completed.operation);
        assert_eq!(advanced.self_wire, completed.self_wire);
        assert_eq!(advanced.provisioned, completed.provisioned);
        for index in 0..3 {
            assert_eq!(
                advanced.own[index].append.as_bytes(),
                completed.own[index].append.as_bytes()
            );
            assert_eq!(
                advanced.own[index].read.as_bytes(),
                completed.own[index].read.as_bytes()
            );
            assert_eq!(
                advanced.own[index].admin.as_bytes(),
                completed.own[index].admin.as_bytes()
            );
            assert_eq!(
                advanced.own[index].route.mailbox,
                completed.own[index].route.mailbox
            );
            let replacement = *super::rotate_update(&advanced, index)
                .unwrap()
                .append
                .as_bytes();
            assert_ne!(*advanced.own[index].append.as_bytes(), replacement);
            match (&completed.pending[index], &advanced.pending[index]) {
                (
                    PendingRequest::Create { request: prior, .. },
                    PendingRequest::Create { request: kept, .. },
                ) => assert_eq!(prior.as_slice(), kept.as_slice()),
                _ => panic!("creation request moved"),
            }
        }
    }
    #[test]
    fn partial_rotation_duplicate_append_fails_closed() {
        use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
        let root = rotation_root("relay56-distinct");
        let member = finish_provision(&root, "http://127.0.0.1:1");
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let prepared = store.prepare_rotation(&mut db, &member).unwrap();
        let mut config = store.load(&db, &member).unwrap().unwrap();
        let route = config.own[0].route.clone();
        let duplicate = *config.own[0].read.as_bytes();
        for pending in &mut config.pending {
            if let PendingRequest::Rotate {
                relay,
                append,
                request,
            } = pending
            {
                if *relay != 0 {
                    continue;
                }
                *append = Secret32::from_bytes(duplicate);
                let revision = loki_relay_protocol::http::decode_append_update(request)
                    .unwrap()
                    .revision;
                let verifier = super::role_verifier(&route, 2, append).unwrap();
                *request = Zeroizing::new(
                    encode_append_update(&AppendUpdate { revision, verifier }).unwrap(),
                );
            }
        }
        assert!(config.encode(&member, prepared.revision()).is_err());
    }
    fn open_prepared(label: &str) -> (ConfigStore, ClientStore, LoadedMember) {
        let root = rotation_root(label);
        let member = finish_provision(&root, "http://127.0.0.1:1");
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        store.prepare_rotation(&mut db, &member).unwrap();
        (store, db, member)
    }
    fn save_next(
        store: &ConfigStore,
        db: &mut ClientStore,
        member: &LoadedMember,
        config: &LocalConfig,
    ) -> MemberResult<ConfigReference> {
        let current = db.config_reference().unwrap().unwrap();
        store.save_revision(db, member, current.revision() + 1, config)
    }
    #[test]
    fn partial_rotation_creation_bytes_stay_bound() {
        use loki_relay_protocol::http::encode_creation;
        let (store, mut db, member) = open_prepared("relay56-creation-bytes");
        let mut config = store.load(&db, &member).unwrap().unwrap();
        for pending in &mut config.pending {
            if let PendingRequest::Create { relay, request } = pending {
                if *relay != 0 {
                    continue;
                }
                let mut creation = decode_creation(request).unwrap();
                creation.quota = 8192;
                *request = Zeroizing::new(encode_creation(&creation).unwrap());
            }
        }
        let revision = db.config_reference().unwrap().unwrap().revision() + 1;
        config.predecessor = db.config_reference().unwrap();
        assert!(config.encode(&member, revision).is_ok());
        assert!(save_next(&store, &mut db, &member, &config).is_err());
    }
    #[test]
    fn partial_rotation_in_progress_rotate_bytes_stay_bound() {
        use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
        let (store, mut db, member) = open_prepared("relay56-rotate-bytes");
        let mut config = store.load(&db, &member).unwrap().unwrap();
        let append = Secret32::from_bytes([0x5A; 32]);
        for pending in &mut config.pending {
            if let PendingRequest::Rotate {
                relay,
                append: slot,
                request,
            } = pending
            {
                if *relay != 1 {
                    continue;
                }
                let revision = decode_append_update(request).unwrap().revision;
                let verifier = super::role_verifier(&config.own[1].route, 2, &append).unwrap();
                *slot = Secret32::from_bytes(*append.as_bytes());
                *request = Zeroizing::new(
                    encode_append_update(&AppendUpdate { revision, verifier }).unwrap(),
                );
            }
        }
        let revision = db.config_reference().unwrap().unwrap().revision() + 1;
        config.predecessor = db.config_reference().unwrap();
        assert!(config.encode(&member, revision).is_ok());
        assert!(save_next(&store, &mut db, &member, &config).is_err());
    }
    #[test]
    fn partial_rotation_first_adoption_counters_are_zero() {
        use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
        let root = rotation_root("relay56-zero-counters");
        let member = finish_provision(&root, "http://127.0.0.1:1");
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        let mut config = store.load(&db, &member).unwrap().unwrap();
        assert!(config.rotated.is_none());
        let mut counters = vec![0; 3];
        for index in 0..3 {
            let mut append = [0x20; 32];
            append[0] = 0xA0 + index as u8;
            let secret = Secret32::from_bytes(append);
            let revision = config.own[index].route.append_revision + 1;
            let verifier = super::role_verifier(&config.own[index].route, 2, &secret).unwrap();
            let request = encode_append_update(&AppendUpdate { revision, verifier }).unwrap();
            config.pending.push(PendingRequest::Rotate {
                relay: index as u16,
                append: secret,
                request: Zeroizing::new(request),
            });
            if index == 0 {
                counters[0] = revision;
            }
        }
        config.rotated = Some(counters);
        let revision = db.config_reference().unwrap().unwrap().revision() + 1;
        config.predecessor = db.config_reference().unwrap();
        assert!(config.encode(&member, revision).is_ok());
        assert!(save_next(&store, &mut db, &member, &config).is_err());
    }
    fn installed_generation(label: &str) -> (ConfigStore, ClientStore, LoadedMember) {
        let (store, mut db, member) = open_prepared(label);
        let mut config = store.load(&db, &member).unwrap().unwrap();
        for index in 0..3 {
            let revision = super::rotate_update(&config, index).unwrap().revision;
            config.rotated.as_mut().unwrap()[index] = revision;
        }
        config.predecessor = db.config_reference().unwrap();
        let verified = config.predecessor.as_ref().unwrap().revision() + 1;
        store
            .save_revision(&mut db, &member, verified, &config)
            .unwrap();
        let mut config = store.load(&db, &member).unwrap().unwrap();
        assert!(super::install_rotation(&member, &mut config).unwrap());
        config.predecessor = db.config_reference().unwrap();
        store
            .save_revision(&mut db, &member, verified + 1, &config)
            .unwrap();
        (store, db, member)
    }
    #[test]
    fn partial_rotation_install_requires_verified_counter() {
        let (store, db, member) = open_prepared("relay56-install-counter");
        let mut config = store.load(&db, &member).unwrap().unwrap();
        for index in 0..3 {
            let revision = super::rotate_update(&config, index).unwrap().revision;
            config.rotated.as_mut().unwrap()[index] = revision;
        }
        config.rotated.as_mut().unwrap()[0] += 1;
        assert!(super::install_rotation(&member, &mut config).is_err());
    }
    #[test]
    fn partial_rotation_prepared_counter_must_match_update() {
        let (store, db, member) = open_prepared("relay56-prepared-counter");
        let mut config = store.load(&db, &member).unwrap().unwrap();
        config.rotated.as_mut().unwrap()[2] = 9;
        assert!(super::authoritative_rotation(&member, &config).is_err());
    }
    #[test]
    fn partial_rotation_partial_install_fails_closed() {
        let (store, db, member) = open_prepared("relay56-partial-install");
        let mut config = store.load(&db, &member).unwrap().unwrap();
        for index in 0..3 {
            let revision = super::rotate_update(&config, index).unwrap().revision;
            config.rotated.as_mut().unwrap()[index] = revision;
        }
        let update = super::rotate_update(&config, 0).unwrap();
        let revision = update.revision;
        let append = *update.append.as_bytes();
        config.own[0].append = Secret32::from_bytes(append);
        config.own[0].route.append_revision = revision;
        assert!(super::install_rotation(&member, &mut config).is_err());
    }
    #[test]
    fn partial_rotation_partial_record_is_not_authoritative() {
        let (store, db, member) = open_prepared("relay56-partial-record");
        let mut config = store.load(&db, &member).unwrap().unwrap();
        let update = super::rotate_update(&config, 0).unwrap();
        let revision = update.revision;
        let append = *update.append.as_bytes();
        config.rotated.as_mut().unwrap()[0] = revision;
        config.own[0].append = Secret32::from_bytes(append);
        config.own[0].route.append_revision = revision;
        assert!(super::authoritative_rotation(&member, &config).is_err());
    }
    #[test]
    fn partial_rotation_counter_change_keeps_credentials() {
        let (store, db, member) = open_prepared("relay56-credential-stable");
        let prior = store.load(&db, &member).unwrap().unwrap();
        let mut next = store.load(&db, &member).unwrap().unwrap();
        let revision = super::rotate_update(&next, 0).unwrap().revision;
        next.rotated.as_mut().unwrap()[0] = revision;
        next.own[0].read = Secret32::from_bytes([0x44; 32]);
        assert!(!super::rotation_transition_ok(&member, &prior, &next));
    }
    #[test]
    fn partial_rotation_provisioned_counters_stay_while_rotated() {
        let (store, db, member) = open_prepared("relay56-provisioned-stable");
        let prior = store.load(&db, &member).unwrap().unwrap();
        let mut next = store.load(&db, &member).unwrap().unwrap();
        next.provisioned = Some(vec![1, 1, 2]);
        assert!(!super::rotation_transition_ok(&member, &prior, &next));
    }
    #[test]
    fn partial_rotation_completed_generation_cannot_drop_rotated() {
        let (store, db, member) = open_prepared("relay56-drop-rotated");
        let prior = store.load(&db, &member).unwrap().unwrap();
        let mut next = store.load(&db, &member).unwrap().unwrap();
        next.rotated = None;
        assert!(!super::rotation_transition_ok(&member, &prior, &next));
    }
    #[test]
    fn partial_rotation_next_counters_start_at_zero() {
        use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
        let (store, db, member) = installed_generation("relay56-next-zero");
        let prior = store.load(&db, &member).unwrap().unwrap();
        let mut next = store.load(&db, &member).unwrap().unwrap();
        next.rotated = Some(vec![0, 0, 1]);
        for index in 0..3 {
            let mut append = [0x30; 32];
            append[0] = 0xB0 + index as u8;
            let secret = Secret32::from_bytes(append);
            let revision = next.own[index].route.append_revision + 1;
            let verifier = super::role_verifier(&next.own[index].route, 2, &secret).unwrap();
            let request = encode_append_update(&AppendUpdate { revision, verifier }).unwrap();
            for pending in &mut next.pending {
                if let PendingRequest::Rotate {
                    relay,
                    append: slot,
                    request: saved,
                } = pending
                {
                    if usize::from(*relay) == index {
                        *slot = secret;
                        *saved = Zeroizing::new(request);
                        break;
                    }
                }
            }
        }
        assert!(!super::next_generation_prepare(&member, &prior, &next));
    }
    #[test]
    fn partial_rotation_next_revision_is_current_plus_one() {
        use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
        let (store, db, member) = installed_generation("relay56-next-revision");
        let prior = store.load(&db, &member).unwrap().unwrap();
        let mut next = store.load(&db, &member).unwrap().unwrap();
        next.rotated = Some(vec![0; 3]);
        for index in 0..3 {
            let mut append = [0x31; 32];
            append[0] = 0xC0 + index as u8;
            let secret = Secret32::from_bytes(append);
            let revision = next.own[index].route.append_revision + 2;
            let verifier = super::role_verifier(&next.own[index].route, 2, &secret).unwrap();
            let request = encode_append_update(&AppendUpdate { revision, verifier }).unwrap();
            for pending in &mut next.pending {
                if let PendingRequest::Rotate {
                    relay,
                    append: slot,
                    request: saved,
                } = pending
                {
                    if usize::from(*relay) == index {
                        *slot = Secret32::from_bytes(*secret.as_bytes());
                        *saved = Zeroizing::new(request);
                        break;
                    }
                }
            }
        }
        assert!(!super::next_generation_prepare(&member, &prior, &next));
    }
    #[test]
    fn partial_rotation_next_append_must_change() {
        use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
        let (store, db, member) = installed_generation("relay56-next-append");
        let prior = store.load(&db, &member).unwrap().unwrap();
        let mut next = store.load(&db, &member).unwrap().unwrap();
        next.rotated = Some(vec![0; 3]);
        for index in 0..3 {
            let update = super::rotate_update(&prior, index).unwrap();
            let secret = Secret32::from_bytes(*update.append.as_bytes());
            let revision = next.own[index].route.append_revision + 1;
            let verifier = super::role_verifier(&next.own[index].route, 2, &secret).unwrap();
            let request = encode_append_update(&AppendUpdate { revision, verifier }).unwrap();
            for pending in &mut next.pending {
                if let PendingRequest::Rotate {
                    relay,
                    request: saved,
                    ..
                } = pending
                {
                    if usize::from(*relay) == index {
                        *saved = Zeroizing::new(request);
                        break;
                    }
                }
            }
        }
        assert!(!super::next_generation_prepare(&member, &prior, &next));
    }
    #[test]
    fn partial_rotation_provision_skips_creation_after_prepare() {
        use std::io::ErrorKind;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let root = rotation_root("relay56-skip-create");
        let member = finish_provision(&root, &endpoint);
        let store = ConfigStore::open(&root, &root.join("pass")).unwrap();
        let mut db = ClientStore::open(&root.join("transport"), &member.roster, 1).unwrap();
        store.prepare_rotation(&mut db, &member).unwrap();
        let hit = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&hit);
        let started = Arc::clone(&ready);
        let finished = Arc::clone(&stop);
        let acceptor = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            started.store(true, Ordering::SeqCst);
            let start = Instant::now();
            while !finished.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(15) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        use std::io::Read;
                        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                        let mut method = [0; 4];
                        if stream.read_exact(&mut method).is_ok() && method == *b"HEAD" {
                            continue;
                        }
                        seen.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return,
                }
            }
        });
        while !ready.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(1));
        }
        let caps: Vec<_> = (0..3)
            .map(|index| Secret32::from_bytes([91 + index; 32]))
            .collect();
        let result = loki_relay_client::RelayRuntime::new()
            .unwrap()
            .block_on(store.provision(
                &mut db,
                &member,
                &loki_relay_client::RelayHttp::new().unwrap(),
                &caps,
            ));
        stop.store(true, Ordering::SeqCst);
        acceptor.join().unwrap();
        assert!(result.is_err());
        assert!(
            !hit.load(Ordering::SeqCst),
            "creation request was sent after rotation prepare"
        );
    }
    #[test]
    fn partial_rotation_process_crash_after_network_file_before_pointer() {
        rotation_network_crash(1);
    }
    #[test]
    fn partial_rotation_process_crash_after_pointer_before_exposure() {
        rotation_network_crash(2);
    }
}

fn same_pending(a: &LocalConfig, b: &LocalConfig) -> bool {
    a.pending.len() == b.pending.len()
        && a.pending.iter().zip(&b.pending).all(|(a, b)| match (a, b) {
            (
                PendingRequest::Create {
                    relay: a,
                    request: x,
                },
                PendingRequest::Create {
                    relay: b,
                    request: y,
                },
            ) => a == b && x.as_slice() == y.as_slice(),
            (
                PendingRequest::Rotate {
                    relay: a,
                    append: x,
                    request: m,
                },
                PendingRequest::Rotate {
                    relay: b,
                    append: y,
                    request: n,
                },
            ) => a == b && x.as_bytes() == y.as_bytes() && m.as_slice() == n.as_slice(),
            _ => false,
        })
}

fn verifier_matches(actual: Id32, expected: Id32) -> bool {
    // This existing type compares bytes in constant time; from_bytes performs no hashing.
    blake3::Hash::from_bytes(actual) == blake3::Hash::from_bytes(expected)
}

struct RotateUpdate<'a> {
    append: &'a Secret32,
    revision: u64,
}
fn rotate_update(config: &LocalConfig, index: usize) -> MemberResult<RotateUpdate<'_>> {
    match config
        .pending
        .iter()
        .find(|p| matches!(p, PendingRequest::Rotate { relay, .. } if usize::from(*relay) == index))
    {
        Some(PendingRequest::Rotate {
            append, request, ..
        }) => Ok(RotateUpdate {
            append,
            revision: decode_append_update(request).map_err(error)?.revision,
        }),
        _ => Err(MemberError::Sealed),
    }
}
fn installed_rotation(config: &LocalConfig, index: usize) -> MemberResult<bool> {
    if config.own.len() <= index
        || !config.pending.iter().any(
            |p| matches!(p, PendingRequest::Rotate { relay, .. } if usize::from(*relay) == index),
        )
    {
        return Ok(false);
    }
    let update = rotate_update(config, index)?;
    Ok(
        config.own[index].append.as_bytes() == update.append.as_bytes()
            && config.own[index].route.append_revision == update.revision,
    )
}
fn creation_requests(config: &LocalConfig) -> Vec<&PendingRequest> {
    config
        .pending
        .iter()
        .filter(|p| matches!(p, PendingRequest::Create { .. }))
        .collect()
}
fn rotation_requests(config: &LocalConfig) -> Vec<&PendingRequest> {
    config
        .pending
        .iter()
        .filter(|p| matches!(p, PendingRequest::Rotate { .. }))
        .collect()
}
fn same_create(a: &PendingRequest, b: &PendingRequest) -> bool {
    match (a, b) {
        (
            PendingRequest::Create {
                relay: a,
                request: x,
            },
            PendingRequest::Create {
                relay: b,
                request: y,
            },
        ) => a == b && x.as_slice() == y.as_slice(),
        _ => false,
    }
}
fn same_rotate(a: &PendingRequest, b: &PendingRequest) -> bool {
    match (a, b) {
        (
            PendingRequest::Rotate {
                relay: a,
                append: x,
                request: m,
            },
            PendingRequest::Rotate {
                relay: b,
                append: y,
                request: n,
            },
        ) => a == b && x.as_bytes() == y.as_bytes() && m.as_slice() == n.as_slice(),
        _ => false,
    }
}
fn creation_and_rotation_authority(member: &LoadedMember, prior: &LocalConfig, next: &LocalConfig) -> bool {
    let prior_creates = creation_requests(prior);
    let next_creates = creation_requests(next);
    if prior_creates.len() != next_creates.len()
        || prior_creates
            .iter()
            .zip(&next_creates)
            .any(|(a, b)| !same_create(a, b))
    {
        return false;
    }
    if next_generation_prepare(member, prior, next) {
        return true;
    }
    let prior_rotates = rotation_requests(prior);
    let next_rotates = rotation_requests(next);
    if prior_rotates.len() > next_rotates.len()
        || prior_rotates
            .iter()
            .zip(&next_rotates)
            .any(|(a, b)| !same_rotate(a, b))
        || (!prior_rotates.is_empty() && prior_rotates.len() != next_rotates.len())
    {
        return false;
    }
    true
}
fn credentials_same(prior: &LocalConfig, next: &LocalConfig) -> bool {
    prior.own.len() == next.own.len()
        && prior.own.iter().zip(&next.own).all(|(a, b)| {
            a.route == b.route
                && a.read.as_bytes() == b.read.as_bytes()
                && a.append.as_bytes() == b.append.as_bytes()
                && a.admin.as_bytes() == b.admin.as_bytes()
        })
        && prior.self_wire == next.self_wire
        && prior.couriers.len() == next.couriers.len()
        && prior
            .couriers
            .iter()
            .zip(&next.couriers)
            .all(|(a, b)| a.peer() == b.peer() && a.wire() == b.wire())
}
fn rotation_shape(member: &LoadedMember, config: &LocalConfig, counters: &[u64]) -> bool {
    config.own.len() == 3
        && config
            .provisioned
            .as_ref()
            .is_some_and(|results| results.len() == 3 && results.iter().all(|result| *result == 1))
        && counters.len() == 3
        && config.couriers.len() == member.roster.members.len() - 1
        && config.self_wire.is_some()
        && creation_requests(config).len() == 3
        && rotation_requests(config).len() == 3
        && config.operation.is_some()
}
fn authoritative_rotation(member: &LoadedMember, config: &LocalConfig) -> MemberResult<bool> {
    let Some(counters) = &config.rotated else {
        return Ok(false);
    };
    if !rotation_shape(member, config, counters) {
        return Err(MemberError::Sealed);
    }
    let mut installed = 0usize;
    for index in 0..3 {
        let update = rotate_update(config, index)?;
        let inbox = &config.own[index];
        let matches_secret = inbox.append.as_bytes() == update.append.as_bytes()
            && inbox.route.append_revision == update.revision;
        let prepared = inbox.append.as_bytes() != update.append.as_bytes()
            && inbox.route.append_revision.checked_add(1) == Some(update.revision);
        if counters[index] > i64::MAX as u64 || (!matches_secret && !prepared) {
            return Err(MemberError::Sealed);
        }
        if matches_secret {
            if counters[index] != update.revision {
                return Err(MemberError::Sealed);
            }
            installed += 1;
        } else if counters[index] != 0 && counters[index] != update.revision {
            return Err(MemberError::Sealed);
        }
    }
    if installed != 0 && installed != 3 {
        return Err(MemberError::Sealed);
    }
    Ok(true)
}
fn generation_complete(member: &LoadedMember, config: &LocalConfig) -> MemberResult<bool> {
    if !authoritative_rotation(member, config)? {
        return Ok(false);
    }
    for index in 0..3 {
        if !installed_rotation(config, index)? {
            return Ok(false);
        }
    }
    Ok(true)
}
fn next_generation_prepare(member: &LoadedMember, prior: &LocalConfig, next: &LocalConfig) -> bool {
    if !matches!(generation_complete(member, prior), Ok(true)) {
        return false;
    }
    let Some(counters) = &next.rotated else {
        return false;
    };
    if counters.len() != 3
        || counters.iter().any(|counter| *counter != 0)
        || !credentials_same(prior, next)
    {
        return false;
    }
    let prior_creates = creation_requests(prior);
    let next_creates = creation_requests(next);
    if prior_creates.len() != next_creates.len()
        || prior_creates
            .iter()
            .zip(&next_creates)
            .any(|(a, b)| !same_create(a, b))
        || rotation_requests(next).len() != 3
    {
        return false;
    }
    (0..3).all(|index| {
        let (Ok(update), Ok(previous)) = (rotate_update(next, index), rotate_update(prior, index))
        else {
            return false;
        };
        let inbox = &next.own[index];
        inbox.append.as_bytes() != update.append.as_bytes()
            && inbox.route.append_revision.checked_add(1) == Some(update.revision)
            && previous.revision != update.revision
            && previous.append.as_bytes() != update.append.as_bytes()
    })
}
fn rotation_transition_ok(member: &LoadedMember, prior: &LocalConfig, next: &LocalConfig) -> bool {
    if (prior.rotated.is_some() || next.rotated.is_some()) && prior.provisioned != next.provisioned
    {
        return false;
    }
    match (&prior.rotated, &next.rotated) {
        (None, None) => rotation_requests(next).is_empty(),
        (None, Some(counters)) => {
            counters.len() == 3
                && counters.iter().all(|counter| *counter == 0)
                && rotation_requests(prior).is_empty()
                && rotation_requests(next).len() == 3
                && credentials_same(prior, next)
        }
        (Some(prior_counters), Some(next_counters)) => {
            if next_generation_prepare(member, prior, next) {
                return true;
            }
            if prior_counters.len() != 3 || next_counters.len() != 3 {
                return false;
            }
            let mut changed = false;
            for (index, (before, after)) in prior_counters.iter().zip(next_counters).enumerate() {
                if before == after {
                    continue;
                }
                let Ok(update) = rotate_update(next, index) else {
                    return false;
                };
                if *before != 0 || *after != update.revision {
                    return false;
                }
                changed = true;
            }
            !changed || credentials_same(prior, next)
        }
        (Some(_), None) => false,
    }
}
fn orphan_authority(member: &LoadedMember, prior: &LocalConfig, next: &LocalConfig) -> bool {
    if prior.operation.is_none() || prior.operation != next.operation {
        return false;
    }
    if same_pending(prior, next) {
        return true;
    }
    if next_generation_prepare(member, prior, next) {
        return true;
    }
    prior.provisioned.is_some()
        && prior.rotated.is_none()
        && next
            .rotated
            .as_ref()
            .is_some_and(|counters| counters.len() == 3 && counters.iter().all(|n| *n == 0))
        && creation_and_rotation_authority(member, prior, next)
        && rotation_requests(prior).is_empty()
        && rotation_requests(next).len() == 3
        && credentials_same(prior, next)
}
fn rotation_blocks_routing(config: &LocalConfig) -> bool {
    config.pending.iter().any(|pending| match pending {
        PendingRequest::Rotate {
            relay,
            append,
            request,
        } => decode_append_update(request).map_or(true, |update| {
            let inbox = &config.own[usize::from(*relay)];
            inbox.append.as_bytes() != append.as_bytes()
                || inbox.route.append_revision != update.revision
        }),
        _ => false,
    })
}
fn install_rotation(member: &LoadedMember, config: &mut LocalConfig) -> MemberResult<bool> {
    use loki_relay_client::{seal_descriptor, Descriptor, DescriptorRelay};
    let counters = config.rotated.clone().ok_or(MemberError::Sealed)?;
    if counters.len() != 3 || counters.iter().any(|counter| *counter == 0) {
        return Ok(false);
    }
    let installed = (0..3)
        .map(|index| installed_rotation(config, index))
        .collect::<MemberResult<Vec<_>>>()?;
    if installed.iter().all(|ready| *ready) {
        return Ok(false);
    }
    if installed.iter().any(|ready| *ready) {
        return Err(MemberError::Sealed);
    }
    let current = open_descriptor(
        &member.identity,
        &member.roster,
        config.self_wire.as_ref().ok_or(MemberError::Sealed)?,
    )
    .map_err(error)?;
    let revision = current
        .body()
        .revision
        .checked_add(1)
        .filter(|revision| *revision <= i64::MAX as u64)
        .ok_or(MemberError::Bounds)?;
    for index in 0..3 {
        let (revision, append) = {
            let update = rotate_update(config, index)?;
            if counters[index] != update.revision {
                return Err(MemberError::Sealed);
            }
            (update.revision, Zeroizing::new(*update.append.as_bytes()))
        };
        config.own[index].append = Secret32::from_bytes(*append);
        config.own[index].route.append_revision = revision;
    }
    let descriptor = Descriptor::new(
        member.roster.vault,
        roster_digest(&member.roster).map_err(error)?,
        member.identity.public().id,
        revision,
        config
            .own
            .iter()
            .map(|inbox| DescriptorRelay {
                route: inbox.route.clone(),
                append: Secret32::from_bytes(*inbox.append.as_bytes()),
            })
            .collect(),
    );
    config.self_wire = Some(
        seal_descriptor(
            &member.identity,
            &member.roster,
            &descriptor,
            &member.identity.public(),
        )
        .map_err(error)?
        .wire,
    );
    let auth = open_descriptor(
        &member.identity,
        &member.roster,
        config.self_wire.as_ref().ok_or(MemberError::Sealed)?,
    )
    .map_err(error)?;
    config.couriers = member
        .roster
        .members
        .iter()
        .filter(|peer| peer.id != member.identity.public().id)
        .map(|peer| super::CourierFile::prepare(member, &auth, peer))
        .collect::<MemberResult<Vec<_>>>()?;
    Ok(true)
}

pub struct ProvisionTarget {
    pub pin: RelayPin,
    pub endpoint: String,
    pub quota: u64,
}
impl ConfigStore {
    fn next_revision(db: &ClientStore) -> MemberResult<u64> {
        db.config_reference().map_err(error)?.map_or(Ok(1), |r| {
            r.revision()
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(MemberError::Bounds)
        })
    }
    pub fn prepare_provision(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
        targets: &[ProvisionTarget],
    ) -> MemberResult<ConfigReference> {
        use loki_relay_client::{seal_descriptor, Descriptor, DescriptorRelay};
        use loki_relay_protocol::{http::encode_creation, types::Creation};
        use rand_core::{OsRng, RngCore};
        if targets.len() != 3
            || targets.windows(2).any(|p| p[0].pin.key >= p[1].pin.key)
            || targets
                .iter()
                .any(|t| t.quota == 0 || t.quota > i64::MAX as u64)
        {
            return Err(MemberError::Bounds);
        }
        let mut config = self.load(db, member)?.unwrap_or_else(LocalConfig::empty);
        if !config.own.is_empty() {
            if config.provisioned.is_none()
                || config
                    .own
                    .iter()
                    .zip(targets)
                    .any(|(i, t)| i.route.pin != t.pin || i.route.endpoint != t.endpoint)
                || config.pending.iter().any(|p| match p {
                    PendingRequest::Create { relay, request } => {
                        targets.get(usize::from(*relay)).is_none_or(|t| {
                            decode_creation(request).map_or(true, |c| c.quota != t.quota)
                        })
                    }
                    _ => true,
                })
            {
                return Err(MemberError::Sealed);
            }
            return db
                .config_reference()
                .map_err(error)?
                .ok_or(MemberError::Sealed);
        }
        if has_persisted_nonces(&self.root)? {
            return Err(MemberError::Sealed);
        }
        if !config.pending.is_empty() {
            return Err(MemberError::Sealed);
        }
        let mut values = Zeroizing::new(Vec::<Id32>::new());
        for target in targets {
            let mut random = Zeroizing::new([[0u8; 32]; 4]);
            for value in random.iter_mut() {
                OsRng.try_fill_bytes(value).map_err(error)?;
                if values.contains(value) {
                    return Err(MemberError::Sealed);
                }
                values.push(*value);
            }
            let inbox = OwnerInbox {
                route: RelayRoute {
                    pin: target.pin.clone(),
                    endpoint: target.endpoint.clone(),
                    mailbox: random[0],
                    append_revision: 1,
                },
                read: Secret32::from_bytes(random[1]),
                append: Secret32::from_bytes(random[2]),
                admin: Secret32::from_bytes(random[3]),
            };
            let request = encode_creation(&Creation {
                read_verifier: role_verifier(&inbox.route, 1, &inbox.read)?,
                append_verifier: role_verifier(&inbox.route, 2, &inbox.append)?,
                admin_verifier: role_verifier(&inbox.route, 3, &inbox.admin)?,
                quota: target.quota,
            })
            .map_err(error)?;
            config.pending.push(PendingRequest::Create {
                relay: config.own.len() as u16,
                request: Zeroizing::new(request),
            });
            config.own.push(inbox);
        }
        let descriptor = Descriptor::new(
            member.roster.vault,
            roster_digest(&member.roster).map_err(error)?,
            member.identity.public().id,
            1,
            config
                .own
                .iter()
                .map(|i| DescriptorRelay {
                    route: i.route.clone(),
                    append: Secret32::from_bytes(*i.append.as_bytes()),
                })
                .collect(),
        );
        config.self_wire = Some(
            seal_descriptor(
                &member.identity,
                &member.roster,
                &descriptor,
                &member.identity.public(),
            )
            .map_err(error)?
            .wire,
        );
        let mut operation = [0; 32];
        OsRng.try_fill_bytes(&mut operation).map_err(error)?;
        config.operation = Some(operation);
        config.provisioned = Some(vec![0; 3]);
        config.predecessor = db.config_reference().map_err(error)?;
        self.save_revision(db, member, Self::next_revision(db)?, &config)
    }
    fn recover_provision(&self, db: &mut ClientStore, member: &LoadedMember) -> MemberResult<()> {
        let prior = self.load(db, member)?.ok_or(MemberError::Sealed)?;
        if prior.provisioned.is_none() || prior.operation.is_none() {
            return Err(MemberError::Sealed);
        }
        let revision = Self::next_revision(db)?;
        let reference = ConfigReference::new(revision, [0; 32]).map_err(error)?;
        let path = self.root.join(reference.file_name());
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(MemberError::Io),
            Ok(_) => {
                let raw = bounded_read(&path, MAX_SEALED, true)?;
                let candidate = LocalConfig::decode(member, revision, &unseal(&raw, &self.pass)?)?;
                if !orphan_authority(member, &prior, &candidate) {
                    return Err(MemberError::Sealed);
                }
                self.save_revision(db, member, revision, &candidate)?;
                Ok(())
            }
        }
    }
    pub async fn provision(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
        http: &loki_relay_client::RelayHttp,
        capabilities: &[Secret32],
    ) -> MemberResult<ClientConfig> {
        if capabilities.len() != 3 {
            return Err(MemberError::Bounds);
        }
        self.recover_provision(db, member)?;
        for index in 0..3 {
            let mut config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
            if config.rotated.is_some() {
                continue;
            }
            if config.provisioned.as_ref().ok_or(MemberError::Sealed)?[index] != 0 {
                continue;
            }
            let request = config
                .pending
                .iter()
                .find_map(|p| match p {
                    PendingRequest::Create { relay, request } if usize::from(*relay) == index => {
                        Some(request)
                    }
                    _ => None,
                })
                .ok_or(MemberError::Sealed)?;
            let result = http
                .create(&config.own[index].route, &capabilities[index], request)
                .await
                .map_err(error)?;
            config.provisioned.as_mut().ok_or(MemberError::Sealed)?[index] = result.append_revision;
            if config.provisioned.as_ref().unwrap().iter().all(|r| *r == 1) {
                let auth = open_descriptor(
                    &member.identity,
                    &member.roster,
                    config.self_wire.as_ref().ok_or(MemberError::Sealed)?,
                )
                .map_err(error)?;
                config.couriers = member
                    .roster
                    .members
                    .iter()
                    .filter(|m| m.id != member.identity.public().id)
                    .map(|peer| super::CourierFile::prepare(member, &auth, peer))
                    .collect::<MemberResult<Vec<_>>>()?;
            }
            config.predecessor = db.config_reference().map_err(error)?;
            self.save_revision(db, member, Self::next_revision(db)?, &config)?;
        }
        self.routing(db, member)
    }
    pub fn routing(&self, db: &ClientStore, member: &LoadedMember) -> MemberResult<ClientConfig> {
        let config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
        if !config.pending.is_empty()
            && (config
                .provisioned
                .as_ref()
                .is_none_or(|r| r.iter().any(|v| *v != 1))
                || config.couriers.len() != member.roster.members.len() - 1)
        {
            return Err(MemberError::Sealed);
        }
        if rotation_blocks_routing(&config) {
            return Err(MemberError::Sealed);
        }
        config.authenticated(member)
    }
    pub fn accept_peer(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
        wire: &[u8],
    ) -> MemberResult<ClientConfig> {
        let mut config = self.load(db, member)?.unwrap_or_else(LocalConfig::empty);
        config.import(member, wire)?;
        config.predecessor = db.config_reference().map_err(error)?;
        self.save_revision(db, member, Self::next_revision(db)?, &config)?;
        self.routing(db, member)
    }
    pub fn publish_provision(
        &self,
        db: &ClientStore,
        member: &LoadedMember,
        directory: &Path,
    ) -> MemberResult<Vec<PathBuf>> {
        self.routing(db, member)?;
        let config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
        if config
            .provisioned
            .as_ref()
            .is_none_or(|r| r.iter().any(|v| *v != 1))
            || config.couriers.len() != member.roster.members.len() - 1
        {
            return Err(MemberError::Sealed);
        }
        config
            .couriers
            .iter()
            .map(|c| c.publish(directory))
            .collect()
    }
    fn current_rotation(
        &self,
        db: &ClientStore,
        member: &LoadedMember,
        config: &LocalConfig,
    ) -> MemberResult<Option<ConfigReference>> {
        if !authoritative_rotation(member, config)? {
            return Ok(None);
        }
        Ok(Some(
            db.config_reference()
                .map_err(error)?
                .ok_or(MemberError::Sealed)?,
        ))
    }
    fn write_rotation_generation(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
        mut config: LocalConfig,
    ) -> MemberResult<ConfigReference> {
        use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
        use rand_core::{OsRng, RngCore};
        let replacing = if config.rotated.is_some() {
            if !generation_complete(member, &config)? {
                return Err(MemberError::Sealed);
            }
            true
        } else {
            let results = config.provisioned.clone().ok_or(MemberError::Sealed)?;
            if config.own.len() != 3
                || results.len() != 3
                || config.couriers.len() != member.roster.members.len() - 1
                || config.self_wire.is_none()
                || creation_requests(&config).len() != 3
                || config.operation.is_none()
                || results.iter().zip(&config.own).any(|(result, inbox)| {
                    *result == 0
                        || *result != inbox.route.append_revision
                        || *result > i64::MAX as u64
                })
                || !rotation_requests(&config).is_empty()
            {
                return Err(MemberError::Sealed);
            }
            false
        };
        if replacing {
            config
                .pending
                .retain(|pending| matches!(pending, PendingRequest::Create { .. }));
        }
        let mut drawn = Zeroizing::new(Vec::<Id32>::new());
        for _ in 0..3 {
            let mut append = Zeroizing::new([0u8; 32]);
            OsRng.try_fill_bytes(append.as_mut()).map_err(error)?;
            let existing = config.own.iter().any(|inbox| {
                inbox.route.mailbox == *append
                    || inbox.read.as_bytes() == &*append
                    || inbox.append.as_bytes() == &*append
                    || inbox.admin.as_bytes() == &*append
            });
            if existing || drawn.iter().any(|value| *value == *append) {
                return Err(MemberError::Sealed);
            }
            drawn.push(*append);
        }
        for index in 0..3 {
            let secret = Secret32::from_bytes(drawn[index]);
            let revision = config.own[index]
                .route
                .append_revision
                .checked_add(1)
                .filter(|revision| *revision <= i64::MAX as u64)
                .ok_or(MemberError::Bounds)?;
            let request = encode_append_update(&AppendUpdate {
                revision,
                verifier: role_verifier(&config.own[index].route, 2, &secret)?,
            })
            .map_err(error)?;
            config.pending.push(PendingRequest::Rotate {
                relay: index as u16,
                append: secret,
                request: Zeroizing::new(request),
            });
        }
        config.rotated = Some(vec![0; 3]);
        config.predecessor = db.config_reference().map_err(error)?;
        self.save_revision(db, member, Self::next_revision(db)?, &config)
    }
    pub fn prepare_rotation(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
    ) -> MemberResult<ConfigReference> {
        self.recover_provision(db, member)?;
        let config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
        if let Some(reference) = self.current_rotation(db, member, &config)? {
            return Ok(reference);
        }
        self.write_rotation_generation(db, member, config)
    }
    pub fn prepare_next_rotation(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
    ) -> MemberResult<ConfigReference> {
        self.recover_provision(db, member)?;
        let config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
        if config.rotated.is_none() {
            return Err(MemberError::Sealed);
        }
        if !generation_complete(member, &config)? {
            return self
                .current_rotation(db, member, &config)?
                .ok_or(MemberError::Sealed);
        }
        self.write_rotation_generation(db, member, config)
    }
    pub async fn rotate(
        &self,
        db: &mut ClientStore,
        member: &LoadedMember,
        http: &loki_relay_client::RelayHttp,
    ) -> MemberResult<ClientConfig> {
        self.recover_provision(db, member)?;
        let mut failed = false;
        for index in 0..3 {
            let prepared = {
                let config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
                if config.rotated.as_ref().ok_or(MemberError::Sealed)?[index] != 0 {
                    None
                } else {
                    let expected = rotate_update(&config, index)?.revision;
                    let request = config
                        .pending
                        .iter()
                        .find_map(|pending| match pending {
                            PendingRequest::Rotate { relay, request, .. }
                                if usize::from(*relay) == index =>
                            {
                                Some(request.clone())
                            }
                            _ => None,
                        })
                        .ok_or(MemberError::Sealed)?;
                    let admin = Secret32::from_bytes(*config.own[index].admin.as_bytes());
                    Some((request, admin, config.own[index].route.clone(), expected))
                }
            };
            let Some((request, admin, route, expected)) = prepared else {
                continue;
            };
            match http.rotate(&route, &admin, &request).await {
                Ok(revision) if revision == expected => {
                    let mut config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
                    if config.rotated.as_ref().ok_or(MemberError::Sealed)?[index] != 0 {
                        continue;
                    }
                    config.rotated.as_mut().ok_or(MemberError::Sealed)?[index] = revision;
                    config.predecessor = db.config_reference().map_err(error)?;
                    self.save_revision(db, member, Self::next_revision(db)?, &config)?;
                }
                _ => failed = true,
            }
        }
        let mut config = self.load(db, member)?.ok_or(MemberError::Sealed)?;
        if install_rotation(member, &mut config)? {
            config.predecessor = db.config_reference().map_err(error)?;
            self.save_revision(db, member, Self::next_revision(db)?, &config)?;
        }
        if failed {
            return Err(MemberError::Sealed);
        }
        self.routing(db, member)
    }
}
