use crate::{root::Root, Capability, RelayError, RelayResult, Role};
use loki_relay_protocol::{
    canonical::{self, Value},
    challenge::{self, ChallengeResponse},
    envelope,
    http::{decode_append_update, decode_creation, NamespaceAction},
    nonce::{self, Claimant, ClaimProof, NonceReceipt},
    receipt,
    types::{CreationResult, Id32, Object, ReceiptBody, RelayPin, MAX_MEMBERS},
};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::{Digest, Sha256};
use std::path::Path;

const SCHEMA: &str = include_str!("schema.sql");
const MAILBOX_SCHEMA: &str = "-- Mailbox schema is installed transactionally on first provisioning, including existing roots.\n";

const OBJECT_SCHEMA: &str =
    "-- Object schema is installed after mailbox authentication, including existing roots.\n";
const NONCE_SCHEMA: &str =
    "-- First-writer-wins nonce claims survive relay restarts for the lifetime of this root.\n";
// Budget for row keys, hashes, SQLite record headers and B-tree overhead, in addition to wire.
const NONCE_ROW_BYTES: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub total_bytes: u64,
    pub mailbox_bytes: u64,
    pub mailbox_count: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Pragmas {
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
    pub busy_timeout: i64,
    pub fullfsync: i64,
}

fn open_committed_readonly(path: &Path) -> RelayResult<Connection> {
    // SQLITE_OPEN_NOFOLLOW rejects any symlink in the full path. Resolve
    // directory symlinks such as /var, and still refuse a symlink database file.
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(RelayError::StorageUnavailable);
    }
    let connection = Connection::open_with_flags(
        path.canonicalize()?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(std::time::Duration::from_millis(5000))?;
    connection.pragma_update(None, "query_only", "ON")?;
    Ok(connection)
}

fn setup_state(connection: &Connection, mailbox: Id32) -> RelayResult<Option<(u64, bool)>> {
    let installed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='setup_namespaces')",
        [],
        |r| r.get(0),
    )?;
    if !installed {
        return Ok(None);
    }
    Ok(connection
        .query_row(
            "SELECT expires,retired FROM setup_namespaces WHERE mailbox=?1",
            [mailbox.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}
// Separate from setup_namespaces: its autonomous janitor cannot know whether
// admission durably certified activation just before the deadline.
const PAYMENT_RESERVATIONS: &str = "CREATE TABLE IF NOT EXISTS payment_reservations (
    mailbox BLOB PRIMARY KEY NOT NULL CHECK(length(mailbox)=32),
    creation_digest BLOB NOT NULL CHECK(length(creation_digest)=32),
    expires INTEGER NOT NULL CHECK(expires>0),
    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2)
) STRICT;";
const PAYMENT_RESERVED: u16 = 0;
const PAYMENT_PROMOTED: u16 = 1;
const PAYMENT_RETIRED: u16 = 2;

fn payment_state(
    connection: &Connection,
    mailbox: Id32,
) -> RelayResult<Option<(Vec<u8>, u64, u16)>> {
    let installed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='payment_reservations')", [], |r| r.get(0),
    )?;
    if !installed {
        return Ok(None);
    }
    Ok(connection
        .query_row(
            "SELECT creation_digest,expires,state FROM payment_reservations WHERE mailbox=?1",
            [mailbox.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?)
}
fn permits_nonce_history(connection: &Connection, mailbox: Id32) -> RelayResult<bool> {
    Ok(setup_state(connection, mailbox)?.is_none()
        && payment_state(connection, mailbox)?.is_none_or(|(_, _, state)| state == PAYMENT_PROMOTED))
}
fn current_time() -> RelayResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|n| n.as_secs())
        .map_err(|_| RelayError::StorageUnavailable)
}
fn setup_active(connection: &Connection, mailbox: Id32) -> RelayResult<()> {
    if let Some((expires, retired)) = setup_state(connection, mailbox)? {
        if retired || current_time()? >= expires {
            return Err(RelayError::Capability);
        }
    }
    if let Some((_, expires, state)) = payment_state(connection, mailbox)? {
        if state == PAYMENT_RETIRED || (state == PAYMENT_RESERVED && current_time()? >= expires) {
            return Err(RelayError::Capability);
        }
    }
    Ok(())
}

fn authenticate_mailbox(
    connection: &Connection,
    mailbox: Id32,
    role: Role,
    capability: &Capability,
) -> RelayResult<()> {
    let provisioned: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailboxes')",
        [],
        |row| row.get(0),
    )?;
    if !provisioned {
        return Err(RelayError::Capability);
    }
    let sql = match role {
        Role::Read => "SELECT read_verifier FROM mailboxes WHERE id=?1",
        Role::Append => "SELECT append_verifier FROM mailboxes WHERE id=?1",
        Role::Admin => "SELECT admin_verifier FROM mailboxes WHERE id=?1",
    };
    let verifier: Option<Vec<u8>> = connection
        .query_row(sql, [mailbox.as_slice()], |row| row.get(0))
        .optional()?;
    let verifier: Id32 = verifier
        .ok_or(RelayError::Capability)?
        .try_into()
        .map_err(|_| RelayError::StorageUnavailable)?;
    setup_active(connection, mailbox)?;
    if !capability.verify(role, mailbox, &verifier) {
        return Err(RelayError::Capability);
    }
    Ok(())
}

fn authenticate_nonce(
    connection: &Connection,
    pin: &RelayPin,
    mailbox: Id32,
    cid: Id32,
    challenge: Id32,
    wire: &[u8],
    proof: &ClaimProof,
) -> RelayResult<(u64, u64)> {
    let enrolled: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='nonce_claimants')",
        [],
        |r| r.get(0),
    )?;
    if !enrolled || !permits_nonce_history(connection, mailbox)? {
        return Err(RelayError::Capability);
    }
    let who = proof.claimant;
    let accounting = connection.query_row(
        "SELECT used_bytes,quota FROM nonce_claimants WHERE mailbox=?1 AND vault=?2 AND slot=?3 AND signing_key=?4",
        params![mailbox.as_slice(), who.vault.as_slice(), who.slot, who.key.as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?.ok_or(RelayError::Capability)?;
    ed25519_dalek::VerifyingKey::from_bytes(&who.key)
        .and_then(|key| {
            key.verify_strict(
                &nonce::claim_input(who, pin, mailbox, cid, challenge, wire),
                &ed25519_dalek::Signature::from_bytes(&proof.signature),
            )
        })
        .map_err(|_| RelayError::Capability)?;
    Ok(accounting)
}

fn configure(connection: &Connection) -> RelayResult<()> {
    connection.busy_timeout(std::time::Duration::from_millis(5000))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    #[cfg(target_os = "macos")]
    connection.pragma_update(None, "fullfsync", "ON")?;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub struct StoredResult {
    pub created: bool,
    pub sequence: u64,
    pub receipt: Vec<u8>,
}

/// Advisory classification of a committed snapshot. `put` repeats every check.
#[derive(Debug, Eq, PartialEq)]
pub enum PutClass {
    Duplicate(StoredResult),
    Fresh,
}

/// Hash-only view of the committed snapshot. Exact bytes stay in `classify_committed`.
#[derive(Debug, Eq, PartialEq)]
pub enum HashPresence {
    Fresh,
    Committed,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PutFault {
    PauseBeforeCommit,
    PauseAfterCommit,
    ObserveFull,
    LostReply,
    CommitError,
    AfterInsert,
    PreInsert,
}

#[cfg(test)]
fn bounded_put_barrier() {
    let marker = std::env::var_os("RELAY_36_CHILD_MARKER").expect("unit-test marker");
    std::fs::write(marker, b"at barrier").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(10));
}

pub struct RelayStore {
    // Close SQLite before releasing the identity lock.
    connection: Connection,
    root: Root,
    #[cfg(test)]
    put_fault: Option<PutFault>,
    #[cfg(test)]
    page_barrier: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}
impl Limits {
    fn validate(self) -> RelayResult<()> {
        if [self.total_bytes, self.mailbox_bytes, self.mailbox_count]
            .into_iter()
            .any(|value| value > i64::MAX as u64)
        {
            return Err(RelayError::MalformedRequest);
        }
        Ok(())
    }
}

impl RelayStore {
    /// Admit a vault member from a trusted roster. The offline operator reserves a separate
    /// claim budget up front, so a claimant cannot consume another member's allotment.
    pub fn enroll_nonce_claimant(
        &mut self,
        mailbox: Id32,
        who: Claimant,
        quota: u64,
    ) -> RelayResult<()> {
        if who.vault == [0; 32] || !(1..=MAX_MEMBERS).contains(&who.slot) || quota <= NONCE_ROW_BYTES
            || ed25519_dalek::VerifyingKey::from_bytes(&who.key).map_or(true, |key| key.is_weak())
        {
            return Err(RelayError::MalformedRequest);
        }
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !permits_nonce_history(&tx, mailbox)? {
            return Err(RelayError::Capability);
        }
        let limit: u64 = tx.query_row(
            "SELECT byte_quota FROM mailboxes WHERE id=?1", [mailbox.as_slice()], |r| r.get(0),
        ).optional()?.ok_or(RelayError::Capability)?;
        let relay_limit: u64 = tx.query_row("SELECT total_bytes FROM metadata", [], |r| r.get(0))?;
        tx.execute_batch(SCHEMA.split_once(NONCE_SCHEMA).ok_or(RelayError::StorageUnavailable)?.1)?;
        let prior: Option<(Vec<u8>, u64)> = tx.query_row(
            "SELECT signing_key,quota FROM nonce_claimants WHERE mailbox=?1 AND vault=?2 AND slot=?3",
            params![mailbox.as_slice(), who.vault.as_slice(), who.slot], |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        let prior_quota = match prior {
            Some((key, old_quota)) if key == who.key && old_quota <= quota => old_quota,
            Some(_) => return Err(RelayError::Conflict),
            None => 0,
        };
        // Legacy rows have no trustworthy owner. Charge their full storage to both shared
        // budgets without rewriting them or resetting the old object-accounting counters.
        for (scope, limit) in [(Some(mailbox.as_slice()), limit), (None, relay_limit)] {
            let reserved: u64 = tx.query_row(
                "SELECT (SELECT coalesce(sum(quota),0) FROM nonce_claimants WHERE ?1 IS NULL OR mailbox=?1)
                      + (SELECT coalesce(sum(length(wire)+?2),0) FROM nonce_uses WHERE ?1 IS NULL OR mailbox=?1)",
                params![scope, NONCE_ROW_BYTES], |r| r.get(0),
            )?;
            reserved.checked_add(quota - prior_quota).filter(|n| *n <= limit)
                .ok_or(RelayError::QuotaExhausted)?;
        }
        tx.execute(
            "INSERT INTO nonce_claimants (mailbox,vault,slot,signing_key,quota,used_bytes)
             VALUES (?1,?2,?3,?4,?5,0) ON CONFLICT (mailbox,vault,slot) DO UPDATE SET quota=excluded.quota",
            params![mailbox.as_slice(), who.vault.as_slice(), who.slot, who.key.as_slice(), quota],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn authenticate_committed_nonce(
        root: &Path,
        mailbox: Id32,
        cid: Id32,
        challenge: Id32,
        wire: &[u8],
        proof: &ClaimProof,
    ) -> RelayResult<()> {
        let connection = open_committed_readonly(&root.join("relay.sqlite3"))?;
        let pin = connection.query_row(
            "SELECT receipt_public_key,run_id FROM metadata WHERE singleton=1",
            [],
            |row| Ok(RelayPin { key: row.get(0)?, run: row.get(1)? }),
        )?;
        authenticate_nonce(&connection, &pin, mailbox, cid, challenge, wire, proof)?;
        Ok(())
    }

    /// Atomically claim a commitment ID. A duplicate is reported as `created=false`,
    /// even when its encrypted record is identical: it must never authorize re-signing.
    pub fn claim_nonce(
        &mut self,
        mailbox: Id32,
        cid: Id32,
        challenge: Id32,
        wire: &[u8],
        proof: &ClaimProof,
    ) -> RelayResult<(bool, Vec<u8>)> {
        if wire.is_empty() || wire.len() > nonce::MAX_RECORD || challenge == [0; 32] {
            return Err(RelayError::MalformedRequest);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pin = RelayPin { key: self.root.public_key, run: self.root.run_id };
        let (used, quota) = authenticate_nonce(&tx, &pin, mailbox, cid, challenge, wire, proof)?;
        let who = proof.claimant;
        let record_hash: Id32 = Sha256::digest(wire).into();
        let old: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT record_hash,wire FROM nonce_uses WHERE mailbox=?1 AND cid=?2
                 UNION ALL
                 SELECT record_hash,wire FROM nonce_claims WHERE mailbox=?1 AND cid=?2 AND vault=?3 AND slot=?4 LIMIT 1",
                params![mailbox.as_slice(), cid.as_slice(), who.vault.as_slice(), who.slot],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let created =
            match old {
                Some((hash, prior)) => {
                    if hash != record_hash || prior != wire {
                        return Err(RelayError::Conflict);
                    }
                    false
                }
                None => {
                    let next_used = used.checked_add(wire.len() as u64 + NONCE_ROW_BYTES)
                        .filter(|n| *n <= quota).ok_or(RelayError::QuotaExhausted)?;
                    tx.execute(
                        "INSERT INTO nonce_claims (mailbox,vault,slot,cid,record_hash,wire) VALUES (?1,?2,?3,?4,?5,?6)",
                        params![mailbox.as_slice(), who.vault.as_slice(), who.slot, cid.as_slice(), record_hash.as_slice(), wire],
                    )?;
                    tx.execute(
                        "UPDATE nonce_claimants SET used_bytes=?1 WHERE mailbox=?2 AND vault=?3 AND slot=?4",
                        params![next_used, mailbox.as_slice(), who.vault.as_slice(), who.slot],
                    )?;
                    true
                }
            };
        let body = nonce::encode_body(&NonceReceipt {
            pin,
            mailbox,
            vault: who.vault,
            slot: who.slot,
            cid,
            record_hash,
            challenge,
            created,
        })?;
        let signature = self.root.sign_nonce_receipt(&body)?;
        let receipt = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_vec()),
        ]))?;
        tx.commit()?;
        Ok((created, receipt))
    }
    /// Create a new root with a fresh receipt seed and caller-supplied provisioning material.
    /// The caller computes the protocol provisioning verifier; this layer only persists it.
    pub fn init(
        root: &Path,
        run_id: [u8; 32],
        relay_url: &str,
        provisioning_secret: &[u8; 32],
        provisioning_verifier: [u8; 32],
        limits: Limits,
    ) -> RelayResult<Self> {
        limits.validate()?;
        let root = Root::init(root, run_id, relay_url, provisioning_secret)?;
        let mut connection = Connection::open(root.path.join("relay.sqlite3"))?;
        configure(&connection)?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            SCHEMA
                .split_once(MAILBOX_SCHEMA)
                .ok_or(RelayError::StorageUnavailable)?
                .0,
        )?;
        transaction.execute(
            "INSERT INTO metadata VALUES (1,1,1,?1,?2,?3,?4,?5,?6,0)",
            params![
                run_id.as_slice(),
                root.public_key.as_slice(),
                provisioning_verifier.as_slice(),
                limits.total_bytes,
                limits.mailbox_bytes,
                limits.mailbox_count
            ],
        )?;
        transaction.commit()?;
        std::fs::File::open(&root.path)?.sync_all()?;
        Ok(Self {
            root,
            connection,
            #[cfg(test)]
            put_fault: None,
            #[cfg(test)]
            page_barrier: None,
        })
    }
    /// Open existing state without creating a database or replacing secrets.
    pub fn open(root: &Path, limits: Limits) -> RelayResult<Self> {
        limits.validate()?;
        let root = Root::open(root)?;
        let connection = Connection::open_with_flags(
            root.path.join("relay.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM metadata", [], |row| row.get(0))?;
        if count != 1 {
            return Err(RelayError::StorageUnavailable);
        }
        let run_id: Vec<u8> =
            connection.query_row("SELECT run_id FROM metadata WHERE singleton=1", [], |row| {
                row.get(0)
            })?;
        if run_id != root.run_id {
            return Err(RelayError::StorageUnavailable);
        }
        let key: Vec<u8> = connection.query_row(
            "SELECT receipt_public_key FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if key != root.public_key {
            return Err(RelayError::StorageUnavailable);
        }
        let verifier: Vec<u8> = connection.query_row(
            "SELECT provisioning_verifier FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if verifier.len() != 32 {
            return Err(RelayError::StorageUnavailable);
        }
        let version: i64 = connection.query_row(
            "SELECT schema_version FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version != 1 {
            return Err(RelayError::StorageUnavailable);
        }
        let protocol: i64 = connection.query_row(
            "SELECT protocol_version FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if protocol != 1 {
            return Err(RelayError::StorageUnavailable);
        }
        let persisted: (u64, u64, u64) = connection.query_row(
            "SELECT total_bytes,mailbox_bytes,mailbox_count FROM metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if persisted
            != (
                limits.total_bytes,
                limits.mailbox_bytes,
                limits.mailbox_count,
            )
        {
            return Err(RelayError::StorageUnavailable);
        }
        let used: u64 = connection.query_row(
            "SELECT used_bytes FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if used > limits.total_bytes {
            return Err(RelayError::StorageUnavailable);
        }
        configure(&connection)?;
        let has_setup: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='setup_namespaces')",
            [],
            |row| row.get(0),
        )?;
        if has_setup {
            connection.execute_batch(include_str!("setup_schema.sql"))?;
        }
        Ok(Self {
            root,
            connection,
            #[cfg(test)]
            put_fault: None,
            #[cfg(test)]
            page_barrier: None,
        })
    }
    pub fn pragmas(&self) -> RelayResult<Pragmas> {
        let integer = |name| {
            self.connection
                .pragma_query_value(None, name, |row| row.get(0))
        };
        Ok(Pragmas {
            journal_mode: self
                .connection
                .pragma_query_value(None, "journal_mode", |row| row.get(0))?,
            synchronous: integer("synchronous")?,
            foreign_keys: integer("foreign_keys")?,
            busy_timeout: integer("busy_timeout")?,
            fullfsync: integer("fullfsync")?,
        })
    }
    pub fn run_id(&self) -> [u8; 32] {
        self.root.run_id
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.root.public_key
    }

    pub fn challenge(&self, nonce: Id32) -> RelayResult<Vec<u8>> {
        let body = challenge::encode_body(&ChallengeResponse {
            pin: RelayPin {
                key: self.root.public_key,
                run: self.root.run_id,
            },
            endpoint: self.root.endpoint.clone(),
            challenge: nonce,
        })?;
        let signature = self.root.sign_challenge(&body)?;
        Ok(canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_vec()),
        ]))?)
    }

    pub fn rotate(
        &mut self,
        mailbox: Id32,
        request: &[u8],
        admin: &Capability,
    ) -> RelayResult<u64> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let provisioned: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailboxes')",
            [],
            |r| r.get(0),
        )?;
        if !provisioned {
            return Err(RelayError::Capability);
        }
        let current: Option<(Vec<u8>, u64, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT admin_verifier,append_revision,append_update FROM mailboxes WHERE id=?1",
                [mailbox.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (verifier, revision, last_update) = current.ok_or(RelayError::Capability)?;
        let verifier: Id32 = verifier
            .try_into()
            .map_err(|_| RelayError::StorageUnavailable)?;
        setup_active(&transaction, mailbox)?;
        if !admin.verify(Role::Admin, mailbox, &verifier) {
            return Err(RelayError::Capability);
        }
        let update = decode_append_update(request)?;
        if update.revision == revision && last_update.as_deref() == Some(request) {
            transaction.commit()?;
            return Ok(revision);
        }
        let next = revision
            .checked_add(1)
            .filter(|n| revision > 0 && *n <= i64::MAX as u64)
            .ok_or(RelayError::Conflict)?;
        if update.revision != next {
            return Err(RelayError::Conflict);
        }
        transaction.execute(
            "UPDATE mailboxes SET append_verifier=?1,append_revision=?2,append_update=?3 WHERE id=?4",
            params![update.verifier.as_slice(), update.revision, request, mailbox.as_slice()],
        )?;
        transaction.commit()?;
        Ok(update.revision)
    }

    pub fn put(
        &mut self,
        mailbox: Id32,
        object: &Object,
        append: &Capability,
    ) -> RelayResult<StoredResult> {
        #[cfg(test)]
        let fault = self.put_fault.take();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let provisioned: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailboxes')",
            [],
            |r| r.get(0),
        )?;
        if !provisioned {
            return Err(RelayError::Capability);
        }
        let verifier: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT append_verifier FROM mailboxes WHERE id=?1",
                [mailbox.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let verifier: Id32 = verifier
            .ok_or(RelayError::Capability)?
            .try_into()
            .map_err(|_| RelayError::StorageUnavailable)?;
        setup_active(&transaction, mailbox)?;
        if !append.verify(Role::Append, mailbox, &verifier) {
            return Err(RelayError::Capability);
        }
        transaction.execute_batch(
            SCHEMA
                .split_once(OBJECT_SCHEMA)
                .ok_or(RelayError::StorageUnavailable)?
                .1,
        )?;
        let existing: Option<(Vec<u8>, u64, Vec<u8>)> = transaction
            .query_row(
                "SELECT wire,sequence,receipt FROM objects WHERE mailbox=?1 AND hash=?2",
                params![mailbox.as_slice(), object.hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((wire, sequence, receipt)) = existing {
            if wire != object.wire {
                return Err(RelayError::Conflict);
            }
            transaction.commit()?;
            return Ok(StoredResult {
                created: false,
                sequence,
                receipt,
            });
        }
        if object.wire.len() > envelope::MAX_WIRE_LEN {
            return Err(RelayError::ObjectTooLarge);
        }
        envelope::validate_wire(&object.wire)?;
        if <Id32>::from(Sha256::digest(&object.wire)) != object.hash {
            return Err(RelayError::MalformedRequest);
        }
        let (used, quota, sequence): (u64, u64, u64) = transaction.query_row(
            "SELECT used_bytes,byte_quota,next_sequence FROM mailboxes WHERE id=?1",
            [mailbox.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let (total_used, total_quota): (u64, u64) = transaction.query_row(
            "SELECT used_bytes,total_bytes FROM metadata WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let length = object.wire.len() as u64;
        let add = |used: u64, quota: u64| {
            used.checked_add(length)
                .filter(|n| *n <= quota && *n <= i64::MAX as u64)
                .ok_or(RelayError::QuotaExhausted)
        };
        let mailbox_used = add(used, quota)?;
        let total_used = add(total_used, total_quota)?;
        let next = sequence
            .checked_add(1)
            .filter(|n| sequence > 0 && *n <= i64::MAX as u64)
            .ok_or(RelayError::StorageUnavailable)?;
        let body = receipt::encode_body(&ReceiptBody {
            pin: RelayPin {
                key: self.root.public_key,
                run: self.root.run_id,
            },
            mailbox,
            hash: object.hash,
            wire_length: length,
            sequence,
            retention: receipt::RETENTION_RUN,
        })?;
        let signature = self.root.sign_receipt(&body)?;
        let receipt = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_vec()),
        ]))?;
        #[cfg(test)]
        if fault == Some(PutFault::PreInsert) {
            return Err(RelayError::StorageUnavailable);
        }
        let insert_result = transaction.execute(
            "INSERT INTO objects (mailbox,hash,wire,wire_length,sequence,receipt) VALUES (?1,?2,?3,?4,?5,?6)",
            params![mailbox.as_slice(),object.hash.as_slice(),&object.wire,length,sequence,&receipt],
        );
        #[cfg(test)]
        if fault == Some(PutFault::ObserveFull) {
            assert!(
                matches!(&insert_result, Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DiskFull),
                "expected actual SQLITE_FULL, got {insert_result:?}"
            );
            eprintln!("writing connection returned SQLITE_FULL (13)");
        }
        insert_result?;
        #[cfg(test)]
        if fault == Some(PutFault::AfterInsert) {
            return Err(RelayError::StorageUnavailable);
        }
        transaction.execute(
            "UPDATE mailboxes SET used_bytes=?1,next_sequence=?2 WHERE id=?3",
            params![mailbox_used, next, mailbox.as_slice()],
        )?;
        transaction.execute(
            "UPDATE metadata SET used_bytes=?1 WHERE singleton=1",
            [total_used],
        )?;
        #[cfg(test)]
        if fault == Some(PutFault::PauseBeforeCommit) {
            bounded_put_barrier();
        }
        #[cfg(test)]
        if fault == Some(PutFault::CommitError) {
            // Simulate a failed commit before SQLite commits; this is not an I/O fault.
            transaction.rollback()?;
            return Err(RelayError::StorageUnavailable);
        }
        transaction.commit()?;
        #[cfg(test)]
        if fault == Some(PutFault::PauseAfterCommit) {
            bounded_put_barrier();
        }
        #[cfg(test)]
        if fault == Some(PutFault::LostReply) {
            return Err(RelayError::StorageUnavailable);
        }
        Ok(StoredResult {
            created: true,
            sequence,
            receipt,
        })
    }

    /// Advisory ingress check; the writer still enforces current operation-specific authority.
    pub(crate) fn authenticate_committed(
        root: &Path,
        target: Option<(Id32, Role)>,
        capability: &Capability,
    ) -> RelayResult<()> {
        let connection = open_committed_readonly(&root.join("relay.sqlite3"))?;
        if let Some((mailbox, role)) = target {
            return authenticate_mailbox(&connection, mailbox, role, capability);
        }
        let (run, verifier): (Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT run_id,provisioning_verifier FROM metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let run = run.try_into().map_err(|_| RelayError::StorageUnavailable)?;
        let verifier = verifier.try_into().map_err(|_| RelayError::StorageUnavailable)?;
        if !capability.verify_provision(run, &verifier) {
            return Err(RelayError::Capability);
        }
        Ok(())
    }

    /// Read the last committed snapshot on a short-lived connection.
    /// Does not take the root lock, insert, allocate a sequence, or charge quota.
    /// A missing object table is fresh so the first authenticated put can install it.
    pub fn classify_committed(
        root: &Path,
        mailbox: Id32,
        object: &Object,
        append: &Capability,
    ) -> RelayResult<PutClass> {
        let connection = open_committed_readonly(&root.join("relay.sqlite3"))?;
        authenticate_mailbox(&connection, mailbox, Role::Append, append)?;
        let objects: bool = connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='objects')",
            [],
            |row| row.get(0),
        )?;
        if !objects {
            return Ok(PutClass::Fresh);
        }
        let existing: Option<(Vec<u8>, u64, Vec<u8>)> = connection
            .query_row(
                "SELECT wire,sequence,receipt FROM objects WHERE mailbox=?1 AND hash=?2",
                params![mailbox.as_slice(), object.hash.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((wire, sequence, receipt)) = existing {
            if wire != object.wire {
                return Err(RelayError::Conflict);
            }
            return Ok(PutClass::Duplicate(StoredResult {
                created: false,
                sequence,
                receipt,
            }));
        }
        Ok(PutClass::Fresh)
    }

    /// Auth-first presence check. A missing object table is fresh, so the first put can install it.
    /// This does not compare bytes, allocate a sequence, or charge quota.
    pub fn classify_committed_hash(
        root: &Path,
        mailbox: Id32,
        hash: Id32,
        append: &Capability,
    ) -> RelayResult<HashPresence> {
        let connection = open_committed_readonly(&root.join("relay.sqlite3"))?;
        authenticate_mailbox(&connection, mailbox, Role::Append, append)?;
        let objects: bool = connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='objects')",
            [],
            |row| row.get(0),
        )?;
        if !objects {
            return Ok(HashPresence::Fresh);
        }
        let present: bool = connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM objects WHERE mailbox=?1 AND hash=?2)",
            params![mailbox.as_slice(), hash.as_slice()],
            |row| row.get(0),
        )?;
        Ok(if present {
            HashPresence::Committed
        } else {
            HashPresence::Fresh
        })
    }

    pub fn get(&mut self, mailbox: Id32, hash: Id32, read: &Capability) -> RelayResult<Vec<u8>> {
        let transaction = self.connection.transaction()?;
        let provisioned: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailboxes')",
            [],
            |r| r.get(0),
        )?;
        if !provisioned {
            return Err(RelayError::Capability);
        }
        let verifier: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT read_verifier FROM mailboxes WHERE id=?1",
                [mailbox.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let verifier: Id32 = verifier
            .ok_or(RelayError::Capability)?
            .try_into()
            .map_err(|_| RelayError::StorageUnavailable)?;
        setup_active(&transaction, mailbox)?;
        if !read.verify(Role::Read, mailbox, &verifier) {
            return Err(RelayError::Capability);
        }
        let installed: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='objects')",
            [],
            |r| r.get(0),
        )?;
        if !installed {
            return Err(RelayError::ObjectNotFound);
        }
        let wire = transaction
            .query_row(
                "SELECT wire FROM objects WHERE mailbox=?1 AND hash=?2",
                params![mailbox.as_slice(), hash.as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(RelayError::ObjectNotFound)?;
        transaction.commit()?;
        Ok(wire)
    }

    pub fn create(
        &mut self,
        mailbox: Id32,
        request: &[u8],
        provision: &Capability,
    ) -> RelayResult<CreationResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorize_provision(&transaction, self.root.run_id, provision)?;
        setup_active(&transaction, mailbox)?;
        install_mailboxes(&transaction)?;
        let result = create_mailbox(&transaction, self.root.run_id, mailbox, request)?;
        transaction.commit()?;
        Ok(result)
    }
}

fn authorize_provision(tx: &Transaction<'_>, run: Id32, provision: &Capability) -> RelayResult<()> {
    let expected: Vec<u8> = tx.query_row(
        "SELECT provisioning_verifier FROM metadata WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let expected: Id32 = expected
        .try_into()
        .map_err(|_| RelayError::StorageUnavailable)?;
    if !provision.verify_provision(run, &expected) {
        return Err(RelayError::Capability);
    }
    Ok(())
}

fn install_mailboxes(tx: &Transaction<'_>) -> RelayResult<()> {
    tx.execute_batch(
        SCHEMA
            .split_once(MAILBOX_SCHEMA)
            .ok_or(RelayError::StorageUnavailable)?
            .1,
    )?;
    Ok(())
}

fn create_mailbox(
    transaction: &Transaction<'_>,
    run: Id32,
    mailbox: Id32,
    request: &[u8],
) -> RelayResult<CreationResult> {
    let creation = decode_creation(request)?;
    let existing: Option<(Vec<u8>, u64, u64)> = transaction
        .query_row(
            "SELECT creation_request,byte_quota,append_revision FROM mailboxes WHERE id=?1",
            [mailbox.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((original, quota, append_revision)) = existing {
        if original != request {
            return Err(RelayError::Conflict);
        }
        return Ok(CreationResult {
            created: false,
            run,
            quota,
            append_revision,
        });
    }
    let (mailbox_bytes, total_bytes, mailbox_count): (u64, u64, u64) = transaction.query_row(
        "SELECT mailbox_bytes,total_bytes,mailbox_count FROM metadata WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let count: u64 =
        transaction.query_row("SELECT count(*) FROM mailboxes", [], |row| row.get(0))?;
    if creation.quota > mailbox_bytes || creation.quota > total_bytes || count >= mailbox_count {
        return Err(RelayError::QuotaExhausted);
    }
    transaction.execute(
        "INSERT INTO mailboxes VALUES (?1,?2,?3,?4,?5,1,NULL,?6,0,1)",
        params![
            mailbox.as_slice(),
            creation.read_verifier.as_slice(),
            creation.append_verifier.as_slice(),
            creation.admin_verifier.as_slice(),
            request,
            creation.quota
        ],
    )?;
    Ok(CreationResult {
        created: true,
        run,
        quota: creation.quota,
        append_revision: 1,
    })
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod fault_support;

#[cfg(test)]
mod fault_tests {
    use super::*;
    use crate::capability::{provisioning_verifier, verifier};
    use fault_support::Scratch;
    use loki_relay_protocol::{http::encode_creation, types::Creation};

    fn limits() -> Limits {
        Limits {
            total_bytes: 1_000_000,
            mailbox_bytes: 1_000_000,
            mailbox_count: 1,
        }
    }
    fn fixture() -> (Scratch, RelayStore) {
        let root = Scratch::new();
        let mut store = RelayStore::init(
            root.path(),
            [7; 32],
            "http://127.0.0.1:8000",
            &[8; 32],
            provisioning_verifier([7; 32], &[8; 32]),
            limits(),
        )
        .unwrap();
        let creation = encode_creation(&Creation {
            read_verifier: verifier(Role::Read, [1; 32], &[2; 32]),
            append_verifier: verifier(Role::Append, [1; 32], &[3; 32]),
            admin_verifier: verifier(Role::Admin, [1; 32], &[4; 32]),
            quota: limits().mailbox_bytes,
        })
        .unwrap();
        store
            .create([1; 32], &creation, &Capability::new([8; 32]))
            .unwrap();
        (root, store)
    }
    fn object(tag: u8, length: usize) -> Object {
        let mut wire = vec![tag; length];
        wire[..8].copy_from_slice(b"LOKIRLY1");
        wire[8] = 1;
        Object {
            hash: Sha256::digest(&wire).into(),
            wire,
        }
    }
    fn put(store: &mut RelayStore, object: &Object) -> RelayResult<StoredResult> {
        store.put([1; 32], object, &Capability::new([3; 32]))
    }

    #[test]
    fn nonce_claim_is_first_writer_wins_across_restart() {
        use ed25519_dalek::{Signer, SigningKey};
        let (root, mut store) = fixture();
        let key = SigningKey::from_bytes(&[2; 32]);
        let who = Claimant { vault: [6; 32], slot: 1, key: key.verifying_key().to_bytes() };
        let mailbox = [1; 32];
        let cid = [9; 32];
        let pin = RelayPin { key: store.public_key(), run: store.run_id() };
        let proof = |n, wire: &[u8]| ClaimProof {
            claimant: who,
            signature: key.sign(&nonce::claim_input(who, &pin, mailbox, cid, [n; 32], wire)).to_bytes(),
        };
        store.enroll_nonce_claimant(mailbox, who, 1024).unwrap();
        let (created, first) = store
            .claim_nonce(mailbox, cid, [7; 32], b"sealed record", &proof(7, b"sealed record"))
            .unwrap();
        assert!(created);
        let Value::Array(fields) = canonical::decode(&first, 512).unwrap() else {
            panic!()
        };
        let [Value::Bytes(body), Value::Bytes(_)] = fields.as_slice() else {
            panic!()
        };
        assert_eq!(nonce::decode_body(body).unwrap().challenge, [7; 32]);
        drop(store);
        let mut reopened = RelayStore::open(root.path(), limits()).unwrap();
        let (created, repeat) = reopened
            .claim_nonce(mailbox, cid, [8; 32], b"sealed record", &proof(8, b"sealed record"))
            .unwrap();
        assert!(!created);
        assert_ne!(first, repeat);
        assert_eq!(
            reopened.claim_nonce(mailbox, cid, [9; 32], b"other record", &proof(9, b"other record")),
            Err(RelayError::Conflict)
        );
        assert_eq!(
            reopened.claim_nonce(
                mailbox,
                cid,
                [9; 32],
                b"sealed record",
                &proof(7, b"sealed record")
            ),
            Err(RelayError::Capability)
        );
    }
    fn snapshot(store: &RelayStore) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        let counters: (u64,u64,u64,u64,u64) = store.connection.query_row(
            "SELECT (SELECT used_bytes FROM metadata),used_bytes,next_sequence,(SELECT coalesce(sum(wire_length),0) FROM objects),(SELECT coalesce(max(sequence),0)+1 FROM objects) FROM mailboxes",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).unwrap();
        assert_eq!(
            (counters.0, counters.1, counters.2),
            (counters.3, counters.3, counters.4),
            "atomic counters and next sequence"
        );
        let mut rows = store
            .connection
            .prepare("SELECT hash,wire,wire_length,sequence,receipt FROM objects ORDER BY sequence")
            .unwrap();
        let rows = rows
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u64>(2)?,
                    r.get::<_, u64>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (hash, wire, length, sequence, saved) = row.unwrap();
            assert_eq!(hash, Sha256::digest(&wire).to_vec());
            assert_eq!(length, wire.len() as u64);
            let Value::Array(fields) = canonical::decode(&saved, 512).unwrap() else {
                panic!("receipt array")
            };
            let [Value::Bytes(body), Value::Bytes(signature)] = fields.as_slice() else {
                panic!("receipt fields")
            };
            let mut signed = b"Loki_Relay_Stored_v1\0".to_vec();
            signed.extend_from_slice(&(body.len() as u32).to_be_bytes());
            signed.extend_from_slice(body);
            ed25519_dalek::VerifyingKey::from_bytes(&store.public_key())
                .unwrap()
                .verify_strict(
                    &signed,
                    &ed25519_dalek::Signature::from_slice(signature).unwrap(),
                )
                .unwrap();
            assert_eq!(
                receipt::decode_body(body).unwrap(),
                ReceiptBody {
                    pin: RelayPin {
                        key: store.public_key(),
                        run: store.run_id()
                    },
                    mailbox: [1; 32],
                    hash: hash.try_into().unwrap(),
                    wire_length: length,
                    sequence,
                    retention: 1
                }
            );
        }
        [
            "SELECT * FROM metadata ORDER BY singleton",
            "SELECT * FROM mailboxes ORDER BY id",
            "SELECT * FROM objects ORDER BY mailbox,sequence",
        ]
        .iter()
        .map(|sql| {
            let mut statement = store.connection.prepare(sql).unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        })
        .collect()
    }
    fn rollback_case(fault: PutFault) {
        let (root, mut store) = fixture();
        let original = object(3, 1024);
        let saved = put(&mut store, &original).unwrap();
        let before = snapshot(&store);
        let rejected = object(4, 1024);
        store.put_fault = Some(fault);
        assert_eq!(
            put(&mut store, &rejected),
            Err(RelayError::StorageUnavailable)
        );
        assert_eq!(snapshot(&store), before);
        assert_eq!(
            store.get([1; 32], rejected.hash, &Capability::new([2; 32])),
            Err(RelayError::ObjectNotFound)
        );
        log_state(&store);
        drop(store);
        retain(&root, &format!("rollback-{fault:?}"));
        let mut store = RelayStore::open(root.path(), limits()).unwrap();
        assert_eq!(snapshot(&store), before);
        assert_eq!(
            put(&mut store, &original).unwrap(),
            StoredResult {
                created: false,
                ..saved
            }
        );
        assert_eq!(put(&mut store, &rejected).unwrap().sequence, 2);
    }
    #[test]
    fn relay_commit_fault_preinsert() {
        rollback_case(PutFault::PreInsert);
    }
    #[test]
    fn relay_commit_fault_afterinsert() {
        rollback_case(PutFault::AfterInsert);
    }
    #[test]
    fn relay_commit_fault_commit_error() {
        rollback_case(PutFault::CommitError);
    }
    #[test]
    fn relay_commit_fault_lostreply() {
        let (root, mut store) = fixture();
        let original = object(3, 1024);
        put(&mut store, &original).unwrap();
        let pending = object(4, 1024);
        store.put_fault = Some(PutFault::LostReply);
        assert_eq!(
            put(&mut store, &pending),
            Err(RelayError::StorageUnavailable)
        );
        let before = snapshot(&store);
        let (sequence, receipt): (u64, Vec<u8>) = store
            .connection
            .query_row(
                "SELECT sequence,receipt FROM objects WHERE hash=?1",
                [pending.hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sequence, 2);
        let key = store.public_key();
        let run = store.run_id();
        log_state(&store);
        drop(store);
        retain(&root, "lostreply-committed");
        let mut store = RelayStore::open(root.path(), limits()).unwrap();
        assert_eq!((store.public_key(), store.run_id()), (key, run));
        assert_eq!(snapshot(&store), before);
        assert_eq!(
            put(&mut store, &pending).unwrap(),
            StoredResult {
                created: false,
                sequence,
                receipt
            }
        );
        assert_eq!(
            store
                .get([1; 32], pending.hash, &Capability::new([2; 32]))
                .unwrap(),
            pending.wire
        );
        assert_eq!(snapshot(&store), before);
        assert_eq!(put(&mut store, &object(5, 1024)).unwrap().sequence, 3);
    }
    #[test]
    fn relay_commit_fault_sqlite_full() {
        let (root, mut store) = fixture();
        let original = object(3, 1024);
        let saved = put(&mut store, &original).unwrap();
        let before = snapshot(&store);
        let pages: u64 = store
            .connection
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        // The page ceiling must be applied to the connection that executes PUT.
        store
            .connection
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let effective: u64 = store
            .connection
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .unwrap();
        eprintln!(
            "writer page_count={pages} max_page_count={effective} pragmas={:?}",
            store.pragmas().unwrap()
        );
        let pending = object(4, 65536);
        store.put_fault = Some(PutFault::ObserveFull);
        assert_eq!(
            put(&mut store, &pending),
            Err(RelayError::StorageUnavailable)
        );
        assert_eq!(effective, pages);
        assert!(store.connection.is_autocommit());
        assert_eq!(snapshot(&store), before);
        assert_eq!(
            store.get([1; 32], pending.hash, &Capability::new([2; 32])),
            Err(RelayError::ObjectNotFound)
        );
        assert_eq!(
            store
                .get([1; 32], original.hash, &Capability::new([2; 32]))
                .unwrap(),
            original.wire
        );
        assert_eq!(
            put(&mut store, &original).unwrap(),
            StoredResult {
                created: false,
                sequence: saved.sequence,
                receipt: saved.receipt.clone()
            }
        );
        assert_eq!(snapshot(&store), before);
        log_state(&store);
        drop(store);
        retain(&root, "sqlite-full-rolled-back");
        let mut store = RelayStore::open(root.path(), limits()).unwrap();
        assert_eq!(snapshot(&store), before);
        assert_eq!(
            store
                .get([1; 32], original.hash, &Capability::new([2; 32]))
                .unwrap(),
            original.wire
        );
        assert_eq!(
            put(&mut store, &original).unwrap(),
            StoredResult {
                created: false,
                ..saved
            }
        );
        assert_eq!(snapshot(&store), before);
        assert_eq!(put(&mut store, &pending).unwrap().sequence, 2);
        retain(&root, "sqlite-full-recovered");
    }
    fn retain(root: &Scratch, name: &str) {
        if let Some(directory) = std::env::var_os("RELAY_36_EVIDENCE_DIRECTORY") {
            let target = std::path::PathBuf::from(directory).join(name);
            std::fs::create_dir_all(&target).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            for entry in std::fs::read_dir(root.path()).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
                }
            }
        }
    }
    #[test]
    #[ignore]
    fn fault_barrier_child() {
        let root = std::env::var_os("RELAY_36_CHILD_ROOT").unwrap();
        let mut store = RelayStore::open(Path::new(&root), limits()).unwrap();
        store.put_fault = Some(
            if std::env::var("RELAY_36_CHILD_STAGE").unwrap() == "before" {
                PutFault::PauseBeforeCommit
            } else {
                PutFault::PauseAfterCommit
            },
        );
        let _ = put(&mut store, &object(4, 1024));
        panic!("child was not killed at the bounded barrier");
    }
    struct KillChild(std::process::Child);
    impl Drop for KillChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn process_case(committed: bool) {
        use std::time::{Duration, Instant};
        let (root, mut store) = fixture();
        let original = object(3, 1024);
        let saved = put(&mut store, &original).unwrap();
        let before = snapshot(&store);
        let key = store.public_key();
        let run = store.run_id();
        drop(store);
        let marker = root.path().join("fault-barrier");
        let mut child = KillChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::fault_tests::fault_barrier_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("RELAY_36_CHILD_ROOT", root.path())
                .env(
                    "RELAY_36_CHILD_STAGE",
                    if committed { "after" } else { "before" },
                )
                .env("RELAY_36_CHILD_MARKER", &marker)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before barrier"
            );
            assert!(Instant::now() < deadline, "child never reached barrier");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Observe from an independent reader while the child is alive at the barrier.
        let observer = Connection::open(root.path().join("relay.sqlite3")).unwrap();
        let visible: u64 = observer
            .query_row("SELECT count(*) FROM objects", [], |r| r.get(0))
            .unwrap();
        assert_eq!(visible, if committed { 2 } else { 1 });
        let pending = object(4, 1024);
        let committed_receipt: Option<(u64, Vec<u8>)> = observer
            .query_row(
                "SELECT sequence,receipt FROM objects WHERE hash=?1",
                [pending.hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap();
        drop(observer);
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        assert!(!status.success());
        eprintln!(
            "process kill at {}commit: {status}; no hardware power-loss claim",
            if committed { "post" } else { "pre" }
        );
        let mut store = RelayStore::open(root.path(), limits()).unwrap();
        assert_eq!((store.public_key(), store.run_id()), (key, run));
        if committed {
            let (sequence, receipt) = committed_receipt.unwrap();
            assert_eq!(sequence, 2);
            let persisted = snapshot(&store);
            assert_eq!(
                put(&mut store, &pending).unwrap(),
                StoredResult {
                    created: false,
                    sequence,
                    receipt
                }
            );
            assert_eq!(snapshot(&store), persisted);
            assert_eq!(
                store
                    .get([1; 32], pending.hash, &Capability::new([2; 32]))
                    .unwrap(),
                pending.wire
            );
        } else {
            assert_eq!(snapshot(&store), before);
            assert_eq!(committed_receipt, None);
            assert_eq!(
                store.get([1; 32], pending.hash, &Capability::new([2; 32])),
                Err(RelayError::ObjectNotFound)
            );
            assert_eq!(put(&mut store, &pending).unwrap().sequence, 2);
        }
        assert_eq!(
            put(&mut store, &original).unwrap(),
            StoredResult {
                created: false,
                ..saved
            }
        );
        log_state(&store);
        drop(store);
        retain(
            &root,
            if committed {
                "process-postcommit"
            } else {
                "process-precommit"
            },
        );
    }
    #[test]
    fn relay_commit_fault_process_precommit() {
        process_case(false);
    }
    #[test]
    fn relay_commit_fault_process_postcommit() {
        process_case(true);
    }
    fn log_state(store: &RelayStore) {
        eprintln!(
            "public key={} run={} mailbox={}",
            hex::encode(store.public_key()),
            hex::encode(store.run_id()),
            hex::encode([1; 32])
        );
        let counters: (u64, u64, u64) = store
            .connection
            .query_row(
                "SELECT (SELECT used_bytes FROM metadata),used_bytes,next_sequence FROM mailboxes",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        eprintln!(
            "total_used={} mailbox_used={} next_sequence={}",
            counters.0, counters.1, counters.2
        );
        let mut statement = store
            .connection
            .prepare("SELECT hash,sequence,receipt FROM objects ORDER BY sequence")
            .unwrap();
        for row in statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
        {
            let (hash, sequence, receipt) = row.unwrap();
            eprintln!(
                "ciphertext_hash={} sequence={sequence} receipt_sha256={}",
                hex::encode(hash),
                hex::encode(Sha256::digest(receipt))
            );
        }
    }
}

impl RelayStore {
    pub fn page(
        &mut self,
        mailbox: Id32,
        after: u64,
        limit: u16,
        read: &Capability,
    ) -> RelayResult<loki_relay_protocol::types::Page> {
        use loki_relay_protocol::types::{Entry, Page};
        loki_relay_protocol::http::validate_limit(Some(u64::from(limit)))?;
        let transaction = self.connection.transaction()?;
        let provisioned: bool = transaction.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailboxes')",
            [],
            |r| r.get(0),
        )?;
        if !provisioned {
            return Err(RelayError::Capability);
        }
        let state: Option<(Vec<u8>, u64)> = transaction
            .query_row(
                "SELECT read_verifier,next_sequence FROM mailboxes WHERE id=?1",
                [mailbox.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (verifier, next_sequence) = state.ok_or(RelayError::Capability)?;
        let verifier: Id32 = verifier
            .try_into()
            .map_err(|_| RelayError::StorageUnavailable)?;
        setup_active(&transaction, mailbox)?;
        if !read.verify(Role::Read, mailbox, &verifier) {
            return Err(RelayError::Capability);
        }
        let high_water = next_sequence
            .checked_sub(1)
            .ok_or(RelayError::StorageUnavailable)?;
        if after > high_water {
            return Err(RelayError::CursorAhead);
        }
        let cursor = i64::try_from(after).map_err(|_| RelayError::CursorAhead)?;
        #[cfg(test)]
        if let Some((entered, release)) = self.page_barrier.take() {
            entered.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("page barrier release");
            let snapshot_next: u64 = transaction
                .query_row(
                    "SELECT next_sequence FROM mailboxes WHERE id=?1",
                    [mailbox.as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                snapshot_next, next_sequence,
                "same SQLite snapshot after concurrent append"
            );
        }
        let mut entries = Vec::new();
        if after < high_water {
            let mut statement = transaction.prepare(
                "SELECT sequence,hash,wire_length,receipt FROM objects WHERE mailbox=?1 AND sequence>?2 AND sequence<=?3 ORDER BY sequence ASC LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![mailbox.as_slice(), cursor, high_water, limit],
                |r| {
                    Ok((
                        r.get::<_, u64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, u64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )?;
            for row in rows {
                let (sequence, hash, wire_length, receipt) = row?;
                if receipt.len() > receipt::MAX_BODY_LEN + 128 {
                    return Err(RelayError::StorageUnavailable);
                }
                entries.push(Entry {
                    sequence,
                    hash: hash
                        .try_into()
                        .map_err(|_| RelayError::StorageUnavailable)?,
                    wire_length,
                    receipt,
                });
            }
            if entries.len() as u64 != (high_water - after).min(u64::from(limit)) {
                return Err(RelayError::StorageUnavailable);
            }
        }
        let page = Page {
            mailbox,
            after,
            next: entries.last().map_or(after, |entry| entry.sequence),
            high_water,
            entries,
        };
        loki_relay_protocol::http::encode_page(&page)
            .map_err(|_| RelayError::StorageUnavailable)?;
        transaction.commit()?;
        Ok(page)
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::capability::{provisioning_verifier, verifier};
    mod support {
        include!("../tests/support/mod.rs");
    }

    fn fixture() -> (support::Scratch, RelayStore) {
        let root = support::Scratch::new();
        let mut store = RelayStore::init(
            root.path(),
            [7; 32],
            "http://127.0.0.1:8000",
            &[8; 32],
            provisioning_verifier([7; 32], &[8; 32]),
            Limits {
                total_bytes: 100_000,
                mailbox_bytes: 100_000,
                mailbox_count: 10,
            },
        )
        .unwrap();
        let body =
            loki_relay_protocol::http::encode_creation(&loki_relay_protocol::types::Creation {
                read_verifier: verifier(Role::Read, [1; 32], &[2; 32]),
                append_verifier: verifier(Role::Append, [1; 32], &[3; 32]),
                admin_verifier: verifier(Role::Admin, [1; 32], &[4; 32]),
                quota: 100_000,
            })
            .unwrap();
        store
            .create([1; 32], &body, &Capability::new([8; 32]))
            .unwrap();
        (root, store)
    }
    fn object(tag: u8) -> Object {
        let mut wire = vec![tag; 1024];
        wire[..8].copy_from_slice(b"LOKIRLY1");
        wire[8] = 1;
        Object {
            hash: Sha256::digest(&wire).into(),
            wire,
        }
    }
    #[test]
    fn snapshot_page_concurrent_append() {
        let (root, mut store) = fixture();
        let first = object(9);
        let second = object(10);
        let saved = store
            .put([1; 32], &first, &Capability::new([3; 32]))
            .unwrap();
        let body = receipt::encode_body(&ReceiptBody {
            pin: RelayPin {
                key: store.public_key(),
                run: store.run_id(),
            },
            mailbox: [1; 32],
            hash: second.hash,
            wire_length: 1024,
            sequence: 2,
            retention: receipt::RETENTION_RUN,
        })
        .unwrap();
        let signature = store.root.sign_receipt(&body).unwrap();
        let second_receipt = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_vec()),
        ]))
        .unwrap();
        let (entered, observed) = std::sync::mpsc::channel();
        let (resume, release) = std::sync::mpsc::channel();
        store.page_barrier = Some((entered, release));
        let reader = std::thread::spawn(move || {
            let page = store
                .page([1; 32], 0, 100, &Capability::new([2; 32]))
                .unwrap();
            (store, page)
        });
        observed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let mut writer = Connection::open(root.path().join("relay.sqlite3")).unwrap();
        configure(&writer).unwrap();
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("INSERT INTO objects (mailbox,hash,wire,wire_length,sequence,receipt) VALUES (?1,?2,?3,1024,2,?4)", params![[1u8; 32].as_slice(), second.hash.as_slice(), second.wire, second_receipt]).unwrap();
        tx.execute(
            "UPDATE mailboxes SET used_bytes=2048,next_sequence=3 WHERE id=?1",
            [[1u8; 32].as_slice()],
        )
        .unwrap();
        tx.execute("UPDATE metadata SET used_bytes=2048", [])
            .unwrap();
        tx.commit().unwrap();
        let committed: u64 = writer
            .query_row("SELECT next_sequence FROM mailboxes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(committed, 3);
        resume.send(()).unwrap();
        let (mut store, page) = reader.join().unwrap();
        assert_eq!((page.high_water, page.next, page.entries.len()), (1, 1, 1));
        assert_eq!(page.entries[0].receipt, saved.receipt);
        let next = store
            .page([1; 32], 1, 100, &Capability::new([2; 32]))
            .unwrap();
        assert_eq!((next.high_water, next.next, next.entries.len()), (2, 2, 1));
        assert_eq!(next.entries[0].receipt, second_receipt);
        eprintln!("snapshot H=1; independent WAL append committed sequence=2 before release; next snapshot H=2");
    }
    #[test]
    fn snapshot_page_store_limits() {
        let (_root, mut store) = fixture();
        for limit in [0, 101, u16::MAX] {
            assert_eq!(
                store.page([1; 32], 0, limit, &Capability::new([2; 32])),
                Err(RelayError::MalformedRequest)
            );
        }
    }
    #[test]
    fn snapshot_page_unprovisioned() {
        let (root, store) = fixture();
        drop(store);
        let connection = Connection::open(root.path().join("relay.sqlite3")).unwrap();
        connection.execute("DROP TABLE mailboxes", []).unwrap();
        drop(connection);
        let mut store = RelayStore::open(
            root.path(),
            Limits {
                total_bytes: 100_000,
                mailbox_bytes: 100_000,
                mailbox_count: 10,
            },
        )
        .unwrap();
        assert_eq!(
            store.page([1; 32], 0, 100, &Capability::new([2; 32])),
            Err(RelayError::Capability)
        );
    }
    #[test]
    fn snapshot_page_current_read_capability() {
        let (_root, mut store) = fixture();
        store
            .connection
            .execute(
                "UPDATE mailboxes SET read_verifier=?1",
                [verifier(Role::Read, [1; 32], &[6; 32]).as_slice()],
            )
            .unwrap();
        assert_eq!(
            store.page([1; 32], 0, 100, &Capability::new([2; 32])),
            Err(RelayError::Capability)
        );
        assert!(store
            .page([1; 32], 0, 100, &Capability::new([6; 32]))
            .is_ok());
    }
    #[test]
    fn snapshot_page_saved_receipt_bound() {
        let (_root, mut store) = fixture();
        let obj = object(9);
        store.put([1; 32], &obj, &Capability::new([3; 32])).unwrap();
        store
            .connection
            .execute(
                "UPDATE objects SET receipt=?1",
                [vec![0; receipt::MAX_BODY_LEN + 129]],
            )
            .unwrap();
        assert_eq!(
            store.page([1; 32], 0, 100, &Capability::new([2; 32])),
            Err(RelayError::StorageUnavailable)
        );
    }
    #[test]
    fn snapshot_page_gap() {
        let (_root, mut store) = fixture();
        for tag in 9..12 {
            store
                .put([1; 32], &object(tag), &Capability::new([3; 32]))
                .unwrap();
        }
        store
            .connection
            .execute("DELETE FROM objects WHERE sequence=2", [])
            .unwrap();
        assert_eq!(
            store.page([1; 32], 0, 100, &Capability::new([2; 32])),
            Err(RelayError::StorageUnavailable)
        );
    }
    #[test]
    fn snapshot_page_missing_tail() {
        let (_root, mut store) = fixture();
        store
            .put([1; 32], &object(9), &Capability::new([3; 32]))
            .unwrap();
        store.connection.execute("DELETE FROM objects", []).unwrap();
        assert_eq!(
            store.page([1; 32], 0, 100, &Capability::new([2; 32])),
            Err(RelayError::StorageUnavailable)
        );
    }
    #[test]
    fn snapshot_page_metadata_bound() {
        let (_root, mut store) = fixture();
        store
            .put([1; 32], &object(9), &Capability::new([3; 32]))
            .unwrap();
        store
            .connection
            .execute("UPDATE objects SET receipt=?1", [vec![0; 128 * 1024]])
            .unwrap();
        assert!(matches!(
            store.page([1; 32], 0, 100, &Capability::new([2; 32])),
            Err(RelayError::StorageUnavailable)
        ));
    }
}

impl RelayStore {
    pub fn setup_control(
        &mut self,
        mailbox: Id32,
        request: &[u8],
        provision: &Capability,
    ) -> RelayResult<CreationResult> {
        let (creation, expires, action) =
            loki_relay_protocol::http::decode_namespace_control(request)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorize_provision(&tx, self.root.run_id, provision)?;
        let now = current_time()?;
        if expires
            > now
                .checked_add(2592000)
                .ok_or(RelayError::MalformedRequest)?
        {
            return Err(RelayError::MalformedRequest);
        }
        let retire = match action {
            NamespaceAction::ReserveSetup => false,
            NamespaceAction::RetireSetup => true,
            _ => {
                let result = payment_control(
                    &tx,
                    self.root.run_id,
                    mailbox,
                    &creation,
                    expires,
                    now,
                    action,
                )?;
                tx.commit()?;
                return Ok(result);
            }
        };
        let digest: Id32 = Sha256::digest(&creation).into();
        tx.execute_batch(include_str!("setup_schema.sql"))?;
        let prior: Option<(Vec<u8>, u64, bool)> = tx
            .query_row(
                "SELECT creation_digest,expires,retired FROM setup_namespaces WHERE mailbox=?1",
                [mailbox.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((old, deadline, retired)) = prior {
            if old != digest || deadline != expires {
                return Err(RelayError::Conflict);
            }
            if retired && !retire {
                return Err(RelayError::Capability);
            }
        } else {
            if !retire && expires <= now {
                return Err(RelayError::MalformedRequest);
            }
            if payment_state(&tx, mailbox)?.is_some() {
                return Err(RelayError::Conflict);
            }
            let installed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailboxes')",[],|r|r.get(0))?;
            if installed {
                let existing: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE id=?1)",
                    [mailbox.as_slice()],
                    |r| r.get(0),
                )?;
                if existing {
                    return Err(RelayError::Conflict);
                }
            }
            tx.execute(
                "INSERT INTO setup_namespaces VALUES(?1,?2,?3,0)",
                params![mailbox.as_slice(), digest.as_slice(), expires],
            )?;
        }
        if retire {
            tx.execute(
                "UPDATE setup_namespaces SET retired=1 WHERE mailbox=?1 AND retired=0",
                [mailbox.as_slice()],
            )?;
        }
        tx.commit()?;
        if retire || expires <= now {
            self.cleanup_setup(now)?;
            return Ok(CreationResult {
                created: false,
                run: self.root.run_id,
                quota: decode_creation(&creation)?.quota,
                append_revision: 1,
            });
        }
        self.create(mailbox, &creation, provision)
    }
    pub fn cleanup_setup(&mut self, now: u64) -> RelayResult<usize> {
        if now > i64::MAX as u64 {
            return Err(RelayError::MalformedRequest);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let installed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='setup_namespaces')",
            [],
            |row| row.get(0),
        )?;
        if !installed {
            return Ok(0);
        }
        const BATCH: u32 = 64;
        let mailboxes_installed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='mailboxes')",
            [],
            |r| r.get(0),
        )?;
        if !mailboxes_installed {
            tx.execute(
                "UPDATE setup_namespaces SET retired=1 WHERE mailbox IN
                 (SELECT mailbox FROM setup_namespaces WHERE retired=0 AND expires<=?1 LIMIT ?2)",
                params![now, BATCH],
            )?;
            tx.commit()?;
            return Ok(0);
        }
        // Start the retired lookup from actual mailboxes, not the accumulating tombstones.
        let mut q = tx.prepare(
            "SELECT n.mailbox,m.used_bytes FROM mailboxes m CROSS JOIN setup_namespaces n ON n.mailbox=m.id
             WHERE n.retired=1
             UNION ALL
             SELECT n.mailbox,m.used_bytes FROM setup_namespaces n LEFT JOIN mailboxes m ON m.id=n.mailbox
             WHERE n.retired=0 AND n.expires<=?1 LIMIT ?2",
        )?;
        let rows = q
            .query_map(params![now, BATCH], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<u64>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(q);
        let objects_installed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='objects')",
            [],
            |r| r.get(0),
        )?;
        let nonces_installed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='nonce_uses')",
            [],
            |r| r.get(0),
        )?;
        let mut removed = 0;
        for (mailbox, used) in &rows {
            tx.execute(
                "UPDATE setup_namespaces SET retired=1 WHERE mailbox=?1 AND retired=0",
                [mailbox],
            )?;
            let Some(used) = used else { continue };
            if nonces_installed {
                let nonces: u64 = tx.query_row(
                    "SELECT count(*) FROM nonce_uses WHERE mailbox=?1",
                    [mailbox],
                    |r| r.get(0),
                )?;
                if nonces != 0 {
                    return Err(RelayError::StorageUnavailable);
                }
            }
            if objects_installed {
                tx.execute("DELETE FROM objects WHERE mailbox=?1", [mailbox])?;
            }
            tx.execute(
                "UPDATE metadata SET used_bytes=used_bytes-?1 WHERE singleton=1",
                [used],
            )?;
            tx.execute("DELETE FROM mailboxes WHERE id=?1", [mailbox])?;
            removed += 1;
        }
        tx.commit()?;
        Ok(removed)
    }
}

fn payment_control(
    tx: &Transaction<'_>,
    run: Id32,
    mailbox: Id32,
    creation: &[u8],
    expires: u64,
    now: u64,
    action: NamespaceAction,
) -> RelayResult<CreationResult> {
    let id = mailbox.as_slice();
    let digest: Id32 = Sha256::digest(creation).into();
    let quota = decode_creation(creation)?.quota;
    tx.execute_batch(PAYMENT_RESERVATIONS)?;
    install_mailboxes(tx)?;
    let prior = payment_state(tx, mailbox)?;
    let used: Option<u64> = tx
        .query_row("SELECT used_bytes FROM mailboxes WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    let state = if let Some((old, deadline, state)) = prior {
        if old != digest || deadline != expires {
            return Err(RelayError::Conflict);
        }
        state
    } else {
        // Never adopt a legacy mailbox or a setup tombstone as a payment reservation.
        if used.is_some() || setup_state(tx, mailbox)?.is_some() {
            return Err(RelayError::Conflict);
        }
        PAYMENT_RESERVED
    };
    let next = match action {
        NamespaceAction::ReservePayment
            if state != PAYMENT_RETIRED && (state == PAYMENT_PROMOTED || now < expires) =>
        {
            if used.is_none() {
                let (reserved, limit): (u64, u64) = tx.query_row(
                    "SELECT (SELECT COALESCE(sum(m.byte_quota),0) FROM payment_reservations p JOIN mailboxes m ON m.id=p.mailbox WHERE p.state=0), total_bytes FROM metadata WHERE singleton=1",
                    [], |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if reserved
                    .checked_add(quota)
                    .is_none_or(|total| total > limit)
                {
                    return Err(RelayError::QuotaExhausted);
                }
            }
            state
        }
        NamespaceAction::PromotePayment if state != PAYMENT_RETIRED => PAYMENT_PROMOTED,
        NamespaceAction::RetirePayment if state != PAYMENT_PROMOTED => PAYMENT_RETIRED,
        _ => return Err(RelayError::Conflict),
    };
    let result = if next == PAYMENT_RETIRED {
        if let Some(used) = used {
            let nonce_history: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM nonce_uses WHERE mailbox=?1)
                     OR EXISTS(SELECT 1 FROM nonce_claimants WHERE mailbox=?1)",
                [id],
                |r| r.get(0),
            )?;
            if nonce_history {
                return Err(RelayError::StorageUnavailable);
            }
            tx.execute("DELETE FROM objects WHERE mailbox=?1", [id])?;
            tx.execute("DELETE FROM mailboxes WHERE id=?1", [id])?;
            tx.execute(
                "UPDATE metadata SET used_bytes=used_bytes-?1 WHERE singleton=1",
                [used],
            )?;
        }
        CreationResult {
            created: false,
            run,
            quota,
            append_revision: 1,
        }
    } else {
        create_mailbox(tx, run, mailbox, creation)?
    };
    tx.execute(
        "INSERT INTO payment_reservations VALUES(?1,?2,?3,?4) ON CONFLICT(mailbox) DO UPDATE SET state=excluded.state",
        params![id, digest.as_slice(), expires, next],
    )?;
    Ok(result)
}
