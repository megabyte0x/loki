use crate::{ClientError, ClientResult};
use loki_relay_protocol::WireError;
use loki_relay_protocol::types::{
    roster_digest, Id32, LogicalKey, MemberId, MessageRef, Object, RelayRoute, Roster,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
    time::Duration,
};

pub(crate) const SCHEMA: &str = include_str!("schema.sql");

/// The transport schema for a vault of `count` members: the 3-member schema with every
/// member-number bound raised to `count`.
fn member_schema(count: usize) -> &'static str {
    static SCHEMAS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    if count == 3 {
        return SCHEMA;
    }
    let schemas = SCHEMAS.get_or_init(|| {
        // Without the template text `replace` would return the 3-member schema unchanged,
        // and the stored schema would still validate against it.
        assert!(
            SCHEMA.contains(MEMBER_BOUND),
            "schema.sql lost its member-number bound"
        );
        (0..=usize::from(loki_relay_protocol::types::MAX_MEMBERS))
            .map(|n| SCHEMA.replace(MEMBER_BOUND, &format!("BETWEEN 1 AND {n})")))
            .collect()
    });
    &schemas[count]
}
const MEMBER_BOUND: &str = "BETWEEN 1 AND 3)";

#[cfg(test)]
mod member_schema_tests {
    #[test]
    fn every_member_count_raises_every_bound() {
        let bounds = super::SCHEMA.matches(super::MEMBER_BOUND).count();
        assert!(bounds > 0);
        for count in 3..=usize::from(loki_relay_protocol::types::MAX_MEMBERS) {
            let schema = super::member_schema(count);
            let wanted = format!("BETWEEN 1 AND {count})");
            assert_eq!(schema.matches(wanted.as_str()).count(), bounds, "{count}");
            if count != 3 {
                assert!(!schema.contains(super::MEMBER_BOUND), "{count}");
            }
        }
    }
}
const STORAGE_BUDGET: u64 = 512 * 1024 * 1024;
const PENDING_TRANSFERS: u64 = 128;
const INCOMPLETE_TOTAL: u64 = 32; // Leave at least half of polling intake for complete messages.
const INCOMPLETE_TTL_MS: u64 = 10 * 60 * 1000;

fn incomplete_per_sender(members: usize) -> u64 {
    (INCOMPLETE_TOTAL / members as u64).min(4)
}

fn schema_parts() -> (&'static str, &'static str) {
    let offset = SCHEMA
        .find("CREATE TABLE ciphertext_objects")
        .expect("outbox schema boundary");
    SCHEMA.split_at(offset)
}

fn request_schema_parts() -> (&'static str, &'static str) {
    SCHEMA.split_at(
        SCHEMA
            .find("CREATE TABLE caller_requests")
            .expect("request schema boundary"),
    )
}

fn generation_parts() -> (&'static str, &'static str) {
    SCHEMA.split_at(
        SCHEMA
            .find("CREATE TABLE upload_generation")
            .expect("generation schema boundary"),
    )
}

fn completion_parts() -> (&'static str, &'static str) {
    SCHEMA.split_at(
        SCHEMA
            .find("CREATE TABLE delivery_completion")
            .expect("completion schema boundary"),
    )
}

fn incoming_parts() -> (&'static str, &'static str) {
    SCHEMA.split_at(
        SCHEMA
            .find("CREATE TABLE route_cursors")
            .expect("incoming schema boundary"),
    )
}

fn seed_diagnostic_ids(connection: &Connection) -> ClientResult<()> {
    let max_id: Option<i64> = connection.query_row("SELECT max(id) FROM quarantine_samples", [], |row| {
        row.get(0)
    })?;
    let next = match max_id {
        None => 1,
        Some(id) if id > 0 => id.checked_add(1).ok_or(ClientError::Capacity)?,
        Some(_) => return Err(ClientError::Storage),
    };
    connection.execute(
        "INSERT INTO diagnostic_ids (singleton, next_id) VALUES (1, ?1)",
        [next],
    )?;
    Ok(())
}

fn recovery_parts() -> (&'static str, &'static str) {
    SCHEMA.split_at(
        SCHEMA
            .find("CREATE TABLE route_capture")
            .expect("recovery schema boundary"),
    )
}

fn inbox_work_parts(count: usize) -> (&'static str, &'static str) {
    let schema = member_schema(count);
    schema.split_at(schema.find("CREATE TABLE incomplete_leases").expect("inbox work schema boundary"))
}

const CURRENT_CATALOG: u8 = 7;

/// Widen CHECK constraints in place by rewriting the schema text: every saved row already
/// satisfies the wider bound, so the file content does not change (SQLite's documented
/// `writable_schema` procedure for constraint changes). Checks integrity afterwards.
pub(crate) fn widen_checks(connection: &mut Connection, narrow: &str, wide: &str) -> ClientResult<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = transaction.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
    transaction.execute_batch("PRAGMA writable_schema=ON;")?;
    let changed = transaction.execute(
        "UPDATE sqlite_master SET sql=replace(sql,?1,?2) WHERE type='table' AND instr(sql,?1)>0",
        params![narrow, wide],
    )?;
    transaction.execute_batch(&format!(
        "PRAGMA schema_version={}; PRAGMA writable_schema=OFF;",
        version + 1
    ))?;
    if changed == 0 {
        return Err(ClientError::Storage);
    }
    let integrity: String = transaction.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        return Err(ClientError::Storage);
    }
    transaction.commit()?;
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection, schema: &str) -> ClientResult<()> {
    let count: usize = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE sql IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    if count != schema.split("CREATE ").count() - 1 {
        return Err(ClientError::Storage);
    }
    for declaration in schema.split("CREATE ").skip(1) {
        let name = declaration
            .split_whitespace()
            .nth(1)
            .ok_or(ClientError::Storage)?;
        let actual: String =
            connection.query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })?;
        let expected = format!("CREATE {}", declaration.trim().trim_end_matches(';'));
        if actual.split_whitespace().collect::<Vec<_>>()
            != expected.split_whitespace().collect::<Vec<_>>()
        {
            return Err(ClientError::Storage);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigReference {
    revision: u64,
    hash: Id32,
}

impl ConfigReference {
    pub fn new(revision: u64, hash: Id32) -> ClientResult<Self> {
        if revision == 0 || revision > i64::MAX as u64 {
            return Err(ClientError::Config);
        }
        Ok(Self { revision, hash })
    }

    /// Hashes exact sealed ciphertext bytes; this does not authenticate or publish a configuration.
    pub fn from_ciphertext(revision: u64, exact_ciphertext: &[u8]) -> ClientResult<Self> {
        let reference = Self::new(revision, [0; 32])?;
        Ok(Self {
            hash: Sha256::digest(exact_ciphertext).into(),
            ..reference
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn hash(&self) -> &Id32 {
        &self.hash
    }

    pub fn file_name(&self) -> String {
        format!("secrets/relay-config-{:016}.sealed", self.revision)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StorePragmas {
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
    pub busy_timeout: i64,
    pub fullfsync: i64,
}

struct RootLock(File);

impl Drop for RootLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub struct ClientStore {
    // Field order keeps SQLite closed before releasing the root lock.
    pub(crate) connection: Connection,
    pub(crate) storage_budget: u64,
    member_count: usize,
    _root: RootLock,
}

#[cfg(unix)]
pub(crate) fn check_owner(metadata: &fs::Metadata, mode: u32, directory: bool) -> ClientResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // geteuid takes no arguments and returns the process's effective Unix user ID.
    let uid = unsafe { geteuid() };
    if metadata.uid() != uid
        || metadata.permissions().mode() & 0o7777 != mode
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(ClientError::Storage);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_owner(_: &fs::Metadata, _: u32, _: bool) -> ClientResult<()> {
    Err(ClientError::Storage)
}

pub(crate) fn root_path(path: &Path) -> ClientResult<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut prefix = PathBuf::new();
    for component in path.components() {
        if component == Component::ParentDir {
            return Err(ClientError::Storage);
        }
        prefix.push(component);
        if prefix == path {
            break;
        }
        if !fs::symlink_metadata(&prefix)?.is_dir() {
            return Err(ClientError::Storage);
        }
    }
    Ok(path)
}

fn check_database_files(root: &Path) -> ClientResult<()> {
    for name in [
        "client.sqlite3",
        "client.sqlite3-wal",
        "client.sqlite3-shm",
        "client.sqlite3-journal",
    ] {
        match fs::symlink_metadata(root.join(name)) {
            Ok(metadata) => check_owner(&metadata, 0o600, false)?,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && name != "client.sqlite3" => {}
            Err(_) => return Err(ClientError::Storage),
        }
    }
    Ok(())
}

pub(crate) fn configure(connection: &Connection) -> ClientResult<()> {
    connection.busy_timeout(Duration::from_millis(5000))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    #[cfg(target_os = "macos")]
    connection.pragma_update(None, "fullfsync", "ON")?;
    let pragmas = read_pragmas(connection)?;
    if pragmas.journal_mode != "wal"
        || pragmas.synchronous != 2
        || pragmas.foreign_keys != 1
        || pragmas.busy_timeout != 5000
        || (cfg!(target_os = "macos") && pragmas.fullfsync != 1)
    {
        return Err(ClientError::Storage);
    }
    configure_storage_limit(connection, STORAGE_BUDGET)?;
    Ok(())
}

fn read_pragmas(connection: &Connection) -> ClientResult<StorePragmas> {
    let integer = |name| connection.pragma_query_value(None, name, |row| row.get(0));
    Ok(StorePragmas {
        journal_mode: connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?,
        synchronous: integer("synchronous")?,
        foreign_keys: integer("foreign_keys")?,
        busy_timeout: integer("busy_timeout")?,
        fullfsync: integer("fullfsync")?,
    })
}

fn read_reference(connection: &Connection) -> ClientResult<Option<ConfigReference>> {
    let mut statement =
        connection.prepare("SELECT singleton,revision,hash FROM config_versions")?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let singleton: i64 = row.get(0)?;
    let revision: i64 = row.get(1)?;
    let hash: Vec<u8> = row.get(2)?;
    if singleton != 1 || revision <= 0 || rows.next()?.is_some() {
        return Err(ClientError::Storage);
    }
    let hash = hash.try_into().map_err(|_| ClientError::Storage)?;
    Ok(Some(ConfigReference {
        revision: revision as u64,
        hash,
    }))
}

fn validate_metadata(
    connection: &Connection,
    roster: &Roster,
    digest: Id32,
    owner: MemberId,
) -> ClientResult<u8> {
    let count: i64 = connection.query_row("SELECT count(*) FROM metadata", [], |r| r.get(0))?;
    if count != 1 {
        return Err(ClientError::Storage);
    }
    let (singleton, version, vault, saved_roster, saved_owner): (i64, i64, Vec<u8>, Vec<u8>, i64) =
        connection.query_row(
            "SELECT singleton,schema_version,vault,roster,owner FROM metadata",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
    if singleton != 1
        || version != 1
        || vault.len() != 32
        || saved_roster.len() != 32
        || !(1..=roster.members.len() as i64).contains(&saved_owner)
    {
        return Err(ClientError::Storage);
    }
    if vault != roster.vault || saved_roster != digest || saved_owner != i64::from(owner) {
        return Err(ClientError::Identity);
    }
    let members = roster.members.len();
    let catalog = if validate_schema(connection, member_schema(members)).is_ok() {
        CURRENT_CATALOG
    } else if validate_schema(connection, inbox_work_parts(members).0).is_ok() {
        6
    } else if members != 3 {
        return Err(ClientError::Storage);
    } else if validate_schema(connection, schema_parts().0).is_ok() {
        0
    } else if validate_schema(connection, request_schema_parts().0).is_ok() {
        1
    } else if validate_schema(connection, generation_parts().0).is_ok() {
        2
    } else if validate_schema(connection, completion_parts().0).is_ok() {
        3
    } else if validate_schema(connection, incoming_parts().0).is_ok() {
        4
    } else if validate_schema(connection, recovery_parts().0).is_ok() {
        5
    } else {
        return Err(ClientError::Storage);
    };
    let integrity: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        return Err(ClientError::Storage);
    }
    let foreign_key_error = connection.prepare("PRAGMA foreign_key_check")?.exists([])?;
    if foreign_key_error {
        return Err(ClientError::Storage);
    }
    read_reference(connection)?;
    Ok(catalog)
}

impl ClientStore {
    pub(crate) fn schema(&self) -> &'static str {
        member_schema(self.member_count)
    }

    /// Creates a new dedicated transport root, or validates an existing complete root.
    /// The roster is supplied by the certified member adapter; no association overrides are accepted.
    pub fn open(root: &Path, roster: &Roster, owner: MemberId) -> ClientResult<Self> {
        let digest = roster_digest(roster)?;
        if owner == 0 || !roster.members.iter().any(|member| member.id == owner) {
            return Err(ClientError::Identity);
        }
        let root = root_path(root)?;
        let fresh = match fs::symlink_metadata(&root) {
            Ok(metadata) => {
                check_owner(&metadata, 0o700, true)?;
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(&root)?;
                check_owner(&fs::symlink_metadata(&root)?, 0o700, true)?;
                true
            }
            Err(_) => return Err(ClientError::Storage),
        };
        let lock = File::open(&root)?;
        lock.try_lock().map_err(|_| ClientError::Storage)?;
        let root_lock = RootLock(lock);
        if fresh {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(root.join("client.sqlite3"))?.sync_all()?;
            File::open(root.parent().ok_or(ClientError::Storage)?)?.sync_all()?;
        }
        check_database_files(&root)?;
        let mut connection = Connection::open_with_flags(
            root.join("client.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let prior = if fresh {
            CURRENT_CATALOG
        } else {
            validate_metadata(&connection, roster, digest, owner)?
        };
        configure(&connection)?;
        if prior < CURRENT_CATALOG {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if validate_metadata(&transaction, roster, digest, owner)? != prior {
                return Err(ClientError::Storage);
            }
            let addition = if prior == 0 {
                schema_parts().1
            } else if prior == 1 {
                request_schema_parts().1
            } else if prior == 2 {
                generation_parts().1
            } else if prior == 3 {
                completion_parts().1
            } else if prior == 4 {
                incoming_parts().1
            } else if prior == 5 {
                recovery_parts().1
            } else {
                inbox_work_parts(roster.members.len()).1
            };
            // A raised page ceiling still reuses free pages in an over-budget file.
            admit_storage_growth(&transaction, STORAGE_BUDGET)?;
            transaction.execute_batch(addition)?;
            if prior < 6 {
                seed_diagnostic_ids(&transaction)?;
            }
            seed_incomplete_leases(&transaction, roster.members.len())?;
            transaction.execute_batch(
                "INSERT INTO received_work(incoming,source) SELECT 1,rowid FROM incoming_originals WHERE kind=2;
                 INSERT INTO received_work(incoming,source) SELECT 0,rowid FROM ack_links;",
            )?;
            if validate_metadata(&transaction, roster, digest, owner)? != CURRENT_CATALOG {
                return Err(ClientError::Storage);
            }
            transaction.commit()?;
        }
        if fresh {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(member_schema(roster.members.len()))?;
            seed_diagnostic_ids(&transaction)?;
            transaction.execute(
                "INSERT INTO metadata VALUES(1,1,?1,?2,?3)",
                params![roster.vault.as_slice(), digest.as_slice(), owner],
            )?;
            transaction.commit()?;
            File::open(&root)?.sync_all()?;
        }
        check_database_files(&root)?;
        Ok(Self {
            connection,
            storage_budget: STORAGE_BUDGET,
            member_count: roster.members.len(),
            _root: root_lock,
        })
    }

    pub fn pragmas(&self) -> ClientResult<StorePragmas> {
        read_pragmas(&self.connection)
    }

    pub fn config_reference(&self) -> ClientResult<Option<ConfigReference>> {
        read_reference(&self.connection)
    }

    /// Publishes only the pointer. The sealed-file publisher must sync its file and directory first.
    pub fn record_config_revision(&mut self, reference: &ConfigReference) -> ClientResult<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(prior) = read_reference(&transaction)? {
            if reference.revision < prior.revision
                || (reference.revision == prior.revision && reference.hash != prior.hash)
            {
                return Err(ClientError::Conflict);
            }
            if reference == &prior {
                transaction.commit()?;
                return Ok(());
            }
        }
        transaction.execute(
            "INSERT INTO config_versions VALUES(1,?1,?2) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,hash=excluded.hash",
            params![reference.revision, reference.hash.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryLogical {
    pub cursor: u64,
    pub key: LogicalKey,
    pub digest: Id32,
    pub kind: u8,
    pub session: Option<Id32>,
    pub source_root: Id32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRecipient {
    pub recipient: MemberId,
    pub transfer: Option<Id32>,
    pub root_hash: Id32,
    pub needs_route: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRequirement {
    pub hash: Id32,
    pub length: u64,
    pub ordinal: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryUpload {
    pub cursor: u64,
    pub key: LogicalKey,
    pub recipient: MemberId,
    pub hash: Id32,
    pub relay_key: Id32,
    pub run: Id32,
    pub mailbox: Id32,
    pub attempts: u64,
    pub retry_at: u64,
    pub acknowledged: bool,
}

/// Structural reference state. It does not authenticate a message or advance a cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePhase {
    Pending,
    Ready,
    Resolved,
    Rejected,
    NotActionable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCursor {
    pub cursor: u64,
    pub relay_key: Id32,
    pub run: Id32,
    pub mailbox: Id32,
    pub position: u64,
}

/// Advertised capture. `receipt` and `wire_length` are untrusted metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCapture {
    pub relay_key: Id32,
    pub run: Id32,
    pub mailbox: Id32,
    pub sequence: u64,
    pub source_hash: Id32,
    pub wire_length: u64,
    pub receipt: Vec<u8>,
    pub disposition: String,
    pub reason: String,
    pub body_digest: Option<Id32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDownload {
    pub cursor: u64,
    pub relay_key: Id32,
    pub run: Id32,
    pub mailbox: Id32,
    pub source_hash: Id32,
    pub wire_length: u64,
    pub attempts: u64,
    pub retry_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadRejection {
    pub cursor: u64,
    pub relay_key: Id32,
    pub run: Id32,
    pub mailbox: Id32,
    pub source_hash: Id32,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedSource {
    pub cursor: u64,
    pub root_hash: Id32,
    pub group_id: Option<Id32>,
    pub claimed_transfer: Option<Id32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedRequirement {
    pub root_hash: Id32,
    pub ordinal: u16,
    pub hash: Id32,
    pub wire_length: u64,
}

/// Verified manifest or single-root binding. Claims are written only at insert.
pub(crate) struct BoundSource {
    pub root_hash: Id32,
    pub root_wire_length: u64,
    pub group_id: Id32,
    pub claimed_transfer: Option<Id32>,
    pub key: LogicalKey,
    pub objects: Vec<(Id32, u64)>,
}

pub(crate) enum StageResult {
    Staged,
    Refreshed,
    Unchanged,
    Mismatch,
    Rejected,
}

/// Where an exact committed digest stores its prerequisite edges.
pub(crate) enum CommittedChain {
    Missing,
    /// Edges persisted for an incoming original. Empty means no further prerequisites.
    Incoming(Vec<MessageRef>),
    /// Authored logical record. Its edges are in the owner ciphertext, not incoming dependencies.
    Outgoing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingOriginal {
    pub cursor: u64,
    pub key: LogicalKey,
    pub digest: Id32,
    pub kind: u8,
    pub session: Option<Id32>,
    pub source_root: Id32,
}

/// One committed logical identity. The columns are lookup metadata.
///
/// Kind and session stay in the database and are not copied here. Callers open
/// the saved ciphertext for those values. `incoming` selects the membership table.
pub(crate) struct SavedRecord {
    pub digest: Id32,
    pub source_root: Id32,
    pub incoming: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckLink {
    pub cursor: u64,
    pub key: LogicalKey,
    pub digest: Id32,
    pub ack_author: MemberId,
    pub ack_message: Id32,
    pub request_id: Id32,
}

/// Result of one immediate original/acknowledgement transaction.
///
/// `Duplicate` and `Conflict` leave the saved original in place. Neither variant uploads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDisposition {
    New,
    Duplicate,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EarlyReceived {
    pub cursor: u64,
    pub key: LogicalKey,
    pub digest: Id32,
    pub session: Option<Id32>,
    pub from_member: MemberId,
    pub source_root: Id32,
    pub phase: ReferencePhase,
}

/// Derived prerequisite state. `phase` is metadata, not application readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingDependency {
    pub cursor: u64,
    pub key: LogicalKey,
    pub prerequisite: MessageRef,
    pub prerequisite_source: Option<Id32>,
    pub phase: ReferencePhase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRejection {
    pub cursor: u64,
    pub root_hash: Id32,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticSample {
    pub id: i64,
    pub relay_key: Id32,
    pub run: Id32,
    pub mailbox: Id32,
    pub sequence: u64,
    pub sample_len: u64,
}

fn page_bounds(after: u64, limit: u16) -> ClientResult<()> {
    if after > i64::MAX as u64 || !(1..=100).contains(&limit) {
        return Err(ClientError::Capacity);
    }
    Ok(())
}

fn row_optional_id(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<Option<Id32>> {
    let value: Option<Vec<u8>> = row.get(column)?;
    value
        .map(|bytes| bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}

fn row_id(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<Id32> {
    row.get::<_, Vec<u8>>(column)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn row_key(row: &rusqlite::Row<'_>, start: usize) -> rusqlite::Result<LogicalKey> {
    Ok(LogicalKey {
        vault: row_id(row, start)?,
        roster: row_id(row, start + 1)?,
        sender: row.get(start + 2)?,
        message: row_id(row, start + 3)?,
    })
}

impl ClientStore {
    /// Checks public association against the current database without changing it.
    pub fn check_association(&self, roster: &Roster, owner: MemberId) -> ClientResult<()> {
        if owner == 0 || !roster.members.iter().any(|member| member.id == owner) {
            return Err(ClientError::Identity);
        }
        if validate_metadata(&self.connection, roster, roster_digest(roster)?, owner)? != CURRENT_CATALOG
        {
            return Err(ClientError::Storage);
        }
        Ok(())
    }

    /// Pages local metadata only. Recovery views carry no preparation or authentication authority.
    pub fn recover_logical(&self, after: u64, limit: u16) -> ClientResult<Vec<RecoveryLogical>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,vault,roster,sender,message_id,digest,kind,session,source_root FROM logical_records WHERE rowid>?1 ORDER BY rowid LIMIT ?2"
        )?;
        let rows = statement.query_map(params![after, limit], |r| {
            let session: Option<Vec<u8>> = r.get(7)?;
            Ok(RecoveryLogical {
                cursor: r.get(0)?,
                key: row_key(r, 1)?,
                digest: row_id(r, 5)?,
                kind: r.get(6)?,
                session: session
                    .map(|v| v.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                    .transpose()?,
                source_root: row_id(r, 8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_recipients(&self, key: &LogicalKey) -> ClientResult<Vec<RecoveryRecipient>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT recipient,transfer,root_hash,state FROM outgoing_recipients WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 ORDER BY recipient LIMIT {}",
            loki_relay_protocol::types::MAX_MEMBERS
        ))?;
        let rows = statement.query_map(
            params![key.vault, key.roster, key.sender, key.message],
            |r| {
                let transfer: Option<Vec<u8>> = r.get(1)?;
                Ok(RecoveryRecipient {
                    recipient: r.get(0)?,
                    transfer: transfer
                        .map(|v| v.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                        .transpose()?,
                    root_hash: row_id(r, 2)?,
                    needs_route: r.get::<_, String>(3)? == "needs_route",
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_requirements(
        &self,
        key: &LogicalKey,
        recipient: MemberId,
        after: Option<&Id32>,
        limit: u16,
    ) -> ClientResult<Vec<RecoveryRequirement>> {
        page_bounds(0, limit)?;
        if !(1..=self.member_count as u16).contains(&recipient) {
            return Err(ClientError::Identity);
        }
        let mut statement = self.connection.prepare(
            "SELECT hash,length,ordinal FROM required_objects WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND (?6 IS NULL OR hash>?6) ORDER BY hash LIMIT ?7"
        )?;
        let rows = statement.query_map(
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                recipient,
                after,
                limit
            ],
            |r| {
                Ok(RecoveryRequirement {
                    hash: row_id(r, 0)?,
                    length: r.get(1)?,
                    ordinal: r.get(2)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_uploads(&self, after: u64, limit: u16) -> ClientResult<Vec<RecoveryUpload>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox,attempts,retry_at,state FROM upload_work WHERE rowid>?1 ORDER BY rowid LIMIT ?2"
        )?;
        let rows = statement.query_map(params![after, limit], |r| {
            Ok(RecoveryUpload {
                cursor: r.get(0)?,
                key: row_key(r, 1)?,
                recipient: r.get(5)?,
                hash: row_id(r, 6)?,
                relay_key: row_id(r, 7)?,
                run: row_id(r, 8)?,
                mailbox: row_id(r, 9)?,
                attempts: r.get(10)?,
                retry_at: r.get(11)?,
                acknowledged: r.get::<_, String>(12)? == "acknowledged",
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Returns saved bytes only; receipt verification remains the later consumer's responsibility.
    pub fn saved_receipt(&self, upload: &RecoveryUpload) -> ClientResult<Option<Vec<u8>>> {
        Ok(self.connection.query_row(
            "SELECT receipt FROM verified_receipts WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9 AND length(receipt) BETWEEN 1 AND 4096",
            params![upload.key.vault,upload.key.roster,upload.key.sender,upload.key.message,upload.recipient,upload.hash,upload.relay_key,upload.run,upload.mailbox], |r| r.get(0),
        ).optional()?)
    }

    pub fn saved_object(&self, hash: &Id32) -> ClientResult<Option<Object>> {
        let wire: Option<Vec<u8>> = self.connection.query_row(
            "SELECT wire FROM ciphertext_objects WHERE hash=?1 AND length BETWEEN 1024 AND 65536 AND length%1024=0 AND length(wire)=length", [hash], |r| r.get(0),
        ).optional()?;
        wire.map(|wire| {
            if <Id32>::from(Sha256::digest(&wire)) != *hash {
                return Err(ClientError::Storage);
            }
            Ok(Object { hash: *hash, wire })
        })
        .transpose()
    }
}

fn storage_pages(connection: &Connection, budget: u64) -> ClientResult<(u64, u64)> {
    let size: u64 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
    if !(512..=65536).contains(&size) || !size.is_power_of_two() {
        return Err(ClientError::Storage);
    }
    let limit = budget
        .checked_div(size)
        .filter(|v| *v > 0 && *v <= i64::MAX as u64)
        .ok_or(ClientError::Capacity)?;
    let allocated: u64 = connection.pragma_query_value(None, "page_count", |r| r.get(0))?;
    Ok((allocated, limit))
}

fn configure_storage_limit(connection: &Connection, budget: u64) -> ClientResult<()> {
    let (allocated, requested) = storage_pages(connection, budget)?;
    connection.pragma_update(None, "max_page_count", requested)?;
    let effective: u64 = connection.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
    if effective != requested.max(allocated) {
        return Err(ClientError::Storage);
    }
    Ok(())
}

pub(crate) fn admit_storage_growth(connection: &Connection, budget: u64) -> ClientResult<()> {
    let (allocated, limit) = storage_pages(connection, budget)?;
    let effective: u64 = connection.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
    if effective == 0 || effective > limit.max(allocated) {
        return Err(ClientError::Storage);
    }
    // SQLite raises an undersized page ceiling to the current allocation;
    // its remaining free pages do not authorize growth above our budget.
    if allocated > limit {
        return Err(ClientError::Capacity);
    }
    Ok(())
}

fn reserve_pending(current: u64, additional: u64) -> ClientResult<()> {
    if current
        .checked_add(additional)
        .filter(|v| *v <= PENDING_TRANSFERS)
        .is_none()
    {
        return Err(ClientError::Capacity);
    }
    Ok(())
}

fn outgoing_pending_count(connection: &Connection) -> ClientResult<u64> {
    connection
        .query_row(
            "SELECT count(*) FROM outgoing_recipients o WHERE o.state IN ('needs_route','pending') AND NOT EXISTS (SELECT 1 FROM delivery_completion c WHERE c.vault=o.vault AND c.roster=o.roster AND c.sender=o.sender AND c.message_id=o.message_id)",
            [],
            |r| r.get(0),
        )
        .map_err(Into::into)
}

/// A group stays open while required bytes are still absent or a root is unclassified.
///
/// A pending download whose ciphertext is already cached is stale bookkeeping. It does not
/// keep a published root in the shared count, and the task, reason, and cursor stay. A root
/// that is not rejected, published, or tied to an exact saved digest stays open. Another
/// incomplete root in the same group does too. Claimed identity without that digest does not
/// retire a different body.
const GROUP_OPEN: &str = "EXISTS (
    SELECT 1 FROM staged_sources s
    WHERE s.group_id=g.group_id
    AND NOT EXISTS (SELECT 1 FROM source_rejections j WHERE j.root_hash=s.root_hash)
    AND (
        EXISTS (
            SELECT 1 FROM pending_downloads d
            WHERE d.source_hash=s.root_hash
            AND NOT EXISTS (SELECT 1 FROM ciphertext_objects c WHERE c.hash=d.source_hash)
        )
        OR EXISTS (
            SELECT 1 FROM staged_requirements r
            WHERE r.root_hash=s.root_hash
            AND EXISTS (
                SELECT 1 FROM pending_downloads d
                WHERE d.source_hash=r.hash
                AND NOT EXISTS (SELECT 1 FROM ciphertext_objects c WHERE c.hash=d.source_hash)
            )
        )
        OR (
            NOT EXISTS (SELECT 1 FROM incoming_originals i WHERE i.source_root=s.root_hash)
            AND NOT EXISTS (SELECT 1 FROM incoming_conflicts c WHERE c.source_root=s.root_hash)
            AND NOT EXISTS (SELECT 1 FROM logical_records l WHERE l.source_root=s.root_hash)
            AND NOT EXISTS (SELECT 1 FROM outgoing_recipients o WHERE o.root_hash=s.root_hash)
            AND NOT EXISTS (
                SELECT 1 FROM incoming_journal j
                JOIN incoming_originals i
                  ON i.vault=s.claimed_vault AND i.roster=s.claimed_roster
                 AND i.sender=s.claimed_sender AND i.message_id=s.claimed_message
                 AND i.digest=j.body_digest
                WHERE j.source_hash=s.root_hash AND j.body_digest IS NOT NULL
            )
            AND NOT EXISTS (
                SELECT 1 FROM incoming_journal j
                JOIN logical_records l
                  ON l.vault=s.claimed_vault AND l.roster=s.claimed_roster
                 AND l.sender=s.claimed_sender AND l.message_id=s.claimed_message
                 AND l.digest=j.body_digest
                WHERE j.source_hash=s.root_hash AND j.body_digest IS NOT NULL
            )
            AND NOT EXISTS (
                SELECT 1 FROM incoming_journal j
                JOIN incoming_conflicts c
                  ON c.vault=s.claimed_vault AND c.roster=s.claimed_roster
                 AND c.sender=s.claimed_sender AND c.message_id=s.claimed_message
                 AND c.digest=j.body_digest
                WHERE j.source_hash=s.root_hash AND j.body_digest IS NOT NULL
            )
        )
    )
)";

fn incoming_pending_groups(connection: &Connection) -> ClientResult<u64> {
    connection
        .query_row(
            &format!("SELECT count(*) FROM transfer_groups g WHERE {GROUP_OPEN}"),
            [],
            |r| r.get(0),
        )
        .map_err(Into::into)
}

fn pending_transfer_total(connection: &Connection) -> ClientResult<u64> {
    outgoing_pending_count(connection)?
        .checked_add(incoming_pending_groups(connection)?)
        .ok_or(ClientError::Capacity)
}

fn admit_outbox(connection: &Connection, budget: u64, member_count: usize) -> ClientResult<()> {
    admit_storage_growth(connection, budget)?;
    reserve_pending(pending_transfer_total(connection)?, member_count as u64)
}

fn logical_at(connection: &Connection, key: &LogicalKey) -> ClientResult<Option<RecoveryLogical>> {
    Ok(connection.query_row(
        "SELECT rowid,vault,roster,sender,message_id,digest,kind,session,source_root FROM logical_records WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4",
        params![key.vault,key.roster,key.sender,key.message], |r| {
            let session: Option<Vec<u8>>=r.get(7)?;
            Ok(RecoveryLogical { cursor:r.get(0)?,key:row_key(r,1)?,digest:row_id(r,5)?,kind:r.get(6)?,session:session.map(|v|v.try_into().map_err(|_|rusqlite::Error::InvalidQuery)).transpose()?,source_root:row_id(r,8)? })
        }).optional()?)
}

fn stored_sets(
    connection: &Connection,
    logical: &RecoveryLogical,
    member_count: usize,
) -> ClientResult<Vec<(RecoveryRecipient, Vec<Object>)>> {
    let key = &logical.key;
    let mut statement=connection.prepare("SELECT recipient,transfer,root_hash,state FROM outgoing_recipients WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 ORDER BY recipient")?;
    let rows = statement.query_map(
        params![key.vault, key.roster, key.sender, key.message],
        |r| {
            let transfer: Option<Vec<u8>> = r.get(1)?;
            Ok(RecoveryRecipient {
                recipient: r.get(0)?,
                transfer: transfer
                    .map(|v| v.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                    .transpose()?,
                root_hash: row_id(r, 2)?,
                needs_route: r.get::<_, String>(3)? == "needs_route",
            })
        },
    )?;
    let recipients = rows.collect::<Result<Vec<_>, _>>()?;
    if recipients.len() != member_count || recipients.iter().enumerate().any(|(index, recipient)| recipient.recipient != index as u16 + 1) {
        return Err(ClientError::Storage);
    }
    let mut sets = Vec::with_capacity(member_count);
    let mut hashes = std::collections::BTreeSet::new();
    for recipient in recipients {
        let mut statement=connection.prepare("SELECT r.ordinal,r.hash,r.length,c.wire FROM required_objects r JOIN ciphertext_objects c ON r.hash=c.hash AND r.length=c.length WHERE r.vault=?1 AND r.roster=?2 AND r.sender=?3 AND r.message_id=?4 AND r.recipient=?5 ORDER BY r.ordinal LIMIT 276")?;
        let rows = statement.query_map(
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                recipient.recipient
            ],
            |r| {
                Ok((
                    r.get::<_, u16>(0)?,
                    r.get::<_, u64>(2)?,
                    Object {
                        hash: row_id(r, 1)?,
                        wire: r.get(3)?,
                    },
                ))
            },
        )?;
        let mut objects = vec![];
        for row in rows {
            let (ordinal, length, object) = row?;
            if ordinal as usize != objects.len()
                || length != object.wire.len() as u64
                || !hashes.insert(object.hash)
            {
                return Err(ClientError::Storage);
            }
            objects.push(object);
        }
        crate::outbox::validate_set(&objects, recipient.transfer.as_ref(), &recipient.root_hash)
            .map_err(|_| ClientError::Storage)?;
        if let Some((prior, prior_objects)) = sets.first() {
            let prior: &RecoveryRecipient = prior;
            let prior_objects: &Vec<Object> = prior_objects;
            if prior.transfer.is_some() != recipient.transfer.is_some()
                || !prior_objects
                    .iter()
                    .map(|o| o.wire.len())
                    .eq(objects.iter().map(|o| o.wire.len()))
            {
                return Err(ClientError::Storage);
            }
        }
        if recipient.recipient == key.sender && recipient.root_hash != logical.source_root {
            return Err(ClientError::Storage);
        }
        sets.push((recipient, objects));
    }
    Ok(sets)
}

fn request_at(
    connection: &Connection,
    request: &Id32,
    intent: &Id32,
    member_count: usize,
) -> ClientResult<Option<RecoveryLogical>> {
    let mapping=connection.query_row("SELECT intent_digest,vault,roster,sender,message_id FROM caller_requests WHERE request_id=?1",[request],|r|Ok((row_id(r,0)?,row_key(r,1)?))).optional()?;
    let Some((saved_intent, key)) = mapping else {
        return Ok(None);
    };
    if saved_intent != *intent {
        return Err(ClientError::Conflict);
    }
    let logical = logical_at(connection, &key)?.ok_or(ClientError::Storage)?;
    stored_sets(connection, &logical, member_count)?;
    Ok(Some(logical))
}

fn verify_saved(
    connection: &Connection,
    roster: &Roster,
    identity: &crate::CommIdentity,
    logical: &RecoveryLogical,
    intent: &Id32,
) -> ClientResult<()> {
    let sets = stored_sets(connection, logical, roster.members.len())?;
    let objects = &sets
        .iter()
        .find(|(r, _)| r.recipient == identity.public().id)
        .ok_or(ClientError::Identity)?
        .1;
    let message = crate::outbox::authenticate_author(roster, identity, objects)?;
    let kind = match message.body().payload {
        loki_relay_protocol::types::Payload::Test(_) => 1,
        loki_relay_protocol::types::Payload::Received(_) => 2,
    };
    if message.body().key != logical.key
        || *message.digest() != logical.digest
        || message.body().session != logical.session
        || kind != logical.kind
        || crate::outbox::outbox_intent_digest(message.body())? != *intent
    {
        return Err(ClientError::Conflict);
    }
    Ok(())
}

fn insert_request(
    connection: &Connection,
    request: &Id32,
    intent: &Id32,
    key: &LogicalKey,
) -> ClientResult<()> {
    connection.execute(
        "INSERT INTO caller_requests VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            request,
            intent,
            key.vault,
            key.roster,
            key.sender,
            key.message
        ],
    )?;
    Ok(())
}

/// Insert one prepared outbox into the caller's transaction.
///
/// The caller begins the immediate transaction, admits capacity, and commits.
/// This writes ciphertext, the logical record, all roster recipient sets, and the
/// caller mapping. It does not start another transaction or upload.
fn persist_prepared_outbox(
    connection: &Connection,
    prepared: &crate::PreparedOutbox,
    validated: &crate::outbox::ValidatedOutbox,
    request_id: &Id32,
) -> ClientResult<()> {
    let key = prepared.key();
    for recipient in prepared.recipients() {
        for object in recipient.objects() {
            let prior: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT wire FROM ciphertext_objects WHERE hash=?1",
                    [object.hash],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(wire) = prior {
                if wire != object.wire {
                    return Err(ClientError::Conflict);
                }
            } else {
                let inserted = connection.execute(
                    "INSERT INTO ciphertext_objects VALUES(?1,?2,?3)",
                    params![object.hash, object.wire, object.wire.len()],
                );
                #[cfg(test)]
                incoming_crash_tests::observe_allocating_insert(&inserted);
                inserted?;
            }
        }
    }
    connection.execute(
        "INSERT INTO logical_records VALUES(?1,?2,?3,?4,?5,?6,?7,'committed',?8)",
        params![
            key.vault,
            key.roster,
            key.sender,
            key.message,
            prepared.digest(),
            validated.kind,
            validated.session,
            validated.source_root
        ],
    )?;
    for recipient in prepared.recipients() {
        connection.execute(
            "INSERT INTO outgoing_recipients VALUES(?1,?2,?3,?4,?5,?6,?7,'needs_route')",
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                recipient.recipient(),
                recipient.transfer(),
                recipient.root_hash()
            ],
        )?;
        for (ordinal, object) in recipient.objects().iter().enumerate() {
            connection.execute(
                "INSERT INTO required_objects VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    key.vault,
                    key.roster,
                    key.sender,
                    key.message,
                    recipient.recipient(),
                    ordinal,
                    object.hash,
                    object.wire.len()
                ],
            )?;
        }
    }
    insert_request(connection, request_id, &validated.intent, key)?;
    Ok(())
}

struct ExistingOriginal {
    digest: Id32,
    kind: u8,
    session: Option<Id32>,
}

fn payload_kind(payload: &loki_relay_protocol::types::Payload) -> u8 {
    match payload {
        loki_relay_protocol::types::Payload::Test(_) => 1,
        loki_relay_protocol::types::Payload::Received(_) => 2,
    }
}

fn existing_original(connection: &Connection, key: &LogicalKey) -> ClientResult<Option<ExistingOriginal>> {
    connection
        .query_row(
            "SELECT digest,kind,session FROM incoming_originals WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4",
            params![key.vault, key.roster, key.sender, key.message],
            |row| {
                Ok(ExistingOriginal {
                    digest: row_id(row, 0)?,
                    kind: row.get(1)?,
                    session: row_optional_id(row, 2)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn existing_conflict_root(
    connection: &Connection,
    key: &LogicalKey,
    digest: &Id32,
) -> ClientResult<Option<Id32>> {
    connection
        .query_row(
            "SELECT source_root FROM incoming_conflicts WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND digest=?5",
            params![key.vault, key.roster, key.sender, key.message, digest],
            |row| row_id(row, 0),
        )
        .optional()
        .map_err(Into::into)
}

fn journal_state(connection: &Connection, root: &Id32) -> ClientResult<(bool, bool)> {
    let cached: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming_journal WHERE source_hash=?1 AND disposition='cached')",
        [root],
        |row| row.get(0),
    )?;
    let quarantined: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming_journal WHERE source_hash=?1 AND disposition='quarantine')",
        [root],
        |row| row.get(0),
    )?;
    Ok((cached != 0, quarantined != 0))
}

fn root_terminal(connection: &Connection, root: &Id32) -> ClientResult<bool> {
    let found: i64 = connection.query_row(
        "SELECT (
            EXISTS(SELECT 1 FROM incoming_originals WHERE source_root=?1)
            OR EXISTS(SELECT 1 FROM incoming_conflicts WHERE source_root=?1)
            OR EXISTS(SELECT 1 FROM logical_records WHERE source_root=?1)
            OR EXISTS(SELECT 1 FROM outgoing_recipients WHERE root_hash=?1)
            OR EXISTS(
                SELECT 1 FROM incoming_journal j
                JOIN staged_sources s ON s.root_hash=j.source_hash
                JOIN incoming_originals i
                  ON i.vault=s.claimed_vault AND i.roster=s.claimed_roster
                 AND i.sender=s.claimed_sender AND i.message_id=s.claimed_message
                 AND i.digest=j.body_digest
                WHERE j.source_hash=?1 AND j.body_digest IS NOT NULL
            )
            OR EXISTS(
                SELECT 1 FROM incoming_journal j
                JOIN staged_sources s ON s.root_hash=j.source_hash
                JOIN logical_records l
                  ON l.vault=s.claimed_vault AND l.roster=s.claimed_roster
                 AND l.sender=s.claimed_sender AND l.message_id=s.claimed_message
                 AND l.digest=j.body_digest
                WHERE j.source_hash=?1 AND j.body_digest IS NOT NULL
            )
            OR EXISTS(
                SELECT 1 FROM incoming_journal j
                JOIN staged_sources s ON s.root_hash=j.source_hash
                JOIN incoming_conflicts c
                  ON c.vault=s.claimed_vault AND c.roster=s.claimed_roster
                 AND c.sender=s.claimed_sender AND c.message_id=s.claimed_message
                 AND c.digest=j.body_digest
                WHERE j.source_hash=?1 AND j.body_digest IS NOT NULL
            )
        )",
        [root],
        |row| row.get(0),
    )?;
    Ok(found != 0)
}

fn object_length(connection: &Connection, hash: &Id32) -> ClientResult<i64> {
    connection
        .query_row(
            "SELECT length FROM ciphertext_objects WHERE hash=?1 AND length BETWEEN 1024 AND 65536 AND length%1024=0 AND length(wire)=length",
            [hash],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ClientError::MissingObjects(vec![*hash]))
}

fn note_body_digest(connection: &Connection, root: &Id32, digest: &Id32) -> ClientResult<()> {
    connection.execute(
        "UPDATE incoming_journal SET body_digest=?1 WHERE source_hash=?2 AND body_digest IS NULL",
        params![digest, root],
    )?;
    Ok(())
}

/// Record the authenticated digest on an alternate root when a page is available.
///
/// An exact duplicate still succeeds when the store cannot grow. The saved original and
/// acknowledgement are left untouched.
fn try_note_alternate_root(
    connection: &Connection,
    budget: u64,
    root: &Id32,
    digest: &Id32,
) -> ClientResult<()> {
    if root_terminal(connection, root)? {
        return Ok(());
    }
    let noted: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming_journal WHERE source_hash=?1 AND body_digest=?2)",
        params![root, digest],
        |row| row.get(0),
    )?;
    if noted != 0 {
        return Ok(());
    }
    match admit_storage_growth(connection, budget) {
        Err(ClientError::Capacity) => return Ok(()),
        Err(error) => return Err(error),
        Ok(()) => {}
    }
    match note_body_digest(connection, root, digest) {
        Err(ClientError::Capacity) => Ok(()),
        other => other,
    }
}

fn reopen_saved(
    connection: &Connection,
    roster: &Roster,
    identity: &crate::CommIdentity,
    source: &crate::CompleteSource,
) -> ClientResult<crate::AuthenticatedTransfer> {
    let hashes = source.required_hashes();
    if hashes.is_empty() || hashes.len() > 275 {
        return Err(ClientError::Wire(WireError::Bounds));
    }
    let mut missing = Vec::new();
    let mut root = None;
    let mut objects = std::collections::BTreeMap::new();
    for (index, hash) in hashes.iter().enumerate() {
        let wire: Option<Vec<u8>> = connection
            .query_row(
                "SELECT wire FROM ciphertext_objects WHERE hash=?1 AND length BETWEEN 1024 AND 65536 AND length%1024=0 AND length(wire)=length",
                [hash],
                |row| row.get(0),
            )
            .optional()?;
        let Some(wire) = wire else {
            missing.push(*hash);
            continue;
        };
        let object = Object {
            hash: *hash,
            wire,
        };
        if index == 0 {
            root = Some(object);
        } else {
            objects.insert(*hash, object);
        }
    }
    if !missing.is_empty() {
        return Err(ClientError::MissingObjects(missing));
    }
    crate::TransferAssembler::open(roster, identity, &root.ok_or(ClientError::Storage)?, &objects)
}

fn insert_original_objects(
    connection: &Connection,
    key: &LogicalKey,
    hashes: &[Id32],
) -> ClientResult<()> {
    for (ordinal, hash) in hashes.iter().enumerate() {
        let length = object_length(connection, hash)?;
        connection.execute(
            "INSERT INTO incoming_original_objects VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                ordinal as i64,
                hash,
                length
            ],
        )?;
    }
    Ok(())
}

fn insert_conflict_objects(
    connection: &Connection,
    key: &LogicalKey,
    digest: &Id32,
    hashes: &[Id32],
) -> ClientResult<()> {
    for (ordinal, hash) in hashes.iter().enumerate() {
        let length = object_length(connection, hash)?;
        connection.execute(
            "INSERT INTO incoming_conflict_objects VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                digest,
                ordinal as i64,
                hash,
                length
            ],
        )?;
    }
    Ok(())
}

/// Prerequisite source stays null. The edge is immutable, and a later exact original
/// resolves by sender, message, and digest rather than by rewriting this row.
fn insert_dependency_edges(
    connection: &Connection,
    message: &crate::AuthenticatedMessage,
) -> ClientResult<()> {
    let key = &message.body().key;
    for prerequisite in &message.body().prerequisites {
        connection.execute(
            "INSERT INTO incoming_dependencies VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                prerequisite.sender,
                prerequisite.message,
                prerequisite.digest
            ],
        )?;
    }
    Ok(())
}

fn insert_incoming_original(
    connection: &Connection,
    message: &crate::AuthenticatedMessage,
    source: &crate::CompleteSource,
    kind: u8,
    root: &Id32,
) -> ClientResult<()> {
    let key = &message.body().key;
    connection.execute(
        "INSERT INTO incoming_originals VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            key.vault,
            key.roster,
            key.sender,
            key.message,
            message.digest(),
            kind,
            message.body().session,
            root
        ],
    )?;
    insert_original_objects(connection, key, source.required_hashes())?;
    insert_dependency_edges(connection, message)?;
    // The application row is the test effect. It has no readiness column. A matching
    // original is not treated as a cycle-free ready chain; missing edges stay pending.
    if kind == 1 {
        connection.execute(
            "INSERT INTO incoming_application VALUES(?1,?2,?3,?4)",
            params![key.vault, key.roster, key.sender, key.message],
        )?;
    }
    Ok(())
}

fn save_conflict(
    connection: &Connection,
    budget: u64,
    message: &crate::AuthenticatedMessage,
    source: &crate::CompleteSource,
    root: &Id32,
) -> ClientResult<()> {
    let key = &message.body().key;
    if let Some(saved_root) = existing_conflict_root(connection, key, message.digest())? {
        if saved_root != *root {
            try_note_alternate_root(connection, budget, root, message.digest())?;
        }
        return Ok(());
    }
    admit_storage_growth(connection, budget)?;
    connection.execute(
        "INSERT INTO incoming_conflicts VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            key.vault,
            key.roster,
            key.sender,
            key.message,
            message.digest(),
            root
        ],
    )?;
    insert_conflict_objects(connection, key, message.digest(), source.required_hashes())?;
    note_body_digest(connection, root, message.digest())?;
    Ok(())
}

fn reuse_saved_ack(
    connection: &Connection,
    roster: &Roster,
    identity: &crate::CommIdentity,
    message: &crate::AuthenticatedMessage,
) -> ClientResult<()> {
    let owner = identity.public().id;
    let request_id = crate::received::ack_request_id(owner, message);
    let key = &message.body().key;
    let saved = connection
        .query_row(
            "SELECT ack_message,request_id FROM ack_links WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND digest=?5 AND ack_author=?6",
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                message.digest(),
                owner
            ],
            |row| Ok((row_id(row, 0)?, row_id(row, 1)?)),
        )
        .optional()?;
    let Some((saved_ack, saved_request)) = saved else {
        return Err(ClientError::Storage);
    };
    // The message id is the random value stored with the first commit. The caller id stays derived.
    if saved_request != request_id {
        return Err(ClientError::Storage);
    }
    let logical = logical_at(
        connection,
        &LogicalKey {
            vault: key.vault,
            roster: key.roster,
            sender: owner,
            message: saved_ack,
        },
    )?
    .ok_or(ClientError::Storage)?;
    let expected = crate::received::received_body(owner, message, saved_ack)?;
    let intent = crate::outbox::outbox_intent_digest(&expected)?;
    verify_saved(connection, roster, identity, &logical, &intent)
}

fn commit_reuse(transaction: rusqlite::Transaction<'_>) -> ClientResult<()> {
    if let Err(error) = transaction.commit() {
        let error = ClientError::from(error);
        if error == ClientError::Capacity {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn reconcile_self(
    transaction: rusqlite::Transaction<'_>,
    budget: u64,
    message: &crate::AuthenticatedMessage,
    kind: u8,
    root: &Id32,
    source: &crate::CompleteSource,
) -> ClientResult<CommitDisposition> {
    let Some(logical) = logical_at(&transaction, &message.body().key)? else {
        // No outgoing record means this copy is not the author's committed message.
        return Err(ClientError::Identity);
    };
    if logical.digest == *message.digest()
        && logical.session == message.body().session
        && logical.kind == kind
    {
        try_note_alternate_root(&transaction, budget, root, message.digest())?;
        commit_reuse(transaction)?;
        return Ok(CommitDisposition::Duplicate);
    }
    // A different body under the author's id is evidence only. The outgoing record stays.
    save_conflict(&transaction, budget, message, source, root)?;
    transaction.commit()?;
    Ok(CommitDisposition::Conflict)
}

impl ClientStore {
    /// Look up a prior caller operation before allocating or encrypting a fresh message.
    /// The returned view is recovery metadata, not authentication authority.
    pub fn lookup_outbox_request(
        &self,
        request_id: &Id32,
        expected_intent: &Id32,
    ) -> ClientResult<Option<RecoveryLogical>> {
        request_at(&self.connection, request_id, expected_intent, self.member_count)
    }

    /// Commit all recipient bytes and the caller binding before exposing any work.
    /// Routing is deferred until an authenticated configuration consumer binds it.
    ///
    /// ```compile_fail
    /// use loki_relay_client::PreparedOutbox;
    /// fn mix(first: &mut PreparedOutbox, second: &PreparedOutbox) {
    ///     first.recipients()[1] = second.recipients()[1];
    /// }
    /// ```
    /// ```compile_fail
    /// use loki_relay_client::PreparedOutbox;
    /// fn inject(first: &mut PreparedOutbox, second: &PreparedOutbox) {
    ///     first.recipients()[1].objects()[0] = second.recipients()[1].objects()[0].clone();
    /// }
    /// ```
    pub fn commit_outbox(
        &mut self,
        roster: &Roster,
        identity: &crate::CommIdentity,
        request_id: &Id32,
        prepared: &crate::PreparedOutbox,
    ) -> ClientResult<RecoveryLogical> {
        let validated = crate::outbox::validate(roster, identity, prepared)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if validate_metadata(
            &transaction,
            roster,
            roster_digest(roster)?,
            identity.public().id,
        )? != CURRENT_CATALOG
        {
            return Err(ClientError::Storage);
        }
        if let Some(logical) = request_at(&transaction, request_id, &validated.intent, self.member_count)? {
            verify_saved(&transaction, roster, identity, &logical, &validated.intent)?;
            transaction.commit()?;
            return Ok(logical);
        }
        let key = prepared.key();
        if let Some(logical) = logical_at(&transaction, key)? {
            if logical.digest != *prepared.digest() {
                return Err(ClientError::Conflict);
            }
            verify_saved(&transaction, roster, identity, &logical, &validated.intent)?;
            admit_storage_growth(&transaction, self.storage_budget)?;
            insert_request(&transaction, request_id, &validated.intent, key)?;
            transaction.commit()?;
            return Ok(logical);
        }
        admit_outbox(&transaction, self.storage_budget, self.member_count)?;
        persist_prepared_outbox(&transaction, prepared, &validated, request_id)?;
        let logical = logical_at(&transaction, key)?.ok_or(ClientError::Storage)?;
        #[cfg(test)]
        outbox_commit_tests::checkpoint(&transaction, 1)?;
        // Test pause holds the uncommitted outbox transaction. Production builds omit it.
        #[cfg(test)]
        outbox_commit_tests::pause_barrier("before-commit");
        transaction.commit()?;
        #[cfg(test)]
        outbox_commit_tests::checkpoint(&self.connection, 2)?;
        #[cfg(test)]
        outbox_commit_tests::pause_barrier("after-commit");
        Ok(logical)
    }
}

pub(crate) struct RouteRejection {
    pub descriptor_revision: u64,
    pub append_revision: u64,
    pub config_revision: u64,
}

pub(crate) struct StoredUpload {
    pub upload: RecoveryUpload,
    pub rejection: Option<RouteRejection>,
}

fn persisted_revision(value: u64) -> ClientResult<i64> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(ClientError::Config);
    }
    Ok(value as i64)
}

fn own_inboxes_match(own: &[crate::OwnerInbox], relays: &[crate::DescriptorRelay]) -> bool {
    own.len() == relays.len()
        && relays.len() == 3
        && relays.iter().all(|relay| {
            own.iter().any(|inbox| {
                inbox.route == relay.route && inbox.append.as_bytes() == relay.append.as_bytes()
            })
        })
}

fn route_pins(relays: &[crate::DescriptorRelay]) -> ClientResult<Vec<(Id32, Id32, Id32)>> {
    if relays.len() != 3 {
        return Err(ClientError::Identity);
    }
    Ok(relays
        .iter()
        .map(|relay| (relay.route.pin.key, relay.route.pin.run, relay.route.mailbox))
        .collect())
}

fn status_routes(
    sender: MemberId,
    recipient: MemberId,
    vault: &Id32,
    roster: &Id32,
    config: &crate::ClientConfig,
    self_body: &crate::Descriptor,
) -> Vec<RelayRoute> {
    if recipient == sender {
        if !own_inboxes_match(&config.own, &self_body.relays) {
            return Vec::new();
        }
        return self_body
            .relays
            .iter()
            .map(|relay| relay.route.clone())
            .collect();
    }
    let Some(peer) = config.peers.iter().find(|peer| {
        let body = peer.body();
        body.owner == recipient
            && body.vault == *vault
            && body.roster == *roster
            && body.relays.len() == 3
    }) else {
        return Vec::new();
    };
    peer.body()
        .relays
        .iter()
        .map(|relay| relay.route.clone())
        .collect()
}

fn route_covers(
    connection: &Connection,
    logical: &RecoveryLogical,
    recipient: MemberId,
    route: &RelayRoute,
    objects: &[Object],
) -> ClientResult<bool> {
    if objects.is_empty() {
        return Ok(false);
    }
    for object in objects {
        let saved: Option<Vec<u8>> = connection
            .query_row(
                "SELECT receipt FROM verified_receipts WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9",
                params![
                    logical.key.vault,
                    logical.key.roster,
                    logical.key.sender,
                    logical.key.message,
                    recipient,
                    object.hash,
                    route.pin.key,
                    route.pin.run,
                    route.mailbox
                ],
                |row| row.get(0),
            )
            .optional()?;
        let Some(bytes) = saved else {
            return Ok(false);
        };
        if crate::http::verify_saved_receipt(route, &bytes, object.hash, object.wire.len() as u64)
            .is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn complete_pins(
    connection: &Connection,
    logical: &RecoveryLogical,
    recipient: MemberId,
    routes: &[RelayRoute],
    objects: &[Object],
) -> ClientResult<Vec<(Id32, Id32)>> {
    let mut pins = std::collections::BTreeSet::new();
    for route in routes {
        if route_covers(connection, logical, recipient, route, objects)? {
            pins.insert((route.pin.key, route.pin.run));
        }
    }
    Ok(pins.into_iter().collect())
}

fn delivery_union(
    connection: &Connection,
    roster: &Roster,
    identity: &crate::CommIdentity,
    logical: &RecoveryLogical,
    config: &crate::ClientConfig,
    self_route: &crate::AuthenticatedDescriptor,
) -> ClientResult<crate::outbox::DeliveryReport> {
    let digest = roster_digest(roster)?;
    let sender = identity.public().id;
    if sender == 0 || !roster.members.iter().any(|member| member.id == sender) {
        return Err(ClientError::Identity);
    }
    let mut owners = std::collections::BTreeSet::new();
    for peer in &config.peers {
        let owner = peer.body().owner;
        if owner == sender || !owners.insert(owner) {
            return Err(ClientError::Identity);
        }
    }
    let self_body = self_route.body();
    if self_body.owner != sender
        || self_body.vault != roster.vault
        || self_body.roster != digest
        || self_body.relays.len() != 3
    {
        return Err(ClientError::Identity);
    }
    if validate_metadata(connection, roster, digest, sender)? != CURRENT_CATALOG {
        return Err(ClientError::Storage);
    }
    let Some(reloaded) = logical_at(connection, &logical.key)? else {
        return Err(ClientError::Storage);
    };
    if reloaded.key.sender != sender
        || reloaded.key.vault != roster.vault
        || reloaded.key.roster != digest
    {
        return Err(ClientError::Identity);
    }
    let sets = stored_sets(connection, &reloaded, roster.members.len())?;
    let mut members = vec![Vec::new(); roster.members.len()];
    for (recipient, objects) in &sets {
        let routes = status_routes(
            sender,
            recipient.recipient,
            &reloaded.key.vault,
            &reloaded.key.roster,
            config,
            self_body,
        );
        let pins = complete_pins(connection, &reloaded, recipient.recipient, &routes, objects)?;
        let index = usize::from(recipient.recipient - 1);
        if index >= members.len() {
            return Err(ClientError::Storage);
        }
        members[index] = pins;
    }
    let whole = members[0]
        .iter()
        .copied()
        .filter(|pin| members.iter().skip(1).all(|member| member.contains(pin)))
        .collect();
    Ok(crate::outbox::DeliveryReport::new(
        reloaded.key,
        reloaded.source_root,
        members,
        whole,
    ))
}

fn stored_upload(row: &rusqlite::Row<'_>) -> ClientResult<StoredUpload> {
    let rejection = match (
        row.get::<_, Option<i64>>(13)?,
        row.get::<_, Option<i64>>(14)?,
        row.get::<_, Option<i64>>(15)?,
        row.get::<_, Option<Vec<u8>>>(16)?,
    ) {
        (None, None, None, None) => None,
        (Some(descriptor), Some(append), Some(config), Some(hash))
            if descriptor > 0 && append > 0 && config > 0 && hash.len() == 32 =>
        {
            Id32::try_from(hash).map_err(|_| ClientError::Storage)?;
            Some(RouteRejection {
                descriptor_revision: descriptor as u64,
                append_revision: append as u64,
                config_revision: config as u64,
            })
        }
        _ => return Err(ClientError::Storage),
    };
    Ok(StoredUpload {
        upload: RecoveryUpload {
            cursor: row.get(0)?,
            key: row_key(row, 1)?,
            recipient: row.get(5)?,
            hash: row_id(row, 6)?,
            relay_key: row_id(row, 7)?,
            run: row_id(row, 8)?,
            mailbox: row_id(row, 9)?,
            attempts: row.get(10)?,
            retry_at: row.get(11)?,
            acknowledged: row.get::<_, String>(12)? == "acknowledged",
        },
        rejection,
    })
}

fn upload_key_params(upload: &RecoveryUpload) -> [&dyn rusqlite::ToSql; 9] {
    [
        &upload.key.vault,
        &upload.key.roster,
        &upload.key.sender,
        &upload.key.message,
        &upload.recipient,
        &upload.hash,
        &upload.relay_key,
        &upload.run,
        &upload.mailbox,
    ]
}

impl ClientStore {
    /// Binds committed recipient objects to the opened self descriptor and peer descriptors.
    /// A missing peer leaves only that recipient unrouted. No network call is made.
    pub fn bind_upload_routes(
        &mut self,
        roster: &Roster,
        identity: &crate::CommIdentity,
        logical: &RecoveryLogical,
        config: &crate::ClientConfig,
        self_route: &crate::AuthenticatedDescriptor,
    ) -> ClientResult<()> {
        let digest = roster_digest(roster)?;
        let sender = identity.public().id;
        if sender == 0 || !roster.members.iter().any(|member| member.id == sender) {
            return Err(ClientError::Identity);
        }
        let mut owners = std::collections::BTreeSet::new();
        for peer in &config.peers {
            let owner = peer.body().owner;
            if owner == sender || !owners.insert(owner) {
                return Err(ClientError::Identity);
            }
        }
        let self_body = self_route.body();
        if self_body.owner != sender
            || self_body.vault != roster.vault
            || self_body.roster != digest
            || self_body.relays.len() != 3
        {
            return Err(ClientError::Identity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if validate_metadata(&transaction, roster, digest, sender)? != CURRENT_CATALOG {
            return Err(ClientError::Storage);
        }
        let Some(reloaded) = logical_at(&transaction, &logical.key)? else {
            return Err(ClientError::Storage);
        };
        if reloaded.key.sender != sender
            || reloaded.key.vault != roster.vault
            || reloaded.key.roster != digest
        {
            return Err(ClientError::Identity);
        }
        let sets = stored_sets(&transaction, &reloaded, roster.members.len())?;
        let mut admitted = false;
        for (recipient, objects) in &sets {
            let pins = if recipient.recipient == sender {
                if !own_inboxes_match(&config.own, &self_body.relays) {
                    continue;
                }
                route_pins(&self_body.relays)?
            } else {
                let Some(peer) = config.peers.iter().find(|peer| {
                    let body = peer.body();
                    body.owner == recipient.recipient
                        && body.vault == reloaded.key.vault
                        && body.roster == reloaded.key.roster
                        && body.relays.len() == 3
                }) else {
                    continue;
                };
                route_pins(&peer.body().relays)?
            };
            for object in objects {
                for (relay_key, run, mailbox) in &pins {
                    let present: i64 = transaction.query_row(
                        "SELECT count(*) FROM upload_work WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9",
                        params![
                            reloaded.key.vault,
                            reloaded.key.roster,
                            reloaded.key.sender,
                            reloaded.key.message,
                            recipient.recipient,
                            object.hash,
                            relay_key,
                            run,
                            mailbox
                        ],
                        |row| row.get(0),
                    )?;
                    if present != 0 {
                        continue;
                    }
                    if !admitted {
                        admit_storage_growth(&transaction, self.storage_budget)?;
                        admitted = true;
                    }
                    transaction.execute(
                        "INSERT INTO upload_work VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending',0,0) ON CONFLICT(vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox) DO NOTHING",
                        params![
                            reloaded.key.vault,
                            reloaded.key.roster,
                            reloaded.key.sender,
                            reloaded.key.message,
                            recipient.recipient,
                            object.hash,
                            relay_key,
                            run,
                            mailbox
                        ],
                    )?;
                }
            }
            if !recipient.needs_route {
                continue;
            }
            if !admitted {
                admit_storage_growth(&transaction, self.storage_budget)?;
                admitted = true;
            }
            transaction.execute(
                "UPDATE outgoing_recipients SET state='pending' WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND state='needs_route'",
                params![
                    reloaded.key.vault,
                    reloaded.key.roster,
                    reloaded.key.sender,
                    reloaded.key.message,
                    recipient.recipient
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn message_uploads(&self, key: &LogicalKey) -> ClientResult<Vec<StoredUpload>> {
        let mut statement = self.connection.prepare(
            "SELECT w.rowid,w.vault,w.roster,w.sender,w.message_id,w.recipient,w.hash,w.relay_key,w.run,w.mailbox,w.attempts,w.retry_at,w.state,g.descriptor_revision,g.append_revision,g.config_revision,g.config_hash FROM upload_work w LEFT JOIN upload_generation g ON g.vault=w.vault AND g.roster=w.roster AND g.sender=w.sender AND g.message_id=w.message_id AND g.recipient=w.recipient AND g.hash=w.hash AND g.relay_key=w.relay_key AND g.run=w.run AND g.mailbox=w.mailbox WHERE w.vault=?1 AND w.roster=?2 AND w.sender=?3 AND w.message_id=?4 ORDER BY w.recipient,w.hash,w.relay_key",
        )?;
        let mut rows = statement.query(params![key.vault, key.roster, key.sender, key.message])?;
        let mut uploads = Vec::new();
        while let Some(row) = rows.next()? {
            uploads.push(stored_upload(row)?);
        }
        Ok(uploads)
    }

    /// Reloads one work row and its rejection after earlier writes in the same pass.
    pub(crate) fn upload_eligibility(
        &self,
        upload: &RecoveryUpload,
    ) -> ClientResult<Option<StoredUpload>> {
        let mut statement = self.connection.prepare(
            "SELECT w.rowid,w.vault,w.roster,w.sender,w.message_id,w.recipient,w.hash,w.relay_key,w.run,w.mailbox,w.attempts,w.retry_at,w.state,g.descriptor_revision,g.append_revision,g.config_revision,g.config_hash FROM upload_work w LEFT JOIN upload_generation g ON g.vault=w.vault AND g.roster=w.roster AND g.sender=w.sender AND g.message_id=w.message_id AND g.recipient=w.recipient AND g.hash=w.hash AND g.relay_key=w.relay_key AND g.run=w.run AND g.mailbox=w.mailbox WHERE w.vault=?1 AND w.roster=?2 AND w.sender=?3 AND w.message_id=?4 AND w.recipient=?5 AND w.hash=?6 AND w.relay_key=?7 AND w.run=?8 AND w.mailbox=?9",
        )?;
        let mut rows = statement.query(upload_key_params(upload))?;
        rows.next()?.map(stored_upload).transpose()
    }

    pub(crate) fn clear_rejection(&mut self, upload: &RecoveryUpload) -> ClientResult<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM upload_generation WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9",
            upload_key_params(upload),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn record_route_rejection(
        &mut self,
        key: &LogicalKey,
        recipient: MemberId,
        relay_key: &Id32,
        run: &Id32,
        mailbox: &Id32,
        descriptor_revision: u64,
        append_revision: u64,
        reference: &ConfigReference,
    ) -> ClientResult<()> {
        let descriptor_revision = persisted_revision(descriptor_revision)?;
        let append_revision = persisted_revision(append_revision)?;
        let config_revision = persisted_revision(reference.revision())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        admit_storage_growth(&transaction, self.storage_budget)?;
        let changed = transaction.execute(
            "INSERT INTO upload_generation SELECT vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox,?1,?2,?3,?4 FROM upload_work WHERE vault=?5 AND roster=?6 AND sender=?7 AND recipient=?8 AND relay_key=?9 AND run=?10 AND mailbox=?11 AND state='pending' ON CONFLICT(vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox) DO UPDATE SET descriptor_revision=excluded.descriptor_revision,append_revision=excluded.append_revision,config_revision=excluded.config_revision,config_hash=excluded.config_hash",
            params![
                descriptor_revision,
                append_revision,
                config_revision,
                reference.hash().as_slice(),
                key.vault,
                key.roster,
                key.sender,
                recipient,
                relay_key,
                run,
                mailbox
            ],
        )?;
        if changed == 0 {
            return Err(ClientError::Storage);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Reloads the work row and stores the next attempt. Acknowledged rows are left unchanged.
    pub fn schedule_upload_retry(
        &mut self,
        upload: &RecoveryUpload,
        now_ms: u64,
    ) -> ClientResult<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found = transaction
            .query_row(
                "SELECT attempts,state FROM upload_work WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9",
                upload_key_params(upload),
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((attempts, state)) = found else {
            return Err(ClientError::Storage);
        };
        if state == "acknowledged" {
            transaction.commit()?;
            return Ok(());
        }
        if state != "pending" || attempts < 0 {
            return Err(ClientError::Storage);
        }
        let attempts = u64::try_from(attempts).map_err(|_| ClientError::Storage)?;
        let next = attempts
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(ClientError::Capacity)?;
        let delay = crate::retry::sample_delay(attempts)?;
        let retry_at = now_ms
            .checked_add(delay)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(ClientError::Capacity)?;
        admit_storage_growth(&transaction, self.storage_budget)?;
        let changed = transaction.execute(
            "UPDATE upload_work SET attempts=?1,retry_at=?2 WHERE vault=?3 AND roster=?4 AND sender=?5 AND message_id=?6 AND recipient=?7 AND hash=?8 AND relay_key=?9 AND run=?10 AND mailbox=?11 AND state='pending'",
            params![
                next as i64,
                retry_at as i64,
                upload.key.vault,
                upload.key.roster,
                upload.key.sender,
                upload.key.message,
                upload.recipient,
                upload.hash,
                upload.relay_key,
                upload.run,
                upload.mailbox
            ],
        )?;
        if changed != 1 {
            return Err(ClientError::Storage);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Publishes one verified receipt for the reloaded work row. The selector is not authority.
    pub fn commit_upload_receipt(
        &mut self,
        upload: &RecoveryUpload,
        receipt: &crate::VerifiedReceipt,
    ) -> ClientResult<()> {
        let body = receipt.body();
        let bytes = receipt.bytes();
        if bytes.is_empty() || bytes.len() > 4096 || body.retention != 1 || body.sequence == 0 || body.sequence > i64::MAX as u64
        {
            return Err(ClientError::Receipt);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found = transaction
            .query_row(
                "SELECT w.state,w.relay_key,w.run,w.mailbox,w.hash,r.length,length(c.wire) FROM upload_work w JOIN required_objects r ON r.vault=w.vault AND r.roster=w.roster AND r.sender=w.sender AND r.message_id=w.message_id AND r.recipient=w.recipient AND r.hash=w.hash JOIN ciphertext_objects c ON c.hash=w.hash AND c.length=r.length WHERE w.vault=?1 AND w.roster=?2 AND w.sender=?3 AND w.message_id=?4 AND w.recipient=?5 AND w.hash=?6 AND w.relay_key=?7 AND w.run=?8 AND w.mailbox=?9",
                upload_key_params(upload),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row_id(row, 1)?,
                        row_id(row, 2)?,
                        row_id(row, 3)?,
                        row_id(row, 4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((state, relay_key, run, mailbox, hash, required_len, wire_len)) = found else {
            return Err(ClientError::Storage);
        };
        if required_len <= 0
            || required_len != wire_len
            || required_len as u64 != body.wire_length
            || body.pin.key != relay_key
            || body.pin.run != run
            || body.mailbox != mailbox
            || body.hash != hash
        {
            return Err(ClientError::Receipt);
        }
        let saved: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT receipt FROM verified_receipts WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9",
                upload_key_params(upload),
                |row| row.get(0),
            )
            .optional()?;
        if let Some(saved) = saved {
            if saved.as_slice() != bytes {
                return Err(ClientError::Conflict);
            }
            if state != "acknowledged" {
                transaction.execute(
                    "UPDATE upload_work SET state='acknowledged' WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9",
                    upload_key_params(upload),
                )?;
            }
            transaction.commit()?;
            return Ok(());
        }
        if state != "pending" {
            return Err(ClientError::Storage);
        }
        admit_storage_growth(&transaction, self.storage_budget)?;
        transaction.execute(
            "INSERT INTO verified_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,1,?12)",
            params![
                upload.key.vault,
                upload.key.roster,
                upload.key.sender,
                upload.key.message,
                upload.recipient,
                hash,
                relay_key,
                run,
                mailbox,
                required_len,
                body.sequence as i64,
                bytes
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE upload_work SET state='acknowledged' WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 AND hash=?6 AND relay_key=?7 AND run=?8 AND mailbox=?9 AND state='pending'",
            upload_key_params(upload),
        )?;
        if changed != 1 {
            return Err(ClientError::Storage);
        }
        // Test pause sits after the receipt insert and before durable commit.
        #[cfg(test)]
        outbox_commit_tests::pause_barrier("before-receipt");
        transaction.commit()?;
        Ok(())
    }

    /// Reloads the committed message and re-verifies every saved receipt.
    /// The returned report cannot be supplied back as capacity authority.
    pub fn delivery_report(
        &mut self,
        roster: &Roster,
        identity: &crate::CommIdentity,
        logical: &RecoveryLogical,
        config: &crate::ClientConfig,
        self_route: &crate::AuthenticatedDescriptor,
    ) -> ClientResult<crate::outbox::DeliveryReport> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let report = delivery_union(&transaction, roster, identity, logical, config, self_route)?;
        transaction.commit()?;
        Ok(report)
    }

    /// Inserts the completion marker only after a fresh whole-vault union.
    /// A second call for the same logical row and source root changes nothing.
    pub fn release_stored_capacity(
        &mut self,
        roster: &Roster,
        identity: &crate::CommIdentity,
        logical: &RecoveryLogical,
        config: &crate::ClientConfig,
        self_route: &crate::AuthenticatedDescriptor,
    ) -> ClientResult<crate::outbox::DeliveryReport> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let report = delivery_union(&transaction, roster, identity, logical, config, self_route)?;
        if report.whole_vault() {
            let saved: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT source_root FROM delivery_completion WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4",
                    params![
                        report.key().vault,
                        report.key().roster,
                        report.key().sender,
                        report.key().message
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            match saved {
                Some(saved) if saved.as_slice() == report.source_root().as_slice() => {}
                Some(_) => return Err(ClientError::Conflict),
                None => {
                    admit_storage_growth(&transaction, self.storage_budget)?;
                    transaction.execute(
                        "INSERT INTO delivery_completion VALUES(?1,?2,?3,?4,?5)",
                        params![
                            report.key().vault,
                            report.key().roster,
                            report.key().sender,
                            report.key().message,
                            report.source_root().as_slice()
                        ],
                    )?;
                }
            }
        }
        transaction.commit()?;
        Ok(report)
    }

    /// Shared pending total: outgoing route rows plus nonterminal incoming groups.
    pub fn pending_transfer_count(&self) -> ClientResult<u64> {
        pending_transfer_total(&self.connection)
    }

    pub fn recover_route_cursors(&self, after: u64, limit: u16) -> ClientResult<Vec<RouteCursor>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,relay_key,run,mailbox,position FROM route_cursors WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(RouteCursor {
                cursor: row.get(0)?,
                relay_key: row_id(row, 1)?,
                run: row_id(row, 2)?,
                mailbox: row_id(row, 3)?,
                position: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Returns advertised capture metadata, including length 0 or 123 and an empty receipt.
    pub fn recover_journal(
        &self,
        route: &RelayRoute,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<JournalCapture>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT sequence,source_hash,wire_length,receipt,disposition,reason,body_digest FROM incoming_journal WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND sequence>?4 ORDER BY sequence LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![route.pin.key, route.pin.run, route.mailbox, after, limit],
            |row| {
                Ok(JournalCapture {
                    relay_key: route.pin.key,
                    run: route.pin.run,
                    mailbox: route.mailbox,
                    sequence: row.get(0)?,
                    source_hash: row_id(row, 1)?,
                    wire_length: row.get(2)?,
                    receipt: row.get(3)?,
                    disposition: row.get(4)?,
                    reason: row.get(5)?,
                    body_digest: row_optional_id(row, 6)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_pending_downloads(
        &self,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<PendingDownload>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,relay_key,run,mailbox,source_hash,wire_length,attempts,retry_at FROM pending_downloads WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(PendingDownload {
                cursor: row.get(0)?,
                relay_key: row_id(row, 1)?,
                run: row_id(row, 2)?,
                mailbox: row_id(row, 3)?,
                source_hash: row_id(row, 4)?,
                wire_length: row.get(5)?,
                attempts: row.get(6)?,
                retry_at: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_download_rejections(
        &self,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<DownloadRejection>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,relay_key,run,mailbox,source_hash,reason FROM download_rejections WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(DownloadRejection {
                cursor: row.get(0)?,
                relay_key: row_id(row, 1)?,
                run: row_id(row, 2)?,
                mailbox: row_id(row, 3)?,
                source_hash: row_id(row, 4)?,
                reason: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_staged_sources(&self, after: u64, limit: u16) -> ClientResult<Vec<StagedSource>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,root_hash,group_id,claimed_transfer FROM staged_sources WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(StagedSource {
                cursor: row.get(0)?,
                root_hash: row_id(row, 1)?,
                group_id: row_optional_id(row, 2)?,
                claimed_transfer: row_optional_id(row, 3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Pages requirements in ordinal order. `None` starts at ordinal 0; `Some(ordinal)` resumes after it.
    pub fn recover_staged_requirements(
        &self,
        root_hash: &Id32,
        after: Option<u16>,
        limit: u16,
    ) -> ClientResult<Vec<StagedRequirement>> {
        page_bounds(0, limit)?;
        if after.is_some_and(|ordinal| ordinal > 274) {
            return Err(ClientError::Capacity);
        }
        let mut statement = self.connection.prepare(
            "SELECT ordinal,hash,wire_length FROM staged_requirements WHERE root_hash=?1 AND (?2 IS NULL OR ordinal>?2) ORDER BY ordinal LIMIT ?3",
        )?;
        let rows = statement.query_map(params![root_hash, after, limit], |row| {
            Ok(StagedRequirement {
                root_hash: *root_hash,
                ordinal: row.get(0)?,
                hash: row_id(row, 1)?,
                wire_length: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_incoming_originals(
        &self,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<IncomingOriginal>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,vault,roster,sender,message_id,digest,kind,session,source_root FROM incoming_originals WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(IncomingOriginal {
                cursor: row.get(0)?,
                key: row_key(row, 1)?,
                digest: row_id(row, 5)?,
                kind: row.get(6)?,
                session: row_optional_id(row, 7)?,
                source_root: row_id(row, 8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Reopen a committed incoming message from its saved ciphertext, checking the certified sender again.
    pub fn open_incoming(
        &self,
        roster: &Roster,
        identity: &crate::CommIdentity,
        record: &IncomingOriginal,
    ) -> ClientResult<crate::AuthenticatedTransfer> {
        let owner = identity.public().id;
        self.check_association(roster, owner)?;
        let saved = self.saved_record(&record.key)?.ok_or(ClientError::Storage)?;
        let original =
            existing_original(&self.connection, &record.key)?.ok_or(ClientError::Storage)?;
        if !saved.incoming
            || saved.digest != record.digest
            || saved.source_root != record.source_root
            || original.kind != record.kind
            || original.session != record.session
        {
            return Err(ClientError::Identity);
        }
        let source = crate::CompleteSource::committed(
            self.incoming_hashes(&record.key)?,
            record.key.clone(),
            record.digest,
            owner,
        );
        if source.required_hashes().first() != Some(&record.source_root) {
            return Err(ClientError::Storage);
        }
        let opened = reopen_saved(&self.connection, roster, identity, &source)?;
        if opened.message().body().key != record.key
            || opened.message().digest() != &record.digest
            || opened.message().body().session != record.session
            || payload_kind(&opened.message().body().payload) != record.kind
            || opened.source().required_hashes() != source.required_hashes()
        {
            return Err(ClientError::Identity);
        }
        Ok(opened)
    }

    pub fn recover_ack_links(&self, after: u64, limit: u16) -> ClientResult<Vec<AckLink>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,vault,roster,sender,message_id,digest,ack_author,ack_message,request_id FROM ack_links WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], read_ack_link)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn recover_source_rejections(
        &self,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<SourceRejection>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,root_hash,reason FROM source_rejections WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(SourceRejection {
                cursor: row.get(0)?,
                root_hash: row_id(row, 1)?,
                reason: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Sample length only. The bytes are not authentication evidence.
    pub fn recover_diagnostic_samples(
        &self,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<DiagnosticSample>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT id,relay_key,run,mailbox,sequence,length(sample) FROM quarantine_samples WHERE id>?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(DiagnosticSample {
                id: row.get(0)?,
                relay_key: row_id(row, 1)?,
                run: row_id(row, 2)?,
                mailbox: row_id(row, 3)?,
                sequence: row.get(4)?,
                sample_len: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every early Received reference with its derived phase. Resolved rows are not pending.
    pub fn recover_early_received(
        &self,
        roster: &Roster,
        owner: MemberId,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<EarlyReceived>> {
        page_bounds(after, limit)?;
        let members = certified_owner(roster, owner)?;
        let stored = stored_owner(&self.connection)?;
        if stored != owner {
            return Err(ClientError::Identity);
        }
        // Every roster member, as integer literals: the roster has up to 16 members.
        let members = members
            .iter()
            .map(MemberId::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = self.connection.prepare(&format!(
            "SELECT rowid,vault,roster,sender,message_id,digest,session,from_member,source_root,phase FROM (
                SELECT e.rowid,e.vault,e.roster,e.sender,e.message_id,e.digest,e.session,e.from_member,e.source_root,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM reference_rejections j
                        WHERE j.vault=e.vault AND j.roster=e.roster AND j.sender=e.sender
                        AND j.message_id=e.message_id AND j.digest=e.digest AND j.from_member=e.from_member
                    ) THEN 'rejected'
                    WHEN e.from_member NOT IN ({members}) OR e.from_member=e.sender OR e.from_member=?3 THEN 'not_actionable'
                    WHEN NOT EXISTS (
                        SELECT 1 FROM logical_records l
                        WHERE e.sender=?3 AND l.vault=e.vault AND l.roster=e.roster AND l.sender=e.sender AND l.message_id=e.message_id
                    ) AND NOT EXISTS (
                        SELECT 1 FROM incoming_originals i
                        WHERE e.sender<>?3 AND i.vault=e.vault AND i.roster=e.roster AND i.sender=e.sender AND i.message_id=e.message_id
                    ) THEN 'pending'
                    WHEN NOT EXISTS (
                        SELECT 1 FROM logical_records l
                        WHERE e.sender=?3 AND l.vault=e.vault AND l.roster=e.roster AND l.sender=e.sender AND l.message_id=e.message_id
                        AND l.digest=e.digest AND l.session IS e.session AND l.kind=1
                    ) AND NOT EXISTS (
                        SELECT 1 FROM incoming_originals i
                        WHERE e.sender<>?3 AND i.vault=e.vault AND i.roster=e.roster AND i.sender=e.sender AND i.message_id=e.message_id
                        AND i.digest=e.digest AND i.session IS e.session AND i.kind=1
                    ) THEN 'not_actionable'
                    WHEN EXISTS (
                        SELECT 1 FROM incoming_originals p
                        WHERE p.vault=e.vault AND p.roster=e.roster AND p.sender=e.from_member AND p.kind=2 AND p.source_root=e.source_root
                    ) THEN 'resolved'
                    ELSE 'ready'
                END AS phase
                FROM early_received_refs e
            ) WHERE rowid>?1 ORDER BY rowid LIMIT ?2"
        ))?;
        let rows = statement.query_map(
            params![after, limit, owner],
            |row| {
                Ok(EarlyReceived {
                    cursor: row.get(0)?,
                    key: row_key(row, 1)?,
                    digest: row_id(row, 5)?,
                    session: row_optional_id(row, 6)?,
                    from_member: row.get(7)?,
                    source_root: row_id(row, 8)?,
                    phase: reference_phase(&row.get::<_, String>(9)?)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every dependency with its derived phase. A matching original is resolved, not pending.
    pub fn recover_dependencies(
        &self,
        after: u64,
        limit: u16,
    ) -> ClientResult<Vec<IncomingDependency>> {
        page_bounds(after, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT rowid,vault,roster,sender,message_id,prerequisite_sender,prerequisite,prerequisite_digest,prerequisite_source,phase FROM (
                SELECT d.rowid,d.vault,d.roster,d.sender,d.message_id,d.prerequisite_sender,d.prerequisite,d.prerequisite_digest,d.prerequisite_source,
                CASE
                    WHEN d.prerequisite_source IS NOT NULL AND EXISTS (
                        SELECT 1 FROM source_rejections j WHERE j.root_hash=d.prerequisite_source
                    ) THEN 'rejected'
                    WHEN EXISTS (
                        SELECT 1 FROM logical_records l
                        WHERE l.vault=d.vault AND l.roster=d.roster AND l.sender=d.prerequisite_sender
                        AND l.message_id=d.prerequisite AND l.digest=d.prerequisite_digest
                        AND (d.prerequisite_source IS NULL OR l.source_root=d.prerequisite_source)
                    ) OR EXISTS (
                        SELECT 1 FROM incoming_originals i
                        WHERE i.vault=d.vault AND i.roster=d.roster AND i.sender=d.prerequisite_sender
                        AND i.message_id=d.prerequisite AND i.digest=d.prerequisite_digest
                        AND (d.prerequisite_source IS NULL OR i.source_root=d.prerequisite_source)
                    ) THEN 'resolved'
                    WHEN EXISTS (
                        SELECT 1 FROM logical_records l
                        WHERE l.vault=d.vault AND l.roster=d.roster AND l.sender=d.prerequisite_sender
                        AND l.message_id=d.prerequisite
                    ) OR EXISTS (
                        SELECT 1 FROM incoming_originals i
                        WHERE i.vault=d.vault AND i.roster=d.roster AND i.sender=d.prerequisite_sender
                        AND i.message_id=d.prerequisite
                    ) THEN 'not_actionable'
                    WHEN d.prerequisite_source IS NOT NULL AND EXISTS (
                        SELECT 1 FROM staged_sources s
                        WHERE s.root_hash=d.prerequisite_source
                        AND s.claimed_vault=d.vault AND s.claimed_roster=d.roster
                        AND s.claimed_sender=d.prerequisite_sender AND s.claimed_message=d.prerequisite
                    ) THEN 'ready'
                    WHEN EXISTS (
                        SELECT 1 FROM staged_sources s
                        WHERE s.claimed_vault=d.vault AND s.claimed_roster=d.roster
                        AND s.claimed_sender=d.prerequisite_sender AND s.claimed_message=d.prerequisite
                    ) THEN 'not_actionable'
                    ELSE 'pending'
                END AS phase
                FROM incoming_dependencies d
            ) WHERE rowid>?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| {
            Ok(IncomingDependency {
                cursor: row.get(0)?,
                key: row_key(row, 1)?,
                prerequisite: MessageRef {
                    sender: row.get(5)?,
                    message: row_id(row, 6)?,
                    digest: row_id(row, 7)?,
                },
                prerequisite_source: row_optional_id(row, 8)?,
                phase: reference_phase(&row.get::<_, String>(9)?)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Transport-captured cached hashes, including a staged root that may need new coverage.
    ///
    /// Outgoing ciphertext with no incoming journal row is not selected. A source rejection
    /// stays excluded. A download rejection does not hide an independently valid object.
    pub(crate) fn covered_cached_hashes(
        &self,
        after: Option<&Id32>,
        limit: u16,
    ) -> ClientResult<Vec<Id32>> {
        page_bounds(0, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT hash FROM (SELECT j.source_hash AS hash FROM incoming_journal j INNER JOIN ciphertext_objects c ON c.hash=j.source_hash WHERE j.disposition='cached' UNION SELECT j.source_hash AS hash FROM staged_coverage v INNER JOIN incoming_journal j ON j.relay_key=v.relay_key AND j.run=v.run AND j.mailbox=v.mailbox AND j.sequence=v.sequence INNER JOIN ciphertext_objects c ON c.hash=j.source_hash WHERE j.disposition='cached') covered WHERE (?1 IS NULL OR covered.hash>?1) AND NOT EXISTS (SELECT 1 FROM source_rejections r WHERE r.root_hash=covered.hash) ORDER BY covered.hash LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after, limit], |row| row_id(row, 0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Classify one exact committed digest without reading a staged claim.
    ///
    /// An outgoing `logical_records` row is not given the incoming dependency table.
    /// `commit_outbox` does not write that table, so an empty read would drop authored edges.
    pub(crate) fn committed_chain(
        &self,
        vault: &Id32,
        roster: &Id32,
        sender: MemberId,
        message: &Id32,
        digest: &Id32,
    ) -> ClientResult<CommittedChain> {
        let outgoing: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM logical_records l WHERE l.vault=?1 AND l.roster=?2 AND l.sender=?3 AND l.message_id=?4 AND l.digest=?5)",
            params![vault, roster, sender, message, digest],
            |row| row.get(0),
        )?;
        if outgoing != 0 {
            return Ok(CommittedChain::Outgoing);
        }
        let incoming: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM incoming_originals i WHERE i.vault=?1 AND i.roster=?2 AND i.sender=?3 AND i.message_id=?4 AND i.digest=?5)",
            params![vault, roster, sender, message, digest],
            |row| row.get(0),
        )?;
        if incoming == 0 {
            return Ok(CommittedChain::Missing);
        }
        let mut statement = self.connection.prepare(
            "SELECT prerequisite_sender, prerequisite, prerequisite_digest FROM incoming_dependencies WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 ORDER BY prerequisite_sender, prerequisite, prerequisite_digest",
        )?;
        let rows = statement.query_map(params![vault, roster, sender, message], |row| {
            Ok(MessageRef {
                sender: row.get(0)?,
                message: row_id(row, 1)?,
                digest: row_id(row, 2)?,
            })
        })?;
        Ok(CommittedChain::Incoming(rows.collect::<Result<_, _>>()?))
    }

    /// Digest of a saved incoming original, if this logical identity already has one.
    pub(crate) fn incoming_saved_digest(&self, key: &LogicalKey) -> ClientResult<Option<Id32>> {
        Ok(existing_original(&self.connection, key)?.map(|saved| saved.digest))
    }

    /// Cached and quarantined journal presence for one hash. Missing rows are neither.
    pub(crate) fn root_journal_state(&self, root: &Id32) -> ClientResult<(bool, bool)> {
        journal_state(&self.connection, root)
    }

    /// True when this root is already a terminal incoming or outgoing association.
    ///
    /// Pending downloads are ignored here. Callers that still need the shared slot use `GROUP_OPEN`.
    pub(crate) fn incoming_root_settled(&self, root: &Id32) -> ClientResult<bool> {
        Ok(self.incoming_source_published(root)? || root_terminal(&self.connection, root)?)
    }

    /// Save one authenticated original and, for a foreign test message, its Received outbox.
    ///
    /// The immediate transaction is the whole boundary: the original, its source membership,
    /// dependency edges, and all roster acknowledgement copies commit together or not at all.
    /// Candidate readiness is not an argument. Dependency sources stay null so a later exact
    /// match is derived instead of rewriting an immutable edge. No plaintext, credential,
    /// receipt, or network write is produced.
    pub fn commit_incoming(
        &mut self,
        roster: &Roster,
        identity: &crate::CommIdentity,
        source: &crate::CompleteSource,
        message: &crate::AuthenticatedMessage,
        ack: Option<&crate::PreparedOutbox>,
    ) -> ClientResult<CommitDisposition> {
        let owner = identity.public().id;
        self.check_association(roster, owner)?;
        if source.recipient() != owner
            || source.key() != &message.body().key
            || source.digest() != message.digest()
        {
            return Err(ClientError::Identity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if validate_metadata(
            &transaction,
            roster,
            roster_digest(roster)?,
            owner,
        )? != CURRENT_CATALOG
        {
            return Err(ClientError::Storage);
        }
        if source_rejection_exists(&transaction, &source.required_hashes().first().copied().ok_or(ClientError::Storage)?)? {
            return Err(ClientError::Identity);
        }
        let root = *source.required_hashes().first().ok_or(ClientError::Storage)?;
        let (cached, quarantined) = journal_state(&transaction, &root)?;
        if quarantined && !cached {
            return Err(ClientError::MissingObjects(vec![root]));
        }
        let opened = reopen_saved(&transaction, roster, identity, source)?;
        if opened.message().canonical_body() != message.canonical_body()
            || opened.message().digest() != message.digest()
            || opened.source().required_hashes() != source.required_hashes()
            || opened.source().key() != source.key()
            || opened.source().digest() != source.digest()
            || opened.source().recipient() != owner
        {
            return Err(ClientError::Identity);
        }
        let kind = payload_kind(&message.body().payload);
        let key = message.body().key.clone();
        if let Some(saved) = existing_original(&transaction, &key)? {
            if saved.digest == *message.digest() {
                if saved.kind != kind || saved.session != message.body().session {
                    return Err(ClientError::Storage);
                }
                if kind == 1 && key.sender != owner {
                    reuse_saved_ack(&transaction, roster, identity, message)?;
                }
                try_note_alternate_root(&transaction, self.storage_budget, &root, message.digest())?;
                commit_reuse(transaction)?;
                return Ok(CommitDisposition::Duplicate);
            }
            save_conflict(&transaction, self.storage_budget, message, source, &root)?;
            transaction.commit()?;
            return Ok(CommitDisposition::Conflict);
        }
        if key.sender == owner {
            return reconcile_self(transaction, self.storage_budget, message, kind, &root, source);
        }
        if kind == 1 {
            let prepared = ack.ok_or(ClientError::Identity)?;
            let validated = crate::received::bound_ack(roster, identity, message, prepared)?;
            let request_id = crate::received::ack_request_id(owner, message);
            admit_storage_growth(&transaction, self.storage_budget)?;
            insert_incoming_original(&transaction, message, source, kind, &root)?;
            // The original root is terminal before the three acknowledgement copies are counted.
            admit_outbox(&transaction, self.storage_budget, self.member_count)?;
            persist_prepared_outbox(&transaction, prepared, &validated, &request_id)?;
            transaction.execute(
                "INSERT INTO ack_links VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    key.vault,
                    key.roster,
                    key.sender,
                    key.message,
                    message.digest(),
                    owner,
                    prepared.key().message,
                    request_id
                ],
            )?;
        } else {
            admit_storage_growth(&transaction, self.storage_budget)?;
            insert_incoming_original(&transaction, message, source, kind, &root)?;
        }
        note_body_digest(&transaction, &root, message.digest())?;
        transaction.commit()?;
        Ok(CommitDisposition::New)
    }

    pub(crate) fn source_rejected(&self, root: &Id32) -> ClientResult<bool> {
        let found: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM source_rejections WHERE root_hash=?1)",
            [root],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }

    pub(crate) fn incoming_source_published(&self, root: &Id32) -> ClientResult<bool> {
        let found: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM incoming_originals WHERE source_root=?1)",
            [root],
            |row| row.get(0),
        )?;
        Ok(found != 0)
    }

    pub(crate) fn retire_incomplete(&mut self) -> ClientResult<()> {
        let now = crate::retry::now_ms()?.max(1);
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(&format!("DELETE FROM incomplete_leases AS l WHERE NOT EXISTS(
            SELECT 1 FROM staged_sources s WHERE s.group_id=l.group_id AND {ROOT_MISSING})"), [])?;
        let expired = transaction.execute(&format!("INSERT INTO source_rejections
            SELECT s.root_hash,'incomplete_expired',NULL FROM staged_sources s
            JOIN incomplete_leases l ON l.group_id=s.group_id WHERE l.expires_ms<=?1 AND {ROOT_MISSING}"), [now])?;
        if expired != 0 {
            discard_rejected_downloads(&transaction, None)?;
            transaction.execute("DELETE FROM incomplete_leases WHERE expires_ms<=?1", [now])?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Insert one verified source, its group, and its immutable requirements.
    ///
    /// The shared pending total includes outgoing rows. A group that is already open
    /// does not take another slot. An existing source keeps its claims and refreshes
    /// coverage without another slot. An exact no-op does not admit storage growth.
    /// Cached completion does not close the group.
    pub(crate) fn stage_bound_source(&mut self, source: &BoundSource) -> ClientResult<StageResult> {
        if !(1..=self.member_count as u16).contains(&source.key.sender) || source.objects.len() > 274 {
            return Err(ClientError::Wire(WireError::Schema));
        }
        if !framed_wire(source.root_wire_length)
            || source.objects.iter().any(|(_, wire)| !framed_wire(*wire))
        {
            return Err(ClientError::Wire(WireError::Bounds));
        }
        let mut seen = std::collections::BTreeSet::from([source.root_hash]);
        if source.objects.iter().any(|(hash, _)| !seen.insert(*hash)) {
            return Err(ClientError::Wire(WireError::Schema));
        }
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if source_rejection_exists(&transaction, &source.root_hash)? {
            transaction.commit()?;
            return Ok(StageResult::Rejected);
        }
        if staged_root_exists(&transaction, &source.root_hash)? {
            let result = if same_binding(&transaction, source)? {
                let planned = plan_wanted(&transaction, &source.root_hash, &requirement_wires(source))?;
                if planned.coverage.is_empty() && planned.tasks.is_empty() {
                    StageResult::Unchanged
                } else {
                    admit_storage_growth(&transaction, self.storage_budget)?;
                    apply_wanted(&transaction, &source.root_hash, &planned)?;
                    StageResult::Refreshed
                }
            } else {
                StageResult::Mismatch
            };
            transaction.commit()?;
            return Ok(result);
        }
        admit_storage_growth(&transaction, self.storage_budget)?;
        let open = group_is_open(&transaction, &source.group_id)?;
        let additional = if open == Some(true) { 0 } else { 1 };
        reserve_pending(pending_transfer_total(&transaction)?, additional)?;
        if open.is_none() {
            transaction.execute(
                "INSERT INTO transfer_groups VALUES(?1,?2)",
                params![source.group_id, source.claimed_transfer],
            )?;
        }
        transaction.execute(
            "INSERT INTO staged_sources VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                source.root_hash,
                source.group_id,
                source.claimed_transfer,
                source.key.vault,
                source.key.roster,
                source.key.sender,
                source.key.message
            ],
        )?;
        transaction.execute(
            "INSERT INTO staged_requirements VALUES(?1,0,?2,?3)",
            params![source.root_hash, source.root_hash, source.root_wire_length as i64],
        )?;
        for (index, (hash, wire)) in source.objects.iter().enumerate() {
            let ordinal = u16::try_from(index + 1).map_err(|_| ClientError::Wire(WireError::Bounds))?;
            transaction.execute(
                "INSERT INTO staged_requirements VALUES(?1,?2,?3,?4)",
                params![source.root_hash, ordinal, hash, *wire as i64],
            )?;
        }
        let planned = plan_wanted(&transaction, &source.root_hash, &requirement_wires(source))?;
        if planned.incomplete {
            let admitted = transaction.execute(
                "INSERT OR IGNORE INTO incomplete_leases SELECT ?1,?2,?3
                 WHERE (SELECT count(*) FROM incomplete_leases WHERE sender=?2)<?4
                 AND (SELECT count(*) FROM incomplete_leases)<?5",
                params![source.group_id, source.key.sender, crate::retry::now_ms()? + INCOMPLETE_TTL_MS, incomplete_per_sender(self.member_count), INCOMPLETE_TOTAL],
            )?;
            if admitted == 0 {
                return Err(ClientError::Capacity);
            }
        }
        apply_wanted(&transaction, &source.root_hash, &planned)?;
        transaction.commit()?;
        Ok(StageResult::Staged)
    }

    /// Use the committed prerequisite only to schedule work. The source and its
    /// target still need authentication, including when the expected digest differs.
    pub(crate) fn received_original_work(&self, limit: u16) -> ClientResult<Vec<IncomingOriginal>> {
        let mut statement = self.connection.prepare(
            "SELECT i.rowid,i.vault,i.roster,i.sender,i.message_id,i.digest,i.kind,i.session,i.source_root
             FROM received_work w JOIN incoming_originals i ON i.rowid=w.source
             LEFT JOIN incoming_dependencies d ON (d.vault,d.roster,d.sender,d.message_id)=(i.vault,i.roster,i.sender,i.message_id)
             WHERE w.incoming=1 AND (d.prerequisite IS NULL OR d.prerequisite_sender=i.sender
                OR EXISTS(SELECT 1 FROM incoming_originals o WHERE (o.vault,o.roster,o.sender,o.message_id)=(d.vault,d.roster,d.prerequisite_sender,d.prerequisite))
                OR EXISTS(SELECT 1 FROM logical_records o WHERE (o.vault,o.roster,o.sender,o.message_id)=(d.vault,d.roster,d.prerequisite_sender,d.prerequisite)))
             ORDER BY w.source LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], read_received_original)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub(crate) fn received_local_work(&self, limit: u16) -> ClientResult<Vec<AckLink>> {
        let mut statement = self.connection.prepare(
            "SELECT a.rowid,a.vault,a.roster,a.sender,a.message_id,a.digest,a.ack_author,a.ack_message,a.request_id
             FROM received_work w JOIN ack_links a ON a.rowid=w.source WHERE w.incoming=0 ORDER BY w.source LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], read_ack_link)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub(crate) fn received_for_target(
        &self, key: &LogicalKey, digest: &Id32, session: Option<Id32>, signer: MemberId, after: Option<Id32>,
    ) -> ClientResult<Vec<IncomingOriginal>> {
        let mut statement = self.connection.prepare(
            "SELECT i.rowid,i.vault,i.roster,i.sender,i.message_id,i.digest,i.kind,i.session,i.source_root
             FROM incoming_dependencies d JOIN incoming_originals i ON (i.vault,i.roster,i.sender,i.message_id)=(d.vault,d.roster,d.sender,d.message_id)
             WHERE (d.vault,d.roster,d.prerequisite_sender,d.prerequisite,d.prerequisite_digest,d.sender)=(?1,?2,?3,?4,?5,?6)
             AND i.kind=2 AND i.session IS ?7 AND (?8 IS NULL OR d.message_id>?8) ORDER BY d.message_id LIMIT 16",
        )?;
        let rows = statement.query_map(params![key.vault, key.roster, key.sender, key.message, digest, signer, session, after], read_received_original)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub(crate) fn local_ack_for_target(&self, key: &LogicalKey, digest: &Id32, signer: MemberId) -> ClientResult<Option<AckLink>> {
        Ok(self.connection.query_row(
            "SELECT rowid,vault,roster,sender,message_id,digest,ack_author,ack_message,request_id FROM ack_links
             WHERE (vault,roster,sender,message_id,digest,ack_author)=(?1,?2,?3,?4,?5,?6)",
            params![key.vault, key.roster, key.sender, key.message, digest, signer], read_ack_link,
        ).optional()?)
    }

    /// Saved logical or incoming row for this identity. Neither table is signature proof.
    pub(crate) fn saved_record(&self, key: &LogicalKey) -> ClientResult<Option<SavedRecord>> {
        let outgoing = read_saved(
            &self.connection,
            "SELECT digest,source_root FROM logical_records WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4",
            key,
            false,
        )?;
        let incoming = read_saved(
            &self.connection,
            "SELECT digest,source_root FROM incoming_originals WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4",
            key,
            true,
        )?;
        match (outgoing, incoming) {
            (Some(_), Some(_)) => Err(ClientError::Storage),
            (found, None) | (None, found) => Ok(found),
        }
    }

    /// Incoming membership in ordinal order. Ordinal 0 is the transfer root.
    pub(crate) fn incoming_hashes(&self, key: &LogicalKey) -> ClientResult<Vec<Id32>> {
        ordered_hashes(
            &self.connection,
            "SELECT ordinal,hash FROM incoming_original_objects WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 ORDER BY ordinal",
            key,
            None,
        )
    }

    /// One recipient copy in ordinal order. The last hash is the transfer root.
    pub(crate) fn outgoing_hashes(
        &self,
        key: &LogicalKey,
        recipient: MemberId,
    ) -> ClientResult<Vec<Id32>> {
        if !(1..=self.member_count as u16).contains(&recipient) {
            return Err(ClientError::Identity);
        }
        ordered_hashes(
            &self.connection,
            "SELECT ordinal,hash FROM required_objects WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND recipient=?5 ORDER BY ordinal",
            key,
            Some(recipient),
        )
    }

    /// Record the first certified reference for recovery.
    ///
    /// `early_received_refs` is immutable and its primary key omits the acknowledgement
    /// message, the session, and the source root. An existing row is left unchanged.
    /// Absence of a free slot does not drop the saved acknowledgement.
    pub(crate) fn note_received_ref(
        &mut self,
        target: &LogicalKey,
        digest: &Id32,
        session: Option<Id32>,
        from_member: MemberId,
        source_root: &Id32,
    ) -> ClientResult<()> {
        if !(1..=self.member_count as u16).contains(&target.sender) || !(1..=self.member_count as u16).contains(&from_member) {
            return Err(ClientError::Identity);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: i64 = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM early_received_refs WHERE vault=?1 AND roster=?2 AND sender=?3 AND message_id=?4 AND digest=?5 AND from_member=?6)",
            params![target.vault, target.roster, target.sender, target.message, digest, from_member],
            |row| row.get(0),
        )?;
        if exists != 0 {
            transaction.commit()?;
            return Ok(());
        }
        admit_storage_growth(&transaction, self.storage_budget)?;
        transaction.execute(
            "INSERT INTO early_received_refs VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                target.vault,
                target.roster,
                target.sender,
                target.message,
                digest,
                session,
                from_member,
                source_root
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Permanent source rejection. The ciphertext stays. No transfer group is created.
    pub(crate) fn reject_source_root(
        &mut self,
        root: &Id32,
        reason: &str,
        body_digest: Option<&Id32>,
    ) -> ClientResult<()> {
        if !(1..=64).contains(&reason.len()) {
            return Err(ClientError::Storage);
        }
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if source_rejection_exists(&transaction, root)? {
            transaction.commit()?;
            return Ok(());
        }
        admit_storage_growth(&transaction, self.storage_budget)?;
        if !staged_root_exists(&transaction, root)? {
            transaction.execute(
                "INSERT INTO staged_sources VALUES(?1,NULL,NULL,NULL,NULL,NULL,NULL)",
                [root],
            )?;
        }
        transaction.execute(
            "INSERT INTO source_rejections VALUES(?1,?2,?3)",
            params![root, reason, body_digest],
        )?;
        discard_rejected_downloads(&transaction, Some(root))?;
        transaction.execute(&format!("DELETE FROM incomplete_leases AS l
            WHERE l.group_id=(SELECT group_id FROM staged_sources WHERE root_hash=?1)
            AND NOT EXISTS(SELECT 1 FROM staged_sources s WHERE s.group_id=l.group_id AND {ROOT_MISSING})"), [root])?;
        transaction.commit()?;
        Ok(())
    }
}

const ROOT_MISSING: &str = "NOT EXISTS(SELECT 1 FROM source_rejections j WHERE j.root_hash=s.root_hash)
    AND EXISTS(SELECT 1 FROM staged_requirements r WHERE r.root_hash=s.root_hash
        AND NOT EXISTS(SELECT 1 FROM ciphertext_objects c WHERE c.hash=r.hash))";

fn discard_rejected_downloads(connection: &Connection, root: Option<&Id32>) -> ClientResult<()> {
    // Retain advertised missing entries and requirements shared by any non-rejected root.
    let abandoned = "EXISTS(SELECT 1 FROM staged_requirements r JOIN source_rejections j ON j.root_hash=r.root_hash
            WHERE r.hash=d.source_hash AND (r.root_hash=?1 OR (?1 IS NULL AND j.reason='incomplete_expired')))
        AND NOT EXISTS(SELECT 1 FROM staged_requirements r WHERE r.hash=d.source_hash
            AND NOT EXISTS(SELECT 1 FROM source_rejections j WHERE j.root_hash=r.root_hash))
        AND NOT EXISTS(SELECT 1 FROM incoming_journal j WHERE j.relay_key=d.relay_key AND j.run=d.run
            AND j.mailbox=d.mailbox AND j.source_hash=d.source_hash AND j.disposition='missing')";
    connection.execute(&format!("DELETE FROM download_auth_wait AS d WHERE {abandoned}"), [root])?;
    connection.execute(&format!("DELETE FROM pending_downloads AS d WHERE {abandoned}"), [root])?;
    Ok(())
}

fn read_ack_link(row: &rusqlite::Row<'_>) -> rusqlite::Result<AckLink> {
    Ok(AckLink {
        cursor: row.get(0)?,
        key: row_key(row, 1)?,
        digest: row_id(row, 5)?,
        ack_author: row.get(6)?,
        ack_message: row_id(row, 7)?,
        request_id: row_id(row, 8)?,
    })
}

fn read_received_original(row: &rusqlite::Row<'_>) -> rusqlite::Result<IncomingOriginal> {
    Ok(IncomingOriginal {
        cursor: row.get(0)?,
        key: row_key(row, 1)?,
        digest: row_id(row, 5)?,
        kind: row.get(6)?,
        session: row_optional_id(row, 7)?,
        source_root: row_id(row, 8)?,
    })
}

fn seed_incomplete_leases(connection: &Connection, members: usize) -> ClientResult<()> {
    let now = crate::retry::now_ms()?.max(1);
    // Preserve recoverable legacy groups, but retire over-quota work on first intake.
    connection.execute(&format!("WITH missing AS (
            SELECT s.group_id,min(s.claimed_sender) AS sender,min(s.rowid) AS first_seen
            FROM staged_sources s WHERE s.group_id IS NOT NULL AND {ROOT_MISSING} GROUP BY s.group_id
        ), ranked AS (
            SELECT *,row_number() OVER (PARTITION BY sender ORDER BY first_seen) AS sender_rank,
                row_number() OVER (ORDER BY first_seen) AS total_rank FROM missing
        ) INSERT INTO incomplete_leases
        SELECT group_id,sender,CASE WHEN sender_rank<=?3 AND total_rank<=?4 THEN ?2 ELSE ?1 END FROM ranked"),
        params![now, now + INCOMPLETE_TTL_MS, incomplete_per_sender(members), INCOMPLETE_TOTAL],
    )?;
    Ok(())
}

fn framed_wire(wire: u64) -> bool {
    (1024..=65536).contains(&wire) && wire % 1024 == 0
}

fn read_saved(
    connection: &Connection,
    sql: &str,
    key: &LogicalKey,
    incoming: bool,
) -> ClientResult<Option<SavedRecord>> {
    connection
        .query_row(
            sql,
            params![key.vault, key.roster, key.sender, key.message],
            |row| {
                Ok(SavedRecord {
                    digest: row_id(row, 0)?,
                    source_root: row_id(row, 1)?,
                    incoming,
                })
            },
        )
        .optional()
        .map_err(ClientError::from)
}

fn ordered_hashes(
    connection: &Connection,
    sql: &str,
    key: &LogicalKey,
    recipient: Option<MemberId>,
) -> ClientResult<Vec<Id32>> {
    let mut statement = connection.prepare(sql)?;
    let pairs = if let Some(recipient) = recipient {
        statement
            .query_map(
                params![key.vault, key.roster, key.sender, key.message, recipient],
                ordinal_hash,
            )?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        statement
            .query_map(
                params![key.vault, key.roster, key.sender, key.message],
                ordinal_hash,
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    if pairs.len() > 275 {
        return Err(ClientError::Wire(WireError::Bounds));
    }
    if pairs
        .iter()
        .enumerate()
        .any(|(index, (ordinal, _))| *ordinal != index as i64)
    {
        return Err(ClientError::Storage);
    }
    Ok(pairs.into_iter().map(|(_, hash)| hash).collect())
}

fn ordinal_hash(row: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, Id32)> {
    Ok((row.get(0)?, row_id(row, 1)?))
}

fn source_rejection_exists(connection: &Connection, root: &Id32) -> ClientResult<bool> {
    let found: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM source_rejections WHERE root_hash=?1)",
        [root],
        |row| row.get(0),
    )?;
    Ok(found != 0)
}

fn staged_root_exists(connection: &Connection, root: &Id32) -> ClientResult<bool> {
    let found: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM staged_sources WHERE root_hash=?1)",
        [root],
        |row| row.get(0),
    )?;
    Ok(found != 0)
}

fn group_is_open(connection: &Connection, group_id: &Id32) -> ClientResult<Option<bool>> {
    let sql = format!("SELECT {GROUP_OPEN} FROM transfer_groups g WHERE g.group_id=?1");
    let value: Option<i64> = connection.query_row(&sql, [group_id], |row| row.get(0)).optional()?;
    Ok(value.map(|value| value != 0))
}

fn requirement_wires(source: &BoundSource) -> Vec<(Id32, i64)> {
    let mut wires = Vec::with_capacity(1 + source.objects.len());
    wires.push((source.root_hash, source.root_wire_length as i64));
    wires.extend(source.objects.iter().map(|(hash, wire)| (*hash, *wire as i64)));
    wires
}

fn same_binding(connection: &Connection, source: &BoundSource) -> ClientResult<bool> {
    let (group_id, transfer, vault, roster, sender, message) = connection.query_row(
        "SELECT group_id, claimed_transfer, claimed_vault, claimed_roster, claimed_sender, claimed_message FROM staged_sources WHERE root_hash=?1",
        [source.root_hash],
        |row| {
            Ok((
                row_optional_id(row, 0)?,
                row_optional_id(row, 1)?,
                row_optional_id(row, 2)?,
                row_optional_id(row, 3)?,
                row.get::<_, Option<i64>>(4)?,
                row_optional_id(row, 5)?,
            ))
        },
    )?;
    if group_id != Some(source.group_id)
        || transfer != source.claimed_transfer
        || vault != Some(source.key.vault)
        || roster != Some(source.key.roster)
        || sender != Some(i64::from(source.key.sender))
        || message != Some(source.key.message)
    {
        return Ok(false);
    }
    let mut statement = connection.prepare(
        "SELECT ordinal, hash, wire_length FROM staged_requirements WHERE root_hash=?1 ORDER BY ordinal",
    )?;
    let stored = statement.query_map([source.root_hash], |row| {
        Ok((row.get::<_, u16>(0)?, row_id(row, 1)?, row.get::<_, i64>(2)?))
    })?;
    let stored: Vec<_> = stored.collect::<Result<_, _>>()?;
    let expected = requirement_wires(source);
    Ok(stored.len() == expected.len()
        && stored.iter().enumerate().all(|(index, (ordinal, hash, wire))| {
            usize::from(*ordinal) == index && *hash == expected[index].0 && *wire == expected[index].1
        }))
}

struct CoveredRoute {
    relay_key: Id32,
    run: Id32,
    mailbox: Id32,
}

struct CoverageLink {
    relay_key: Id32,
    run: Id32,
    mailbox: Id32,
    sequence: i64,
}

struct WantedTask {
    relay_key: Id32,
    run: Id32,
    mailbox: Id32,
    hash: Id32,
    wire_length: i64,
    replace: bool,
}

struct WantedPlan {
    coverage: Vec<CoverageLink>,
    tasks: Vec<WantedTask>,
    incomplete: bool,
}

fn plan_wanted(connection: &Connection, root: &Id32, requirements: &[(Id32, i64)]) -> ClientResult<WantedPlan> {
    let mut routes = connection.prepare(
        "SELECT relay_key, run, mailbox FROM incoming_journal WHERE source_hash=?1 UNION SELECT relay_key, run, mailbox FROM staged_coverage WHERE root_hash=?1",
    )?;
    let routes = routes.query_map([root], |row| {
        Ok(CoveredRoute {
            relay_key: row_id(row, 0)?,
            run: row_id(row, 1)?,
            mailbox: row_id(row, 2)?,
        })
    })?;
    let routes: Vec<_> = routes.collect::<Result<_, _>>()?;
    let mut coverage = Vec::new();
    let mut tasks = Vec::new();
    let mut incomplete = false;
    for (hash, wire_length) in requirements {
        let mut missing_coverage = connection.prepare(
            "SELECT j.relay_key, j.run, j.mailbox, j.sequence FROM incoming_journal j WHERE j.source_hash=?1 AND NOT EXISTS (SELECT 1 FROM staged_coverage v WHERE v.root_hash=?2 AND v.relay_key=j.relay_key AND v.run=j.run AND v.mailbox=j.mailbox AND v.sequence=j.sequence)",
        )?;
        let links = missing_coverage.query_map(params![hash, root], |row| {
            Ok(CoverageLink {
                relay_key: row_id(row, 0)?,
                run: row_id(row, 1)?,
                mailbox: row_id(row, 2)?,
                sequence: row.get(3)?,
            })
        })?;
        coverage.extend(links.collect::<Result<Vec<_>, _>>()?);
        let saved: i64 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM ciphertext_objects WHERE hash=?1)",
            [hash],
            |row| row.get(0),
        )?;
        if saved != 0 {
            continue;
        }
        incomplete = true;
        for route in &routes {
            let current: Option<i64> = connection
                .query_row(
                    "SELECT wire_length FROM pending_downloads WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
                    params![route.relay_key, route.run, route.mailbox, hash],
                    |row| row.get(0),
                )
                .optional()?;
            match current {
                Some(length) if length == *wire_length => {}
                current => tasks.push(WantedTask {
                    relay_key: route.relay_key,
                    run: route.run,
                    mailbox: route.mailbox,
                    hash: *hash,
                    wire_length: *wire_length,
                    replace: current.is_some(),
                }),
            }
        }
    }
    Ok(WantedPlan { coverage, tasks, incomplete })
}

fn apply_wanted(connection: &Connection, root: &Id32, planned: &WantedPlan) -> ClientResult<()> {
    for link in &planned.coverage {
        connection.execute(
            "INSERT INTO staged_coverage VALUES(?1,?2,?3,?4,?5)",
            params![root, link.relay_key, link.run, link.mailbox, link.sequence],
        )?;
    }
    for task in &planned.tasks {
        if task.replace {
            connection.execute(
                "DELETE FROM pending_downloads WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
                params![task.relay_key, task.run, task.mailbox, task.hash],
            )?;
        }
        // A historical download rejection stays and does not veto this verified length.
        connection.execute(
            "INSERT INTO pending_downloads (relay_key, run, mailbox, source_hash, wire_length, attempts, retry_at) VALUES(?1,?2,?3,?4,?5,0,0)",
            params![task.relay_key, task.run, task.mailbox, task.hash, task.wire_length],
        )?;
    }
    Ok(())
}

fn certified_owner(roster: &Roster, owner: MemberId) -> ClientResult<Vec<MemberId>> {
    roster_digest(roster)?;
    if !roster.members.iter().any(|member| member.id == owner) {
        return Err(ClientError::Identity);
    }
    Ok(roster.members.iter().map(|member| member.id).collect())
}

fn stored_owner(connection: &Connection) -> ClientResult<MemberId> {
    let owner: i64 = connection.query_row("SELECT owner FROM metadata", [], |row| row.get(0))?;
    MemberId::try_from(owner).map_err(|_| ClientError::Storage)
}

fn reference_phase(value: &str) -> rusqlite::Result<ReferencePhase> {
    match value {
        "pending" => Ok(ReferencePhase::Pending),
        "ready" => Ok(ReferencePhase::Ready),
        "resolved" => Ok(ReferencePhase::Resolved),
        "rejected" => Ok(ReferencePhase::Rejected),
        "not_actionable" => Ok(ReferencePhase::NotActionable),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

#[cfg(test)]
mod outbox_commit_tests {
    use super::*;
    use crate::{outbox_intent_digest, prepare_outbox, CommIdentity};
    use loki_relay_protocol::types::{MessageBody, Payload};
    use std::{
        cell::Cell,
        sync::atomic::{AtomicU64, Ordering},
    };
    thread_local! { static FAULT:Cell<u8>=const{Cell::new(0)}; }

    pub(super) fn checkpoint(connection: &Connection, step: u8) -> ClientResult<()> {
        let fault = FAULT.with(Cell::get);
        if (fault == 1 && step == 1) || (fault == 2 && step == 2) {
            std::process::abort();
        }
        if fault == 3 && step == 1 {
            connection.execute_batch("CREATE TABLE fault_parent(id INTEGER PRIMARY KEY); CREATE TABLE fault_child(id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED); INSERT INTO fault_child VALUES(1);")?;
        }
        Ok(())
    }

    /// Sleeps only when a fixture child asks for this stage. Unset in ordinary tests.
    pub(super) fn pause_barrier(kind: &str) {
        let Ok(stage) = std::env::var("RELAY_6_6_BARRIER") else {
            return;
        };
        if stage != kind {
            return;
        }
        let marker = PathBuf::from(std::env::var_os("RELAY_6_6_MARKER").expect("fixture barrier marker"));
        let temporary = marker.with_extension("part");
        std::fs::write(&temporary, kind.as_bytes()).unwrap();
        std::fs::rename(&temporary, &marker).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(45));
        panic!("fixture parent did not reap the child");
    }
    fn fixture() -> (Roster, CommIdentity, MessageBody, crate::PreparedOutbox) {
        let identities: Vec<_> = (1u16..=3)
            .map(|id| {
                let mut seed = [0; 66];
                seed[..2].copy_from_slice(&id.to_be_bytes());
                seed[2..34].fill(id as u8);
                seed[34..].fill(id as u8 + 10);
                CommIdentity::from_serialized(&seed).unwrap()
            })
            .collect();
        let roster = Roster {
            vault: [70; 32],
            members: identities.iter().map(CommIdentity::public).collect(),
        };
        let identity = identities.into_iter().next().unwrap();
        let body = MessageBody {
            key: LogicalKey {
                vault: roster.vault,
                roster: roster_digest(&roster).unwrap(),
                sender: 1,
                message: [124; 32],
            },
            audience: vec![1, 2, 3],
            session: Some([125; 32]),
            prerequisites: vec![],
            payload: Payload::Test(vec![29; 80000]),
        };
        let prepared = prepare_outbox(&identity, &roster, &body).unwrap();
        (roster, identity, body, prepared)
    }
    fn root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = PathBuf::from("/private/tmp/relay-6.2-evidence").join(format!(
            "native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&parent).unwrap();
        parent.join("client")
    }
    #[test]
    fn outbox_atomic_real_sqlite_failed_commit() {
        let (roster, identity, body, prepared) = fixture();
        let root = root();
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        FAULT.with(|fault| fault.set(3));
        let result = store.commit_outbox(&roster, &identity, &[126; 32], &prepared);
        FAULT.with(|fault| fault.set(0));
        assert_eq!(result, Err(ClientError::Storage));
        assert!(store.connection.is_autocommit());
        for table in [
            "ciphertext_objects",
            "logical_records",
            "outgoing_recipients",
            "required_objects",
            "caller_requests",
            "upload_work",
        ] {
            assert_eq!(
                store
                    .connection
                    .query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get(0))
                    .unwrap(),
                0
            );
        }
        assert!(store
            .lookup_outbox_request(&[126; 32], &outbox_intent_digest(&body).unwrap())
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .connection
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM sqlite_master WHERE name LIKE 'fault_%'",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        drop(store);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        store
            .commit_outbox(&roster, &identity, &[126; 32], &prepared)
            .unwrap();
        assert_eq!(store.recover_recipients(prepared.key()).unwrap().len(), 3);
    }
    #[test]
    #[ignore]
    fn outbox_atomic_crash_child() {
        let root = PathBuf::from(std::env::var("RELAY_6_2_TEST_ROOT").unwrap());
        let (roster, identity, body, prepared) = fixture();
        let expected = serde_json::json!({"key":{"vault":hex::encode(prepared.key().vault),"roster":hex::encode(prepared.key().roster),"sender":prepared.key().sender,"message":hex::encode(prepared.key().message)},"digest":hex::encode(prepared.digest()),"intent":hex::encode(outbox_intent_digest(&body).unwrap()),"recipients":prepared.recipients().iter().map(|r|serde_json::json!({"recipient":r.recipient(),"transfer":r.transfer().map(hex::encode),"root":hex::encode(r.root_hash()),"objects":r.objects().iter().map(|o|serde_json::json!({"hash":hex::encode(o.hash),"wire":hex::encode(&o.wire)})).collect::<Vec<_>>()})).collect::<Vec<_>>()});
        fs::write(
            root.parent().unwrap().join("expected.json"),
            serde_json::to_vec(&expected).unwrap(),
        )
        .unwrap();
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        FAULT.with(|fault| {
            fault.set(
                std::env::var("RELAY_6_2_TEST_FAULT")
                    .unwrap()
                    .parse()
                    .unwrap(),
            )
        });
        let _ = store.commit_outbox(&roster, &identity, &[127; 32], &prepared);
        panic!("native barrier was not reached");
    }
    fn crash_case(fault: u8) {
        use std::os::unix::process::ExitStatusExt;
        let root = root();
        let log = root.parent().unwrap().join("child.log");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::outbox_commit_tests::outbox_atomic_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RELAY_6_2_TEST_ROOT", &root)
            .env("RELAY_6_2_TEST_FAULT", fault.to_string())
            .output()
            .unwrap();
        fs::write(&log, [output.stdout, output.stderr].concat()).unwrap();
        assert_eq!(output.status.signal(), Some(6));
        let expected: serde_json::Value = serde_json::from_slice(
            &fs::read(root.parent().unwrap().join("expected.json")).unwrap(),
        )
        .unwrap();
        let id = |value: &serde_json::Value| -> Id32 {
            hex::decode(value.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let (roster, _, _, _) = fixture();
        let store = ClientStore::open(&root, &roster, 1).unwrap();
        let result = store
            .lookup_outbox_request(&[127; 32], &id(&expected["intent"]))
            .unwrap();
        if fault == 1 {
            assert!(result.is_none());
            for table in [
                "ciphertext_objects",
                "logical_records",
                "outgoing_recipients",
                "required_objects",
                "caller_requests",
                "upload_work",
            ] {
                assert_eq!(
                    store
                        .connection
                        .query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r
                            .get(0))
                        .unwrap(),
                    0
                );
            }
        } else {
            let logical = result.unwrap();
            assert_eq!(logical.key.message, id(&expected["key"]["message"]));
            assert_eq!(logical.digest, id(&expected["digest"]));
            assert_eq!(logical.session, Some([125; 32]));
            let saved = store.recover_recipients(&logical.key).unwrap();
            assert_eq!(saved.len(), 3);
            for (r, e) in saved.iter().zip(expected["recipients"].as_array().unwrap()) {
                assert_eq!(r.recipient, e["recipient"].as_u64().unwrap() as u16);
                assert_eq!(r.root_hash, id(&e["root"]));
                assert_eq!(
                    r.transfer,
                    e["transfer"].as_str().map(|_| id(&e["transfer"]))
                );
                assert!(r.needs_route);
                let mut requirements = store
                    .recover_requirements(&logical.key, r.recipient, None, 100)
                    .unwrap();
                requirements.sort_by_key(|r| r.ordinal);
                assert_eq!(requirements.len(), e["objects"].as_array().unwrap().len());
                for (requirement, o) in requirements.iter().zip(e["objects"].as_array().unwrap()) {
                    assert_eq!(requirement.hash, id(&o["hash"]));
                    assert_eq!(
                        store.saved_object(&requirement.hash).unwrap().unwrap().wire,
                        hex::decode(o["wire"].as_str().unwrap()).unwrap()
                    );
                }
            }
        }
        assert!(store.recover_uploads(0, 100).unwrap().is_empty());
    }
    #[test]
    fn outbox_atomic_crash_before_commit() {
        crash_case(1);
    }
    #[test]
    fn outbox_atomic_crash_after_commit() {
        crash_case(2);
    }

    #[test]
    fn outbox_atomic_storage_limit_default_reopen() {
        let (roster, _, _, _) = fixture();
        let root = root();
        for _ in 0..2 {
            let store = ClientStore::open(&root, &roster, 1).unwrap();
            let page_size: u64 = store
                .connection
                .pragma_query_value(None, "page_size", |r| r.get(0))
                .unwrap();
            let cap: u64 = store
                .connection
                .pragma_query_value(None, "max_page_count", |r| r.get(0))
                .unwrap();
            assert_eq!(
                cap,
                512 * 1024 * 1024 / page_size,
                "shared allocated-page ceiling must be configured"
            );
        }
    }

    fn outgoing_counts(store: &ClientStore) -> [u64; 6] {
        [
            "ciphertext_objects",
            "logical_records",
            "outgoing_recipients",
            "required_objects",
            "caller_requests",
            "upload_work",
        ]
        .map(|table| {
            store
                .connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        })
    }
    fn set_budget(store: &mut ClientStore, bytes: u64) {
        store.storage_budget = bytes;
        configure_storage_limit(&store.connection, bytes).unwrap();
    }
    #[test]
    fn outbox_atomic_shared_storage_full_rolls_back() {
        let (roster, identity, body, prepared) = fixture();
        let root = root();
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let original = store
            .commit_outbox(&roster, &identity, &[140; 32], &prepared)
            .unwrap();
        let mut staged_body = body.clone();
        staged_body.key.message = [141; 32];
        let staged = prepare_outbox(&identity, &roster, &staged_body).unwrap();
        let tx = store.connection.transaction().unwrap();
        for r in staged.recipients() {
            for o in r.objects() {
                tx.execute(
                    "INSERT INTO ciphertext_objects VALUES(?1,?2,?3)",
                    params![o.hash, o.wire, o.wire.len()],
                )
                .unwrap();
            }
        }
        tx.commit().unwrap();
        let size: u64 = store
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .unwrap();
        let pages: u64 = store
            .connection
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        set_budget(&mut store, size * pages);
        let mut next_body = body.clone();
        next_body.key.message = [142; 32];
        let next = prepare_outbox(&identity, &roster, &next_body).unwrap();
        let before = outgoing_counts(&store);
        assert_eq!(
            store.commit_outbox(&roster, &identity, &[143; 32], &next),
            Err(ClientError::Capacity),
            "new complete set must not exceed shared page capacity"
        );
        assert_eq!(outgoing_counts(&store), before);
        assert!(store.connection.is_autocommit());
        assert!(store
            .lookup_outbox_request(&[143; 32], &outbox_intent_digest(&next_body).unwrap())
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .lookup_outbox_request(&[140; 32], &outbox_intent_digest(&body).unwrap())
                .unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            store
                .commit_outbox(&roster, &identity, &[140; 32], &prepared)
                .unwrap(),
            original
        );
        assert_eq!(outgoing_counts(&store), before);
        for r in prepared.recipients().iter().chain(staged.recipients()) {
            for o in r.objects() {
                assert_eq!(store.saved_object(&o.hash).unwrap().unwrap().wire, o.wire);
            }
        }
        assert!(store
            .saved_object(next.recipients()[0].root_hash())
            .unwrap()
            .is_none());
        assert!(store.recover_uploads(0, 100).unwrap().is_empty());
        drop(store);
        let store = ClientStore::open(&root, &roster, 1).unwrap();
        assert_eq!(
            store
                .lookup_outbox_request(&[140; 32], &outbox_intent_digest(&body).unwrap())
                .unwrap(),
            Some(original)
        );
        assert_eq!(outgoing_counts(&store), before);
    }
    #[test]
    fn outbox_atomic_second_request_metadata_capacity() {
        let (roster, identity, body, prepared) = fixture();
        let root = root();
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let original = store
            .commit_outbox(&roster, &identity, &[144; 32], &prepared)
            .unwrap();
        let size: u64 = store
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .unwrap();
        let pages: u64 = store
            .connection
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        set_budget(&mut store, size * pages);
        let intent = outbox_intent_digest(&body).unwrap();
        let mut reached = false;
        for n in 0u32..256 {
            let mut request = [145; 32];
            request[..4].copy_from_slice(&n.to_be_bytes());
            let before = outgoing_counts(&store);
            match store.commit_outbox(&roster, &identity, &request, &prepared) {
                Ok(result) => {
                    assert_eq!(result, original);
                    assert_eq!(outgoing_counts(&store)[4], before[4] + 1);
                }
                Err(error) => {
                    assert_eq!(
                        error,
                        ClientError::Capacity,
                        "new caller mapping must account for SQLite pages"
                    );
                    assert_eq!(outgoing_counts(&store), before);
                    assert!(store
                        .lookup_outbox_request(&request, &intent)
                        .unwrap()
                        .is_none());
                    reached = true;
                    break;
                }
            }
        }
        assert!(
            reached,
            "bounded metadata attempts must reach page capacity"
        );
        assert_eq!(
            store.lookup_outbox_request(&[144; 32], &intent).unwrap(),
            Some(original.clone())
        );
        let before = outgoing_counts(&store);
        assert_eq!(
            store
                .commit_outbox(&roster, &identity, &[144; 32], &prepared)
                .unwrap(),
            original
        );
        assert_eq!(outgoing_counts(&store), before);
        assert_eq!(store.recover_recipients(prepared.key()).unwrap().len(), 3);
        for r in prepared.recipients() {
            for o in r.objects() {
                assert_eq!(store.saved_object(&o.hash).unwrap().unwrap().wire, o.wire);
            }
        }
    }
    #[test]
    fn outbox_atomic_overbudget_free_pages_no_growth() {
        let (roster, identity, body, prepared) = fixture();
        let root = root();
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let original = store
            .commit_outbox(&roster, &identity, &[146; 32], &prepared)
            .unwrap();
        store.connection.execute_batch("CREATE TABLE fixture_padding(wire BLOB); INSERT INTO fixture_padding VALUES(zeroblob(262144)); DROP TABLE fixture_padding;").unwrap();
        let size: u64 = store
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .unwrap();
        let pages: u64 = store
            .connection
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        assert!(
            store
                .connection
                .pragma_query_value::<u64, _>(None, "freelist_count", |r| r.get(0))
                .unwrap()
                > 0
        );
        set_budget(&mut store, size);
        let effective: u64 = store
            .connection
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .unwrap();
        assert_eq!(effective, pages);
        assert!(effective > store.storage_budget / size);
        let mut next_body = body.clone();
        next_body.key.message = [147; 32];
        next_body.payload = Payload::Test(vec![30; 10]);
        let next = prepare_outbox(&identity, &roster, &next_body).unwrap();
        let before = outgoing_counts(&store);
        assert_eq!(
            store.commit_outbox(&roster, &identity, &[148; 32], &next),
            Err(ClientError::Capacity),
            "existing free pages cannot admit above configured budget"
        );
        assert_eq!(outgoing_counts(&store), before);
        assert_eq!(
            store.commit_outbox(&roster, &identity, &[149; 32], &prepared),
            Err(ClientError::Capacity),
            "second caller metadata is growth above budget"
        );
        assert_eq!(outgoing_counts(&store), before);
        assert_eq!(
            store
                .lookup_outbox_request(&[146; 32], &outbox_intent_digest(&body).unwrap())
                .unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            store
                .commit_outbox(&roster, &identity, &[146; 32], &prepared)
                .unwrap(),
            original
        );
        assert_eq!(outgoing_counts(&store), before);
        for r in prepared.recipients() {
            for o in r.objects() {
                assert_eq!(store.saved_object(&o.hash).unwrap().unwrap().wire, o.wire);
            }
        }
    }
    #[test]
    fn outbox_atomic_pending_checked_boundary() {
        assert_eq!(reserve_pending(125, 3), Ok(()));
        assert_eq!(reserve_pending(126, 3), Err(ClientError::Capacity));
        assert_eq!(reserve_pending(128, 0), Ok(()));
        assert_eq!(reserve_pending(129, 0), Err(ClientError::Capacity));
        assert_eq!(reserve_pending(u64::MAX, 3), Err(ClientError::Capacity));
    }
    #[test]
    fn outbox_atomic_storage_arithmetic_bounds() {
        let (roster, _, _, _) = fixture();
        let root = root();
        let store = ClientStore::open(&root, &roster, 1).unwrap();
        assert_eq!(
            storage_pages(&store.connection, 0),
            Err(ClientError::Capacity)
        );
        assert_eq!(
            storage_pages(&store.connection, 511),
            Err(ClientError::Capacity)
        );
        let (allocated, limit) = storage_pages(&store.connection, 512 * 1024 * 1024).unwrap();
        assert!(allocated <= limit);
    }

    #[test]
    fn outbox_atomic_effective_page_ceiling_fails_closed() {
        let (roster, _, _, _) = fixture();
        let root = root();
        let store = ClientStore::open(&root, &roster, 1).unwrap();
        let size: u64 = store
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .unwrap();
        assert_eq!(
            configure_storage_limit(&store.connection, size * 4294967295),
            Err(ClientError::Storage),
            "SQLite-clamped page ceilings cannot authorize a larger configured budget"
        );
    }

/// Process-kill and idempotent PUT evidence for the outbox commit and receipt boundaries.
mod crash {
    use super::*;
    use crate::{
        open_descriptor, seal_descriptor, upload_pending, ClientConfig, Descriptor, DescriptorRelay,
        OwnerInbox, RelayHttp, Secret32, ThirdPass,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_protocol::{
        canonical::{self, Value},
        receipt,
        types::{LogicalKey, MessageBody, Payload, ReceiptBody, RelayPin},
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashMap,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        process::{Child, Command, Stdio},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
        time::{Duration, Instant},
    };

    const COMMIT_REQUEST: [u8; 32] = [160; 32];
    const COMMIT_MESSAGE: [u8; 32] = [124; 32];
    const HTTP_REQUEST: [u8; 32] = [182; 32];
    const HTTP_MESSAGE: [u8; 32] = [180; 32];

    const SOCKET_WAIT: Duration = Duration::from_secs(2);
    const REAP_WAIT: Duration = Duration::from_secs(5);

    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = wait_bounded(&mut self.0, REAP_WAIT);
        }
    }

    fn wait_bounded(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => return None,
            }
        }
    }

    struct PinSecret {
        signer: SigningKey,
        key: [u8; 32],
        run: [u8; 32],
        mailbox: [u8; 32],
        append: [u8; 32],
    }

    struct SavedPut {
        body: Vec<u8>,
        receipt: Vec<u8>,
        sequence: u64,
        wire_len: u64,
        hits: u64,
    }

    struct RelayState {
        saved: HashMap<([u8; 32], [u8; 32]), SavedPut>,
        sequences: HashMap<[u8; 32], u64>,
        first: Option<([u8; 32], [u8; 32])>,
        puts: u64,
        duplicate_puts: u64,
        third_puts: u64,
        mismatches: u64,
        quota: u64,
    }

    struct Shot {
        puts: u64,
        duplicate_puts: u64,
        third_puts: u64,
        mismatches: u64,
        entries: u64,
        quota: u64,
        hits: u64,
        sequence: u64,
        wire_len: u64,
        mailbox: [u8; 32],
        hash: [u8; 32],
        receipt: Vec<u8>,
    }

    struct Loopback {
        port: u16,
        pins: Arc<Vec<PinSecret>>,
        state: Arc<Mutex<RelayState>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for Loopback {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    impl Loopback {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut pins: Vec<PinSecret> = (0..3u8)
                .map(|index| {
                    let signer = SigningKey::from_bytes(&[10 + index; 32]);
                    PinSecret {
                        key: signer.verifying_key().to_bytes(),
                        signer,
                        run: [21 + index; 32],
                        mailbox: [31 + index; 32],
                        append: [41 + index; 32],
                    }
                })
                .collect();
            pins.sort_by(|left, right| left.key.cmp(&right.key));
            let pins = Arc::new(pins);
            let state = Arc::new(Mutex::new(RelayState {
                saved: HashMap::new(),
                sequences: HashMap::new(),
                first: None,
                puts: 0,
                duplicate_puts: 0,
                third_puts: 0,
                mismatches: 0,
                quota: 0,
            }));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_pins = Arc::clone(&pins);
            let thread_state = Arc::clone(&state);
            let thread_stop = Arc::clone(&stop);
            let third = pins[2].mailbox;
            let thread = std::thread::spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            handle(stream, &thread_pins, &thread_state, third);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                port,
                pins,
                state,
                stop,
                thread: Some(thread),
            }
        }

        fn publish(&self, dir: &Path) {
            let public = serde_json::json!({
                "port": self.port,
                "third": hex::encode(self.pins[2].mailbox),
                "relays": self.pins.iter().map(|pin| serde_json::json!({
                    "key": hex::encode(pin.key),
                    "run": hex::encode(pin.run),
                    "mailbox": hex::encode(pin.mailbox),
                })).collect::<Vec<_>>(),
            });
            fs::write(dir.join("routes.json"), serde_json::to_vec(&public).unwrap()).unwrap();
            let mut appends = Vec::with_capacity(96);
            for pin in self.pins.iter() {
                appends.extend_from_slice(&pin.append);
            }
            let path = dir.join("append.bin");
            fs::write(&path, &appends).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn shot(&self) -> Shot {
            let state = self.state.lock().unwrap();
            let (mailbox, hash) = state.first.expect("relay has no stored object");
            let saved = &state.saved[&(mailbox, hash)];
            Shot {
                puts: state.puts,
                duplicate_puts: state.duplicate_puts,
                third_puts: state.third_puts,
                mismatches: state.mismatches,
                entries: state.saved.len() as u64,
                quota: state.quota,
                hits: saved.hits,
                sequence: saved.sequence,
                wire_len: saved.wire_len,
                mailbox,
                hash,
                receipt: saved.receipt.clone(),
            }
        }

        fn counts(&self) -> (u64, u64) {
            let state = self.state.lock().unwrap();
            (state.puts, state.saved.len() as u64)
        }

        fn append_for(&self, mailbox: [u8; 32]) -> [u8; 32] {
            self.pins
                .iter()
                .find(|pin| pin.mailbox == mailbox)
                .unwrap()
                .append
        }
    }

    fn case_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = PathBuf::from("/private/tmp/relay-6.6-evidence").join(format!(
            "native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn scrub_log(path: &Path) -> String {
        let bytes = fs::read(path).unwrap_or_default();
        let start = bytes.len().saturating_sub(2000);
        String::from_utf8_lossy(&bytes[start..])
            .lines()
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                !lower.contains("bearer ") && !lower.contains("authorization:")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn spawn_barrier(dir: &Path, stage: &str) -> (PathBuf, OwnedChild) {
        let marker = dir.join("barrier");
        let log = fs::File::create(dir.join("child.log")).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::outbox_commit_tests::crash::outbox_crash_barrier_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RELAY_6_6_ROOT", dir.join("client"))
            .env("RELAY_6_6_BARRIER", stage)
            .env("RELAY_6_6_MARKER", &marker)
            .env("RELAY_6_6_ROUTES", dir.join("routes.json"))
            .env("RELAY_6_6_APPEND", dir.join("append.bin"))
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        (marker, OwnedChild(child))
    }

    fn reap(child: &mut OwnedChild) {
        let _ = child.0.kill();
        let status = wait_bounded(&mut child.0, REAP_WAIT)
            .expect("fixture child was not reaped before the deadline");
        assert_eq!(
            status.signal(),
            Some(9),
            "fixture child was not reaped by the parent"
        );
    }

    fn table_count(root: &Path, table: &str) -> i64 {
        let sql = Connection::open(root.join("client.sqlite3")).unwrap();
        sql.busy_timeout(Duration::from_secs(1)).unwrap();
        sql.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .unwrap()
    }

    fn owner() -> (Roster, crate::CommIdentity) {
        let identities: Vec<_> = (1u16..=3)
            .map(|id| {
                let mut seed = [0; 66];
                seed[..2].copy_from_slice(&id.to_be_bytes());
                seed[2..34].fill(id as u8);
                seed[34..].fill(id as u8 + 10);
                crate::CommIdentity::from_serialized(&seed).unwrap()
            })
            .collect();
        let roster = Roster {
            vault: [70; 32],
            members: identities.iter().map(crate::CommIdentity::public).collect(),
        };
        let identity = identities.into_iter().next().unwrap();
        (roster, identity)
    }

    fn http_body(roster: &Roster) -> MessageBody {
        MessageBody {
            key: LogicalKey {
                vault: roster.vault,
                roster: roster_digest(roster).unwrap(),
                sender: 1,
                message: HTTP_MESSAGE,
            },
            audience: vec![1, 2, 3],
            session: Some([181; 32]),
            prerequisites: vec![],
            payload: Payload::Test(vec![19; 10]),
        }
    }

    fn decode_id(value: &serde_json::Value) -> Id32 {
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn install_routes(
        store: &mut ClientStore,
        roster: &Roster,
        identity: &crate::CommIdentity,
        routes: &Path,
        append_path: &Path,
    ) -> (ClientConfig, crate::AuthenticatedDescriptor) {
        let public: serde_json::Value =
            serde_json::from_slice(&fs::read(routes).unwrap()).unwrap();
        let appends = fs::read(append_path).unwrap();
        assert_eq!(appends.len(), 96, "route credential file is the wrong length");
        let port = public["port"].as_u64().unwrap();
        let mut relays = Vec::new();
        let mut own = Vec::new();
        for (index, relay) in public["relays"].as_array().unwrap().iter().enumerate() {
            let mut append = [0u8; 32];
            append.copy_from_slice(&appends[index * 32..(index + 1) * 32]);
            let route = RelayRoute {
                pin: RelayPin {
                    key: decode_id(&relay["key"]),
                    run: decode_id(&relay["run"]),
                },
                endpoint: format!("http://127.0.0.1:{port}"),
                mailbox: decode_id(&relay["mailbox"]),
                append_revision: 1,
            };
            relays.push(DescriptorRelay {
                route: route.clone(),
                append: Secret32::from_bytes(append),
            });
            own.push(OwnerInbox {
                route,
                read: Secret32::from_bytes([51; 32]),
                append: Secret32::from_bytes(append),
                admin: Secret32::from_bytes([52; 32]),
            });
        }
        let descriptor = Descriptor::new(
            roster.vault,
            roster_digest(roster).unwrap(),
            1,
            1,
            relays,
        );
        let owner_public = identity.public();
        let sealed = seal_descriptor(identity, roster, &descriptor, &owner_public).unwrap();
        let opened = open_descriptor(identity, roster, &sealed.wire).unwrap();
        let reference = ConfigReference::from_ciphertext(1, &sealed.wire).unwrap();
        // A restarted process keeps the committed pointer. Resealing the same routes
        // must not replace that pointer just to upload.
        if store.config_reference().unwrap().is_none() {
            store.record_config_revision(&reference).unwrap();
        }
        (
            ClientConfig {
                own,
                peers: Vec::new(),
            },
            opened,
        )
    }

    fn write_expected(path: &Path, body: &MessageBody, prepared: &crate::PreparedOutbox) {
        let value = serde_json::json!({
            "request": hex::encode(COMMIT_REQUEST),
            "message": hex::encode(COMMIT_MESSAGE),
            "intent": hex::encode(outbox_intent_digest(body).unwrap()),
            "digest": hex::encode(prepared.digest()),
            "session": hex::encode(body.session.unwrap()),
            "recipients": prepared.recipients().iter().map(|recipient| serde_json::json!({
                "recipient": recipient.recipient(),
                "transfer": recipient.transfer().map(hex::encode),
                "root": hex::encode(recipient.root_hash()),
                "objects": recipient.objects().iter().map(|object| serde_json::json!({
                    "hash": hex::encode(object.hash),
                    "wire": hex::encode(&object.wire),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn retained(store: &ClientStore, expected: &serde_json::Value) {
        let message = decode_id(&expected["message"]);
        assert_eq!(message, COMMIT_MESSAGE, "retained logical id changed");
        let intent = decode_id(&expected["intent"]);
        let logical = store
            .lookup_outbox_request(&COMMIT_REQUEST, &intent)
            .unwrap()
            .expect("caller request was not retained");
        assert_eq!(logical.key.message, COMMIT_MESSAGE);
        assert_eq!(logical.digest, decode_id(&expected["digest"]));
        assert_eq!(logical.session, Some([125; 32]));
        let saved = store.recover_recipients(&logical.key).unwrap();
        let recipients = expected["recipients"].as_array().unwrap();
        assert_eq!(saved.len(), 3, "a committed outbox must retain all three recipients");
        assert_eq!(saved.len(), recipients.len());
        for (recipient, expected_recipient) in saved.iter().zip(recipients) {
            assert_eq!(
                recipient.recipient,
                expected_recipient["recipient"].as_u64().unwrap() as u16
            );
            assert!(recipient.needs_route, "commit must not upload before routing");
            assert_eq!(recipient.root_hash, decode_id(&expected_recipient["root"]));
            let transfer = expected_recipient["transfer"]
                .as_str()
                .map(|_| decode_id(&expected_recipient["transfer"]));
            assert_eq!(recipient.transfer, transfer);
            let mut requirements = store
                .recover_requirements(&logical.key, recipient.recipient, None, 100)
                .unwrap();
            requirements.sort_by_key(|item| item.ordinal);
            let objects = expected_recipient["objects"].as_array().unwrap();
            assert!(
                objects.len() > 1,
                "chunked recipient set collapsed to a single object"
            );
            assert_eq!(requirements.len(), objects.len());
            for (requirement, object) in requirements.iter().zip(objects) {
                let hash = decode_id(&object["hash"]);
                let wire = hex::decode(object["wire"].as_str().unwrap()).unwrap();
                assert_eq!(requirement.hash, hash);
                let saved_object = store.saved_object(&hash).unwrap().expect("object missing");
                assert_eq!(saved_object.wire.len(), wire.len(), "retained wire length changed");
                assert!(
                    saved_object.wire == wire,
                    "retained wire bytes differ from the committed object"
                );
            }
        }
        assert!(
            store.recover_uploads(0, 100).unwrap().is_empty(),
            "commit created upload work before routing"
        );
    }

    fn empty_outbox(root: &Path) {
        for table in [
            "ciphertext_objects",
            "logical_records",
            "outgoing_recipients",
            "required_objects",
            "caller_requests",
            "upload_work",
            "verified_receipts",
            "delivery_completion",
        ] {
            assert_eq!(table_count(root, table), 0, "{table} was visible before commit");
        }
    }

    fn read_request(stream: &mut TcpStream) -> Option<Request> {
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        while header.len() < 8192 {
            if stream.read(&mut byte).ok()? == 0 {
                return None;
            }
            header.push(byte[0]);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        if !header.ends_with(b"\r\n\r\n") {
            return None;
        }
        let text = String::from_utf8_lossy(&header);
        let mut lines = text.split("\r\n");
        let mut parts = lines.next()?.split(' ');
        let method = parts.next()?.to_string();
        let path = parts.next()?.split('?').next()?.to_string();
        let mut content_length = None;
        let mut authorization = String::new();
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse().ok();
            } else if name == "authorization" {
                authorization = value.to_string();
            }
        }
        let length = content_length?;
        if length > 65536 {
            return None;
        }
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).ok()?;
        Some(Request {
            method,
            path,
            authorization,
            body,
        })
    }

    struct Request {
        method: String,
        path: String,
        authorization: String,
        body: Vec<u8>,
    }

    fn parse_put_path(path: &str) -> Option<([u8; 32], [u8; 32])> {
        let rest = path.strip_prefix("/v1/mailboxes/")?;
        let (mailbox, hash) = rest.split_once("/objects/")?;
        if mailbox.len() != 64 || hash.len() != 64 {
            return None;
        }
        Some((
            hex::decode(mailbox).ok()?.try_into().ok()?,
            hex::decode(hash).ok()?.try_into().ok()?,
        ))
    }

    fn bearer_matches(header: &str, append: &[u8; 32]) -> bool {
        let Some(token) = header.strip_prefix("Bearer ") else {
            return false;
        };
        URL_SAFE_NO_PAD
            .decode(token)
            .ok()
            .is_some_and(|bytes| bytes.as_slice() == append)
    }

    fn receipt_bytes(pin: &PinSecret, hash: [u8; 32], wire_len: u64, sequence: u64) -> Vec<u8> {
        let body = ReceiptBody {
            pin: RelayPin {
                key: pin.key,
                run: pin.run,
            },
            mailbox: pin.mailbox,
            hash,
            wire_length: wire_len,
            sequence,
            retention: 1,
        };
        let encoded = receipt::encode_body(&body).unwrap();
        let mut input = b"Loki_Relay_Stored_v1\0".to_vec();
        input.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
        input.extend_from_slice(&encoded);
        let signature = pin.signer.sign(&input);
        canonical::encode(&Value::Array(vec![
            Value::Bytes(encoded),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
        .unwrap()
    }

    fn write_cbor(stream: &mut TcpStream, status: u16, body: &[u8]) {
        let header = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body);
    }

    fn handle(mut stream: TcpStream, pins: &[PinSecret], state: &Mutex<RelayState>, third: [u8; 32]) {
        // A stalled accepted socket must not block listener shutdown.
        stream.set_nonblocking(false).expect("fixture socket mode");
        stream
            .set_read_timeout(Some(SOCKET_WAIT))
            .expect("fixture read timeout");
        stream
            .set_write_timeout(Some(SOCKET_WAIT))
            .expect("fixture write timeout");
        let Some(request) = read_request(&mut stream) else {
            return;
        };
        if request.method != "PUT" {
            write_cbor(&mut stream, 405, b"");
            return;
        }
        let Some((mailbox, hash)) = parse_put_path(&request.path) else {
            write_cbor(&mut stream, 400, b"");
            return;
        };
        let Some(pin) = pins.iter().find(|pin| pin.mailbox == mailbox) else {
            write_cbor(&mut stream, 404, b"");
            return;
        };
        if !bearer_matches(&request.authorization, &pin.append) {
            write_cbor(&mut stream, 401, b"");
            return;
        }
        if Sha256::digest(&request.body).as_slice() != hash {
            state.lock().unwrap().mismatches += 1;
            write_cbor(&mut stream, 400, b"");
            return;
        }
        let mut state = state.lock().unwrap();
        state.puts += 1;
        if mailbox == third {
            state.third_puts += 1;
        }
        if state.saved.contains_key(&(mailbox, hash)) {
            let matches = state.saved[&(mailbox, hash)].body == request.body;
            if !matches {
                state.mismatches += 1;
                drop(state);
                write_cbor(&mut stream, 409, b"");
                return;
            }
            let receipt = state.saved[&(mailbox, hash)].receipt.clone();
            state.saved.get_mut(&(mailbox, hash)).unwrap().hits += 1;
            state.duplicate_puts += 1;
            drop(state);
            write_cbor(&mut stream, 200, &receipt);
            return;
        }
        let wire_len = request.body.len() as u64;
        let sequence = state.sequences.entry(mailbox).or_insert(0);
        *sequence += 1;
        let sequence = *sequence;
        let receipt = receipt_bytes(pin, hash, wire_len, sequence);
        state.quota += wire_len;
        if state.first.is_none() {
            state.first = Some((mailbox, hash));
        }
        state.saved.insert(
            (mailbox, hash),
            SavedPut {
                body: request.body,
                receipt: receipt.clone(),
                sequence,
                wire_len,
                hits: 1,
            },
        );
        drop(state);
        write_cbor(&mut stream, 201, &receipt);
    }

    fn marker_is(dir: &Path, child: &mut OwnedChild, marker: &Path, stage: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before {stage}\n{}",
                scrub_log(&dir.join("child.log"))
            );
            assert!(
                Instant::now() < deadline,
                "child never reached {stage}\n{}",
                scrub_log(&dir.join("child.log"))
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read(marker).unwrap(),
            stage.as_bytes(),
            "child stopped at the wrong boundary"
        );
    }

    /// Commit, bind the published routes, then upload. A barrier env stops inside that sequence.
    async fn commit_then_upload(root: &Path, routes: &Path, appends: &Path) -> crate::UploadPass {
        let (roster, identity, body, prepared) = fixture();
        write_expected(&root.parent().unwrap().join("expected.json"), &body, &prepared);
        let mut store = ClientStore::open(root, &roster, 1).unwrap();
        let logical = store
            .commit_outbox(&roster, &identity, &COMMIT_REQUEST, &prepared)
            .unwrap();
        let (config, opened) = install_routes(&mut store, &roster, &identity, routes, appends);
        let http = RelayHttp::new().unwrap();
        upload_pending(
            &mut store,
            &http,
            &logical,
            &roster,
            &identity,
            &config,
            &opened,
            1_000,
            ThirdPass::StopAfterStored,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn outbox_crash_barrier_child() {
        let stage = std::env::var("RELAY_6_6_BARRIER").unwrap();
        let root = PathBuf::from(std::env::var("RELAY_6_6_ROOT").unwrap());
        if stage == "before-receipt" {
            let (roster, identity) = owner();
            let body = http_body(&roster);
            let prepared = prepare_outbox(&identity, &roster, &body).unwrap();
            let mut store = ClientStore::open(&root, &roster, 1).unwrap();
            let logical = store
                .commit_outbox(&roster, &identity, &HTTP_REQUEST, &prepared)
                .unwrap();
            let (config, opened) = install_routes(
                &mut store,
                &roster,
                &identity,
                Path::new(&std::env::var("RELAY_6_6_ROUTES").unwrap()),
                Path::new(&std::env::var("RELAY_6_6_APPEND").unwrap()),
            );
            let http = RelayHttp::new().unwrap();
            let _ = upload_pending(
                &mut store,
                &http,
                &logical,
                &roster,
                &identity,
                &config,
                &opened,
                1_000,
                ThirdPass::StopAfterStored,
            )
            .await;
            panic!("receipt barrier was not reached");
        }
        let routes = PathBuf::from(std::env::var("RELAY_6_6_ROUTES").unwrap());
        let appends = PathBuf::from(std::env::var("RELAY_6_6_APPEND").unwrap());
        let _ = commit_then_upload(&root, &routes, &appends).await;
        panic!("commit barrier was not reached");
    }

    #[tokio::test]
    async fn outbox_crash_commit_then_upload_puts() {
        assert!(
            std::env::var_os("RELAY_6_6_BARRIER").is_none(),
            "the PUT control must run with no commit barrier"
        );
        let dir = case_dir();
        let relay = Loopback::start();
        relay.publish(&dir);
        let pass = commit_then_upload(
            &dir.join("client"),
            &dir.join("routes.json"),
            &dir.join("append.bin"),
        )
        .await;
        let (puts, entries) = relay.counts();
        assert!(puts >= 1, "commit-then-upload accepted no PUT");
        assert!(entries >= 1, "commit-then-upload stored no object");
        // install_routes leaves peers empty, so Bob and Carol stay unrouted and
        // whole-vault Stored is impossible. The author third pin is still reachable.
        assert_eq!(pass.needs_route, vec![2, 3], "needs_route lost Bob or Carol");
        assert!(
            !pass.stopped_third,
            "unbarred upload skipped the third pin without whole-vault Stored"
        );
        let shot = relay.shot();
        assert_eq!(shot.mismatches, 0, "unbarred upload changed the object");
        let (roster, identity, _, _) = fixture();
        let mut store = ClientStore::open(dir.join("client").as_path(), &roster, 1).unwrap();
        let (config, opened) = install_routes(
            &mut store,
            &roster,
            &identity,
            &dir.join("routes.json"),
            &dir.join("append.bin"),
        );
        let logical = store
            .recover_logical(0, 100)
            .unwrap()
            .pop()
            .expect("committed logical row missing");
        let author_copies = store
            .recover_requirements(&logical.key, 1, None, 100)
            .unwrap()
            .len() as u64;
        assert!(author_copies >= 1, "author copy set was empty");
        assert_eq!(
            shot.third_puts, author_copies,
            "third pin did not receive every author copy"
        );
        assert!(
            !store
                .delivery_report(&roster, &identity, &logical, &config, &opened)
                .unwrap()
                .whole_vault(),
            "unrouted Bob and Carol counted as whole-vault Stored"
        );
        let saved = store.saved_object(&shot.hash).unwrap().expect("PUT hash was not committed");
        let same = relay.state.lock().unwrap().saved[&(shot.mailbox, shot.hash)].body == saved.wire;
        assert!(same, "PUT body differed from the committed wire");
    }

    #[test]
    fn outbox_crash_before_commit_no_put() {
        let dir = case_dir();
        let relay = Loopback::start();
        relay.publish(&dir);
        let (marker, mut child) = spawn_barrier(&dir, "before-commit");
        marker_is(&dir, &mut child, &marker, "before-commit");
        let (puts, entries) = relay.counts();
        assert_eq!(puts, 0, "a PUT was accepted before the outbox commit");
        assert_eq!(entries, 0, "the relay stored an object before the outbox commit");
        let root = dir.join("client");
        empty_outbox(&root);
        reap(&mut child);
        empty_outbox(&root);
        let (roster, _identity, body, _) = fixture();
        let store = ClientStore::open(&root, &roster, 1).unwrap();
        assert!(
            store
                .lookup_outbox_request(&COMMIT_REQUEST, &outbox_intent_digest(&body).unwrap())
                .unwrap()
                .is_none(),
            "a killed pre-commit request became durable"
        );
        let (puts, _) = relay.counts();
        assert_eq!(puts, 0, "reopening the killed root issued a PUT");
    }

    #[test]
    fn outbox_crash_after_commit_retains_wires() {
        let dir = case_dir();
        let relay = Loopback::start();
        relay.publish(&dir);
        let (marker, mut child) = spawn_barrier(&dir, "after-commit");
        marker_is(&dir, &mut child, &marker, "after-commit");
        let (puts, entries) = relay.counts();
        assert_eq!(puts, 0, "upload ran before the after-commit barrier returned");
        assert_eq!(entries, 0, "a relay entry existed before upload_pending");
        let root = dir.join("client");
        assert_eq!(table_count(&root, "logical_records"), 1);
        assert_eq!(table_count(&root, "caller_requests"), 1);
        assert_eq!(table_count(&root, "upload_work"), 0);
        reap(&mut child);
        let (roster, identity, body, reseal) = fixture();
        let store_check = ClientStore::open(&root, &roster, 1).unwrap();
        let expected: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("expected.json")).unwrap()).unwrap();
        retained(&store_check, &expected);
        let original_wire = hex::decode(
            expected["recipients"][0]["objects"][0]["wire"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(
            reseal.recipients()[0].objects()[0].wire != original_wire,
            "reseal matched the committed wire, so replacement would be invisible"
        );
        drop(store_check);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let returned = store
            .commit_outbox(&roster, &identity, &COMMIT_REQUEST, &reseal)
            .unwrap();
        assert_eq!(returned.key.message, COMMIT_MESSAGE);
        retained(&store, &expected);
        let mut other = body;
        other.key.message = [201; 32];
        let other = prepare_outbox(&identity, &roster, &other).unwrap();
        let returned = store
            .commit_outbox(&roster, &identity, &COMMIT_REQUEST, &other)
            .unwrap();
        assert_eq!(
            returned.key.message, COMMIT_MESSAGE,
            "same caller request allocated a new logical identity"
        );
        let created: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM logical_records WHERE message_id=?1",
                [[201u8; 32]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(created, 0, "same caller request persisted the resealed message id");
        retained(&store, &expected);
    }

    #[tokio::test]
    async fn outbox_crash_put_before_receipt_retries_original() {
        let dir = case_dir();
        let relay = Loopback::start();
        relay.publish(&dir);
        let (marker, mut child) = spawn_barrier(&dir, "before-receipt");
        marker_is(&dir, &mut child, &marker, "before-receipt");
        let during = relay.shot();
        assert_eq!(during.puts, 1, "the receipt barrier was not preceded by one PUT");
        assert_eq!(during.entries, 1);
        assert_eq!(during.duplicate_puts, 0);
        assert_eq!(during.third_puts, 0, "StopAfterStored still uploaded the third pin");
        assert_eq!(during.hits, 1);
        let root = dir.join("client");
        assert_eq!(table_count(&root, "verified_receipts"), 0);
        assert_eq!(table_count(&root, "logical_records"), 1);
        reap(&mut child);
        let (roster, identity) = owner();
        let body = http_body(&roster);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let logical = store
            .lookup_outbox_request(&HTTP_REQUEST, &outbox_intent_digest(&body).unwrap())
            .unwrap()
            .expect("committed request missing after the receipt kill");
        assert_eq!(logical.key.message, HTTP_MESSAGE);
        let pending = store
            .message_uploads(&logical.key)
            .unwrap()
            .into_iter()
            .find(|row| row.upload.mailbox == during.mailbox && row.upload.hash == during.hash)
            .expect("killed upload row missing");
        assert!(
            !pending.upload.acknowledged,
            "receipt kill left the upload acknowledged"
        );
        assert!(store.saved_receipt(&pending.upload).unwrap().is_none());
        let (config, opened) = install_routes(
            &mut store,
            &roster,
            &identity,
            &dir.join("routes.json"),
            &dir.join("append.bin"),
        );
        let before_entries = relay.shot().entries;
        let before_quota = relay.shot().quota;
        let http = RelayHttp::new().unwrap();
        let pass = upload_pending(
            &mut store,
            &http,
            &logical,
            &roster,
            &identity,
            &config,
            &opened,
            1_000,
            ThirdPass::StopAfterStored,
        )
        .await
        .unwrap();
        // The barrier above still stops on the first lesser-pin receipt. This
        // later pass has no whole-vault pair, so the author third pin is uploaded.
        assert_eq!(pass.needs_route, vec![2, 3], "needs_route lost Bob or Carol");
        assert!(
            !pass.stopped_third,
            "retry skipped the third pin without whole-vault Stored"
        );
        let after = relay.shot();
        let author_copies = store
            .recover_requirements(&logical.key, 1, None, 100)
            .unwrap()
            .len() as u64;
        assert_eq!(
            after.third_puts, author_copies,
            "retry did not PUT every author copy to the third pin"
        );
        assert!(
            !store
                .delivery_report(&roster, &identity, &logical, &config, &opened)
                .unwrap()
                .whole_vault(),
            "unrouted Bob and Carol counted as whole-vault Stored"
        );
        assert_eq!(after.mismatches, 0, "retry sent a different object");
        assert_eq!(after.sequence, during.sequence, "retry received a new sequence");
        assert_eq!(after.receipt, during.receipt, "retry received a different receipt");
        assert_eq!(after.hits, 2, "retry did not PUT the saved object again");
        assert_eq!(after.wire_len, during.wire_len);
        let same_key_entries = {
            let state = relay.state.lock().unwrap();
            state
                .saved
                .keys()
                .filter(|(mailbox, hash)| *mailbox == during.mailbox && *hash == during.hash)
                .count()
        };
        assert_eq!(same_key_entries, 1, "retry created an extra relay entry");
        assert_eq!(
            after.quota - before_quota,
            after.entries.saturating_sub(before_entries) * during.wire_len,
            "duplicate PUT changed the original object's quota"
        );
        let saved = store
            .message_uploads(&logical.key)
            .unwrap()
            .into_iter()
            .find(|row| row.upload.mailbox == during.mailbox && row.upload.hash == during.hash)
            .unwrap();
        assert!(saved.upload.acknowledged);
        assert_eq!(store.saved_receipt(&saved.upload).unwrap().unwrap(), during.receipt);
        let object = store.saved_object(&during.hash).unwrap().unwrap();
        assert_eq!(object.wire.len() as u64, during.wire_len);
        let body_matches = relay.state.lock().unwrap().saved[&(during.mailbox, during.hash)]
            .body
            == object.wire;
        assert!(body_matches, "relay did not keep the committed wire");
    }

    fn clamp_to_sqlite_full(connection: &Connection) {
        // Fill the receipt table's own pages. Another table's full page still leaves
        // this root page able to accept one receipt without allocating.
        connection.pragma_update(None, "foreign_keys", "OFF").unwrap();
        let pages: i64 = connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        connection
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let mut saw_full = false;
        let mut next = 0u32;
        for size in [4000usize, 2000, 1000, 500, 250, 120, 64] {
            loop {
                let mut hash = [9u8; 32];
                hash[..4].copy_from_slice(&next.to_be_bytes());
                next += 1;
                let result = connection.execute(
                    "INSERT INTO verified_receipts VALUES(?1,?2,1,?3,1,?4,?5,?6,?7,1024,1,1,?8)",
                    rusqlite::params![
                        [255u8; 32],
                        [254u8; 32],
                        [253u8; 32],
                        hash,
                        [252u8; 32],
                        [251u8; 32],
                        [250u8; 32],
                        vec![7u8; size]
                    ],
                );
                match result {
                    Ok(_) => {}
                    Err(error) => {
                        assert_eq!(
                            error.sqlite_error_code(),
                            Some(rusqlite::ErrorCode::DiskFull),
                            "page clamp was not a real SQLite full error"
                        );
                        saw_full = true;
                        break;
                    }
                }
            }
        }
        connection.pragma_update(None, "foreign_keys", "ON").unwrap();
        assert!(saw_full, "lowering max_page_count never returned SQLite full");
    }

    #[tokio::test]
    async fn outbox_crash_receipt_page_full() {
        let dir = case_dir();
        let relay = Loopback::start();
        relay.publish(&dir);
        let (roster, identity) = owner();
        let body = http_body(&roster);
        let prepared = prepare_outbox(&identity, &roster, &body).unwrap();
        let mut store = ClientStore::open(dir.join("client").as_path(), &roster, 1).unwrap();
        let logical = store
            .commit_outbox(&roster, &identity, &HTTP_REQUEST, &prepared)
            .unwrap();
        let (config, opened) = install_routes(
            &mut store,
            &roster,
            &identity,
            &dir.join("routes.json"),
            &dir.join("append.bin"),
        );
        store
            .bind_upload_routes(&roster, &identity, &logical, &config, &opened)
            .unwrap();
        let third = decode_id(
            &serde_json::from_slice::<serde_json::Value>(&fs::read(dir.join("routes.json")).unwrap())
                .unwrap()["third"],
        );
        let pending = store
            .message_uploads(&logical.key)
            .unwrap()
            .into_iter()
            .find(|row| row.upload.mailbox != third)
            .expect("no non-third upload row");
        let route = opened
            .body()
            .relays
            .iter()
            .find(|relay| relay.route.mailbox == pending.upload.mailbox)
            .unwrap()
            .route
            .clone();
        let object = store.saved_object(&pending.upload.hash).unwrap().unwrap();
        let append = Secret32::from_bytes(relay.append_for(pending.upload.mailbox));
        let http = RelayHttp::new().unwrap();
        let receipt = http.put(&route, &append, &object).await.unwrap();
        let shot = relay.shot();
        assert_eq!(shot.puts, 1);
        assert_eq!(shot.entries, 1);
        clamp_to_sqlite_full(&store.connection);
        let before_receipts: i64 = store
            .connection
            .query_row("SELECT count(*) FROM verified_receipts", [], |row| row.get(0))
            .unwrap();
        let result = store.commit_upload_receipt(&pending.upload, &receipt);
        assert_eq!(
            result,
            Err(ClientError::Capacity),
            "real SQLite page ceiling accepted a new receipt"
        );
        assert!(store.connection.is_autocommit());
        let after_receipts: i64 = store
            .connection
            .query_row("SELECT count(*) FROM verified_receipts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(after_receipts, before_receipts, "failed receipt commit persisted");
        assert!(store.saved_receipt(&pending.upload).unwrap().is_none());
        configure_storage_limit(&store.connection, 512 * 1024 * 1024).unwrap();
        store
            .connection
            .execute(
                "DELETE FROM verified_receipts WHERE vault=?1",
                [[255u8; 32]],
            )
            .unwrap();
        store
            .commit_upload_receipt(&pending.upload, &receipt)
            .unwrap();
        assert_eq!(
            store.saved_receipt(&pending.upload).unwrap().unwrap(),
            receipt.bytes()
        );
        let after = relay.shot();
        assert_eq!(after.puts, 1, "receipt retry substituted another PUT");
        assert_eq!(after.entries, 1, "saved receipt created an extra relay entry");
        assert_eq!(after.quota, shot.quota, "saved receipt consumed more quota");
        assert_eq!(after.sequence, shot.sequence);
        assert_eq!(after.receipt, shot.receipt);
    }
}
}

/// Incoming capture and acknowledgement DiskFull cases. Inert unless a case below arms it.
#[cfg(test)]
pub(crate) mod incoming_crash_tests {
    use super::{configure_storage_limit, ClientStore, STORAGE_BUDGET};
    use crate::{
        authenticate_staged, prepare_outbox, prepare_received, ClientError, CommitDisposition,
        DownloadOutcome,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_protocol::{
        canonical::{self, Value},
        receipt,
        types::{
            roster_digest, Entry, Id32, LogicalKey, MessageBody, Object, Page, Payload, ReceiptBody,
            RelayPin, RelayRoute, Roster,
        },
    };
    use rusqlite::ErrorCode;
    use sha2::{Digest, Sha256};
    use std::{
        cell::Cell,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static SAW_DISK_FULL: Cell<bool> = const { Cell::new(false) };
    }

    /// Checks the raw SQLite code only while an incoming library case is armed.
    pub(crate) fn observe_allocating_insert(result: &Result<usize, rusqlite::Error>) {
        if !ARMED.with(Cell::get) {
            return;
        }
        let Err(error) = result else {
            return;
        };
        assert_eq!(
            error.sqlite_error_code(),
            Some(ErrorCode::DiskFull),
            "armed ciphertext insert was not SQLITE_FULL"
        );
        SAW_DISK_FULL.with(|seen| seen.set(true));
    }

    struct Arm;
    impl Arm {
        fn new() -> Self {
            ARMED.with(|armed| armed.set(true));
            SAW_DISK_FULL.with(|seen| seen.set(false));
            Self
        }
        fn saw_disk_full() -> bool {
            SAW_DISK_FULL.with(Cell::get)
        }
    }
    impl Drop for Arm {
        fn drop(&mut self) {
            ARMED.with(|armed| armed.set(false));
        }
    }

    fn evidence(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        let directory = PathBuf::from("/private/tmp/relay-7.7-evidence").join(format!(
            "{name}-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        directory.join("client")
    }

    fn identity(id: u16) -> crate::CommIdentity {
        let mut seed = [0; 66];
        seed[..2].copy_from_slice(&id.to_be_bytes());
        seed[2..34].fill(id as u8);
        seed[34..].fill(id as u8 + 10);
        crate::CommIdentity::from_serialized(&seed).unwrap()
    }

    fn roster() -> (Roster, crate::CommIdentity, crate::CommIdentity) {
        let roster = Roster {
            vault: [70; 32],
            members: (1u16..=3).map(|id| identity(id).public()).collect(),
        };
        (roster, identity(1), identity(2))
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    fn route() -> RelayRoute {
        RelayRoute {
            pin: RelayPin {
                key: signer().verifying_key().to_bytes(),
                run: [2; 32],
            },
            endpoint: "http://127.0.0.1:9".to_string(),
            mailbox: [3; 32],
            append_revision: 1,
        }
    }

    fn framed(mark: u8, len: usize) -> Object {
        let mut wire = vec![mark; len];
        wire[..8].copy_from_slice(b"LOKIRLY1");
        wire[8] = 1;
        wire[9] = mark;
        Object {
            hash: Sha256::digest(&wire).into(),
            wire,
        }
    }

    fn receipt(route: &RelayRoute, hash: Id32, wire_length: u64, sequence: u64) -> Vec<u8> {
        let body = ReceiptBody {
            pin: route.pin.clone(),
            mailbox: route.mailbox,
            hash,
            wire_length,
            sequence,
            retention: 1,
        };
        let encoded = receipt::encode_body(&body).unwrap();
        let mut input = b"Loki_Relay_Stored_v1\0".to_vec();
        input.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
        input.extend_from_slice(&encoded);
        canonical::encode(&Value::Array(vec![
            Value::Bytes(encoded),
            Value::Bytes(signer().sign(&input).to_bytes().to_vec()),
        ]))
        .unwrap()
    }

    fn capture(store: &mut ClientStore, route: &RelayRoute, object: &Object, sequence: u64) -> crate::ClientResult<()> {
        let entry = Entry {
            sequence,
            hash: object.hash,
            wire_length: object.wire.len() as u64,
            receipt: receipt(route, object.hash, object.wire.len() as u64, sequence),
        };
        store.capture_page(
            route,
            &Page {
                mailbox: route.mailbox,
                after: sequence - 1,
                next: sequence,
                high_water: sequence,
                entries: vec![entry],
            },
            &[DownloadOutcome::Cached(object.clone())],
        )
    }

    fn capture_directory(
        store: &mut ClientStore,
        route: &RelayRoute,
        objects: &[Object],
    ) -> crate::ClientResult<()> {
        let entries: Vec<Entry> = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                let sequence = index as u64 + 1;
                Entry {
                    sequence,
                    hash: object.hash,
                    wire_length: object.wire.len() as u64,
                    receipt: receipt(route, object.hash, object.wire.len() as u64, sequence),
                }
            })
            .collect();
        let next = entries.len() as u64;
        let downloads: Vec<_> = objects
            .iter()
            .cloned()
            .map(DownloadOutcome::Cached)
            .collect();
        store.capture_page(
            route,
            &Page {
                mailbox: route.mailbox,
                after: 0,
                next,
                high_water: next,
                entries,
            },
            &downloads,
        )
    }

    fn cursor(store: &ClientStore, route: &RelayRoute) -> Option<u64> {
        store
            .recover_route_cursors(0, 100)
            .unwrap()
            .into_iter()
            .find(|cursor| {
                cursor.relay_key == route.pin.key
                    && cursor.run == route.pin.run
                    && cursor.mailbox == route.mailbox
            })
            .map(|cursor| cursor.position)
    }

    fn rows(store: &ClientStore, table: &str) -> i64 {
        store
            .connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .unwrap()
    }

    fn clamp_to_allocated(store: &ClientStore) -> u64 {
        let pages: u64 = store
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        store
            .connection
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let effective: u64 = store
            .connection
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .unwrap();
        assert_eq!(effective, pages, "writer max_page_count did not stay at page_count");
        pages
    }

    #[test]
    fn incoming_crash_capture_sqlite_full() {
        let (roster, _, _) = roster();
        let route = route();
        let root = evidence("capture-full");
        let mut store = ClientStore::open(&root, &roster, 2).unwrap();
        let prior = framed(7, 1024);
        capture(&mut store, &route, &prior, 1).unwrap();
        let journal = store.recover_journal(&route, 0, 100).unwrap().len();
        let tasks = store.recover_pending_downloads(0, 100).unwrap().len();
        let ciphertext = rows(&store, "ciphertext_objects");
        clamp_to_allocated(&store);
        let wide = framed(8, 65536);
        let arm = Arm::new();
        let result = capture(&mut store, &route, &wide, 2);
        assert!(Arm::saw_disk_full(), "capture insert did not observe SQLITE_FULL");
        drop(arm);
        assert_eq!(
            result,
            Err(ClientError::Capacity),
            "SQLITE_FULL was not mapped to Capacity"
        );
        assert!(store.connection.is_autocommit());
        drop(store);
        let store = ClientStore::open(&root, &roster, 2).unwrap();
        assert_eq!(cursor(&store, &route), Some(1), "restart kept the failed capture cursor");
        let reopened_journal = store.recover_journal(&route, 0, 100).unwrap();
        assert_eq!(reopened_journal.len(), journal);
        assert_eq!(reopened_journal[0].source_hash, prior.hash);
        assert_eq!(reopened_journal[0].disposition, "cached");
        assert_eq!(store.recover_pending_downloads(0, 100).unwrap().len(), tasks);
        assert_eq!(rows(&store, "ciphertext_objects"), ciphertext);
        let saved = store.saved_object(&prior.hash).unwrap().expect("prior ciphertext missing");
        assert!(saved.wire == prior.wire, "restart changed the prior ciphertext");
        assert!(store.saved_object(&wide.hash).unwrap().is_none());
        assert_eq!(rows(&store, "incoming_originals"), 0);
        assert_eq!(rows(&store, "ack_links"), 0);
        assert_eq!(rows(&store, "caller_requests"), 0);
        drop(store);
        let mut store = ClientStore::open(&root, &roster, 2).unwrap();
        configure_storage_limit(&store.connection, STORAGE_BUDGET).unwrap();
        capture(&mut store, &route, &wide, 2).expect("later capture after the ceiling was lifted");
        assert_eq!(cursor(&store, &route), Some(2));
        let saved = store.saved_object(&wide.hash).unwrap().expect("lifted capture missing");
        assert!(saved.wire == wide.wire, "lifted capture changed the new ciphertext");
    }

    #[test]
    fn incoming_crash_original_ack_sqlite_full() {
        let (roster, alice, bob) = roster();
        let route = route();
        let root = evidence("ack-full");
        let body = MessageBody {
            key: LogicalKey {
                vault: roster.vault,
                roster: roster_digest(&roster).unwrap(),
                sender: 1,
                message: [42; 32],
            },
            audience: vec![1, 2, 3],
            session: Some([44; 32]),
            prerequisites: vec![],
            payload: Payload::Test(vec![19; 80_000]),
        };
        let prepared = prepare_outbox(&alice, &roster, &body).unwrap();
        let objects = prepared
            .recipients()
            .iter()
            .find(|recipient| recipient.recipient() == 2)
            .unwrap()
            .objects()
            .to_vec();
        assert!(
            objects.len() > 1,
            "chunked original did not include a manifest"
        );
        assert!(
            objects.iter().any(|object| object.wire.len() > 4096),
            "acknowledgement source is too small to force a new page"
        );
        let mut store = ClientStore::open(&root, &roster, 2).unwrap();
        capture_directory(&mut store, &route, &objects).unwrap();
        let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
        assert_eq!(candidates.len(), 1);
        let ack = prepare_received(
            &store,
            &bob,
            &roster,
            candidates[0].message(),
            candidates[0].source(),
        )
        .unwrap()
        .unwrap();
        let cursor_before = cursor(&store, &route);
        let journal = store.recover_journal(&route, 0, 100).unwrap().len();
        let tasks = store.recover_pending_downloads(0, 100).unwrap().len();
        let ciphertext = rows(&store, "ciphertext_objects");
        clamp_to_allocated(&store);
        let arm = Arm::new();
        let result = store.commit_incoming(
            &roster,
            &bob,
            candidates[0].source(),
            candidates[0].message(),
            Some(&ack),
        );
        assert!(
            Arm::saw_disk_full(),
            "acknowledgement insert did not observe SQLITE_FULL"
        );
        drop(arm);
        assert_eq!(
            result,
            Err(ClientError::Capacity),
            "SQLITE_FULL was not mapped to Capacity"
        );
        assert!(store.connection.is_autocommit());
        drop(store);
        let store = ClientStore::open(&root, &roster, 2).unwrap();
        assert_eq!(cursor(&store, &route), cursor_before, "restart kept the failed acknowledgement cursor");
        assert_eq!(store.recover_journal(&route, 0, 100).unwrap().len(), journal);
        assert_eq!(store.recover_pending_downloads(0, 100).unwrap().len(), tasks);
        assert_eq!(rows(&store, "ciphertext_objects"), ciphertext);
        for object in &objects {
            let saved = store.saved_object(&object.hash).unwrap().expect("captured object missing");
            assert!(saved.wire == object.wire, "restart changed a captured object");
        }
        assert_eq!(rows(&store, "incoming_originals"), 0);
        assert_eq!(rows(&store, "ack_links"), 0);
        assert_eq!(rows(&store, "caller_requests"), 0);
        assert_eq!(rows(&store, "logical_records"), 0);
        drop(store);
        let mut store = ClientStore::open(&root, &roster, 2).unwrap();
        configure_storage_limit(&store.connection, STORAGE_BUDGET).unwrap();
        assert_eq!(
            store
                .commit_incoming(
                    &roster,
                    &bob,
                    candidates[0].source(),
                    candidates[0].message(),
                    Some(&ack),
                )
                .unwrap(),
            CommitDisposition::New
        );
        assert_eq!(rows(&store, "incoming_originals"), 1);
        assert_eq!(rows(&store, "ack_links"), 1);
        assert_eq!(rows(&store, "caller_requests"), 1);
        drop(store);
        let store = ClientStore::open(&root, &roster, 2).unwrap();
        assert_eq!(store.recover_ack_links(0, 100).unwrap().len(), 1);
        assert_eq!(store.recover_incoming_originals(0, 100).unwrap().len(), 1);
        assert_eq!(cursor(&store, &route), cursor_before);
    }

    /// One page of configured budget is below the allocated file. SQLite keeps
    /// max_page_count at page_count, so this refusal is not SQLITE_FULL.
    fn configure_below_allocated(store: &mut ClientStore) {
        let page_size: u64 = store
            .connection
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        let allocated: u64 = store
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        assert!(allocated > 1, "store allocated no extra page to exceed");
        store.storage_budget = page_size;
        configure_storage_limit(&store.connection, page_size).unwrap();
        let effective: u64 = store
            .connection
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .unwrap();
        assert_eq!(
            effective, allocated,
            "configured budget lowered the SQLite page ceiling"
        );
    }

    #[test]
    fn orphan_chunk_flood_budget_preserves_downloads_after_reopen() {
        let (roster, _, bob) = roster();
        let route = route();
        let root = evidence("orphan-flood");
        let mut store = ClientStore::open(&root, &roster, 2).unwrap();
        let missing = framed(2, 1024);
        store.capture_page(&route, &Page {
            mailbox: route.mailbox, after: 0, next: 1, high_water: 1,
            entries: vec![Entry { sequence: 1, hash: missing.hash, wire_length: 1024,
                receipt: receipt(&route, missing.hash, 1024, 1) }],
        }, &[DownloadOutcome::Missing(missing.hash)]).unwrap();
        let page_size: u64 = store.connection.pragma_query_value(None, "page_size", |r| r.get(0)).unwrap();
        let allocated: u64 = store.connection.pragma_query_value(None, "page_count", |r| r.get(0)).unwrap();
        // A reduced test budget reaches real staging admission with a small flood.
        store.storage_budget = (allocated + 48) * page_size;
        configure_storage_limit(&store.connection, store.storage_budget).unwrap();
        let context = crate::SealContext { domain: crate::SealDomain::Message,
            vault: roster.vault, roster: roster_digest(&roster).unwrap(), recipient: bob.public() };
        let mut accepted = Vec::new();
        let mut refused = None;
        for n in 0u8..20 {
            let record = canonical::encode(&Value::Array(vec![Value::Integer(3.into()),
                Value::Bytes(vec![n; 32]), Value::Integer(0.into()), Value::Bytes(vec![19; 60 * 1024])])).unwrap();
            let object = crate::seal_record(&context, &record).unwrap();
            let sequence = accepted.len() as u64 + 2;
            match capture(&mut store, &route, &object, sequence) {
                Ok(()) => accepted.push(object),
                Err(ClientError::Capacity) => { refused = Some(object); break; }
                other => panic!("unexpected orphan admission result: {other:?}"),
            }
        }
        assert!(!accepted.is_empty());
        let refused = refused.expect("orphan flood never hit admission limit");
        let position = accepted.len() as u64 + 1;
        assert_eq!(cursor(&store, &route), Some(position));
        assert!(store.saved_object(&refused.hash).unwrap().is_none());
        assert!(authenticate_staged(&mut store, &roster, &bob).unwrap().is_empty());
        assert_eq!(store.pending_transfer_count().unwrap(), 0);
        assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());
        assert!(store.recover_ack_links(0, 100).unwrap().is_empty());
        drop(store);
        let store = ClientStore::open(&root, &roster, 2).unwrap();
        assert_eq!(cursor(&store, &route), Some(position));
        let pending = store.recover_pending_downloads(0, 100).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_hash, missing.hash);
        assert_eq!(store.recover_journal(&route, 0, 100).unwrap().len(), position as usize);
        for object in accepted { assert_eq!(store.saved_object(&object.hash).unwrap().unwrap().wire, object.wire); }
        assert!(store.saved_object(&refused.hash).unwrap().is_none());
        println!("orphan-flood accepted={} pending=1 cursor={} refused_hash={}", position - 1, position, hex::encode(refused.hash));
    }

    #[test]
    fn download_recovery_budget_keeps_pending_and_stops_admission() {
        let (roster, _, _) = roster();
        let route = route();
        let root = evidence("budget-pending");
        let mut store = ClientStore::open(&root, &roster, 2).unwrap();
        let cached = framed(1, 1024);
        capture(&mut store, &route, &cached, 1).unwrap();
        let missing = framed(2, 1024);
        store
            .capture_page(
                &route,
                &Page {
                    mailbox: route.mailbox,
                    after: 1,
                    next: 2,
                    high_water: 2,
                    entries: vec![Entry {
                        sequence: 2,
                        hash: missing.hash,
                        wire_length: missing.wire.len() as u64,
                        receipt: receipt(&route, missing.hash, missing.wire.len() as u64, 2),
                    }],
                },
                &[DownloadOutcome::Missing(missing.hash)],
            )
            .unwrap();
        assert_eq!(cursor(&store, &route), Some(2));
        let pending = store.recover_pending_downloads(0, 100).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_hash, missing.hash);
        assert_eq!(pending[0].wire_length, 1024);
        let journal_before = store.recover_journal(&route, 0, 100).unwrap();
        assert_eq!(journal_before.len(), 2);
        configure_below_allocated(&mut store);
        assert!(
            !Arm::saw_disk_full(),
            "configured budget was reported as SQLITE_FULL"
        );

        let uncovered = framed(3, 1024);
        let refused = capture(&mut store, &route, &uncovered, 3);
        assert_eq!(refused, Err(ClientError::Capacity));
        assert!(store.connection.is_autocommit());
        assert!(store.saved_object(&uncovered.hash).unwrap().is_none());
        assert!(store.saved_object(&missing.hash).unwrap().is_none());

        let refused_pending = store.capture_page(
            &route,
            &Page {
                mailbox: route.mailbox,
                after: 2,
                next: 3,
                high_water: 3,
                entries: vec![Entry {
                    sequence: 3,
                    hash: missing.hash,
                    wire_length: missing.wire.len() as u64,
                    receipt: receipt(&route, missing.hash, missing.wire.len() as u64, 3),
                }],
            },
            &[DownloadOutcome::Cached(missing.clone())],
        );
        assert_eq!(
            refused_pending,
            Err(ClientError::Capacity),
            "over-budget caching of the pending object was admitted"
        );
        assert!(store.connection.is_autocommit());
        assert!(store.saved_object(&missing.hash).unwrap().is_none());
        assert!(!Arm::saw_disk_full(), "pending-object refusal was SQLITE_FULL");
        let pending = store.recover_pending_downloads(0, 100).unwrap();
        assert_eq!(pending.len(), 1, "refused cache deleted the outstanding task");
        assert_eq!(pending[0].source_hash, missing.hash);
        assert_eq!(cursor(&store, &route), Some(2));
        assert_eq!(store.recover_journal(&route, 0, 100).unwrap().len(), 2);
        drop(store);

        let store = ClientStore::open(&root, &roster, 2).unwrap();
        assert_eq!(cursor(&store, &route), Some(2));
        let pending = store.recover_pending_downloads(0, 100).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_hash, missing.hash);
        assert_eq!(pending[0].wire_length, 1024);
        let journal = store.recover_journal(&route, 0, 100).unwrap();
        assert_eq!(journal.len(), journal_before.len());
        assert_eq!(journal[0].disposition, "cached");
        assert_eq!(journal[0].source_hash, cached.hash);
        assert_eq!(journal[1].disposition, "missing");
        assert_eq!(journal[1].source_hash, missing.hash);
        let saved = store.saved_object(&cached.hash).unwrap().expect("prior ciphertext missing");
        assert!(saved.wire == cached.wire, "reopen changed the cached wire");
        assert!(store.saved_object(&missing.hash).unwrap().is_none());
        assert!(store.saved_object(&uncovered.hash).unwrap().is_none());
    }
}
