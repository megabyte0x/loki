use crate::{AuthenticatedSetupRecord, ClientError, ClientResult, PreparedSetup, SetupTransport};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::SetupKey,
    types::{Id32, Object},
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::Path,
};
const SCHEMA: &str = include_str!("setup_store.sql");
const DEFERRED_SCHEMA: &str =
    "CREATE TABLE deferred (hash BLOB PRIMARY KEY REFERENCES objects(hash)) STRICT;\n";
const PENDING_ROOTS_SCHEMA: &str =
    "CREATE TABLE pending_roots (hash BLOB PRIMARY KEY REFERENCES objects(hash), expires_ms INTEGER NOT NULL CHECK(expires_ms>0)) STRICT;\n";
const BUDGET: u64 = 256 * 1024 * 1024;
/// Stores made before vaults grew past 4 members bound recipients at 4.
const NARROW_RECIPIENT: &str = "recipient BETWEEN 1 AND 4)";
const WIDE_RECIPIENT: &str = "recipient BETWEEN 1 AND 16)";
pub struct SetupStore {
    pub(crate) connection: Connection,
    _lock: File,
}
pub(crate) fn key_bytes(key: &SetupKey) -> ClientResult<Vec<u8>> {
    Ok(canonical::encode(&Value::Array(vec![
        Value::Integer((key.phase as u8).into()),
        Value::Integer(key.author.into()),
        Value::Integer(key.recipient.into()),
        Value::Integer(key.revision.into()),
    ]))?)
}
fn association(t: &SetupTransport<'_>) -> ClientResult<Vec<u8>> {
    let p = t.context().policy();
    let m = t.identity.public();
    Ok(canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(p.ceremony.to_vec()),
        Value::Text(p.network.clone()),
        Value::Integer(p.threshold.into()),
        Value::Integer(p.member_count.into()),
        Value::Bytes(p.config_digest.to_vec()),
        Value::Integer(m.id.into()),
        Value::Bytes(m.signing.to_vec()),
        Value::Bytes(m.encryption.to_vec()),
    ]))?)
}
pub(crate) fn add_object(c: &Connection, o: &Object) -> ClientResult<()> {
    loki_relay_protocol::envelope::validate_wire(&o.wire)?;
    if <Id32>::from(Sha256::digest(&o.wire)) != o.hash {
        return Err(ClientError::Identity);
    }
    let prior: Option<Vec<u8>> = c
        .query_row(
            "SELECT wire FROM objects WHERE hash=?1",
            [o.hash.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(prior) = prior {
        if prior != o.wire {
            return Err(ClientError::Conflict);
        }
        return Ok(());
    }
    let used: u64 = c.query_row(
        "SELECT coalesce(sum(length(wire)),0) FROM objects",
        [],
        |r| r.get(0),
    )?;
    if used.saturating_add(o.wire.len() as u64) > BUDGET {
        return Err(ClientError::Capacity);
    }
    c.execute(
        "INSERT INTO objects VALUES(?1,?2)",
        params![o.hash.as_slice(), &o.wire],
    )?;
    Ok(())
}
impl SetupStore {
    /// Completed setup retires inboxes that already returned a stored receipt.
    pub fn clear_retries_for_stored_routes(&self) -> ClientResult<()> {
        self.connection.execute(
            "DELETE FROM retries WHERE pin IN (SELECT DISTINCT pin FROM stored)",
            [],
        )?;
        Ok(())
    }

    pub fn open(path: &Path, transport: &SetupTransport<'_>) -> ClientResult<Self> {
        let path = crate::store::root_path(path)?;
        let fresh = match fs::symlink_metadata(&path) {
            Ok(m) => {
                crate::store::check_owner(&m, 0o700, true)?;
                false
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut b = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                }
                b.create(&path)?;
                true
            }
            Err(_) => return Err(ClientError::Storage),
        };
        let lock = File::open(&path)?;
        lock.try_lock().map_err(|_| ClientError::Storage)?;
        let db = path.join("setup.sqlite3");
        if fresh {
            let mut o = OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(&db)?.sync_all()?;
            File::open(path.parent().ok_or(ClientError::Storage)?)?.sync_all()?;
        }
        for name in [
            "setup.sqlite3",
            "setup.sqlite3-wal",
            "setup.sqlite3-shm",
            "setup.sqlite3-journal",
        ] {
            match fs::symlink_metadata(path.join(name)) {
                Ok(m) => crate::store::check_owner(&m, 0o600, false)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && name != "setup.sqlite3" => {}
                Err(_) => return Err(ClientError::Storage),
            }
        }
        let mut c = Connection::open_with_flags(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        crate::store::configure(&c)?;
        c.pragma_update(None, "trusted_schema", "OFF")?;
        if fresh {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO metadata VALUES(1,?1,0)",
                [association(transport)?],
            )?;
            tx.commit()?;
            File::open(&path)?.sync_all()?;
        }
        if crate::store::validate_schema(&c, SCHEMA).is_err() {
            // Recognize exact previous catalogs before adding derived pending work.
            let previous = SCHEMA.strip_suffix(PENDING_ROOTS_SCHEMA).ok_or(ClientError::Storage)?;
            let narrow = previous.replace(WIDE_RECIPIENT, NARROW_RECIPIENT);
            let without_deferred =
                |schema: &str| schema.strip_suffix(DEFERRED_SCHEMA).map(str::to_owned);
            let (deferred, widen) = if crate::store::validate_schema(&c, previous).is_ok() {
                (true, false)
            } else if crate::store::validate_schema(&c, &narrow).is_ok() {
                (true, true)
            } else if without_deferred(&narrow)
                .is_some_and(|legacy| crate::store::validate_schema(&c, &legacy).is_ok())
            {
                (false, true)
            } else {
                let legacy = without_deferred(previous).ok_or(ClientError::Storage)?;
                crate::store::validate_schema(&c, &legacy)?;
                (false, false)
            };
            let saved: Vec<u8> = c.query_row(
                "SELECT association FROM metadata WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            if saved != association(transport)? {
                return Err(ClientError::Identity);
            }
            if widen {
                crate::store::widen_checks(&mut c, NARROW_RECIPIENT, WIDE_RECIPIENT)?;
            }
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if !deferred {
                tx.execute_batch(DEFERRED_SCHEMA)?;
            }
            tx.execute_batch(PENDING_ROOTS_SCHEMA)?;
            crate::store::validate_schema(&tx, SCHEMA)?;
            tx.commit()?;
        }
        let saved: Vec<u8> = c.query_row(
            "SELECT association FROM metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if saved != association(transport)? {
            return Err(ClientError::Identity);
        }
        Ok(Self {
            connection: c,
            _lock: lock,
        })
    }
    pub(crate) fn check_transport(&self, t: &SetupTransport<'_>) -> ClientResult<()> {
        let saved: Vec<u8> = self.connection.query_row(
            "SELECT association FROM metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if saved != association(t)? {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
    pub fn is_terminal(&self) -> ClientResult<bool> {
        Ok(self.connection.query_row(
            "SELECT terminal FROM metadata WHERE singleton=1",
            [],
            |r| r.get::<_, i64>(0),
        )? != 0)
    }
    pub(crate) fn active(&self) -> ClientResult<()> {
        if self.is_terminal()? {
            Err(ClientError::Conflict)
        } else {
            Ok(())
        }
    }
    pub fn commit_outgoing(
        &mut self,
        t: &SetupTransport<'_>,
        p: &PreparedSetup,
    ) -> ClientResult<bool> {
        self.check_transport(t)?;
        self.active()?;
        if p.ceremony != t.context().policy().ceremony
            || p.config != *t.operators.digest()
            || p.author != t.identity.public()
        {
            return Err(ClientError::Identity);
        }
        let own = p
            .copies
            .iter()
            .find(|c| c.key.recipient == p.author.id)
            .ok_or(ClientError::Identity)?;
        let root = own.objects.last().ok_or(ClientError::Identity)?;
        let objects = own.objects.iter().map(|o| (o.hash, o.clone())).collect();
        let authenticated = t.assemble(root, &objects)?;
        if authenticated.body().key != own.key || authenticated.digest() != &own.digest {
            return Err(ClientError::Identity);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut existing = 0;
        for copy in &p.copies {
            let key = key_bytes(&copy.key)?;
            let prior: Option<Vec<u8>> = tx
                .query_row("SELECT digest FROM outgoing WHERE key=?1", [&key], |r| {
                    r.get(0)
                })
                .optional()?;
            if let Some(prior) = prior {
                if prior != copy.digest {
                    tx.execute("UPDATE metadata SET terminal=1 WHERE singleton=1", [])?;
                    tx.commit()?;
                    return Err(ClientError::Conflict);
                }
                existing += 1;
            }
        }
        if existing != 0 {
            if existing != p.copies.len() {
                return Err(ClientError::Storage);
            }
            return Ok(false);
        }
        let count: u64 = tx.query_row("SELECT count(*) FROM outgoing", [], |r| r.get(0))?;
        if count + p.copies.len() as u64 > 4096 {
            return Err(ClientError::Capacity);
        }
        for copy in &p.copies {
            let key = key_bytes(&copy.key)?;
            for o in &copy.objects {
                add_object(&tx, o)?;
            }
            tx.execute(
                "INSERT INTO outgoing VALUES(?1,?2,?3,?4)",
                params![
                    &key,
                    copy.digest.as_slice(),
                    copy.key.recipient,
                    copy.root.as_slice()
                ],
            )?;
            for (i, o) in copy.objects.iter().enumerate() {
                tx.execute(
                    "INSERT INTO required VALUES(?1,?2,?3)",
                    params![&key, i as i64, o.hash.as_slice()],
                )?;
            }
        }
        let key = key_bytes(&own.key)?;
        let prior: Option<Vec<u8>> = tx
            .query_row("SELECT digest FROM incoming WHERE key=?1", [&key], |r| {
                r.get(0)
            })
            .optional()?;
        if prior.as_deref().is_some_and(|d| d != own.digest) {
            tx.execute("UPDATE metadata SET terminal=1 WHERE singleton=1", [])?;
            tx.commit()?;
            return Err(ClientError::Conflict);
        }
        let deps = canonical::encode(&Value::Array(
            own.prerequisites
                .iter()
                .map(|d| Value::Bytes(d.to_vec()))
                .collect(),
        ))?;
        tx.execute(
            "INSERT OR IGNORE INTO incoming VALUES(?1,?2,?3,?4)",
            params![key, own.digest.as_slice(), own.root.as_slice(), deps],
        )?;
        tx.commit()?;
        Ok(true)
    }
    pub fn commit_incoming(
        &mut self,
        t: &SetupTransport<'_>,
        root: &Object,
        objects: &BTreeMap<Id32, Object>,
    ) -> ClientResult<bool> {
        self.check_transport(t)?;
        self.active()?;
        let record = match t.assemble(root, objects) {
            Ok(record) => record,
            Err(ClientError::SetupAgreementPending) => {
                let requirements = t.inspect(root)?;
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM deferred WHERE hash=?1)",
                    [root.hash.as_slice()],
                    |r| r.get(0),
                )?;
                let count: u64 = tx.query_row(
                    "SELECT (SELECT count(*) FROM deferred) + (SELECT count(*) FROM incoming)",
                    [],
                    |r| r.get(0),
                )?;
                if !exists && count >= 4096 {
                    return Err(ClientError::Capacity);
                }
                add_object(&tx, root)?;
                for (hash, _) in requirements {
                    add_object(&tx, objects.get(&hash).ok_or(ClientError::Storage)?)?;
                }
                tx.execute(
                    "INSERT OR IGNORE INTO deferred VALUES(?1)",
                    [root.hash.as_slice()],
                )?;
                tx.commit()?;
                return Err(ClientError::SetupAgreementPending);
            }
            Err(ClientError::Conflict) => {
                self.connection
                    .execute("UPDATE metadata SET terminal=1 WHERE singleton=1", [])?;
                return Err(ClientError::Conflict);
            }
            Err(error) => return Err(error),
        };
        let key = key_bytes(&record.body().key)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<Vec<u8>> = tx
            .query_row("SELECT digest FROM incoming WHERE key=?1", [&key], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(prior) = prior {
            if prior != record.digest().as_slice() {
                tx.execute("UPDATE metadata SET terminal=1 WHERE singleton=1", [])?;
                tx.commit()?;
                return Err(ClientError::Conflict);
            }
            return Ok(false);
        }
        let count: u64 = tx.query_row("SELECT count(*) FROM incoming", [], |r| r.get(0))?;
        if count >= 4096 {
            return Err(ClientError::Capacity);
        }
        add_object(&tx, root)?;
        for (hash, _) in t.inspect(root)? {
            add_object(&tx, objects.get(&hash).ok_or(ClientError::Storage)?)?;
        }
        let deps = canonical::encode(&Value::Array(
            record
                .body()
                .prerequisites
                .iter()
                .map(|d| Value::Bytes(d.to_vec()))
                .collect(),
        ))?;
        tx.execute(
            "INSERT INTO incoming VALUES(?1,?2,?3,?4)",
            params![&key, record.digest().as_slice(), root.hash.as_slice(), deps],
        )?;
        if let Some((recipient, ack)) = t.prepare_ack(&record)? {
            add_object(&tx, &ack)?;
            tx.execute(
                "INSERT INTO acknowledgements VALUES(?1,?2,?3)",
                params![&key, recipient, ack.hash.as_slice()],
            )?;
        }
        tx.execute("DELETE FROM deferred WHERE hash=?1", [root.hash.as_slice()])?;
        tx.commit()?;
        Ok(true)
    }
    pub fn reconcile_deferred(&mut self, t: &SetupTransport<'_>) -> ClientResult<usize> {
        self.check_transport(t)?;
        self.active()?;
        if !t.has_accepted_roster() {
            return Ok(0);
        }
        let hashes: Vec<Vec<u8>> = {
            let mut statement = self
                .connection
                .prepare("SELECT hash FROM deferred ORDER BY hash LIMIT 32")?;
            let rows = statement.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut committed = 0;
        for hash in hashes {
            let hash: Id32 = hash.try_into().map_err(|_| ClientError::Storage)?;
            let load = |hash: &Id32| -> ClientResult<Object> {
                Ok(Object {
                    hash: *hash,
                    wire: self.connection.query_row(
                        "SELECT wire FROM objects WHERE hash=?1",
                        [hash.as_slice()],
                        |r| r.get(0),
                    )?,
                })
            };
            let root = load(&hash)?;
            let mut objects = BTreeMap::new();
            for (hash, _) in t.inspect(&root)? {
                objects.insert(hash, load(&hash)?);
            }
            match self.commit_incoming(t, &root, &objects) {
                Ok(_) => {
                    committed += 1;
                }
                Err(
                    error @ (ClientError::Conflict | ClientError::Storage | ClientError::Capacity),
                ) => return Err(error),
                Err(_) => {
                    let tx = self
                        .connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)?;
                    tx.execute(
                        "INSERT OR IGNORE INTO rejected VALUES(?1)",
                        [hash.as_slice()],
                    )?;
                    tx.execute("DELETE FROM deferred WHERE hash=?1", [hash.as_slice()])?;
                    tx.commit()?;
                }
            }
        }
        Ok(committed)
    }
    pub fn saved_objects(&self) -> ClientResult<Vec<(Id32, Vec<u8>)>> {
        let mut stmt = self
            .connection
            .prepare("SELECT hash,wire FROM objects ORDER BY hash")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|r| {
            let (h, w) = r?;
            Ok((h.try_into().map_err(|_| ClientError::Storage)?, w))
        })
        .collect()
    }
    pub fn receive(
        &self,
        t: &SetupTransport<'_>,
        key: &SetupKey,
    ) -> ClientResult<Option<AuthenticatedSetupRecord>> {
        self.check_transport(t)?;
        self.active()?;
        if key.ceremony != t.context().policy().ceremony || key.recipient != t.identity.public().id
        {
            return Err(ClientError::Identity);
        }
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT digest,root FROM incoming WHERE key=?1",
                [key_bytes(key)?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((digest, root)) = row else {
            return Ok(None);
        };
        let objects: BTreeMap<_, _> = self
            .saved_objects()?
            .into_iter()
            .map(|(hash, wire)| (hash, Object { hash, wire }))
            .collect();
        let root: Id32 = root.try_into().map_err(|_| ClientError::Storage)?;
        let record = t.assemble(objects.get(&root).ok_or(ClientError::Storage)?, &objects)?;
        if record.body().key != *key || record.digest().as_slice() != digest {
            return Err(ClientError::Storage);
        }
        let mut pending = record.body().prerequisites.clone();
        let mut graph = BTreeMap::<Id32, Vec<Id32>>::new();
        while let Some(d) = pending.pop() {
            if graph.contains_key(&d) {
                continue;
            }
            if graph.len() >= 4096 {
                return Err(ClientError::Capacity);
            }
            let row: Option<(Vec<u8>, Vec<u8>)> = self
                .connection
                .query_row(
                    "SELECT key,root FROM incoming WHERE digest=?1",
                    [d.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((saved_key, h)) = row else {
                return Ok(None);
            };
            let h: Id32 = h.try_into().map_err(|_| ClientError::Storage)?;
            let prerequisite =
                t.assemble(objects.get(&h).ok_or(ClientError::Storage)?, &objects)?;
            if prerequisite.digest() != &d || key_bytes(&prerequisite.body().key)? != saved_key {
                return Err(ClientError::Storage);
            }
            pending.extend_from_slice(&prerequisite.body().prerequisites);
            graph.insert(d, prerequisite.body().prerequisites.clone());
        }
        let mut ready = std::collections::BTreeSet::new();
        while !graph.is_empty() {
            let leaves: Vec<_> = graph
                .iter()
                .filter(|(_, deps)| deps.iter().all(|d| ready.contains(d)))
                .map(|(d, _)| *d)
                .collect();
            if leaves.is_empty() {
                return Ok(None);
            }
            for d in leaves {
                graph.remove(&d);
                ready.insert(d);
            }
        }
        Ok(Some(record))
    }
}
