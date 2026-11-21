use crate::{
    signature_input, AdmissionError as Error, AdmissionResult as Result, EnrollmentVerifier,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use loki_relay_client::OperatorSet;
use loki_relay_protocol::{
    admission::{self, AdmissionCommand as Command, AdmissionRequest},
    canonical::{self, Value},
    http::{self, NamespaceAction},
    types::{Id32, MemberPublic},
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    path::Path,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct ProvisionIntent {
    ceremony: Id32,
    slot: u16,
    relay: u16,
    purpose: u16,
    mailbox: Id32,
    request: Vec<u8>,
    quota: u64,
    expires: u64,
    retire: bool,
    pub(crate) action: Option<NamespaceAction>,
}
impl ProvisionIntent {
    pub fn ceremony(&self) -> &Id32 {
        &self.ceremony
    }
    pub fn slot(&self) -> u16 {
        self.slot
    }
    pub fn relay(&self) -> u16 {
        self.relay
    }
    pub fn purpose(&self) -> u16 {
        self.purpose
    }
    pub fn mailbox(&self) -> &Id32 {
        &self.mailbox
    }
    pub fn request(&self) -> &[u8] {
        &self.request
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn retire(&self) -> bool {
        self.retire
    }
    pub fn quota(&self) -> u64 {
        self.quota
    }
}
const SCHEMA: &str = include_str!("schema.sql");
const TERMINAL_NOTICES: &str = include_str!("terminal_notices.sql");
/// Databases made before vaults grew past 4 members (user_version 0 and 1) bound member
/// counts and slots at 4. Each pair is (narrow, wide) and appears in exactly one table.
const WIDENED: [(&str, &str); 3] = [
    (
        "CHECK(member_count IN(3,4))",
        "CHECK(member_count BETWEEN 3 AND 16)",
    ),
    (
        "CHECK(slot BETWEEN 2 AND 4)",
        "CHECK(slot BETWEEN 2 AND 16)",
    ),
    (
        "CHECK(slot BETWEEN 1 AND 4)",
        "CHECK(slot BETWEEN 1 AND 16)",
    ),
];
const SCHEMA_VERSION: u64 = 3;
// State 0 is legacy: the relay may already hold permanent data for these mailboxes.
const RESERVATIONS: &str = "
ALTER TABLE mailboxes ADD COLUMN payment_state INTEGER NOT NULL DEFAULT 0 CHECK(payment_state BETWEEN 0 AND 2);
ALTER TABLE operations ADD COLUMN slot INTEGER NOT NULL DEFAULT 0 CHECK(slot BETWEEN 0 AND 16);
CREATE INDEX operations_ceremony_slot ON operations(ceremony,slot);
CREATE INDEX mailboxes_payment_relay ON mailboxes(relay,payment_state) WHERE purpose=2 AND retired=0;
";

fn narrow_schema() -> String {
    WIDENED
        .iter()
        .fold(SCHEMA.to_owned(), |schema, (narrow, wide)| {
            schema.replace(wide, narrow)
        })
}

/// Widen the version-1 CHECK constraints in place. Every saved row already satisfies the
/// wider bound, so only the schema text changes (SQLite's documented `writable_schema`
/// procedure for constraint changes); integrity is checked before committing.
fn widen_checks(tx: &Transaction<'_>) -> Result<()> {
    let version: i64 = tx.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
    tx.execute_batch("PRAGMA writable_schema=ON;")?;
    for (narrow, wide) in WIDENED {
        let changed = tx.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?1,?2) WHERE type='table' AND instr(sql,?1)>0",
            params![narrow, wide],
        )?;
        if changed != 1 {
            return Err(Error::Storage);
        }
    }
    tx.execute_batch(&format!(
        "PRAGMA schema_version={}; PRAGMA writable_schema=RESET;",
        version + 1
    ))?;
    let integrity: String = tx.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(Error::Storage);
    }
    Ok(())
}
pub struct AdmissionStore {
    connection: Connection,
    enrollment: EnrollmentVerifier,
    signer: SigningKey,
    config: Id32,
    claim_seconds: u64,
    ceremony_seconds: u64,
    storage_bytes: u64,
    retry_min: u64,
    retry_max: u64,
    request_seconds: u64,
}
pub(crate) struct Reply {
    pub bytes: Vec<u8>,
    pub error: Option<Error>,
}
fn n(value: u64) -> Value {
    Value::Integer(value.into())
}
fn b(id: &Id32) -> Value {
    Value::Bytes(id.to_vec())
}
fn error_from_code(code: &str) -> Result<Error> {
    Ok(match code {
        "enrollment" => Error::Enrollment,
        "identity" => Error::Identity,
        "conflict" => Error::Conflict,
        "expired" => Error::Expired,
        "terminal" => Error::Terminal,
        "quota" => Error::Quota,
        "malformed" => Error::Malformed,
        "storage" => Error::Storage,
        "unavailable" => Error::Unavailable,
        _ => return Err(Error::Storage),
    })
}
fn schema_catalog(connection: &Connection) -> Result<Vec<(String, String)>> {
    let mut q = connection.prepare(
        "SELECT name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY name",
    )?;
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}
pub(crate) fn parse_package(package: &[u8]) -> Result<AdmissionRequest> {
    let value = canonical::decode(package, admission::MAX_REQUEST)?;
    let Value::Array(f) = value else {
        return Err(Error::Malformed);
    };
    let [Value::Bytes(body), Value::Bytes(signature)] = f.as_slice() else {
        return Err(Error::Malformed);
    };
    if signature.len() != 64 {
        return Err(Error::Identity);
    }
    let request = admission::decode_request(body)?;
    VerifyingKey::from_bytes(&request.device.signing)?.verify_strict(
        &signature_input(admission::REQUEST_DOMAIN, body)?,
        &Signature::from_slice(signature)?,
    )?;
    Ok(request)
}
fn response(
    signer: &SigningKey,
    request: &AdmissionRequest,
    digest: Id32,
    result: std::result::Result<Value, Error>,
) -> Result<Reply> {
    let error = result.as_ref().err().copied();
    let result = match result {
        Ok(value) => Value::Array(vec![n(1), value]),
        Err(error) => Value::Array(vec![n(0), Value::Text(error.code().into())]),
    };
    let body = canonical::encode(&Value::Array(vec![
        n(1),
        b(&request.operation),
        b(&digest),
        result,
    ]))?;
    let signature = signer.sign(&signature_input(admission::RESPONSE_DOMAIN, &body)?);
    Ok(Reply {
        bytes: canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))?,
        error,
    })
}
impl AdmissionStore {
    pub fn open(
        root: &Path,
        operators: &OperatorSet,
        enrollment: EnrollmentVerifier,
        signer: SigningKey,
    ) -> Result<Self> {
        if root.canonicalize()? != root || !fs::symlink_metadata(root)?.is_dir() {
            return Err(Error::Storage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let md = fs::symlink_metadata(root)?;
            if md.permissions().mode() & 0o777 != 0o700 {
                return Err(Error::Storage);
            }
            for name in [
                "admission.sqlite",
                "admission.sqlite-wal",
                "admission.sqlite-shm",
            ] {
                let path = root.join(name);
                if let Ok(file) = fs::symlink_metadata(path) {
                    if !file.is_file()
                        || file.uid() != md.uid()
                        || file.permissions().mode() & 0o077 != 0
                    {
                        return Err(Error::Storage);
                    }
                }
            }
        }
        if signer.verifying_key().to_bytes() != *operators.admission_key() {
            return Err(Error::Identity);
        }
        let path = root.join("admission.sqlite");
        let fresh = !path.exists();
        if fresh {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => file.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.into()),
            }
        }
        let mut connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let initialize = version == 0
            && tx.query_row(
                "SELECT NOT EXISTS (SELECT 1 FROM sqlite_schema)
                 AND (SELECT application_id FROM pragma_application_id)=0
                 AND (SELECT schema_version FROM pragma_schema_version)=0",
                [],
                |row| row.get::<_, bool>(0),
            )?;
        if initialize {
            tx.execute_batch(SCHEMA)?;
            tx.execute_batch(TERMINAL_NOTICES)?;
            tx.execute_batch(RESERVATIONS)?;
            tx.execute_batch(&format!("PRAGMA user_version={SCHEMA_VERSION};"))?;
            tx.execute(
                "INSERT INTO metadata VALUES(1,?1,?2)",
                params![
                    operators.digest().as_slice(),
                    operators.admission_key().as_slice()
                ],
            )?;
        } else {
            let catalog = Connection::open_in_memory()?;
            catalog.execute_batch(&narrow_schema())?;
            let legacy_catalog = schema_catalog(&catalog)?;
            catalog.execute_batch(TERMINAL_NOTICES)?;
            let narrow_catalog = schema_catalog(&catalog)?;
            let current = Connection::open_in_memory()?;
            current.execute_batch(SCHEMA)?;
            current.execute_batch(TERMINAL_NOTICES)?;
            let wide_catalog = schema_catalog(&current)?;
            current.execute_batch(RESERVATIONS)?;
            let current_catalog = schema_catalog(&current)?;
            let found = schema_catalog(&tx)?;
            let found_version = if found == legacy_catalog {
                0
            } else if found == narrow_catalog {
                1
            } else if found == wide_catalog {
                2
            } else if found == current_catalog {
                SCHEMA_VERSION
            } else {
                return Err(Error::Storage);
            };
            if version != found_version {
                return Err(Error::Storage);
            }
            let metadata: (Vec<u8>, Vec<u8>) = tx.query_row(
                "SELECT config,signer FROM metadata WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if metadata.0 != operators.digest() || metadata.1 != operators.admission_key() {
                return Err(Error::Storage);
            }
            if version == 0 {
                tx.execute_batch(TERMINAL_NOTICES)?;
            }
            if version < 2 {
                widen_checks(&tx)?;
            }
            if version < SCHEMA_VERSION {
                tx.execute_batch(RESERVATIONS)?;
                tx.execute_batch(&format!("PRAGMA user_version={SCHEMA_VERSION};"))?;
                if schema_catalog(&tx)? != current_catalog {
                    return Err(Error::Storage);
                }
            }
        }
        tx.commit()?;
        if initialize {
            fs::File::open(root)?.sync_all()?;
        }
        Ok(Self {
            connection,
            enrollment,
            signer,
            config: *operators.digest(),
            claim_seconds: operators.limits().first_claim_seconds,
            ceremony_seconds: operators.limits().ceremony_seconds,
            storage_bytes: operators.limits().storage_bytes_per_relay,
            retry_min: operators.limits().retry_min_seconds,
            retry_max: operators.limits().retry_max_seconds,
            request_seconds: operators.limits().request_seconds,
        })
    }
    pub fn request_seconds(&self) -> u64 {
        self.request_seconds
    }
    pub fn apply(
        &mut self,
        package: &[u8],
        credential: Option<&[u8]>,
        now: u64,
    ) -> Result<Vec<u8>> {
        let reply = self.execute(package, credential, || Ok(now))?;
        match reply.error {
            Some(error) => Err(error),
            None => Ok(reply.bytes),
        }
    }
    pub(crate) fn execute(
        &mut self,
        package: &[u8],
        credential: Option<&[u8]>,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<Reply> {
        if credential.is_some_and(|c| c.len() > 4096) {
            return Err(Error::Malformed);
        }
        let request = parse_package(package)?;
        let digest: Id32 = Sha256::digest(package).into();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((old, saved_response, error)) = tx
            .query_row(
                "SELECT digest,response,error FROM operations WHERE id=?1",
                [request.operation.as_slice()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if old != digest {
                return response(&self.signer, &request, digest, Err(Error::Conflict));
            }
            return Ok(Reply {
                bytes: saved_response,
                error: error.as_deref().map(error_from_code).transpose()?,
            });
        }
        let now = clock()?;
        if now > i64::MAX as u64 {
            return Err(Error::Malformed);
        }
        let changes = tx.total_changes();
        let result = apply_command(
            &tx,
            &request,
            package,
            credential,
            now,
            &self.enrollment,
            self.config,
            self.claim_seconds,
            self.ceremony_seconds,
            self.storage_bytes,
        );
        if matches!(
            result,
            Err(Error::Storage | Error::StorageBusy | Error::Unavailable)
        ) {
            return Err(result.err().ok_or(Error::Storage)?);
        }
        // Only committed transitions need exact replay. Notices are already stored by slot.
        let should_save = tx.total_changes() != changes
            && (result.is_ok()
                || matches!(
                    (&request.command, &result),
                    (Command::Checkpoint { .. }, Err(Error::Conflict))
                ))
            && !matches!(
                request.command,
                Command::State { .. } | Command::TerminalNotice { .. }
            );
        let reply = response(&self.signer, &request, digest, result)?;
        if should_save {
            // Checkpoints are the only repeatable transition. Leave room for every
            // bounded transition (claims, routes, terminal votes), regardless of this cap.
            if matches!(request.command, Command::Checkpoint { .. }) && reply.error.is_none() {
                let count: u64 = tx.query_row(
                    "SELECT count(*) FROM operations WHERE ceremony=?1 AND slot=?2",
                    params![request.command.ceremony().as_slice(), request.device.id],
                    |r| r.get(0),
                )?;
                if count >= 256 {
                    return response(&self.signer, &request, digest, Err(Error::Quota));
                }
            }
            tx.execute(
                "INSERT INTO operations(id,ceremony,digest,response,error,slot) VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    request.operation.as_slice(),
                    request.command.ceremony().as_slice(),
                    digest.as_slice(),
                    &reply.bytes,
                    reply.error.map(Error::code),
                    request.device.id,
                ],
            )?;
        }
        tx.commit()?;
        Ok(reply)
    }
    pub fn pending(&self, now: u64, limit: usize) -> Result<Vec<ProvisionIntent>> {
        self.pending_kind(now, limit, false, 1)
    }
    pub fn pending_retirement(&self, now: u64, limit: usize) -> Result<Vec<ProvisionIntent>> {
        self.pending_kind(now, limit, true, 1)
    }
    pub(crate) fn pending_kind(
        &self,
        now: u64,
        limit: usize,
        retire: bool,
        first_relay: usize,
    ) -> Result<Vec<ProvisionIntent>> {
        if now > i64::MAX as u64 || !(1..=3).contains(&limit) {
            return Err(Error::Malformed);
        }
        let condition = if retire {
            // A deadline observed outside the write transaction is not a decision.
            "m.retired=0 AND ((m.purpose=1 AND c.terminal!=0)
              OR (m.payment_state=1 AND c.terminal IN(1,3,4)))"
        } else {
            "m.retired=0 AND ((c.terminal=0 AND c.deadline>?1 AND m.provisioned=0)
              OR (c.terminal=2 AND m.purpose=2 AND (m.provisioned=0 OR m.payment_state=1)))"
        };
        // Take the oldest due row on each relay before considering a second row there.
        let sql = format!(
            "SELECT m.ceremony,m.slot,m.relay,m.purpose,m.mailbox,m.request,m.quota,c.deadline,m.payment_state,c.terminal
             FROM mailboxes m JOIN ceremonies c ON c.id=m.ceremony
             WHERE m.next_retry<=?1 AND ({condition})
             ORDER BY row_number() OVER(PARTITION BY m.relay
                 ORDER BY m.next_retry,m.ceremony,m.slot,m.purpose), (m.relay+3-?3)%3
             LIMIT ?2"
        );
        let mut query = self.connection.prepare(&sql)?;
        let rows = query.query_map(params![now, limit, first_relay], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u16>(1)?,
                r.get::<_, u16>(2)?,
                r.get::<_, u16>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, u64>(6)?,
                r.get::<_, u64>(7)?,
                r.get::<_, u16>(8)?,
                r.get::<_, u16>(9)?,
            ))
        })?;
        rows.map(|row| {
            let (
                ceremony,
                slot,
                relay,
                purpose,
                mailbox,
                request,
                quota,
                expires,
                payment,
                terminal,
            ) = row?;
            let action = match (purpose, payment, retire, terminal) {
                (1, _, true, _) => Some(NamespaceAction::RetireSetup),
                (1, _, false, _) => Some(NamespaceAction::ReserveSetup),
                (2, 1, true, _) => Some(NamespaceAction::RetirePayment),
                (2, 1, false, 2) => Some(NamespaceAction::PromotePayment),
                (2, 1, false, _) => Some(NamespaceAction::ReservePayment),
                _ => None,
            };
            Ok(ProvisionIntent {
                ceremony: ceremony.try_into().map_err(|_| Error::Storage)?,
                slot,
                relay,
                purpose,
                mailbox: mailbox.try_into().map_err(|_| Error::Storage)?,
                request,
                quota,
                expires,
                retire,
                action,
            })
        })
        .collect()
    }
    pub(crate) fn finish_provision(
        &mut self,
        intent: &ProvisionIntent,
        success: bool,
        now: u64,
    ) -> Result<()> {
        if now > i64::MAX as u64 - 60 {
            return Err(Error::Malformed);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (request,attempts):(Vec<u8>,u64)=tx.query_row("SELECT request,attempts FROM mailboxes WHERE ceremony=?1 AND slot=?2 AND relay=?3 AND purpose=?4 AND mailbox=?5",params![intent.ceremony.as_slice(),intent.slot,intent.relay,intent.purpose,intent.mailbox.as_slice()],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if request != intent.request {
            return Err(Error::Conflict);
        }
        let attempts = attempts.saturating_add(1).min(i64::MAX as u64);
        let mut sample = [0; 8];
        getrandom::fill(&mut sample).map_err(|_| Error::Unavailable)?;
        let delay = retry_delay(
            self.retry_min,
            self.retry_max,
            attempts,
            u64::from_be_bytes(sample),
        );
        let retired = success && intent.retire;
        let promoted = success && intent.action == Some(NamespaceAction::PromotePayment);
        let changed = tx.execute("UPDATE mailboxes SET provisioned=max(provisioned,?1),attempts=?2,next_retry=?3,retired=?8,payment_state=CASE WHEN ?9 THEN 2 ELSE payment_state END WHERE ceremony=?4 AND slot=?5 AND relay=?6 AND purpose=?7 AND retired=0",params![success && !intent.retire,attempts,now+delay,intent.ceremony.as_slice(),intent.slot,intent.relay,intent.purpose,retired,promoted])?;
        if retired && changed == 1 {
            tx.execute(
                "UPDATE grants SET mailboxes=mailboxes-1 WHERE id=(SELECT grant_id FROM ceremonies WHERE id=?1 AND terminal IN(1,3,4))",
                [intent.ceremony.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn cleanup(&mut self, now: u64) -> Result<usize> {
        if now > i64::MAX as u64 {
            return Err(Error::Malformed);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count = tx.execute(
            "UPDATE ceremonies SET terminal=4 WHERE terminal=0 AND deadline<=?1",
            [now],
        )?;
        tx.commit()?;
        Ok(count)
    }
}
fn owned(tx: &Transaction<'_>, ceremony: &Id32, device: &MemberPublic) -> Result<()> {
    let expected: Option<(Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT signing,encryption FROM claims WHERE ceremony=?1 AND slot=?2",
            params![ceremony.as_slice(), device.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if expected != Some((device.signing.to_vec(), device.encryption.to_vec())) {
        return Err(Error::Identity);
    }
    Ok(())
}
fn apply_command(
    tx: &Transaction<'_>,
    request: &AdmissionRequest,
    package: &[u8],
    credential: Option<&[u8]>,
    now: u64,
    enrollment: &EnrollmentVerifier,
    config: Id32,
    claim_seconds: u64,
    ceremony_seconds: u64,
    storage_bytes: u64,
) -> Result<Value> {
    let ceremony = request.command.ceremony();
    if let Command::Create {
        network,
        member_count,
        config_digest,
        grant_digest,
        invite_hashes,
        ..
    } = &request.command
    {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM ceremonies WHERE id=?1)",
            [ceremony.as_slice()],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error::Conflict);
        }
        let credential = credential.ok_or(Error::Enrollment)?;
        let budget = enrollment.verify(credential, &request.device.signing, now)?;
        if *config_digest != config
            || budget.config_digest() != &config
            || budget.grant_digest() != grant_digest
        {
            return Err(Error::Enrollment);
        }
        let prior: Option<(Vec<u8>, u64, u64)> = tx
            .query_row(
                "SELECT digest,creations,max_creations FROM grants WHERE id=?1",
                [budget.grant_id().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((digest, created, maximum)) = prior {
            if digest != *budget.grant_digest() {
                return Err(Error::Conflict);
            }
            if created >= maximum {
                return Err(Error::Quota);
            }
        }
        let claim_deadline = now
            .checked_add(claim_seconds)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Malformed)?;
        let deadline = now
            .checked_add(ceremony_seconds)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Malformed)?;
        tx.execute(
            "INSERT OR IGNORE INTO grants VALUES(?1,?2,0,0,?3,?4)",
            params![
                budget.grant_id().as_slice(),
                budget.grant_digest().as_slice(),
                budget.max_creations(),
                budget.mailbox_budget()
            ],
        )?;
        tx.execute(
            "INSERT INTO ceremonies VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![
                ceremony.as_slice(),
                network,
                member_count,
                budget.grant_id().as_slice(),
                claim_deadline,
                deadline
            ],
        )?;
        for (i, hash) in invite_hashes.iter().enumerate() {
            tx.execute(
                "INSERT INTO invitations VALUES(?1,?2,?3)",
                params![ceremony.as_slice(), i as u16 + 2, hash.as_slice()],
            )?;
        }
        tx.execute(
            "INSERT INTO claims VALUES(?1,1,?2,?3)",
            params![
                ceremony.as_slice(),
                request.device.signing.as_slice(),
                request.device.encryption.as_slice()
            ],
        )?;
        tx.execute(
            "UPDATE grants SET creations=creations+1 WHERE id=?1",
            [budget.grant_id().as_slice()],
        )?;
        return Ok(Value::Array(vec![n(claim_deadline), n(deadline)]));
    }
    let state:Option<(u16,u64,u64,u16,Vec<u8>)>=tx.query_row("SELECT member_count,claim_deadline,deadline,terminal,grant_id FROM ceremonies WHERE id=?1",[ceremony.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    let (member_count, claim_deadline, deadline, mut terminal, grant_id) =
        state.ok_or(Error::Identity)?;
    if matches!(
        request.command,
        Command::State { .. } | Command::TerminalNotice { .. }
    ) {
        if terminal == 0 && now >= deadline {
            tx.execute(
                "UPDATE ceremonies SET terminal=4 WHERE id=?1",
                [ceremony.as_slice()],
            )?;
            terminal = 4;
        }
    } else {
        if terminal != 0 {
            return Err(Error::Terminal);
        }
        if now >= deadline {
            tx.execute(
                "UPDATE ceremonies SET terminal=4 WHERE id=?1",
                [ceremony.as_slice()],
            )?;
            return Err(Error::Expired);
        }
    }
    match &request.command {
        Command::Claim {
            slot, invite_hash, ..
        } => {
            if *slot > member_count {
                return Err(Error::Identity);
            }
            let hash: Vec<u8> = tx.query_row(
                "SELECT hash FROM invitations WHERE ceremony=?1 AND slot=?2",
                params![ceremony.as_slice(), slot],
                |r| r.get(0),
            )?;
            if hash != *invite_hash
                || credential
                    .map(|c| Sha256::digest(c).as_slice() != invite_hash)
                    .unwrap_or(true)
            {
                return Err(Error::Identity);
            }
            let claimed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM claims WHERE ceremony=?1 AND slot=?2)",
                params![ceremony.as_slice(), slot],
                |r| r.get(0),
            )?;
            if claimed {
                owned(tx, ceremony, &request.device).map_err(|_| Error::Conflict)?;
                return Ok(n(*slot as u64));
            }
            if now >= claim_deadline {
                return Err(Error::Expired);
            }
            let duplicate:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM claims WHERE ceremony=?1 AND (signing=?2 OR encryption=?3))",params![ceremony.as_slice(),request.device.signing.as_slice(),request.device.encryption.as_slice()],|r|r.get(0))?;
            if duplicate {
                return Err(Error::Conflict);
            }
            tx.execute(
                "INSERT INTO claims VALUES(?1,?2,?3,?4)",
                params![
                    ceremony.as_slice(),
                    slot,
                    request.device.signing.as_slice(),
                    request.device.encryption.as_slice()
                ],
            )?;
            Ok(n(*slot as u64))
        }
        Command::Mailbox {
            slot,
            relay,
            purpose,
            mailbox,
            creation,
            ..
        } => {
            owned(tx, ceremony, &request.device)?;
            let existing:Option<(Vec<u8>,Vec<u8>)>=tx.query_row("SELECT mailbox,request FROM mailboxes WHERE ceremony=?1 AND slot=?2 AND relay=?3 AND purpose=?4",params![ceremony.as_slice(),slot,relay,purpose],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            if let Some((id, bytes)) = existing {
                if id != *mailbox || bytes != *creation {
                    return Err(Error::Conflict);
                }
                return Ok(b(mailbox));
            }
            let duplicate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE relay=?1 AND mailbox=?2)",
                params![relay, mailbox.as_slice()],
                |r| r.get(0),
            )?;
            if duplicate {
                return Err(Error::Conflict);
            }
            let (used, budget): (u64, u64) = tx.query_row(
                "SELECT mailboxes,max_mailboxes FROM grants WHERE id=?1",
                [&grant_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if used >= budget {
                return Err(Error::Quota);
            }
            let c = http::decode_creation(creation)?;
            let reserved: u64 = if *purpose == 1 {
                tx.query_row("SELECT COALESCE(sum(quota),0) FROM mailboxes WHERE ceremony=?1 AND relay=?2 AND purpose=1",params![ceremony.as_slice(),relay],|r|r.get(0))?
            } else {
                tx.query_row("SELECT COALESCE(sum(m.quota),0) FROM mailboxes m JOIN ceremonies c ON c.id=m.ceremony WHERE c.grant_id=?1 AND m.relay=?2 AND m.purpose=2 AND m.retired=0 AND (m.payment_state=1 OR m.ceremony=?3)",params![grant_id,relay,ceremony.as_slice()],|r|r.get(0))?
            };
            if reserved.saturating_add(c.quota) > storage_bytes {
                return Err(Error::Quota);
            }
            tx.execute(
                "INSERT INTO mailboxes(ceremony,slot,relay,purpose,mailbox,request,quota,payment_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    ceremony.as_slice(),
                    slot,
                    relay,
                    purpose,
                    mailbox.as_slice(),
                    creation,
                    c.quota,
                    *purpose == 2,
                ],
            )?;
            tx.execute(
                "UPDATE grants SET mailboxes=mailboxes+1 WHERE id=?1",
                [&grant_id],
            )?;
            Ok(b(mailbox))
        }
        Command::Checkpoint {
            slot,
            generation,
            predecessor,
            checkpoint,
            ..
        } => {
            owned(tx, ceremony, &request.device)?;
            let previous:Option<(u64,Vec<u8>,Vec<u8>)>=tx.query_row("SELECT generation,predecessor,digest FROM checkpoints WHERE ceremony=?1 AND slot=?2",params![ceremony.as_slice(),slot],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let valid = match &previous {
                None => *generation == 1 && *predecessor == [0; 32],
                Some((old, pred, digest)) => {
                    if *old == *generation {
                        if *pred == *predecessor && *digest == *checkpoint {
                            return Ok(Value::Array(vec![n(*generation), b(checkpoint)]));
                        }
                        false
                    } else {
                        old.checked_add(1) == Some(*generation) && *digest == *predecessor
                    }
                }
            };
            if !valid {
                tx.execute(
                    "UPDATE ceremonies SET terminal=3 WHERE id=?1",
                    [ceremony.as_slice()],
                )?;
                return Err(Error::Conflict);
            }
            tx.execute("INSERT INTO checkpoints VALUES(?1,?2,?3,?4,?5) ON CONFLICT(ceremony,slot) DO UPDATE SET generation=excluded.generation,predecessor=excluded.predecessor,digest=excluded.digest",params![ceremony.as_slice(),slot,generation,predecessor.as_slice(),checkpoint.as_slice()])?;
            Ok(Value::Array(vec![n(*generation), b(checkpoint)]))
        }
        Command::TerminalNotice { kind, .. } => {
            owned(tx, ceremony, &request.device)?;
            if *kind != 0 {
                if *kind != terminal || package.len() > 1024 {
                    return Err(Error::Terminal);
                }
                tx.execute(
                    "INSERT OR IGNORE INTO terminal_notices VALUES(?1,?2,?3,?4)",
                    params![ceremony.as_slice(), request.device.id, kind, package],
                )?;
            }
            let mut q = tx.prepare(
                "SELECT request FROM terminal_notices WHERE ceremony=?1 AND kind=?2 ORDER BY slot",
            )?;
            let notices = q
                .query_map(params![ceremony.as_slice(), terminal], |r| {
                    Ok(Value::Bytes(r.get(0)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(Value::Array(vec![
                n(terminal as u64),
                Value::Array(notices),
            ]))
        }
        Command::Terminal { kind, .. } => {
            owned(tx, ceremony, &request.device)?;
            if package.len() > 1024 {
                return Err(Error::Malformed);
            }
            if *kind == 1 {
                tx.execute(
                    "INSERT OR IGNORE INTO terminal_notices VALUES(?1,?2,?3,?4)",
                    params![ceremony.as_slice(), request.device.id, kind, package],
                )?;

                tx.execute(
                    "UPDATE ceremonies SET terminal=1 WHERE id=?1",
                    [ceremony.as_slice()],
                )?;
                return Ok(n(1));
            }
            let mut q = tx.prepare("SELECT slot FROM claims WHERE ceremony=?1 ORDER BY slot")?;
            let slots = q
                .query_map([ceremony.as_slice()], |r| r.get::<_, u16>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if slots.len() != member_count as usize {
                return Err(Error::Conflict);
            }
            let common:u64=tx.query_row("SELECT count(*) FROM (SELECT relay FROM mailboxes WHERE ceremony=?1 AND purpose=2 AND provisioned=1 GROUP BY relay HAVING count(*)=?2)",params![ceremony.as_slice(),member_count],|r|r.get(0))?;
            if common < 2 {
                return Err(Error::Unavailable);
            }
            tx.execute(
                "INSERT OR IGNORE INTO terminal_notices VALUES(?1,?2,?3,?4)",
                params![ceremony.as_slice(), request.device.id, kind, package],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO activation_votes VALUES(?1,?2)",
                params![ceremony.as_slice(), request.device.id],
            )?;
            let count: u64 = tx.query_row(
                "SELECT count(*) FROM activation_votes WHERE ceremony=?1",
                [ceremony.as_slice()],
                |r| r.get(0),
            )?;
            if count == member_count as u64 {
                tx.execute(
                    "UPDATE ceremonies SET terminal=2 WHERE id=?1",
                    [ceremony.as_slice()],
                )?;
                tx.execute(
                    "UPDATE mailboxes SET next_retry=0 WHERE ceremony=?1 AND payment_state=1",
                    [ceremony.as_slice()],
                )?;
            }
            Ok(n(count))
        }
        Command::State { slot, .. } => {
            owned(tx, ceremony, &request.device)?;
            let mut q = tx.prepare(
                "SELECT slot,signing,encryption FROM claims WHERE ceremony=?1 ORDER BY slot",
            )?;
            let claims = q
                .query_map([ceremony.as_slice()], |r| {
                    Ok(Value::Array(vec![
                        n(r.get::<_, u64>(0)?),
                        Value::Bytes(r.get(1)?),
                        Value::Bytes(r.get(2)?),
                    ]))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut q=tx.prepare("SELECT relay,purpose,mailbox,provisioned,retired FROM mailboxes WHERE ceremony=?1 AND slot=?2 ORDER BY relay,purpose")?;
            let mailboxes = q
                .query_map(params![ceremony.as_slice(), slot], |r| {
                    Ok(Value::Array(vec![
                        n(r.get::<_, u64>(0)?),
                        n(r.get::<_, u64>(1)?),
                        Value::Bytes(r.get(2)?),
                        n(r.get::<_, u64>(3)?),
                        n(r.get::<_, u64>(4)?),
                    ]))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let cp:Option<(u64,Vec<u8>,Vec<u8>)>=tx.query_row("SELECT generation,predecessor,digest FROM checkpoints WHERE ceremony=?1 AND slot=?2",params![ceremony.as_slice(),slot],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            Ok(Value::Array(vec![
                n(member_count as u64),
                n(claim_deadline),
                n(deadline),
                n(terminal as u64),
                Value::Array(claims),
                Value::Array(mailboxes),
                cp.map(|(generation, pred, digest)| {
                    Value::Array(vec![
                        n(generation),
                        Value::Bytes(pred),
                        Value::Bytes(digest),
                    ])
                })
                .unwrap_or(Value::Null),
            ]))
        }
        Command::Create { .. } => Err(Error::Malformed),
    }
}

fn retry_delay(min: u64, max: u64, attempts: u64, sample: u64) -> u64 {
    let ceiling = (1u64 << attempts.min(6)).max(min).min(max);
    min + sample % (ceiling - min + 1)
}
#[cfg(test)]
mod retry_tests {
    #[test]
    fn retry_jitter_stays_inside_signed_policy_and_changes_schedule() {
        assert_eq!(super::retry_delay(1, 60, 99, 0), 1);
        assert_eq!(super::retry_delay(1, 60, 99, 59), 60);
        for sample in [0, 1, 23, u64::MAX] {
            assert_eq!(super::retry_delay(60, 60, 1, sample), 60);
            let delay = super::retry_delay(3, 30, u64::MAX, sample);
            assert!((3..=30).contains(&delay));
        }
    }
}
