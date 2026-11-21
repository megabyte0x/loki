use crate::store::{
    admit_storage_growth, validate_schema, BoundSource, ClientStore, PendingDownload, StageResult,
};
use crate::{
    http, AuthenticatedDescriptor, AuthenticatedMessage, ClientConfig, ClientError, ClientResult, CommIdentity,
    CompleteSource, ConfigReference, RelayHttp, RootInspection, TransferAssembler,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    envelope,
    http::MAX_METADATA_LEN,
    types::{roster_digest, Id32, LogicalKey, MessageRef, Object, Page, RelayRoute, Roster},
    WireError,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const SAMPLE_ROWS: i64 = 1024;
const SAMPLE_BYTES: i64 = 8 * 1024 * 1024;
const SAMPLE_MAX: usize = 4096;

/// Stable journal and download-rejection codes. The text is the persisted reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineReason {
    Receipt,
    Length,
    Framing,
    Hash,
    Conflict,
}

impl QuarantineReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::Length => "length",
            Self::Framing => "framing",
            Self::Hash => "hash",
            Self::Conflict => "conflict",
        }
    }
}

impl fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Untrusted transport input for one advertised object. It is not an authentication proof.
#[derive(Clone, Eq, PartialEq)]
pub enum DownloadOutcome {
    Cached(Object),
    Missing(Id32),
    Rejected {
        hash: Id32,
        reason: QuarantineReason,
        sample: Vec<u8>,
    },
}

impl fmt::Debug for DownloadOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cached(object) => f.debug_struct("Cached").field("hash", &object.hash).finish(),
            Self::Missing(hash) => f.debug_tuple("Missing").field(hash).finish(),
            Self::Rejected { hash, reason, sample } => f
                .debug_struct("Rejected")
                .field("hash", hash)
                .field("reason", &reason.code())
                .field("sample_len", &sample.len())
                .finish(),
        }
    }
}

#[derive(Clone, Copy)]
enum Class<'a> {
    Cache(&'a [u8]),
    /// Ciphertext is already stored and checked. No new object bytes are written.
    Stored,
    Task,
    Tomb(QuarantineReason),
}

struct Draft<'a> {
    sequence: u64,
    hash: Id32,
    wire_length: u64,
    receipt: &'a [u8],
    sample: &'a [u8],
    class: Class<'a>,
}

struct Effect<'a> {
    hash: Id32,
    insert_wire: Option<&'a [u8]>,
    insert_task: Option<u64>,
}

fn framed_len(n: u64) -> bool {
    (1024..=65536).contains(&n) && n % 1024 == 0
}

fn prefix(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(SAMPLE_MAX)]
}

fn digest(wire: &[u8]) -> Id32 {
    Sha256::digest(wire).into()
}

fn persisted(n: u64) -> bool {
    n <= i64::MAX as u64
}

fn as_i64(n: u64) -> ClientResult<i64> {
    i64::try_from(n).map_err(|_| ClientError::Wire(WireError::Bounds))
}

/// Bad shape covers nothing. Invalid entry lengths stay in range so they can be journaled.
fn validate_shape(route: &RelayRoute, page: &Page) -> ClientResult<()> {
    if page.mailbox != route.mailbox {
        return Err(ClientError::Wire(WireError::Schema));
    }
    if !persisted(page.after) || !persisted(page.next) || !persisted(page.high_water) {
        return Err(ClientError::Wire(WireError::Bounds));
    }
    if page.entries.len() > 100 || page.after > page.high_water {
        return Err(ClientError::Wire(if page.entries.len() > 100 {
            WireError::Bounds
        } else {
            WireError::Schema
        }));
    }
    let mut previous = page.after;
    let mut receipts = 0usize;
    for entry in &page.entries {
        if entry.sequence == 0
            || !persisted(entry.sequence)
            || previous.checked_add(1) != Some(entry.sequence)
            || entry.sequence > page.high_water
            || !persisted(entry.wire_length)
            || entry.receipt.len() > MAX_METADATA_LEN
        {
            return Err(ClientError::Wire(if !persisted(entry.wire_length) || entry.receipt.len() > MAX_METADATA_LEN {
                WireError::Bounds
            } else {
                WireError::Schema
            }));
        }
        receipts = receipts.saturating_add(entry.receipt.len());
        if receipts > MAX_METADATA_LEN {
            return Err(ClientError::Wire(WireError::Bounds));
        }
        previous = entry.sequence;
    }
    if page.next != previous {
        return Err(ClientError::Wire(WireError::Schema));
    }
    let encoded = canonical::encode(&Value::Array(vec![
        Value::Integer(1u64.into()),
        Value::Bytes(page.mailbox.to_vec()),
        Value::Integer(page.after.into()),
        Value::Integer(page.next.into()),
        Value::Integer(page.high_water.into()),
        Value::Array(
            page.entries
                .iter()
                .map(|entry| {
                    Value::Array(vec![
                        Value::Integer(entry.sequence.into()),
                        Value::Bytes(entry.hash.to_vec()),
                        Value::Integer(entry.wire_length.into()),
                        Value::Bytes(entry.receipt.clone()),
                    ])
                })
                .collect(),
        ),
    ]))?;
    if encoded.len() > MAX_METADATA_LEN {
        return Err(ClientError::Wire(WireError::Bounds));
    }
    Ok(())
}

fn receipt_matches(route: &RelayRoute, page: &Page, index: usize) -> bool {
    let entry = &page.entries[index];
    let Ok(verified) = http::verify_saved_receipt(route, &entry.receipt, entry.hash, entry.wire_length) else {
        return false;
    };
    verified.body().sequence == entry.sequence
}

fn object_failure(object: &Object, hash: &Id32, wire_length: u64) -> Option<QuarantineReason> {
    // Untrusted download bytes are not hashed until the wire is inside the framed cap.
    if object.wire.len() > 65536 || object.wire.len() as u64 != wire_length || !framed_len(wire_length) {
        return Some(QuarantineReason::Length);
    }
    if object.hash != *hash || digest(&object.wire) != *hash {
        return Some(QuarantineReason::Hash);
    }
    if envelope::validate_wire(&object.wire).is_err() {
        return Some(QuarantineReason::Framing);
    }
    None
}

fn classify<'a>(route: &RelayRoute, page: &'a Page, downloads: &'a [DownloadOutcome]) -> Vec<Draft<'a>> {
    page.entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let sample = prefix(&entry.receipt);
            let class = if !framed_len(entry.wire_length) {
                Class::Tomb(QuarantineReason::Length)
            } else if !receipt_matches(route, page, index) {
                Class::Tomb(QuarantineReason::Receipt)
            } else {
                classify_outcomes(entry.hash, entry.wire_length, downloads)
            };
            Draft {
                sequence: entry.sequence,
                hash: entry.hash,
                wire_length: entry.wire_length,
                receipt: &entry.receipt,
                sample: match &class {
                    Class::Tomb(QuarantineReason::Receipt) | Class::Tomb(QuarantineReason::Length) => sample,
                    Class::Tomb(_) => sample,
                    _ => &[],
                },
                class,
            }
        })
        .collect()
}

fn classify_outcomes<'a>(
    hash: Id32,
    wire_length: u64,
    downloads: &'a [DownloadOutcome],
) -> Class<'a> {
    let mut caches: Vec<&[u8]> = Vec::new();
    let mut missing = false;
    let mut rejects: Vec<(QuarantineReason, &[u8])> = Vec::new();
    let mut cache_fail: Option<QuarantineReason> = None;
    for outcome in downloads {
        match outcome {
            DownloadOutcome::Missing(id) if *id == hash => missing = true,
            DownloadOutcome::Cached(object) if object.hash == hash => {
                match object_failure(object, &hash, wire_length) {
                    None => caches.push(object.wire.as_slice()),
                    Some(reason) => {
                        cache_fail = Some(match cache_fail {
                            Some(prior) if prior != reason => QuarantineReason::Conflict,
                            _ => reason,
                        });
                    }
                }
            }
            DownloadOutcome::Rejected { hash: id, reason, sample } if *id == hash => {
                rejects.push((*reason, prefix(sample)));
            }
            _ => {}
        }
    }
    let same_cache = caches.windows(2).all(|pair| pair[0] == pair[1]);
    if !missing && rejects.is_empty() && cache_fail.is_none() && !caches.is_empty() && same_cache {
        return Class::Cache(caches[0]);
    }
    // No outcome is a durable missing task. Absence must not skip the position.
    if caches.is_empty() && rejects.is_empty() && cache_fail.is_none() {
        return Class::Task;
    }
    if !missing && caches.is_empty() && cache_fail.is_none() && !rejects.is_empty()
        && rejects.iter().all(|item| item.0 == rejects[0].0)
    {
        return Class::Tomb(rejects[0].0);
    }
    if !missing && caches.is_empty() && rejects.is_empty() {
        return Class::Tomb(cache_fail.unwrap_or(QuarantineReason::Conflict));
    }
    Class::Tomb(QuarantineReason::Conflict)
}

fn rejected_sample<'a>(hash: &Id32, downloads: &'a [DownloadOutcome]) -> &'a [u8] {
    downloads
        .iter()
        .find_map(|outcome| match outcome {
            DownloadOutcome::Rejected { hash: id, sample, .. } if id == hash && !sample.is_empty() => {
                Some(prefix(sample))
            }
            _ => None,
        })
        .unwrap_or(&[])
}

fn merge_hash(drafts: &mut [Draft<'_>], indexes: &[usize]) {
    let mut cache: Option<&[u8]> = None;
    let mut cache_conflict = false;
    let mut task_len: Option<u64> = None;
    let mut task_conflict = false;
    for index in indexes {
        let draft = &drafts[*index];
        match draft.class {
            Class::Cache(wire) => match cache {
                None => cache = Some(wire),
                Some(prior) if prior == wire => {}
                Some(_) => cache_conflict = true,
            },
            Class::Task => match task_len {
                None => task_len = Some(draft.wire_length),
                Some(len) if len == draft.wire_length => {}
                Some(_) => task_conflict = true,
            },
            Class::Stored | Class::Tomb(_) => {}
        }
    }
    if !(cache_conflict || task_conflict || (cache.is_some() && task_len.is_some())) {
        return;
    }
    for index in indexes {
        if matches!(drafts[*index].class, Class::Cache(_) | Class::Task) {
            let receipt = drafts[*index].receipt;
            drafts[*index].class = Class::Tomb(QuarantineReason::Conflict);
            drafts[*index].sample = prefix(receipt);
        }
    }
}

fn attach_rejected_samples<'a>(drafts: &mut [Draft<'a>], downloads: &'a [DownloadOutcome]) {
    for draft in drafts {
        if matches!(draft.class, Class::Tomb(_)) {
            let sample = rejected_sample(&draft.hash, downloads);
            if !sample.is_empty() {
                draft.sample = sample;
            }
        }
    }
}

fn disposition(class: Class<'_>) -> &'static str {
    match class {
        Class::Cache(_) | Class::Stored => "cached",
        Class::Task => "missing",
        Class::Tomb(_) => "quarantine",
    }
}

fn reason(draft: &Draft<'_>) -> &'static str {
    match draft.class {
        Class::Cache(_) | Class::Stored => "cached",
        Class::Task => "missing",
        Class::Tomb(reason) => reason.code(),
    }
}

fn apply_existing<'a>(
    tx: &rusqlite::Connection,
    route: &RelayRoute,
    drafts: &mut [Draft<'a>],
    indexes: &[usize],
    hash: Id32,
) -> ClientResult<Effect<'a>> {
    let existing: Option<Vec<u8>> = tx
        .query_row(
            "SELECT wire FROM ciphertext_objects WHERE hash=?1",
            [hash],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(wire) = existing.as_deref() {
        if digest(wire) != hash {
            return Err(ClientError::Storage);
        }
        let usable = envelope::validate_wire(wire).is_ok() && framed_len(wire.len() as u64);
        for index in indexes {
            match drafts[*index].class {
                Class::Cache(planned) if planned == wire => drafts[*index].class = Class::Stored,
                Class::Cache(_) => {
                    let receipt = drafts[*index].receipt;
                    drafts[*index].class = Class::Tomb(QuarantineReason::Conflict);
                    drafts[*index].sample = prefix(receipt);
                }
                Class::Task if usable && drafts[*index].wire_length == wire.len() as u64 => {
                    drafts[*index].class = Class::Stored;
                    drafts[*index].sample = &[];
                }
                _ => {}
            }
        }
    }

    let task: Option<i64> = tx
        .query_row(
            "SELECT wire_length FROM pending_downloads WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
            params![route.pin.key, route.pin.run, route.mailbox, hash],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(len) = task {
        for index in indexes {
            if matches!(drafts[*index].class, Class::Task) && as_i64(drafts[*index].wire_length)? != len {
                let receipt = drafts[*index].receipt;
                drafts[*index].class = Class::Tomb(QuarantineReason::Conflict);
                drafts[*index].sample = prefix(receipt);
            }
        }
    }

    let insert_wire = indexes.iter().find_map(|index| match drafts[*index].class {
        Class::Cache(wire) => Some(wire),
        _ => None,
    });
    let insert_task = if task.is_some() {
        None
    } else {
        indexes.iter().find_map(|index| match drafts[*index].class {
            Class::Task => Some(drafts[*index].wire_length),
            _ => None,
        })
    };
    Ok(Effect { hash, insert_wire, insert_task })
}

fn journal_is_new(
    tx: &rusqlite::Connection,
    route: &RelayRoute,
    draft: &Draft<'_>,
) -> ClientResult<bool> {
    let prior: Option<(Vec<u8>, i64, Vec<u8>, String, String, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT source_hash, wire_length, receipt, disposition, reason, body_digest FROM incoming_journal WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND sequence=?4",
            params![route.pin.key, route.pin.run, route.mailbox, as_i64(draft.sequence)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()?;
    let Some((hash, wire_length, receipt, disposition_text, reason_text, body_digest)) = prior else {
        return Ok(true);
    };
    if hash.as_slice() == draft.hash.as_slice()
        && wire_length == as_i64(draft.wire_length)?
        && receipt == draft.receipt
        && disposition_text == disposition(draft.class)
        && reason_text == reason(draft)
        && body_digest.is_none()
    {
        return Ok(false);
    }
    Err(ClientError::Conflict)
}

fn sample_totals(tx: &rusqlite::Connection) -> ClientResult<(i64, i64, i64, i64)> {
    let (quarantine_count, quarantine_bytes): (i64, i64) = tx.query_row(
        "SELECT count(*), coalesce(sum(length(sample)), 0) FROM quarantine_samples",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (page_count, page_bytes): (i64, i64) = tx.query_row(
        "SELECT count(*), coalesce(sum(length(sample)), 0) FROM page_diagnostics",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((quarantine_count, quarantine_bytes, page_count, page_bytes))
}

fn sample_over_budget(quarantine: bool, len: i64, totals: (i64, i64, i64, i64)) -> bool {
    let (quarantine_count, quarantine_bytes, page_count, page_bytes) = totals;
    let shared_rows = quarantine_count.saturating_add(page_count) >= SAMPLE_ROWS;
    let shared_bytes = quarantine_bytes.saturating_add(page_bytes).saturating_add(len) > SAMPLE_BYTES;
    let own = quarantine
        && (quarantine_count >= SAMPLE_ROWS || quarantine_bytes.saturating_add(len) > SAMPLE_BYTES);
    shared_rows || shared_bytes || own
}

/// Both tables take ids from `diagnostic_ids`, so the smaller id is the older sample.
fn evict_oldest_sample(tx: &rusqlite::Connection) -> ClientResult<bool> {
    let quarantine_id: Option<i64> = tx
        .query_row(
            "SELECT id FROM quarantine_samples ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let page_id: Option<i64> = tx
        .query_row(
            "SELECT id FROM page_diagnostics ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match (quarantine_id, page_id) {
        (None, None) => Ok(false),
        (Some(quarantine), Some(page)) if page < quarantine => {
            tx.execute("DELETE FROM page_diagnostics WHERE id=?1", [page])?;
            Ok(true)
        }
        (Some(quarantine), _) => {
            tx.execute("DELETE FROM quarantine_samples WHERE id=?1", [quarantine])?;
            Ok(true)
        }
        (None, Some(page)) => {
            tx.execute("DELETE FROM page_diagnostics WHERE id=?1", [page])?;
            Ok(true)
        }
    }
}

fn fit_diagnostic(tx: &rusqlite::Connection, len: i64, quarantine: bool) -> ClientResult<()> {
    for _ in 0..SAMPLE_ROWS + 1 {
        if !sample_over_budget(quarantine, len, sample_totals(tx)?) {
            return Ok(());
        }
        if !evict_oldest_sample(tx)? {
            return Err(ClientError::Capacity);
        }
    }
    Err(ClientError::Capacity)
}

fn fit_sample(tx: &rusqlite::Connection, len: i64) -> ClientResult<()> {
    fit_diagnostic(tx, len, true)
}

/// Ids come from one counter, including ids already stored before catalog 6.
fn allocate_sample_id(tx: &rusqlite::Connection) -> ClientResult<i64> {
    let id: i64 = tx.query_row("SELECT next_id FROM diagnostic_ids WHERE singleton=1", [], |row| {
        row.get(0)
    })?;
    if id <= 0 {
        return Err(ClientError::Storage);
    }
    let next = id.checked_add(1).ok_or(ClientError::Capacity)?;
    let updated = tx.execute(
        "UPDATE diagnostic_ids SET next_id=?1 WHERE singleton=1 AND next_id=?2",
        params![next, id],
    )?;
    if updated != 1 {
        return Err(ClientError::Storage);
    }
    Ok(id)
}

fn sample_is_new(
    tx: &rusqlite::Connection,
    route: &RelayRoute,
    draft: &Draft<'_>,
) -> ClientResult<bool> {
    if draft.sample.is_empty() || !matches!(draft.class, Class::Tomb(_)) {
        return Ok(false);
    }
    let present: i64 = tx.query_row(
        "SELECT count(*) FROM quarantine_samples WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND sequence=?4 AND sample=?5",
        params![route.pin.key, route.pin.run, route.mailbox, as_i64(draft.sequence)?, draft.sample],
        |row| row.get(0),
    )?;
    Ok(present == 0)
}

impl ClientStore {
    /// Journals every covered position, then advances the route cursor in the same transaction.
    ///
    /// The cursor means durable transport capture. Saved ciphertext stays unauthenticated, and
    /// this transaction does not retire an earlier download task. An invalid receipt or
    /// advertised length remains a per-sequence journal tombstone. Existing download rejections
    /// stay untouched and do not replace a validated cache.
    pub fn capture_page(
        &mut self,
        route: &RelayRoute,
        page: &Page,
        downloads: &[DownloadOutcome],
    ) -> ClientResult<()> {
        if downloads.len() > 100 {
            return Err(ClientError::Wire(WireError::Bounds));
        }
        validate_shape(route, page)?;
        let mut drafts = classify(route, page, downloads);
        let groups = group_indexes(&drafts);
        for indexes in &groups {
            merge_hash(&mut drafts, indexes);
        }
        attach_rejected_samples(&mut drafts, downloads);

        let schema = self.schema();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&transaction, schema)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT position FROM route_cursors WHERE relay_key=?1 AND run=?2 AND mailbox=?3",
                params![route.pin.key, route.pin.run, route.mailbox],
                |row| row.get(0),
            )
            .optional()?;
        let position = current.unwrap_or(0);
        if position < 0 || as_i64(page.after)? != position {
            return Err(ClientError::Cursor);
        }

        let mut effects = Vec::with_capacity(groups.len());
        for indexes in &groups {
            let hash = drafts[indexes[0]].hash;
            effects.push(apply_existing(&transaction, route, &mut drafts, indexes, hash)?);
        }

        let mut grows = current.is_none() && page.next != page.after;
        let mut new_journal = Vec::with_capacity(drafts.len());
        for draft in &drafts {
            let fresh = journal_is_new(&transaction, route, draft)?;
            new_journal.push(fresh);
            grows |= fresh;
            if fresh {
                grows |= sample_is_new(&transaction, route, draft)?;
            }
        }
        for effect in &effects {
            grows |= effect.insert_wire.is_some() || effect.insert_task.is_some();
        }
        if grows {
            admit_storage_growth(&transaction, self.storage_budget)?;
        }

        for (draft, fresh) in drafts.iter().zip(&new_journal) {
            if !fresh {
                continue;
            }
            transaction.execute(
                "INSERT INTO incoming_journal VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL)",
                params![
                    route.pin.key,
                    route.pin.run,
                    route.mailbox,
                    as_i64(draft.sequence)?,
                    draft.hash,
                    as_i64(draft.wire_length)?,
                    draft.receipt,
                    disposition(draft.class),
                    reason(draft)
                ],
            )?;
        }
        for effect in &effects {
            if let Some(wire) = effect.insert_wire {
                let prior: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT wire FROM ciphertext_objects WHERE hash=?1",
                        [effect.hash],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(saved) = prior {
                    if saved.as_slice() != wire {
                        return Err(ClientError::Conflict);
                    }
                } else {
                    let inserted = transaction.execute(
                        "INSERT INTO ciphertext_objects VALUES(?1,?2,?3)",
                        params![effect.hash, wire, wire.len() as i64],
                    );
                    #[cfg(test)]
                    crate::store::incoming_crash_tests::observe_allocating_insert(&inserted);
                    inserted?;
                }
            }
            if let Some(len) = effect.insert_task {
                transaction.execute(
                    "INSERT INTO pending_downloads VALUES(?1,?2,?3,?4,?5,0,0)",
                    params![
                        route.pin.key,
                        route.pin.run,
                        route.mailbox,
                        effect.hash,
                        as_i64(len)?
                    ],
                )?;
            }
        }
        for (draft, fresh) in drafts.iter().zip(&new_journal) {
            if !fresh || !sample_is_new(&transaction, route, draft)? {
                continue;
            }
            fit_sample(&transaction, draft.sample.len() as i64)?;
            let sample_id = allocate_sample_id(&transaction)?;
            transaction.execute(
                "INSERT INTO quarantine_samples (id, relay_key, run, mailbox, sequence, sample) VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    sample_id,
                    route.pin.key,
                    route.pin.run,
                    route.mailbox,
                    as_i64(draft.sequence)?,
                    draft.sample
                ],
            )?;
        }
        if page.next != page.after {
            if current.is_none() {
                transaction.execute(
                    "INSERT INTO route_cursors VALUES(?1,?2,?3,?4)",
                    params![route.pin.key, route.pin.run, route.mailbox, as_i64(page.next)?],
                )?;
            } else {
                let updated = transaction.execute(
                    "UPDATE route_cursors SET position=?4 WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND position=?5",
                    params![
                        route.pin.key,
                        route.pin.run,
                        route.mailbox,
                        as_i64(page.next)?,
                        position
                    ],
                )?;
                if updated != 1 {
                    return Err(ClientError::Cursor);
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }
}

fn group_indexes(drafts: &[Draft<'_>]) -> Vec<Vec<usize>> {
    let mut order = Vec::new();
    for draft in drafts {
        if !order.contains(&draft.hash) {
            order.push(draft.hash);
        }
    }
    order
        .into_iter()
        .map(|hash| {
            drafts
                .iter()
                .enumerate()
                .filter(|(_, draft)| draft.hash == hash)
                .map(|(index, _)| index)
                .collect()
        })
        .collect()
}

fn wire_failure(wire: &[u8], hash: &Id32) -> Option<QuarantineReason> {
    if wire.len() > 65536 || !framed_len(wire.len() as u64) {
        return Some(QuarantineReason::Length);
    }
    if digest(wire) != *hash {
        return Some(QuarantineReason::Hash);
    }
    if envelope::validate_wire(wire).is_err() {
        return Some(QuarantineReason::Framing);
    }
    None
}

fn bind_capture_scope(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    config: &ClientConfig,
    self_route: &AuthenticatedDescriptor,
) -> ClientResult<()> {
    let public = identity.public();
    store.check_association(roster, public.id)?;
    if !roster.members.iter().any(|member| member == &public) {
        return Err(ClientError::Identity);
    }
    let body = self_route.body();
    if body.owner != public.id || body.vault != roster.vault || body.roster != roster_digest(roster)? {
        return Err(ClientError::Identity);
    }
    // The same three-route match upload uses. A foreign key or mailbox is not this store's inbox.
    if !crate::outbox::inboxes_match(&config.own, &body.relays) {
        return Err(ClientError::Config);
    }
    Ok(())
}

fn route_position(store: &ClientStore, route: &RelayRoute) -> ClientResult<u64> {
    let position: Option<i64> = store
        .connection
        .query_row(
            "SELECT position FROM route_cursors WHERE relay_key=?1 AND run=?2 AND mailbox=?3",
            params![route.pin.key, route.pin.run, route.mailbox],
            |row| row.get(0),
        )
        .optional()?;
    match position {
        None => Ok(0),
        Some(position) if position >= 0 => u64::try_from(position).map_err(|_| ClientError::Storage),
        Some(_) => Err(ClientError::Storage),
    }
}

fn clear_route_auth(store: &mut ClientStore, route: &RelayRoute, reference: &ConfigReference) -> ClientResult<()> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "UPDATE route_capture SET config_revision=NULL, config_hash=NULL WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND isolated=0 AND config_revision IS NOT NULL AND config_revision < ?4",
        params![route.pin.key, route.pin.run, route.mailbox, as_i64(reference.revision())?],
    )?;
    transaction.commit()?;
    Ok(())
}

fn route_due(store: &ClientStore, route: &RelayRoute, now_ms: u64, reference: &ConfigReference) -> ClientResult<bool> {
    let row: Option<(i64, i64, Option<i64>)> = store
        .connection
        .query_row(
            "SELECT retry_at, isolated, config_revision FROM route_capture WHERE relay_key=?1 AND run=?2 AND mailbox=?3",
            params![route.pin.key, route.pin.run, route.mailbox],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((retry_at, isolated, config_revision)) = row else {
        return Ok(true);
    };
    if isolated != 0 {
        return Ok(false);
    }
    if config_revision.is_some_and(|revision| reference.revision() <= revision as u64) {
        return Ok(false);
    }
    Ok(retry_at <= as_i64(now_ms)?)
}

fn isolate_route(store: &mut ClientStore, route: &RelayRoute, reason: &str) -> ClientResult<()> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let isolated: Option<i64> = transaction
        .query_row(
            "SELECT isolated FROM route_capture WHERE relay_key=?1 AND run=?2 AND mailbox=?3",
            params![route.pin.key, route.pin.run, route.mailbox],
            |row| row.get(0),
        )
        .optional()?;
    match isolated {
        Some(1) => {
            transaction.commit()?;
            Ok(())
        }
        Some(_) => {
            transaction.execute(
                "UPDATE route_capture SET isolated=1, reason=?4 WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND isolated=0",
                params![route.pin.key, route.pin.run, route.mailbox, reason],
            )?;
            transaction.commit()?;
            Ok(())
        }
        None => {
            admit_storage_growth(&transaction, store.storage_budget)?;
            transaction.execute(
                "INSERT INTO route_capture VALUES(?1,?2,?3,0,0,1,?4,NULL,NULL)",
                params![route.pin.key, route.pin.run, route.mailbox, reason],
            )?;
            transaction.commit()?;
            Ok(())
        }
    }
}

fn note_route_retry(store: &mut ClientStore, route: &RelayRoute, now_ms: u64, reason: &str) -> ClientResult<()> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(i64, i64)> = transaction
        .query_row(
            "SELECT attempts, isolated FROM route_capture WHERE relay_key=?1 AND run=?2 AND mailbox=?3",
            params![route.pin.key, route.pin.run, route.mailbox],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (attempts, delay_attempts) = if let Some((attempts, isolated)) = row {
        if isolated != 0 {
            transaction.commit()?;
            return Ok(());
        }
        let current = u64::try_from(attempts).map_err(|_| ClientError::Storage)?;
        let next = current
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .unwrap_or(current);
        (next, current)
    } else {
        (1, 0)
    };
    let retry_at = now_ms
        .checked_add(crate::retry::sample_delay(delay_attempts)?)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(ClientError::Capacity)?;
    admit_storage_growth(&transaction, store.storage_budget)?;
    if row.is_some() {
        transaction.execute(
            "UPDATE route_capture SET attempts=?4, retry_at=?5, reason=?6 WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND isolated=0",
            params![
                route.pin.key,
                route.pin.run,
                route.mailbox,
                attempts as i64,
                as_i64(retry_at)?,
                reason
            ],
        )?;
    } else {
        transaction.execute(
            "INSERT INTO route_capture VALUES(?1,?2,?3,?4,?5,0,?6,NULL,NULL)",
            params![
                route.pin.key,
                route.pin.run,
                route.mailbox,
                attempts as i64,
                as_i64(retry_at)?,
                reason
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn note_route_auth(store: &mut ClientStore, route: &RelayRoute, reference: &ConfigReference) -> ClientResult<()> {
    let revision = as_i64(reference.revision())?;
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(i64, Option<i64>, Option<Vec<u8>>)> = transaction
        .query_row(
            "SELECT isolated, config_revision, config_hash FROM route_capture WHERE relay_key=?1 AND run=?2 AND mailbox=?3",
            params![route.pin.key, route.pin.run, route.mailbox],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((isolated, config_revision, config_hash)) = row {
        if isolated != 0 {
            transaction.commit()?;
            return Ok(());
        }
        if config_revision == Some(revision) && config_hash.as_deref() == Some(reference.hash().as_slice()) {
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "UPDATE route_capture SET reason='identity', config_revision=?4, config_hash=?5 WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND isolated=0",
            params![route.pin.key, route.pin.run, route.mailbox, revision, reference.hash().as_slice()],
        )?;
        transaction.commit()?;
        return Ok(());
    }
    admit_storage_growth(&transaction, store.storage_budget)?;
    transaction.execute(
        "INSERT INTO route_capture VALUES(?1,?2,?3,0,0,0,'identity',?4,?5)",
        params![route.pin.key, route.pin.run, route.mailbox, revision, reference.hash().as_slice()],
    )?;
    transaction.commit()?;
    Ok(())
}

fn release_route(store: &mut ClientStore, route: &RelayRoute) -> ClientResult<()> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "UPDATE route_capture SET attempts=0, retry_at=0, reason=NULL, config_revision=NULL, config_hash=NULL WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND isolated=0 AND (attempts!=0 OR retry_at!=0 OR reason IS NOT NULL OR config_revision IS NOT NULL)",
        params![route.pin.key, route.pin.run, route.mailbox],
    )?;
    transaction.commit()?;
    Ok(())
}

fn save_page_sample(store: &mut ClientStore, route: &RelayRoute, sample: &[u8]) -> ClientResult<()> {
    let sample = prefix(sample);
    if sample.is_empty() {
        return Ok(());
    }
    let present: i64 = store.connection.query_row(
        "SELECT count(*) FROM page_diagnostics WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND sample=?4",
        params![route.pin.key, route.pin.run, route.mailbox, sample],
        |row| row.get(0),
    )?;
    if present > 0 {
        return Ok(());
    }
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    admit_storage_growth(&transaction, store.storage_budget)?;
    fit_diagnostic(&transaction, sample.len() as i64, false)?;
    let sample_id = allocate_sample_id(&transaction)?;
    transaction.execute(
        "INSERT INTO page_diagnostics (id, relay_key, run, mailbox, sample) VALUES(?1,?2,?3,?4,?5)",
        params![sample_id, route.pin.key, route.pin.run, route.mailbox, sample],
    )?;
    transaction.commit()?;
    Ok(())
}

fn record_route_failure(
    store: &mut ClientStore,
    route: &RelayRoute,
    now_ms: u64,
    reason: &str,
    sample: &[u8],
    isolate: bool,
) -> ClientResult<()> {
    if isolate {
        isolate_route(store, route, reason)?;
    } else {
        note_route_retry(store, route, now_ms, reason)?;
    }
    // The reason is already durable. A full sample budget must not roll it back.
    let _ = save_page_sample(store, route, sample);
    Ok(())
}

/// One transport pass. Store and owner association is checked once before any route or download work.
/// Each owned route is independent, and download completion does not move a cursor.
pub async fn poll_transport(
    store: &mut ClientStore,
    http: &RelayHttp,
    roster: &Roster,
    identity: &CommIdentity,
    config: &ClientConfig,
    self_route: &AuthenticatedDescriptor,
    now_ms: u64,
) -> ClientResult<()> {
    if now_ms > i64::MAX as u64 {
        return Err(ClientError::Capacity);
    }
    let Some(reference) = store.config_reference()? else {
        return Err(ClientError::Config);
    };
    bind_capture_scope(store, roster, identity, config, self_route)?;
    let mut seen = Vec::new();
    for inbox in &config.own {
        let key = (inbox.route.pin.key, inbox.route.pin.run, inbox.route.mailbox);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if poll_route(store, http, inbox, &reference, now_ms).await.is_err() {
            continue;
        }
    }
    recover_downloads(store, http, config, &reference, now_ms).await
}

/// One client pass: capture, authenticate, commit, reconcile references, then upload.
///
/// Each owned route already fails independently inside `poll_transport`. A missing
/// sealed configuration still commits local originals and Received copies, then
/// returns `Config` before any upload. Upload reads only rows already in `logical_records`.
/// The extra relay pin stays on the existing stop-after-stored policy.
pub async fn poll_once(
    store: &mut ClientStore,
    http: &RelayHttp,
    identity: &CommIdentity,
    roster: &Roster,
    config: &ClientConfig,
    self_route: &AuthenticatedDescriptor,
    now_ms: u64,
) -> ClientResult<()> {
    if now_ms > i64::MAX as u64 {
        return Err(ClientError::Capacity);
    }
    let transport_blocked = match poll_transport(store, http, roster, identity, config, self_route, now_ms).await
    {
        Ok(()) => false,
        Err(ClientError::Config) => true,
        Err(error) => return Err(error),
    };
    // Publication is local. A full page budget must not skip outboxes that are already saved.
    let published = publish_candidates(store, roster, identity);
    let reconciled = crate::received::reconcile_received(store, roster, identity);
    let uploaded = if transport_blocked {
        Ok(())
    } else {
        upload_committed(store, http, roster, identity, config, self_route, now_ms).await
    };
    published?;
    reconciled?;
    uploaded?;
    if transport_blocked {
        return Err(ClientError::Config);
    }
    Ok(())
}

/// Commit every staged candidate that authenticates.
///
/// Self-delivery, a Received message, a partial set, and quarantine produce no
/// acknowledgement. One such candidate does not stop the next message. Routing
/// is not required for the three saved copies.
fn publish_candidates(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
) -> ClientResult<()> {
    let candidates = authenticate_staged_with_limit(store, roster, identity, Some(64))?;
    let mut capacity_blocked = false;
    for candidate in &candidates {
        let ack = match crate::prepare_received(
            store,
            identity,
            roster,
            candidate.message(),
            candidate.source(),
        ) {
            Ok(ack) => ack,
            Err(ClientError::Identity) => continue,
            Err(error) => return Err(error),
        };
        match store.commit_incoming(roster, identity, candidate.source(), candidate.message(), ack.as_ref()) {
            Ok(_) => {}
            Err(ClientError::Identity) if candidate.message().body().key.sender == identity.public().id => {
                let root = candidate.source().required_hashes().first().ok_or(ClientError::Storage)?;
                store.reject_source_root(root, "self_uncommitted", Some(candidate.message().digest()))?;
            }
            Err(ClientError::Identity | ClientError::MissingObjects(_)) => continue,
            Err(ClientError::Capacity) => capacity_blocked = true,
            Err(error) => return Err(error),
        }
    }
    if capacity_blocked {
        return Err(ClientError::Capacity);
    }
    Ok(())
}

async fn upload_committed(
    store: &mut ClientStore,
    http: &RelayHttp,
    roster: &Roster,
    identity: &CommIdentity,
    config: &ClientConfig,
    self_route: &AuthenticatedDescriptor,
    now_ms: u64,
) -> ClientResult<()> {
    let mut after = 0u64;
    loop {
        let page = store.recover_logical(after, RECOVERY_PAGE)?;
        let Some(last) = page.last() else {
            break;
        };
        let cursor = last.cursor;
        let short = page.len() < usize::from(RECOVERY_PAGE);
        for logical in &page {
            crate::upload_pending(
                store,
                http,
                logical,
                roster,
                identity,
                config,
                self_route,
                now_ms,
                crate::ThirdPass::StopAfterStored,
            )
            .await?;
        }
        if short || cursor <= after {
            break;
        }
        after = cursor;
    }
    Ok(())
}

async fn poll_route(
    store: &mut ClientStore,
    http: &RelayHttp,
    inbox: &crate::OwnerInbox,
    reference: &ConfigReference,
    now_ms: u64,
) -> ClientResult<()> {
    let route = &inbox.route;
    clear_route_auth(store, route, reference)?;
    if !route_due(store, route, now_ms, reference)? {
        return Ok(());
    }
    let position = route_position(store, route)?;
    match http.capture_entries(route, &inbox.read, position, Some(100)).await {
        Ok(http::PageRead::Page(page)) => capture_loaded(store, http, inbox, &page, now_ms, reference).await,
        Ok(http::PageRead::Invalid { reason, sample }) => {
            record_route_failure(store, route, now_ms, reason, &sample, true)
        }
        Ok(http::PageRead::Unavailable { reason, sample }) => {
            record_route_failure(store, route, now_ms, reason, &sample, false)
        }
        Err(ClientError::Identity) => note_route_auth(store, route, reference),
        Err(_) => record_route_failure(store, route, now_ms, "transport", &[], false),
    }
}

async fn capture_loaded(
    store: &mut ClientStore,
    http: &RelayHttp,
    inbox: &crate::OwnerInbox,
    page: &Page,
    now_ms: u64,
    reference: &ConfigReference,
) -> ClientResult<()> {
    let route = &inbox.route;
    let mut downloads = Vec::new();
    for (index, entry) in page.entries.iter().enumerate() {
        // Position length and receipt stay with capture_page. One bad advertisement must not reject the hash.
        if !framed_len(entry.wire_length) || !receipt_matches(route, page, index) {
            continue;
        }
        if downloads.iter().any(|outcome| match outcome {
            DownloadOutcome::Cached(object) => object.hash == entry.hash,
            DownloadOutcome::Missing(hash) => *hash == entry.hash,
            DownloadOutcome::Rejected { hash, .. } => *hash == entry.hash,
        }) {
            continue;
        }
        if let Some(saved) = store.saved_object(&entry.hash)? {
            downloads.push(match wire_failure(&saved.wire, &entry.hash) {
                None => DownloadOutcome::Cached(saved),
                Some(reason) => DownloadOutcome::Rejected {
                    hash: entry.hash,
                    reason,
                    sample: prefix(&saved.wire).to_vec(),
                },
            });
            continue;
        }
        match http.capture_object(route, &inbox.read, &entry.hash).await {
            Ok(wire) => downloads.push(match wire_failure(&wire, &entry.hash) {
                None => DownloadOutcome::Cached(Object { hash: entry.hash, wire }),
                Some(reason) => DownloadOutcome::Rejected {
                    hash: entry.hash,
                    reason,
                    sample: prefix(&wire).to_vec(),
                },
            }),
            Err(ClientError::Identity) => return note_route_auth(store, route, reference),
            Err(ClientError::Wire(WireError::Bounds)) => downloads.push(DownloadOutcome::Rejected {
                hash: entry.hash,
                reason: QuarantineReason::Length,
                sample: Vec::new(),
            }),
            Err(ClientError::MissingObjects(_) | ClientError::Transport | ClientError::Storage | ClientError::Capacity) => {
                downloads.push(DownloadOutcome::Missing(entry.hash));
            }
            Err(_) => downloads.push(DownloadOutcome::Missing(entry.hash)),
        }
    }
    match store.capture_page(route, page, &downloads) {
        Ok(()) => release_route(store, route),
        Err(ClientError::Cursor) => isolate_route(store, route, "cursor"),
        Err(ClientError::Capacity) => Ok(()),
        Err(_) => record_route_failure(store, route, now_ms, "transport", &[], false),
    }
}

async fn recover_downloads(
    store: &mut ClientStore,
    http: &RelayHttp,
    config: &ClientConfig,
    reference: &ConfigReference,
    now_ms: u64,
) -> ClientResult<()> {
    let mut after = 0u64;
    loop {
        let page = store.recover_pending_downloads(after, 100)?;
        let Some(next) = page.last().map(|task| task.cursor) else {
            break;
        };
        for task in &page {
            let _ = recover_one(store, http, config, reference, now_ms, task).await;
        }
        if next <= after {
            break;
        }
        after = next;
    }
    Ok(())
}

async fn recover_one(
    store: &mut ClientStore,
    http: &RelayHttp,
    config: &ClientConfig,
    reference: &ConfigReference,
    now_ms: u64,
    task: &PendingDownload,
) -> ClientResult<()> {
    // A valid object cached through another relay retires this task before auth wait, backoff, or route lookup.
    if let Some(saved) = store.saved_object(&task.source_hash)? {
        return if let Some(reason) = wire_failure(&saved.wire, &task.source_hash) {
            let sample = prefix(&saved.wire).to_vec();
            settle_download(store, task, None, Some((reason, sample)))
        } else {
            settle_download(store, task, Some(saved.wire), None)
        };
    }
    if download_waiting(store, task, reference)? || task.retry_at > now_ms {
        return Ok(());
    }
    let Some(inbox) = config.own.iter().find(|inbox| {
        inbox.route.pin.key == task.relay_key && inbox.route.pin.run == task.run && inbox.route.mailbox == task.mailbox
    }) else {
        return Ok(());
    };
    match http.capture_object(&inbox.route, &inbox.read, &task.source_hash).await {
        Ok(wire) => match wire_failure(&wire, &task.source_hash) {
            None => settle_download(store, task, Some(wire), None),
            Some(reason) => {
                let sample = prefix(&wire).to_vec();
                settle_download(store, task, None, Some((reason, sample)))
            }
        },
        Err(ClientError::Wire(WireError::Bounds)) => {
            settle_download(store, task, None, Some((QuarantineReason::Length, Vec::new())))
        }
        Err(ClientError::Identity) => note_download_auth(store, task, reference),
        Err(ClientError::MissingObjects(_) | ClientError::Transport | ClientError::Storage | ClientError::Capacity) => {
            schedule_download_retry(store, task, now_ms)
        }
        Err(_) => schedule_download_retry(store, task, now_ms),
    }
}

fn download_waiting(store: &mut ClientStore, task: &PendingDownload, reference: &ConfigReference) -> ClientResult<bool> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "DELETE FROM download_auth_wait WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4 AND config_revision < ?5",
        params![task.relay_key, task.run, task.mailbox, task.source_hash, as_i64(reference.revision())?],
    )?;
    let waiting: Option<i64> = transaction
        .query_row(
            "SELECT config_revision FROM download_auth_wait WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
            |row| row.get(0),
        )
        .optional()?;
    transaction.commit()?;
    Ok(waiting.is_some())
}

fn note_download_auth(store: &mut ClientStore, task: &PendingDownload, reference: &ConfigReference) -> ClientResult<()> {
    let revision = as_i64(reference.revision())?;
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT config_revision, config_hash FROM download_auth_wait WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((stored_revision, stored_hash)) = row {
        if stored_revision == revision && stored_hash.as_slice() == reference.hash().as_slice() {
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "UPDATE download_auth_wait SET config_revision=?5, config_hash=?6 WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
            params![
                task.relay_key,
                task.run,
                task.mailbox,
                task.source_hash,
                revision,
                reference.hash().as_slice()
            ],
        )?;
        transaction.commit()?;
        return Ok(());
    }
    let pending: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM pending_downloads WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
            |row| row.get(0),
        )
        .optional()?;
    if pending.is_none() {
        transaction.commit()?;
        return Ok(());
    }
    admit_storage_growth(&transaction, store.storage_budget)?;
    transaction.execute(
        "INSERT INTO download_auth_wait VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            task.relay_key,
            task.run,
            task.mailbox,
            task.source_hash,
            revision,
            reference.hash().as_slice()
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn schedule_download_retry(store: &mut ClientStore, task: &PendingDownload, now_ms: u64) -> ClientResult<()> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let attempts: Option<i64> = transaction
        .query_row(
            "SELECT attempts FROM pending_downloads WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
            |row| row.get(0),
        )
        .optional()?;
    let Some(attempts) = attempts else {
        transaction.commit()?;
        return Ok(());
    };
    let current = u64::try_from(attempts).map_err(|_| ClientError::Storage)?;
    let next = current
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .unwrap_or(current);
    let retry_at = now_ms
        .checked_add(crate::retry::sample_delay(current)?)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(ClientError::Capacity)?;
    admit_storage_growth(&transaction, store.storage_budget)?;
    let changed = transaction.execute(
        "UPDATE pending_downloads SET attempts=?5, retry_at=?6 WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
        params![
            task.relay_key,
            task.run,
            task.mailbox,
            task.source_hash,
            next as i64,
            as_i64(retry_at)?
        ],
    )?;
    if changed != 1 {
        return Err(ClientError::Storage);
    }
    transaction.commit()?;
    Ok(())
}

fn settle_download(
    store: &mut ClientStore,
    task: &PendingDownload,
    validated: Option<Vec<u8>>,
    failure: Option<(QuarantineReason, Vec<u8>)>,
) -> ClientResult<()> {
    let schema = store.schema();
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_schema(&transaction, schema)?;
    let stored_len: Option<i64> = transaction
        .query_row(
            "SELECT wire_length FROM pending_downloads WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
            |row| row.get(0),
        )
        .optional()?;
    let Some(stored_len) = stored_len else {
        transaction.commit()?;
        return Ok(());
    };
    if stored_len != as_i64(task.wire_length)? {
        return Err(ClientError::Conflict);
    }
    let cipher: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT wire FROM ciphertext_objects WHERE hash=?1",
            [task.source_hash],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(wire) = validated.as_deref() {
        if let Some(saved) = cipher.as_deref() {
            if saved != wire {
                return Err(ClientError::Conflict);
            }
        }
    }
    let insert_wire = validated.as_ref().filter(|_| cipher.is_none());
    // Task length is the covered advertisement. A different valid wire stays cached and still records Length.
    let reason_code = if let Some(wire) = validated.as_ref() {
        if wire.len() as i64 != stored_len {
            Some(QuarantineReason::Length.code())
        } else {
            None
        }
    } else {
        failure.as_ref().map(|(reason, _)| reason.code())
    };
    let rejection = if reason_code.is_some() {
        let existing: Option<String> = transaction
            .query_row(
                "SELECT reason FROM download_rejections WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
                params![task.relay_key, task.run, task.mailbox, task.source_hash],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_none() { reason_code } else { None }
    } else {
        None
    };
    let sample = failure.as_ref().filter(|_| validated.is_none()).and_then(|(_, sample)| {
        let sample = prefix(sample);
        if sample.is_empty() {
            None
        } else {
            Some(sample.to_vec())
        }
    });
    let sample_sequence: Option<i64> = if sample.is_some() {
        transaction.query_row(
            "SELECT min(sequence) FROM incoming_journal WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4 AND disposition='missing'",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
            |row| row.get(0),
        )?
    } else {
        None
    };
    let sample_is_new = match (sample.as_deref(), sample_sequence) {
        (Some(sample), Some(sequence)) => {
            let present: i64 = transaction.query_row(
                "SELECT count(*) FROM quarantine_samples WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND sequence=?4 AND sample=?5",
                params![task.relay_key, task.run, task.mailbox, sequence, sample],
                |row| row.get(0),
            )?;
            present == 0
        }
        _ => false,
    };
    if insert_wire.is_some() || rejection.is_some() {
        admit_storage_growth(&transaction, store.storage_budget)?;
    }
    if let Some(wire) = insert_wire {
        transaction.execute(
            "INSERT INTO ciphertext_objects VALUES(?1,?2,?3)",
            params![task.source_hash, wire, wire.len() as i64],
        )?;
    }
    if let Some(reason) = rejection {
        transaction.execute(
            "INSERT INTO download_rejections VALUES(?1,?2,?3,?4,?5)",
            params![task.relay_key, task.run, task.mailbox, task.source_hash, reason],
        )?;
    }
    if let Some(wire) = validated.as_deref() {
        transaction.execute(
            "UPDATE incoming_journal SET disposition='cached' WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4 AND disposition='missing' AND wire_length=?5",
            params![task.relay_key, task.run, task.mailbox, task.source_hash, wire.len() as i64],
        )?;
        transaction.execute(
            "UPDATE incoming_journal SET disposition='quarantine' WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4 AND disposition='missing'",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
        )?;
    } else {
        transaction.execute(
            "UPDATE incoming_journal SET disposition='quarantine' WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4 AND disposition='missing'",
            params![task.relay_key, task.run, task.mailbox, task.source_hash],
        )?;
        if sample_is_new {
            if let (Some(sample), Some(sequence)) = (sample.as_deref(), sample_sequence) {
                match fit_sample(&transaction, sample.len() as i64) {
                    Ok(()) => {
                        let sample_id = allocate_sample_id(&transaction)?;
                        transaction.execute(
                            "INSERT INTO quarantine_samples (id, relay_key, run, mailbox, sequence, sample) VALUES(?1,?2,?3,?4,?5,?6)",
                            params![sample_id, task.relay_key, task.run, task.mailbox, sequence, sample],
                        )?;
                    }
                    Err(ClientError::Capacity) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    transaction.execute(
        "DELETE FROM download_auth_wait WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4",
        params![task.relay_key, task.run, task.mailbox, task.source_hash],
    )?;
    let removed = transaction.execute(
        "DELETE FROM pending_downloads WHERE relay_key=?1 AND run=?2 AND mailbox=?3 AND source_hash=?4 AND wire_length=?5",
        params![task.relay_key, task.run, task.mailbox, task.source_hash, stored_len],
    )?;
    if removed != 1 {
        return Err(ClientError::Storage);
    }
    transaction.commit()?;
    Ok(())
}

const RECOVERY_PAGE: u16 = 100;
const MAX_STAGED_OBJECTS: usize = 275;

/// Readonly application readiness. Pending does not drop the candidate or withhold a future Received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateReadiness {
    Ready,
    Pending,
}

/// One application prerequisite and the readiness of its full chain.
///
/// This is not recovery metadata. A staged claim is not Ready, and a committed row is not
/// Resolved until its exact dependency edges have been walked.
pub struct PrerequisiteStatus {
    prerequisite: MessageRef,
    readiness: CandidateReadiness,
}

impl PrerequisiteStatus {
    pub fn prerequisite(&self) -> &MessageRef {
        &self.prerequisite
    }

    pub fn readiness(&self) -> CandidateReadiness {
        self.readiness
    }
}

/// Authenticated message and complete source kept in memory until publication.
///
/// `readiness` describes other authenticated candidates in this batch. It is not stored and
/// it is not proof that a committed dependency chain is ready. Recovery rows are not
/// authentication proof either.
pub struct AuthenticatedCandidate {
    message: AuthenticatedMessage,
    source: CompleteSource,
    prerequisites: Vec<PrerequisiteStatus>,
}

impl AuthenticatedCandidate {
    pub fn message(&self) -> &AuthenticatedMessage {
        &self.message
    }

    pub fn source(&self) -> &CompleteSource {
        &self.source
    }

    pub fn prerequisites(&self) -> &[PrerequisiteStatus] {
        &self.prerequisites
    }

    /// Ready only when every prerequisite chain is ready. An empty list is ready.
    pub fn readiness(&self) -> CandidateReadiness {
        if self.prerequisites.iter().all(|status| status.readiness == CandidateReadiness::Ready) {
            CandidateReadiness::Ready
        } else {
            CandidateReadiness::Pending
        }
    }
}

struct Opened {
    root: Id32,
    message: AuthenticatedMessage,
    source: CompleteSource,
}

/// Stage verified roots and return complete authenticated candidates.
///
/// Partial manifests stay staged. Nothing here writes an original, an application row, or an acknowledgement.
/// Download rejections do not veto a cached object that matches the current source set.
pub fn authenticate_staged(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
) -> ClientResult<Vec<AuthenticatedCandidate>> {
    authenticate_staged_with_limit(store, roster, identity, None)
}

fn authenticate_staged_with_limit(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    admission_limit: Option<u64>,
) -> ClientResult<Vec<AuthenticatedCandidate>> {
    let public = identity.public();
    store.check_association(roster, public.id)?;
    if !roster.members.iter().any(|member| member == &public) {
        return Err(ClientError::Identity);
    }
    store.retire_incomplete()?;
    let mut opened = Vec::new();
    discover_objects(store, roster, identity, &mut opened, admission_limit)?;
    complete_staged(store, roster, identity, &mut opened)?;
    let prerequisites = classify_prerequisites(store, roster, identity, &opened)?;
    Ok(opened
        .into_iter()
        .zip(prerequisites)
        .map(|(opened, prerequisites)| AuthenticatedCandidate {
            message: opened.message,
            source: opened.source,
            prerequisites,
        })
        .collect())
}

fn discover_objects(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    opened: &mut Vec<Opened>,
    admission_limit: Option<u64>,
) -> ClientResult<()> {
    let mut after = None;
    loop {
        let page = store.covered_cached_hashes(after.as_ref(), RECOVERY_PAGE)?;
        let Some(last) = page.last().copied() else {
            break;
        };
        let short = page.len() < usize::from(RECOVERY_PAGE);
        for hash in page {
            if let Some(limit) = admission_limit {
                if store.pending_transfer_count()? >= limit {
                    return Ok(());
                }
            }
            classify_cached(store, roster, identity, hash, opened)?;
        }
        after = Some(last);
        if short {
            break;
        }
    }
    Ok(())
}

fn classify_cached(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    hash: Id32,
    opened: &mut Vec<Opened>,
) -> ClientResult<()> {
    if store.source_rejected(&hash)? || store.incoming_root_settled(&hash)? {
        return Ok(());
    }
    let Some(object) = store.saved_object(&hash)? else {
        return Ok(());
    };
    // One covered packet's failure is durable for that hash. It does not stop the rest of the page.
    match TransferAssembler::inspect(roster, identity, &object)? {
        RootInspection::Chunk => Ok(()),
        RootInspection::Invalid(reason) => store.reject_source_root(&hash, reason, None),
        RootInspection::Single => admit_single(store, roster, identity, object, opened),
        RootInspection::Manifest(manifest) => admit_manifest(store, &object, &manifest),
    }
}

fn admit_single(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    object: Object,
    opened: &mut Vec<Opened>,
) -> ClientResult<()> {
    let transfer = match TransferAssembler::open(roster, identity, &object, &BTreeMap::new()) {
        Ok(transfer) => transfer,
        Err(error) => return store.reject_source_root(&object.hash, source_reason(&error), None),
    };
    let (message, source) = transfer.into_parts();
    // The group is the verified binding. The ciphertext hash is not shared with another message.
    let group_id = crate::transfer::source_group_id(&message.body().key, message.digest(), source.recipient(), None)?;
    let bound = BoundSource {
        root_hash: object.hash,
        root_wire_length: object.wire.len() as u64,
        group_id,
        claimed_transfer: None,
        key: message.body().key.clone(),
        objects: Vec::new(),
    };
    match stage_or_wait(store, &bound)? {
        Some(StageResult::Staged | StageResult::Refreshed | StageResult::Unchanged) => {
            // Route refresh already happened. A settled root is not another candidate.
            if store.incoming_root_settled(&object.hash)? {
                return Ok(());
            }
            opened.push(Opened {
                root: object.hash,
                message,
                source,
            });
            Ok(())
        }
        Some(StageResult::Rejected) | None => Ok(()),
        Some(StageResult::Mismatch) => store.reject_source_root(&object.hash, "manifest", None),
    }
}

fn admit_manifest(
    store: &mut ClientStore,
    object: &Object,
    manifest: &crate::SignedManifest,
) -> ClientResult<()> {
    let mut objects = Vec::with_capacity(manifest.requirements().len());
    for requirement in manifest.requirements() {
        let wire = u64::try_from(requirement.wire_length()).map_err(|_| ClientError::Wire(WireError::Bounds))?;
        match store.saved_object(requirement.hash())? {
            Some(cached) if cached.wire.len() as u64 != wire => {
                return store.reject_source_root(manifest.root(), "bounds", None);
            }
            Some(_) | None => objects.push((*requirement.hash(), wire)),
        }
    }
    // A reused transfer id does not merge a different vault, roster, sender, message, digest, or recipient.
    let group_id = crate::transfer::source_group_id(
        manifest.key(),
        manifest.digest(),
        manifest.recipient(),
        Some(manifest.transfer()),
    )?;
    let bound = BoundSource {
        root_hash: *manifest.root(),
        root_wire_length: object.wire.len() as u64,
        group_id,
        claimed_transfer: Some(*manifest.transfer()),
        key: manifest.key().clone(),
        objects,
    };
    match stage_or_wait(store, &bound)? {
        Some(StageResult::Mismatch) => store.reject_source_root(manifest.root(), "manifest", None),
        _ => Ok(()),
    }
}

fn stage_or_wait(store: &mut ClientStore, source: &BoundSource) -> ClientResult<Option<StageResult>> {
    match store.stage_bound_source(source) {
        Ok(result) => Ok(Some(result)),
        Err(ClientError::Capacity) => Ok(None),
        Err(error) => Err(error),
    }
}

fn complete_staged(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    opened: &mut Vec<Opened>,
) -> ClientResult<()> {
    let mut after = 0u64;
    loop {
        let page = store.recover_staged_sources(after, RECOVERY_PAGE)?;
        if page.is_empty() {
            break;
        }
        let cursor = page[page.len() - 1].cursor;
        let short = page.len() < usize::from(RECOVERY_PAGE);
        for source in page {
            if source.group_id.is_none() || opened.iter().any(|opened| opened.root == source.root_hash) {
                continue;
            }
            open_if_complete(store, roster, identity, source.root_hash, opened)?;
        }
        if cursor <= after || short {
            break;
        }
        after = cursor;
    }
    Ok(())
}

fn open_if_complete(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    root_hash: Id32,
    opened: &mut Vec<Opened>,
) -> ClientResult<()> {
    if store.source_rejected(&root_hash)? || store.incoming_root_settled(&root_hash)? {
        return Ok(());
    }
    let requirements = load_requirements(store, &root_hash)?;
    if requirements.first().map(|requirement| requirement.ordinal) != Some(0) {
        return Err(ClientError::Storage);
    }
    let Some(root) = store.saved_object(&root_hash)? else {
        return Ok(());
    };
    let mut objects = BTreeMap::new();
    let mut missing = false;
    for (index, requirement) in requirements.iter().enumerate() {
        if requirement.ordinal as usize != index {
            return Err(ClientError::Storage);
        }
        if requirement.ordinal == 0 {
            if requirement.hash != root_hash || requirement.wire_length != root.wire.len() as u64 {
                return store.reject_source_root(&root_hash, "manifest", None);
            }
            continue;
        }
        match store.saved_object(&requirement.hash)? {
            None => missing = true,
            Some(object) if object.wire.len() as u64 != requirement.wire_length => {
                return store.reject_source_root(&root_hash, "bounds", None);
            }
            Some(object) => {
                objects.insert(object.hash, object);
            }
        }
    }
    if missing {
        return Ok(());
    }
    match TransferAssembler::open(roster, identity, &root, &objects) {
        Ok(transfer) => {
            let (message, source) = transfer.into_parts();
            opened.push(Opened {
                root: root_hash,
                message,
                source,
            });
            Ok(())
        }
        Err(ClientError::MissingObjects(_)) => Ok(()),
        Err(error) => store.reject_source_root(&root_hash, source_reason(&error), None),
    }
}

fn load_requirements(store: &ClientStore, root_hash: &Id32) -> ClientResult<Vec<crate::StagedRequirement>> {
    let mut after = None;
    let mut requirements = Vec::new();
    loop {
        let page = store.recover_staged_requirements(root_hash, after, RECOVERY_PAGE)?;
        let Some(last) = page.last() else {
            break;
        };
        after = Some(last.ordinal);
        let short = page.len() < usize::from(RECOVERY_PAGE);
        requirements.extend(page);
        if requirements.len() > MAX_STAGED_OBJECTS {
            return Err(ClientError::Wire(WireError::Bounds));
        }
        if short {
            break;
        }
    }
    Ok(requirements)
}

fn source_reason(error: &ClientError) -> &'static str {
    match error {
        ClientError::Identity => "identity",
        ClientError::Crypto => "signature",
        ClientError::Wire(WireError::Bounds) => "bounds",
        ClientError::Wire(WireError::Schema) => "schema",
        ClientError::Wire(_) => "framing",
        _ => "manifest",
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
struct PrerequisiteNode {
    vault: Id32,
    roster: Id32,
    sender: u16,
    message: Id32,
    digest: Id32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReadinessMemo {
    Visiting,
    Ready,
    Pending,
}

struct ReadinessWalk<'a> {
    store: &'a ClientStore,
    roster: &'a Roster,
    identity: &'a CommIdentity,
    opened: &'a [Opened],
    index: BTreeMap<PrerequisiteNode, usize>,
    memo: BTreeMap<PrerequisiteNode, ReadinessMemo>,
    loaded: BTreeMap<PrerequisiteNode, Option<Vec<PrerequisiteNode>>>,
}

impl<'a> ReadinessWalk<'a> {
    fn new(store: &'a ClientStore, roster: &'a Roster, identity: &'a CommIdentity, opened: &'a [Opened]) -> Self {
        let mut index = BTreeMap::new();
        for (position, opened) in opened.iter().enumerate() {
            index.entry(prerequisite_node(&opened.message)).or_insert(position);
        }
        Self {
            store,
            roster,
            identity,
            opened,
            index,
            memo: BTreeMap::new(),
            loaded: BTreeMap::new(),
        }
    }

    /// Iterative walk. A finite acyclic chain becomes Ready at any depth.
    ///
    /// A node stays Pending when an exact prerequisite is missing, the saved source does not
    /// authenticate, or a back-edge reaches a node already being resolved. No depth or batch
    /// ceiling turns a complete chain Pending, and a partial load is not marked Ready.
    fn readiness(&mut self, start: PrerequisiteNode) -> ClientResult<CandidateReadiness> {
        let mut stack = vec![(start, false)];
        while let Some((node, finishing)) = stack.pop() {
            if finishing {
                let ready = match self.loaded.get(&node) {
                    Some(Some(children)) => children
                        .iter()
                        .all(|child| self.memo.get(child) == Some(&ReadinessMemo::Ready)),
                    _ => false,
                };
                self.memo.insert(
                    node,
                    if ready {
                        ReadinessMemo::Ready
                    } else {
                        ReadinessMemo::Pending
                    },
                );
                continue;
            }
            match self.memo.get(&node).copied() {
                Some(ReadinessMemo::Ready | ReadinessMemo::Pending | ReadinessMemo::Visiting) => continue,
                None => {}
            }
            self.memo.insert(node, ReadinessMemo::Visiting);
            let children = self.edge_nodes(&node)?;
            self.loaded.insert(node, children.clone());
            stack.push((node, true));
            if let Some(children) = children {
                for child in children.into_iter().rev() {
                    stack.push((child, false));
                }
            }
        }
        Ok(match self.memo.get(&start) {
            Some(ReadinessMemo::Ready) => CandidateReadiness::Ready,
            _ => CandidateReadiness::Pending,
        })
    }

    /// Prefer this pass's authenticated body. Incoming rows keep their stored edges.
    /// An outgoing record is reopened from the owner's saved recipient copy.
    fn edge_nodes(&self, node: &PrerequisiteNode) -> ClientResult<Option<Vec<PrerequisiteNode>>> {
        let refs = if let Some(position) = self.index.get(node) {
            Some(self.opened[*position].message.body().prerequisites.clone())
        } else {
            match self.store.committed_chain(
                &node.vault,
                &node.roster,
                node.sender,
                &node.message,
                &node.digest,
            )? {
                crate::store::CommittedChain::Missing => None,
                crate::store::CommittedChain::Incoming(edges) => Some(edges),
                crate::store::CommittedChain::Outgoing => {
                    outgoing_prerequisites(self.store, self.roster, self.identity, node)?
                }
            }
        };
        Ok(refs.map(|refs| {
            refs.into_iter()
                .map(|edge| PrerequisiteNode {
                    vault: node.vault,
                    roster: node.roster,
                    sender: edge.sender,
                    message: edge.message,
                    digest: edge.digest,
                })
                .collect()
        }))
    }
}

/// Authenticate the owner's saved copy of one authored message and return its prerequisites.
///
/// A missing object, a short requirement page, or a failed open stays unavailable. It is not
/// an empty ready list. The plaintext is dropped with the authenticated message.
fn outgoing_prerequisites(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    node: &PrerequisiteNode,
) -> ClientResult<Option<Vec<MessageRef>>> {
    let owner = identity.public().id;
    if node.sender != owner {
        return Ok(None);
    }
    let key = LogicalKey {
        vault: node.vault,
        roster: node.roster,
        sender: node.sender,
        message: node.message,
    };
    let Some(copy) = store
        .recover_recipients(&key)?
        .into_iter()
        .find(|recipient| recipient.recipient == owner)
    else {
        return Ok(None);
    };
    let mut requirements = Vec::new();
    let mut after = None;
    loop {
        let page = store.recover_requirements(&key, owner, after.as_ref(), RECOVERY_PAGE)?;
        if page.is_empty() {
            break;
        }
        let next = page[page.len() - 1].hash;
        if after.is_some_and(|cursor| next <= cursor) {
            return Err(ClientError::Storage);
        }
        let short = page.len() < usize::from(RECOVERY_PAGE);
        requirements.extend(page);
        after = Some(next);
        if requirements.len() > MAX_STAGED_OBJECTS {
            return Ok(None);
        }
        if short {
            break;
        }
    }
    requirements.sort_by_key(|requirement| requirement.ordinal);
    let mut seen = BTreeSet::new();
    if requirements.is_empty()
        || requirements.iter().enumerate().any(|(index, requirement)| {
            requirement.ordinal as usize != index || !seen.insert(requirement.hash)
        })
        || requirements.last().map(|requirement| requirement.hash) != Some(copy.root_hash)
    {
        return Ok(None);
    }
    let mut objects = Vec::with_capacity(requirements.len());
    for requirement in &requirements {
        let Some(object) = store.saved_object(&requirement.hash)? else {
            return Ok(None);
        };
        if object.wire.len() as u64 != requirement.length {
            return Ok(None);
        }
        objects.push(object);
    }
    let root = objects[objects.len() - 1].clone();
    let map = objects.iter().cloned().map(|object| (object.hash, object)).collect();
    let opened = match TransferAssembler::open(roster, identity, &root, &map) {
        Ok(opened) => opened,
        Err(ClientError::Storage) => return Err(ClientError::Storage),
        Err(_) => return Ok(None),
    };
    let (message, source) = opened.into_parts();
    let actual: BTreeSet<_> = objects.iter().map(|object| object.hash).collect();
    let required: BTreeSet<_> = source.required_hashes().iter().copied().collect();
    if actual != required
        || message.body().key != key
        || message.digest() != &node.digest
        || source.recipient() != owner
    {
        return Ok(None);
    }
    Ok(Some(message.body().prerequisites.clone()))
}

fn prerequisite_node(message: &AuthenticatedMessage) -> PrerequisiteNode {
    let key = &message.body().key;
    PrerequisiteNode {
        vault: key.vault,
        roster: key.roster,
        sender: key.sender,
        message: key.message,
        digest: *message.digest(),
    }
}

/// Ready or pending for one committed message.
///
/// `authenticate_staged` skips a published root, so a candidate's in-memory
/// readiness cannot observe an ancestor that arrives later. This walk uses the
/// same iterative exact edges and reopens an authored copy from saved ciphertext.
/// Nothing is written, including no ready flag and no further acknowledgement.
pub fn committed_readiness(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    key: &LogicalKey,
    digest: &Id32,
) -> ClientResult<CandidateReadiness> {
    store.check_association(roster, identity.public().id)?;
    if key.vault != roster.vault || key.roster != roster_digest(roster)? || !roster.members.iter().any(|member| member.id == key.sender) {
        return Err(ClientError::Identity);
    }
    let mut walk = ReadinessWalk::new(store, roster, identity, &[]);
    walk.readiness(PrerequisiteNode {
        vault: key.vault,
        roster: key.roster,
        sender: key.sender,
        message: key.message,
        digest: *digest,
    })
}

fn classify_prerequisites(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    opened: &[Opened],
) -> ClientResult<Vec<Vec<PrerequisiteStatus>>> {
    let mut walk = ReadinessWalk::new(store, roster, identity, opened);
    let mut rows = Vec::with_capacity(opened.len());
    for opened in opened {
        let vault = opened.message.body().key.vault;
        let roster = opened.message.body().key.roster;
        let mut statuses = Vec::new();
        for prerequisite in &opened.message.body().prerequisites {
            let readiness = walk.readiness(PrerequisiteNode {
                vault,
                roster,
                sender: prerequisite.sender,
                message: prerequisite.message,
                digest: prerequisite.digest,
            })?;
            statuses.push(PrerequisiteStatus {
                prerequisite: prerequisite.clone(),
                readiness,
            });
        }
        rows.push(statuses);
    }
    Ok(rows)
}

#[cfg(test)]
mod bounded_intake_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_protocol::types::{LogicalKey, MessageBody, Payload, ReceiptBody, RelayPin};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[test]
    fn polling_backlog_preserves_capacity_for_atomic_received_copies() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for (count, sender) in [(3u16, 2u16), (4, 2), (3, 1), (4, 1)] {
            let identities: Vec<_> = (1..=count)
                .map(|id| {
                    let mut seed = [0u8; 66];
                    seed[..2].copy_from_slice(&id.to_be_bytes());
                    seed[2..34].fill(id as u8);
                    seed[34..].fill(id as u8 + 10);
                    CommIdentity::from_serialized(&seed).unwrap()
                })
                .collect();
            let roster = Roster {
                vault: [77; 32],
                members: identities.iter().map(CommIdentity::public).collect(),
            };
            let parent = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "loki-bounded-intake-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
            let mut store = ClientStore::open(&parent.join("client"), &roster, 1).unwrap();
            let signer = SigningKey::from_bytes(&[91; 32]);
            let route = RelayRoute {
                pin: RelayPin {
                    key: signer.verifying_key().to_bytes(),
                    run: [92; 32],
                },
                endpoint: "http://127.0.0.1:9".into(),
                mailbox: [93; 32],
                append_revision: 1,
            };
            let objects: Vec<_> = (0u8..70)
                .map(|id| {
                    let body = MessageBody {
                        key: LogicalKey {
                            vault: roster.vault,
                            roster: roster_digest(&roster).unwrap(),
                            sender,
                            message: [id; 32],
                        },
                        audience: (1..=count).collect(),
                        session: Some([94; 32]),
                        prerequisites: vec![],
                        payload: Payload::Test(vec![id]),
                    };
                    crate::prepare_outbox(&identities[usize::from(sender - 1)], &roster, &body)
                        .unwrap()
                        .recipients()
                        .iter()
                        .find(|copy| copy.recipient() == 1)
                        .unwrap()
                        .objects()[0]
                        .clone()
                })
                .collect();
            for (batch, chunk) in objects.chunks(35).enumerate() {
                let after = (batch * 35) as u64;
                let entries = chunk
                    .iter()
                    .enumerate()
                    .map(|(index, object)| {
                        let sequence = after + index as u64 + 1;
                        let body = ReceiptBody {
                            pin: route.pin.clone(),
                            mailbox: route.mailbox,
                            hash: object.hash,
                            wire_length: object.wire.len() as u64,
                            sequence,
                            retention: 1,
                        };
                        let encoded = loki_relay_protocol::receipt::encode_body(&body).unwrap();
                        let mut input = b"Loki_Relay_Stored_v1\0".to_vec();
                        input.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
                        input.extend_from_slice(&encoded);
                        let receipt = canonical::encode(&Value::Array(vec![
                            Value::Bytes(encoded),
                            Value::Bytes(signer.sign(&input).to_bytes().to_vec()),
                        ]))
                        .unwrap();
                        loki_relay_protocol::types::Entry {
                            sequence,
                            hash: object.hash,
                            wire_length: object.wire.len() as u64,
                            receipt,
                        }
                    })
                    .collect();
                let page = Page {
                    mailbox: route.mailbox,
                    after,
                    next: after + chunk.len() as u64,
                    high_water: after + chunk.len() as u64,
                    entries,
                };
                let downloads = chunk
                    .iter()
                    .cloned()
                    .map(DownloadOutcome::Cached)
                    .collect::<Vec<_>>();
                store.capture_page(&route, &page, &downloads).unwrap();
            }
            let candidates =
                authenticate_staged_with_limit(&mut store, &roster, &identities[0], Some(64))
                    .unwrap();
            assert_eq!(candidates.len(), 64);
            assert_eq!(store.pending_transfer_count().unwrap(), 64);
            if sender == 1 {
                for _ in 0..3 {
                    publish_candidates(&mut store, &roster, &identities[0]).unwrap();
                }
                assert_eq!(store.pending_transfer_count().unwrap(), 0);
                for table in [
                    "logical_records",
                    "incoming_originals",
                    "caller_requests",
                    "ack_links",
                ] {
                    let rows: u64 = store
                        .connection
                        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })
                        .unwrap();
                    assert_eq!(rows, 0, "uncommitted self copies must not manufacture local publication or acknowledgements");
                }
                let rejected: u64 = store
                    .connection
                    .query_row(
                        "SELECT count(*) FROM source_rejections WHERE reason='self_uncommitted'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(rejected, 70);
                for object in &objects {
                    assert_eq!(
                        store.saved_object(&object.hash).unwrap().unwrap().wire,
                        object.wire
                    );
                }
                continue;
            }
            let candidate = &candidates[0];
            let ack = crate::prepare_received(
                &store,
                &identities[0],
                &roster,
                candidate.message(),
                candidate.source(),
            )
            .unwrap();
            store
                .commit_incoming(
                    &roster,
                    &identities[0],
                    candidate.source(),
                    candidate.message(),
                    ack.as_ref(),
                )
                .unwrap();
            assert_eq!(
                store.pending_transfer_count().unwrap(),
                64 + u64::from(count) - 1
            );
            for object in &objects {
                assert_eq!(
                    store.saved_object(&object.hash).unwrap().unwrap().wire,
                    object.wire
                );
            }
        }
    }
}
