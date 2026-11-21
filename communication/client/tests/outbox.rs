mod support;
use loki_relay_client::ClientStore;

#[test]
fn outbox_schema_layout() {
    let root = support::root();
    drop(ClientStore::open(&root, &support::roster(), 1).unwrap());
    let sql = support::sql(&root);
    let mut statement = sql
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let tables: Vec<String> = statement
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    // Names are the schema.sql CREATE TABLE contract in sqlite_master order.
    // They are written here and are not loaded from this database.
    assert_eq!(
        tables,
        [
            "ack_links",
            "caller_requests",
            "ciphertext_objects",
            "config_versions",
            "delivery_completion",
            "diagnostic_ids",
            "download_auth_wait",
            "download_rejections",
            "early_received_refs",
            "incoming_application",
            "incoming_conflict_objects",
            "incoming_conflicts",
            "incoming_dependencies",
            "incoming_journal",
            "incoming_original_objects",
            "incoming_originals",
            "incomplete_leases",
            "logical_records",
            "metadata",
            "outgoing_recipients",
            "page_diagnostics",
            "pending_downloads",
            "quarantine_samples",
            "received_work",
            "reference_rejections",
            "required_objects",
            "route_capture",
            "route_cursors",
            "source_rejections",
            "staged_coverage",
            "staged_requirements",
            "staged_sources",
            "transfer_groups",
            "upload_generation",
            "upload_work",
            "verified_receipts",
        ]
    );
}

#[test]
fn outbox_schema_prior_migration() {
    let root = support::prior_root();
    let store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    assert_eq!(
        store.config_reference().unwrap(),
        Some(loki_relay_client::ConfigReference::new(7, [88; 32]).unwrap())
    );
    let sql = support::sql(&root);
    let count: i64 = sql
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='required_objects'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn outbox_schema_reopen_exact_sets() {
    let support::Fixture {
        root,
        store,
        prepared,
    } = support::fixture(80000);
    let before = store.recover_logical(0, 100).unwrap();
    let uploads = store.recover_uploads(0, 100).unwrap();
    drop(store);
    let store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    assert_eq!(store.recover_logical(0, 100).unwrap(), before);
    assert_eq!(store.recover_uploads(0, 100).unwrap(), uploads);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].key, *prepared.key());
    assert_eq!(&before[0].digest, prepared.digest());
    assert_eq!(before[0].session, Some([92; 32]));
    assert_eq!(before[0].kind, 1);
    assert_eq!(&before[0].source_root, prepared.recipients()[0].root_hash());
    let recipients = store.recover_recipients(prepared.key()).unwrap();
    assert_eq!(recipients.len(), 3);
    for (actual, expected) in recipients.iter().zip(prepared.recipients()) {
        assert_eq!(actual.recipient, expected.recipient());
        assert_eq!(actual.transfer.as_ref(), expected.transfer());
        assert_eq!(&actual.root_hash, expected.root_hash());
        assert!(actual.needs_route);
        let requirements = store
            .recover_requirements(prepared.key(), actual.recipient, None, 100)
            .unwrap();
        assert_eq!(requirements.len(), expected.objects().len());
        for (ordinal, object) in expected.objects().iter().enumerate() {
            assert_eq!(store.saved_object(&object.hash).unwrap().unwrap(), *object);
            assert!(requirements.iter().any(|r| r.hash == object.hash
                && r.length == object.wire.len() as u64
                && r.ordinal == ordinal as u16));
        }
    }
    assert_eq!(
        uploads.len(),
        3 * prepared
            .recipients()
            .iter()
            .map(|r| r.objects().len())
            .sum::<usize>()
    );
    for upload in uploads {
        assert_eq!(store.saved_receipt(&upload).unwrap(), Some(vec![1, 2, 3]));
        let mut wrong = upload.clone();
        wrong.mailbox[0] ^= 1;
        assert_eq!(store.saved_receipt(&wrong).unwrap(), None);
    }
    assert_eq!(store.saved_object(&[0; 32]).unwrap(), None);
}

#[test]
fn outbox_schema_reference_ciphertext_factory() {
    use loki_relay_client::{ClientError, ConfigReference};
    let reference = ConfigReference::from_ciphertext(1, b"abc").unwrap();
    assert_eq!(
        hex::encode(reference.hash()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(
        reference.hash(),
        ConfigReference::from_ciphertext(1, b"abd").unwrap().hash()
    );
    assert_eq!(
        reference,
        ConfigReference::new(1, *reference.hash()).unwrap()
    );
    assert_eq!(
        reference.file_name(),
        "secrets/relay-config-0000000000000001.sealed"
    );
    assert_eq!(
        ConfigReference::from_ciphertext(0, b"abc"),
        Err(ClientError::Config)
    );
    assert_eq!(
        ConfigReference::from_ciphertext(i64::MAX as u64 + 1, b"abc"),
        Err(ClientError::Config)
    );
    assert_eq!(
        ConfigReference::from_ciphertext(i64::MAX as u64, b"abc")
            .unwrap()
            .revision(),
        i64::MAX as u64
    );
}

#[test]
fn outbox_schema_readonly_association() {
    use loki_relay_client::ClientError;
    let fixture = support::fixture(10);
    let sql = support::sql(&fixture.root);
    let before: i64 = sql
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        fixture.store.check_association(&support::roster(), 1),
        Ok(())
    );
    for owner in [0, 2, 4] {
        assert_eq!(
            fixture.store.check_association(&support::roster(), owner),
            Err(ClientError::Identity)
        );
    }
    let mut roster = support::roster();
    roster.vault[0] ^= 1;
    assert_eq!(
        fixture.store.check_association(&roster, 1),
        Err(ClientError::Identity)
    );
    let mut roster = support::roster();
    roster.members[1].signing[0] ^= 1;
    assert!(fixture.store.check_association(&roster, 1).is_err());
    let after: i64 = sql
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
}

#[test]
fn outbox_schema_query_bounds_and_cursors() {
    let fixture = support::fixture(80000);
    let store = &fixture.store;
    let key = fixture.prepared.key();
    for limit in [0, 101, u16::MAX] {
        assert!(store.recover_logical(0, limit).is_err());
        assert!(store.recover_uploads(0, limit).is_err());
        assert!(store.recover_requirements(key, 1, None, limit).is_err());
    }
    assert!(store.recover_logical(i64::MAX as u64 + 1, 1).is_err());
    assert!(store.recover_uploads(u64::MAX, 1).is_err());
    assert!(store.recover_requirements(key, 0, None, 1).is_err());
    let all = store.recover_uploads(0, 100).unwrap();
    let mut paged = Vec::new();
    let mut cursor = 0;
    loop {
        let page = store.recover_uploads(cursor, 1).unwrap();
        if page.is_empty() {
            break;
        }
        cursor = page[0].cursor;
        paged.extend(page);
    }
    assert_eq!(paged, all);
    let requirements = store.recover_requirements(key, 1, None, 100).unwrap();
    let mut paged = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .recover_requirements(key, 1, cursor.as_ref(), 1)
            .unwrap();
        if page.is_empty() {
            break;
        }
        cursor = Some(page[0].hash);
        paged.extend(page);
    }
    assert_eq!(paged, requirements);
    let mut wrong = key.clone();
    wrong.message[0] ^= 1;
    assert!(store.recover_recipients(&wrong).unwrap().is_empty());
    assert!(store
        .recover_requirements(&wrong, 1, None, 100)
        .unwrap()
        .is_empty());
}

#[test]
fn outbox_schema_page_cap() {
    let fixture = support::fixture(10);
    let sql = support::sql(&fixture.root);
    for n in 0u32..105 {
        let mut message = [0u8; 32];
        message[..4].copy_from_slice(&n.to_be_bytes());
        sql.execute("INSERT INTO logical_records SELECT vault,roster,sender,?1,digest,kind,session,state,source_root FROM logical_records LIMIT 1", [message]).unwrap();
    }
    let first = fixture.store.recover_logical(0, 100).unwrap();
    assert_eq!(first.len(), 100);
    let next = fixture
        .store
        .recover_logical(first.last().unwrap().cursor, 100)
        .unwrap();
    assert_eq!(next.len(), 6);
    assert!(next[0].cursor > first.last().unwrap().cursor);
}

#[test]
fn outbox_schema_no_plaintext_or_capabilities() {
    let fixture = support::fixture(80000);
    let sql = support::sql(&fixture.root);
    let schema: String = sql
        .query_row(
            "SELECT group_concat(sql) FROM sqlite_master WHERE sql IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    for prohibited in [
        "payload",
        "append_cap",
        "read_cap",
        "admin_cap",
        "secret",
        "plaintext",
        "signed_package",
    ] {
        assert!(!schema.contains(prohibited));
    }
    drop(sql);
    drop(fixture.store);
    for name in ["client.sqlite3", "client.sqlite3-wal", "client.sqlite3-shm"] {
        if let Ok(bytes) = std::fs::read(fixture.root.join(name)) {
            assert!(!bytes.windows(512).any(|w| w.iter().all(|b| *b == 19)));
        }
    }
}

macro_rules! rejected {
    ($name:ident, $table:literal, $columns:literal) => {
        #[test]
        fn $name() {
            support::reject_insert($table, $columns);
        }
    };
}
rejected!(outbox_schema_unique_ciphertext, "ciphertext_objects", "*");
rejected!(outbox_schema_unique_logical, "logical_records", "*");
rejected!(outbox_schema_unique_recipient, "outgoing_recipients", "*");
rejected!(outbox_schema_unique_requirement, "required_objects", "*");
rejected!(outbox_schema_unique_upload, "upload_work", "*");
rejected!(outbox_schema_unique_receipt, "verified_receipts", "*");
rejected!(
    outbox_schema_ciphertext_short_hash,
    "ciphertext_objects",
    "x'01',wire,length"
);
rejected!(
    outbox_schema_ciphertext_wire_length,
    "ciphertext_objects",
    "randomblob(32),wire,length+1024"
);
rejected!(
    outbox_schema_ciphertext_padding,
    "ciphertext_objects",
    "randomblob(32),zeroblob(1025),1025"
);
rejected!(
    outbox_schema_ciphertext_maximum,
    "ciphertext_objects",
    "randomblob(32),zeroblob(66560),66560"
);
rejected!(
    outbox_schema_ciphertext_minimum,
    "ciphertext_objects",
    "randomblob(32),zeroblob(0),0"
);
rejected!(
    outbox_schema_logical_scope,
    "logical_records",
    "randomblob(32),roster,sender,randomblob(32),digest,kind,session,state,source_root"
);
rejected!(
    outbox_schema_logical_owner,
    "logical_records",
    "vault,roster,2,randomblob(32),digest,kind,session,state,source_root"
);
rejected!(
    outbox_schema_logical_digest,
    "logical_records",
    "vault,roster,sender,randomblob(32),x'01',kind,session,state,source_root"
);
rejected!(
    outbox_schema_logical_session,
    "logical_records",
    "vault,roster,sender,randomblob(32),digest,kind,x'01',state,source_root"
);
rejected!(
    outbox_schema_recipient_bounds,
    "outgoing_recipients",
    "vault,roster,sender,message_id,4,transfer,root_hash,state"
);
rejected!(
    outbox_schema_required_missing_object,
    "required_objects",
    "vault,roster,sender,message_id,recipient,274,randomblob(32),length"
);
rejected!(
    outbox_schema_required_wrong_length,
    "required_objects",
    "vault,roster,sender,message_id,recipient,274,hash,length+1024"
);
rejected!(
    outbox_schema_required_ordinal,
    "required_objects",
    "vault,roster,sender,message_id,recipient,275,hash,length"
);
rejected!(outbox_schema_upload_missing_requirement, "upload_work", "vault,roster,sender,message_id,recipient,randomblob(32),relay_key,run,mailbox,state,attempts,retry_at");
rejected!(
    outbox_schema_upload_negative_attempt,
    "upload_work",
    "vault,roster,sender,message_id,recipient,hash,randomblob(32),run,mailbox,state,-1,retry_at"
);
rejected!(outbox_schema_upload_overflow, "upload_work", "vault,roster,sender,message_id,recipient,hash,randomblob(32),run,mailbox,state,9223372036854775808,retry_at");
rejected!(outbox_schema_receipt_missing_upload, "verified_receipts", "vault,roster,sender,message_id,recipient,hash,randomblob(32),run,mailbox,length,sequence,retention,receipt");
rejected!(outbox_schema_receipt_zero_sequence, "verified_receipts", "vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox,length,0,retention,receipt");
rejected!(outbox_schema_receipt_negative_retention, "verified_receipts", "vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox,length,sequence,-1,receipt");
rejected!(outbox_schema_receipt_oversize, "verified_receipts", "vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox,length,sequence,retention,zeroblob(4097)");

#[test]
fn outbox_schema_corrupt_object_hash() {
    let fixture = support::fixture(10);
    let sql = support::sql(&fixture.root);
    let hash = [1u8; 32];
    sql.execute(
        "INSERT INTO ciphertext_objects VALUES(?1,zeroblob(1024),1024)",
        [hash],
    )
    .unwrap();
    assert!(fixture.store.saved_object(&hash).is_err());
}

#[test]
fn outbox_schema_immutable_saved_bytes() {
    let fixture = support::fixture(10);
    let sql = support::sql(&fixture.root);
    assert!(sql
        .execute("UPDATE ciphertext_objects SET wire=zeroblob(length)", [])
        .is_err());
    assert!(sql
        .execute("UPDATE logical_records SET digest=randomblob(32)", [])
        .is_err());
}

#[test]
fn outbox_schema_partial_extension_rejected() {
    let root = support::prior_root();
    let sql = support::sql(&root);
    let extension = include_str!("../src/schema.sql")
        .split("CREATE TABLE ciphertext_objects")
        .nth(1)
        .unwrap();
    let first = extension
        .split("CREATE TABLE logical_records")
        .next()
        .unwrap();
    sql.execute_batch(&format!("CREATE TABLE ciphertext_objects{first}"))
        .unwrap();
    drop(sql);
    assert!(ClientStore::open(&root, &support::roster(), 1).is_err());
    let sql = support::sql(&root);
    assert_eq!(
        sql.query_row::<i64, _, _>(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        3
    );
}

#[test]
fn outbox_schema_prior_mismatch_no_migration() {
    let root = support::prior_root();
    assert!(ClientStore::open(&root, &support::roster(), 2).is_err());
    let sql = support::sql(&root);
    assert_eq!(
        sql.query_row::<i64, _, _>(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        sql.query_row::<i64, _, _>("SELECT revision FROM config_versions", [], |r| r.get(0))
            .unwrap(),
        7
    );
}

#[test]
fn outbox_schema_unknown_catalog_rejected() {
    let root = support::prior_root();
    let sql = support::sql(&root);
    sql.execute_batch("CREATE TABLE unknown_extension (value BLOB);")
        .unwrap();
    drop(sql);
    assert!(ClientStore::open(&root, &support::roster(), 1).is_err());
}

#[test]
fn outbox_schema_prior_hash_pointer_preserved() {
    use loki_relay_client::ConfigReference;
    let root = support::prior_root();
    let ciphertext = b"public synthetic sealed-ciphertext fixture 6.1";
    let reference = ConfigReference::from_ciphertext(7, ciphertext).unwrap();
    std::fs::create_dir(root.join("secrets")).unwrap();
    std::fs::write(root.join(reference.file_name()), ciphertext).unwrap();
    std::fs::write(
        root.join("secrets/relay-config-0000000000000008.sealed"),
        b"orphan",
    )
    .unwrap();
    let sql = support::sql(&root);
    sql.execute("UPDATE config_versions SET hash=?1", [reference.hash()])
        .unwrap();
    let before: (i64, Vec<u8>, Vec<u8>, i64) = sql
        .query_row(
            "SELECT schema_version,vault,roster,owner FROM metadata",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    drop(sql);
    for _ in 0..2 {
        let store = ClientStore::open(&root, &support::roster(), 1).unwrap();
        assert_eq!(store.config_reference().unwrap(), Some(reference.clone()));
        let sql = support::sql(&root);
        let after = sql
            .query_row(
                "SELECT schema_version,vault,roster,owner FROM metadata",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            std::fs::read(root.join(reference.file_name())).unwrap(),
            ciphertext
        );
        assert_eq!(
            std::fs::read(root.join("secrets/relay-config-0000000000000008.sealed")).unwrap(),
            b"orphan"
        );
    }
}

#[test]
fn outbox_schema_prior_corrupt_reference_no_migration() {
    let root = support::prior_root();
    let sql = support::sql(&root);
    sql.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE config_versions SET hash=x'01';")
        .unwrap();
    drop(sql);
    assert!(ClientStore::open(&root, &support::roster(), 1).is_err());
    let sql = support::sql(&root);
    assert_eq!(
        sql.query_row::<i64, _, _>(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        sql.query_row::<Vec<u8>, _, _>("SELECT hash FROM config_versions", [], |r| r.get(0))
            .unwrap(),
        vec![1]
    );
}

#[test]
fn outbox_schema_prior_corrupt_schema_no_migration() {
    let root = support::prior_root();
    let sql = support::sql(&root);
    sql.execute_batch("DROP TRIGGER metadata_no_delete;")
        .unwrap();
    drop(sql);
    assert!(ClientStore::open(&root, &support::roster(), 1).is_err());
    let sql = support::sql(&root);
    assert_eq!(
        sql.query_row::<i64, _, _>(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
}

#[test]
fn outbox_schema_immutable_logical_identity() {
    let fixture = support::fixture(10);
    let sql = support::sql(&fixture.root);
    assert!(sql
        .execute("UPDATE logical_records SET digest=randomblob(32)", [])
        .is_err());
}

#[test]
fn outbox_schema_current_unknown_catalog_rejected() {
    let root = support::root();
    drop(ClientStore::open(&root, &support::roster(), 1).unwrap());
    let sql = support::sql(&root);
    sql.execute_batch("CREATE TABLE unknown_extension (value BLOB);")
        .unwrap();
    drop(sql);
    assert!(ClientStore::open(&root, &support::roster(), 1).is_err());
}

#[test]
fn outbox_schema_acknowledged_recovery_and_counter_maximum() {
    let fixture = support::fixture(10);
    let sql = support::sql(&fixture.root);
    sql.execute_batch("UPDATE upload_work SET state='acknowledged',attempts=9223372036854775807,retry_at=9223372036854775807 WHERE rowid=(SELECT rowid FROM upload_work LIMIT 1); UPDATE verified_receipts SET sequence=9223372036854775807,retention=9223372036854775807;").unwrap();
    let uploads = fixture.store.recover_uploads(0, 100).unwrap();
    assert_eq!(uploads.len(), 9);
    let completed = uploads.iter().find(|u| u.acknowledged).unwrap();
    assert_eq!(completed.attempts, i64::MAX as u64);
    assert_eq!(completed.retry_at, i64::MAX as u64);
    assert_eq!(
        fixture.store.saved_receipt(completed).unwrap(),
        Some(vec![1, 2, 3])
    );
}

fn atomic_body(size: usize) -> loki_relay_protocol::types::MessageBody {
    use loki_relay_protocol::types::{roster_digest, LogicalKey, MessageBody, Payload};
    let roster = support::roster();
    MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(&roster).unwrap(),
            sender: 1,
            message: [101; 32],
        },
        audience: vec![1, 2, 3],
        session: Some([102; 32]),
        prerequisites: vec![],
        payload: Payload::Test(vec![23; size]),
    }
}

fn assert_atomic_saved(store: &ClientStore, prepared: &loki_relay_client::PreparedOutbox) {
    let recipients = store.recover_recipients(prepared.key()).unwrap();
    assert_eq!(recipients.len(), 3);
    for (saved, original) in recipients.iter().zip(prepared.recipients()) {
        assert_eq!(saved.recipient, original.recipient());
        assert_eq!(saved.transfer.as_ref(), original.transfer());
        assert_eq!(&saved.root_hash, original.root_hash());
        assert!(saved.needs_route);
        let mut all = vec![];
        let mut after = None;
        loop {
            let page = store
                .recover_requirements(prepared.key(), saved.recipient, after.as_ref(), 100)
                .unwrap();
            if page.is_empty() {
                break;
            }
            after = Some(page.last().unwrap().hash);
            all.extend(page);
        }
        all.sort_by_key(|r| r.ordinal);
        assert_eq!(all.len(), original.objects().len());
        for (required, object) in all.iter().zip(original.objects()) {
            assert_eq!(required.hash, object.hash);
            assert_eq!(required.length, object.wire.len() as u64);
            assert_eq!(
                store.saved_object(&required.hash).unwrap().unwrap().wire,
                object.wire
            );
        }
    }
    assert!(store.recover_uploads(0, 100).unwrap().is_empty());
}

#[test]
fn outbox_atomic_complete_reopen_and_request_lookup() {
    use loki_relay_client::{outbox_intent_digest, prepare_outbox};
    for size in [10, 80000, 61440 * 101] {
        let body = atomic_body(size);
        let intent = outbox_intent_digest(&body).unwrap();
        let prepared = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
        let root = support::root();
        let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
        assert_eq!(
            store.lookup_outbox_request(&[103; 32], &intent).unwrap(),
            None
        );
        let result = store
            .commit_outbox(
                &support::roster(),
                &support::identity(1),
                &[103; 32],
                &prepared,
            )
            .unwrap();
        assert_eq!(&result.key, prepared.key());
        assert_eq!(&result.digest, prepared.digest());
        assert_eq!(result.kind, 1);
        assert_eq!(result.session, body.session);
        assert_atomic_saved(&store, &prepared);
        drop(store);
        let store = ClientStore::open(&root, &support::roster(), 1).unwrap();
        assert_eq!(
            store.lookup_outbox_request(&[103; 32], &intent).unwrap(),
            Some(result)
        );
        assert_atomic_saved(&store, &prepared);
    }
}

#[test]
fn outbox_atomic_randomized_retry_preserves_original() {
    use loki_relay_client::{outbox_intent_digest, prepare_outbox};
    for size in [10, 80000] {
        let mut body = atomic_body(size);
        let original = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
        let root = support::root();
        let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
        let first = store
            .commit_outbox(
                &support::roster(),
                &support::identity(1),
                &[104; 32],
                &original,
            )
            .unwrap();
        let fresh = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
        assert_ne!(
            fresh.recipients()[0].root_hash(),
            original.recipients()[0].root_hash()
        );
        assert_eq!(
            store
                .commit_outbox(
                    &support::roster(),
                    &support::identity(1),
                    &[104; 32],
                    &fresh
                )
                .unwrap(),
            first
        );
        assert_eq!(
            store
                .commit_outbox(
                    &support::roster(),
                    &support::identity(1),
                    &[105; 32],
                    &fresh
                )
                .unwrap(),
            first
        );
        body.key.message = [106; 32];
        let changed_id = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
        assert_eq!(
            store
                .commit_outbox(
                    &support::roster(),
                    &support::identity(1),
                    &[104; 32],
                    &changed_id
                )
                .unwrap(),
            first
        );
        assert_atomic_saved(&store, &original);
        assert!(store
            .saved_object(fresh.recipients()[0].root_hash())
            .unwrap()
            .is_none());
        assert!(store
            .saved_object(changed_id.recipients()[0].root_hash())
            .unwrap()
            .is_none());
        assert_eq!(store.recover_logical(0, 100).unwrap().len(), 1);
        assert_eq!(
            store
                .lookup_outbox_request(&[105; 32], &outbox_intent_digest(&body).unwrap())
                .unwrap(),
            Some(first)
        );
    }
}

#[test]
fn outbox_atomic_conflicts_preserve_original() {
    use loki_relay_client::{outbox_intent_digest, prepare_outbox, ClientError};
    let mut body = atomic_body(10);
    let original = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
    let root = support::root();
    let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    store
        .commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[107; 32],
            &original,
        )
        .unwrap();
    body.session = None;
    let intent = outbox_intent_digest(&body).unwrap();
    assert_eq!(
        store.lookup_outbox_request(&[107; 32], &intent),
        Err(ClientError::Conflict)
    );
    let conflicting = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
    assert_eq!(
        store.commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[107; 32],
            &conflicting
        ),
        Err(ClientError::Conflict)
    );
    assert_eq!(
        store.commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[108; 32],
            &conflicting
        ),
        Err(ClientError::Conflict)
    );
    body.key.message = [109; 32];
    let different = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
    assert_eq!(
        store.commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[107; 32],
            &different
        ),
        Err(ClientError::Conflict)
    );
    assert_atomic_saved(&store, &original);
    assert!(store
        .lookup_outbox_request(&[108; 32], &intent)
        .unwrap()
        .is_none());
    assert_eq!(store.recover_logical(0, 100).unwrap().len(), 1);
}

#[test]
fn outbox_atomic_intent_only_normalizes_own_message() {
    use loki_relay_client::outbox_intent_digest;
    use loki_relay_protocol::types::{MessageRef, Payload};
    let mut body = atomic_body(10);
    let expected = outbox_intent_digest(&body).unwrap();
    body.key.message = [1; 32];
    assert_eq!(outbox_intent_digest(&body).unwrap(), expected);
    for field in 0..8 {
        let mut changed = body.clone();
        match field {
            0 => changed.key.vault = [2; 32],
            1 => changed.key.roster = [2; 32],
            2 => changed.key.sender = 2,
            3 => changed.session = None,
            4 => {
                changed.prerequisites = vec![MessageRef {
                    sender: 2,
                    message: [4; 32],
                    digest: [5; 32],
                }]
            }
            5 => changed.payload = Payload::Test(vec![24; 10]),
            6 => changed.payload = Payload::Test(vec![23; 11]),
            _ => {
                let r = MessageRef {
                    sender: 2,
                    message: [4; 32],
                    digest: [5; 32],
                };
                changed.prerequisites = vec![r.clone()];
                changed.payload = Payload::Received(r);
            }
        }
        assert_ne!(outbox_intent_digest(&changed).unwrap(), expected);
    }
    body.audience = vec![1, 2];
    assert!(outbox_intent_digest(&body).is_err());
    body = atomic_body(16 * 1024 * 1024);
    assert!(outbox_intent_digest(&body).is_err());
}

#[test]
fn outbox_atomic_received_and_each_author() {
    use loki_relay_client::{outbox_intent_digest, prepare_outbox};
    use loki_relay_protocol::types::{MessageRef, Payload};
    for sender in 1..=3 {
        let mut body = atomic_body(10);
        body.key.sender = sender;
        let r = MessageRef {
            sender: if sender == 1 { 2 } else { 1 },
            message: [110; 32],
            digest: [111; 32],
        };
        body.prerequisites = vec![r.clone()];
        body.payload = Payload::Received(r);
        let prepared =
            prepare_outbox(&support::identity(sender), &support::roster(), &body).unwrap();
        let root = support::root();
        let mut store = ClientStore::open(&root, &support::roster(), sender).unwrap();
        let result = store
            .commit_outbox(
                &support::roster(),
                &support::identity(sender),
                &[112; 32],
                &prepared,
            )
            .unwrap();
        assert_eq!(result.kind, 2);
        assert_eq!(result.session, body.session);
        assert_eq!(
            result.source_root,
            *prepared
                .recipients()
                .iter()
                .find(|r| r.recipient() == sender)
                .unwrap()
                .root_hash()
        );
        assert_atomic_saved(&store, &prepared);
        drop(store);
        let store = ClientStore::open(&root, &support::roster(), sender).unwrap();
        assert_eq!(
            store
                .lookup_outbox_request(&[112; 32], &outbox_intent_digest(&body).unwrap())
                .unwrap(),
            Some(result)
        );
    }
}

#[test]
fn outbox_atomic_wrong_store_and_identity_no_rows() {
    use loki_relay_client::prepare_outbox;
    let prepared =
        prepare_outbox(&support::identity(1), &support::roster(), &atomic_body(10)).unwrap();
    for mode in 0..3 {
        let mut roster = support::roster();
        if mode == 1 {
            roster.vault = [113; 32];
        }
        if mode == 2 {
            let mut seed = [0u8; 66];
            seed[..2].copy_from_slice(&2u16.to_be_bytes());
            seed[2..].fill(99);
            roster.members[1] = loki_relay_client::CommIdentity::from_serialized(&seed)
                .unwrap()
                .public();
        }
        let root = support::root();
        let mut store = ClientStore::open(&root, &roster, if mode == 0 { 2 } else { 1 }).unwrap();
        assert!(store
            .commit_outbox(
                &support::roster(),
                &support::identity(1),
                &[114; 32],
                &prepared
            )
            .is_err());
        assert!(store.recover_logical(0, 100).unwrap().is_empty());
        assert!(store
            .saved_object(prepared.recipients()[0].root_hash())
            .unwrap()
            .is_none());
        assert!(store.recover_uploads(0, 100).unwrap().is_empty());
    }
    let root = support::root();
    let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    assert!(store
        .commit_outbox(
            &support::roster(),
            &support::identity(2),
            &[114; 32],
            &prepared
        )
        .is_err());
    assert!(store.recover_logical(0, 100).unwrap().is_empty());
}

#[test]
fn outbox_atomic_statement_failure_rolls_back_all_sets() {
    use loki_relay_client::{outbox_intent_digest, prepare_outbox};
    let body = atomic_body(80000);
    let prepared = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
    let root = support::root();
    let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    let sql = support::sql(&root);
    sql.execute(
        "INSERT INTO ciphertext_objects VALUES(?1,zeroblob(1024),1024)",
        [prepared.recipients()[2].root_hash()],
    )
    .unwrap();
    let prior: Vec<u8> = sql
        .query_row("SELECT wire FROM ciphertext_objects", [], |r| r.get(0))
        .unwrap();
    assert!(store
        .commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[115; 32],
            &prepared
        )
        .is_err());
    for table in [
        "logical_records",
        "outgoing_recipients",
        "required_objects",
        "caller_requests",
        "upload_work",
    ] {
        assert_eq!(
            sql.query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(
        sql.query_row::<i64, _, _>("SELECT count(*) FROM ciphertext_objects", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        sql.query_row::<Vec<u8>, _, _>("SELECT wire FROM ciphertext_objects", [], |r| r.get(0))
            .unwrap(),
        prior
    );
    assert!(store
        .lookup_outbox_request(&[115; 32], &outbox_intent_digest(&body).unwrap())
        .unwrap()
        .is_none());
    assert!(store
        .saved_object(prepared.recipients()[0].root_hash())
        .unwrap()
        .is_none());
}

fn reviewed_6_1_prefix_database(source: &std::path::Path, prefix: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let root = support::root();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let database = root.join("client.sqlite3");
    std::fs::File::create(&database).unwrap();
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    let sql = support::sql(&root);
    sql.execute_batch(prefix).unwrap();
    let source_database = source.join("client.sqlite3");
    sql.execute(
        "ATTACH DATABASE ?1 AS source",
        [source_database.to_str().unwrap()],
    )
    .unwrap();
    sql.execute_batch(
        "INSERT INTO metadata SELECT * FROM source.metadata;
         INSERT INTO ciphertext_objects SELECT * FROM source.ciphertext_objects;
         INSERT INTO logical_records SELECT * FROM source.logical_records;
         INSERT INTO outgoing_recipients SELECT * FROM source.outgoing_recipients;
         INSERT INTO required_objects SELECT * FROM source.required_objects;
         INSERT INTO upload_work SELECT * FROM source.upload_work;
         INSERT INTO verified_receipts SELECT * FROM source.verified_receipts;",
    )
    .unwrap();
    sql.execute("DETACH DATABASE source", []).unwrap();
    for name in [
        "client.sqlite3",
        "client.sqlite3-wal",
        "client.sqlite3-shm",
        "client.sqlite3-journal",
    ] {
        let path = root.join(name);
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    root
}

fn catalog_table_names(sql: &rusqlite::Connection) -> Vec<String> {
    sql.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn legacy_row_counts(sql: &rusqlite::Connection) -> Vec<i64> {
    [
        "metadata",
        "config_versions",
        "ciphertext_objects",
        "logical_records",
        "outgoing_recipients",
        "required_objects",
        "upload_work",
        "verified_receipts",
    ]
    .into_iter()
    .map(|table| {
        sql.query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    })
    .collect()
}

fn legacy_wire_digest(sql: &rusqlite::Connection) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut statement = sql
        .prepare("SELECT hash, wire FROM ciphertext_objects ORDER BY hash")
        .unwrap();
    let mut rows = statement.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        let hash: Vec<u8> = row.get(0).unwrap();
        let wire: Vec<u8> = row.get(1).unwrap();
        hasher.update(hash);
        hasher.update((wire.len() as u64).to_be_bytes());
        hasher.update(&wire);
    }
    hex::encode(hasher.finalize())
}

#[test]
fn outbox_atomic_reviewed_6_1_migration_exact_reopen() {
    use sha2::{Digest, Sha256};
    let fixture = support::fixture(80000);
    let prefix = include_str!("../src/schema.sql")
        .split("CREATE TABLE caller_requests")
        .next()
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(prefix)),
        "3f1da2e39b50fd5670b097cd90344be6561301cf0701cf053d3e2920e30651ea"
    );
    let root = reviewed_6_1_prefix_database(&fixture.root, prefix);
    let sql = support::sql(&root);
    sql.execute("INSERT INTO config_versions VALUES(1,7,?1)", [[88u8; 32]])
        .unwrap();
    let before: Vec<(String, String)> = sql
        .prepare("SELECT name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        catalog_table_names(&sql),
        [
            "ciphertext_objects",
            "config_versions",
            "logical_records",
            "metadata",
            "outgoing_recipients",
            "required_objects",
            "upload_work",
            "verified_receipts",
        ]
    );
    for later in [
        "ack_links",
        "caller_requests",
        "delivery_completion",
        "diagnostic_ids",
        "incoming_journal",
        "incoming_originals",
        "route_capture",
        "route_cursors",
        "upload_generation",
    ] {
        assert_eq!(
            sql.query_row::<i64, _, _>(
                "SELECT count(*) FROM sqlite_master WHERE name=?1",
                [later],
                |row| row.get(0)
            )
            .unwrap(),
            0,
            "reviewed 6.1 prefix must not contain {later}"
        );
    }
    let counts = legacy_row_counts(&sql);
    let wires = legacy_wire_digest(&sql);
    drop(sql);
    drop(fixture.store);
    for _ in 0..2 {
        let store = ClientStore::open(&root, &support::roster(), 1).unwrap();
        assert_eq!(
            store.config_reference().unwrap(),
            Some(loki_relay_client::ConfigReference::new(7, [88; 32]).unwrap())
        );
        for recipient in fixture.prepared.recipients() {
            for object in recipient.objects() {
                assert_eq!(
                    store.saved_object(&object.hash).unwrap().unwrap().wire,
                    object.wire
                );
            }
        }
        let sql = support::sql(&root);
        for (name, expected) in &before {
            assert_eq!(
                sql.query_row::<String, _, _>(
                    "SELECT sql FROM sqlite_master WHERE name=?1",
                    [name],
                    |r| r.get(0)
                )
                .unwrap(),
                *expected
            );
        }
        assert_eq!(
            sql.query_row::<i64, _, _>("SELECT schema_version FROM metadata", [], |r| r.get(0))
                .unwrap(),
            1
        );
        assert_eq!(
            sql.query_row::<i64, _, _>("SELECT count(*) FROM caller_requests", [], |r| r.get(0))
                .unwrap(),
            0
        );
        assert_eq!(legacy_row_counts(&sql), counts);
        assert_eq!(legacy_wire_digest(&sql), wires);
        assert_eq!(
            catalog_table_names(&sql),
            [
                "ack_links",
                "caller_requests",
                "ciphertext_objects",
                "config_versions",
                "delivery_completion",
                "diagnostic_ids",
                "download_auth_wait",
                "download_rejections",
                "early_received_refs",
                "incoming_application",
                "incoming_conflict_objects",
                "incoming_conflicts",
                "incoming_dependencies",
                "incoming_journal",
                "incoming_original_objects",
                "incoming_originals",
                "incomplete_leases",
                "logical_records",
                "metadata",
                "outgoing_recipients",
                "page_diagnostics",
                "pending_downloads",
                "quarantine_samples",
                "received_work",
                "reference_rejections",
                "required_objects",
                "route_capture",
                "route_cursors",
                "source_rejections",
                "staged_coverage",
                "staged_requirements",
                "staged_sources",
                "transfer_groups",
                "upload_generation",
                "upload_work",
                "verified_receipts",
            ]
        );
    }
}

#[test]
fn outbox_atomic_partial_request_catalog_rejected() {
    let root = support::root();
    drop(ClientStore::open(&root, &support::roster(), 1).unwrap());
    let sql = support::sql(&root);
    sql.execute_batch("DROP TRIGGER caller_requests_no_delete;")
        .unwrap();
    drop(sql);
    assert!(ClientStore::open(&root, &support::roster(), 1).is_err());
}

fn atomic_request_constraint(columns: &str) {
    let body = atomic_body(10);
    let prepared =
        loki_relay_client::prepare_outbox(&support::identity(1), &support::roster(), &body)
            .unwrap();
    let root = support::root();
    let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    store
        .commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[128; 32],
            &prepared,
        )
        .unwrap();
    let sql = support::sql(&root);
    assert!(
        sql.execute(
            &format!("INSERT INTO caller_requests SELECT {columns} FROM caller_requests LIMIT 1"),
            []
        )
        .is_err(),
        "invalid request binding must refuse"
    );
    assert_eq!(
        store
            .lookup_outbox_request(
                &[128; 32],
                &loki_relay_client::outbox_intent_digest(&body).unwrap()
            )
            .unwrap()
            .unwrap()
            .key,
        *prepared.key()
    );
    assert_atomic_saved(&store, &prepared);
}
macro_rules! request_rejected {
    ($name:ident,$columns:literal) => {
        #[test]
        fn $name() {
            atomic_request_constraint($columns);
        }
    };
}
request_rejected!(outbox_atomic_request_unique, "*");
request_rejected!(
    outbox_atomic_request_id_bound,
    "x'01',intent_digest,vault,roster,sender,message_id"
);
request_rejected!(
    outbox_atomic_request_intent_bound,
    "randomblob(32),x'01',vault,roster,sender,message_id"
);
request_rejected!(
    outbox_atomic_request_vault_bound,
    "randomblob(32),intent_digest,x'01',roster,sender,message_id"
);
request_rejected!(
    outbox_atomic_request_roster_bound,
    "randomblob(32),intent_digest,vault,x'01',sender,message_id"
);
request_rejected!(
    outbox_atomic_request_sender_bound,
    "randomblob(32),intent_digest,vault,roster,4,message_id"
);
request_rejected!(
    outbox_atomic_request_message_bound,
    "randomblob(32),intent_digest,vault,roster,sender,x'01'"
);
request_rejected!(
    outbox_atomic_request_missing_logical,
    "randomblob(32),intent_digest,vault,roster,sender,randomblob(32)"
);

fn atomic_immutable(query: &str) {
    let body = atomic_body(10);
    let prepared =
        loki_relay_client::prepare_outbox(&support::identity(1), &support::roster(), &body)
            .unwrap();
    let root = support::root();
    let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    store
        .commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[129; 32],
            &prepared,
        )
        .unwrap();
    let sql = support::sql(&root);
    assert!(
        sql.execute(query, []).is_err(),
        "durable binding must remain immutable"
    );
    assert_atomic_saved(&store, &prepared);
    assert!(store
        .lookup_outbox_request(
            &[129; 32],
            &loki_relay_client::outbox_intent_digest(&body).unwrap()
        )
        .unwrap()
        .is_some());
}
macro_rules! immutable_rejected {
    ($name:ident,$query:literal) => {
        #[test]
        fn $name() {
            atomic_immutable($query);
        }
    };
}
immutable_rejected!(
    outbox_atomic_request_immutable_update,
    "UPDATE caller_requests SET intent_digest=randomblob(32)"
);
immutable_rejected!(
    outbox_atomic_request_immutable_delete,
    "DELETE FROM caller_requests"
);
immutable_rejected!(
    outbox_atomic_recipient_immutable_update,
    "UPDATE outgoing_recipients SET transfer=randomblob(32)"
);
immutable_rejected!(
    outbox_atomic_requirement_immutable_update,
    "UPDATE required_objects SET ordinal=ordinal+1"
);
immutable_rejected!(
    outbox_atomic_requirement_immutable_delete,
    "DELETE FROM required_objects"
);
immutable_rejected!(
    outbox_atomic_recipient_immutable_delete,
    "DELETE FROM outgoing_recipients"
);
immutable_rejected!(
    outbox_atomic_logical_immutable_delete,
    "DELETE FROM logical_records"
);
immutable_rejected!(
    outbox_atomic_ciphertext_immutable_delete,
    "DELETE FROM ciphertext_objects"
);

#[test]
fn outbox_atomic_saved_corruption_fails_closed() {
    use loki_relay_client::{outbox_intent_digest, prepare_outbox};
    for corrupt in ["UPDATE ciphertext_objects SET wire=zeroblob(length) WHERE hash=(SELECT hash FROM required_objects WHERE recipient=2 LIMIT 1)", "UPDATE required_objects SET ordinal=10 WHERE recipient=2", "DELETE FROM outgoing_recipients WHERE recipient=2"] {
        let body=atomic_body(10);let prepared=prepare_outbox(&support::identity(1),&support::roster(),&body).unwrap();
        let root=support::root();let mut store=ClientStore::open(&root,&support::roster(),1).unwrap();store.commit_outbox(&support::roster(),&support::identity(1),&[130;32],&prepared).unwrap();
        let sql=support::sql(&root);
        let triggers:[(&str,&str);3]=[("ciphertext_objects_no_update","CREATE TRIGGER ciphertext_objects_no_update BEFORE UPDATE ON ciphertext_objects\nBEGIN SELECT RAISE(ABORT, 'immutable ciphertext'); END"),("required_objects_no_update","CREATE TRIGGER required_objects_no_update BEFORE UPDATE ON required_objects\nBEGIN SELECT RAISE(ABORT, 'immutable requirement'); END"),("outgoing_recipients_no_delete","CREATE TRIGGER outgoing_recipients_no_delete BEFORE DELETE ON outgoing_recipients\nBEGIN SELECT RAISE(ABORT, 'immutable recipient'); END")];
        sql.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        for (name,_) in triggers {sql.execute_batch(&format!("DROP TRIGGER {name};")).unwrap();}
        sql.execute_batch(corrupt).unwrap();
        for (_,ddl) in triggers {sql.execute_batch(ddl).unwrap();}
        assert!(store.lookup_outbox_request(&[130;32],&outbox_intent_digest(&body).unwrap()).is_err());
        let fresh=prepare_outbox(&support::identity(1),&support::roster(),&body).unwrap();
        assert!(store.commit_outbox(&support::roster(),&support::identity(1),&[130;32],&fresh).is_err());
        assert!(store.saved_object(fresh.recipients()[0].root_hash()).unwrap().is_none());
    }
}

#[test]
fn outbox_atomic_pending_budget_preserves_original() {
    use loki_relay_client::{outbox_intent_digest, prepare_outbox, ClientError};
    let root = support::root();
    let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    let mut first = None;
    for n in 0u32..42 {
        let mut body = atomic_body(10);
        body.key.message[..4].copy_from_slice(&n.to_be_bytes());
        let prepared = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
        let mut request = [131; 32];
        request[..4].copy_from_slice(&n.to_be_bytes());
        store
            .commit_outbox(
                &support::roster(),
                &support::identity(1),
                &request,
                &prepared,
            )
            .unwrap();
        if n == 0 {
            first = Some((body, prepared, request));
        }
    }
    let sql = support::sql(&root);
    assert_eq!(
        sql.query_row::<i64, _, _>("SELECT count(*) FROM outgoing_recipients", [], |r| r.get(0))
            .unwrap(),
        126
    );
    let counts = |sql: &rusqlite::Connection| {
        [
            "ciphertext_objects",
            "logical_records",
            "outgoing_recipients",
            "required_objects",
            "caller_requests",
            "upload_work",
        ]
        .map(|table| {
            sql.query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        })
    };
    let before = counts(&sql);
    let mut body = atomic_body(80000);
    body.key.message = [132; 32];
    let refused = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
    assert_eq!(
        store.commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[133; 32],
            &refused
        ),
        Err(ClientError::Capacity)
    );
    assert_eq!(counts(&sql), before);
    assert!(store
        .lookup_outbox_request(&[133; 32], &outbox_intent_digest(&body).unwrap())
        .unwrap()
        .is_none());
    assert!(store
        .saved_object(refused.recipients()[0].root_hash())
        .unwrap()
        .is_none());
    let (body, first, request) = first.unwrap();
    let intent = outbox_intent_digest(&body).unwrap();
    let original = store
        .lookup_outbox_request(&request, &intent)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .commit_outbox(&support::roster(), &support::identity(1), &request, &first)
            .unwrap(),
        original
    );
    assert_atomic_saved(&store, &first);
    store
        .commit_outbox(
            &support::roster(),
            &support::identity(1),
            &[134; 32],
            &first,
        )
        .unwrap();
    assert_eq!(
        sql.query_row::<i64, _, _>("SELECT count(*) FROM outgoing_recipients", [], |r| r.get(0))
            .unwrap(),
        126
    );
    assert_eq!(
        sql.query_row::<i64, _, _>("SELECT count(*) FROM caller_requests", [], |r| r.get(0))
            .unwrap(),
        43
    );
    drop(sql);
    drop(store);
    let store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    assert_eq!(
        store.lookup_outbox_request(&request, &intent).unwrap(),
        Some(original)
    );
    assert_atomic_saved(&store, &first);
}

#[test]
fn outbox_atomic_saved_signed_binding_refuses_corruption() {
    use loki_relay_client::prepare_outbox;
    for assignment in [
        "digest=randomblob(32)",
        "kind=2",
        "session=NULL",
        "source_root=(SELECT root_hash FROM outgoing_recipients WHERE recipient=2 LIMIT 1)",
    ] {
        let body = atomic_body(10);
        let prepared = prepare_outbox(&support::identity(1), &support::roster(), &body).unwrap();
        let root = support::root();
        let mut store = ClientStore::open(&root, &support::roster(), 1).unwrap();
        store
            .commit_outbox(
                &support::roster(),
                &support::identity(1),
                &[150; 32],
                &prepared,
            )
            .unwrap();
        let sql = support::sql(&root);
        sql.execute_batch("DROP TRIGGER logical_records_identity;")
            .unwrap();
        sql.execute_batch(&format!("UPDATE logical_records SET {assignment}; CREATE TRIGGER logical_records_identity BEFORE UPDATE ON logical_records\nBEGIN SELECT RAISE(ABORT, 'immutable logical record'); END;")).unwrap();
        assert!(
            store
                .commit_outbox(
                    &support::roster(),
                    &support::identity(1),
                    &[150; 32],
                    &prepared
                )
                .is_err(),
            "saved signed association must refuse corruption"
        );
        for r in prepared.recipients() {
            for o in r.objects() {
                assert_eq!(store.saved_object(&o.hash).unwrap().unwrap().wire, o.wire);
            }
        }
    }
}

mod receipt_binding {
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_client::{ClientError, RelayHttp, Secret32};
    use loki_relay_protocol::{
        canonical::{self, Value},
        http::{self, ErrorCode},
        receipt,
        types::{Entry, Id32, Object, Page, ReceiptBody, RelayPin, RelayRoute},
    };
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }
    fn key() -> Id32 {
        signer().verifying_key().to_bytes()
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
    fn sign(body: &[u8]) -> [u8; 64] {
        let mut input = b"Loki_Relay_Stored_v1\0".to_vec();
        input.extend_from_slice(&(u32::try_from(body.len()).unwrap()).to_be_bytes());
        input.extend_from_slice(body);
        signer().sign(&input).to_bytes()
    }
    fn pack(body: &ReceiptBody) -> Vec<u8> {
        let encoded = receipt::encode_body(body).unwrap();
        canonical::encode(&Value::Array(vec![
            Value::Bytes(encoded),
            Value::Bytes(sign(&receipt::encode_body(body).unwrap()).to_vec()),
        ]))
        .unwrap()
    }
    fn body(hash: Id32, len: u64, sequence: u64) -> ReceiptBody {
        ReceiptBody {
            pin: RelayPin {
                key: key(),
                run: [2; 32],
            },
            mailbox: [3; 32],
            hash,
            wire_length: len,
            sequence,
            retention: 1,
        }
    }
    fn serve(
        status: u16,
        headers: &str,
        payload: Vec<u8>,
    ) -> (RelayRoute, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let headers = headers.to_owned();
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = [0; 8192];
            let _ = stream.read(&mut buf);
            let response = format!("HTTP/1.1 {status} X\r\n{headers}Connection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&payload);
        });
        (
            RelayRoute {
                pin: RelayPin {
                    key: key(),
                    run: [2; 32],
                },
                endpoint: format!("http://127.0.0.1:{port}"),
                mailbox: [3; 32],
                append_revision: 1,
            },
            task,
        )
    }
    fn cbor(status: u16, payload: Vec<u8>) -> (RelayRoute, std::thread::JoinHandle<()>) {
        serve(
            status,
            &format!(
                "Content-Type: application/cbor\r\nContent-Length: {}\r\n",
                payload.len()
            ),
            payload,
        )
    }
    fn http() -> RelayHttp {
        RelayHttp::new().unwrap()
    }
    fn append() -> Secret32 {
        Secret32::from_bytes([4; 32])
    }
    fn read_secret() -> Secret32 {
        Secret32::from_bytes([5; 32])
    }
    trait ErrOnly {
        type Error;
        fn err_only(self, claim: &str) -> Self::Error;
    }
    impl<T, E> ErrOnly for Result<T, E> {
        type Error = E;
        fn err_only(self, claim: &str) -> E {
            assert!(self.is_err(), "{claim}");
            match self {
                Err(error) => error,
                Ok(_) => unreachable!("{claim}"),
            }
        }
    }

    #[tokio::test]
    async fn receipt_binding_put_exact() {
        let saved = object(7);
        for status in [201, 200] {
            let bytes = pack(&body(saved.hash, 1024, 4));
            let (route, server) = cbor(status, bytes.clone());
            let receipt = http().put(&route, &append(), &saved).await.unwrap();
            assert_eq!(receipt.bytes(), bytes.as_slice());
            assert_eq!(receipt.body().hash, saved.hash);
            assert_eq!(receipt.body().sequence, 4);
            assert_eq!(receipt.body().retention, 1);
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn receipt_binding_get_exact() {
        let saved = object(8);
        let (route, server) = serve(
            200,
            &format!(
                "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
                saved.wire.len()
            ),
            saved.wire.clone(),
        );
        let got = http()
            .get(&route, &read_secret(), &saved.hash)
            .await
            .unwrap();
        assert_eq!(got.wire, saved.wire);
        assert_eq!(got.hash, saved.hash);
        server.join().unwrap();
    }

    fn entry(sequence: u64, saved: &Object) -> Entry {
        Entry {
            sequence,
            hash: saved.hash,
            wire_length: saved.wire.len() as u64,
            receipt: pack(&body(saved.hash, saved.wire.len() as u64, sequence)),
        }
    }
    fn page(after: u64, high: u64, entries: Vec<Entry>) -> Vec<u8> {
        let next = entries.last().map(|entry| entry.sequence).unwrap_or(after);
        http::encode_page(&Page {
            mailbox: [3; 32],
            after,
            next,
            high_water: high,
            entries,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn receipt_binding_entries_exact() {
        let saved = object(9);
        let full = page(0, 5, vec![entry(1, &saved), entry(2, &saved)]);
        let (route, server) = cbor(200, full.clone());
        let got = http()
            .entries(&route, &read_secret(), 0, Some(2))
            .await
            .unwrap();
        assert_eq!(got.entries().len(), 2);
        assert_eq!(got.next(), 2);
        assert_eq!(got.high_water(), 5);
        assert_eq!(got.entries()[1].receipt().bytes(), entry(2, &saved).receipt);
        server.join().unwrap();
        let tail = page(0, 1, vec![entry(1, &saved)]);
        let (route, server) = cbor(200, tail);
        let got = http()
            .entries(&route, &read_secret(), 0, Some(100))
            .await
            .unwrap();
        assert_eq!(got.entries().len(), 1);
        assert_eq!(got.next(), 1);
        server.join().unwrap();
        let empty = page(4, 4, vec![]);
        let (route, server) = cbor(200, empty);
        let got = http()
            .entries(&route, &read_secret(), 4, None)
            .await
            .unwrap();
        assert!(got.entries().is_empty());
        assert_eq!(got.after(), 4);
        assert_eq!(got.next(), 4);
        server.join().unwrap();
    }

    async fn put_receipt(receipt: ReceiptBody) -> ClientError {
        let saved = object(7);
        let (route, server) = cbor(201, pack(&receipt));
        let error = http()
            .put(&route, &append(), &saved)
            .await
            .err_only("response was accepted");
        server.join().unwrap();
        error
    }

    #[tokio::test]
    async fn receipt_binding_pin_key() {
        let saved = object(7);
        let mut receipt = body(saved.hash, 1024, 1);
        receipt.pin.key = [8; 32];
        assert_eq!(put_receipt(receipt).await, ClientError::Config);
    }

    #[tokio::test]
    async fn receipt_binding_pin_run() {
        let saved = object(7);
        let mut receipt = body(saved.hash, 1024, 1);
        receipt.pin.run = [8; 32];
        assert_eq!(put_receipt(receipt).await, ClientError::Config);
    }

    #[tokio::test]
    async fn receipt_binding_mailbox() {
        let saved = object(7);
        let mut receipt = body(saved.hash, 1024, 1);
        receipt.mailbox = [8; 32];
        assert_eq!(put_receipt(receipt).await, ClientError::Receipt);
    }

    #[tokio::test]
    async fn receipt_binding_hash() {
        let receipt = body([8; 32], 1024, 1);
        assert_eq!(put_receipt(receipt).await, ClientError::Receipt);
    }

    #[tokio::test]
    async fn receipt_binding_length() {
        let saved = object(7);
        let receipt = body(saved.hash, 2048, 1);
        assert_eq!(put_receipt(receipt).await, ClientError::Receipt);
    }

    #[tokio::test]
    async fn receipt_binding_entry_sequence() {
        let saved = object(9);
        let mut listed = entry(1, &saved);
        listed.receipt = pack(&body(saved.hash, 1024, 2));
        let encoded = page(0, 1, vec![listed]);
        let (route, server) = cbor(200, encoded);
        let error = http()
            .entries(&route, &read_secret(), 0, Some(1))
            .await
            .err_only("response was accepted");
        server.join().unwrap();
        assert_eq!(error, ClientError::Receipt);
    }

    #[tokio::test]
    async fn receipt_binding_signature() {
        let saved = object(7);
        let encoded = receipt::encode_body(&body(saved.hash, 1024, 1)).unwrap();
        let mut signature = sign(&encoded);
        signature[63] ^= 1;
        let bytes = canonical::encode(&Value::Array(vec![
            Value::Bytes(encoded),
            Value::Bytes(signature.to_vec()),
        ]))
        .unwrap();
        let (route, server) = cbor(201, bytes);
        let error = http()
            .put(&route, &append(), &saved)
            .await
            .err_only("response was accepted");
        server.join().unwrap();
        assert_eq!(error, ClientError::Receipt);
    }

    #[tokio::test]
    async fn receipt_binding_retention_and_zero_sequence() {
        let saved = object(7);
        let mut retention = body(saved.hash, 1024, 1);
        retention.retention = 2;
        let encoded = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(retention.pin.key.to_vec()),
            Value::Bytes(retention.pin.run.to_vec()),
            Value::Bytes(retention.mailbox.to_vec()),
            Value::Bytes(retention.hash.to_vec()),
            Value::Integer(retention.wire_length.into()),
            Value::Integer(retention.sequence.into()),
            Value::Integer(2.into()),
        ]))
        .unwrap();
        let bytes = canonical::encode(&Value::Array(vec![
            Value::Bytes(encoded.clone()),
            Value::Bytes(sign(&encoded).to_vec()),
        ]))
        .unwrap();
        let (route, server) = cbor(201, bytes);
        assert_eq!(
            http()
                .put(&route, &append(), &saved)
                .await
                .err_only("response was accepted"),
            ClientError::Receipt
        );
        server.join().unwrap();
        let mut zero = body(saved.hash, 1024, 1);
        zero.sequence = 0;
        let encoded = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(zero.pin.key.to_vec()),
            Value::Bytes(zero.pin.run.to_vec()),
            Value::Bytes(zero.mailbox.to_vec()),
            Value::Bytes(zero.hash.to_vec()),
            Value::Integer(1024.into()),
            Value::Integer(0.into()),
            Value::Integer(1.into()),
        ]))
        .unwrap();
        let bytes = canonical::encode(&Value::Array(vec![
            Value::Bytes(encoded.clone()),
            Value::Bytes(sign(&encoded).to_vec()),
        ]))
        .unwrap();
        let (route, server) = cbor(201, bytes);
        assert_eq!(
            http()
                .put(&route, &append(), &saved)
                .await
                .err_only("response was accepted"),
            ClientError::Receipt
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_noncanonical() {
        let saved = object(7);
        let mut bytes = pack(&body(saved.hash, 1024, 1));
        bytes.push(0);
        let (route, server) = cbor(201, bytes);
        assert_eq!(
            http()
                .put(&route, &append(), &saved)
                .await
                .err_only("response was accepted"),
            ClientError::Receipt
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_put_status() {
        let saved = object(7);
        let (route, server) = cbor(204, pack(&body(saved.hash, 1024, 1)));
        assert_eq!(
            http()
                .put(&route, &append(), &saved)
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_put_accepted_202() {
        let saved = object(7);
        let bytes = pack(&body(saved.hash, 1024, 1));
        let (route, server) = cbor(202, bytes);
        let result = http().put(&route, &append(), &saved).await;
        server.join().unwrap();
        assert!(result.is_err(), "disallowed success status was accepted");
        assert_eq!(
            result.err_only("disallowed success status was accepted"),
            ClientError::Transport
        );
    }

    #[tokio::test]
    async fn receipt_binding_get_status() {
        let saved = object(8);
        let (route, server) = serve(
            201,
            &format!(
                "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
                saved.wire.len()
            ),
            saved.wire.clone(),
        );
        assert_eq!(
            http()
                .get(&route, &read_secret(), &saved.hash)
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_entries_status() {
        let saved = object(9);
        let (route, server) = cbor(201, page(0, 1, vec![entry(1, &saved)]));
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(1))
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_media() {
        let saved = object(7);
        let bytes = pack(&body(saved.hash, 1024, 1));
        let (route, server) = serve(
            201,
            &format!(
                "Content-Type: text/plain\r\nContent-Length: {}\r\n",
                bytes.len()
            ),
            bytes,
        );
        assert_eq!(
            http()
                .put(&route, &append(), &saved)
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_encoding() {
        let saved = object(7);
        let bytes = pack(&body(saved.hash, 1024, 1));
        let (route, server) = serve(
            201,
            &format!(
                "Content-Type: application/cbor\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n",
                bytes.len()
            ),
            bytes,
        );
        assert_eq!(
            http()
                .put(&route, &append(), &saved)
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    fn hold_route(port: u16) -> RelayRoute {
        RelayRoute {
            pin: RelayPin {
                key: key(),
                run: [2; 32],
            },
            endpoint: format!("http://127.0.0.1:{port}"),
            mailbox: [3; 32],
            append_revision: 1,
        }
    }

    fn hold_tail(
        content_type: &str,
        payload: Vec<u8>,
    ) -> (RelayRoute, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let content_type = content_type.to_owned();
        listener.set_nonblocking(true).unwrap();
        let task = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if started.elapsed() < std::time::Duration::from_secs(3) => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let header = format!("HTTP/1.1 200 X\r\nContent-Type: {content_type}\r\n\r\n");
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&payload);
            let _ = stream.flush();
            std::thread::sleep(std::time::Duration::from_millis(2000));
        });
        (hold_route(port), task)
    }

    fn hold_length(
        content_type: &str,
        declared: usize,
    ) -> (RelayRoute, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let content_type = content_type.to_owned();
        listener.set_nonblocking(true).unwrap();
        let task = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if started.elapsed() < std::time::Duration::from_secs(3) => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 200 X\r\nContent-Type: {content_type}\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.flush();
            std::thread::sleep(std::time::Duration::from_millis(2000));
            let _ = stream.write_all(&vec![0x11; declared]);
        });
        (hold_route(port), task)
    }

    async fn refuse_before_tail<T>(
        call: impl std::future::Future<Output = Result<T, ClientError>>,
        server: std::thread::JoinHandle<()>,
        claim: &str,
    ) {
        let result = tokio::time::timeout(std::time::Duration::from_millis(1000), call).await;
        let _ = server.join();
        assert!(result.is_ok(), "{claim}");
        assert_eq!(result.unwrap().err_only(claim), ClientError::Transport);
    }

    #[tokio::test]
    async fn receipt_binding_object_cap() {
        let payload = vec![0x11u8; 65537];
        let hash: Id32 = Sha256::digest(&payload).into();
        let (route, server) = hold_tail("application/octet-stream", payload);
        refuse_before_tail(
            http().get(&route, &read_secret(), &hash),
            server,
            "object stream cap waited for the held tail",
        )
        .await;
        let (route, server) = hold_length("application/octet-stream", 65537);
        refuse_before_tail(
            http().get(&route, &read_secret(), &hash),
            server,
            "object content-length cap waited for the held body",
        )
        .await;
    }

    #[tokio::test]
    async fn receipt_binding_page_cap() {
        let (route, server) = hold_tail("application/cbor", vec![1; 128 * 1024 + 1]);
        refuse_before_tail(
            http().entries(&route, &read_secret(), 0, Some(1)),
            server,
            "page stream cap waited for the held tail",
        )
        .await;
    }

    #[tokio::test]
    async fn receipt_binding_receipt_cap() {
        let saved = object(7);
        let (route, server) = hold_tail("application/cbor", vec![1; 4097]);
        refuse_before_tail(
            http().put(&route, &append(), &saved),
            server,
            "receipt stream cap waited for the held tail",
        )
        .await;
    }

    #[tokio::test]
    async fn receipt_binding_sha256() {
        let saved = object(8);
        let (route, server) = serve(
            200,
            &format!(
                "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
                saved.wire.len()
            ),
            saved.wire,
        );
        assert_eq!(
            http()
                .get(&route, &read_secret(), &[9; 32])
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_framing() {
        let mut wire = vec![3; 1024];
        wire[..8].copy_from_slice(b"NOTAREAL");
        wire[8] = 1;
        let hash: Id32 = Sha256::digest(&wire).into();
        let (route, server) = serve(
            200,
            &format!(
                "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
                wire.len()
            ),
            wire,
        );
        assert_eq!(
            http()
                .get(&route, &read_secret(), &hash)
                .await
                .err_only("response was accepted"),
            ClientError::Wire(loki_relay_protocol::WireError::Schema)
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_page_mailbox() {
        let saved = object(9);
        let encoded = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(vec![8; 32]),
            Value::Integer(0.into()),
            Value::Integer(1.into()),
            Value::Integer(1.into()),
            Value::Array(vec![Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(saved.hash.to_vec()),
                Value::Integer(1024.into()),
                Value::Bytes({
                    let mut receipt = body(saved.hash, 1024, 1);
                    receipt.mailbox = [8; 32];
                    pack(&receipt)
                }),
            ])]),
        ]))
        .unwrap();
        let (route, server) = cbor(200, encoded);
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(1))
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_page_short_valid_receipts() {
        let saved = object(9);
        let encoded = page(0, 5, vec![entry(1, &saved)]);
        let (route, server) = cbor(200, encoded);
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(2))
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_page_empty_when_h_above_c() {
        let encoded = page(0, 4, vec![]);
        let (route, server) = cbor(200, encoded);
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(1))
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_page_after() {
        let saved = object(9);
        let encoded = page(1, 2, vec![entry(2, &saved)]);
        let (route, server) = cbor(200, encoded);
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(1))
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_page_gap() {
        let saved = object(9);
        let encoded = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(vec![3; 32]),
            Value::Integer(0.into()),
            Value::Integer(3.into()),
            Value::Integer(3.into()),
            Value::Array(vec![
                Value::Array(vec![
                    Value::Integer(1.into()),
                    Value::Bytes(saved.hash.to_vec()),
                    Value::Integer(1024.into()),
                    Value::Bytes(pack(&body(saved.hash, 1024, 1))),
                ]),
                Value::Array(vec![
                    Value::Integer(3.into()),
                    Value::Bytes(saved.hash.to_vec()),
                    Value::Integer(1024.into()),
                    Value::Bytes(pack(&body(saved.hash, 1024, 3))),
                ]),
            ]),
        ]))
        .unwrap();
        let (route, server) = cbor(200, encoded);
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(2))
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_limit_local() {
        for limit in [Some(0), Some(101)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let route = RelayRoute {
                pin: RelayPin {
                    key: key(),
                    run: [2; 32],
                },
                endpoint: format!("http://127.0.0.1:{port}"),
                mailbox: [3; 32],
                append_revision: 1,
            };
            assert_eq!(
                http()
                    .entries(&route, &read_secret(), 0, limit)
                    .await
                    .err_only("response was accepted"),
                ClientError::Wire(loki_relay_protocol::WireError::Bounds)
            );
            assert!(listener.accept().is_err());
        }
    }

    #[tokio::test]
    async fn receipt_binding_cursor() {
        let body = http::encode_error(ErrorCode::CursorAhead).unwrap();
        let (route, server) = cbor(409, body);
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 9, Some(1))
                .await
                .err_only("response was accepted"),
            ClientError::Cursor
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_retry_after() {
        let body = http::encode_error(ErrorCode::AdmissionLimit).unwrap();
        let (route, server) = serve(
            429,
            &format!(
                "Content-Type: application/cbor\r\nRetry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\nContent-Length: {}\r\n",
                body.len()
            ),
            body.clone(),
        );
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(1))
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
        let (route, server) = serve(
            429,
            &format!(
                "Content-Type: application/cbor\r\nRetry-After: 1\r\nContent-Length: {}\r\n",
                body.len()
            ),
            body,
        );
        assert_eq!(
            http()
                .entries(&route, &read_secret(), 0, Some(1))
                .await
                .err_only("response was accepted"),
            ClientError::Capacity
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn receipt_binding_endpoint() {
        let route = RelayRoute {
            pin: RelayPin {
                key: key(),
                run: [2; 32],
            },
            endpoint: "http://127.0.0.1:9/v1".into(),
            mailbox: [3; 32],
            append_revision: 1,
        };
        assert_eq!(
            http()
                .put(&route, &append(), &object(7))
                .await
                .err_only("response was accepted"),
            ClientError::Config
        );
    }

    #[tokio::test]
    async fn receipt_binding_endpoint_owned() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = stop.clone();
        let server = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut contacts = 0usize;
            while !done.load(std::sync::atomic::Ordering::SeqCst)
                && started.elapsed() < std::time::Duration::from_secs(12)
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        contacts += 1;
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                        let mut buf = [0u8; 8192];
                        let _ = stream.read(&mut buf);
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(2)),
                }
            }
            contacts
        });
        let route = RelayRoute {
            pin: RelayPin {
                key: key(),
                run: [2; 32],
            },
            endpoint: format!("http://127.0.0.1:{port}/v1"),
            mailbox: [3; 32],
            append_revision: 1,
        };
        let result = http().put(&route, &append(), &object(7)).await;
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let contacts = server.join().unwrap();
        assert_eq!(
            contacts, 0,
            "endpoint preflight contacted the owned listener"
        );
        assert_eq!(
            result.err_only("invalid endpoint was accepted"),
            ClientError::Config
        );
    }

    #[tokio::test]
    async fn receipt_binding_redirect() {
        let saved = object(7);
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        second.set_nonblocking(true).unwrap();
        let port = second.local_addr().unwrap().port();
        let bytes = pack(&body(saved.hash, 1024, 1));
        let (route, server) = serve(
            302,
            &format!(
                "Content-Type: application/cbor\r\nLocation: http://127.0.0.1:{port}/\r\nContent-Length: {}\r\n",
                bytes.len()
            ),
            bytes,
        );
        assert_eq!(
            http()
                .put(&route, &append(), &saved)
                .await
                .err_only("response was accepted"),
            ClientError::Transport
        );
        server.join().unwrap();
        assert!(second.accept().is_err());
    }

    #[tokio::test]
    async fn receipt_binding_missing_object() {
        let body = http::encode_error(ErrorCode::ObjectNotFound).unwrap();
        let (route, server) = cbor(404, body);
        assert_eq!(
            http()
                .get(&route, &read_secret(), &[4; 32])
                .await
                .err_only("response was accepted"),
            ClientError::MissingObjects(vec![[4; 32]])
        );
        server.join().unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn receipt_binding_proxy_child() {
        let saved = object(7);
        let bytes = pack(&body(saved.hash, 1024, 1));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if started.elapsed() < std::time::Duration::from_secs(3) => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 201 X\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&bytes);
        });
        let route = RelayRoute {
            pin: RelayPin {
                key: key(),
                run: [2; 32],
            },
            endpoint: format!("http://127.0.0.1:{port}"),
            mailbox: [3; 32],
            append_revision: 1,
        };
        let result = http().put(&route, &append(), &saved).await;
        let _ = server.join();
        assert!(result.is_ok(), "proxied put failed");
    }

    #[test]
    fn receipt_binding_proxy_disabled() {
        let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        proxy.set_nonblocking(true).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = stop.clone();
        let server = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut requests = 0;
            while !done.load(std::sync::atomic::Ordering::SeqCst)
                && started.elapsed() < std::time::Duration::from_secs(15)
            {
                if proxy.accept().is_ok() {
                    requests += 1;
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            }
            requests
        });
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "receipt_binding::receipt_binding_proxy_child",
                "--exact",
                "--ignored",
            ])
            .env("HTTP_PROXY", format!("http://127.0.0.1:{port}"))
            .env("http_proxy", format!("http://127.0.0.1:{port}"))
            .env("ALL_PROXY", format!("http://127.0.0.1:{port}"))
            .env("all_proxy", format!("http://127.0.0.1:{port}"))
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut child_out = child.stdout.take().unwrap();
        let mut child_err = child.stderr.take().unwrap();
        let out_task = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = child_out.read_to_end(&mut buf);
            buf
        });
        let err_task = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = child_err.read_to_end(&mut buf);
            buf
        });
        let started = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(Some(status)),
                Ok(None) if started.elapsed() < std::time::Duration::from_secs(8) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Ok(None);
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(error);
                }
            }
        };
        let stdout_bytes = out_task.join().unwrap();
        let stderr_bytes = err_task.join().unwrap();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::write("/tmp/relay-6.3-evidence/proxy-child.stdout", &stdout_bytes);
        let _ = std::fs::write("/tmp/relay-6.3-evidence/proxy-child.stderr", &stderr_bytes);
        let requests = server.join().unwrap();
        let _ = std::fs::write(
            "/tmp/relay-6.3-evidence/proxy-requests.txt",
            requests.to_string(),
        );
        let stdout = String::from_utf8_lossy(&stdout_bytes);
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                panic!("proxy child wait failed: {error}; requests={requests}\n{stdout}{stderr}")
            }
        };
        assert!(
            status.is_some(),
            "owned proxy child exceeded the deadline: {stdout}{stderr}"
        );
        assert!(
            stdout.contains("running 1 test")
                && stdout.contains("receipt_binding::receipt_binding_proxy_child"),
            "proxy child filter matched nothing: {stdout}{stderr}"
        );
        assert_eq!(requests, 0, "proxy observed {requests} requests");
        assert!(
            stdout.contains("receipt_binding::receipt_binding_proxy_child ... ok")
                && stdout.contains("1 passed")
                && stdout.contains("0 failed"),
            "proxy child did not pass: {stdout}{stderr}"
        );
        assert!(status.unwrap().success(), "proxy child failed: {stderr}");
    }
}

fn scrub_crash_output(text: &str) -> String {
    text.lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("bearer ") && !lower.contains("authorization:")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn crash_metric(line: &str, label: &str) -> Option<u64> {
    let index = line.find(label)?;
    line[..index].split_whitespace().last()?.parse().ok()
}

#[test]
fn outbox_crash() {
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "test",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"),
            "-p",
            "loki-relay-client",
            "--locked",
            "--offline",
            "--lib",
            "outbox_crash",
            "--",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let result = stdout
        .lines()
        .rev()
        .find(|line| line.contains("test result:"))
        .unwrap_or("missing test result");
    println!("{result}");
    if !output.status.success() {
        panic!(
            "library outbox_crash failed\n{}\n{}",
            scrub_crash_output(&stdout),
            scrub_crash_output(&stderr)
        );
    }
    for name in [
        "outbox_crash_before_commit_no_put",
        "outbox_crash_after_commit_retains_wires",
        "outbox_crash_commit_then_upload_puts",
        "outbox_crash_put_before_receipt_retries_original",
        "outbox_crash_receipt_page_full",
    ] {
        assert!(
            stdout
                .lines()
                .any(|line| line.contains(name) && line.contains("... ok")),
            "library case did not pass: {name}\n{}\n{}",
            scrub_crash_output(&stdout),
            scrub_crash_output(&stderr)
        );
    }
    let passed = crash_metric(result, " passed").unwrap_or(0);
    let failed = crash_metric(result, " failed").unwrap_or(1);
    assert!(
        passed >= 1,
        "library outbox_crash executed no cases: {result}"
    );
    assert_eq!(
        failed, 0,
        "library outbox_crash reported failures: {result}"
    );
}

mod upload_retry_failover {
    use super::support;
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_client::{
        open_descriptor, prepare_outbox, seal_descriptor, upload_pending, ClientConfig,
        ClientStore, ConfigReference, Descriptor, DescriptorRelay, OwnerInbox, RelayHttp,
        RelayRuntime, Secret32, ThirdPass,
    };
    use loki_relay_protocol::{
        canonical::{self, Value},
        receipt,
        types::{
            roster_digest, Id32, LogicalKey, MessageBody, Payload, ReceiptBody, RelayPin,
            RelayRoute, Roster,
        },
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeSet, HashMap},
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
        thread,
        time::Duration,
    };

    const HEADER_CAP: usize = 8192;
    const BODY_CAP: usize = 65536;
    const SOCKET_WAIT: Duration = Duration::from_secs(2);
    const SEEDS: [[u8; 32]; 3] = [[31; 32], [32; 32], [33; 32]];

    fn evidence(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = PathBuf::from("/private/tmp/relay-6.4a-evidence").join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn roster() -> Roster {
        support::roster()
    }

    fn body(message: Id32, payload: Vec<u8>) -> MessageBody {
        let roster = roster();
        MessageBody {
            key: LogicalKey {
                vault: roster.vault,
                roster: roster_digest(&roster).unwrap(),
                sender: 1,
                message,
            },
            audience: vec![1, 2, 3],
            session: Some([64; 32]),
            prerequisites: vec![],
            payload: Payload::Test(payload),
        }
    }

    fn relay_key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn sorted_seeds() -> [u8; 3] {
        let mut order = [0u8, 1, 2];
        order.sort_by_key(|index| relay_key(SEEDS[*index as usize][0]));
        order
    }

    fn mailbox(owner: u8, relay: u8) -> Id32 {
        let mut id = [0; 32];
        id[0] = owner;
        id[1] = relay;
        id
    }

    fn run_id(relay: u8) -> Id32 {
        let mut id = [100; 32];
        id[0] = relay;
        id
    }

    fn route_for(owner: u8, relay: u8, port: u16, key: &SigningKey) -> RelayRoute {
        RelayRoute {
            pin: RelayPin {
                key: key.verifying_key().to_bytes(),
                run: run_id(relay),
            },
            endpoint: format!("http://127.0.0.1:{port}"),
            mailbox: mailbox(owner, relay),
            append_revision: 1,
        }
    }

    fn signed_receipt(
        key: &SigningKey,
        route: &RelayRoute,
        hash: Id32,
        wire_length: u64,
        sequence: u64,
    ) -> Vec<u8> {
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
            Value::Bytes(key.sign(&input).to_bytes().to_vec()),
        ]))
        .unwrap()
    }

    fn descriptor_for(owner: u16, port: u16) -> Descriptor {
        let roster = roster();
        let mut relays: Vec<_> = (0..3u8)
            .map(|relay| {
                let key = SigningKey::from_bytes(&SEEDS[usize::from(relay)]);
                DescriptorRelay {
                    route: route_for(owner as u8, relay, port, &key),
                    append: Secret32::from_bytes([180 + relay; 32]),
                }
            })
            .collect();
        relays.sort_by(|left, right| left.route.pin.key.cmp(&right.route.pin.key));
        Descriptor::new(
            roster.vault,
            roster_digest(&roster).unwrap(),
            owner,
            1,
            relays,
        )
    }

    fn opened(owner: u16, recipient: u16, port: u16) -> loki_relay_client::AuthenticatedDescriptor {
        let roster = roster();
        let sealed = seal_descriptor(
            &support::identity(owner),
            &roster,
            &descriptor_for(owner, port),
            &support::identity(recipient).public(),
        )
        .unwrap();
        open_descriptor(&support::identity(recipient), &roster, &sealed.wire).unwrap()
    }

    struct SavedPut {
        body: Vec<u8>,
        receipt: Vec<u8>,
        sequence: u64,
        hits: u64,
    }

    struct PeerShot {
        sequence: u64,
        hits: u64,
        receipt: Vec<u8>,
    }

    struct PeerState {
        saved: HashMap<(Id32, Id32), SavedPut>,
        sequences: HashMap<Id32, u64>,
        drop_first: bool,
        append_base: Option<u8>,
        admit: Option<u64>,
        admitted: u64,
        bearers: Vec<(u8, [u8; 32])>,
    }

    struct Peer {
        port: u16,
        stop: Arc<AtomicBool>,
        state: Arc<Mutex<PeerState>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Peer {
        fn start(down_seed: Option<u8>, drop_first: bool) -> Self {
            Self::open(down_seed, drop_first, None, None)
        }

        fn open(
            down_seed: Option<u8>,
            drop_first: bool,
            append_base: Option<u8>,
            admit: Option<u64>,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let state = Arc::new(Mutex::new(PeerState {
                saved: HashMap::new(),
                sequences: HashMap::new(),
                drop_first,
                append_base,
                admit,
                admitted: 0,
                bearers: Vec::new(),
            }));
            let thread_stop = Arc::clone(&stop);
            let thread_state = Arc::clone(&state);
            let thread =
                thread::spawn(move || serve(listener, down_seed, thread_stop, thread_state));
            Self {
                port,
                stop,
                state,
                thread: Some(thread),
            }
        }

        fn shot(&self, mailbox: &Id32, hash: &Id32) -> Option<PeerShot> {
            let state = self.state.lock().unwrap();
            state.saved.get(&(*mailbox, *hash)).map(|saved| PeerShot {
                sequence: saved.sequence,
                hits: saved.hits,
                receipt: saved.receipt.clone(),
            })
        }

        fn body_matches(&self, mailbox: &Id32, hash: &Id32, body: &[u8]) -> bool {
            self.state
                .lock()
                .unwrap()
                .saved
                .get(&(*mailbox, *hash))
                .is_some_and(|saved| saved.body == body)
        }

        fn requests(&self) -> Vec<(u8, [u8; 32])> {
            self.state.lock().unwrap().bearers.clone()
        }
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
        headers.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn read_put(stream: &mut TcpStream) -> Option<(Id32, Id32, Vec<u8>, [u8; 32])> {
        stream.set_nonblocking(false).ok()?;
        stream.set_read_timeout(Some(SOCKET_WAIT)).ok()?;
        stream.set_write_timeout(Some(SOCKET_WAIT)).ok()?;
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        while header.len() < HEADER_CAP {
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
        let headers = String::from_utf8_lossy(&header);
        let content_length = header_value(&headers, "content-length")?
            .parse::<usize>()
            .ok()?;
        if content_length > BODY_CAP {
            return None;
        }
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body).ok()?;
        let path = headers.lines().next()?.split_whitespace().nth(1)?;
        let mut parts = path.split('/');
        if parts.next() != Some("")
            || parts.next() != Some("v1")
            || parts.next() != Some("mailboxes")
        {
            return None;
        }
        let mailbox = hex::decode(parts.next()?).ok()?;
        if parts.next() != Some("objects") {
            return None;
        }
        let hash = hex::decode(parts.next()?).ok()?;
        let auth = header_value(&headers, "authorization")
            .map(|value| <[u8; 32]>::from(Sha256::digest(value.as_bytes())))
            .unwrap_or([0; 32]);
        Some((mailbox.try_into().ok()?, hash.try_into().ok()?, body, auth))
    }

    fn write_receipt(stream: &mut TcpStream, receipt: &[u8]) {
        let response = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            receipt.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(receipt);
        let _ = stream.shutdown(Shutdown::Both);
    }

    fn write_cbor(stream: &mut TcpStream, status: u16, reason: &str, body: &[u8]) {
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.shutdown(Shutdown::Both);
    }

    fn b64url(bytes: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut index = 0;
        while index + 3 <= bytes.len() {
            let value = ((bytes[index] as u32) << 16)
                | ((bytes[index + 1] as u32) << 8)
                | bytes[index + 2] as u32;
            out.push(ALPHABET[((value >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((value >> 12) & 63) as usize] as char);
            out.push(ALPHABET[((value >> 6) & 63) as usize] as char);
            out.push(ALPHABET[(value & 63) as usize] as char);
            index += 3;
        }
        let value = ((bytes[30] as u32) << 16) | ((bytes[31] as u32) << 8);
        out.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        out.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        out
    }

    fn bearer_hash(secret: &[u8; 32]) -> [u8; 32] {
        let encoded = b64url(secret);
        let mut header = Vec::with_capacity(7 + encoded.len());
        header.extend_from_slice(b"Bearer ");
        header.extend_from_slice(encoded.as_bytes());
        Sha256::digest(&header).into()
    }

    fn serve(
        listener: TcpListener,
        down_seed: Option<u8>,
        stop: Arc<AtomicBool>,
        state: Arc<Mutex<PeerState>>,
    ) {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let Some((mailbox, hash, body, auth)) = read_put(&mut stream) else {
                        continue;
                    };
                    if down_seed == Some(mailbox[1]) || Sha256::digest(&body).as_slice() != hash {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let relay = usize::from(mailbox[1]);
                    if relay >= SEEDS.len() {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let mut peer = state.lock().unwrap();
                    peer.bearers.push((mailbox[1], auth));
                    if let Some(base) = peer.append_base {
                        let mut secret = [base.wrapping_add(mailbox[1]); 32];
                        let expected = bearer_hash(&secret);
                        secret.fill(0);
                        if auth != expected {
                            drop(peer);
                            write_cbor(&mut stream, 401, "Unauthorized", &[0x82, 1, 2]);
                            continue;
                        }
                    }
                    let key = (mailbox, hash);
                    if let Some(saved) = peer.saved.get_mut(&key) {
                        if saved.body != body {
                            drop(peer);
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        saved.hits += 1;
                        let receipt = saved.receipt.clone();
                        drop(peer);
                        write_receipt(&mut stream, &receipt);
                        continue;
                    }
                    if peer.admit.is_some_and(|limit| peer.admitted >= limit) {
                        drop(peer);
                        write_cbor(&mut stream, 507, "Insufficient Storage", &[0x82, 1, 10]);
                        continue;
                    }
                    peer.admitted += 1;
                    let sequence = peer.sequences.entry(mailbox).or_insert(0);
                    *sequence += 1;
                    let sequence = *sequence;
                    let signer = SigningKey::from_bytes(&SEEDS[relay]);
                    let route = RelayRoute {
                        pin: RelayPin {
                            key: signer.verifying_key().to_bytes(),
                            run: run_id(mailbox[1]),
                        },
                        endpoint: "http://127.0.0.1:9".to_string(),
                        mailbox,
                        append_revision: 1,
                    };
                    let receipt =
                        signed_receipt(&signer, &route, hash, body.len() as u64, sequence);
                    let drop_first = peer.drop_first;
                    peer.saved.insert(
                        key,
                        SavedPut {
                            body,
                            receipt,
                            sequence,
                            hits: 1,
                        },
                    );
                    drop(peer);
                    if drop_first {
                        let _ = stream.shutdown(Shutdown::Both);
                    } else if let Some(saved) = state.lock().unwrap().saved.get(&key) {
                        write_receipt(&mut stream, &saved.receipt);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    }

    fn capture(prepared: &loki_relay_client::PreparedOutbox) -> HashMap<Id32, Vec<u8>> {
        let mut wires = HashMap::new();
        for recipient in prepared.recipients() {
            for object in recipient.objects() {
                assert!(
                    wires.insert(object.hash, object.wire.clone()).is_none(),
                    "recipient copies reused an object hash"
                );
            }
        }
        wires
    }

    fn install(
        store: &mut ClientStore,
        roster: &Roster,
        port: u16,
    ) -> (ClientConfig, loki_relay_client::AuthenticatedDescriptor) {
        let alice = support::identity(1);
        let sealed =
            seal_descriptor(&alice, roster, &descriptor_for(1, port), &alice.public()).unwrap();
        let self_route = open_descriptor(&alice, roster, &sealed.wire).unwrap();
        store
            .record_config_revision(&ConfigReference::from_ciphertext(1, &sealed.wire).unwrap())
            .unwrap();
        let own = self_route
            .body()
            .relays
            .iter()
            .map(|relay| OwnerInbox {
                route: relay.route.clone(),
                read: Secret32::from_bytes([210; 32]),
                append: Secret32::from_bytes(*relay.append.as_bytes()),
                admin: Secret32::from_bytes([211; 32]),
            })
            .collect();
        let peers = vec![opened(2, 1, port), opened(3, 1, port)];
        (ClientConfig { own, peers }, self_route)
    }

    fn rows(store: &ClientStore) -> Vec<loki_relay_client::RecoveryUpload> {
        store.recover_uploads(0, 100).unwrap()
    }

    fn assert_wires(store: &ClientStore, wires: &HashMap<Id32, Vec<u8>>) {
        for (hash, wire) in wires {
            let saved = store
                .saved_object(hash)
                .unwrap()
                .expect("saved object missing");
            assert_eq!(saved.wire.len(), wire.len(), "saved wire length changed");
            assert!(saved.wire == *wire, "saved wire bytes changed");
        }
    }

    #[test]
    fn upload_retry_failover_each_unavailable_pin() {
        let order = sorted_seeds();
        let third = relay_key(SEEDS[usize::from(order[2])][0]);
        for (chunked, payload) in [(false, vec![19u8, 29, 39]), (true, vec![29u8; 80_000])] {
            for down in 0..3usize {
                let down_seed = order[down];
                let prepared = prepare_outbox(
                    &support::identity(1),
                    &roster(),
                    &body(
                        [70 + down as u8 + u8::from(chunked) * 10; 32],
                        payload.clone(),
                    ),
                )
                .unwrap();
                let object_count = prepared.recipients()[0].objects().len();
                assert_eq!(prepared.recipients().len(), 3);
                assert_eq!(
                    object_count > 1,
                    chunked,
                    "object set was not the requested shape"
                );
                assert!(prepared
                    .recipients()
                    .iter()
                    .all(|recipient| recipient.objects().len() == object_count));
                let wires = capture(&prepared);
                let peer = Peer::start(Some(down_seed), false);
                let root = evidence(if chunked {
                    "chunked-down"
                } else {
                    "ordinary-down"
                })
                .join("client");
                let roster = roster();
                let alice = support::identity(1);
                let mut store = ClientStore::open(&root, &roster, 1).unwrap();
                let logical = store
                    .commit_outbox(&roster, &alice, &[80 + down as u8; 32], &prepared)
                    .unwrap();
                let (config, self_route) = install(&mut store, &roster, peer.port);
                assert_eq!(self_route.body().relays[2].route.pin.key, third);
                let http = RelayHttp::new().unwrap();
                let runtime = RelayRuntime::new().unwrap();
                let pass = runtime
                    .block_on(upload_pending(
                        &mut store,
                        &http,
                        &logical,
                        &roster,
                        &alice,
                        &config,
                        &self_route,
                        10_000,
                        ThirdPass::StopAfterStored,
                    ))
                    .unwrap();
                assert!(pass.needs_route.is_empty(), "a recipient stayed unrouted");
                let report = store
                    .delivery_report(&roster, &alice, &logical, &config, &self_route)
                    .unwrap();
                let live: BTreeSet<_> = (0..3usize)
                    .filter(|index| *index != down)
                    .map(|index| relay_key(SEEDS[usize::from(order[index])][0]))
                    .collect();
                let whole: BTreeSet<_> = report.whole_pins().iter().map(|pin| pin.0).collect();
                assert_eq!(
                    whole, live,
                    "pin {down} chunked={chunked} did not leave the other two pins as the whole-vault pair"
                );
                if down != 2 {
                    assert!(
                        whole.contains(&third),
                        "reachable third pin skipped before whole-vault Stored; pin {down} chunked={chunked}"
                    );
                }
                assert!(report.whole_vault(), "whole-vault Stored was not proven");
                for member in 1..=3u16 {
                    assert!(
                        report.member_stored(member),
                        "recipient {member} was not stored"
                    );
                    let member_pins: BTreeSet<_> =
                        report.member_pins(member).iter().map(|pin| pin.0).collect();
                    assert_eq!(
                        member_pins, live,
                        "recipient {member} used a different pin pair"
                    );
                }
                let uploads = rows(&store);
                assert_eq!(uploads.len(), object_count * 9);
                for upload in &uploads {
                    let wire = &wires[&upload.hash];
                    if upload.relay_key == relay_key(SEEDS[usize::from(down_seed)][0]) {
                        assert!(!upload.acknowledged, "unavailable pin was acknowledged");
                        assert!(store.saved_receipt(upload).unwrap().is_none());
                        assert!(peer.shot(&upload.mailbox, &upload.hash).is_none());
                        if down == 2 {
                            assert_eq!(
                                upload.attempts, 0,
                                "unavailable greatest pin was attempted after Stored"
                            );
                            assert!(
                                pass.stopped_third,
                                "optional third was not stopped after Stored"
                            );
                        } else {
                            assert!(
                                upload.attempts >= 1,
                                "unavailable reachable pin was not attempted"
                            );
                        }
                    } else {
                        assert!(
                            upload.acknowledged,
                            "live pin did not acknowledge the object"
                        );
                        let shot = peer
                            .shot(&upload.mailbox, &upload.hash)
                            .expect("live pin stored nothing");
                        assert!(
                            peer.body_matches(&upload.mailbox, &upload.hash, wire),
                            "live pin stored other bytes"
                        );
                        assert_eq!(shot.hits, 1);
                        assert_eq!(store.saved_receipt(upload).unwrap().unwrap(), shot.receipt);
                    }
                }
                assert_wires(&store, &wires);
                drop(store);
                let mut store = ClientStore::open(&root, &roster, 1).unwrap();
                let reopened = store
                    .delivery_report(&roster, &alice, &logical, &config, &self_route)
                    .unwrap();
                assert!(reopened.whole_vault(), "reopen lost whole-vault Stored");
                let again: BTreeSet<_> = reopened.whole_pins().iter().map(|pin| pin.0).collect();
                assert_eq!(again, live, "reopen changed the pin pair");
                for upload in rows(&store) {
                    if upload.relay_key == relay_key(SEEDS[usize::from(down_seed)][0]) {
                        assert!(
                            !upload.acknowledged,
                            "reopen acknowledged the unavailable pin"
                        );
                    }
                }
                assert_wires(&store, &wires);
            }
        }
    }

    #[test]
    fn upload_retry_failover_lost_response_then_continue_third() {
        let prepared = prepare_outbox(
            &support::identity(1),
            &roster(),
            &body([91; 32], vec![19, 29, 39]),
        )
        .unwrap();
        assert_eq!(prepared.recipients()[0].objects().len(), 1);
        let wires = capture(&prepared);
        let peer = Peer::start(None, true);
        let root = evidence("lost").join("client");
        let roster = roster();
        let alice = support::identity(1);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let logical = store
            .commit_outbox(&roster, &alice, &[92; 32], &prepared)
            .unwrap();
        let (config, self_route) = install(&mut store, &roster, peer.port);
        let third = self_route.body().relays[2].route.pin.key;
        let http = RelayHttp::new().unwrap();
        let runtime = RelayRuntime::new().unwrap();
        let first = runtime
            .block_on(upload_pending(
                &mut store,
                &http,
                &logical,
                &roster,
                &alice,
                &config,
                &self_route,
                10_000,
                ThirdPass::StopAfterStored,
            ))
            .unwrap();
        assert!(
            !first.stopped_third,
            "StopAfterStored skipped a reachable third before whole-vault Stored"
        );
        let mut retry_at = 0;
        let mut first_shots = HashMap::new();
        for upload in rows(&store) {
            assert!(upload.attempts >= 1, "a reachable pin was not attempted");
            assert!(!upload.acknowledged);
            assert!(store.saved_receipt(&upload).unwrap().is_none());
            assert!(
                peer.body_matches(&upload.mailbox, &upload.hash, &wires[&upload.hash]),
                "lost response stored different bytes"
            );
            let shot = peer
                .shot(&upload.mailbox, &upload.hash)
                .expect("lost put was not stored");
            assert_eq!(shot.hits, 1);
            assert!(shot.sequence >= 1);
            retry_at = retry_at.max(upload.retry_at);
            first_shots.insert((upload.mailbox, upload.hash), (shot.sequence, shot.receipt));
        }
        assert_wires(&store, &wires);
        drop(store);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        assert!(rows(&store).iter().all(|upload| !upload.acknowledged));
        let second = runtime
            .block_on(upload_pending(
                &mut store,
                &http,
                &logical,
                &roster,
                &alice,
                &config,
                &self_route,
                retry_at,
                ThirdPass::StopAfterStored,
            ))
            .unwrap();
        let report = store
            .delivery_report(&roster, &alice, &logical, &config, &self_route)
            .unwrap();
        assert!(
            report.whole_vault(),
            "retry did not prove whole-vault Stored"
        );
        assert!(
            second.stopped_third,
            "third work did not survive after Stored"
        );
        for upload in rows(&store) {
            let (sequence, receipt) = &first_shots[&(upload.mailbox, upload.hash)];
            let shot = peer.shot(&upload.mailbox, &upload.hash).unwrap();
            assert_eq!(shot.sequence, *sequence, "retry assigned a new sequence");
            assert_eq!(shot.receipt, *receipt, "retry replaced the saved receipt");
            assert!(peer.body_matches(&upload.mailbox, &upload.hash, &wires[&upload.hash]));
            if upload.relay_key == third {
                assert!(
                    !upload.acknowledged,
                    "StopAfterStored acknowledged optional third work"
                );
                assert!(store.saved_receipt(&upload).unwrap().is_none());
                assert_eq!(shot.hits, 1, "optional third was retried after Stored");
            } else {
                assert!(upload.acknowledged, "pair retry stayed pending");
                assert_eq!(shot.hits, 2, "pair retry was not the saved put");
                assert_eq!(store.saved_receipt(&upload).unwrap().unwrap(), shot.receipt);
            }
        }
        assert_wires(&store, &wires);
        let third_pass = runtime
            .block_on(upload_pending(
                &mut store,
                &http,
                &logical,
                &roster,
                &alice,
                &config,
                &self_route,
                retry_at,
                ThirdPass::ContinueThird,
            ))
            .unwrap();
        assert!(!third_pass.stopped_third, "ContinueThird reported a stop");
        for upload in rows(&store) {
            let (sequence, receipt) = &first_shots[&(upload.mailbox, upload.hash)];
            let shot = peer.shot(&upload.mailbox, &upload.hash).unwrap();
            assert_eq!(shot.sequence, *sequence);
            assert_eq!(shot.receipt, *receipt);
            assert!(upload.acknowledged, "ContinueThird left work pending");
            assert_eq!(store.saved_receipt(&upload).unwrap().unwrap(), shot.receipt);
            assert!(peer.body_matches(&upload.mailbox, &upload.hash, &wires[&upload.hash]));
            if upload.relay_key == third {
                assert_eq!(
                    shot.hits, 2,
                    "ContinueThird did not reuse the original third put"
                );
            }
        }
        assert_wires(&store, &wires);
        let final_report = store
            .delivery_report(&roster, &alice, &logical, &config, &self_route)
            .unwrap();
        assert!(final_report.whole_vault());
    }

    fn evidence_c(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = PathBuf::from("/private/tmp/relay-6.4c-evidence").join(format!(
            "{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn descriptor_custom(
        owner: u16,
        port: u16,
        revision: u64,
        append_revision: u64,
        append_base: u8,
    ) -> Descriptor {
        let roster = roster();
        let mut relays: Vec<_> = (0..3u8)
            .map(|relay| {
                let key = SigningKey::from_bytes(&SEEDS[usize::from(relay)]);
                let mut route = route_for(owner as u8, relay, port, &key);
                route.append_revision = append_revision;
                DescriptorRelay {
                    route,
                    append: Secret32::from_bytes([append_base.wrapping_add(relay); 32]),
                }
            })
            .collect();
        relays.sort_by(|left, right| left.route.pin.key.cmp(&right.route.pin.key));
        Descriptor::new(
            roster.vault,
            roster_digest(&roster).unwrap(),
            owner,
            revision,
            relays,
        )
    }

    fn open_member(
        owner: u16,
        port: u16,
        revision: u64,
        append_revision: u64,
        append_base: u8,
    ) -> loki_relay_client::AuthenticatedDescriptor {
        let roster = roster();
        let sealed = seal_descriptor(
            &support::identity(owner),
            &roster,
            &descriptor_custom(owner, port, revision, append_revision, append_base),
            &support::identity(1).public(),
        )
        .unwrap();
        open_descriptor(&support::identity(1), &roster, &sealed.wire).unwrap()
    }

    fn view(
        store: &mut ClientStore,
        roster: &Roster,
        port: u16,
        revision: u64,
        append_revision: u64,
        append_base: u8,
        config_revision: Option<u64>,
        peers: &[u16],
    ) -> (ClientConfig, loki_relay_client::AuthenticatedDescriptor) {
        let alice = support::identity(1);
        let sealed = seal_descriptor(
            &alice,
            roster,
            &descriptor_custom(1, port, revision, append_revision, append_base),
            &alice.public(),
        )
        .unwrap();
        let self_route = open_descriptor(&alice, roster, &sealed.wire).unwrap();
        if let Some(config_revision) = config_revision {
            store
                .record_config_revision(
                    &ConfigReference::from_ciphertext(config_revision, &sealed.wire).unwrap(),
                )
                .unwrap();
        }
        let own = self_route
            .body()
            .relays
            .iter()
            .map(|relay| OwnerInbox {
                route: relay.route.clone(),
                read: Secret32::from_bytes([210; 32]),
                append: Secret32::from_bytes(*relay.append.as_bytes()),
                admin: Secret32::from_bytes([211; 32]),
            })
            .collect();
        let peers = peers
            .iter()
            .copied()
            .map(|owner| open_member(owner, port, revision, append_revision, append_base))
            .collect();
        (ClientConfig { own, peers }, self_route)
    }

    fn drive(
        runtime: &RelayRuntime,
        store: &mut ClientStore,
        http: &RelayHttp,
        logical: &loki_relay_client::RecoveryLogical,
        roster: &Roster,
        config: &ClientConfig,
        self_route: &loki_relay_client::AuthenticatedDescriptor,
        now: u64,
    ) -> loki_relay_client::UploadPass {
        runtime
            .block_on(upload_pending(
                store,
                http,
                logical,
                roster,
                &support::identity(1),
                config,
                self_route,
                now,
                ThirdPass::StopAfterStored,
            ))
            .unwrap()
    }

    fn identity_rows(store: &ClientStore, key: &LogicalKey) -> Vec<(u16, Option<Id32>, Id32)> {
        store
            .recover_recipients(key)
            .unwrap()
            .into_iter()
            .map(|row| (row.recipient, row.transfer, row.root_hash))
            .collect()
    }

    fn assert_identity(
        store: &ClientStore,
        key: &LogicalKey,
        wires: &HashMap<Id32, Vec<u8>>,
        before: &[(u16, Option<Id32>, Id32)],
    ) {
        assert_eq!(identity_rows(store, key), before);
        assert_eq!(
            store
                .recover_logical(0, 100)
                .unwrap()
                .iter()
                .find(|row| row.key == *key)
                .unwrap()
                .key
                .message,
            key.message
        );
        assert_wires(store, wires);
    }

    fn expect_new_bearers(peer: &Peer, from: usize, base: u8) -> usize {
        let rows = peer.requests();
        assert!(rows.len() > from, "credential change sent no upload");
        for (relay, hash) in &rows[from..] {
            let mut secret = [base.wrapping_add(*relay); 32];
            let expected = bearer_hash(&secret);
            secret.fill(0);
            assert_eq!(*hash, expected, "append header did not follow the current credential");
        }
        rows.len()
    }

    // Scripted 401 and 507 stand in for relay HTTP. Exact duplicate PUT and read under quota stay on the relay store gate.
    #[test]
    fn upload_retry_append_change_sleeps_until_config_and_revision() {
        let prepared = prepare_outbox(
            &support::identity(1),
            &roster(),
            &body([81; 32], vec![19, 29, 39]),
        )
        .unwrap();
        assert_eq!(prepared.recipients()[0].objects().len(), 1);
        let wires = capture(&prepared);
        let peer = Peer::open(None, false, Some(190), None);
        let root = evidence_c("append").join("client");
        let roster = roster();
        let alice = support::identity(1);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let logical = store
            .commit_outbox(&roster, &alice, &[84; 32], &prepared)
            .unwrap();
        let before = identity_rows(&store, &logical.key);
        let (config, self_route) = view(
            &mut store, &roster, peer.port, 2, 1, 180, Some(1), &[2, 3],
        );
        assert_eq!(self_route.body().revision, 2);
        assert!(self_route
            .body()
            .relays
            .iter()
            .all(|relay| relay.route.append_revision == 1));
        let http = RelayHttp::new().unwrap();
        let runtime = RelayRuntime::new().unwrap();
        let denied = drive(
            &runtime, &mut store, &http, &logical, &roster, &config, &self_route, 30_000,
        );
        assert!(denied.needs_route.is_empty());
        let denied_at = expect_new_bearers(&peer, 0, 180);
        assert_eq!(denied_at, 9, "old append was not offered on every route");
        assert_eq!(peer.state.lock().unwrap().saved.len(), 0);
        for upload in rows(&store) {
            assert_eq!(upload.attempts, 0, "unauthorized append scheduled a resend");
            assert_eq!(upload.retry_at, 0);
            assert!(!upload.acknowledged);
            assert!(store.saved_receipt(&upload).unwrap().is_none());
        }
        assert_identity(&store, &logical.key, &wires, &before);
        let quiet = |store: &mut ClientStore,
                     config: &ClientConfig,
                     self_route: &loki_relay_client::AuthenticatedDescriptor| {
            drive(
                &runtime, store, &http, &logical, &roster, config, self_route, 30_000,
            );
            assert_eq!(peer.requests().len(), denied_at, "asleep route sent an append");
        };
        quiet(&mut store, &config, &self_route);
        let (rotated, rotated_route) = view(
            &mut store, &roster, peer.port, 2, 2, 190, None, &[2, 3],
        );
        assert_eq!(store.config_reference().unwrap().unwrap().revision(), 1);
        assert_eq!(rotated_route.body().revision, 2);
        quiet(&mut store, &rotated, &rotated_route);
        let (stale_append, stale_route) = view(
            &mut store, &roster, peer.port, 2, 1, 180, Some(2), &[2, 3],
        );
        assert_eq!(store.config_reference().unwrap().unwrap().revision(), 2);
        quiet(&mut store, &stale_append, &stale_route);
        let (older, older_route) = view(
            &mut store, &roster, peer.port, 1, 2, 190, None, &[2, 3],
        );
        assert_eq!(older_route.body().revision, 1);
        assert!(older_route
            .body()
            .relays
            .iter()
            .all(|relay| relay.route.append_revision == 2));
        assert_eq!(store.config_reference().unwrap().unwrap().revision(), 2);
        quiet(&mut store, &older, &older_route);
        let (current, current_route) = view(
            &mut store, &roster, peer.port, 2, 2, 190, None, &[2, 3],
        );
        let woken = drive(
            &runtime,
            &mut store,
            &http,
            &logical,
            &roster,
            &current,
            &current_route,
            30_000,
        );
        assert!(woken.needs_route.is_empty());
        assert!(woken.stopped_third, "current append uploaded the optional third pin");
        let third = current_route.body().relays[2].route.pin.key;
        assert_eq!(expect_new_bearers(&peer, denied_at, 190), denied_at + 6);
        for upload in rows(&store) {
            assert_eq!(upload.attempts, 0, "current append counted as a failed retry");
            if upload.relay_key == third {
                assert!(!upload.acknowledged, "optional third was acknowledged");
                assert!(peer.shot(&upload.mailbox, &upload.hash).is_none());
                assert!(store.saved_receipt(&upload).unwrap().is_none());
            } else {
                let wire = &wires[&upload.hash];
                assert!(upload.acknowledged, "current append left a pair route pending");
                assert!(peer.body_matches(&upload.mailbox, &upload.hash, wire));
                let shot = peer.shot(&upload.mailbox, &upload.hash).unwrap();
                assert_eq!(shot.hits, 1);
                assert_eq!(store.saved_receipt(&upload).unwrap().unwrap(), shot.receipt);
            }
        }
        assert_identity(&store, &logical.key, &wires, &before);
    }

    #[test]
    fn upload_retry_missing_route_binds_later_without_reprepare() {
        let prepared = prepare_outbox(
            &support::identity(1),
            &roster(),
            &body([82; 32], vec![19, 29, 39]),
        )
        .unwrap();
        let wires = capture(&prepared);
        let peer = Peer::start(None, false);
        let root = evidence_c("missing").join("client");
        let roster = roster();
        let alice = support::identity(1);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let logical = store
            .commit_outbox(&roster, &alice, &[85; 32], &prepared)
            .unwrap();
        let before = identity_rows(&store, &logical.key);
        let (config, self_route) = view(
            &mut store, &roster, peer.port, 1, 1, 180, Some(1), &[3],
        );
        let http = RelayHttp::new().unwrap();
        let runtime = RelayRuntime::new().unwrap();
        let waiting = drive(
            &runtime, &mut store, &http, &logical, &roster, &config, &self_route, 40_000,
        );
        assert_eq!(waiting.needs_route, vec![2]);
        assert!(!waiting.stopped_third, "missing recipient stopped the third pin");
        let stored = rows(&store);
        assert!(stored.iter().all(|upload| upload.mailbox[0] != 2));
        assert!(stored.iter().all(|upload| upload.acknowledged));
        assert_eq!(stored.len(), 6);
        assert_identity(&store, &logical.key, &wires, &before);
        drop(store);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let reopened = store.recover_recipients(&logical.key).unwrap();
        assert!(reopened
            .iter()
            .any(|row| row.recipient == 2 && row.needs_route));
        assert_identity(&store, &logical.key, &wires, &before);
        let (bound, bound_route) = view(
            &mut store, &roster, peer.port, 1, 1, 180, None, &[2, 3],
        );
        let third = bound_route.body().relays[2].route.pin.key;
        let pass = drive(
            &runtime, &mut store, &http, &logical, &roster, &bound, &bound_route, 40_000,
        );
        assert!(pass.needs_route.is_empty(), "later descriptor left Bob unrouted");
        assert!(pass.stopped_third, "bound third pin ignored whole-vault Stored");
        for upload in rows(&store) {
            let wire = &wires[&upload.hash];
            if upload.mailbox[0] == 2 && upload.relay_key == third {
                assert!(!upload.acknowledged);
                assert_eq!(upload.attempts, 0);
                assert!(peer.shot(&upload.mailbox, &upload.hash).is_none());
            } else {
                assert!(upload.acknowledged);
                assert!(peer.body_matches(&upload.mailbox, &upload.hash, wire));
                assert_eq!(peer.shot(&upload.mailbox, &upload.hash).unwrap().hits, 1);
            }
        }
        assert_identity(&store, &logical.key, &wires, &before);
        assert!(store
            .recover_recipients(&logical.key)
            .unwrap()
            .iter()
            .all(|row| !row.needs_route));
    }

    #[test]
    fn upload_retry_capacity_schedules_saved_retry() {
        let prepared = prepare_outbox(
            &support::identity(1),
            &roster(),
            &body([83; 32], vec![19, 29, 39]),
        )
        .unwrap();
        let wires = capture(&prepared);
        let peer = Peer::open(None, false, None, Some(2));
        let root = evidence_c("quota").join("client");
        let roster = roster();
        let alice = support::identity(1);
        let mut store = ClientStore::open(&root, &roster, 1).unwrap();
        let logical = store
            .commit_outbox(&roster, &alice, &[86; 32], &prepared)
            .unwrap();
        let before = identity_rows(&store, &logical.key);
        let (config, self_route) = install(&mut store, &roster, peer.port);
        let http = RelayHttp::new().unwrap();
        let runtime = RelayRuntime::new().unwrap();
        let now = 50_000u64;
        drive(
            &runtime, &mut store, &http, &logical, &roster, &config, &self_route, now,
        );
        let first = rows(&store);
        let acked: Vec<_> = first.iter().filter(|upload| upload.acknowledged).collect();
        let waiting: Vec<_> = first.iter().filter(|upload| !upload.acknowledged).collect();
        assert_eq!(acked.len(), 2, "quota did not keep two stored objects");
        assert_eq!(waiting.len(), 7, "quota did not leave the other routes pending");
        let mut kept = Vec::new();
        for upload in &acked {
            assert_eq!(upload.attempts, 0);
            let shot = peer.shot(&upload.mailbox, &upload.hash).unwrap();
            assert_eq!(shot.hits, 1);
            assert_eq!(store.saved_receipt(upload).unwrap().unwrap(), shot.receipt);
            kept.push((upload.mailbox, upload.hash, shot.receipt));
        }
        for upload in &waiting {
            assert_eq!(upload.attempts, 1);
            assert_eq!(upload.retry_at, now + 250);
            assert!(store.saved_receipt(upload).unwrap().is_none());
        }
        assert_identity(&store, &logical.key, &wires, &before);
        let sent = peer.requests().len();
        drive(
            &runtime, &mut store, &http, &logical, &roster, &config, &self_route, now,
        );
        assert_eq!(peer.requests().len(), sent, "early schedule sent another put");
        for upload in rows(&store).iter().filter(|upload| !upload.acknowledged) {
            assert_eq!(upload.attempts, 1);
            assert_eq!(upload.retry_at, now + 250);
        }
        drive(
            &runtime,
            &mut store,
            &http,
            &logical,
            &roster,
            &config,
            &self_route,
            now + 250,
        );
        for upload in rows(&store) {
            if upload.acknowledged {
                let (_, _, receipt) = kept
                    .iter()
                    .find(|(mailbox, hash, _)| *mailbox == upload.mailbox && *hash == upload.hash)
                    .unwrap();
                assert_eq!(store.saved_receipt(&upload).unwrap().unwrap(), *receipt);
                assert_eq!(peer.shot(&upload.mailbox, &upload.hash).unwrap().hits, 1);
            } else {
                assert_eq!(upload.attempts, 2);
                assert!(upload.retry_at >= now + 500);
                assert!(upload.retry_at <= now + 750);
                assert!(store.saved_receipt(&upload).unwrap().is_none());
            }
        }
        assert_identity(&store, &logical.key, &wires, &before);
    }

    /// Per-owner relay mask for the scripted stored-pair peer. Default is closed.
    #[derive(Clone)]
    struct StoredPolicy {
        owner_relays: [[bool; 3]; 4],
        /// 0 keeps every hash, 1 keeps roots only, 2 keeps non-roots only.
        root_mode: u8,
        roots: Vec<Id32>,
        acknowledge: bool,
    }

    impl StoredPolicy {
        fn closed() -> Self {
            Self {
                owner_relays: [[false; 3]; 4],
                root_mode: 0,
                roots: Vec::new(),
                acknowledge: false,
            }
        }

        fn allow(mut self, owner: u8, relays: &[u8]) -> Self {
            for relay in relays {
                self.owner_relays[usize::from(owner)][usize::from(*relay)] = true;
            }
            self
        }

        fn allow_all(self, relays: &[u8]) -> Self {
            self.allow(1, relays).allow(2, relays).allow(3, relays)
        }

        fn roots(mut self, mode: u8, roots: Vec<Id32>) -> Self {
            self.root_mode = mode;
            self.roots = roots;
            self
        }

        fn acknowledge(mut self) -> Self {
            self.acknowledge = true;
            self
        }
    }

    fn pair_allows(policy: &StoredPolicy, mailbox: Id32, hash: Id32) -> bool {
        let owner = usize::from(mailbox[0]);
        let relay = usize::from(mailbox[1]);
        if owner >= 4 || relay >= 3 || !policy.owner_relays[owner][relay] {
            return false;
        }
        match policy.root_mode {
            1 => policy.roots.iter().any(|root| *root == hash),
            2 => policy.roots.iter().all(|root| *root != hash),
            _ => true,
        }
    }

    struct PairState {
        saved: HashMap<(Id32, Id32), SavedPut>,
        sequences: HashMap<Id32, u64>,
        policy: StoredPolicy,
        seen: u64,
    }

    struct PairPeer {
        port: u16,
        stop: Arc<AtomicBool>,
        state: Arc<Mutex<PairState>>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl PairPeer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let state = Arc::new(Mutex::new(PairState {
                saved: HashMap::new(),
                sequences: HashMap::new(),
                policy: StoredPolicy::closed(),
                seen: 0,
            }));
            let thread_stop = Arc::clone(&stop);
            let thread_state = Arc::clone(&state);
            let thread = thread::spawn(move || serve_pair(listener, thread_stop, thread_state));
            Self {
                port,
                stop,
                state,
                thread: Some(thread),
            }
        }

        fn set_policy(&self, policy: StoredPolicy) {
            self.state.lock().unwrap().policy = policy;
        }

        fn shot(&self, mailbox: &Id32, hash: &Id32) -> Option<Vec<u8>> {
            self.state
                .lock()
                .unwrap()
                .saved
                .get(&(*mailbox, *hash))
                .map(|saved| saved.receipt.clone())
        }

        fn seen(&self) -> u64 {
            self.state.lock().unwrap().seen
        }
    }

    impl Drop for PairPeer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Scripted loopback signer. A 200 response with an empty CBOR array is an acknowledgement, not a stored receipt.
    fn serve_pair(listener: TcpListener, stop: Arc<AtomicBool>, state: Arc<Mutex<PairState>>) {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let Some((mailbox, hash, body, _)) = read_put(&mut stream) else {
                        continue;
                    };
                    if Sha256::digest(&body).as_slice() != hash.as_slice() {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let relay = usize::from(mailbox[1]);
                    if relay >= SEEDS.len() {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let mut peer = state.lock().unwrap();
                    peer.seen += 1;
                    if !pair_allows(&peer.policy, mailbox, hash) {
                        drop(peer);
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    if peer.policy.acknowledge {
                        drop(peer);
                        write_cbor(&mut stream, 200, "OK", &[0x80]);
                        continue;
                    }
                    let key = (mailbox, hash);
                    if let Some(saved) = peer.saved.get_mut(&key) {
                        if saved.body != body {
                            drop(peer);
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        saved.hits += 1;
                        let receipt = saved.receipt.clone();
                        drop(peer);
                        write_receipt(&mut stream, &receipt);
                        continue;
                    }
                    let sequence = peer.sequences.entry(mailbox).or_insert(0);
                    *sequence += 1;
                    let sequence = *sequence;
                    let signer = SigningKey::from_bytes(&SEEDS[relay]);
                    let route = RelayRoute {
                        pin: RelayPin {
                            key: signer.verifying_key().to_bytes(),
                            run: run_id(mailbox[1]),
                        },
                        endpoint: "http://127.0.0.1:9".to_string(),
                        mailbox,
                        append_revision: 1,
                    };
                    let receipt =
                        signed_receipt(&signer, &route, hash, body.len() as u64, sequence);
                    peer.saved.insert(
                        key,
                        SavedPut {
                            body,
                            receipt: receipt.clone(),
                            sequence,
                            hits: 1,
                        },
                    );
                    drop(peer);
                    write_receipt(&mut stream, &receipt);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    }

    fn install_member_ports(
        store: &mut ClientStore,
        roster: &Roster,
        ports: [u16; 3],
    ) -> (ClientConfig, loki_relay_client::AuthenticatedDescriptor) {
        let alice = support::identity(1);
        let sealed = seal_descriptor(
            &alice,
            roster,
            &descriptor_for(1, ports[0]),
            &alice.public(),
        )
        .unwrap();
        let self_route = open_descriptor(&alice, roster, &sealed.wire).unwrap();
        store
            .record_config_revision(&ConfigReference::from_ciphertext(1, &sealed.wire).unwrap())
            .unwrap();
        let own = self_route
            .body()
            .relays
            .iter()
            .map(|relay| OwnerInbox {
                route: relay.route.clone(),
                read: Secret32::from_bytes([210; 32]),
                append: Secret32::from_bytes(*relay.append.as_bytes()),
                admin: Secret32::from_bytes([211; 32]),
            })
            .collect();
        let peers = vec![opened(2, 1, ports[1]), opened(3, 1, ports[2])];
        (ClientConfig { own, peers }, self_route)
    }

    fn pair_directory() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = PathBuf::from("/private/tmp/relay-6.5a-stored-pair").join(format!(
            "case-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn pin_of(index: u8) -> (Id32, Id32) {
        (relay_key(SEEDS[usize::from(index)][0]), run_id(index))
    }

    fn relay_index_of(key: &Id32) -> u8 {
        (0..3u8)
            .find(|index| pin_of(*index).0 == *key)
            .expect("upload relay key")
    }

    fn roots_of(prepared: &loki_relay_client::PreparedOutbox) -> Vec<Id32> {
        prepared
            .recipients()
            .iter()
            .map(|recipient| *recipient.root_hash())
            .collect()
    }

    fn assert_chunked(prepared: &loki_relay_client::PreparedOutbox) {
        let count = prepared.recipients()[0].objects().len();
        assert!(count >= 2, "chunked set collapsed to one object");
        assert!(prepared
            .recipients()
            .iter()
            .all(|recipient| recipient.objects().len() == count));
        for recipient in prepared.recipients() {
            assert_eq!(
                recipient.objects().last().unwrap().hash,
                *recipient.root_hash(),
                "manifest was not the last required object"
            );
        }
    }

    fn uploads_for(
        store: &ClientStore,
        message: Id32,
    ) -> Vec<loki_relay_client::RecoveryUpload> {
        let mut after = 0;
        let mut matched = Vec::new();
        loop {
            let page = store.recover_uploads(after, 100).unwrap();
            if page.is_empty() {
                break;
            }
            after = page.last().unwrap().cursor;
            let more = page.len() == 100;
            for upload in page {
                if upload.key.message == message {
                    matched.push(upload);
                }
            }
            if !more {
                break;
            }
        }
        matched
    }

    fn expect_member(report: &loki_relay_client::DeliveryReport, member: u16, seeds: &[u8]) {
        let expected: BTreeSet<_> = seeds.iter().copied().map(pin_of).collect();
        let actual: BTreeSet<_> = report.member_pins(member).iter().copied().collect();
        assert_eq!(actual, expected, "recipient {member} pins");
        assert_eq!(
            report.member_pins(member).len(),
            expected.len(),
            "recipient {member} duplicated a pin"
        );
        assert_eq!(
            report.member_stored(member),
            expected.len() >= 2,
            "recipient {member} stored bit"
        );
    }

    fn expect_whole(report: &loki_relay_client::DeliveryReport, seeds: &[u8]) {
        let expected: BTreeSet<_> = seeds.iter().copied().map(pin_of).collect();
        let actual: BTreeSet<_> = report.whole_pins().iter().copied().collect();
        assert_eq!(actual, expected, "whole-vault pins");
        assert_eq!(
            report.whole_pins().len(),
            expected.len(),
            "whole-vault duplicated a pin"
        );
        assert_eq!(report.whole_vault(), expected.len() >= 2);
        let members: [BTreeSet<_>; 3] = [1, 2, 3].map(|member| {
            report
                .member_pins(member)
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        });
        let folded: BTreeSet<_> = members[0]
            .iter()
            .copied()
            .filter(|pin| members[1].contains(pin) && members[2].contains(pin))
            .collect();
        assert_eq!(actual, folded, "whole pins are not the three-copy intersection");
    }

    fn set_both(peers: &[PairPeer; 2], policy: StoredPolicy) {
        peers[0].set_policy(policy.clone());
        peers[1].set_policy(policy);
    }

    fn drive_report(
        runtime: &RelayRuntime,
        store: &mut ClientStore,
        http: &RelayHttp,
        logical: &loki_relay_client::RecoveryLogical,
        roster: &Roster,
        identity: &loki_relay_client::CommIdentity,
        config: &ClientConfig,
        self_route: &loki_relay_client::AuthenticatedDescriptor,
    ) -> loki_relay_client::DeliveryReport {
        let pass = runtime
            .block_on(upload_pending(
                store,
                http,
                logical,
                roster,
                identity,
                config,
                self_route,
                10_000,
                ThirdPass::ContinueThird,
            ))
            .unwrap();
        assert!(pass.needs_route.is_empty(), "a recipient stayed unrouted");
        let report = store
            .delivery_report(roster, identity, logical, config, self_route)
            .unwrap();
        assert_eq!(report.key(), &logical.key);
        assert_eq!(report.source_root(), &logical.source_root);
        report
    }

    fn assert_signed(
        store: &ClientStore,
        peers: &[PairPeer; 2],
        message: Id32,
        objects: usize,
        accept: impl Fn(u8, u8, &Id32) -> bool,
    ) {
        let uploads = uploads_for(store, message);
        assert_eq!(uploads.len(), objects * 9, "required object routes were incomplete");
        for upload in &uploads {
            let index = relay_index_of(&upload.relay_key);
            let peer = if upload.mailbox[0] == 2 {
                &peers[1]
            } else {
                &peers[0]
            };
            if accept(upload.mailbox[0], index, &upload.hash) {
                assert!(upload.acknowledged, "accepted upload was not acknowledged");
                assert_eq!(upload.attempts, 0, "accepted upload counted a failure");
                let receipt = peer
                    .shot(&upload.mailbox, &upload.hash)
                    .expect("scripted peer did not sign a receipt");
                assert_eq!(store.saved_receipt(upload).unwrap().as_ref(), Some(&receipt));
            } else {
                assert!(!upload.acknowledged, "refused upload was acknowledged");
                assert!(upload.attempts >= 1, "refused upload was not attempted");
                assert!(store.saved_receipt(upload).unwrap().is_none());
                assert!(peer.shot(&upload.mailbox, &upload.hash).is_none());
            }
        }
    }

    #[test]
    fn stored_pair() {
        // These listeners are scripted HTTP signers, not loki-relay-server.
        let order = sorted_seeds();
        let low = order[0];
        let mid = order[1];
        let high = order[2];
        let peers = [PairPeer::start(), PairPeer::start()];
        let directory = pair_directory();
        let roster = roster();
        let alice = support::identity(1);
        let mut store = ClientStore::open(&directory.join("client"), &roster, 1).unwrap();
        let (config, self_route) = install_member_ports(
            &mut store,
            &roster,
            [peers[0].port, peers[1].port, peers[0].port],
        );
        let alice_route = &self_route.body().relays[0].route;
        let bob_route = &config
            .peers
            .iter()
            .find(|peer| peer.body().owner == 2)
            .unwrap()
            .body()
            .relays[0]
            .route;
        let carol_route = &config
            .peers
            .iter()
            .find(|peer| peer.body().owner == 3)
            .unwrap()
            .body()
            .relays[0]
            .route;
        assert_eq!(
            alice_route.endpoint,
            format!("http://127.0.0.1:{}", peers[0].port)
        );
        assert_eq!(
            bob_route.endpoint,
            format!("http://127.0.0.1:{}", peers[1].port)
        );
        assert_eq!(carol_route.endpoint, alice_route.endpoint);
        assert_ne!(alice_route.endpoint, bob_route.endpoint, "duplicate-key URLs collapsed");
        assert_eq!(alice_route.pin.key, bob_route.pin.key);
        assert_eq!(alice_route.pin.run, bob_route.pin.run);
        assert_eq!(alice_route.pin.key, pin_of(low).0);
        let http = RelayHttp::new().unwrap();
        let runtime = RelayRuntime::new().unwrap();

        let crossed = prepare_outbox(&alice, &roster, &body([0x51; 32], vec![19, 29, 39])).unwrap();
        assert_eq!(crossed.recipients().len(), 3);
        assert_eq!(crossed.recipients()[0].objects().len(), 1);
        let crossed_logical = store
            .commit_outbox(&roster, &alice, &[0x61; 32], &crossed)
            .unwrap();
        assert_eq!(crossed_logical.kind, 1);
        assert_eq!(crossed_logical.digest, *crossed.digest());
        set_both(
            &peers,
            StoredPolicy::closed()
                .allow(1, &[low, mid])
                .allow(2, &[mid, high])
                .allow(3, &[low, mid]),
        );
        let crossed_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &crossed_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        expect_member(&crossed_report, 1, &[low, mid]);
        expect_member(&crossed_report, 2, &[mid, high]);
        expect_member(&crossed_report, 3, &[low, mid]);
        expect_whole(&crossed_report, &[mid]);
        let saved = rusqlite::Connection::open_with_flags(
            directory.join("client/client.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let completions: i64 = saved
            .query_row(
                "SELECT count(*) FROM delivery_completion WHERE message_id=?1",
                [crossed_logical.key.message],
                |row| row.get(0),
            )
            .unwrap();
        drop(saved);
        assert_eq!(
            completions, 0,
            "upload capacity release must use the verified whole-vault intersection"
        );
        let crossed_release = store
            .release_stored_capacity(&roster, &alice, &crossed_logical, &config, &self_route)
            .unwrap();
        assert!(!crossed_release.whole_vault(), "crossed pairs released whole-vault capacity");
        assert_signed(&store, &peers, crossed_logical.key.message, 1, |owner, relay, _| {
            match owner {
                1 | 3 => relay == low || relay == mid,
                2 => relay == mid || relay == high,
                _ => false,
            }
        });

        let author = prepare_outbox(&alice, &roster, &body([0x52; 32], vec![21, 22, 23])).unwrap();
        let author_logical = store
            .commit_outbox(&roster, &alice, &[0x62; 32], &author)
            .unwrap();
        set_both(
            &peers,
            StoredPolicy::closed()
                .allow(2, &[low, mid])
                .allow(3, &[low, mid]),
        );
        let author_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &author_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        expect_member(&author_report, 1, &[]);
        expect_member(&author_report, 2, &[low, mid]);
        expect_member(&author_report, 3, &[low, mid]);
        expect_whole(&author_report, &[]);
        assert_signed(&store, &peers, author_logical.key.message, 1, |owner, relay, _| {
            (owner == 2 || owner == 3) && (relay == low || relay == mid)
        });

        let chunk_gap = prepare_outbox(&alice, &roster, &body([0x53; 32], vec![29u8; 80_000])).unwrap();
        assert_chunked(&chunk_gap);
        let chunk_roots = roots_of(&chunk_gap);
        let chunk_objects = chunk_gap.recipients()[0].objects().len();
        let chunk_logical = store
            .commit_outbox(&roster, &alice, &[0x63; 32], &chunk_gap)
            .unwrap();
        set_both(
            &peers,
            StoredPolicy::closed()
                .allow_all(&[low, mid])
                .roots(1, chunk_roots.clone()),
        );
        let chunk_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &chunk_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        for member in 1..=3 {
            expect_member(&chunk_report, member, &[]);
        }
        expect_whole(&chunk_report, &[]);
        assert_signed(
            &store,
            &peers,
            chunk_logical.key.message,
            chunk_objects,
            |_, relay, hash| (relay == low || relay == mid) && chunk_roots.contains(hash),
        );

        let manifest_gap =
            prepare_outbox(&alice, &roster, &body([0x54; 32], vec![29u8; 80_000])).unwrap();
        assert_chunked(&manifest_gap);
        let manifest_roots = roots_of(&manifest_gap);
        let manifest_objects = manifest_gap.recipients()[0].objects().len();
        let manifest_logical = store
            .commit_outbox(&roster, &alice, &[0x64; 32], &manifest_gap)
            .unwrap();
        set_both(
            &peers,
            StoredPolicy::closed()
                .allow_all(&[low, mid])
                .roots(2, manifest_roots.clone()),
        );
        let manifest_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &manifest_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        for member in 1..=3 {
            expect_member(&manifest_report, member, &[]);
        }
        expect_whole(&manifest_report, &[]);
        assert_signed(
            &store,
            &peers,
            manifest_logical.key.message,
            manifest_objects,
            |_, relay, hash| (relay == low || relay == mid) && !manifest_roots.contains(hash),
        );

        let single = prepare_outbox(&alice, &roster, &body([0x56; 32], vec![31, 32, 33])).unwrap();
        assert_eq!(single.recipients()[0].objects().len(), 1);
        let single_logical = store
            .commit_outbox(&roster, &alice, &[0x66; 32], &single)
            .unwrap();
        set_both(&peers, StoredPolicy::closed().allow_all(&[low]));
        let single_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &single_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        for member in 1..=3 {
            expect_member(&single_report, member, &[low]);
        }
        expect_whole(&single_report, &[low]);
        assert_eq!(single_report.member_pins(1), single_report.member_pins(2));
        assert_eq!(single_report.member_pins(1), single_report.member_pins(3));
        assert_eq!(single_report.whole_pins().len(), 1, "two URLs of one key counted twice");
        assert_signed(&store, &peers, single_logical.key.message, 1, |_, relay, _| {
            relay == low
        });

        let original = prepare_outbox(&alice, &roster, &body([0x57; 32], vec![41, 42, 43])).unwrap();
        let original_logical = store
            .commit_outbox(&roster, &alice, &[0x67; 32], &original)
            .unwrap();
        assert_eq!(original_logical.kind, 1);
        assert_eq!(original_logical.digest, *original.digest());
        let seen_before = peers[0].seen() + peers[1].seen();
        set_both(
            &peers,
            StoredPolicy::closed()
                .allow_all(&[low, mid, high])
                .acknowledge(),
        );
        let ack_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &original_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        for member in 1..=3 {
            expect_member(&ack_report, member, &[]);
        }
        expect_whole(&ack_report, &[]);
        let original_uploads = uploads_for(&store, original_logical.key.message);
        assert_eq!(original_uploads.len(), 9);
        assert_eq!(
            peers[0].seen() + peers[1].seen(),
            seen_before + 9,
            "scripted acknowledgement peer saw a different number of uploads"
        );
        for upload in &original_uploads {
            assert!(!upload.acknowledged, "acknowledgement became upload state");
            assert_eq!(upload.attempts, 0, "acknowledgement was recorded as a transport failure");
            assert!(store.saved_receipt(upload).unwrap().is_none());
            let peer = if upload.mailbox[0] == 2 {
                &peers[1]
            } else {
                &peers[0]
            };
            assert!(peer.shot(&upload.mailbox, &upload.hash).is_none());
        }
        let reference = loki_relay_protocol::types::MessageRef {
            sender: 1,
            message: original_logical.key.message,
            digest: original_logical.digest,
        };
        let mut received_body = body([0x58; 32], Vec::new());
        received_body.prerequisites = vec![reference.clone()];
        received_body.payload = Payload::Received(reference);
        let received = prepare_outbox(&alice, &roster, &received_body).unwrap();
        let received_logical = store
            .commit_outbox(&roster, &alice, &[0x68; 32], &received)
            .unwrap();
        assert_eq!(received_logical.kind, 2);
        set_both(&peers, StoredPolicy::closed().allow_all(&[low, mid]));
        let received_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &received_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        for member in 1..=3 {
            expect_member(&received_report, member, &[low, mid]);
        }
        expect_whole(&received_report, &[low, mid]);
        assert_signed(&store, &peers, received_logical.key.message, 1, |_, relay, _| {
            relay == low || relay == mid
        });
        let original_again = store
            .delivery_report(&roster, &alice, &original_logical, &config, &self_route)
            .unwrap();
        for member in 1..=3 {
            expect_member(&original_again, member, &[]);
        }
        expect_whole(&original_again, &[]);
        for upload in uploads_for(&store, original_logical.key.message) {
            assert!(store.saved_receipt(&upload).unwrap().is_none());
            assert!(!upload.acknowledged);
        }

        let complete = prepare_outbox(&alice, &roster, &body([0x55; 32], vec![29u8; 80_000])).unwrap();
        assert_chunked(&complete);
        let complete_objects = complete.recipients()[0].objects().len();
        let wires = capture(&complete);
        let complete_logical = store
            .commit_outbox(&roster, &alice, &[0x65; 32], &complete)
            .unwrap();
        set_both(&peers, StoredPolicy::closed().allow_all(&[low, mid]));
        let complete_report = drive_report(
            &runtime,
            &mut store,
            &http,
            &complete_logical,
            &roster,
            &alice,
            &config,
            &self_route,
        );
        for member in 1..=3 {
            expect_member(&complete_report, member, &[low, mid]);
        }
        expect_whole(&complete_report, &[low, mid]);
        assert_eq!(complete_report.member_pins(1), complete_report.member_pins(2));
        assert_eq!(complete_report.member_pins(1), complete_report.member_pins(3));
        assert!(complete_report
            .member_pins(1)
            .iter()
            .all(|pin| pin.0 != pin_of(high).0));
        assert_signed(
            &store,
            &peers,
            complete_logical.key.message,
            complete_objects,
            |_, relay, _| relay == low || relay == mid,
        );
        assert_wires(&store, &wires);
        let saved = rusqlite::Connection::open_with_flags(
            directory.join("client/client.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let completions: i64 = saved
            .query_row(
                "SELECT count(*) FROM delivery_completion WHERE message_id=?1",
                [complete_logical.key.message],
                |row| row.get(0),
            )
            .unwrap();
        drop(saved);
        assert_eq!(
            completions, 1,
            "upload capacity release must use the verified whole-vault intersection"
        );
        let released = store
            .release_stored_capacity(&roster, &alice, &complete_logical, &config, &self_route)
            .unwrap();
        assert!(released.whole_vault(), "complete pair did not release");
        let released_again = store
            .release_stored_capacity(&roster, &alice, &complete_logical, &config, &self_route)
            .unwrap();
        assert!(released_again.whole_vault());
        assert_eq!(released_again.whole_pins(), released.whole_pins());
        drop(store);
        let mut store = ClientStore::open(&directory.join("client"), &roster, 1).unwrap();
        let reopened = store
            .delivery_report(&roster, &alice, &complete_logical, &config, &self_route)
            .unwrap();
        assert!(reopened.whole_vault(), "reopen lost whole-vault Stored");
        assert_eq!(reopened.whole_pins(), complete_report.whole_pins());
        for member in 1..=3 {
            assert_eq!(reopened.member_pins(member), complete_report.member_pins(member));
        }
        assert_wires(&store, &wires);
    }
}
