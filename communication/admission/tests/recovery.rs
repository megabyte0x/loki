mod support;
use loki_relay_protocol::{admission::AdmissionCommand, http, types::Creation};
use loki_setup_admission::AdmissionError;
use support::*;
fn mailbox(op: u8, relay: u16, purpose: u16, quota: u64, id: u8) -> Vec<u8> {
    request(
        op,
        &identity(1, 1),
        AdmissionCommand::Mailbox {
            ceremony: [70; 32],
            slot: 1,
            relay,
            purpose,
            mailbox: [id; 32],
            creation: http::encode_creation(&Creation {
                read_verifier: [1; 32],
                append_verifier: [2; 32],
                admin_verifier: [3; 32],
                quota,
            })
            .unwrap(),
        },
    )
}
#[test]
fn claim_is_not_consumed_when_operation_commit_fails() {
    let db = OwnedDb::new();
    let mut store = db.open();
    let g = grant(2, 48);
    store
        .apply(&create(1, [70; 32], 4, &g), Some(&g), 100)
        .unwrap();
    let external = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
    external.execute_batch("CREATE TRIGGER fail_test_operation BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT,'owned_fault'); END;").unwrap();
    let req = claim(2, [70; 32], 2, 2);
    assert_eq!(
        store.apply(&req, Some(&[2; 32]), 101).unwrap_err(),
        AdmissionError::Storage
    );
    let count: u64 = external
        .query_row(
            "SELECT count(*) FROM claims WHERE ceremony=?1 AND slot=2",
            [[70u8; 32].as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    external
        .execute_batch("DROP TRIGGER fail_test_operation")
        .unwrap();
    store.apply(&req, Some(&[2; 32]), 102).unwrap();
}
#[test]
fn provision_intents_are_exact_and_survive_lost_admission_response() {
    let db = OwnedDb::new();
    let mut store = db.open();
    let g = grant(2, 48);
    store
        .apply(&create(1, [70; 32], 4, &g), Some(&g), 100)
        .unwrap();
    let req = mailbox(2, 1, 1, 1024, 50);
    let saved = store.apply(&req, None, 101).unwrap();
    let pending = store.pending(101, 3).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].mailbox(), &[50; 32]);
    let exact = pending[0].request().to_vec();
    drop(store);
    let mut store = db.open();
    assert_eq!(store.apply(&req, None, 102).unwrap(), saved);
    assert_eq!(store.pending(102, 3).unwrap()[0].request(), exact);
    assert_eq!(
        store
            .apply(&mailbox(3, 1, 1, 2048, 50), None, 102)
            .unwrap_err(),
        AdmissionError::Conflict
    );
    assert_eq!(
        store
            .apply(&mailbox(4, 1, 2, 1024, 50), None, 102)
            .unwrap_err(),
        AdmissionError::Conflict
    );
    assert_eq!(store.pending(102, 3).unwrap().len(), 1);
}
#[test]
fn setup_storage_quota_is_per_relay_and_purpose() {
    let db = OwnedDb::new();
    let mut store = db.open();
    let g = grant(2, 48);
    store
        .apply(&create(1, [70; 32], 4, &g), Some(&g), 100)
        .unwrap();
    store
        .apply(&mailbox(2, 1, 1, 67108864, 50), None, 101)
        .unwrap();
    store
        .apply(&claim(3, [70; 32], 2, 2), Some(&[2; 32]), 102)
        .unwrap();
    let request_for_peer = request(
        4,
        &identity(2, 2),
        AdmissionCommand::Mailbox {
            ceremony: [70; 32],
            slot: 2,
            relay: 1,
            purpose: 1,
            mailbox: [51; 32],
            creation: http::encode_creation(&Creation {
                read_verifier: [4; 32],
                append_verifier: [5; 32],
                admin_verifier: [6; 32],
                quota: 1024,
            })
            .unwrap(),
        },
    );
    assert_eq!(
        store.apply(&request_for_peer, None, 103).unwrap_err(),
        AdmissionError::Quota
    );
    store
        .apply(&mailbox(5, 2, 1, 67108864, 52), None, 104)
        .unwrap();
    store
        .apply(&mailbox(6, 1, 2, 67108864, 53), None, 105)
        .unwrap();
    assert_eq!(store.pending(105, 3).unwrap().len(), 3);
    store.cleanup(2592100).unwrap();
    assert_eq!(store.pending(2592100, 3).unwrap().len(), 0);
    let state = request(
        7,
        &identity(1, 1),
        AdmissionCommand::State {
            ceremony: [70; 32],
            slot: 1,
        },
    );
    assert!(store.apply(&state, None, 2592101).is_ok());
}

/// Rewrite a current root's schema back to version 1 (at most 4 members).
fn narrow_to_version_one(external: &rusqlite::Connection) {
    external
        .execute_batch(
            "DROP INDEX operations_ceremony_slot; DROP INDEX mailboxes_payment_relay;
        ALTER TABLE operations DROP COLUMN slot; ALTER TABLE mailboxes DROP COLUMN payment_state;",
        )
        .unwrap();
    let version: i64 = external
        .query_row("PRAGMA schema_version", [], |r| r.get(0))
        .unwrap();
    external.execute_batch("PRAGMA writable_schema=ON;").unwrap();
    for (narrow, wide) in [
        ("CHECK(member_count IN(3,4))", "CHECK(member_count BETWEEN 3 AND 16)"),
        ("CHECK(slot BETWEEN 2 AND 4)", "CHECK(slot BETWEEN 2 AND 16)"),
        ("CHECK(slot BETWEEN 1 AND 4)", "CHECK(slot BETWEEN 1 AND 16)"),
    ] {
        external
            .execute(
                "UPDATE sqlite_master SET sql=replace(sql,?1,?2) WHERE type='table'",
                [wide, narrow],
            )
            .unwrap();
    }
    external
        .execute_batch(&format!(
            "PRAGMA schema_version={}; PRAGMA writable_schema=OFF; PRAGMA user_version=1;",
            version + 1
        ))
        .unwrap();
}

#[test]
fn terminal_notice_schema_migrates_only_unversioned_legacy_roots() {
    let db = OwnedDb::new();
    drop(db.open());
    let external = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
    narrow_to_version_one(&external);
    external
        .execute_batch("DROP TABLE terminal_notices; PRAGMA user_version=0;")
        .unwrap();
    drop(db.open());
    let version: u64 = external
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
    external
        .execute_batch("DROP TABLE terminal_notices;")
        .unwrap();
    assert!(matches!(
        loki_setup_admission::AdmissionStore::open(
            &db.root,
            &config(),
            loki_setup_admission::EnrollmentVerifier::new(Some(
                ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes()
            )),
            ed25519_dalek::SigningKey::from_bytes(&[8; 32])
        ),
        Err(AdmissionError::Storage)
    ));
}

/// A version-1 root (bounded at 4 members) keeps its ceremonies and accepts larger
/// vaults after the in-place widening.
#[test]
fn version_one_root_widens_in_place_for_larger_vaults() {
    let db = OwnedDb::new();
    let grant = grant(3, 120);
    {
        let mut store = db.open();
        store
            .apply(&create(91, [91; 32], 4, &grant), Some(&grant), 100)
            .unwrap();
    }
    let external = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
    narrow_to_version_one(&external);
    assert!(external
        .execute(
            "UPDATE ceremonies SET member_count=5 WHERE id=?1",
            [[91u8; 32].as_slice()],
        )
        .is_err());
    let mut store = db.open();
    let version: u64 = external
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
    let kept: u16 = external
        .query_row(
            "SELECT member_count FROM ceremonies WHERE id=?1",
            [[91u8; 32].as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, 4);
    store
        .apply(&create(92, [92; 32], 16, &grant), Some(&grant), 100)
        .unwrap();
    for slot in 2..=16 {
        store
            .apply(
                &claim(slot as u8 + 100, [92; 32], slot, slot as u8),
                Some(&[slot as u8; 32]),
                101,
            )
            .unwrap();
    }
}

#[test]
fn terminal_notification_and_receipt_commit_atomically() {
    for count in [3u16, 4] {
        let db = OwnedDb::new();
        let mut store = db.open();
        let grant = grant(2, 48);
        store
            .apply(&create(81, [76; 32], count, &grant), Some(&grant), 100)
            .unwrap();
        let external = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
        external.execute_batch("CREATE TRIGGER fail_test_operation BEFORE INSERT ON operations BEGIN SELECT RAISE(ABORT,'owned_fault'); END;").unwrap();
        let abort = request(
            82,
            &identity(1, 1),
            AdmissionCommand::Terminal {
                ceremony: [76; 32],
                kind: 1,
            },
        );
        assert_eq!(
            store.apply(&abort, None, 101).unwrap_err(),
            AdmissionError::Storage
        );
        let terminal: u64 = external
            .query_row("SELECT terminal FROM ceremonies", [], |r| r.get(0))
            .unwrap();
        let notices: u64 = external
            .query_row("SELECT count(*) FROM terminal_notices", [], |r| r.get(0))
            .unwrap();
        assert_eq!((terminal, notices), (0, 0));
        external
            .execute_batch("DROP TRIGGER fail_test_operation")
            .unwrap();
        store.apply(&abort, None, 102).unwrap();
        let terminal: u64 = external
            .query_row("SELECT terminal FROM ceremonies", [], |r| r.get(0))
            .unwrap();
        let saved: Vec<u8> = external
            .query_row("SELECT request FROM terminal_notices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(terminal, 1);
        assert_eq!(saved, abort);
    }
}
