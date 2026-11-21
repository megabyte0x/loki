mod support;
use ed25519_dalek::{Signer, SigningKey};
use loki_relay_protocol::{
    envelope,
    http::{encode_creation, encode_setup_control},
    nonce::{self, ClaimProof, Claimant},
    types::{Creation, Object, RelayPin},
};
use loki_relay_server::{
    capability::{provisioning_verifier, verifier},
    Capability, Limits, RelayError, RelayStore, Role,
};
use sha2::{Digest, Sha256};
use support::Scratch;
fn limits() -> Limits {
    Limits {
        total_bytes: 100000,
        mailbox_bytes: 10000,
        mailbox_count: 10,
    }
}
fn create(id: [u8; 32]) -> Vec<u8> {
    encode_creation(&Creation {
        read_verifier: verifier(Role::Read, id, &[2; 32]),
        append_verifier: verifier(Role::Append, id, &[3; 32]),
        admin_verifier: verifier(Role::Admin, id, &[4; 32]),
        quota: 10000,
    })
    .unwrap()
}
fn object(tag: u8, setup: bool) -> Object {
    let mut wire = vec![tag; 1024];
    wire[..8].copy_from_slice(if setup {
        envelope::SETUP_MAGIC
    } else {
        envelope::MESSAGE_MAGIC
    });
    wire[8] = 1;
    Object {
        hash: Sha256::digest(&wire).into(),
        wire,
    }
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
#[test]
fn setup_expiry_retains_active_data_then_removes_only_setup_objects_and_never_revives() {
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
    let setup = [1; 32];
    let payment = [5; 32];
    let deadline = now() + 10000;
    let control = encode_setup_control(&create(setup), deadline, false).unwrap();
    store
        .setup_control(setup, &control, &Capability::new([8; 32]))
        .unwrap();
    store
        .create(payment, &create(payment), &Capability::new([8; 32]))
        .unwrap();
    let setup_obj = object(11, true);
    let payment_obj = object(12, false);
    store
        .put(setup, &setup_obj, &Capability::new([3; 32]))
        .unwrap();
    store
        .put(payment, &payment_obj, &Capability::new([3; 32]))
        .unwrap();
    let key = SigningKey::from_bytes(&[2; 32]);
    let who = Claimant {
        vault: [9; 32],
        slot: 1,
        key: key.verifying_key().to_bytes(),
    };
    let pin = RelayPin {
        key: store.public_key(),
        run: store.run_id(),
    };
    let proof = |mailbox| ClaimProof {
        claimant: who,
        signature: key
            .sign(&nonce::claim_input(
                who,
                &pin,
                mailbox,
                [10; 32],
                [11; 32],
                &[1, 2, 3],
            ))
            .to_bytes(),
    };
    store.enroll_nonce_claimant(payment, who, 2048).unwrap();
    store
        .claim_nonce(payment, [10; 32], [11; 32], &[1, 2, 3], &proof(payment))
        .unwrap();
    assert_eq!(
        store.claim_nonce(setup, [10; 32], [11; 32], &[1, 2, 3], &proof(setup)),
        Err(RelayError::Capability)
    );
    assert_eq!(store.cleanup_setup(deadline - 1).unwrap(), 0);
    assert_eq!(
        store
            .get(setup, setup_obj.hash, &Capability::new([2; 32]))
            .unwrap(),
        setup_obj.wire
    );
    assert_eq!(store.cleanup_setup(deadline).unwrap(), 1);
    assert_eq!(
        store.get(setup, setup_obj.hash, &Capability::new([2; 32])),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.put(setup, &setup_obj, &Capability::new([3; 32])),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store
            .get(payment, payment_obj.hash, &Capability::new([2; 32]))
            .unwrap(),
        payment_obj.wire
    );
    drop(store);
    let mut store = RelayStore::open(root.path(), limits()).unwrap();
    assert_eq!(
        store.create(setup, &create(setup), &Capability::new([8; 32])),
        Err(RelayError::Capability)
    );
    assert!(store
        .setup_control(setup, &control, &Capability::new([8; 32]))
        .is_err());
    let (fresh, _) = store
        .claim_nonce(payment, [10; 32], [11; 32], &[1, 2, 3], &proof(payment))
        .unwrap();
    assert!(!fresh, "the payment claim survived cleanup and reopening");
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT used_bytes FROM nonce_claimants", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        515
    );
    assert_eq!(
        db.query_row(
            "SELECT used_bytes FROM metadata WHERE singleton=1",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        1024
    );
}
#[test]
fn setup_control_rejects_foreign_capability_deadline_change_and_payment_conversion() {
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
    let deadline = now() + 10000;
    let control = encode_setup_control(&create([1; 32]), deadline, false).unwrap();
    assert_eq!(
        store.setup_control([1; 32], &control, &Capability::new([9; 32])),
        Err(RelayError::Capability)
    );
    store
        .setup_control([1; 32], &control, &Capability::new([8; 32]))
        .unwrap();
    assert_eq!(
        store.setup_control(
            [1; 32],
            &encode_setup_control(&create([1; 32]), deadline + 1, false).unwrap(),
            &Capability::new([8; 32])
        ),
        Err(RelayError::Conflict)
    );
    store
        .create([5; 32], &create([5; 32]), &Capability::new([8; 32]))
        .unwrap();
    assert_eq!(
        store.setup_control(
            [5; 32],
            &encode_setup_control(&create([5; 32]), deadline, false).unwrap(),
            &Capability::new([8; 32])
        ),
        Err(RelayError::Conflict)
    );
    let retire = encode_setup_control(&create([1; 32]), deadline, true).unwrap();
    store
        .setup_control([1; 32], &retire, &Capability::new([8; 32]))
        .unwrap();
    store
        .setup_control([1; 32], &retire, &Capability::new([8; 32]))
        .unwrap();
    assert_eq!(
        store.setup_control([1; 32], &control, &Capability::new([8; 32])),
        Err(RelayError::Capability)
    );
}

#[test]
fn namespace_intent_survives_failed_mailbox_creation_and_reopen() {
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
    store
        .create([5; 32], &create([5; 32]), &Capability::new([8; 32]))
        .unwrap();
    let external = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    external.execute_batch("CREATE TRIGGER fail_owned_setup BEFORE INSERT ON mailboxes BEGIN SELECT RAISE(ABORT,'owned_fault'); END;").unwrap();
    let exact = encode_setup_control(&create([1; 32]), now() + 10000, false).unwrap();
    assert_eq!(
        store.setup_control([1; 32], &exact, &Capability::new([8; 32])),
        Err(RelayError::StorageUnavailable)
    );
    assert_eq!(
        external
            .query_row("SELECT count(*) FROM setup_namespaces", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        external
            .query_row("SELECT count(*) FROM mailboxes", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        1
    );
    external
        .execute_batch("DROP TRIGGER fail_owned_setup")
        .unwrap();
    drop(store);
    let mut store = RelayStore::open(root.path(), limits()).unwrap();
    assert!(
        store
            .setup_control([1; 32], &exact, &Capability::new([8; 32]))
            .unwrap()
            .created
    );
    assert!(
        !store
            .setup_control([1; 32], &exact, &Capability::new([8; 32]))
            .unwrap()
            .created
    );
}
#[test]
fn elapsed_namespace_rejects_all_capabilities_before_janitor_runs() {
    use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
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
    let expires = now() + 2;
    let control = encode_setup_control(&create([1; 32]), expires, false).unwrap();
    store
        .setup_control([1; 32], &control, &Capability::new([8; 32]))
        .unwrap();
    let original = object(12, true);
    store
        .put([1; 32], &original, &Capability::new([3; 32]))
        .unwrap();
    while now() < expires {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(
        store.get([1; 32], original.hash, &Capability::new([2; 32])),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.page([1; 32], 0, 1, &Capability::new([2; 32])),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.put([1; 32], &original, &Capability::new([3; 32])),
        Err(RelayError::Capability)
    );
    let rotate = encode_append_update(&AppendUpdate {
        revision: 2,
        verifier: verifier(Role::Append, [1; 32], &[20; 32]),
    })
    .unwrap();
    assert_eq!(
        store.rotate([1; 32], &rotate, &Capability::new([4; 32])),
        Err(RelayError::Capability)
    );
}
