use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use loki_relay_client::{
    accept_descriptor, open_descriptor, open_record, seal_descriptor, seal_record,
    AuthenticatedDescriptor, ClientError, CommIdentity, Descriptor, DescriptorRelay, SealContext,
    SealDomain, Secret32,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    types::{roster_digest, RelayPin, RelayRoute, Roster},
};
use sha2::{Digest, Sha256};

fn identity(id: u16) -> CommIdentity {
    let mut seed = [0; 66];
    seed[..2].copy_from_slice(&id.to_be_bytes());
    seed[2..34].fill(id as u8);
    seed[34..].fill(id as u8 + 10);
    CommIdentity::from_serialized(&seed).unwrap()
}

fn roster() -> Roster {
    Roster {
        vault: [70; 32],
        members: (1..=3).map(|id| identity(id).public()).collect(),
    }
}

fn descriptor(revision: u64) -> Descriptor {
    let roster = roster();
    Descriptor::new(
        roster.vault,
        roster_digest(&roster).unwrap(),
        1,
        revision,
        (1..=3)
            .map(|index| DescriptorRelay {
                route: RelayRoute {
                    pin: RelayPin {
                        key: [index; 32],
                        run: [index + 10; 32],
                    },
                    endpoint: format!("http://127.0.0.1:{}", 8000 + u16::from(index)),
                    mailbox: [index + 20; 32],
                    append_revision: u64::from(index),
                },
                append: Secret32::from_bytes([index + 30; 32]),
            })
            .collect(),
    )
}

fn context(domain: SealDomain, recipient: u16) -> SealContext {
    let roster = roster();
    SealContext {
        vault: roster.vault,
        roster: roster_digest(&roster).unwrap(),
        recipient: identity(recipient).public(),
        domain,
    }
}

fn array(value: &Value) -> &[Value] {
    let Value::Array(fields) = value else {
        panic!("expected array")
    };
    fields
}

fn bytes(value: &Value) -> &[u8] {
    let Value::Bytes(bytes) = value else {
        panic!("expected bytes")
    };
    bytes
}

fn body_fields() -> Vec<Value> {
    let descriptor = descriptor(7);
    vec![
        Value::Integer(1.into()),
        Value::Bytes(descriptor.vault.to_vec()),
        Value::Bytes(descriptor.roster.to_vec()),
        Value::Integer(1.into()),
        Value::Integer(7.into()),
        Value::Array(
            descriptor
                .relays
                .iter()
                .map(|relay| {
                    Value::Array(vec![
                        Value::Bytes(relay.route.pin.key.to_vec()),
                        Value::Bytes(relay.route.endpoint.as_bytes().to_vec()),
                        Value::Bytes(relay.route.pin.run.to_vec()),
                        Value::Bytes(relay.route.mailbox.to_vec()),
                        Value::Integer(relay.route.append_revision.into()),
                        Value::Bytes(relay.append.as_bytes().to_vec()),
                    ])
                })
                .collect(),
        ),
    ]
}

fn raw_package(body: &[u8], signer: u8, domain: &[u8]) -> Vec<u8> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(body);
    let signature = SigningKey::from_bytes(&[signer; 32]).sign(&input);
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body.to_vec()),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
    .unwrap()
}

fn raw_record(package: &[u8]) -> Vec<u8> {
    canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(package.to_vec()),
    ]))
    .unwrap()
}

fn raw_wire(fields: Vec<Value>) -> Vec<u8> {
    let body = canonical::encode(&Value::Array(fields)).unwrap();
    let package = raw_package(&body, 1, b"Loki_Relay_Config_v1\0");
    seal_record(&context(SealDomain::Config, 2), &raw_record(&package))
        .unwrap()
        .wire
}

fn imported(revision: u64) -> AuthenticatedDescriptor {
    let roster = roster();
    let object = seal_descriptor(
        &identity(1),
        &roster,
        &descriptor(revision),
        &identity(2).public(),
    )
    .unwrap();
    open_descriptor(&identity(2), &roster, &object.wire).unwrap()
}

#[test]
fn descriptor_binding_exact_schema_and_domains() {
    let roster = roster();
    let mut copies = Vec::new();
    for recipient in 1..=3 {
        let object = seal_descriptor(
            &identity(1),
            &roster,
            &descriptor(7),
            &identity(recipient).public(),
        )
        .unwrap();
        assert_eq!(&object.wire[..9], b"LOKICFG1\x01");
        assert_eq!(object.wire.len() % 1024, 0);
        assert!(object.wire.len() <= 65536);
        assert_eq!(object.hash, <[u8; 32]>::from(Sha256::digest(&object.wire)));
        let record = open_record(
            &context(SealDomain::Config, recipient),
            &identity(recipient),
            &object.wire,
        )
        .unwrap();
        let inner = canonical::decode(&record, 65536).unwrap();
        assert_eq!(array(&inner).len(), 2);
        assert_eq!(array(&inner)[0], Value::Integer(1.into()));
        let package = canonical::decode(bytes(&array(&inner)[1]), 65536).unwrap();
        assert_eq!(array(&package).len(), 2);
        let body = bytes(&array(&package)[0]);
        assert_eq!(
            body,
            canonical::encode(&Value::Array(body_fields())).unwrap()
        );
        let mut input = b"Loki_Relay_Config_v1\0".to_vec();
        input.extend_from_slice(&(body.len() as u32).to_be_bytes());
        input.extend_from_slice(body);
        VerifyingKey::from_bytes(&roster.members[0].signing)
            .unwrap()
            .verify_strict(
                &input,
                &Signature::from_slice(bytes(&array(&package)[1])).unwrap(),
            )
            .unwrap();
        let opened = open_descriptor(&identity(recipient), &roster, &object.wire).unwrap();
        assert_eq!(*opened.digest(), <[u8; 32]>::from(Sha256::digest(body)));
        for (actual, expected) in opened.body().relays.iter().zip(descriptor(7).relays.iter()) {
            assert_eq!(actual.route, expected.route);
            assert_eq!(actual.append.as_bytes(), expected.append.as_bytes());
        }
        copies.push(object.wire);
    }
    assert_ne!(copies[0], copies[1]);
    assert_ne!(copies[1], copies[2]);
}

#[test]
fn descriptor_binding_fresh_ciphertext_same_revision() {
    let prior = imported(7);
    let fresh = imported(7);
    assert_eq!(accept_descriptor(&prior, &fresh), Ok(()));
    let next = imported(8);
    assert_eq!(accept_descriptor(&prior, &next), Ok(()));
}

#[test]
fn descriptor_binding_old_revision() {
    assert_eq!(
        accept_descriptor(&imported(7), &imported(6)),
        Err(ClientError::Conflict)
    );
}

#[test]
fn descriptor_binding_conflicting_revision() {
    let roster = roster();
    let mut conflicting = descriptor(7);
    conflicting.relays[0].route.mailbox = [99; 32];
    let wire = seal_descriptor(&identity(1), &roster, &conflicting, &identity(2).public())
        .unwrap()
        .wire;
    let conflicting = open_descriptor(&identity(2), &roster, &wire).unwrap();
    assert_eq!(
        accept_descriptor(&imported(7), &conflicting),
        Err(ClientError::Conflict)
    );
}

#[test]
fn descriptor_binding_readonly_canonical_association() {
    let import = imported(7);
    assert_eq!(
        import.canonical_body(),
        canonical::encode(&Value::Array(body_fields())).unwrap()
    );
    assert_eq!(
        *import.digest(),
        <[u8; 32]>::from(Sha256::digest(import.canonical_body()))
    );
    assert_eq!(import.body().vault, roster().vault);
    assert_eq!(import.body().roster, roster_digest(&roster()).unwrap());
    assert_eq!(import.body().owner, 1);
    assert_eq!(import.body().revision, 7);
}

#[test]
fn descriptor_binding_local_edits_do_not_change_import() {
    let import = imported(7);
    let mut local = descriptor(7);
    local.vault = [99; 32];
    local.relays[0].route.mailbox = [99; 32];
    local.relays[0].append = Secret32::from_bytes([99; 32]);
    assert_eq!(import.body().vault, roster().vault);
    assert_eq!(import.body().relays[0].route.mailbox, [21; 32]);
    assert_eq!(import.body().relays[0].append.as_bytes(), &[31; 32]);
}

#[test]
fn descriptor_binding_acceptance_scope() {
    let mut fields = body_fields();
    fields[3] = Value::Integer(3.into());
    fields[4] = Value::Integer(8.into());
    let body = canonical::encode(&Value::Array(fields)).unwrap();
    let package = raw_package(&body, 3, b"Loki_Relay_Config_v1\0");
    let wire = seal_record(&context(SealDomain::Config, 2), &raw_record(&package))
        .unwrap()
        .wire;
    let other = open_descriptor(&identity(2), &roster(), &wire).unwrap();
    assert_eq!(
        accept_descriptor(&imported(7), &other),
        Err(ClientError::Identity)
    );
}

#[test]
fn descriptor_binding_acceptance_different_vault() {
    let mut other_roster = roster();
    other_roster.vault = [71; 32];
    let mut input = descriptor(8);
    input.vault = other_roster.vault;
    input.roster = roster_digest(&other_roster).unwrap();
    let wire = seal_descriptor(&identity(1), &other_roster, &input, &identity(2).public())
        .unwrap()
        .wire;
    let other = open_descriptor(&identity(2), &other_roster, &wire).unwrap();
    assert_eq!(other.body().vault, other_roster.vault);
    assert_eq!(
        accept_descriptor(&imported(7), &other),
        Err(ClientError::Identity)
    );
}

#[test]
fn descriptor_binding_acceptance_different_roster() {
    let mut other_roster = roster();
    other_roster.members[2].encryption = identity(4).public().encryption;
    let mut input = descriptor(8);
    input.roster = roster_digest(&other_roster).unwrap();
    let wire = seal_descriptor(&identity(1), &other_roster, &input, &identity(2).public())
        .unwrap()
        .wire;
    let other = open_descriptor(&identity(2), &other_roster, &wire).unwrap();
    assert_eq!(other.body().roster, roster_digest(&other_roster).unwrap());
    assert_eq!(
        accept_descriptor(&imported(7), &other),
        Err(ClientError::Identity)
    );
}

fn reject_body(case: &str) {
    let mut fields = body_fields();
    match case {
        "version" => fields[0] = Value::Integer(2.into()),
        "vault" => fields[1] = Value::Bytes(vec![71; 32]),
        "roster" => fields[2] = Value::Bytes(vec![0; 32]),
        "owner" => fields[3] = Value::Integer(2.into()),
        "owner_zero" => fields[3] = Value::Integer(0.into()),
        "owner_overflow" => fields[3] = Value::Integer(65537u64.into()),
        "revision_zero" => fields[4] = Value::Integer(0.into()),
        "revision_overflow" => fields[4] = Value::Integer((i64::MAX as u64 + 1).into()),
        "extra_field" => fields.push(Value::Null),
        "short_id" => fields[1] = Value::Bytes(vec![70; 31]),
        other => {
            let Value::Array(relays) = &mut fields[5] else {
                panic!()
            };
            match other {
                "two_pins" => {
                    relays.pop();
                }
                "four_pins" => relays.push(relays[0].clone()),
                "unsorted_pins" => relays.swap(0, 1),
                "duplicate_pins" => {
                    let key = array(&relays[0])[0].clone();
                    let Value::Array(entry) = &mut relays[1] else {
                        panic!()
                    };
                    entry[0] = key;
                }
                "duplicate_caps" => {
                    let cap = array(&relays[0])[5].clone();
                    let Value::Array(entry) = &mut relays[1] else {
                        panic!()
                    };
                    entry[5] = cap;
                }
                other => {
                    let Value::Array(entry) = &mut relays[0] else {
                        panic!()
                    };
                    match other {
                        "extra_read_admin" => {
                            entry.push(Value::Bytes(vec![90; 32]));
                            entry.push(Value::Bytes(vec![91; 32]));
                        }
                        "append_revision_zero" => entry[4] = Value::Integer(0.into()),
                        "append_revision_overflow" => {
                            entry[4] = Value::Integer((i64::MAX as u64 + 1).into())
                        }
                        "short_cap" => entry[5] = Value::Bytes(vec![31; 31]),
                        "short_key" => entry[0] = Value::Bytes(vec![1; 31]),
                        "short_run" => entry[2] = Value::Bytes(vec![11; 31]),
                        "short_mailbox" => entry[3] = Value::Bytes(vec![21; 31]),
                        "url_utf8" => entry[1] = Value::Bytes(vec![255]),
                        "url_oversize" => entry[1] = Value::Bytes(vec![b'a'; 2049]),
                        _ => panic!("unknown body case"),
                    }
                }
            }
        }
    }
    assert!(
        open_descriptor(&identity(2), &roster(), &raw_wire(fields)).is_err(),
        "{case}"
    );
}

macro_rules! body_cases {
    ($($name:ident => $case:literal),* $(,)?) => { $(#[test] fn $name() { reject_body($case); })* };
}

body_cases! {
    descriptor_binding_body_version => "version",
    descriptor_binding_body_vault => "vault",
    descriptor_binding_body_roster => "roster",
    descriptor_binding_body_owner_signature => "owner",
    descriptor_binding_body_owner_zero => "owner_zero",
    descriptor_binding_body_owner_overflow => "owner_overflow",
    descriptor_binding_body_revision_zero => "revision_zero",
    descriptor_binding_body_revision_overflow => "revision_overflow",
    descriptor_binding_body_extra_field => "extra_field",
    descriptor_binding_body_short_id => "short_id",
    descriptor_binding_body_two_pins => "two_pins",
    descriptor_binding_body_four_pins => "four_pins",
    descriptor_binding_body_unsorted_pins => "unsorted_pins",
    descriptor_binding_body_duplicate_pins => "duplicate_pins",
    descriptor_binding_body_duplicate_caps => "duplicate_caps",
    descriptor_binding_body_extra_read_admin => "extra_read_admin",
    descriptor_binding_body_append_revision_zero => "append_revision_zero",
    descriptor_binding_body_append_revision_overflow => "append_revision_overflow",
    descriptor_binding_body_short_cap => "short_cap",
    descriptor_binding_body_short_key => "short_key",
    descriptor_binding_body_short_run => "short_run",
    descriptor_binding_body_short_mailbox => "short_mailbox",
    descriptor_binding_body_url_utf8 => "url_utf8",
    descriptor_binding_body_url_oversize => "url_oversize",
}

#[test]
fn descriptor_binding_url_rejections() {
    for url in [
        "http://localhost:8001",
        "http://127.0.0.2:8001",
        "http://0.0.0.0:8001",
        "http://[::2]:8001",
        "http://127.1:8001",
        "http://2130706433:8001",
        "http://0x7f000001:8001",
        "http://0177.0.0.1:8001",
        "http://127.0.0.1",
        "http://[::1]",
        "http://127.0.0.1:",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:+80",
        "http://user@127.0.0.1:8001",
        "http://%75ser@127.0.0.1:8001",
        "http://127.0.0.1:8001?",
        "http://127.0.0.1:8001#",
        "http://127.0.0.1:8001/?x=1",
        "http://127.0.0.1:8001/#x",
        "http://127.0.0.1:8001/v1",
        "http://127.0.0.1:8001/..",
        "http://127.0.0.1:8001/%2f",
        "http://127.0.0.1:8001//",
        "http://127.0.0.1:8001\\",
        "http://127.0.0.1:8001\n",
    ] {
        let mut input = descriptor(7);
        input.relays[0].route.endpoint = url.into();
        assert!(
            seal_descriptor(&identity(1), &roster(), &input, &identity(2).public()).is_err(),
            "{url}"
        );
        let mut fields = body_fields();
        let Value::Array(relays) = &mut fields[5] else {
            panic!()
        };
        let Value::Array(entry) = &mut relays[0] else {
            panic!()
        };
        entry[1] = Value::Bytes(url.as_bytes().to_vec());
        assert!(
            open_descriptor(&identity(2), &roster(), &raw_wire(fields)).is_err(),
            "{url}"
        );
    }
}

#[test]
fn descriptor_binding_url_acceptance_and_revision_independence() {
    for url in [
        "https://relay.example:443",
        "https://127.0.0.1:8001",
        "http://127.0.0.1:80",
        "http://127.0.0.1:65535/",
        "http://[::1]:80",
        "http://[::1]:8001/",
    ] {
        let mut input = descriptor(1);
        input.relays[0].route.endpoint = url.into();
        input.relays[2].route.append_revision = i64::MAX as u64;
        let wire = seal_descriptor(&identity(1), &roster(), &input, &identity(2).public())
            .unwrap()
            .wire;
        let opened = open_descriptor(&identity(2), &roster(), &wire).unwrap();
        assert_eq!(opened.body().relays[0].route.endpoint, url);
        assert_eq!(
            opened.body().relays[2].route.append_revision,
            i64::MAX as u64
        );
    }
}

#[test]
fn descriptor_binding_sealing_owner_and_recipient() {
    let input = descriptor(7);
    assert!(seal_descriptor(&identity(2), &roster(), &input, &identity(3).public()).is_err());
    let mut other = identity(2).public();
    other.signing[0] ^= 1;
    assert!(seal_descriptor(&identity(1), &roster(), &input, &other).is_err());
    other = identity(2).public();
    other.encryption[0] ^= 1;
    assert!(seal_descriptor(&identity(1), &roster(), &input, &other).is_err());
    let mut uncertified = roster();
    uncertified.members[0].encryption[0] ^= 1;
    assert!(seal_descriptor(&identity(1), &uncertified, &input, &identity(2).public()).is_err());
}

#[test]
fn descriptor_binding_opening_recipient_and_roster() {
    let wire = raw_wire(body_fields());
    assert!(open_descriptor(&identity(3), &roster(), &wire).is_err());
    for signing in [true, false] {
        let mut uncertified = roster();
        if signing {
            uncertified.members[1].signing[0] ^= 1;
        } else {
            uncertified.members[1].encryption[0] ^= 1;
        }
        assert!(open_descriptor(&identity(2), &uncertified, &wire).is_err());
    }
    let mut invalid = roster();
    invalid.members.swap(0, 1);
    assert!(open_descriptor(&identity(2), &invalid, &wire).is_err());
}

#[test]
fn descriptor_binding_uncertified_recipient_signing_identity() {
    let mut uncertified = roster();
    uncertified.members[1].signing = identity(4).public().signing;
    let digest = roster_digest(&uncertified).unwrap();
    let mut fields = body_fields();
    fields[2] = Value::Bytes(digest.to_vec());
    let body = canonical::encode(&Value::Array(fields)).unwrap();
    let package = raw_package(&body, 1, b"Loki_Relay_Config_v1\0");
    let mut ctx = context(SealDomain::Config, 2);
    ctx.roster = digest;
    let wire = seal_record(&ctx, &raw_record(&package)).unwrap().wire;
    assert!(open_descriptor(&identity(2), &uncertified, &wire).is_err());
}

#[test]
fn descriptor_binding_uncertified_signing_owner() {
    let mut uncertified = roster();
    uncertified.members[0].encryption = identity(4).public().encryption;
    let mut input = descriptor(7);
    input.roster = roster_digest(&uncertified).unwrap();
    assert!(seal_descriptor(&identity(1), &uncertified, &input, &identity(2).public()).is_err());
}

#[test]
fn descriptor_binding_config_signature_domain() {
    let body = canonical::encode(&Value::Array(body_fields())).unwrap();
    let package = raw_package(&body, 1, b"Loki_Relay_Message_v1\0");
    let wire = seal_record(&context(SealDomain::Config, 2), &raw_record(&package))
        .unwrap()
        .wire;
    assert!(open_descriptor(&identity(2), &roster(), &wire).is_err());
}

#[test]
fn descriptor_binding_message_envelope_domain() {
    let body = canonical::encode(&Value::Array(body_fields())).unwrap();
    let package = raw_package(&body, 1, b"Loki_Relay_Config_v1\0");
    let wire = seal_record(&context(SealDomain::Message, 2), &raw_record(&package))
        .unwrap()
        .wire;
    assert!(open_descriptor(&identity(2), &roster(), &wire).is_err());
}

#[test]
fn descriptor_binding_signature_and_package_schema() {
    let body = canonical::encode(&Value::Array(body_fields())).unwrap();
    for package in [
        canonical::encode(&Value::Array(vec![
            Value::Bytes(body.clone()),
            Value::Bytes(vec![0; 64]),
        ]))
        .unwrap(),
        canonical::encode(&Value::Array(vec![
            Value::Bytes(body.clone()),
            Value::Bytes(vec![0; 63]),
        ]))
        .unwrap(),
        canonical::encode(&Value::Array(vec![
            Value::Bytes(body.clone()),
            Value::Bytes(vec![0; 65]),
        ]))
        .unwrap(),
        canonical::encode(&Value::Array(vec![
            Value::Bytes(body.clone()),
            Value::Integer(1.into()),
        ]))
        .unwrap(),
        canonical::encode(&Value::Array(vec![Value::Bytes(body.clone())])).unwrap(),
        raw_package(&body, 2, b"Loki_Relay_Config_v1\0"),
    ] {
        let wire = seal_record(&context(SealDomain::Config, 2), &raw_record(&package))
            .unwrap()
            .wire;
        assert!(open_descriptor(&identity(2), &roster(), &wire).is_err());
    }
}

#[test]
fn descriptor_binding_inner_schema() {
    let body = canonical::encode(&Value::Array(body_fields())).unwrap();
    let package = raw_package(&body, 1, b"Loki_Relay_Config_v1\0");
    for inner in [
        Value::Array(vec![
            Value::Integer(2.into()),
            Value::Bytes(package.clone()),
        ]),
        Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(package.clone()),
            Value::Null,
        ]),
        Value::Array(vec![Value::Integer(1.into()), Value::Integer(1.into())]),
        Value::Array(vec![Value::Integer(1.into())]),
    ] {
        let record = canonical::encode(&inner).unwrap();
        let wire = seal_record(&context(SealDomain::Config, 2), &record)
            .unwrap()
            .wire;
        assert!(open_descriptor(&identity(2), &roster(), &wire).is_err());
    }
}

#[test]
fn descriptor_binding_nested_canonical_and_bounds() {
    let body = canonical::encode(&Value::Array(body_fields())).unwrap();
    let mut noncanonical_body = vec![0x98, 6];
    noncanonical_body.extend_from_slice(&body[1..]);
    let mut trailing_body = body.clone();
    trailing_body.push(0);
    let mut deep = vec![0x81; 16];
    deep.push(0xf6);
    for bad_body in [
        noncanonical_body,
        trailing_body,
        deep,
        vec![0x86, 0x5a, 0xff, 0xff, 0xff, 0xff],
    ] {
        let package = raw_package(&bad_body, 1, b"Loki_Relay_Config_v1\0");
        let wire = seal_record(&context(SealDomain::Config, 2), &raw_record(&package))
            .unwrap()
            .wire;
        assert!(open_descriptor(&identity(2), &roster(), &wire).is_err());
    }
    let package = raw_package(&body, 1, b"Loki_Relay_Config_v1\0");
    let mut noncanonical_package = vec![0x98, 2];
    noncanonical_package.extend_from_slice(&package[1..]);
    let wire = seal_record(
        &context(SealDomain::Config, 2),
        &raw_record(&noncanonical_package),
    )
    .unwrap()
    .wire;
    assert!(open_descriptor(&identity(2), &roster(), &wire).is_err());
    let mut oversized = raw_wire(body_fields());
    oversized.resize(66560, 0);
    assert!(open_descriptor(&identity(2), &roster(), &oversized).is_err());
}

use loki_relay_client::{ClientStore, ConfigReference};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

fn config_root(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = PathBuf::from("/private/tmp/relay-5.3-evidence").join(format!(
        "{}-{}-{}",
        label,
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&parent).unwrap();
    parent.join("client")
}

fn config_ref(revision: u64, byte: u8) -> ConfigReference {
    ConfigReference::new(revision, [byte; 32]).unwrap()
}

fn config_sql(root: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(root.join("client.sqlite3")).unwrap()
}

fn config_error<T>(result: Result<T, ClientError>, expected: ClientError) {
    match result {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("expected {expected}"),
    }
}

#[test]
fn config_reference_publication_retry_reopen() {
    let root = config_root("publication");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    assert_eq!(store.config_reference().unwrap(), None);
    let reference = config_ref(1, 41);
    store.record_config_revision(&reference).unwrap();
    store.record_config_revision(&reference).unwrap();
    assert_eq!(store.config_reference().unwrap(), Some(reference.clone()));
    drop(store);
    let store = ClientStore::open(&root, &roster(), 1).unwrap();
    let saved = store.config_reference().unwrap().unwrap();
    assert_eq!(saved.revision(), 1);
    assert_eq!(saved.hash(), &[41; 32]);
    assert_eq!(
        saved.file_name(),
        "secrets/relay-config-0000000000000001.sealed"
    );
}

#[test]
fn config_reference_conflicting_hash() {
    let root = config_root("conflict");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    store.record_config_revision(&config_ref(2, 42)).unwrap();
    config_error(
        store.record_config_revision(&config_ref(2, 43)),
        ClientError::Conflict,
    );
    assert_eq!(store.config_reference().unwrap(), Some(config_ref(2, 42)));
}

#[test]
fn config_reference_lower_revision() {
    let root = config_root("lower");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    store.record_config_revision(&config_ref(2, 42)).unwrap();
    config_error(
        store.record_config_revision(&config_ref(1, 42)),
        ClientError::Conflict,
    );
    assert_eq!(store.config_reference().unwrap(), Some(config_ref(2, 42)));
}

#[test]
fn config_reference_revision_bounds() {
    config_error(ConfigReference::new(0, [1; 32]), ClientError::Config);
    config_error(
        ConfigReference::new(i64::MAX as u64 + 1, [1; 32]),
        ClientError::Config,
    );
    config_error(ConfigReference::new(u64::MAX, [1; 32]), ClientError::Config);
    let root = config_root("bounds");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    store
        .record_config_revision(&config_ref(i64::MAX as u64, 44))
        .unwrap();
    assert_eq!(
        store.config_reference().unwrap(),
        Some(config_ref(i64::MAX as u64, 44))
    );
}

#[test]
fn config_reference_wrong_owner() {
    let root = config_root("owner");
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
    config_error(
        ClientStore::open(&root, &roster(), 2),
        ClientError::Identity,
    );
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
}

#[test]
fn config_reference_invalid_owner_and_roster() {
    for owner in [0, 4, u16::MAX] {
        let root = config_root("invalid-owner");
        config_error(
            ClientStore::open(&root, &roster(), owner),
            ClientError::Identity,
        );
        assert!(!root.exists());
    }
    let mut bad = roster();
    bad.members.pop();
    let root = config_root("invalid-roster");
    assert!(matches!(
        ClientStore::open(&root, &bad, 1),
        Err(ClientError::Wire(_))
    ));
    assert!(!root.exists());
}

#[test]
fn config_reference_wrong_vault() {
    let root = config_root("vault");
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
    let mut changed = roster();
    changed.vault[0] ^= 1;
    config_error(ClientStore::open(&root, &changed, 1), ClientError::Identity);
}

#[test]
fn config_reference_wrong_roster_keys() {
    let root = config_root("roster-keys");
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
    for member in 0..3 {
        let mut changed = roster();
        changed.members[member].encryption[0] ^= 1;
        config_error(ClientStore::open(&root, &changed, 1), ClientError::Identity);
    }
}

#[test]
fn config_reference_root_lock() {
    let root = config_root("lock");
    let store = ClientStore::open(&root, &roster(), 1).unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    drop(store);
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
}

#[test]
fn config_reference_pragmas_init_reopen() {
    let root = config_root("pragmas");
    for _ in 0..2 {
        let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
        let pragmas = store.pragmas().unwrap();
        assert_eq!(pragmas.journal_mode, "wal");
        assert_eq!(pragmas.synchronous, 2);
        assert_eq!(pragmas.foreign_keys, 1);
        assert_eq!(pragmas.busy_timeout, 5000);
        #[cfg(target_os = "macos")]
        assert_eq!(pragmas.fullfsync, 1);
        store.record_config_revision(&config_ref(1, 45)).unwrap();
    }
}

#[test]
fn config_reference_partial_root() {
    use std::os::unix::fs::PermissionsExt;
    let root = config_root("partial");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    assert!(!root.join("client.sqlite3").exists());
}

#[test]
fn config_reference_unknown_schema() {
    let root = config_root("schema");
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
    let sql = config_sql(&root);
    sql.execute_batch("DROP TRIGGER metadata_no_update; UPDATE metadata SET schema_version=2;")
        .unwrap();
    drop(sql);
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
}

#[test]
fn config_reference_corrupt_metadata() {
    for mutation in [
        "UPDATE metadata SET vault=x'00'",
        "UPDATE metadata SET roster=x'00'",
        "UPDATE metadata SET owner=0",
        "DELETE FROM metadata",
    ] {
        let root = config_root("metadata");
        drop(ClientStore::open(&root, &roster(), 1).unwrap());
        let sql = config_sql(&root);
        sql.execute_batch("DROP TRIGGER metadata_no_update; DROP TRIGGER metadata_no_delete; PRAGMA ignore_check_constraints=ON;").unwrap();
        sql.execute_batch(mutation).unwrap();
        drop(sql);
        config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    }
}

#[test]
fn config_reference_immutable_metadata() {
    let root = config_root("immutable");
    let store = ClientStore::open(&root, &roster(), 1).unwrap();
    let sql = config_sql(&root);
    assert!(sql.execute("UPDATE metadata SET owner=2", []).is_err());
    assert!(sql.execute("DELETE FROM metadata", []).is_err());
    assert_eq!(store.config_reference().unwrap(), None);
}

#[test]
fn config_reference_corrupt_reference() {
    for mutation in [
        "UPDATE config_versions SET revision=0",
        "UPDATE config_versions SET hash=x'00'",
    ] {
        let root = config_root("bad-reference");
        let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
        store.record_config_revision(&config_ref(1, 46)).unwrap();
        drop(store);
        let sql = config_sql(&root);
        sql.execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        sql.execute_batch(mutation).unwrap();
        drop(sql);
        config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    }
}

#[test]
fn config_reference_insert_failure_atomic() {
    let root = config_root("insert-failure");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    let sql = config_sql(&root);
    sql.execute_batch("CREATE TRIGGER fail_insert BEFORE INSERT ON config_versions BEGIN SELECT RAISE(ABORT,'fault'); END;").unwrap();
    config_error(
        store.record_config_revision(&config_ref(1, 47)),
        ClientError::Storage,
    );
    assert_eq!(store.config_reference().unwrap(), None);
    sql.execute_batch("DROP TRIGGER fail_insert;").unwrap();
    store.record_config_revision(&config_ref(1, 47)).unwrap();
    assert_eq!(store.config_reference().unwrap(), Some(config_ref(1, 47)));
}

#[test]
fn config_reference_commit_failure_atomic() {
    let root = config_root("commit-failure");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    store.record_config_revision(&config_ref(1, 48)).unwrap();
    let sql = config_sql(&root);
    sql.execute_batch("CREATE TABLE fault_parent(id INTEGER PRIMARY KEY); CREATE TABLE fault_child(id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER UPDATE ON config_versions BEGIN INSERT INTO fault_child VALUES(1); END;").unwrap();
    config_error(
        store.record_config_revision(&config_ref(2, 49)),
        ClientError::Storage,
    );
    assert_eq!(store.config_reference().unwrap(), Some(config_ref(1, 48)));
    drop(store);
    sql.execute_batch("DROP TRIGGER fail_commit; DROP TABLE fault_child; DROP TABLE fault_parent;").unwrap();
    drop(sql);
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    assert_eq!(store.config_reference().unwrap(), Some(config_ref(1, 48)));
    store.record_config_revision(&config_ref(2, 49)).unwrap();
}

#[test]
fn config_reference_no_orphan_adoption_or_capabilities() {
    let root = config_root("orphan");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    store.record_config_revision(&config_ref(1, 50)).unwrap();
    fs::create_dir(root.join("secrets")).unwrap();
    let sentinel = b"CAPABILITY_MUST_REMAIN_ONLY_IN_SEALED_CONFIGURATION_5_3";
    fs::write(
        root.join("secrets/relay-config-0000000000000002.sealed"),
        sentinel,
    )
    .unwrap();
    drop(store);
    let store = ClientStore::open(&root, &roster(), 1).unwrap();
    assert_eq!(store.config_reference().unwrap(), Some(config_ref(1, 50)));
    for file in ["client.sqlite3", "client.sqlite3-wal", "client.sqlite3-shm"] {
        if let Ok(bytes) = fs::read(root.join(file)) {
            assert!(!bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel));
        }
    }
    let sql = config_sql(&root);
    let mut stmt = sql
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let tables: Vec<String> = stmt
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
fn config_reference_permissions_and_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = config_root("permissions");
    let store = ClientStore::open(&root, &roster(), 1).unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["client.sqlite3", "client.sqlite3-wal", "client.sqlite3-shm"] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(store);
    let alias = root.parent().unwrap().join("alias");
    symlink(&root, &alias).unwrap();
    config_error(
        ClientStore::open(&alias, &roster(), 1),
        ClientError::Storage,
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let db = root.join("client.sqlite3");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    let moved = root.join("original.sqlite3");
    fs::rename(&db, &moved).unwrap();
    symlink(&moved, &db).unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
}

#[test]
fn config_reference_missing_schema_objects() {
    for mutation in [
        "DROP TABLE config_versions",
        "DROP TRIGGER metadata_no_update",
        "DROP TRIGGER metadata_no_delete",
    ] {
        let root = config_root("missing-schema");
        drop(ClientStore::open(&root, &roster(), 1).unwrap());
        config_sql(&root).execute_batch(mutation).unwrap();
        config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    }
}

#[test]
fn config_reference_retry_does_not_rewrite() {
    let root = config_root("retry-no-write");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    let reference = config_ref(1, 53);
    store.record_config_revision(&reference).unwrap();
    config_sql(&root).execute_batch("CREATE TRIGGER no_rewrite BEFORE UPDATE ON config_versions BEGIN SELECT RAISE(ABORT,'no rewrite'); END;").unwrap();
    store.record_config_revision(&reference).unwrap();
    assert_eq!(store.config_reference().unwrap(), Some(reference));
}

#[test]
fn config_reference_sidecar_symlink() {
    use std::os::unix::fs::symlink;
    let root = config_root("sidecar-symlink");
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
    let target = root.parent().unwrap().join("target");
    fs::write(&target, b"DO NOT TOUCH").unwrap();
    symlink(&target, root.join("client.sqlite3-wal")).unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    assert_eq!(fs::read(target).unwrap(), b"DO NOT TOUCH");
}

#[test]
fn config_reference_ancestor_symlink() {
    use std::os::unix::fs::symlink;
    let root = config_root("ancestor-symlink");
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
    let parent = root.parent().unwrap();
    let alias = parent.parent().unwrap().join(format!(
        "alias-{}",
        parent.file_name().unwrap().to_string_lossy()
    ));
    symlink(parent, &alias).unwrap();
    config_error(
        ClientStore::open(&alias.join("client"), &roster(), 1),
        ClientError::Storage,
    );
}

#[test]
fn config_reference_database_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let root = config_root("database-permissions");
    drop(ClientStore::open(&root, &roster(), 1).unwrap());
    fs::set_permissions(
        root.join("client.sqlite3"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
}

#[test]
fn config_reference_missing_database_schema() {
    use std::os::unix::fs::PermissionsExt;
    let root = config_root("empty-database");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("client.sqlite3"), []).unwrap();
    fs::set_permissions(
        root.join("client.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    config_error(ClientStore::open(&root, &roster(), 1), ClientError::Storage);
    assert_eq!(fs::metadata(root.join("client.sqlite3")).unwrap().len(), 0);
}

#[test]
#[ignore = "invoked by process parent or retained crash script"]
fn config_reference_process_child() {
    let root = PathBuf::from(std::env::var_os("RELAY_53_CHILD_ROOT").unwrap());
    let marker = PathBuf::from(std::env::var_os("RELAY_53_CHILD_MARKER").unwrap());
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    store.record_config_revision(&config_ref(2, 55)).unwrap();
    fs::write(marker, b"committed").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(10));
}

#[test]
fn config_reference_process_kill_after_commit() {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = config_root("process");
    let mut store = ClientStore::open(&root, &roster(), 1).unwrap();
    store.record_config_revision(&config_ref(1, 54)).unwrap();
    drop(store);
    let marker = root.parent().unwrap().join("marker");
    let log = fs::File::create(root.parent().unwrap().join("child.log")).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "config_reference_process_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RELAY_53_CHILD_ROOT", &root)
        .env("RELAY_53_CHILD_MARKER", &marker)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let ready = marker.exists();
    let lock_result = ClientStore::open(&root, &roster(), 1);
    let status = Command::new("kill")
        .args(["-KILL", &child.id().to_string()])
        .status()
        .unwrap();
    child.wait().unwrap();
    assert!(
        ready,
        "child did not reach committed barrier; see retained child.log"
    );
    assert!(status.success());
    config_error(lock_result, ClientError::Storage);
    let store = ClientStore::open(&root, &roster(), 1).unwrap();
    assert_eq!(store.config_reference().unwrap(), Some(config_ref(2, 55)));
}

fn control_request() -> Vec<u8> {
    loki_relay_protocol::http::encode_creation(&loki_relay_protocol::types::Creation {
        read_verifier: [1; 32],
        append_verifier: [2; 32],
        admin_verifier: [3; 32],
        quota: 4096,
    })
    .unwrap()
}
fn control_server(
    status: u16,
    headers: &str,
    body: Vec<u8>,
) -> (RelayRoute, std::thread::JoinHandle<Vec<u8>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let headers = headers.to_owned();
    let task = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let text = String::from_utf8(request.clone()).unwrap();
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
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).unwrap();
        request.extend(payload);
        let response = format!("HTTP/1.1 {status} Control\r\n{headers}Connection: close\r\n\r\n");
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&body);
        request
    });
    (
        RelayRoute {
            pin: RelayPin {
                key: [1; 32],
                run: [2; 32],
            },
            endpoint: format!("http://127.0.0.1:{port}"),
            mailbox: [3; 32],
            append_revision: 1,
        },
        task,
    )
}
fn control_result(mailbox: [u8; 32], run: [u8; 32], quota: u64, revision: u64) -> Vec<u8> {
    loki_relay_protocol::http::encode_creation_result(
        &mailbox,
        &loki_relay_protocol::types::CreationResult {
            created: true,
            run,
            quota,
            append_revision: revision,
        },
    )
    .unwrap()
}
#[tokio::test]
async fn owner_provision_http_exact_request_and_retry_revision() {
    use base64::Engine;
    let http = loki_relay_client::RelayHttp::new().unwrap();
    for (status, revision) in [(201, 1), (200, 7)] {
        let body = control_result([3; 32], [2; 32], 4096, revision);
        let (route, server) = control_server(
            status,
            &format!(
                "Content-Type: application/cbor\r\nContent-Length: {}\r\n",
                body.len()
            ),
            body,
        );
        let result = http
            .create(&route, &Secret32::from_bytes([9; 32]), &control_request())
            .await
            .unwrap();
        assert_eq!(result.created, status == 201);
        assert_eq!(result.append_revision, revision);
        let wire = server.join().unwrap();
        let split = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&wire[split..], control_request());
        let header = String::from_utf8(wire[..split].to_vec())
            .unwrap()
            .to_ascii_lowercase();
        assert!(header.starts_with(&format!(
            "put /v1/mailboxes/{} http/1.1",
            hex::encode([3; 32])
        )));
        let exact = String::from_utf8(wire[..split].to_vec()).unwrap();
        let authorization = exact
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(": ")?;
                name.eq_ignore_ascii_case("authorization").then_some(value)
            })
            .unwrap();
        assert_eq!(
            authorization,
            format!(
                "Bearer {}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32])
            )
        );
        assert!(header.contains("content-type: application/cbor"));
        assert!(!header.contains("accept-encoding:"));
    }
}
#[tokio::test]
async fn owner_provision_http_rejects_scope_status_media_and_stream() {
    let http = loki_relay_client::RelayHttp::new().unwrap();
    for (status, headers, body) in [
        (
            201,
            "Content-Type: application/cbor\r\n",
            control_result([4; 32], [2; 32], 4096, 1),
        ),
        (
            201,
            "Content-Type: application/cbor\r\n",
            control_result([3; 32], [4; 32], 4096, 1),
        ),
        (
            201,
            "Content-Type: application/cbor\r\n",
            control_result([3; 32], [2; 32], 4097, 1),
        ),
        (
            201,
            "Content-Type: application/cbor\r\n",
            control_result([3; 32], [2; 32], 4096, 2),
        ),
        (
            202,
            "Content-Type: application/cbor\r\n",
            control_result([3; 32], [2; 32], 4096, 1),
        ),
        (
            201,
            "Content-Type: application/cbor; charset=utf-8\r\n",
            control_result([3; 32], [2; 32], 4096, 1),
        ),
        (
            201,
            "Content-Type: application/cbor\r\nContent-Encoding: gzip\r\n",
            control_result([3; 32], [2; 32], 4096, 1),
        ),
        (201, "Content-Type: application/cbor\r\n", vec![0; 4097]),
        (
            201,
            "Content-Type: application/cbor\r\n",
            vec![0x9f, 1, 0xff],
        ),
        (201, "Content-Type: application/cbor\r\n", {
            let mut b = control_result([3; 32], [2; 32], 4096, 1);
            b.push(0);
            b
        }),
        (
            302,
            "Content-Type: application/cbor\r\nLocation: http://127.0.0.1:1/\r\n",
            vec![],
        ),
    ] {
        let (route, server) = control_server(status, headers, body);
        assert!(
            http.create(&route, &Secret32::from_bytes([9; 32]), &control_request())
                .await
                .is_err(),
            "accepted status {status} headers {headers}"
        );
        server.join().unwrap();
    }
}
#[test]
fn owner_provision_http_literal_endpoint() {
    // Unsafe original authorities must be refused before URL normalization.
    let http = loki_relay_client::RelayHttp::new().unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for endpoint in [
        "http://localhost:1",
        "http://127.1:1",
        "http://2130706433:1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:1/?x",
        "http://127.0.0.1:1/..",
        "http://u@127.0.0.1:1",
    ] {
        let route = RelayRoute {
            pin: RelayPin {
                key: [1; 32],
                run: [2; 32],
            },
            endpoint: endpoint.into(),
            mailbox: [3; 32],
            append_revision: 1,
        };
        assert_eq!(
            runtime
                .block_on(http.create(&route, &Secret32::from_bytes([9; 32]), &control_request()))
                .err(),
            Some(ClientError::Config)
        );
    }
}
#[tokio::test]
async fn owner_provision_http_closed_error_mapping() {
    use loki_relay_protocol::http::{encode_error, ErrorCode};
    let http = loki_relay_client::RelayHttp::new().unwrap();
    for (code, want) in [
        (ErrorCode::MalformedRequest, ClientError::Config),
        (ErrorCode::InvalidCapability, ClientError::Identity),
        (ErrorCode::ObjectNotFound, ClientError::Config),
        (ErrorCode::Conflict, ClientError::Conflict),
        (ErrorCode::CursorAhead, ClientError::Config),
        (ErrorCode::ObjectTooLarge, ClientError::Capacity),
        (ErrorCode::UnsupportedMediaType, ClientError::Config),
        (ErrorCode::AdmissionLimit, ClientError::Capacity),
        (ErrorCode::StorageUnavailable, ClientError::Storage),
        (ErrorCode::QuotaExhausted, ClientError::Capacity),
    ] {
        let (route, server) = control_server(
            code.status(),
            "Content-Type: application/cbor\r\n",
            encode_error(code).unwrap(),
        );
        assert_eq!(
            http.create(&route, &Secret32::from_bytes([9; 32]), &control_request())
                .await
                .err(),
            Some(want)
        );
        server.join().unwrap();
    }
    for (status, body) in [
        (401, encode_error(ErrorCode::Conflict).unwrap()),
        (418, vec![0x82, 1, 2]),
        (400, vec![0x82, 1, 11]),
    ] {
        let (route, server) = control_server(status, "Content-Type: application/cbor\r\n", body);
        assert_eq!(
            http.create(&route, &Secret32::from_bytes([9; 32]), &control_request())
                .await
                .err(),
            Some(ClientError::Transport)
        );
        server.join().unwrap();
    }
}
#[tokio::test]
async fn owner_provision_http_rotate_binding() {
    use loki_relay_protocol::{
        http::{encode_append_result, encode_append_update},
        types::AppendUpdate,
    };
    let http = loki_relay_client::RelayHttp::new().unwrap();
    let request = encode_append_update(&AppendUpdate {
        revision: 2,
        verifier: [5; 32],
    })
    .unwrap();
    for (status, mailbox, revision, ok) in [
        (200, [3; 32], 2, true),
        (201, [3; 32], 2, false),
        (200, [4; 32], 2, false),
        (200, [3; 32], 3, false),
    ] {
        let (route, server) = control_server(
            status,
            "Content-Type: application/cbor\r\n",
            encode_append_result(&mailbox, revision).unwrap(),
        );
        let result = http
            .rotate(&route, &Secret32::from_bytes([8; 32]), &request)
            .await;
        assert_eq!(result.is_ok(), ok);
        let wire = server.join().unwrap();
        assert!(String::from_utf8_lossy(&wire).starts_with(&format!(
            "PUT /v1/mailboxes/{}/append-capability ",
            hex::encode([3; 32])
        )));
    }
}

async fn control_rejected(status: u16, headers: &str, body: Vec<u8>) {
    let http = loki_relay_client::RelayHttp::new().unwrap();
    let (route, server) = control_server(status, headers, body);
    let result = http
        .create(&route, &Secret32::from_bytes([9; 32]), &control_request())
        .await;
    server.join().unwrap();
    assert!(
        result.is_err(),
        "unbound or malformed control result accepted"
    );
}
macro_rules! control_negative {
    ($name:ident,$status:expr,$headers:expr,$body:expr) => {
        #[tokio::test]
        async fn $name() {
            control_rejected($status, $headers, $body).await;
        }
    };
}
control_negative!(
    owner_provision_guard_mailbox,
    201,
    "Content-Type: application/cbor\r\n",
    control_result([4; 32], [2; 32], 4096, 1)
);
control_negative!(
    owner_provision_guard_run,
    201,
    "Content-Type: application/cbor\r\n",
    control_result([3; 32], [4; 32], 4096, 1)
);
control_negative!(
    owner_provision_guard_quota,
    201,
    "Content-Type: application/cbor\r\n",
    control_result([3; 32], [2; 32], 4097, 1)
);
control_negative!(
    owner_provision_guard_new_revision,
    201,
    "Content-Type: application/cbor\r\n",
    control_result([3; 32], [2; 32], 4096, 2)
);
control_negative!(
    owner_provision_guard_success_status,
    202,
    "Content-Type: application/cbor\r\n",
    control_result([3; 32], [2; 32], 4096, 1)
);
control_negative!(
    owner_provision_guard_media,
    201,
    "Content-Type: application/cbor; charset=utf-8\r\n",
    control_result([3; 32], [2; 32], 4096, 1)
);
control_negative!(
    owner_provision_guard_duplicate_media,
    201,
    "Content-Type: application/cbor\r\nContent-Type: application/cbor\r\n",
    control_result([3; 32], [2; 32], 4096, 1)
);
control_negative!(
    owner_provision_guard_encoding,
    201,
    "Content-Type: application/cbor\r\nContent-Encoding: gzip\r\n",
    control_result([3; 32], [2; 32], 4096, 1)
);
control_negative!(
    owner_provision_guard_declared_limit_malformed,
    201,
    "Content-Type: application/cbor\r\nContent-Length: 4097\r\n",
    {
        let mut b = control_result([3; 32], [2; 32], 4096, 1);
        b.resize(4097, 0);
        b
    }
);
control_negative!(
    owner_provision_guard_actual_stream_limit_malformed,
    201,
    "Content-Type: application/cbor\r\nTransfer-Encoding: chunked\r\n",
    format!("1001\r\n{}\r\n0\r\n\r\n", "x".repeat(4097)).into_bytes()
);
control_negative!(
    owner_provision_guard_error_status,
    401,
    "Content-Type: application/cbor\r\n",
    loki_relay_protocol::http::encode_error(loki_relay_protocol::http::ErrorCode::Conflict)
        .unwrap()
);
control_negative!(
    owner_provision_guard_closed_error,
    400,
    "Content-Type: application/cbor\r\n",
    vec![0x82, 1, 11]
);
#[tokio::test]
async fn owner_provision_guard_stale_retry_revision() {
    let (mut route, server) = control_server(
        200,
        "Content-Type: application/cbor\r\n",
        control_result([3; 32], [2; 32], 4096, 1),
    );
    route.append_revision = 2;
    let result = loki_relay_client::RelayHttp::new()
        .unwrap()
        .create(&route, &Secret32::from_bytes([9; 32]), &control_request())
        .await;
    server.join().unwrap();
    assert!(result.is_err(), "retry rolled back known revision");
}
#[tokio::test]
async fn owner_provision_guard_rotate_mailbox() {
    let (route, server) = control_server(
        200,
        "Content-Type: application/cbor\r\n",
        loki_relay_protocol::http::encode_append_result(&[4; 32], 2).unwrap(),
    );
    let request = loki_relay_protocol::http::encode_append_update(
        &loki_relay_protocol::types::AppendUpdate {
            revision: 2,
            verifier: [5; 32],
        },
    )
    .unwrap();
    let result = loki_relay_client::RelayHttp::new()
        .unwrap()
        .rotate(&route, &Secret32::from_bytes([8; 32]), &request)
        .await;
    server.join().unwrap();
    assert!(result.is_err(), "rotation accepted wrong mailbox");
}
#[tokio::test]
async fn owner_provision_guard_rotate_revision() {
    let (route, server) = control_server(
        200,
        "Content-Type: application/cbor\r\n",
        loki_relay_protocol::http::encode_append_result(&[3; 32], 3).unwrap(),
    );
    let request = loki_relay_protocol::http::encode_append_update(
        &loki_relay_protocol::types::AppendUpdate {
            revision: 2,
            verifier: [5; 32],
        },
    )
    .unwrap();
    let result = loki_relay_client::RelayHttp::new()
        .unwrap()
        .rotate(&route, &Secret32::from_bytes([8; 32]), &request)
        .await;
    server.join().unwrap();
    assert!(result.is_err(), "rotation accepted wrong revision");
}
#[tokio::test]
async fn owner_provision_guard_rotate_status() {
    let (route, server) = control_server(
        201,
        "Content-Type: application/cbor\r\n",
        loki_relay_protocol::http::encode_append_result(&[3; 32], 2).unwrap(),
    );
    let request = loki_relay_protocol::http::encode_append_update(
        &loki_relay_protocol::types::AppendUpdate {
            revision: 2,
            verifier: [5; 32],
        },
    )
    .unwrap();
    let result = loki_relay_client::RelayHttp::new()
        .unwrap()
        .rotate(&route, &Secret32::from_bytes([8; 32]), &request)
        .await;
    server.join().unwrap();
    assert!(result.is_err(), "rotation accepted wrong status");
}
#[tokio::test]
async fn owner_provision_http_redirect_not_followed() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (route, server) = control_server(
        302,
        &format!("Content-Type: application/cbor\r\nLocation: http://127.0.0.1:{port}/\r\n"),
        vec![],
    );
    listener.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = stop.clone();
    let redirected = std::thread::spawn(move || {
        let mut visits = 0;
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    visits += 1;
                    let mut b = [0; 4096];
                    let _ = stream.read(&mut b);
                    let _=stream.write_all(b"HTTP/1.1 400 Bad\r\nContent-Type: application/cbor\r\nContent-Length: 3\r\n\r\n\x82\x01\x01");
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(2)),
            }
        }
        visits
    });
    let result = loki_relay_client::RelayHttp::new()
        .unwrap()
        .create(&route, &Secret32::from_bytes([9; 32]), &control_request())
        .await;
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    server.join().unwrap();
    assert_eq!(
        redirected.join().unwrap(),
        0,
        "redirect destination contacted"
    );
    assert!(result.is_err());
}

async fn control_early_bound(chunked: bool) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut byte = [0; 1];
        let mut raw = Vec::new();
        while !raw.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            raw.push(byte[0]);
        }
        let length: usize = String::from_utf8(raw)
            .unwrap()
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .unwrap()
            .parse()
            .unwrap();
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        if chunked {
            let _=stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Type: application/cbor\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n");
            let _ = stream.write_all(&vec![0; 4097]);
            let _ = stream.write_all(b"\r\n");
        } else {
            let _=stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Type: application/cbor\r\nContent-Length: 4097\r\n\r\n");
            let _ = stream.write_all(&control_result([3; 32], [2; 32], 4096, 1));
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
    let route = RelayRoute {
        pin: RelayPin {
            key: [1; 32],
            run: [2; 32],
        },
        endpoint: format!("http://127.0.0.1:{port}"),
        mailbox: [3; 32],
        append_revision: 1,
    };
    let http = loki_relay_client::RelayHttp::new().unwrap();
    let start = std::time::Instant::now();
    let result = http
        .create(&route, &Secret32::from_bytes([9; 32]), &control_request())
        .await;
    let elapsed = start.elapsed();
    task.join().unwrap();
    assert!(result.is_err());
    assert!(
        elapsed < std::time::Duration::from_millis(1500),
        "control limit waited for untrusted stream: {elapsed:?}"
    );
}
#[tokio::test]
async fn owner_provision_guard_declared_limit() {
    control_early_bound(false).await;
}
#[tokio::test]
async fn owner_provision_guard_actual_stream_limit() {
    control_early_bound(true).await;
}

#[tokio::test]
async fn owner_provision_http_total_timeout_and_redacted_error() {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0; 4096];
        let _ = stream.read(&mut buf);
        std::thread::sleep(std::time::Duration::from_secs(11));
    });
    let route = RelayRoute {
        pin: RelayPin {
            key: [1; 32],
            run: [2; 32],
        },
        endpoint: format!("http://127.0.0.1:{port}"),
        mailbox: [3; 32],
        append_revision: 1,
    };
    let start = std::time::Instant::now();
    let result = loki_relay_client::RelayHttp::new()
        .unwrap()
        .create(&route, &Secret32::from_bytes([9; 32]), &control_request())
        .await;
    let elapsed = start.elapsed();
    server.join().unwrap();
    assert_eq!(result.err(), Some(ClientError::Transport));
    assert!(
        elapsed >= std::time::Duration::from_secs(9)
            && elapsed < std::time::Duration::from_millis(10800),
        "timeout {elapsed:?}"
    );
}

#[tokio::test]
#[ignore]
async fn owner_provision_proxy_child() {
    let (route, server) = control_server(
        201,
        "Content-Type: application/cbor\r\n",
        control_result([3; 32], [2; 32], 4096, 1),
    );
    let result = loki_relay_client::RelayHttp::new()
        .unwrap()
        .create(&route, &Secret32::from_bytes([9; 32]), &control_request())
        .await;
    if result.is_err() {
        std::process::exit(23);
    }
    server.join().unwrap();
}
#[test]
fn owner_provision_guard_proxy_disabled() {
    use std::io::{Read, Write};
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = proxy.local_addr().unwrap().port();
    proxy.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = stop.clone();
    let server = std::thread::spawn(move || {
        let mut requests = 0;
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((mut stream, _)) = proxy.accept() {
                requests += 1;
                let mut raw = [0; 4096];
                let _ = stream.read(&mut raw);
                let _=stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/cbor\r\nContent-Length: 3\r\nConnection: close\r\n\r\n\x82\x01\x02");
            } else {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        requests
    });
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child.args(["owner_provision_proxy_child", "--exact", "--ignored"]);
    for key in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        child.env(key, format!("http://127.0.0.1:{port}"));
    }
    for key in ["NO_PROXY", "no_proxy"] {
        child.env(key, "");
    }
    let output = child.output().unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let requests = server.join().unwrap();
    assert_eq!(requests, 0, "client sent capability to proxy");
    assert!(
        output.status.success(),
        "proxy child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
