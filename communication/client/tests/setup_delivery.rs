use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{
    BootstrapContext, ClientError, CommIdentity, OperatorSet, SetupAuthority, SetupPolicy,
    SetupStore, SetupTransport,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{SetupKey, SetupPhase, SetupRecord},
    types::{roster_digest, Roster},
};
fn bundle(signer: &SigningKey, change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut fields = vec![
        Value::Integer(1.into()),
        Value::Array(
            (1u8..=3)
                .map(|i| {
                    Value::Array(vec![
                        Value::Bytes(
                            SigningKey::from_bytes(&[i; 32])
                                .verifying_key()
                                .to_bytes()
                                .to_vec(),
                        ),
                        Value::Bytes(vec![i + 10; 32]),
                        Value::Bytes(format!("https://relay{i}.example").into_bytes()),
                    ])
                })
                .collect(),
        ),
        Value::Array(vec![
            Value::Bytes(b"https://admission.example".to_vec()),
            Value::Bytes(
                SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            ),
        ]),
        Value::Array(vec![Value::Integer(2.into())]),
        Value::Array(vec![
            Value::Integer(86400.into()),
            Value::Integer(2592000.into()),
            Value::Integer(1048576.into()),
            Value::Integer(67108864.into()),
            Value::Integer(30.into()),
            Value::Integer(1.into()),
            Value::Integer(60.into()),
        ]),
    ];
    if let Value::Array(routes) = &mut fields[1] {
        routes.sort_by_key(|r| canonical::encode(r).unwrap());
    }
    change(&mut fields);
    let body = canonical::encode(&Value::Array(fields)).unwrap();
    let mut input = b"Loki_Operator_Config_v1\0".to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(signer.sign(&input).to_bytes().to_vec()),
    ]))
    .unwrap()
}

fn identity(id: u16) -> CommIdentity {
    let mut raw = [0; 66];
    raw[..2].copy_from_slice(&id.to_be_bytes());
    raw[2..34].fill(id as u8);
    raw[34..].fill(id as u8 + 10);
    CommIdentity::from_serialized(&raw).unwrap()
}
fn config() -> (Vec<u8>, [u8; 32], OperatorSet) {
    let signer = SigningKey::from_bytes(&[90; 32]);
    let b = bundle(&signer, |_| {});
    let key = signer.verifying_key().to_bytes();
    let op = OperatorSet::verify(&b, &key).unwrap();
    (b, key, op)
}
fn policy(count: u16, op: &OperatorSet) -> SetupPolicy {
    SetupPolicy {
        ceremony: [70; 32],
        network: "regtest".into(),
        threshold: 2,
        member_count: count,
        config_digest: *op.digest(),
    }
}
fn roster(count: u16) -> Roster {
    Roster {
        vault: [70; 32],
        members: (1..=count).map(|id| identity(id).public()).collect(),
    }
}

fn root() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::path::PathBuf::from("/private/tmp").join(format!(
        "loki-setup-delivery-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn join(p: &SetupPolicy, recipient: u16, payload: Vec<u8>) -> SetupRecord {
    SetupRecord {
        version: loki_relay_protocol::setup::SETUP_VERSION,
        key: SetupKey {
            ceremony: p.ceremony,
            phase: SetupPhase::Join,
            author: p.member_count,
            recipient,
            revision: 1,
        },
        network: p.network.clone(),
        threshold: 2,
        member_count: p.member_count,
        roster_digest: None,
        prerequisites: vec![],
        payload,
    }
}
#[test]
fn durable_exact_ciphertext_self_copy_and_conflict() {
    for n in [3, 4] {
        let (_, _, op) = config();
        let p = policy(n, &op);
        let r = roster(n);
        let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
        let id = identity(n);
        let transport =
            SetupTransport::new(&id, &op, SetupAuthority::Bootstrap(&ctx, &r.members), false)
                .unwrap();
        let records = vec![
            join(&p, 1, vec![83; 1024 * 1024]),
            join(&p, n, vec![83; 1024 * 1024]),
        ];
        let prepared = transport.prepare(&records).unwrap();
        let checkpoint = transport.checkpoint_prepared(&prepared).unwrap();
        let restored = transport.restore_prepared(&checkpoint).unwrap();
        for record in &records {
            use sha2::{Digest, Sha256};
            let expected: [u8; 32] =
                Sha256::digest(loki_relay_protocol::setup::encode_record(record).unwrap()).into();
            assert_eq!(
                prepared.recipient_digest(record.key.recipient).unwrap(),
                expected
            );
            assert_eq!(
                restored.recipient_digest(record.key.recipient).unwrap(),
                expected
            );
        }
        assert!(prepared.recipient_digest(0).is_err());
        assert_eq!(
            checkpoint,
            transport.checkpoint_prepared(&restored).unwrap()
        );
        for recipient in [1, n] {
            let (root, objects) = prepared.recipient_objects(recipient).unwrap();
            let (same, copies) = restored.recipient_objects(recipient).unwrap();
            assert_eq!(root, same);
            assert_eq!(objects, copies);
        }
        let mut corrupt = checkpoint.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(transport.restore_prepared(&corrupt).is_err());
        let mut trailing = checkpoint.clone();
        trailing.push(0);
        assert!(transport.restore_prepared(&trailing).is_err());

        let path = root();
        let mut store = SetupStore::open(&path, &transport).unwrap();
        assert!(store.commit_outgoing(&transport, &prepared).unwrap());
        for name in ["setup.sqlite3", "setup.sqlite3-wal"] {
            let raw = std::fs::read(path.join(name)).unwrap();
            assert!(!raw.windows(32).any(|b| b == [83; 32]));
        }
        let saved = store.saved_objects().unwrap();
        assert!(saved.len() > 2);
        assert!(!store.commit_outgoing(&transport, &prepared).unwrap());
        let got = store.receive(&transport, &records[1].key).unwrap().unwrap();
        assert_eq!(got.body().payload, records[1].payload);
        drop(store);
        let mut store = SetupStore::open(&path, &transport).unwrap();
        assert_eq!(saved, store.saved_objects().unwrap());
        let changed = transport
            .prepare(&[join(&p, 1, vec![7]), join(&p, n, vec![7])])
            .unwrap();
        assert_eq!(
            store.commit_outgoing(&transport, &changed),
            Err(ClientError::Conflict)
        );
        drop(store);
        let store = SetupStore::open(&path, &transport).unwrap();
        assert!(store.is_terminal().unwrap());
        assert!(store.receive(&transport, &records[1].key).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
#[test]
fn join_requires_creator_and_self_and_rejects_dkg_before_acceptance() {
    let (_, _, op) = config();
    let p = policy(4, &op);
    let r = roster(4);
    let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
    let id = identity(4);
    let t =
        SetupTransport::new(&id, &op, SetupAuthority::Bootstrap(&ctx, &r.members), false).unwrap();
    assert!(t.prepare(&[join(&p, 1, vec![1])]).is_err());
    let mut round = join(&p, 1, vec![1]);
    round.key.phase = SetupPhase::Round1;
    round.roster_digest = Some(roster_digest(&r).unwrap());
    assert!(t.prepare(&[round]).is_err());
}

#[test]
fn incoming_commit_is_duplicate_safe_and_blocks_out_of_order_prerequisites() {
    let (_, _, op) = config();
    let p = policy(4, &op);
    let r = roster(4);
    let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
    let sender = identity(4);
    let receiver = identity(1);
    let send = SetupTransport::new(
        &sender,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let recv = SetupTransport::new(
        &receiver,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let early = vec![join(&p, 1, vec![1]), join(&p, 4, vec![1])];
    let prepared = send.prepare(&early).unwrap();
    let (root, objects) = prepared.recipient_objects(1).unwrap();
    let path = root_path_for_receive();
    let mut store = SetupStore::open(&path, &recv).unwrap();
    let original = recv.authenticate_objects(&root, &objects).unwrap();
    let mut late = early.clone();
    for record in &mut late {
        record.key.revision = 2;
        record.prerequisites = vec![*original.digest()];
        record.payload = vec![2];
    }
    let later = send.prepare(&late).unwrap();
    let (later_root, later_objects) = later.recipient_objects(1).unwrap();
    assert!(store
        .commit_incoming(&recv, &later_root, &later_objects)
        .unwrap());
    assert!(store.receive(&recv, &late[0].key).unwrap().is_none());
    drop(store);
    let mut store = SetupStore::open(&path, &recv).unwrap();
    assert!(store.commit_incoming(&recv, &root, &objects).unwrap());
    assert!(!store.commit_incoming(&recv, &root, &objects).unwrap());
    assert_eq!(
        store
            .receive(&recv, &late[0].key)
            .unwrap()
            .unwrap()
            .body()
            .payload,
        vec![2]
    );
    let different = send
        .prepare(&[join(&p, 1, vec![9]), join(&p, 4, vec![9])])
        .unwrap();
    let (bad_root, bad_objects) = different.recipient_objects(1).unwrap();
    assert_eq!(
        store.commit_incoming(&recv, &bad_root, &bad_objects),
        Err(ClientError::Conflict)
    );
    assert!(store.is_terminal().unwrap());
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}
fn root_path_for_receive() -> std::path::PathBuf {
    root()
}

#[test]
fn invitation_bootstrap_descriptor_is_encrypted_and_policy_bound() {
    use loki_relay_client::{DescriptorRelay, Secret32, SetupInboxDescriptor, SetupInvite};
    let (bundle, key, op) = config();
    let p = policy(4, &op);
    let creator = identity(1);
    let relays = op
        .relay_routes()
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut route = r.clone();
            route.mailbox = [i as u8 + 80; 32];
            route.append_revision = 1;
            DescriptorRelay {
                route,
                append: Secret32::from_bytes([i as u8 + 90; 32]),
            }
        })
        .collect();
    let signed = SetupInboxDescriptor::sign(&creator, &p, &op, relays).unwrap();
    let raw =
        SetupInvite::create_with_bootstrap(&creator, &p, 4, 1000, [42; 32], &op, &signed).unwrap();
    let v = canonical::decode(&raw, 16384).unwrap();
    let Value::Array(f) = v else { panic!() };
    assert_eq!(f.len(), 3);
    let Value::Bytes(cipher) = &f[2] else {
        panic!()
    };
    assert_eq!(&cipher[..8], b"LOKISET1");
    assert!(!cipher.windows(32).any(|w| w == [90; 32]));
    let invite = SetupInvite::verify(&raw, &creator.public(), &bundle, &key, 100).unwrap();
    let desc = invite.bootstrap_descriptor().unwrap();
    assert_eq!(&*desc.to_package(), &*signed);
    assert_eq!(desc.owner(), 1);
    assert_eq!(desc.relays().len(), 3);
    assert_eq!(desc.relays()[0].append.as_bytes(), &[90; 32]);
    let other = policy(3, &op);
    assert!(
        SetupInvite::create_with_bootstrap(&creator, &other, 3, 1000, [42; 32], &op, &signed)
            .is_err()
    );
}

#[test]
fn prerequisites_are_transitive_and_store_association_is_checked_on_every_commit() {
    let (_, _, op) = config();
    let p = policy(4, &op);
    let r = roster(4);
    let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
    let sender = identity(4);
    let receiver = identity(1);
    let send = SetupTransport::new(
        &sender,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let recv = SetupTransport::new(
        &receiver,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let first = send
        .prepare(&[join(&p, 1, vec![1]), join(&p, 4, vec![1])])
        .unwrap();
    let (a, ao) = first.recipient_objects(1).unwrap();
    let ad = *recv.authenticate_objects(&a, &ao).unwrap().digest();
    let mut b = vec![join(&p, 1, vec![2]), join(&p, 4, vec![2])];
    for x in &mut b {
        x.key.revision = 2;
        x.prerequisites = vec![ad];
    }
    let second = send.prepare(&b).unwrap();
    let (br, bo) = second.recipient_objects(1).unwrap();
    let bd = *recv.authenticate_objects(&br, &bo).unwrap().digest();
    let mut c = b.clone();
    for x in &mut c {
        x.key.revision = 3;
        x.prerequisites = vec![bd];
        x.payload = vec![3];
    }
    let third = send.prepare(&c).unwrap();
    let (cr, co) = third.recipient_objects(1).unwrap();
    let path = root();
    let mut store = SetupStore::open(&path, &recv).unwrap();
    store.commit_incoming(&recv, &br, &bo).unwrap();
    store.commit_incoming(&recv, &cr, &co).unwrap();
    assert!(store.receive(&recv, &c[0].key).unwrap().is_none());
    store.commit_incoming(&recv, &a, &ao).unwrap();
    assert!(store.receive(&recv, &c[0].key).unwrap().is_some());
    let mut other = p.clone();
    other.ceremony = [71; 32];
    let ctx2 = BootstrapContext::creator(other.clone(), identity(1).public(), &op).unwrap();
    let send2 = SetupTransport::new(
        &sender,
        &op,
        SetupAuthority::Bootstrap(&ctx2, &r.members),
        false,
    )
    .unwrap();
    let recv2 = SetupTransport::new(
        &receiver,
        &op,
        SetupAuthority::Bootstrap(&ctx2, &r.members),
        false,
    )
    .unwrap();
    let p2 = send2
        .prepare(&[join(&other, 1, vec![1]), join(&other, 4, vec![1])])
        .unwrap();
    let (o, oo) = p2.recipient_objects(1).unwrap();
    assert_eq!(
        store.commit_incoming(&recv2, &o, &oo),
        Err(ClientError::Identity)
    );
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

/// Relay request deadline in the operator bundle of the delivery test.
const REQUEST_SECONDS: u64 = 3;

#[tokio::test]
async fn peers_arrive_independently_after_creator_offline_and_ack_survives_reopen() {
    use loki_relay_client::{
        DescriptorRelay, OwnerInbox, Secret32, SetupInboxDescriptor, SetupRoutes,
    };
    use loki_relay_protocol::{
        http::encode_creation,
        types::{Creation, RelayPin, RelayRoute},
    };
    use loki_relay_server::{
        capability::{provisioning_verifier, verifier},
        Capability, DbHandle, Limits, RelayStore, Role,
    };
    for n in [3u16, 4] {
        let parent = root();
        std::fs::create_dir(&parent).unwrap();
        let limits = Limits {
            total_bytes: 32 * 1024 * 1024,
            mailbox_bytes: 4 * 1024 * 1024,
            mailbox_count: 4,
        };
        let mut routes = Vec::new();
        let mut servers = Vec::new();
        let mut owners = Vec::new();
        for index in 1u8..=3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let run = [index + 10; 32];
            let provision = [index + 20; 32];
            let relay_root = parent.join(format!("relay{index}"));
            let mut relay = RelayStore::init(
                &relay_root,
                run,
                &endpoint,
                &provision,
                provisioning_verifier(run, &provision),
                limits,
            )
            .unwrap();
            let pin = RelayPin {
                key: relay.public_key(),
                run,
            };
            for member in 1u8..=n as u8 {
                let mut mailbox = [0; 32];
                mailbox[0] = member;
                mailbox[1] = index;
                relay
                    .create(
                        mailbox,
                        &encode_creation(&Creation {
                            read_verifier: verifier(Role::Read, mailbox, &[member + 40; 32]),
                            append_verifier: verifier(
                                Role::Append,
                                mailbox,
                                &[member + index + 50; 32],
                            ),
                            admin_verifier: verifier(Role::Admin, mailbox, &[member + 60; 32]),
                            quota: 4 * 1024 * 1024,
                        })
                        .unwrap(),
                        &Capability::new(provision),
                    )
                    .unwrap();
            }
            drop(relay);
            routes.push((pin, endpoint, index));
            let (db, owner) = DbHandle::open(relay_root, limits).await.unwrap();
            owners.push(owner);
            servers.push(tokio::spawn(async move {
                axum::serve(listener, loki_relay_server::http::router(db))
                    .await
                    .unwrap();
            }));
        }
        routes.sort_by_key(|(pin, _, _)| pin.key);
        let signer = SigningKey::from_bytes(&[90; 32]);
        let raw = bundle(&signer, |f| {
            f[1] = Value::Array(
                routes
                    .iter()
                    .map(|(pin, origin, _)| {
                        Value::Array(vec![
                            Value::Bytes(pin.key.to_vec()),
                            Value::Bytes(pin.run.to_vec()),
                            Value::Bytes(origin.as_bytes().to_vec()),
                        ])
                    })
                    .collect(),
            );
            if let Value::Array(limits) = &mut f[4] {
                limits[4] = Value::Integer(REQUEST_SECONDS.into());
            }
            f[2] = Value::Array(vec![
                Value::Bytes(b"http://127.0.0.1:19999".to_vec()),
                Value::Bytes(
                    SigningKey::from_bytes(&[8; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                ),
            ]);
        });
        let op = OperatorSet::verify_development(&raw, &signer.verifying_key().to_bytes()).unwrap();
        let p = policy(n, &op);
        let r = roster(n);
        let creator = identity(1);
        let ctx = BootstrapContext::creator(p.clone(), creator.public(), &op).unwrap();
        let make_routes = |member: u16| {
            let route_for = |m: u16| {
                routes
                    .iter()
                    .map(|(pin, endpoint, index)| {
                        let mut mailbox = [0; 32];
                        mailbox[0] = m as u8;
                        mailbox[1] = *index;
                        DescriptorRelay {
                            route: RelayRoute {
                                pin: pin.clone(),
                                endpoint: endpoint.clone(),
                                mailbox,
                                append_revision: 1,
                            },
                            append: Secret32::from_bytes([m as u8 + index + 50; 32]),
                        }
                    })
                    .collect::<Vec<_>>()
            };
            let own = route_for(member)
                .into_iter()
                .map(|d| OwnerInbox {
                    route: d.route,
                    append: d.append,
                    read: Secret32::from_bytes([member as u8 + 40; 32]),
                    admin: Secret32::from_bytes([member as u8 + 60; 32]),
                })
                .collect();
            let peers = (1..=n)
                .filter(|m| *m != member)
                .map(|m| {
                    let package =
                        SetupInboxDescriptor::sign(&identity(m), &p, &op, route_for(m)).unwrap();
                    SetupInboxDescriptor::verify(&package, &p, &op, &identity(m).public()).unwrap()
                })
                .collect();
            SetupRoutes { own, peers }
        };
        let t = SetupTransport::new(
            &creator,
            &op,
            SetupAuthority::Bootstrap(&ctx, &r.members),
            true,
        )
        .unwrap();
        let creator_routes = make_routes(1);
        let records: Vec<_> = (1..=n)
            .map(|recipient| SetupRecord {
                version: loki_relay_protocol::setup::SETUP_VERSION,
                key: SetupKey {
                    ceremony: p.ceremony,
                    phase: SetupPhase::RosterProposal,
                    author: 1,
                    recipient,
                    revision: 1,
                },
                network: p.network.clone(),
                threshold: 2,
                member_count: n,
                roster_digest: Some(roster_digest(&r).unwrap()),
                prerequisites: vec![],
                payload: vec![74; 70_000],
            })
            .collect();
        let foreign_context = loki_relay_client::SealContext {
            vault: p.ceremony,
            roster: p.config_digest,
            recipient: creator.public(),
            domain: loki_relay_client::SealDomain::Message,
        };
        let foreign = loki_relay_client::seal_record(
            &foreign_context,
            &canonical::encode(&Value::Array(vec![Value::Integer(1.into())])).unwrap(),
        )
        .unwrap();
        let http = loki_relay_client::RelayHttp::new().unwrap();
        for own in &creator_routes.own {
            http.put(&own.route, &own.append, &foreign).await.unwrap();
        }
        let mut store = SetupStore::open(&parent.join("member1"), &t).unwrap();
        store
            .commit_outgoing(&t, &t.prepare(&records).unwrap())
            .unwrap();
        let unavailable = servers.remove(0);
        unavailable.abort();
        let _ = unavailable.await;
        // With four members the first relay accepts connections but never answers: the
        // drive must still finish within one relay deadline and store on the other two.
        let hanging = if n == 4 {
            let (_, endpoint, _) = routes.iter().find(|(_, _, index)| *index == 1).unwrap();
            let listener = tokio::net::TcpListener::bind(endpoint.trim_start_matches("http://"))
                .await
                .unwrap();
            Some(tokio::spawn(async move {
                let mut held = Vec::new();
                while let Ok((socket, _)) = listener.accept().await {
                    held.push(socket);
                }
            }))
        } else {
            None
        };
        let started = std::time::Instant::now();
        let progress = t.drive_once(&mut store, &creator_routes).await.unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2 * REQUEST_SECONDS),
            "a hanging relay held the drive for {:?}",
            started.elapsed()
        );
        if let Some(hanging) = hanging {
            hanging.abort();
            let _ = hanging.await;
        }
        assert_eq!(progress.stored_groups, 1);
        assert_eq!(progress.received_groups, 0);
        let retry_sql = rusqlite::Connection::open(parent.join("member1/setup.sqlite3")).unwrap();
        let retries: i64 = retry_sql
            .query_row(
                "SELECT count(*) FROM retries WHERE attempts>0 AND next_ms>0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retries, 1);
        drop(retry_sql);
        drop(store);
        for member in (2..=n).rev() {
            let id = identity(member);
            let peer =
                SetupTransport::new(&id, &op, SetupAuthority::Bootstrap(&ctx, &r.members), true)
                    .unwrap();
            let peer_routes = make_routes(member);
            let path = parent.join(format!("member{member}"));
            let mut store = SetupStore::open(&path, &peer).unwrap();
            peer.drive_once(&mut store, &peer_routes).await.unwrap();
            assert_eq!(
                store
                    .receive(&peer, &records[member as usize - 1].key)
                    .unwrap()
                    .unwrap()
                    .body()
                    .payload,
                vec![74; 70_000]
            );
            let saved = store.saved_objects().unwrap();
            drop(store);
            let mut store = SetupStore::open(&path, &peer).unwrap();
            assert_eq!(saved, store.saved_objects().unwrap());
            peer.drive_once(&mut store, &peer_routes).await.unwrap();
            assert_eq!(saved, store.saved_objects().unwrap());
        }
        let mut store = SetupStore::open(&parent.join("member1"), &t).unwrap();
        let progress = t.drive_once(&mut store, &creator_routes).await.unwrap();
        assert_eq!(progress.stored_groups, 1);
        assert_eq!(progress.received_groups, 1);
        let mut next_records = records.clone();
        for record in &mut next_records {
            record.key.revision = 2;
        }
        store
            .commit_outgoing(&t, &t.prepare(&next_records).unwrap())
            .unwrap();
        let old = store
            .progress_for(&t, &creator_routes, &records[0].key)
            .unwrap();
        assert_eq!((old.stored_groups, old.received_groups), (1, 1));
        let next = store
            .progress_for(&t, &creator_routes, &next_records[0].key)
            .unwrap();
        assert_eq!(
            (next.stored_groups, next.received_groups),
            (0, 0),
            "the old phase quorum must not authorize unpublished new ciphertext"
        );
        let mut foreign = next_records[0].key.clone();
        foreign.ceremony = [5; 32];
        assert_eq!(
            store.progress_for(&t, &creator_routes, &foreign),
            Err(ClientError::Identity)
        );
        let sql = rusqlite::Connection::open(parent.join("member1/setup.sqlite3")).unwrap();
        sql.execute("UPDATE stored SET receipt=x'80'", []).unwrap();
        assert!(store.progress(&t, &creator_routes).is_err());
        drop(sql);
        drop(store);
        for server in servers {
            server.abort();
            let _ = server.await;
        }
        for owner in owners {
            owner.shutdown().await.unwrap();
        }
        std::fs::remove_dir_all(parent).unwrap();
    }
}

#[test]
fn acceptance_transport_requires_inner_agreement_and_keeps_history_after_acceptance() {
    use loki_relay_client::{sign_roster_acceptance, AcceptedSetupRoster};
    use loki_relay_protocol::setup::SetupCapabilities;
    let (_, _, op) = config();
    let p = policy(4, &op);
    let r = roster(4);
    let creator = identity(1);
    let ctx = BootstrapContext::creator(p.clone(), creator.public(), &op).unwrap();
    let id = identity(4);
    let t =
        SetupTransport::new(&id, &op, SetupAuthority::Bootstrap(&ctx, &r.members), false).unwrap();
    let inner = sign_roster_acceptance(&id, &ctx, &r, &SetupCapabilities::current()).unwrap();
    let records: Vec<_> = (1..=4)
        .map(|recipient| SetupRecord {
            version: loki_relay_protocol::setup::SETUP_VERSION,
            key: SetupKey {
                ceremony: p.ceremony,
                phase: SetupPhase::RosterAccept,
                author: 4,
                recipient,
                revision: 1,
            },
            network: p.network.clone(),
            threshold: 2,
            member_count: 4,
            roster_digest: Some(roster_digest(&r).unwrap()),
            prerequisites: vec![],
            payload: inner.clone(),
        })
        .collect();
    let prepared = t.prepare(&records).unwrap();
    let (root, objects) = prepared.recipient_objects(4).unwrap();
    assert_eq!(
        t.authenticate_objects(&root, &objects)
            .unwrap()
            .body()
            .payload,
        inner
    );
    let mut bad = records.clone();
    for b in &mut bad {
        b.payload = vec![1];
    }
    assert!(t.prepare(&bad).is_err());
    let acceptances: Vec<_> = (1..=4)
        .map(|m| {
            sign_roster_acceptance(&identity(m), &ctx, &r, &SetupCapabilities::current()).unwrap()
        })
        .collect();
    let accepted = AcceptedSetupRoster::verify(&ctx, r.clone(), &acceptances).unwrap();
    let post = SetupTransport::new(&id, &op, SetupAuthority::Accepted(&accepted), false).unwrap();
    assert_eq!(
        post.authenticate_objects(&root, &objects)
            .unwrap()
            .body()
            .payload,
        inner
    );
}

#[test]
fn signed_changed_roster_is_terminal_but_unauthenticated_noise_is_not() {
    use loki_relay_client::{sign_roster_acceptance, AcceptedSetupRoster};
    use loki_relay_protocol::setup::SetupCapabilities;
    let (_, _, op) = config();
    let p = policy(4, &op);
    let r = roster(4);
    let creator = identity(1);
    let member = identity(4);
    let ctx = BootstrapContext::creator(p.clone(), creator.public(), &op).unwrap();
    let all: Vec<_> = (1..=4)
        .map(|m| {
            sign_roster_acceptance(&identity(m), &ctx, &r, &SetupCapabilities::current()).unwrap()
        })
        .collect();
    let accepted = AcceptedSetupRoster::verify(&ctx, r.clone(), &all).unwrap();
    let sender = SetupTransport::new(
        &creator,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let receiver =
        SetupTransport::new(&member, &op, SetupAuthority::Accepted(&accepted), false).unwrap();
    let records: Vec<_> = (1..=4)
        .map(|recipient| SetupRecord {
            version: loki_relay_protocol::setup::SETUP_VERSION,
            key: SetupKey {
                ceremony: p.ceremony,
                phase: SetupPhase::RosterProposal,
                author: 1,
                recipient,
                revision: 2,
            },
            network: p.network.clone(),
            threshold: 2,
            member_count: 4,
            roster_digest: Some([99; 32]),
            prerequisites: vec![],
            payload: vec![6],
        })
        .collect();
    let prepared = sender.prepare(&records).unwrap();
    let (root, objects) = prepared.recipient_objects(4).unwrap();
    let path = root_path_for_receive();
    let mut store = SetupStore::open(&path, &receiver).unwrap();
    let mut noise = root.clone();
    noise.wire[100] ^= 1;
    assert!(store.commit_incoming(&receiver, &noise, &objects).is_err());
    assert!(!store.is_terminal().unwrap());
    let seal = loki_relay_client::SealContext {
        vault: p.ceremony,
        roster: p.config_digest,
        recipient: member.public(),
        domain: loki_relay_client::SealDomain::Setup,
    };
    let plaintext = loki_relay_client::open_record(&seal, &member, &root.wire).unwrap();
    let mut frame = canonical::decode(&plaintext, 65536).unwrap();
    let Value::Array(f) = &mut frame else {
        panic!()
    };
    let Value::Bytes(package) = &mut f[1] else {
        panic!()
    };
    let mut signed = canonical::decode(package, 65536).unwrap();
    let Value::Array(s) = &mut signed else {
        panic!()
    };
    let Value::Bytes(signature) = &mut s[1] else {
        panic!()
    };
    signature[0] ^= 1;
    *package = canonical::encode(&signed).unwrap();
    let forged =
        loki_relay_client::seal_record(&seal, &canonical::encode(&frame).unwrap()).unwrap();
    assert!(store
        .commit_incoming(&receiver, &forged, &std::collections::BTreeMap::new())
        .is_err());
    assert!(!store.is_terminal().unwrap());
    assert_eq!(
        store.commit_incoming(&receiver, &root, &objects),
        Err(ClientError::Conflict)
    );
    assert!(store.is_terminal().unwrap());
    drop(store);
    let store = SetupStore::open(&path, &receiver).unwrap();
    assert!(store.is_terminal().unwrap());
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn lower_signed_payload_limit_is_enforced_before_preparation() {
    let signer = SigningKey::from_bytes(&[90; 32]);
    let b = bundle(&signer, |f| {
        let Value::Array(limits) = &mut f[4] else {
            panic!()
        };
        limits[2] = Value::Integer(8.into());
    });
    let op = OperatorSet::verify(&b, &signer.verifying_key().to_bytes()).unwrap();
    let p = policy(4, &op);
    let r = roster(4);
    let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
    let id = identity(4);
    let t =
        SetupTransport::new(&id, &op, SetupAuthority::Bootstrap(&ctx, &r.members), false).unwrap();
    assert!(t
        .prepare(&[join(&p, 1, vec![5; 9]), join(&p, 4, vec![5; 9])])
        .is_err());
}

#[test]
fn incoming_and_acknowledgement_commit_roll_back_together_on_storage_failure() {
    let (_, _, op) = config();
    let p = policy(4, &op);
    let r = roster(4);
    let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
    let sender = identity(4);
    let owner = identity(1);
    let send = SetupTransport::new(
        &sender,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let receive = SetupTransport::new(
        &owner,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let records = vec![join(&p, 1, vec![5]), join(&p, 4, vec![5])];
    let prepared = send.prepare(&records).unwrap();
    let (root, objects) = prepared.recipient_objects(1).unwrap();
    let path = root_path_for_receive();
    let mut store = SetupStore::open(&path, &receive).unwrap();
    let sql = rusqlite::Connection::open(path.join("setup.sqlite3")).unwrap();
    sql.execute_batch("CREATE TRIGGER owned_ack_failure BEFORE INSERT ON acknowledgements BEGIN SELECT RAISE(ABORT,'owned fault'); END;").unwrap();
    assert!(store.commit_incoming(&receive, &root, &objects).is_err());
    assert!(store.receive(&receive, &records[0].key).unwrap().is_none());
    assert!(store.saved_objects().unwrap().is_empty());
    sql.execute_batch("DROP TRIGGER owned_ack_failure;")
        .unwrap();
    drop(sql);
    drop(store);
    let mut store = SetupStore::open(&path, &receive).unwrap();
    assert!(store.commit_incoming(&receive, &root, &objects).unwrap());
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn wrong_relay_identity_never_receives_private_read_capability() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use loki_relay_client::{OwnerInbox, Secret32, SetupRoutes};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let exposed = Arc::new(AtomicUsize::new(0));
    let count = exposed.clone();
    let app = axum::Router::new().fallback(move |request: Request<Body>| {
        let count = count.clone();
        async move {
            if request.headers().contains_key("authorization") {
                count.fetch_add(1, Ordering::SeqCst);
            }
            StatusCode::BAD_REQUEST
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let signer = SigningKey::from_bytes(&[90; 32]);
    let b = bundle(&signer, |f| {
        let Value::Array(relays) = &mut f[1] else {
            panic!()
        };
        for relay in relays {
            let Value::Array(r) = relay else { panic!() };
            r[2] = Value::Bytes(endpoint.as_bytes().to_vec());
        }
        let Value::Array(admission) = &mut f[2] else {
            panic!()
        };
        admission[0] = Value::Bytes(endpoint.as_bytes().to_vec());
    });
    let op = OperatorSet::verify_development(&b, &signer.verifying_key().to_bytes()).unwrap();
    let p = policy(3, &op);
    let r = roster(3);
    let id = identity(1);
    let ctx = BootstrapContext::creator(p, id.public(), &op).unwrap();
    let t =
        SetupTransport::new(&id, &op, SetupAuthority::Bootstrap(&ctx, &r.members), true).unwrap();
    let own = op
        .relay_routes()
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut route = r.clone();
            route.mailbox = [i as u8 + 80; 32];
            route.append_revision = 1;
            OwnerInbox {
                route,
                read: Secret32::from_bytes([70; 32]),
                append: Secret32::from_bytes([71; 32]),
                admin: Secret32::from_bytes([72; 32]),
            }
        })
        .collect();
    let routes = SetupRoutes { own, peers: vec![] };
    let path = root_path_for_receive();
    let mut store = SetupStore::open(&path, &t).unwrap();
    t.drive_once(&mut store, &routes).await.unwrap();
    assert_eq!(exposed.load(Ordering::SeqCst), 0);
    drop(store);
    server.abort();
    let _ = server.await;
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn bootstrap_abort_remains_authenticated_after_roster_acceptance() {
    use loki_relay_client::{sign_roster_acceptance, AcceptedSetupRoster};
    use loki_relay_protocol::setup::SetupCapabilities;
    let (_, _, op) = config();
    let p = policy(4, &op);
    let r = roster(4);
    let creator = identity(1);
    let member = identity(4);
    let ctx = BootstrapContext::creator(p.clone(), creator.public(), &op).unwrap();
    let all: Vec<_> = (1..=4)
        .map(|m| {
            sign_roster_acceptance(&identity(m), &ctx, &r, &SetupCapabilities::current()).unwrap()
        })
        .collect();
    let accepted = AcceptedSetupRoster::verify(&ctx, r.clone(), &all).unwrap();
    let sender = SetupTransport::new(
        &creator,
        &op,
        SetupAuthority::Bootstrap(&ctx, &r.members),
        false,
    )
    .unwrap();
    let receiver =
        SetupTransport::new(&member, &op, SetupAuthority::Accepted(&accepted), false).unwrap();
    let records: Vec<_> = (1..=4)
        .map(|recipient| SetupRecord {
            version: loki_relay_protocol::setup::SETUP_VERSION,
            key: SetupKey {
                ceremony: p.ceremony,
                phase: SetupPhase::Abort,
                author: 1,
                recipient,
                revision: 1,
            },
            network: p.network.clone(),
            threshold: 2,
            member_count: 4,
            roster_digest: None,
            prerequisites: vec![],
            payload: vec![6],
        })
        .collect();
    let prepared = sender.prepare(&records).unwrap();
    let (root, objects) = prepared.recipient_objects(4).unwrap();
    assert_eq!(
        receiver
            .authenticate_objects(&root, &objects)
            .unwrap()
            .body()
            .key
            .phase,
        SetupPhase::Abort
    );
}

#[test]
fn oversized_chunk_manifest_rejected_before_requesting_objects_under_signed_payload_limit() {
    use loki_relay_client::{seal_record, SealContext, SealDomain};
    for n in [3u16, 4] {
        let signer = SigningKey::from_bytes(&[90; 32]);
        let package = bundle(&signer, |fields| {
            let Value::Array(limits) = &mut fields[4] else {
                panic!("limits")
            };
            limits[2] = Value::Integer(8.into());
        });
        let operators = OperatorSet::verify(&package, &signer.verifying_key().to_bytes()).unwrap();
        let p = policy(n, &operators);
        let r = roster(n);
        let own = identity(n);
        let context =
            BootstrapContext::creator(p.clone(), identity(1).public(), &operators).unwrap();
        let transport = SetupTransport::new(
            &own,
            &operators,
            SetupAuthority::Bootstrap(&context, &r.members),
            false,
        )
        .unwrap();
        let manifest = canonical::encode(&Value::Array(vec![
            Value::Integer(2.into()),
            Value::Integer(60001.into()),
            Value::Bytes(vec![40; 32]),
            Value::Array(vec![
                Value::Array(vec![
                    Value::Bytes(vec![41; 32]),
                    Value::Integer(60000.into()),
                ]),
                Value::Array(vec![Value::Bytes(vec![42; 32]), Value::Integer(1.into())]),
            ]),
        ]))
        .unwrap();
        let root = seal_record(
            &SealContext {
                vault: p.ceremony,
                roster: p.config_digest,
                recipient: own.public(),
                domain: SealDomain::Setup,
            },
            &manifest,
        )
        .unwrap();
        assert!(matches!(
            transport.authenticate_objects(&root, &std::collections::BTreeMap::new()),
            Err(ClientError::Config)
        ));
    }
}

#[test]
fn early_native_round_is_saved_until_all_member_acceptance_is_available() {
    use loki_relay_client::{sign_roster_acceptance, AcceptedSetupRoster};
    use loki_relay_protocol::setup::SetupCapabilities;
    for n in [3, 4] {
        let (_, _, op) = config();
        let p = policy(n, &op);
        let r = roster(n);
        let creator = identity(1);
        let member = identity(n);
        let ctx = BootstrapContext::creator(p.clone(), creator.public(), &op).unwrap();
        let all: Vec<_> = (1..=n)
            .map(|id| {
                sign_roster_acceptance(&identity(id), &ctx, &r, &SetupCapabilities::current())
                    .unwrap()
            })
            .collect();
        let accepted = AcceptedSetupRoster::verify(&ctx, r.clone(), &all).unwrap();
        let sender =
            SetupTransport::new(&creator, &op, SetupAuthority::Accepted(&accepted), false).unwrap();
        let bootstrap = SetupTransport::new(
            &member,
            &op,
            SetupAuthority::Bootstrap(&ctx, &r.members),
            false,
        )
        .unwrap();
        let records: Vec<_> = (1..=n)
            .map(|recipient| SetupRecord {
                version: loki_relay_protocol::setup::SETUP_VERSION,
                key: SetupKey {
                    ceremony: p.ceremony,
                    phase: SetupPhase::Round1,
                    author: 1,
                    recipient,
                    revision: 1,
                },
                network: p.network.clone(),
                threshold: 2,
                member_count: n,
                roster_digest: Some(*accepted.digest()),
                prerequisites: vec![],
                payload: vec![83; 100],
            })
            .collect();
        let prepared = sender.prepare(&records).unwrap();
        let (hash, objects) = prepared.recipient_objects(n).unwrap();
        let map = objects;
        let path = root();
        let mut store = SetupStore::open(&path, &bootstrap).unwrap();
        let mut noise = hash.clone();
        let last = noise.wire.len() - 1;
        noise.wire[last] ^= 1;
        assert!(store.commit_incoming(&bootstrap, &noise, &map).is_err());
        assert!(store.saved_objects().unwrap().is_empty());
        let sql = rusqlite::Connection::open(path.join("setup.sqlite3")).unwrap();
        sql.execute_batch("CREATE TRIGGER fail_deferred BEFORE INSERT ON deferred BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(matches!(
            store.commit_incoming(&bootstrap, &hash, &map),
            Err(ClientError::Storage)
        ));
        assert!(store.saved_objects().unwrap().is_empty());
        sql.execute_batch("DROP TRIGGER fail_deferred;").unwrap();
        assert!(matches!(
            store.commit_incoming(&bootstrap, &hash, &map),
            Err(ClientError::SetupAgreementPending)
        ));
        assert!(!store.is_terminal().unwrap());
        assert!(store
            .receive(&bootstrap, &records[n as usize - 1].key)
            .unwrap()
            .is_none());
        assert_eq!(store.reconcile_deferred(&bootstrap).unwrap(), 0);
        let saved = store.saved_objects().unwrap();
        assert!(!saved.is_empty());
        let acks: u64 = sql
            .query_row("SELECT count(*) FROM acknowledgements", [], |r| r.get(0))
            .unwrap();
        assert_eq!(acks, 0);
        drop(sql);
        drop(store);
        let receiver =
            SetupTransport::new(&member, &op, SetupAuthority::Accepted(&accepted), false).unwrap();
        let mut store = SetupStore::open(&path, &receiver).unwrap();
        assert_eq!(store.saved_objects().unwrap(), saved);
        assert_eq!(store.reconcile_deferred(&receiver).unwrap(), 1);
        assert!(
            store
                .receive(&receiver, &records[n as usize - 1].key)
                .unwrap()
                .unwrap()
                .body()
                == &records[n as usize - 1]
        );
        assert_eq!(store.reconcile_deferred(&receiver).unwrap(), 0);
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn setup_store_migrates_only_the_exact_legacy_catalog() {
    for n in [3, 4] {
        let (_, _, op) = config();
        let p = policy(n, &op);
        let r = roster(n);
        let member = identity(n);
        let ctx = BootstrapContext::creator(p, identity(1).public(), &op).unwrap();
        let transport = SetupTransport::new(
            &member,
            &op,
            SetupAuthority::Bootstrap(&ctx, &r.members),
            false,
        )
        .unwrap();
        let path = root();
        drop(SetupStore::open(&path, &transport).unwrap());
        let sql = rusqlite::Connection::open(path.join("setup.sqlite3")).unwrap();
        // The oldest catalog: no `deferred` table and recipients bounded at 4.
        let version: i64 = sql.query_row("PRAGMA schema_version", [], |r| r.get(0)).unwrap();
        sql.execute_batch("DROP TABLE pending_roots; DROP TABLE deferred; PRAGMA writable_schema=ON;").unwrap();
        sql.execute(
            "UPDATE sqlite_master SET sql=replace(sql,'recipient BETWEEN 1 AND 16)','recipient BETWEEN 1 AND 4)') WHERE type='table'",
            [],
        )
        .unwrap();
        sql.execute_batch(&format!(
            "PRAGMA schema_version={}; PRAGMA writable_schema=OFF;",
            version + 2
        ))
        .unwrap();
        drop(sql);
        drop(SetupStore::open(&path, &transport).unwrap());
        let sql = rusqlite::Connection::open(path.join("setup.sqlite3")).unwrap();
        let widened: String = sql
            .query_row("SELECT sql FROM sqlite_master WHERE name='outgoing'", [], |r| r.get(0))
            .unwrap();
        assert!(widened.contains("recipient BETWEEN 1 AND 16)"));
        drop(sql);
        let sql = rusqlite::Connection::open(path.join("setup.sqlite3")).unwrap();
        assert_eq!(
            sql.query_row("SELECT count(*) FROM deferred", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            0
        );
        sql.execute_batch("DROP TABLE ack_stored;").unwrap();
        drop(sql);
        assert!(SetupStore::open(&path, &transport).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
}
