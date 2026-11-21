mod support;
use ed25519_dalek::SigningKey;
use loki_relay_client::Secret32;
use loki_relay_protocol::{
    admission::AdmissionCommand,
    http::encode_creation,
    types::{Creation, RelayPin, RelayRoute},
};
use loki_relay_server::{capability::provisioning_verifier, DbHandle, Limits, RelayStore};
use loki_setup_admission::{AdmissionStore, EnrollmentVerifier, OwnedProvisioner};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use support::*;
#[tokio::test]
async fn real_relays_partial_provision_lost_response_and_restart_backfill_exact_intents() {
    for n in [3u16, 4] {
        let db = OwnedDb::new();
        let clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut fixtures = Vec::new();
        let limits = Limits {
            total_bytes: 1000000,
            mailbox_bytes: 100000,
            mailbox_count: 8,
        };
        for index in 0u8..3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let endpoint = format!("http://{address}");
            let run = [index + 10; 32];
            let provision = [index + 20; 32];
            let root = db.root.join(format!("relay{index}"));
            let relay = RelayStore::init(
                &root,
                run,
                &endpoint,
                &provision,
                provisioning_verifier(run, &provision),
                limits,
            )
            .unwrap();
            let route = RelayRoute {
                pin: RelayPin {
                    key: relay.public_key(),
                    run,
                },
                endpoint,
                mailbox: [0; 32],
                append_revision: 1,
            };
            drop(relay);
            let (handle, owner) = DbHandle::open(root.clone(), limits).await.unwrap();
            let (stop, wait) = tokio::sync::oneshot::channel::<()>();
            let lost = Arc::new(AtomicBool::new(true));
            let router = loki_relay_server::http::router(handle.clone()).layer(
                axum::middleware::from_fn_with_state(lost.clone(), lose_created_response),
            );
            let server = tokio::spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = wait.await;
                    })
                    .await
                    .unwrap()
            });
            fixtures.push((
                route,
                provision,
                root,
                handle,
                owner,
                Some(stop),
                Some(server),
                address,
                lost,
            ));
        }
        fixtures.sort_by_key(|f| f.0.pin.key);
        let routes: Vec<_> = fixtures.iter().map(|f| f.0.clone()).collect();
        let cfg = config_with_routes(&routes, "http://127.0.0.1:9000");
        let store_root = db.root.join("admission");
        std::fs::create_dir(&store_root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut store = AdmissionStore::open(
            &store_root,
            &cfg,
            EnrollmentVerifier::new(Some(
                SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
            )),
            SigningKey::from_bytes(&[8; 32]),
        )
        .unwrap();
        let grant = grant_for(&cfg, 2, 48, clock + 3600);
        store
            .apply(
                &create_for(1, [70; 32], n, &grant, &cfg),
                Some(&grant),
                clock,
            )
            .unwrap();
        let mut op = 2u8;
        for slot in 2..=n {
            store
                .apply(
                    &claim(op, [70; 32], slot, slot as u8),
                    Some(&[slot as u8; 32]),
                    clock + 1,
                )
                .unwrap();
            op += 1;
        }
        for slot in 1..=n {
            for relay in 1..=3 {
                for purpose in 1..=2 {
                    let mailbox = [slot as u8 * 10 + relay as u8 * 2 + purpose as u8; 32];
                    let req = request(
                        op,
                        &identity(slot, slot as u8),
                        AdmissionCommand::Mailbox {
                            ceremony: [70; 32],
                            slot,
                            relay,
                            purpose,
                            mailbox,
                            creation: encode_creation(&Creation {
                                read_verifier: loki_relay_server::capability::verifier(
                                    loki_relay_server::Role::Read,
                                    mailbox,
                                    &[slot as u8 * 10 + relay as u8 * 3 + purpose as u8 * 40; 32],
                                ),
                                append_verifier: loki_relay_server::capability::verifier(
                                    loki_relay_server::Role::Append,
                                    mailbox,
                                    &[slot as u8 * 10 + relay as u8 * 3 + purpose as u8 * 40 + 1;
                                        32],
                                ),
                                admin_verifier: loki_relay_server::capability::verifier(
                                    loki_relay_server::Role::Admin,
                                    mailbox,
                                    &[slot as u8 * 10 + relay as u8 * 3 + purpose as u8 * 40 + 2;
                                        32],
                                ),
                                quota: 1024,
                            })
                            .unwrap(),
                        },
                    );
                    store.apply(&req, None, clock + 2).unwrap();
                    op += 1;
                }
            }
        }
        let service = Arc::new(Mutex::new(store));
        let provisioner = OwnedProvisioner::development(
            &cfg,
            std::array::from_fn(|i| Secret32::from_bytes(fixtures[i].1)),
        )
        .unwrap();
        fixtures[2].5.take().unwrap().send(()).unwrap();
        fixtures[2].6.take().unwrap().await.unwrap();
        for step in 0..10 {
            provisioner
                .drive_once(&service, clock + 10 + step * 100)
                .await
                .unwrap();
        }
        for index in 0..2 {
            let connection =
                rusqlite::Connection::open(fixtures[index].2.join("relay.sqlite3")).unwrap();
            assert_eq!(
                connection
                    .query_row("SELECT count(*) FROM mailboxes", [], |r| r.get::<_, u64>(0))
                    .unwrap(),
                n as u64 * 2
            );
        }
        assert!(!service
            .lock()
            .unwrap()
            .pending(clock + 5000, 3)
            .unwrap()
            .is_empty());
        let listener = tokio::net::TcpListener::bind(fixtures[2].7).await.unwrap();
        let (stop, wait) = tokio::sync::oneshot::channel::<()>();
        let router = loki_relay_server::http::router(fixtures[2].3.clone()).layer(
            axum::middleware::from_fn_with_state(fixtures[2].8.clone(), lose_created_response),
        );
        fixtures[2].5 = Some(stop);
        fixtures[2].6 = Some(tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = wait.await;
                })
                .await
                .unwrap()
        }));
        for step in 0..5 {
            provisioner
                .drive_once(&service, clock + 5000 + step * 100)
                .await
                .unwrap();
        }
        assert!(service
            .lock()
            .unwrap()
            .pending(clock + 6000, 3)
            .unwrap()
            .is_empty());
        let admission = rusqlite::Connection::open(store_root.join("admission.sqlite")).unwrap();
        for (index, fixture) in fixtures.iter().enumerate() {
            assert!(!fixture.8.load(Ordering::SeqCst));
            let remote = rusqlite::Connection::open(fixture.2.join("relay.sqlite3")).unwrap();
            let mut rows = admission
                .prepare("SELECT mailbox,request FROM mailboxes WHERE relay=?1")
                .unwrap();
            for row in rows
                .query_map([index as u16 + 1], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .unwrap()
            {
                let (mailbox, exact) = row.unwrap();
                let saved: Vec<u8> = remote
                    .query_row(
                        "SELECT creation_request FROM mailboxes WHERE id=?1",
                        [mailbox],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(saved, exact);
            }
        }
        for fixture in &fixtures {
            let remote = rusqlite::Connection::open(fixture.2.join("relay.sqlite3")).unwrap();
            assert_eq!(
                remote
                    .query_row("SELECT count(*) FROM setup_namespaces", [], |r| r
                        .get::<_, u64>(0))
                    .unwrap(),
                u64::from(n)
            );
        }
        let expired = clock + 2592000;
        service.lock().unwrap().cleanup(expired).unwrap();
        for step in 0..10 {
            provisioner
                .drive_once(&service, expired + step * 100)
                .await
                .unwrap();
        }
        for fixture in &fixtures {
            let remote = rusqlite::Connection::open(fixture.2.join("relay.sqlite3")).unwrap();
            assert_eq!(
                remote
                    .query_row("SELECT count(*) FROM mailboxes", [], |r| r.get::<_, u64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                remote
                    .query_row(
                        "SELECT count(*) FROM setup_namespaces WHERE retired=1",
                        [],
                        |r| r.get::<_, u64>(0)
                    )
                    .unwrap(),
                u64::from(n)
            );
        }
        for fixture in &mut fixtures {
            fixture.5.take().unwrap().send(()).unwrap();
            fixture.6.take().unwrap().await.unwrap();
        }
        drop(provisioner);
        drop(service);
        drop(fixtures);
    }
}

async fn lose_created_response(
    axum::extract::State(lost): axum::extract::State<Arc<AtomicBool>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let creation =
        request.method() == axum::http::Method::PUT && request.uri().path().ends_with("/setup");
    let reply = next.run(request).await;
    if creation
        && reply.status() == axum::http::StatusCode::CREATED
        && lost.swap(false, Ordering::SeqCst)
    {
        axum::response::Response::builder()
            .status(503)
            .body(axum::body::Body::empty())
            .unwrap()
    } else {
        reply
    }
}
