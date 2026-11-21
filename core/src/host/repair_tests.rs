use super::*;
use crate::transport::Incoming;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct MemoryTransport {
    me: Peer,
    inboxes: Arc<Mutex<BTreeMap<[u8; 32], Vec<Incoming>>>>,
    wires: Arc<Mutex<Vec<Vec<u8>>>>,
    fault: Option<Fault>,
    receive_failures: Arc<Mutex<usize>>,
}

impl Transport for MemoryTransport {
    type Error = String;
    type Channel = uuid::Uuid;
    fn open(&mut self, _: &[Peer], _: u8) -> Result<Self::Channel, String> {
        Ok(uuid::Uuid::new_v4())
    }
    fn join(&mut self, id: uuid::Uuid) -> Result<Self::Channel, String> {
        Ok(id)
    }
    fn send(&self, _: &Self::Channel, to: &[Peer], msg: &Outbound) -> Result<(), String> {
        let mut message = msg.to_bytes().map_err(|e| e.to_string())?;
        if matches!(self.fault, Some(Fault::Send)) {
            return Err("disconnected".into());
        }
        if let Some(Fault::Replay(ref old)) = self.fault {
            if message.starts_with(b"LOKIR1V1") {
                message = old.clone();
            }
        }
        if message.starts_with(b"LOKIDKG2") {
            match self.fault {
                Some(Fault::Ciphertext) => message[104] ^= 1,
                Some(Fault::Recipient) => message[43] ^= 1,
                _ => (),
            }
        }
        self.wires.lock().unwrap().push(message.clone());
        for peer in to {
            let copies = if matches!(self.fault, Some(Fault::Duplicate)) {
                2
            } else {
                1
            };
            for _ in 0..copies {
                self.inboxes
                    .lock()
                    .unwrap()
                    .entry(peer.0)
                    .or_default()
                    .push(Incoming {
                        from: if matches!(self.fault, Some(Fault::Sender)) {
                            Peer([99; 32])
                        } else {
                            self.me.clone()
                        },
                        message: message.clone(),
                    });
            }
        }
        Ok(())
    }
    fn recv(&self, _: &Self::Channel, _: bool) -> Result<Vec<Incoming>, String> {
        if matches!(self.fault, Some(Fault::LateReceive)) {
            std::thread::sleep(Duration::from_millis(1100));
        }
        let mut failures = self.receive_failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            return Err("transient receive failure".into());
        }
        Ok(self
            .inboxes
            .lock()
            .unwrap()
            .remove(&self.me.0)
            .unwrap_or_default())
    }
    fn close(&self, _: Self::Channel) -> Result<(), String> {
        let mut failures = self.receive_failures.lock().unwrap();
        if matches!(self.fault, Some(Fault::Close)) && *failures > 0 {
            *failures -= 1;
            return Err("relay unavailable".into());
        }
        Ok(())
    }
}

#[test]
fn wired_repair_2_of_3_reconstructs_over_encrypted_transport() {
    wired_repair(2, 3, 2, None);
}

#[derive(Clone)]
enum Fault {
    Duplicate,
    Sender,
    Recipient,
    Ciphertext,
    Replay(Vec<u8>),
    Metadata,
    Send,
    LateReceive,
    Close,
}

#[test]
fn wired_repair_3_of_5_reconstructs_over_encrypted_transport() {
    wired_repair(3, 5, 4, None);
}

#[test]
fn wired_repair_rejects_duplicate_spoofed_replayed_and_corrupt_messages() {
    for fault in [
        Fault::Duplicate,
        Fault::Sender,
        Fault::Recipient,
        Fault::Ciphertext,
        Fault::Replay(vec![]),
        Fault::Metadata,
        Fault::Send,
    ] {
        wired_repair(2, 3, 2, Some(fault));
    }
}

fn wired_repair(threshold: u16, members: u16, lost: u16, fault: Option<Fault>) {
    let data = std::env::temp_dir().join(format!("loki-wired-repair-{}", uuid::Uuid::new_v4()));
    let vault = [7; 32];
    let identities: Vec<_> = (1..=members).map(Identity::new).collect();
    let roster: Vec<_> = identities
        .iter()
        .map(|i| Member::from_public(i.public()))
        .collect();
    let helpers: Vec<_> = (1..=members)
        .filter(|i| *i != lost)
        .take(threshold as usize)
        .collect();
    let recipient = Identity::new(lost);
    let invite = Invitation {
        version: 1,
        vault: hex::encode(vault),
        threshold,
        roster,
        helpers: helpers.clone(),
        recipient: Member::from_public(recipient.public()),
        session_id: uuid::Uuid::new_v4(),
        expires: now().unwrap() + if fault.is_some() { 2 } else { 30 },
        frostd_url: "http://configured-relay".into(),
        network: "regtest".into(),
    };
    let (shares, public) = frost::keys::generate_with_dealer(
        members,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rand_core::OsRng,
    )
    .unwrap();
    let keys: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let metadata = Metadata {
        public_package: hex::encode(public.serialize().unwrap()),
        roster_fingerprint: hex::encode(invite.roster().unwrap().fingerprint()),
        vault_secret: hex::encode([42; 32]),
        network: "regtest".into(),
        birth_height: 100,
    };
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let wires = Arc::new(Mutex::new(Vec::new()));
    let result = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for identity in identities
            .iter()
            .filter(|i| helpers.contains(&i.public().id))
        {
            let mut helper_fault = if identity.public().id == helpers[0] {
                fault.clone()
            } else {
                None
            };
            if matches!(helper_fault, Some(Fault::Replay(_))) {
                let mut old = invite.clone();
                old.session_id = uuid::Uuid::new_v4();
                let hello = Hello {
                    fresh: FreshKey::generate().public(),
                    metadata: Some(metadata.digest().unwrap()),
                };
                helper_fault = Some(Fault::Replay(
                    identity
                        .sign_round1(&old.context().unwrap(), &encode(&hello).unwrap())
                        .unwrap(),
                ));
            }
            let mut metadata = metadata.clone();
            if matches!(helper_fault, Some(Fault::Metadata)) {
                metadata.birth_height += 1;
            }
            let tx = MemoryTransport {
                me: Peer(identity.public().encryption),
                inboxes: inboxes.clone(),
                wires: wires.clone(),
                fault: helper_fault,
                receive_failures: Arc::new(Mutex::new(1)),
            };
            let invite = &invite;
            let key = &keys[&frost::Identifier::try_from(identity.public().id).unwrap()];
            threads.push(scope.spawn(move || {
                run_ceremony(
                    &tx,
                    &invite.session_id,
                    invite,
                    identity,
                    Some((key, &metadata)),
                )
            }));
        }
        let tx = MemoryTransport {
            me: Peer(recipient.public().encryption),
            inboxes: inboxes.clone(),
            wires: wires.clone(),
            fault: None,
            receive_failures: Arc::new(Mutex::new(1)),
        };
        let result = run_ceremony(&tx, &invite.session_id, &invite, &recipient, None)
            .and_then(|r| r.unwrap().restore(&data, "replacement pass", &invite));
        for thread in threads {
            let helper = thread.join().unwrap();
            if fault.is_none() {
                assert!(helper.unwrap().is_none());
            }
        }
        result
    });
    if fault.is_some() {
        assert!(result.is_err(), "fault must prevent restoration");
        assert!(!data.exists(), "refused repair must not create a vault");
        if matches!(fault, Some(Fault::Metadata)) {
            assert!(
                wires
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|w| w.starts_with(b"LOKIR1V1")),
                "no shares before metadata agreement"
            );
        }
        return;
    }
    result.unwrap();
    let raw = MemberDir::open(&data.join("vaults"), &hex::encode(vault))
        .read_sealed("vault.sealed", "replacement pass")
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let expected = keys[&frost::Identifier::try_from(lost).unwrap()]
        .serialize()
        .unwrap();
    // `vault.sealed` is public metadata; signing reads the share from the signer store.
    assert!(stored.get("key_package").is_none() && stored.get("vault_secret").is_none());
    let sdir = super::super::ceremony::signer_dir(&data, &hex::encode(vault)).unwrap();
    let se = crate::signer::secure_element::SoftwareSecureElement::persistent(&sdir, "replacement pass").unwrap();
    let (_, raw) = crate::signer::store::SignerStore::open(&sdir).unwrap()
        .read(&se, crate::signer::store::FileKind::Share).unwrap().unwrap();
    let (key, _, secret) = crate::signer::local::decode_share(&raw).unwrap();
    assert_eq!(*key, expected);
    assert_eq!(secret, [42; 32]);
    assert_eq!(stored["birth_height"], 100);
    assert_eq!(stored["network"], "regtest");
    for wire in wires.lock().unwrap().iter() {
        assert!(wire.starts_with(b"LOKIR1V1") || wire.starts_with(b"LOKIDKG2"));
        assert!(!wire
            .windows(64)
            .any(|w| w == hex::encode([42; 32]).as_bytes()));
    }
    std::fs::remove_dir_all(data).unwrap();
}

fn invitation() -> (Invitation, Vec<Identity>) {
    let identities: Vec<_> = (1..=3).map(Identity::new).collect();
    (
        Invitation {
            version: 1,
            vault: hex::encode([7; 32]),
            threshold: 2,
            roster: identities
                .iter()
                .map(|i| Member::from_public(i.public()))
                .collect(),
            helpers: vec![1, 3],
            recipient: Member::from_public(Identity::new(2).public()),
            session_id: Uuid::new_v4(),
            expires: now().unwrap() + LIFETIME,
            frostd_url: "http://configured-relay".into(),
            network: "regtest".into(),
        },
        identities,
    )
}

#[test]
fn repair_invitation_enforces_policy_membership_expiry_and_recipient_binding() {
    let (invite, _) = invitation();
    invite.validate().unwrap();
    for helpers in [
        vec![1],
        vec![1, 1],
        vec![1, 2],
        vec![1, 4],
        vec![3, 1],
        vec![1, 2, 3],
    ] {
        let mut bad = invite.clone();
        bad.helpers = helpers;
        assert!(bad.validate().is_err());
    }
    for threshold in [0, 1, 3, 17] {
        let mut bad = invite.clone();
        bad.threshold = threshold;
        assert!(bad.validate().is_err());
    }
    let mut bad = invite.clone();
    bad.expires = now().unwrap();
    assert!(bad.validate().is_err());
    bad = invite.clone();
    bad.roster[1] = bad.roster[0].clone();
    assert!(bad.validate().is_err());
    bad = invite.clone();
    bad.recipient = bad.roster[0].clone();
    bad.recipient.id = 2;
    assert!(bad.validate().is_err());
    bad = invite.clone();
    bad.recipient = Member::from_public(Identity::new(2).public());
    bad.validate().unwrap();
    assert_ne!(
        bad.context().unwrap(),
        invite.context().unwrap(),
        "recipient replacement needs fresh approval"
    );
}

#[test]
fn repair_claim_survives_restart_and_status_records_failure() {
    let data = std::env::temp_dir().join(format!("loki-repair-claim-{}", Uuid::new_v4()));
    let (invite, _) = invitation();
    claim(&data, "pass", &invite).unwrap();
    let reloaded: Invitation = serde_json::from_slice(
        &repair_dir(&data, &invite.vault)
            .unwrap()
            .read_sealed(&format!("repair.{}.sealed", invite.session_id), "pass")
            .unwrap(),
    )
    .unwrap();
    assert!(claim(&data, "pass", &reloaded).is_err());
    let query = json!({"vault":invite.vault,"session_id":invite.session_id});
    assert_eq!(status(&data, "pass", &query).unwrap()["phase"], "running");
    finish(
        &data,
        "pass",
        &invite,
        Err("timed out".into()),
        Some("relay unavailable".into()),
    )
    .unwrap();
    assert_eq!(status(&data, "pass", &query).unwrap()["phase"], "failed");
    assert_eq!(
        status(&data, "pass", &query).unwrap()["relay_cleanup_error"],
        "relay unavailable"
    );
    assert!(claim(&data, "pass", &reloaded).is_err());
    let mut fresh = invite;
    fresh.session_id = Uuid::new_v4();
    claim(&data, "pass", &fresh).unwrap();
    std::fs::remove_dir_all(data).unwrap();
}

#[test]
fn repair_times_out_when_helpers_do_not_consent() {
    let (mut invite, identities) = invitation();
    invite.expires = now().unwrap() + 1;
    let tx = MemoryTransport {
        me: Peer(identities[0].public().encryption),
        inboxes: Arc::new(Mutex::new(BTreeMap::new())),
        wires: Arc::new(Mutex::new(vec![])),
        fault: None,
        receive_failures: Arc::new(Mutex::new(0)),
    };
    assert!(receive(&tx, &invite.session_id, now().unwrap())
        .unwrap_err()
        .contains("timed out"));
    while receive(&tx, &invite.session_id, invite.expires).is_ok() {}
    assert!(tx.wires.lock().unwrap().is_empty());
}

#[tokio::test]
async fn repair_handlers_require_unlock_consent_and_local_relay_and_original_vault() {
    use super::super::state::{AppState, Config, Session};
    let data = std::env::temp_dir().join(format!("loki-repair-http-{}", Uuid::new_v4()));
    let st = Arc::new(AppState::new(Config {
        registration: None, native: false,
        bind: "127.0.0.1".parse().unwrap(), peer_port: None, advertise_url: None,
        data: data.clone(),
        port: 3001,
        network: "regtest".into(),
        lightwalletd: None,
        transport: "local".into(),
        secure_element: "software".into(),
        operator_bundle: None, nonce_witnesses: None,
        operator_key: None,
        enrollment_issuer: None,
        development_http: false,
        token: "test".into(),
        frostd_url: "http://configured-relay".into(),
        peers: BTreeMap::new(), loopback_peers: false,
    }));
    assert_eq!(
        repair_begin(State(st.clone()), Json(json!({}))).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        repair_contribute(State(st.clone()), Json(json!({})))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    *st.session.write().await = Some(Session {
        data: data.clone(),
        passphrase: Zeroizing::new("pass".into()),
    });
    let (invite, identities) = invitation();
    let contribute =
        |invite: &Invitation, approve: String| json!({"invite":invite, "approve":approve});
    let reply = repair_contribute(
        State(st.clone()),
        Json(contribute(&invite, "unapproved".into())),
    )
    .await;
    assert_eq!(reply.0, StatusCode::BAD_REQUEST);
    assert!(reply.1 .0["error"]
        .as_str()
        .unwrap()
        .contains("explicit approval"));
    let mut foreign = invite.clone();
    foreign.frostd_url = "http://169.254.169.254".into();
    let reply = repair_contribute(
        State(st.clone()),
        Json(contribute(
            &foreign,
            hex::encode(foreign.context().unwrap()),
        )),
    )
    .await;
    assert!(reply.1 .0["error"]
        .as_str()
        .unwrap()
        .contains("not locally configured"));
    assert!(!data.exists());

    // Authenticate helpers against their sealed DKG roster and vault, not invite claims.
    let (shares, public) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::Default,
        &mut rand_core::OsRng,
    )
    .unwrap();
    let id = frost::Identifier::try_from(1u16).unwrap();
    let key = frost::keys::KeyPackage::try_from(shares[&id].clone()).unwrap();
    let root = MemberDir::create(&data, "").unwrap();
    // This profile first joined another vault at slot 3; this vault uses local slot 1.
    let mut identity_bytes = Zeroizing::new(identities[0].to_secret_bytes());
    identity_bytes[..2].copy_from_slice(&3u16.to_be_bytes());
    root.write_sealed("identity.sealed", &*identity_bytes, "pass")
        .unwrap();
    let dir = MemberDir::create(&data.join("vaults"), &invite.vault).unwrap();
    let fingerprint = hex::encode(invite.roster().unwrap().fingerprint());
    let slots: BTreeMap<_, _> = invite
        .roster
        .iter()
        .map(|m| (m.id, json!({"identity":m,"pending_token":null})))
        .collect();
    let ceremony = json!({"vault":invite.vault, "name":"original", "members":3, "threshold":2, "my_slot":1,
        "creator_base_url":"http://configured-peer", "frostd_url":invite.frostd_url, "slots":slots,
        "fingerprint":fingerprint, "agreed":[1,2,3], "session_id":null, "dkg_started":true, "error":null});
    dir.write_sealed("ceremony.sealed", &encode(&ceremony).unwrap(), "pass")
        .unwrap();
    let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
    let fvk = crate::zip2005::frost_viewing_key(&ak, &[42; 32]).unwrap();
    let bytes = super::super::ceremony::vault_sealed_bytes(
        &invite.vault,
        1,
        2,
        3,
        &fingerprint,
        &public,
        &fvk,
        100,
        VaultNetwork::Regtest,
    )
    .unwrap();
    dir.write_sealed("vault.sealed", &bytes, "pass").unwrap();
    let sdir = super::super::ceremony::signer_dir(&data, &invite.vault).unwrap();
    let se = crate::signer::secure_element::SoftwareSecureElement::persistent(&sdir, "pass").unwrap();
    let store = crate::signer::store::SignerStore::create(&sdir, crate::signer::Network::Regtest, hex32(&invite.vault).unwrap(), 1).unwrap();
    store.write(&se, crate::signer::store::FileKind::Share, 0,
        &crate::signer::local::encode_share(&key.serialize().unwrap(), &public.serialize().unwrap(), &[42; 32])).unwrap();
    let (identity, loaded, metadata) = load_helper(&data, "pass", &invite).unwrap();
    assert_eq!(identity.public(), identities[0].public());
    assert_eq!(loaded.serialize().unwrap(), key.serialize().unwrap());
    assert_eq!(metadata.birth_height, 100);
    assert!(load_helper(&data, "wrong pass", &invite).is_err());
    let mut wrong = invite.clone();
    wrong.roster[2] = Member::from_public(Identity::new(3).public());
    let reply = repair_contribute(
        State(st.clone()),
        Json(contribute(&wrong, hex::encode(wrong.context().unwrap()))),
    )
    .await;
    assert!(reply.1 .0["error"]
        .as_str()
        .unwrap()
        .contains("original roster"));
    // An existing vault must be refused before opening any relay session.
    let body = json!({"vault":invite.vault,"threshold":2,"roster":invite.roster,"roster_fingerprint":fingerprint,"helpers":[2,3],"lost":1});
    let reply = repair_begin(State(st.clone()), Json(body)).await;
    assert!(reply.1 .0["error"]
        .as_str()
        .unwrap()
        .contains("never overwrite"));
    assert_eq!(dir.read_sealed("vault.sealed", "pass").unwrap(), *bytes);
    std::fs::remove_file(root.path().join("identity.sealed")).unwrap();
    assert!(load_helper(&data, "pass", &invite).is_err());
    assert!(!root.exists("identity.sealed"), "repair must not replace a missing recovery identity");
    std::fs::remove_dir_all(data).unwrap();
}

#[test]
fn repair_rejects_a_receive_that_returns_after_expiry() {
    let tx = MemoryTransport {
        me: Peer([1; 32]),
        inboxes: Arc::new(Mutex::new(BTreeMap::from([(
            [1; 32],
            vec![Incoming {
                from: Peer([2; 32]),
                message: vec![3],
            }],
        )]))),
        wires: Arc::new(Mutex::new(vec![])),
        fault: Some(Fault::LateReceive),
        receive_failures: Arc::new(Mutex::new(0)),
    };
    assert!(receive(&tx, &Uuid::new_v4(), now().unwrap() + 1).is_err());
}

#[test]
fn repair_retries_session_cleanup_and_reports_exhaustion() {
    let tx = MemoryTransport {
        me: Peer([1; 32]),
        inboxes: Arc::new(Mutex::new(BTreeMap::new())),
        wires: Arc::new(Mutex::new(vec![])),
        fault: Some(Fault::Close),
        receive_failures: Arc::new(Mutex::new(2)),
    };
    assert!(close_session(&tx, Uuid::new_v4()).is_ok());
    *tx.receive_failures.lock().unwrap() = 3;
    assert!(close_session(&tx, Uuid::new_v4()).is_err());
}
