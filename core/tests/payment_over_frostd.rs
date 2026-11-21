use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    thread,
};

use loki_poc::candidate::{quote_fee, CandidateInputs};
use loki_poc::network::VaultNetwork;
use loki_poc::payment_transport::{coordinate, signer_loop};
use loki_poc::setup_transport::Identity;
use loki_poc::signing_session::{AttemptId, SessionContext};
use loki_poc::signer::{
    local::LocalSigner, secure_element::SoftwareSecureElement, CandidateRef, Network,
    PublicPaymentParams, Signer,
};
use loki_poc::transport::{FrostdLoginKey, FrostdTransport, Incoming, Outbound, Peer, Transport};
use loki_poc::zip2005;
use orchard::{
    keys::{FullViewingKey, Scope},
    note::{RandomSeed, Rho},
    value::NoteValue,
    NoteVersion,
};
use reddsa_frost::frost::redpallas as frost;
use uuid::Uuid;
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

#[derive(Clone)]
struct MemoryTransport {
    me: Peer,
    coordinator: Peer,
    inboxes: Arc<Mutex<BTreeMap<[u8; 32], Vec<Incoming>>>>,
    /// Every message the relay carried, as a relay operator would see it.
    relayed: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Transport for MemoryTransport {
    type Error = String;
    type Channel = Uuid;

    fn open(&mut self, _peers: &[Peer], _message_count: u8) -> Result<Uuid, String> {
        Ok(Uuid::new_v4())
    }
    fn join(&mut self, session: Uuid) -> Result<Uuid, String> {
        Ok(session)
    }
    fn send(&self, _channel: &Uuid, to: &[Peer], message: &Outbound) -> Result<(), String> {
        let message = message.to_bytes().map_err(|e| e.to_string())?;
        self.relayed.lock().unwrap().push(message.clone());
        let recipients = if to.is_empty() {
            std::slice::from_ref(&self.coordinator)
        } else {
            to
        };
        let mut inboxes = self.inboxes.lock().unwrap();
        for recipient in recipients {
            inboxes.entry(recipient.0).or_default().push(Incoming {
                from: self.me.clone(),
                message: message.clone(),
            });
        }
        Ok(())
    }
    fn recv(&self, _channel: &Uuid, _as_coordinator: bool) -> Result<Vec<Incoming>, String> {
        Ok(self
            .inboxes
            .lock()
            .unwrap()
            .remove(&self.me.0)
            .unwrap_or_default())
    }
    fn close(&self, _channel: Uuid) -> Result<(), String> {
        Ok(())
    }
}

fn vault_note(fvk: &FullViewingKey) -> orchard::Note {
    let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
    orchard::Note::from_parts(
        fvk.address_at(0u64, Scope::External),
        NoteValue::from_raw(625_000_000),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap()
}

#[test]
fn two_of_three_payment_pczt_verifies_over_frostd() {
    let url = std::env::var("FROSTD_URL").expect("set FROSTD_URL to the running frostd relay");
    roundtrip(
        Identity::new(0),
        VaultNetwork::Regtest,
        |identity| {
            let secret: [u8; 32] = identity.to_secret_bytes()[34..].try_into().unwrap();
            FrostdTransport::new(&url, FrostdLoginKey::from_secret_bytes(secret)).unwrap()
        },
        |channel| channel.session_id(),
    );
    eprintln!("payment over frostd: 2-of-3 PCZT signature verifies under randomized group key");
}

#[test]
fn two_of_three_payment_pczt_verifies_in_memory() {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let relayed = Arc::new(Mutex::new(Vec::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    let fvk = roundtrip(
        coordinator,
        VaultNetwork::Regtest,
        |identity| MemoryTransport {
            me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(),
            inboxes: inboxes.clone(),
            relayed: relayed.clone(),
        },
        |channel| *channel,
    );
    // The relay carried sealed commitments, candidates, packages, seeds and shares,
    // but never a readable candidate or the vault's viewing key.
    let fvk = fvk.to_bytes();
    let relayed = relayed.lock().unwrap();
    assert!(relayed.len() >= 8, "relay carried {} messages", relayed.len());
    for message in relayed.iter() {
        assert!(pczt::Pczt::parse(message).is_err(), "a plaintext PCZT crossed the relay");
        assert!(
            !message.windows(fvk.len()).any(|window| window == fvk),
            "the full viewing key crossed the relay"
        );
    }
}

#[test]
fn testnet_payment_uses_nu7_over_in_memory_transport() {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    roundtrip(
        coordinator,
        VaultNetwork::Testnet,
        |identity| MemoryTransport {
            me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(),
            inboxes: inboxes.clone(),
            relayed: Arc::new(Mutex::new(Vec::new())),
        },
        |channel| *channel,
    );
}

fn roundtrip<T: Transport + Send>(
    coordinator: Identity,
    network: VaultNetwork,
    make_transport: impl Fn(&Identity) -> T,
    session_id: impl Fn(&T::Channel) -> Uuid,
) -> FullViewingKey
where
    T::Channel: Send,
    T::Error: std::fmt::Debug + std::fmt::Display,
{
    let (shares, public) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::Default,
        &mut rand_core::OsRng,
    )
    .unwrap();
    let keys: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
    let note = vault_note(&fvk);
    let mut inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: vec![note],
        recipient: fvk.address_at(7u64, Scope::External),
        amount: Zatoshis::const_from_u64(40_000_000),
        memo: MemoBytes::from_bytes(b"loki u2").unwrap(),
        change: Zatoshis::ZERO,
        target_height: if network == VaultNetwork::Testnet {
            4_465_056
        } else {
            700
        },
        expiry_height: if network == VaultNetwork::Testnet {
            4_466_208
        } else {
            1_152
        },
    };
    let fee = quote_fee(&network, &inputs).unwrap();
    inputs.change = Zatoshis::const_from_u64(625_000_000 - 40_000_000 - u64::from(fee));

    let ids: Vec<_> = (1u16..=2)
        .map(|id| frost::Identifier::try_from(id).unwrap())
        .collect();
    let identities: Vec<_> = (1u16..=2).map(Identity::new).collect();
    let publics: Vec<_> = identities.iter().map(Identity::public).collect();
    let context = SessionContext {
        vault: [1; 32],
        payment: [7; 32],
        attempt: AttemptId([9; 32]),
        signers: vec![1, 2],
    };
    let handoff = Mutex::new(None::<Vec<u8>>);
    let peer_of: BTreeMap<_, _> = ids
        .iter()
        .copied()
        .zip(
            publics.iter().cloned(),
        )
        .collect();
    let mut tx = make_transport(&coordinator);
    let peers: Vec<_> = ids.iter().map(|id| Peer(peer_of[id].encryption)).collect();
    let channel = tx.open(&peers, 4).unwrap();
    let session = session_id(&channel);
    let member_transports: Vec<_> = identities.iter().map(make_transport).collect();
    let signer_network = if network == VaultNetwork::Testnet { Network::Testnet } else { Network::Regtest };
    let candidate = CandidateRef { vault_id: [1; 32], payment_id: [7; 32], attempt_id: [9; 32] };
    let params = PublicPaymentParams {
        recipient: inputs.recipient, amount: inputs.amount, memo: inputs.memo.clone(),
        target_height: inputs.target_height, expiry_height: inputs.expiry_height,
    };

    thread::scope(|scope| {
        let handles: Vec<_> = identities
            .into_iter()
            .zip(member_transports)
            .zip(ids.iter().copied())
            .map(|((identity, mut member_tx), id)| {
                let key = keys[&id].clone();
                let proposer_inputs = if id == ids[0] { Some(&params) } else { None };
                let other_signers: Vec<_> = if proposer_inputs.is_some() { publics[1..].to_vec() } else { Vec::new() };
                let proposer = publics[0].clone();
                let coordinator = coordinator.public();
                let context = context.clone();
                let handoff = &handoff;
                let request = &params;
                let public_bytes = public.serialize().unwrap();
                let signer_public = public.clone();
                let signer_fvk = fvk.clone();
                let candidate = candidate.clone();
                scope.spawn(move || {
                    let channel = member_tx.join(session).unwrap();
                    let nonce_dir = std::env::temp_dir().join(format!("loki-payment-{}-{}", std::process::id(), rand_core::RngCore::next_u64(&mut rand_core::OsRng)));
                    let mut signer = LocalSigner::with_sealed_share(
                        identity.public().id, 2, 3, [1; 32], "payment test".into(), signer_network,
                        SoftwareSecureElement::generate(), &key.serialize().unwrap(),
                        public_bytes, signer_fvk, nonce_dir, Box::new(|_| true),
                    ).unwrap();
                    signer.set_candidate_notes(vec![note]);
                    let signer_session = signer.connect("payment test", signer_network, b"test").unwrap().session;
                    signer_loop(
                        &member_tx,
                        &channel,
                        &mut signer, &signer_session, &candidate, &signer_public, id,
                        request, &identity, &context, &proposer, &coordinator, &other_signers,
                        &|| Ok(()),
                        &|| Ok(()),
                        &mut |bytes| {
                            if proposer_inputs.is_some() {
                                *handoff.lock().unwrap() = Some(bytes.to_vec());
                            }
                            Ok(())
                        },
                    )
                    .unwrap();
                })
            })
            .collect();
        let signed =
            coordinate(&tx, &channel, &public, &ids, &peer_of, 2, rand_core::OsRng, &coordinator, &context, &|| Ok(()), || {
                Ok(handoff.lock().unwrap().clone())
            })
            .unwrap();
        for handle in handles {
            handle.join().unwrap();
        }
        tx.close(channel).unwrap();

        let parsed = pczt::Pczt::parse(&signed).unwrap();
        let branch = if network == VaultNetwork::Testnet {
            zcash_protocol::consensus::BranchId::Nu7
        } else {
            zcash_protocol::consensus::BranchId::Nu6_3
        };
        assert_eq!(*parsed.global().consensus_branch_id(), u32::from(branch));
        let sighash = pczt::roles::signer::Signer::new(parsed.clone())
            .unwrap()
            .shielded_sighash();
        let action = parsed
            .ironwood()
            .actions()
            .iter()
            .find(|action| action.spend().nullifier() == &note.nullifier(&fvk).to_bytes())
            .unwrap();
        let signature = action.spend().spend_auth_sig().expect("signed spend");
        let rk = orchard::primitives::redpallas::VerificationKey::<
            orchard::primitives::redpallas::SpendAuth,
        >::try_from(*action.spend().rk())
        .unwrap();
        rk.verify(
            &sighash,
            &orchard::primitives::redpallas::Signature::from(signature),
        )
        .unwrap();
    });
    fvk
}
