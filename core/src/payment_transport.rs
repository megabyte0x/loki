//! Keyless, one-note PCZT signing over an opaque relay transport.

use std::{collections::BTreeMap, time::{Duration, Instant}};

use reddsa_frost::frost::redpallas as frost;

use crate::{
    setup_transport::{Identity, PublicIdentity},
    signer::{CandidateRef, PublicPaymentParams, Session, Signer},
    signing_session::{MessageKind, OpenedMessage, SessionContext},
    transport::{Outbound, Peer, SealedSigning, Transport},
};

#[derive(Clone, Debug)]
pub enum RoundError {
    Other(String),
    ReceiveDeadline { received: usize, expected: usize, shares: bool },
}

impl From<&str> for RoundError {
    fn from(error: &str) -> Self { Self::Other(error.into()) }
}

impl From<String> for RoundError {
    fn from(error: String) -> Self { Self::Other(error) }
}

impl From<RoundError> for String {
    fn from(error: RoundError) -> Self {
        match error {
            RoundError::Other(error) => error,
            RoundError::ReceiveDeadline { received, expected, .. } =>
                format!("relay delivered {received} of {expected} expected messages"),
        }
    }
}

fn recv_until<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    own: &Identity,
    context: &SessionContext,
    expected: &[(&PublicIdentity, MessageKind)],
    check_running: &dyn Fn() -> Result<(), String>,
) -> Result<BTreeMap<(u16, MessageKind), OpenedMessage>, RoundError>
where
    T::Error: std::fmt::Display,
{
    let attempt = hex::encode(context.attempt.0);
    let as_coordinator = own.public().id == 0;
    let deadline = receive_deadline();
    let mut got = BTreeMap::new();
    while Instant::now() < deadline {
        check_running()?;
        let batch = transport.recv(channel, as_coordinator).map_err(|e| {
            eprintln!("payment {attempt}: frostd signing receive error");
            format!("relay recv: {e}")
        })?;
        for msg in batch {
            let Some((sender, _)) = expected.iter().find(|(peer, _)| peer.encryption == msg.from.0) else {
                continue;
            };
            let Ok(opened) = own.open_session(sender, context, &msg.message) else { continue };
            let kind = opened.kind();
            if !expected.contains(&(sender, kind)) {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(entry) = got.entry((sender.id, kind)) {
                if !kind.valid_hosted_body(context, opened.body()) {
                    continue;
                }
                eprintln!("payment {attempt}: frostd received {kind:?}");
                entry.insert(opened);
            }
        }
        if got.len() == expected.len() {
            return Ok(got);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    eprintln!("payment {attempt}: frostd signing receive timeout ({}/{})", got.len(), expected.len());
    Err(RoundError::ReceiveDeadline {
        received: got.len(),
        expected: expected.len(),
        shares: expected.first().is_some_and(|(_, kind)| *kind == MessageKind::HostedShare),
    })
}

fn receive_deadline() -> Instant { Instant::now() + Duration::from_secs(120) }

fn send<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    own: &Identity,
    peer: &PublicIdentity,
    context: &SessionContext,
    kind: MessageKind,
    body: &[u8],
) -> Result<(), String>
where
    T::Error: std::fmt::Display,
{
    let attempt = hex::encode(context.attempt.0);
    let message = Outbound::Signing(SealedSigning::seal(own, peer, context, kind, body)?);
    let address = Peer(peer.encryption);
    // frostd routes an empty recipient list to the channel's coordinator mailbox.
    let recipients = if peer.id == 0 { &[] } else { std::slice::from_ref(&address) };
    match transport.send(channel, recipients, &message) {
        Ok(()) => { eprintln!("payment {attempt}: frostd sent {kind:?}"); Ok(()) }
        Err(e) => {
            eprintln!("payment {attempt}: frostd send {kind:?} error");
            Err(format!("send {kind:?}: {e}"))
        }
    }
}

/// Commit, optionally build the candidate as proposer, then sign the candidate-bound package.
/// The nonce, key package, viewing key, and selected note stay inside this process. The
/// candidate crosses the relay only sealed from the proposer to each other selected signer;
/// every signer passes it to `accept_candidate` (review, and for the proposer the local
/// hand-off to its coordinator) before using it.
#[allow(clippy::too_many_arguments)]
pub fn signer_loop<T: Transport, S: Signer>(
    transport: &T,
    channel: &T::Channel,
    signer: &mut S,
    session: &Session,
    candidate_ref: &CandidateRef,
    group_vk: &frost::keys::PublicKeyPackage,
    own_id: frost::Identifier,
    params: &PublicPaymentParams,
    own: &Identity,
    context: &SessionContext,
    proposer: &PublicIdentity,
    coordinator: &PublicIdentity,
    other_signers: &[PublicIdentity],
    check_running: &dyn Fn() -> Result<(), String>,
    before_share: &dyn Fn() -> Result<(), String>,
    accept_candidate: &mut dyn FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), RoundError>
where
    T::Error: std::fmt::Display,
    S::Error: std::fmt::Display,
{
    participate(
        transport, channel, signer, session, candidate_ref, group_vk, own_id, params,
        own, context, proposer, coordinator, other_signers, check_running, before_share,
        accept_candidate, &|_| {},
    )
}

/// The hosted signer can observe a round-two refusal locally before it becomes a string.
#[allow(clippy::too_many_arguments)]
pub(crate) fn participate<T: Transport, S: Signer>(
    transport: &T,
    channel: &T::Channel,
    signer: &mut S,
    session: &Session,
    candidate_ref: &CandidateRef,
    group_vk: &frost::keys::PublicKeyPackage,
    own_id: frost::Identifier,
    params: &PublicPaymentParams,
    own: &Identity,
    context: &SessionContext,
    proposer: &PublicIdentity,
    coordinator: &PublicIdentity,
    other_signers: &[PublicIdentity],
    check_running: &dyn Fn() -> Result<(), String>,
    before_share: &dyn Fn() -> Result<(), String>,
    accept_candidate: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    on_sign_refusal: &dyn Fn(&S::Error),
) -> Result<(), RoundError>
where
    T::Error: std::fmt::Display,
    S::Error: std::fmt::Display,
{
    use MessageKind::*;
    context.validate()?;
    let own_slot = own.public().id;
    if context.vault != candidate_ref.vault_id
        || context.payment != candidate_ref.payment_id
        || context.attempt.0 != candidate_ref.attempt_id
        || !context.signers.contains(&own_slot)
        || !context.signers.contains(&proposer.id)
        || coordinator.id != 0
    {
        return Err("invalid hosted signing context".into());
    }
    check_running()?;
    let commitment = signer.sign_commit(session, candidate_ref).map_err(|e| format!("sign_commit: {e}"))?;
    send(transport, channel, own, coordinator, context, HostedCommitment,
        &commitment.serialize().map_err(|e| e.to_string())?)?;

    let local_candidate = if own_slot == proposer.id {
        let alpha = recv_until(transport, channel, own, context, &[(coordinator, HostedAlpha)], check_running)?;
        let alpha_bytes = alpha[&(0, HostedAlpha)].body().try_into().map_err(|_| "alpha must be 32 bytes")?;
        let candidate = signer.build_candidate(session, candidate_ref, params, &alpha_bytes)
            .map_err(|e| format!("build_candidate: {e}"))?;
        accept_candidate(candidate.as_bytes())?;
        for peer in other_signers {
            send(transport, channel, own, peer, context, Candidate, candidate.as_bytes())?;
        }
        Some(candidate.into_bytes())
    } else { None };

    let expected = [(coordinator, HostedPackage), (coordinator, HostedSeed), (proposer, Candidate)];
    let expected = if local_candidate.is_some() { &expected[..2] } else { &expected[..] };
    let got = recv_until(transport, channel, own, context, expected, check_running)?;
    let candidate_bytes = if let Some(ref bytes) = local_candidate {
        bytes.as_slice()
    } else {
        let bytes = got[&(proposer.id, Candidate)].body();
        accept_candidate(bytes)?;
        bytes
    };
    let candidate = pczt::Pczt::parse(candidate_bytes).map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?
        .shielded_sighash();
    let package = frost::SigningPackage::deserialize(got[&(0, HostedPackage)].body())
        .map_err(|e| format!("decode package: {e}"))?;
    let seed: [u8; 32] = got[&(0, HostedSeed)].body()
        .try_into()
        .map_err(|_| "randomizer seed must be 32 bytes")?;
    if package.message().as_slice() != sighash
        || package.signing_commitments().get(&own_id) != Some(&commitment)
    {
        return Err("signing package differs from candidate or own commitment".into());
    }
    let randomized = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
        group_vk.verifying_key(), &seed, package.signing_commitments(),
    ).map_err(|e| format!("regenerate randomizer: {e}"))?;
    let rk: [u8; 32] = randomized.randomized_verifying_key().serialize()
        .map_err(|e| e.to_string())?.try_into()
        .map_err(|_| "randomized key is not 32 bytes")?;
    if !candidate.ironwood().actions().iter().any(|action| action.spend().rk() == &rk) {
        return Err("candidate has no spend under the randomized group key".into());
    }
    check_running()?;
    let share = signer.sign_approve(session, candidate_ref, params, candidate_bytes, &package, &seed)
        .inspect_err(on_sign_refusal)
        .map_err(|e| format!("sign_approve: {e}"))?;
    before_share()?;
    Ok(send(transport, channel, own, coordinator, context, HostedShare, &share.serialize())?)
}

/// Gather a threshold of commitments, request the proposer candidate, aggregate, and apply.
/// `peer_ids[0]` is the designated proposer. The candidate never comes over the relay:
/// `local_candidate` polls the proposer's local hand-off and returns `None` until it exists.
pub fn coordinate<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    group_vk: &frost::keys::PublicKeyPackage,
    peer_ids: &[frost::Identifier],
    peer_of: &BTreeMap<frost::Identifier, PublicIdentity>,
    threshold: u16,
    rng: impl rand_core::CryptoRngCore,
    own: &Identity,
    context: &SessionContext,
    check_running: &dyn Fn() -> Result<(), String>,
    mut local_candidate: impl FnMut() -> Result<Option<Vec<u8>>, String>,
) -> Result<Vec<u8>, RoundError>
where
    T::Error: std::fmt::Display,
{
    use MessageKind::*;
    if own.public().id != 0 || threshold == 0
        || peer_ids.len() != usize::from(threshold)
        || group_vk.min_signers() != Some(threshold)
        || peer_ids
            .iter()
            .any(|id| !group_vk.verifying_shares().contains_key(id) || !peer_of.contains_key(id))
    {
        return Err("invalid signing quorum".into());
    }
    let expected = |kind| peer_ids.iter().map(|id| (&peer_of[id], kind)).collect::<Vec<_>>();
    let received = recv_until(transport, channel, own, context, &expected(HostedCommitment), check_running)?;
    let mut commitments = BTreeMap::new();
    for id in peer_ids {
        let commitment = frost::round1::SigningCommitments::deserialize(received[&(peer_of[id].id, HostedCommitment)].body())
            .map_err(|e| format!("decode commitment: {e}"))?;
        commitments.insert(*id, commitment);
    }
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        group_vk.verifying_key(),
        &commitments,
        rng,
    )
    .map_err(|e| format!("randomizer: {e}"))?;
    let alpha: [u8; 32] = params
        .randomizer()
        .serialize()
        .try_into()
        .map_err(|_| "alpha is not 32 bytes")?;
    let proposer = peer_of
        .get(&peer_ids[0])
        .ok_or("proposer has no relay address")?;
    send(transport, channel, own, proposer, context, HostedAlpha, &alpha)?;
    let mut candidate_bytes = None;
    let deadline = receive_deadline();
    while Instant::now() < deadline {
        check_running()?;
        candidate_bytes = local_candidate()?;
        if candidate_bytes.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let candidate_bytes = candidate_bytes.ok_or("the proposer built no candidate")?;
    let candidate = pczt::Pczt::parse(&candidate_bytes)
        .map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?
        .shielded_sighash();
    let package = frost::SigningPackage::new(commitments, &sighash);
    let package_bytes = package.serialize().map_err(|e| e.to_string())?;
    for id in peer_ids {
        let peer = peer_of.get(id).ok_or("signer has no relay address")?;
        send(transport, channel, own, peer, context, HostedPackage, &package_bytes)?;
        send(transport, channel, own, peer, context, HostedSeed, &seed)?;
    }
    let mut shares = BTreeMap::new();
    let received = recv_until(transport, channel, own, context, &expected(HostedShare), check_running)?;
    for id in peer_ids {
        let share = frost::round2::SignatureShare::deserialize(received[&(peer_of[id].id, HostedShare)].body())
            .map_err(|e| format!("decode share: {e}"))?;
        shares.insert(*id, share);
    }
    let signature = frost_rerandomized::aggregate(&package, &shares, group_vk, &params)
        .map_err(|e| format!("aggregate: {e}"))?;
    params
        .randomized_verifying_key()
        .verify(&sighash, &signature)
        .map_err(|e| format!("verify aggregate: {e}"))?;
    let rk: [u8; 32] = params
        .randomized_verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "randomized key is not 32 bytes")?;
    let index = candidate
        .ironwood()
        .actions()
        .iter()
        .position(|action| action.spend().rk() == &rk)
        .ok_or("candidate has no spend under the randomized group key")?;
    let bytes: [u8; 64] = signature
        .serialize()
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let orchard_sig = orchard::primitives::redpallas::Signature::<
        orchard::primitives::redpallas::SpendAuth,
    >::from(bytes);
    let mut signer = pczt::roles::signer::Signer::new(candidate)
        .map_err(|e| format!("candidate signer: {e:?}"))?;
    signer
        .apply_ironwood_signature(index, orchard_sig)
        .map_err(|e| format!("apply signature: {e:?}"))?;
    Ok(signer.finish().serialize().map_err(|e| format!("serialize signed: {e:?}"))?)
}
