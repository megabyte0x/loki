//! Keyless PCZT signing over an opaque relay transport.
//!
//! A payment may spend up to `MAX_SPENDS` notes. Every spend is its own Orchard action under its
//! own randomized key, so it needs its own nonce, randomiser, signing package and signature
//! share. All spends sign the same sighash and travel in one round: each hosted message carries
//! one value per spend (`encode_hosted`). Each spend has its own `CandidateRef`, so its nonce id
//! is distinct and the nonce store's single-use rule holds per spend.

use std::{collections::BTreeMap, time::{Duration, Instant}};

use reddsa_frost::frost::redpallas as frost;

use crate::{
    setup_transport::{Identity, PublicIdentity},
    signer::{CandidateRef, PublicPaymentParams, Session, Signer},
    signing_session::{decode_hosted, encode_hosted, MessageKind, OpenedMessage, SessionContext, MAX_SPENDS},
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

/// The per-spend values of a hosted message, which must carry exactly `spends` of them.
fn spend_values(message: &OpenedMessage, spends: usize) -> Result<Vec<&[u8]>, String> {
    decode_hosted(message.body())
        .filter(|items| items.len() == spends)
        .ok_or_else(|| format!("hosted message does not carry exactly {spends} spends"))
}

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
    candidate_refs: &[CandidateRef],
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
        transport, channel, signer, session, candidate_refs, group_vk, own_id, params,
        own, context, proposer, coordinator, other_signers, check_running, before_share, accept_candidate,
        &|_| {},
    )
}

/// The hosted signer can observe a round-two refusal locally before it becomes a string.
#[allow(clippy::too_many_arguments)]
pub(crate) fn participate<T: Transport, S: Signer>(
    transport: &T,
    channel: &T::Channel,
    signer: &mut S,
    session: &Session,
    candidate_refs: &[CandidateRef],
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
    let spends = candidate_refs.len();
    let first = candidate_refs.first().ok_or("a payment spends at least one note")?;
    if spends > MAX_SPENDS
        || context.vault != first.vault_id
        || context.payment != first.payment_id
        || context.attempt.0 != first.attempt_id
        || candidate_refs.iter().any(|c| c.vault_id != first.vault_id || c.payment_id != first.payment_id)
        || candidate_refs.iter().enumerate().any(|(i, c)| candidate_refs[..i].iter().any(|d| d.attempt_id == c.attempt_id))
        || !context.signers.contains(&own_slot)
        || !context.signers.contains(&proposer.id)
        || coordinator.id != 0
    {
        return Err("invalid hosted signing context".into());
    }
    check_running()?;
    // One single-use nonce per spend, each under its own id.
    let mut commitments = Vec::with_capacity(spends);
    for candidate_ref in candidate_refs {
        commitments.push(signer.sign_commit(session, candidate_ref).map_err(|e| format!("sign_commit: {e}"))?);
    }
    let serialized = commitments.iter().map(|c| c.serialize().map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?;
    send(transport, channel, own, coordinator, context, HostedCommitment, &encode_hosted(&serialized)?)?;

    let local_candidate = if own_slot == proposer.id {
        let alpha = recv_until(transport, channel, own, context, &[(coordinator, HostedAlpha)], check_running)?;
        let alphas = spend_values(&alpha[&(0, HostedAlpha)], spends)?
            .into_iter()
            .map(|a| <[u8; 32]>::try_from(a).map_err(|_| "alpha must be 32 bytes"))
            .collect::<Result<Vec<_>, _>>()?;
        let candidate = signer.build_candidate(session, first, params, &alphas)
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
    let packages = spend_values(&got[&(0, HostedPackage)], spends)?;
    let seeds = spend_values(&got[&(0, HostedSeed)], spends)?;
    // Check every spend before any share is made: each package names the candidate's sighash
    // and this signer's own commitment for that spend, and each randomized key is a distinct
    // spend of the candidate.
    let mut checked = Vec::with_capacity(spends);
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(spends);
    for ((package, seed), commitment) in packages.into_iter().zip(seeds).zip(&commitments) {
        let package = frost::SigningPackage::deserialize(package).map_err(|e| format!("decode package: {e}"))?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| "randomizer seed must be 32 bytes")?;
        if package.message().as_slice() != sighash
            || package.signing_commitments().get(&own_id) != Some(commitment)
        {
            return Err("signing package differs from candidate or own commitment".into());
        }
        let randomized = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            group_vk.verifying_key(), &seed, package.signing_commitments(),
        ).map_err(|e| format!("regenerate randomizer: {e}"))?;
        let rk: [u8; 32] = randomized.randomized_verifying_key().serialize()
            .map_err(|e| e.to_string())?.try_into()
            .map_err(|_| "randomized key is not 32 bytes")?;
        if keys.contains(&rk) || !candidate.ironwood().actions().iter().any(|action| action.spend().rk() == &rk) {
            return Err("candidate has no distinct spend under each randomized group key".into());
        }
        keys.push(rk);
        checked.push((package, seed));
    }
    check_running()?;
    // The member approves once for the payment; each spend then burns its own nonce.
    let mut shares = Vec::with_capacity(spends);
    for (candidate_ref, (package, seed)) in candidate_refs.iter().zip(&checked) {
        let share = signer.sign_approve(session, candidate_ref, params, candidate_bytes, package, seed)
            .inspect_err(on_sign_refusal)
            .map_err(|e| format!("sign_approve: {e}"))?;
        shares.push(share.serialize());
    }
    before_share()?;
    Ok(send(transport, channel, own, coordinator, context, HostedShare, &encode_hosted(&shares)?)?)
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
    spends: usize,
    mut rng: impl rand_core::CryptoRngCore,
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
        || spends == 0 || spends > MAX_SPENDS
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
    // Per spend: every signer's commitment for that spend.
    let mut commitments = vec![BTreeMap::new(); spends];
    for id in peer_ids {
        let values = spend_values(&received[&(peer_of[id].id, HostedCommitment)], spends)?;
        for (spend, value) in commitments.iter_mut().zip(values) {
            let commitment = frost::round1::SigningCommitments::deserialize(value)
                .map_err(|e| format!("decode commitment: {e}"))?;
            spend.insert(*id, commitment);
        }
    }
    let mut randomized = Vec::with_capacity(spends);
    let mut alphas = Vec::with_capacity(spends);
    let mut seeds = Vec::with_capacity(spends);
    for spend in &commitments {
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            group_vk.verifying_key(),
            spend,
            &mut rng,
        )
        .map_err(|e| format!("randomizer: {e}"))?;
        let alpha: [u8; 32] = params
            .randomizer()
            .serialize()
            .try_into()
            .map_err(|_| "alpha is not 32 bytes")?;
        alphas.push(alpha.to_vec());
        seeds.push(seed.to_vec());
        randomized.push(params);
    }
    let proposer = peer_of
        .get(&peer_ids[0])
        .ok_or("proposer has no relay address")?;
    send(transport, channel, own, proposer, context, HostedAlpha, &encode_hosted(&alphas)?)?;
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
    let packages = commitments
        .into_iter()
        .map(|spend| frost::SigningPackage::new(spend, &sighash))
        .collect::<Vec<_>>();
    let package_bytes = packages.iter().map(|p| p.serialize().map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?;
    let package_body = encode_hosted(&package_bytes)?;
    let seed_body = encode_hosted(&seeds)?;
    for id in peer_ids {
        let peer = peer_of.get(id).ok_or("signer has no relay address")?;
        send(transport, channel, own, peer, context, HostedPackage, &package_body)?;
        send(transport, channel, own, peer, context, HostedSeed, &seed_body)?;
    }
    let received = recv_until(transport, channel, own, context, &expected(HostedShare), check_running)?;
    let mut shares = vec![BTreeMap::new(); spends];
    for id in peer_ids {
        let values = spend_values(&received[&(peer_of[id].id, HostedShare)], spends)?;
        for (spend, value) in shares.iter_mut().zip(values) {
            let share = frost::round2::SignatureShare::deserialize(value)
                .map_err(|e| format!("decode share: {e}"))?;
            spend.insert(*id, share);
        }
    }
    let mut signer = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?;
    let mut signed_actions = Vec::with_capacity(spends);
    for ((package, spend_shares), params) in packages.iter().zip(&shares).zip(&randomized) {
        let signature = frost_rerandomized::aggregate(package, spend_shares, group_vk, params)
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
        if signed_actions.contains(&index) {
            return Err("two spends share one randomized key".into());
        }
        signed_actions.push(index);
        let bytes: [u8; 64] = signature
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "signature is not 64 bytes")?;
        let orchard_sig = orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(bytes);
        signer
            .apply_ironwood_signature(index, orchard_sig)
            .map_err(|e| format!("apply signature: {e:?}"))?;
    }
    Ok(signer.finish().serialize().map_err(|e| format!("serialize signed: {e:?}"))?)
}
