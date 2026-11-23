//! UNIT U2: the keyless coordination loop.
//!
//! [`drive_to_signed_pczt`] drives a quorum of [`Signer`]s from a payment intent to a
//! signed PCZT. It links NO share/nonce code: every secret stays inside the signers, and
//! the coordinator only ever moves PUBLIC artifacts (commitments, a `SigningPackage`, a
//! randomizer seed, signature shares) between them — the same seam the `PublicArtifact`
//! guard in [`crate::signer`] pins.
//!
//! The loop is, for a one-note candidate:
//!   1. round 1: [`Signer::sign_commit`] on each quorum member → public commitments,
//!   2. derive the rerandomizer from those commitments and the candidate's `alpha` from it,
//!   3. ASK THE PROPOSER SIGNER to build the unproved candidate PCZT under that alpha
//!      ([`Signer::build_candidate`]) — using ITS own viewing key and ITS own selected note.
//!      The coordinator passes only the public payment effects + alpha and never selects a
//!      note. It does see the viewing key: the candidate PCZT it gets back carries the vault
//!      FVK and the spent note in each Orchard spend, so this loop must run where that is
//!      acceptable (in the host, the coordinator role runs inside the proposer member's
//!      process).
//!   4. assemble the FROST [`SigningPackage`] from the commitments + the candidate sighash,
//!   5. round 2: [`Signer::sign_approve`] on each member (pczt + package + randomizer seed),
//!   6. aggregate the shares ([`frost_rerandomized::aggregate`]), apply the signature to the
//!      PCZT, and return the signed bytes.
//!
//! It stops at the signed PCZT: no prove, broadcast, scan, or chain contact.
//!
//! The setup drivers [`member_dkg_step`], [`relay_dkg`] and [`redeliver_dkg`] carry the
//! signer's DKG wires over a [`Transport`]: members send to the coordinator, which logs
//! each wire in its [`RelayLog`] before forwarding it, and redelivers from the log after a
//! restart. The coordinator only moves wires; it cannot open round two.

use crate::signer::{CandidateRef, DkgInput, PublicPaymentParams, Session, Signer, VaultRef};
use crate::transport::{Outbound, Peer, RelayLog, Transport};
use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;

/// What the coordinator knows to drive the payment: the PUBLIC effects only. No viewing
/// key, no note, no share, no nonce, no spend authority. The signer selects its own note
/// and builds under its own viewing key.
pub type PaymentIntent = PublicPaymentParams;

/// One quorum member as the coordinator sees it: its FROST identifier, the session handle
/// returned by [`Signer::connect`], and the signer itself. No key material.
pub struct QuorumMember<'a, S: Signer> {
    pub id: frost::Identifier,
    pub session: Session,
    pub signer: &'a mut S,
}

/// Drive the quorum to a signed PCZT. `public` is the group public key package (public).
/// `cand` names the candidate for the signers' nonce/render bookkeeping.
///
/// Returns the signed PCZT bytes. Errors are plain strings: this is a coordinator, it has
/// no secrets to leak in a message.
pub fn drive_to_signed_pczt<S>(
    public: &frost::keys::PublicKeyPackage,
    intent: &PaymentIntent,
    cand: &CandidateRef,
    quorum: &mut [QuorumMember<'_, S>],
) -> Result<Vec<u8>, String>
where
    S: Signer,
    S::Error: std::fmt::Display,
{
    if quorum.is_empty() {
        return Err("empty quorum".into());
    }

    // 1. Round 1: each member commits. The secret nonce stays inside the signer; only the
    //    public commitment comes back.
    let mut commitments = BTreeMap::new();
    for m in quorum.iter_mut() {
        let c = m
            .signer
            .sign_commit(&m.session, cand)
            .map_err(|e| format!("member {:?} sign_commit: {e}", m.id))?;
        commitments.insert(m.id, c);
    }

    // 2. The rerandomizer is bound to THIS quorum's commitments; alpha is derived from it.
    let (fparams, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .map_err(|e| format!("randomizer: {e}"))?;
    let seed_bytes: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "randomizer seed is not 32 bytes")?;
    let alpha_bytes: [u8; 32] = fparams
        .randomizer()
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| "randomizer alpha is not 32 bytes")?;

    // 3. Ask the PROPOSER signer (quorum member 0) to build the unproved candidate under
    //    this alpha. It uses its OWN viewing key and OWN selected note; the coordinator
    //    hands over only the public effects + alpha (canonical bytes) and never selects a
    //    note; the returned candidate carries the vault FVK and the spent note.
    let pczt_bytes = {
        let proposer = &quorum[0];
        proposer
            .signer
            .build_candidate(&proposer.session, cand, intent, &[alpha_bytes])
            .map_err(|e| format!("proposer {:?} build_candidate: {e}", proposer.id))?
            .0
    };

    // Recompute the sighash from the bytes the proposer returned — the signers redo this
    // independently in round 2 (WYSIWYS binding).
    let candidate = pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate)
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();

    // 4. Assemble the FROST signing package from the commitments + the candidate sighash.
    let package = frost::SigningPackage::new(commitments.clone(), &sighash);

    // 5. Round 2: each member renders+approves the bytes and returns a public share.
    let mut shares = BTreeMap::new();
    for m in quorum.iter_mut() {
        let share = m
            .signer
            .sign_approve(&m.session, cand, intent, &pczt_bytes, &package, &seed_bytes)
            .map_err(|e| format!("member {:?} sign_approve: {e}", m.id))?;
        shares.insert(m.id, share);
    }

    // 6. Aggregate, verify under the randomized group key, apply, and return signed bytes.
    let group_sig = frost_rerandomized::aggregate(&package, &shares, public, &fparams)
        .map_err(|e| format!("aggregate: {e}"))?;
    fparams
        .randomized_verifying_key()
        .verify(&sighash, &group_sig)
        .map_err(|e| format!("aggregate does not verify under randomized group key: {e}"))?;
    let sig_bytes: [u8; 64] = group_sig
        .serialize()
        .map_err(|e| format!("{e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let orchard_sig = orchard::primitives::redpallas::Signature::<
        orchard::primitives::redpallas::SpendAuth,
    >::from(sig_bytes);

    // Keyless action selection: the signed spend is the one whose `rk` equals the group's
    // randomized verifying key (ak·alpha). Padding actions carry independent dummy `rk`s.
    // The coordinator has no viewing key and no note, so it CANNOT match by nullifier.
    let parsed = pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("reparse: {e:?}"))?;
    let want_rk: [u8; 32] = fparams
        .randomized_verifying_key()
        .serialize()
        .map_err(|e| format!("{e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "randomized vk is not 32 bytes")?;
    let index = parsed
        .ironwood()
        .actions()
        .iter()
        .position(|a| a.spend().rk() == &want_rk)
        .ok_or("candidate has no spend under the randomized group key")?;
    let mut signer =
        pczt::roles::signer::Signer::new(parsed).map_err(|e| format!("signer: {e:?}"))?;
    signer
        .apply_ironwood_signature(index, orchard_sig)
        .map_err(|e| format!("apply signature: {e:?}"))?;
    signer
        .finish()
        .serialize()
        .map_err(|e| format!("serialize signed: {e:?}"))
}

/// Member side of one setup pass: hand the signer what the coordinator relayed, then
/// send every setup message the signer returns to the coordinator. Only messages from
/// `coordinator` are taken: frostd lets any session participant write to a member, and
/// the coordinator's relay log is what checks each wire against its real sender. If the
/// signer refuses an input it still re-sends what it has saved, then the refusal is
/// returned. Returns how many messages it sent.
pub fn member_dkg_step<S, T>(
    signer: &mut S,
    session: &Session,
    vault: &VaultRef,
    transport: &T,
    channel: &T::Channel,
    coordinator: &Peer,
) -> Result<usize, String>
where
    S: Signer,
    S::Error: std::fmt::Display,
    T: Transport,
    T::Error: std::fmt::Display,
{
    let inputs = transport
        .recv(channel, false)
        .map_err(|e| format!("recv: {e}"))?
        .into_iter()
        .filter(|incoming| incoming.from == *coordinator)
        .filter_map(|incoming| DkgInput::from_relay(incoming.message).ok())
        .collect::<Vec<_>>();
    let (wires, refused) = match signer.dkg_step(session, vault, &inputs) {
        Ok(wires) => (wires, None),
        Err(error) => match signer.dkg_step(session, vault, &[]) {
            Ok(wires) => (wires, Some(error)),
            Err(_) => return Err(format!("dkg_step: {error}")),
        },
    };
    let sent = wires.len();
    for wire in wires {
        transport
            .send(channel, &[], &Outbound::Dkg(wire))
            .map_err(|e| format!("send: {e}"))?;
    }
    match refused {
        Some(error) => Err(format!("dkg_step: {error}")),
        None => Ok(sent),
    }
}

/// Coordinator side of one setup pass: log each wire a member sent, then forward it to
/// its recipients. A message from outside the roster, or one that is not a well-formed
/// wire from its relay sender, is dropped. Returns how many new wires it forwarded.
pub fn relay_dkg<T>(
    log: &mut RelayLog,
    transport: &T,
    channel: &T::Channel,
    members: &BTreeMap<u16, Peer>,
) -> Result<usize, String>
where
    T: Transport,
    T::Error: std::fmt::Display,
{
    let mut forwarded = 0;
    for incoming in transport
        .recv(channel, true)
        .map_err(|e| format!("recv: {e}"))?
    {
        let Some(from) = members
            .iter()
            .find(|(_, peer)| **peer == incoming.from)
            .map(|(id, _)| *id)
        else {
            continue;
        };
        let Ok(relayed) = log.relay(from, incoming.message) else {
            continue;
        };
        if let Some((wire, recipients)) = relayed {
            let to: Vec<Peer> = recipients.iter().map(|id| members[id].clone()).collect();
            transport
                .send(channel, &to, &Outbound::Dkg(wire))
                .map_err(|e| format!("send: {e}"))?;
            forwarded += 1;
        }
    }
    Ok(forwarded)
}

/// After a coordinator restart: send every logged wire to its recipients again. Members
/// ignore exact repeats.
pub fn redeliver_dkg<T>(
    log: &RelayLog,
    transport: &T,
    channel: &T::Channel,
    members: &BTreeMap<u16, Peer>,
) -> Result<usize, String>
where
    T: Transport,
    T::Error: std::fmt::Display,
{
    let mut sent = 0;
    for (id, peer) in members {
        for wire in log.for_member(*id) {
            transport
                .send(channel, std::slice::from_ref(peer), &Outbound::Dkg(wire))
                .map_err(|e| format!("send: {e}"))?;
            sent += 1;
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::local::LocalSigner;
    use crate::signer::secure_element::SoftwareSecureElement;
    use crate::signer::Network;
    use crate::zip2005;
    use orchard::keys::{FullViewingKey, Scope};
    use orchard::note::{RandomSeed, Rho};
    use orchard::value::NoteValue;
    use orchard::NoteVersion;
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    const SPEND_VALUE: u64 = 625_000_000;
    const AMOUNT: u64 = 40_000_000;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-coord-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn vault_note(fvk: &FullViewingKey) -> orchard::Note {
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        orchard::Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(SPEND_VALUE),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap()
    }

    /// Dealer-keygen a t-of-n vault, connect every member, and drive the FIRST quorum
    /// (members 1..=t) through the keyless loop. The loop itself verifies the aggregated
    /// signature under the randomized group key before returning — the exact bytes a prover
    /// would accept — so a non-error return IS the acceptance.
    fn roundtrip(threshold: u16, members: u16) {
        let (shares, public) = frost::keys::generate_with_dealer(
            members,
            threshold,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .expect("dealer keygen");
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        let note = vault_note(&fvk);
        let pp_bytes = public.serialize().unwrap();

        // One LocalSigner per quorum member (ids 1..=threshold), each with its dealt share.
        let mut signers: Vec<LocalSigner<SoftwareSecureElement>> = (1..=threshold)
            .map(|id| {
                let ident = frost::Identifier::try_from(id).unwrap();
                let kp =
                    frost::keys::KeyPackage::try_from(shares.get(&ident).unwrap().clone()).unwrap();
                LocalSigner::with_sealed_share(
                    id,
                    threshold,
                    members,
                    [id as u8; 32],
                    "coord vault".into(),
                    Network::Regtest,
                    SoftwareSecureElement::generate(),
                    &kp.serialize().unwrap(),
                    pp_bytes.clone(),
                    fvk.clone(),
                    tempdir(&format!("t{threshold}n{members}m{id}")),
                    Box::new(|_view| true), // approval policy returns true in the test
                )
                .unwrap()
            })
            .collect();

        // Each signer scans its own note member-side; give it to the signer, NOT the
        // coordinator. The proposer (member 0) builds the candidate from its own note.
        for s in signers.iter_mut() {
            s.set_candidate_notes(vec![note]);
        }

        let sessions: Vec<Session> = signers
            .iter_mut()
            .map(|s| {
                s.connect("http://coordinator.test", Network::Regtest, b"u2-challenge")
                    .unwrap()
                    .session
            })
            .collect();

        // PUBLIC effects only: no fvk, no note. The coordinator never learns either.
        let intent = PaymentIntent {
            recipient: fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::const_from_u64(AMOUNT),
            memo: MemoBytes::from_bytes(b"loki u2").unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        };
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };

        let mut quorum: Vec<QuorumMember<'_, _>> = signers
            .iter_mut()
            .zip(sessions)
            .enumerate()
            .map(|(i, (signer, session))| QuorumMember {
                id: frost::Identifier::try_from((i as u16) + 1).unwrap(),
                session,
                signer,
            })
            .collect();

        let signed = drive_to_signed_pczt(&public, &intent, &cand, &mut quorum)
            .expect("the keyless loop produces a verified signed PCZT");

        // The returned bytes parse and the intended spend now carries a spend-auth sig.
        let parsed = pczt::Pczt::parse(&signed).unwrap();
        let nf = note.nullifier(&fvk).to_bytes();
        let action = parsed
            .ironwood()
            .actions()
            .iter()
            .find(|a| a.spend().nullifier() == &nf)
            .expect("signed pczt still spends the intended note");
        assert!(
            action.spend().spend_auth_sig().is_some(),
            "the aggregated signature must be applied to the spend"
        );
    }

    #[test]
    fn keyless_loop_signs_2_of_3() {
        roundtrip(2, 3);
    }

    #[test]
    fn keyless_loop_signs_3_of_5() {
        roundtrip(3, 5);
    }
}
