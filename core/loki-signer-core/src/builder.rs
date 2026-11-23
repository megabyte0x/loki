//! Untrusted server-side payment builder (W4) — the heavy, SHARE-FREE wallet work.
//!
//! In-browser signers are light: they hold the FROST share, recompute the sighash from the
//! candidate bytes (WYSIWYS — [`crate::verify::check_candidate`] + [`sighash_of_pczt`]) and
//! refuse any mismatch before releasing a share (host/payment.rs `review_candidate`). The
//! heavy work — scan via lightwalletd, note selection, PCZT assembly, Orchard proving,
//! broadcast — needs only the vault's VIEWING key, never a spend share. This module is that
//! heavy half, factored out so a server (the coordinator or a sibling service) can run it
//! without ever holding a `KeyPackage` or joining the FROST signing round.
//!
//! SAFETY — why an untrusted builder cannot steal or forge: no function here takes a
//! `frost::keys::KeyPackage`, a signing share, a nonce, or a `SecureElement` — only a
//! [`FullViewingKey`], public payment params, and public randomizers. It can *propose* a
//! transaction; it cannot *authorize* one. A dishonest build is caught by the signers' WYSIWYS
//! check before any share is emitted, so the builder is untrusted-for-integrity. The one thing
//! it does see is the vault's activity and each payment's recipient/amount/memo (it holds the
//! viewing key) — the documented, per-vault opt-in privacy tradeoff.
//!
//! NOTE — why [`build_unsigned`] is not a stateless oracle: the Orchard `rk`, and therefore the
//! sighash, are bound to the quorum's round-1 commitments through the FROST re-randomizer
//! `alpha` (`RandomizedParams::new_from_commitments`, payment_transport.rs). The builder can
//! only produce the candidate the signers accept once the live session has yielded `alpha`, so
//! it runs as the session's coordinator — it is not a pre-session `build(intent) -> sighash`.
//! Proving and broadcast (the `broadcast(signed_pczt) -> txid` half) are the equally share-free
//! `loki_poc::tx_finalize::prove` followed by the lightwalletd send in host/payment.rs `finish`.

use orchard::{keys::FullViewingKey, Note};
use zcash_protocol::consensus::Parameters;

use crate::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs},
    network::VaultNetwork,
    signer::{wysiwys, PublicPaymentParams},
};

/// Build one unsigned, unproven single-note candidate PCZT under `alpha`, from the vault's
/// viewing key alone. This is the exact build the production signer runs — `LocalSigner`'s
/// `build_single_note_pczt` delegates here — so what the builder emits is byte-for-byte what an
/// in-browser signer's WYSIWYS check validates. No share, nonce, or secret is touched.
pub fn build_unsigned<P: Parameters + Clone>(
    vault_fvk: &FullViewingKey,
    params_net: &P,
    params: &PublicPaymentParams,
    notes: &[Note],
    alphas: &[[u8; 32]],
) -> Result<Vec<u8>, String> {
    if notes.is_empty() || notes.len() != alphas.len() {
        return Err("each spent note needs exactly one randomiser".into());
    }
    let alphas = alphas
        .iter()
        .map(|alpha| alpha_from_canonical_bytes(alpha).ok_or("noncanonical alpha"))
        .collect::<Result<Vec<_>, _>>()?;

    let mut inputs = CandidateInputs {
        vault_fvk,
        notes: notes.to_vec(),
        recipient: params.recipient,
        amount: params.amount,
        memo: params.memo.clone(),
        change: zcash_protocol::value::Zatoshis::ZERO,
        target_height: params.target_height,
        expiry_height: params.expiry_height,
    };
    let fee = u64::from(quote_fee(params_net, &inputs)?);
    let spend = notes
        .iter()
        .try_fold(0u64, |sum, note| sum.checked_add(note.value().inner()))
        .ok_or("note values overflow")?;
    let amount = u64::from(params.amount);
    let change = spend
        .checked_sub(amount)
        .and_then(|r| r.checked_sub(fee))
        .ok_or("notes do not cover amount + fee")?;
    inputs.change =
        zcash_protocol::value::Zatoshis::from_u64(change).map_err(|e| format!("{e:?}"))?;

    let built = build_candidate(
        params_net,
        &inputs,
        &alphas,
        rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
    )?;
    let candidate = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
        .ok_or("build_from_parts returned None")?;
    let candidate = pczt::roles::io_finalizer::IoFinalizer::new(candidate)
        .finalize_io()
        .map_err(|e| format!("io finalize: {e:?}"))?;
    candidate
        .serialize()
        .map_err(|e| format!("serialize: {e:?}"))
}

/// The `build(vault, intent) -> {pczt_unsigned, sighash}` half of the builder's HTTP surface:
/// pick the vault's network parameters, build the unsigned candidate, and return it with the
/// sighash the signers will independently recompute. `fee` and `change` are not returned
/// separately — they are carried in the PCZT and re-derived by the signers' WYSIWYS check, so
/// there is nothing here for a dishonest builder to misreport.
pub fn build_candidate_for_vault(
    vault_fvk: &FullViewingKey,
    network: VaultNetwork,
    params: &PublicPaymentParams,
    note: Note,
    alpha: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let pczt = match network {
        VaultNetwork::Regtest => {
            build_unsigned(vault_fvk, &crate::candidate::Regtest, params, &[note], &[*alpha])
        }
        VaultNetwork::Testnet => build_unsigned(
            vault_fvk,
            &zcash_protocol::consensus::TEST_NETWORK,
            params,
            &[note],
            &[*alpha],
        ),
    }?;
    let sighash = wysiwys::sighash_of_pczt(&pczt, vault_fvk)?;
    Ok((pczt, sighash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        verify::{check_candidate, Expectations, Refusal},
        zip2005,
    };
    use orchard::{
        keys::Scope,
        note::{RandomSeed, Rho},
        value::NoteValue,
        NoteVersion,
    };
    use reddsa_frost::frost::redpallas as frost;
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    /// The builder produces an unsigned candidate that an in-browser signer's WYSIWYS check
    /// accepts, and whose sighash the signer recomputes identically — all from the vault's
    /// viewing key, with no share anywhere in the path.
    #[test]
    fn builder_unsigned_pczt_is_accepted_by_a_wysiwys_signer() {
        // A real group viewing key. The builder is handed ONLY this fvk — never the shares.
        let (_shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();

        // One vault note to spend, a recipient, an amount and a memo — the payment intent.
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note = orchard::Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(625_000_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let recipient = fvk.address_at(7u64, Scope::External);
        let memo = b"loki w4 builder".to_vec();
        let params = PublicPaymentParams {
            recipient,
            amount: Zatoshis::const_from_u64(40_000_000),
            memo: MemoBytes::from_bytes(&memo).unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        };
        // Stands in for a live quorum's re-randomizer (derived from round-1 commitments).
        let alpha = [9u8; 32];

        let (pczt_bytes, sighash) =
            build_candidate_for_vault(&fvk, VaultNetwork::Regtest, &params, note, &alpha).unwrap();

        // The fee the builder used is the conventional ZIP 317 fee, re-derived here so the
        // signer's expectations are independent of anything the builder claims.
        let fee: u64 = quote_fee(
            &crate::candidate::Regtest,
            &CandidateInputs {
                vault_fvk: &fvk,
                notes: vec![note],
                recipient,
                amount: params.amount,
                memo: params.memo.clone(),
                change: Zatoshis::ZERO,
                target_height: 700,
                expiry_height: 1_152,
            },
        )
        .unwrap()
        .into();
        let expected = Expectations {
            input_nullifiers: vec![note.nullifier(&fvk).to_bytes()],
            recipient: recipient.to_raw_address_bytes(),
            amount_zat: 40_000_000,
            memo,
            change_zat: 625_000_000 - 40_000_000 - fee,
            fee_zat: fee,
            expiry_height: 1_152,
        };

        // Exactly the signer-side WYSIWYS gate (host/payment.rs `review_candidate`): open the
        // PCZT with the verifier and prove its effects equal the reviewed intent.
        let parsed = pczt::Pczt::parse(&pczt_bytes).unwrap();
        pczt::roles::verifier::Verifier::new(parsed)
            .with_ironwood::<Refusal, _>(|bundle| {
                check_candidate(bundle, &fvk, &expected)
                    .map_err(pczt::roles::verifier::OrchardError::Custom)
            })
            .expect("a WYSIWYS signer accepts the builder's candidate");

        // The signer recomputes the sighash from the same bytes; the builder's matches it.
        let recomputed = wysiwys::sighash_of_pczt(&pczt_bytes, &fvk).unwrap();
        assert_eq!(recomputed, sighash, "signer's sighash must match the builder's");

        // And the independent render agrees on recipient/amount/memo.
        let view = wysiwys::describe_pczt(&pczt_bytes, &fvk).unwrap();
        assert_eq!(view.to, recipient.to_raw_address_bytes());
        assert_eq!(view.amount_zat, 40_000_000);
        // describe_pczt returns the 512-byte padded memo field; the intent text is its prefix.
        assert!(view.memo.starts_with(b"loki w4 builder"));
    }

    /// A builder that tampers with the amount is caught by the signer's WYSIWYS check — the
    /// reason the builder can be untrusted. The builder cannot both pay elsewhere and keep the
    /// effects the signer reviewed.
    #[test]
    fn a_tampered_build_is_refused_by_the_signer() {
        let (_shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note = orchard::Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(625_000_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let recipient = fvk.address_at(7u64, Scope::External);
        let params = PublicPaymentParams {
            recipient,
            amount: Zatoshis::const_from_u64(40_000_000),
            memo: MemoBytes::from_bytes(b"loki w4 builder").unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        };
        let (pczt_bytes, _) =
            build_candidate_for_vault(&fvk, VaultNetwork::Regtest, &params, note, &[9u8; 32])
                .unwrap();

        // The signer reviewed a 40_000_001-zat payment; the builder's candidate pays 40_000_000.
        let fee: u64 = quote_fee(
            &crate::candidate::Regtest,
            &CandidateInputs {
                vault_fvk: &fvk,
                notes: vec![note],
                recipient,
                amount: params.amount,
                memo: params.memo.clone(),
                change: Zatoshis::ZERO,
                target_height: 700,
                expiry_height: 1_152,
            },
        )
        .unwrap()
        .into();
        let mut want = Expectations {
            input_nullifiers: vec![note.nullifier(&fvk).to_bytes()],
            recipient: recipient.to_raw_address_bytes(),
            amount_zat: 40_000_001,
            memo: b"loki w4 builder".to_vec(),
            change_zat: 625_000_000 - 40_000_000 - fee,
            fee_zat: fee,
            expiry_height: 1_152,
        };
        want.amount_zat = 40_000_001;

        let parsed = pczt::Pczt::parse(&pczt_bytes).unwrap();
        let refused = pczt::roles::verifier::Verifier::new(parsed)
            .with_ironwood::<Refusal, _>(|bundle| {
                check_candidate(bundle, &fvk, &want)
                    .map_err(pczt::roles::verifier::OrchardError::Custom)
            });
        assert!(refused.is_err(), "WYSIWYS must refuse an intent the build does not match");
    }
}
