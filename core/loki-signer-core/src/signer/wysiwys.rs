//! "What you see is what you sign" (ws1-signer §5.4, invariant 3).
//!
//! Parses a PCZT and returns the payment facts DERIVED FROM THE BYTES — never from any
//! caller-supplied label. The member approves THIS on-device. A malicious coordinator
//! that claims recipient X while the PCZT actually pays Y is caught here, because every
//! field below comes from the PCZT openings + the vault viewing key, not from the claim.
//!
//! Derivation:
//! - recipient / amount / change: each output note is reconstructed from its openings
//!   (`verify::open_output`), then classified as change iff its address equals the vault's
//!   own internal address, otherwise it is the payment. Nonzero change must also decrypt
//!   with the vault's internal viewing key. No expected recipient is consulted.
//! - memo: the vault is the SENDER, so it recovers its own output's memo from
//!   `enc_ciphertext` using the esk/pk_d of the reconstructed note.
//! - fee: inputs minus outputs, from the opened values.
//! - network: the consensus branch id committed in the PCZT global (the bytes bind it).

use super::local::SignerError;
use crate::verify::{check_change_decryption, open_output};
use orchard::{
    keys::FullViewingKey,
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::IronwoodDomain,
    primitives::redpallas::{self, SpendAuth},
    value::ValueCommitment,
    Action,
};
use pczt::roles::verifier::{OrchardError, Verifier};
use zcash_note_encryption::{try_output_recovery_with_pkd_esk, Domain};

/// Exactly the facts the member confirms on the signer. All derived from PCZT bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentView {
    /// Raw 43-byte Orchard address of the real payee, from the PCZT.
    pub to: [u8; 43],
    pub amount_zat: u64,
    pub fee_zat: u64,
    pub change_zat: u64,
    /// The payee's memo, recovered from the ciphertext.
    pub memo: Vec<u8>,
    /// Height after which the transaction cannot be mined, from the signed PCZT.
    pub expiry_height: u32,
    /// Consensus branch id the PCZT commits to (e.g. NU7); several networks can share it.
    pub network_branch_id: u32,
    /// `true` iff every action's declared spend/output value was bound to its `cv_net`
    /// value commitment (`verify_cv_net`), so the rendered fee is the one the sighash
    /// commits to — not a forgeable, self-declared number. `false` when any action is
    /// missing its `rcv` trapdoor (e.g. a not-yet-IO-finalized PCZT); the fee is then
    /// `amount_in - amount_out` of UNVERIFIED openings and MUST be shown as such.
    pub fee_verified: bool,
}

/// Parse `pczt_bytes` with the vault's viewing key and return what the member will sign.
/// Errors on a structurally invalid PCZT or one whose payment cannot be fully reviewed.
pub fn describe_pczt(pczt_bytes: &[u8], vault_fvk: &FullViewingKey) -> Result<PaymentView, String> {
    let parsed = pczt::Pczt::parse(pczt_bytes).map_err(|e| format!("pczt parse: {e:?}"))?;
    if *parsed.global().tx_version() != zcash_protocol::constants::V6_TX_VERSION {
        return Err("unsupported transaction version".into());
    }
    if !parsed.orchard().actions().is_empty()
        || !parsed.transparent().inputs().is_empty()
        || !parsed.transparent().outputs().is_empty()
        || !parsed.sapling().spends().is_empty()
        || !parsed.sapling().outputs().is_empty()
    {
        return Err("pczt includes an unsupported pool".into());
    }
    if parsed.ironwood().anchor().is_some() {
        return Err("pczt already carries an Ironwood anchor".into());
    }
    let network_branch_id = *parsed.global().consensus_branch_id();
    let expiry_height = *parsed.global().expiry_height();

    let change_address = vault_fvk
        .address_at(0u64, orchard::keys::Scope::Internal)
        .to_raw_address_bytes();

    let mut payee: Option<([u8; 43], u64, Vec<u8>)> = None;
    let mut change_zat: u64 = 0;
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;
    // Fee integrity: a spend's declared value is only trustworthy once it is bound to the
    // action's `cv_net` value commitment (the thing the sighash commits to). We start
    // "verified" and clear it the moment any action lacks its `rcv` trapdoor or fails the
    // binding — so a PCZT that hands us self-declared, uncommitted values renders an
    // explicitly UNVERIFIED fee rather than a forgeable one.
    let mut fee_verified = true;
    let mut inner: Result<(), String> = Ok(());

    // The Verifier yields the parsed `orchard::pczt::Bundle`, whose actions carry the
    // openings `open_output` needs. We only read; `check_candidate` uses the same path.
    Verifier::new(parsed)
        .with_ironwood::<String, _>(|bundle| {
            let mut run = || -> Result<(), String> {
                for action in bundle.actions() {
                    if action.spend().witness().is_some()
                        && action
                            .spend()
                            .value()
                            .is_some_and(|value| value.inner() > 0)
                    {
                        return Err("pczt already carries a spend witness".into());
                    }
                    // Bind this action's declared values to its value commitment. If the
                    // trapdoor is absent or the commitment disagrees, the declared spend
                    // value is not something the sighash commits to: keep reading for the
                    // render but mark the fee unverified.
                    if action.verify_cv_net().is_err() {
                        fee_verified = false;
                    }
                    if let Some(v) = action.spend().value() {
                        total_in =
                            total_in.checked_add(v.inner()).ok_or("input value overflow")?;
                    }
                }
                for (i, action) in bundle.actions().iter().enumerate() {
                    let label = format!("output {i}");
                    let (note, recipient, value) =
                        open_output(action, &label).map_err(|e| format!("{e:?}"))?;
                    total_out =
                        total_out.checked_add(value).ok_or("output value overflow")?;

                    if recipient == change_address {
                        check_change_decryption(action, &note, vault_fvk, &label)
                            .map_err(|e| e.to_string())?;
                        change_zat =
                            change_zat.checked_add(value).ok_or("change overflow")?;
                        continue;
                    }
                    if value == 0 {
                        continue; // builder padding, not a payment
                    }
                    if payee.is_some() {
                        return Err("pczt has more than one non-change payment output".into());
                    }
                    // Recover the payee memo from the ciphertext as the SENDER (vault):
                    // recovery with the reconstructed esk/pk_d also checks the transmitted epk.
                    let memo = recover_memo(action, &note)
                        .ok_or_else(|| format!("output {i} memo cannot be recovered"))?;
                    payee = Some((recipient, value, memo));
                }
                Ok(())
            };
            inner = run();
            Ok(())
        })
        .map_err(|e: OrchardError<String>| format!("ironwood parse: {e:?}"))?;
    inner?;

    let (to, amount_zat, memo) = payee.ok_or("pczt has no payment output")?;
    let fee_zat = total_in
        .checked_sub(total_out)
        .ok_or("outputs exceed inputs")?;

    Ok(PaymentView {
        to,
        amount_zat,
        fee_zat,
        change_zat,
        memo,
        expiry_height,
        network_branch_id,
        fee_verified,
    })
}

/// Independently recompute the FROST signing message (shielded sighash) from the PCZT
/// bytes — the exact value a correct `SigningPackage.message()` must equal.
///
/// This is the WYSIWYS-to-signature binding: the member approves what [`describe_pczt`]
/// rendered; this proves the `SigningPackage` the coordinator asks us to sign actually
/// commits to THOSE bytes. It re-runs the same value/nullifier/rk bindings the live
/// signing path uses (`signing_session`), so the sighash is only produced for a PCZT
/// whose openings match its commitments for this vault's key.
pub fn sighash_of_pczt(pczt_bytes: &[u8], vault_fvk: &FullViewingKey) -> Result<[u8; 32], String> {
    checked_sighash_of_pczt(pczt_bytes, vault_fvk).map_err(|e| e.to_string())
}

/// The same checks, retaining the fee refusal for device-local signing callers.
pub fn checked_sighash_of_pczt(
    pczt_bytes: &[u8],
    vault_fvk: &FullViewingKey,
) -> Result<[u8; 32], SignerError> {
    use pczt::roles::signer::Signer;
    let parsed = pczt::Pczt::parse(pczt_bytes).map_err(|e| format!("pczt parse: {e:?}"))?;
    let mut err = None;
    let checked = Verifier::new(parsed)
        .with_ironwood::<String, _>(|bundle| {
            let run = || -> Result<(), SignerError> {
                for (i, action) in bundle.actions().iter().enumerate() {
                    action.verify_cv_net().map_err(|e| {
                        SignerError::FeeUnverified(format!("action {i} value commitment: {e:?}"))
                    })?;
                    action
                        .spend()
                        .verify_nullifier(Some(vault_fvk))
                        .map_err(|e| format!("action {i} spend nullifier: {e:?}"))?;
                    action
                        .spend()
                        .verify_rk(Some(vault_fvk))
                        .map_err(|e| format!("action {i} rk: {e:?}"))?;
                }
                Ok(())
            };
            err = run().err();
            Ok(())
        })
        .map_err(|e: OrchardError<String>| format!("ironwood verify: {e:?}"))?
        .finish();
    if let Some(e) = err {
        return Err(e);
    }
    Ok(Signer::new(checked)
        .map_err(|e| format!("sighash: {e:?}"))?
        .shielded_sighash())
}

/// Rebuild the on-chain action and recover the note plaintext (incl. memo) as the sender.
fn recover_memo(action: &orchard::pczt::Action, note: &orchard::note::Note) -> Option<Vec<u8>> {
    let enc = &action.output().encrypted_note();
    let enc_ct: [u8; 580] = enc.enc_ciphertext.as_slice().try_into().ok()?;
    let rebuilt = Action::from_parts(
        Nullifier::from_bytes(&action.spend().nullifier().to_bytes()).into_option()?,
        redpallas::VerificationKey::<SpendAuth>::try_from(<[u8; 32]>::from(action.spend().rk()))
            .ok()?,
        ExtractedNoteCommitment::from_bytes(&action.output().cmx().to_bytes()).into_option()?,
        TransmittedNoteCiphertext {
            epk_bytes: enc.epk_bytes,
            enc_ciphertext: enc_ct,
            out_ciphertext: enc.out_ciphertext,
        },
        ValueCommitment::from_bytes(&action.cv_net().to_bytes()).into_option()?,
        (),
    )
    .ok()?;
    let domain = IronwoodDomain::for_action(&rebuilt);
    let esk = IronwoodDomain::derive_esk(note)?;
    let pk_d = IronwoodDomain::get_pk_d(note);
    let (_, _, memo) = try_output_recovery_with_pkd_esk(&domain, pk_d, esk, &rebuilt)?;
    Some(memo.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{
        alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest,
    };
    use crate::zip2005;
    use orchard::{
        keys::Scope,
        note::{Note, RandomSeed, Rho},
        value::NoteValue,
        NoteVersion,
    };
    use reddsa_frost::frost::redpallas as frost;
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    const SPEND_VALUE: u64 = 625_000_000;
    const AMOUNT: u64 = 40_000_000;

    /// A real serialized regtest PCZT paying `recipient` with `memo`, sent by `fvk`.
    fn sample_pczt_with(
        recipient: orchard::Address,
        memo: &[u8],
        tamper: impl FnOnce(&mut zcash_primitives::transaction::builder::PcztParts<Regtest>),
    ) -> (Vec<u8>, FullViewingKey, u64) {
        let rng = rand_core::OsRng;
        let (_shares, pubkeys) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
                .unwrap();
        let ak: [u8; 32] = pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();

        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(SPEND_VALUE),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();

        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: vec![note],
            recipient,
            amount: Zatoshis::const_from_u64(AMOUNT),
            memo: MemoBytes::from_bytes(memo).unwrap(),
            change: Zatoshis::ZERO,
            target_height: 700,
            expiry_height: 1_152,
        };
        let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
        inputs.change = Zatoshis::const_from_u64(SPEND_VALUE - AMOUNT - fee);

        let alpha = alpha_from_canonical_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        })
        .unwrap();
        let built = build_candidate(
            &Regtest,
            &inputs,
            &[alpha],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let mut parts = built.pczt_parts;
        tamper(&mut parts);
        let pczt = pczt::roles::creator::Creator::build_from_parts(parts).expect("assemble PCZT");
        (pczt.serialize().unwrap(), fvk, SPEND_VALUE - AMOUNT - fee)
    }

    fn sample_pczt(recipient: orchard::Address, memo: &[u8]) -> (Vec<u8>, FullViewingKey, u64) {
        sample_pczt_with(recipient, memo, |_| {})
    }

    fn payee_address() -> orchard::Address {
        let (_, key) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        let ak: [u8; 32] = key.verifying_key().serialize().unwrap().try_into().unwrap();
        zip2005::frost_viewing_key(&ak, &[1u8; 32])
            .unwrap()
            .address_at(7u64, Scope::External)
    }

    #[test]
    fn describe_rejects_unrecoverable_payee_memo() {
        let payee = payee_address();
        let (mut bytes, fvk, _) = sample_pczt(payee, b"memo must be read");
        let parsed = pczt::Pczt::parse(&bytes).unwrap();
        let ciphertext = parsed
            .ironwood()
            .actions()
            .iter()
            .find(|action| action.output().recipient() == &Some(payee.to_raw_address_bytes()))
            .map(|action| action.output().enc_ciphertext())
            .and_then(|ciphertext| match ciphertext {
                pczt::orchard::EncCiphertext::Encrypted(bytes) => Some(bytes),
                _ => None,
            })
            .unwrap();
        let offset = bytes
            .windows(ciphertext.len())
            .position(|window| window == ciphertext.as_slice())
            .unwrap();
        bytes[offset + 100] ^= 1;
        assert!(
            pczt::Pczt::parse(&bytes).is_ok(),
            "tamper remains a serialized PCZT"
        );
        assert!(
            describe_pczt(&bytes, &fvk).is_err(),
            "unreadable memo must not display as empty"
        );
    }

    #[test]
    fn describe_rejects_other_pool_outputs() {
        let recipient = payee_address();
        let (bytes, fvk, _) = sample_pczt_with(recipient, b"pool guard", |parts| {
            parts.transparent = Some(crate::candidate::forbidden_transparent_bundle().unwrap());
        });
        assert!(pczt::Pczt::parse(&bytes).is_ok());
        assert!(
            describe_pczt(&bytes, &fvk).is_err(),
            "transparent output must be rejected"
        );

        let (bytes, fvk, _) = sample_pczt_with(recipient, b"pool guard", |parts| {
            parts.sapling = Some(crate::candidate::forbidden_sapling_bundle().unwrap());
        });
        assert!(pczt::Pczt::parse(&bytes).is_ok());
        assert!(
            describe_pczt(&bytes, &fvk).is_err(),
            "Sapling output must be rejected"
        );
    }

    #[test]
    fn describe_rejects_spend_witness_before_approval() {
        let (bytes, fvk, _) = sample_pczt(payee_address(), b"witness guard");
        let empty = orchard::tree::MerkleHashOrchard::from_bytes(&[0u8; 32]).unwrap();
        let path = orchard::tree::MerklePath::from_parts(0, [empty; 32]);
        let parsed = pczt::Pczt::parse(&bytes).unwrap();
        let mut funded_spend = None;
        Verifier::new(parsed.clone())
            .with_ironwood::<String, _>(|bundle| {
                funded_spend = bundle.actions().iter().position(|action| {
                    action
                        .spend()
                        .value()
                        .is_some_and(|value| value.inner() > 0)
                });
                Ok(())
            })
            .unwrap();
        let with_witness = pczt::roles::updater::Updater::new(parsed)
            .set_ironwood_spend_witnesses([(funded_spend.unwrap(), path)])
            .unwrap()
            .finish()
            .serialize()
            .unwrap();
        assert!(pczt::Pczt::parse(&with_witness).is_ok());
        assert!(
            describe_pczt(&with_witness, &fvk).is_err(),
            "pre-approval witness must be refused"
        );
    }

    #[test]
    fn describe_rejects_anchor_before_approval() {
        let (bytes, fvk, _) = sample_pczt(payee_address(), b"anchor guard");
        let anchored = pczt::roles::updater::Updater::new(pczt::Pczt::parse(&bytes).unwrap())
            .set_ironwood_anchor(orchard::Anchor::empty_tree())
            .unwrap()
            .finish()
            .serialize()
            .unwrap();
        assert!(pczt::Pczt::parse(&anchored).is_ok());
        assert!(
            describe_pczt(&anchored, &fvk).is_err(),
            "pre-approval anchor must be refused"
        );
    }

    #[test]
    fn describe_rejects_unsupported_transaction_version() {
        let (bytes, fvk, _) = sample_pczt_with(payee_address(), b"version guard", |parts| {
            parts.version = zcash_primitives::transaction::TxVersion::V5;
        });
        assert!(pczt::Pczt::parse(&bytes).is_ok());
        let err = describe_pczt(&bytes, &fvk).unwrap_err();
        assert!(err.contains("unsupported transaction version"), "got {err}");
    }

    // describe_pczt reports the TRUE recipient derived from the bytes, defeating a
    // coordinator that "claims" a different payee (ws1-signer §5.4, acceptance test 4).
    #[test]
    fn describe_catches_claimed_vs_real_recipient() {
        // Two distinct recipient addresses; the PCZT really pays `real`.
        let (_, fvk0, _) = sample_pczt(
            {
                let rng = rand_core::OsRng;
                let (_s, pk) = frost::keys::generate_with_dealer(
                    3,
                    2,
                    frost::keys::IdentifierList::Default,
                    rng,
                )
                .unwrap();
                let ak: [u8; 32] = pk.verifying_key().serialize().unwrap().try_into().unwrap();
                zip2005::frost_viewing_key(&ak, &[1u8; 32])
                    .unwrap()
                    .address_at(7u64, Scope::External)
            },
            b"loki wysiwys",
        );
        let real = fvk0.address_at(7u64, Scope::External);
        let claimed = fvk0.address_at(99u64, Scope::External); // what a liar would display

        let (bytes, fvk, change) = sample_pczt(real, b"loki wysiwys");
        let view = describe_pczt(&bytes, &fvk).unwrap();

        // Derived-from-bytes recipient equals the real payee, never the claim.
        assert_eq!(view.to, real.to_raw_address_bytes());
        assert_ne!(view.to, claimed.to_raw_address_bytes());
        assert_eq!(view.amount_zat, AMOUNT);
        assert_eq!(view.change_zat, change);
        assert!(view.fee_zat > 0);
        assert_eq!(view.expiry_height, 1_152);
        // Memo recovered from the ciphertext, padded to 512 bytes.
        assert!(view.memo.starts_with(b"loki wysiwys"));
    }
}
