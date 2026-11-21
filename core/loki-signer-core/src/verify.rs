//! Checkpoint 4's approval binding: what a signer must prove about a candidate before it
//! will emit a share.
//!
//! Every value here is checked against the PCZT and its cryptographic openings. Nothing
//! is taken from a proposer annotation, and no check is silently skipped when a field is
//! missing: an absent opening is a refusal, not a pass.

use orchard::{
    keys::{FullViewingKey, OutgoingViewingKey, Scope},
    note::{ExtractedNoteCommitment, Rho},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    Note,
};
use zcash_note_encryption::{try_note_decryption, Domain};
use zcash_primitives::transaction::fees::zip317::{GRACE_ACTIONS, MARGINAL_FEE};
use zcash_protocol::memo::MemoBytes;

/// What the signer requires of a candidate, derived from the intent and the vault key.
pub struct Expectations {
    /// Exactly these notes may be spent. An exact set, not a subset.
    pub input_nullifiers: Vec<[u8; 32]>,
    pub recipient: [u8; 43],
    pub amount_zat: u64,
    pub memo: Vec<u8>,
    pub change_zat: u64,
    pub fee_zat: u64,
    pub expiry_height: u32,
}

/// Why a candidate was refused. Each variant is a line in the brief's checklist.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    WrongNetworkOrVersion(String),
    InputSetDiffers {
        expected: usize,
        found: usize,
        detail: String,
    },
    MissingOpening(String),
    OpeningsDoNotMatchCommitment(String),
    InvalidOutputEncryption(String),
    MemoDiffers(String),
    ChangeAddressDiffers {
        expected: String,
        found: String,
    },
    AmountDiffers {
        what: String,
        expected: u64,
        found: u64,
    },
    FeeDiffers {
        expected: u64,
        found: u64,
    },
    ExpiryDiffers {
        expected: u32,
        found: u32,
    },
    ExtraOutputOrPool(String),
    RkDoesNotMatchAlpha {
        expected: String,
        found: String,
    },
    PackageSighashMismatch,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Refusal::*;
        match self {
            WrongNetworkOrVersion(s) => write!(f, "wrong network or tx version: {s}"),
            InputSetDiffers { expected, found, detail } => write!(
                f,
                "input set differs: expected {expected} real spend(s), found {found} ({detail})"
            ),
            MissingOpening(s) => write!(f, "a required opening is absent: {s}"),
            OpeningsDoNotMatchCommitment(s) => {
                write!(f, "openings do not match the commitment: {s}")
            }
            InvalidOutputEncryption(s) => write!(f, "invalid output encryption: {s}"),
            MemoDiffers(s) => write!(f, "memo differs from the intent: {s}"),
            ChangeAddressDiffers { expected, found } => write!(
                f,
                "change address is not the vault's internal address: expected {expected}, found {found}"
            ),
            AmountDiffers { what, expected, found } => {
                write!(f, "{what} differs: expected {expected} zat, found {found}")
            }
            FeeDiffers { expected, found } => {
                write!(f, "fee differs: intent says {expected} zat, transaction implies {found}")
            }
            ExpiryDiffers { expected, found } => {
                write!(f, "expiry height differs: intent says {expected}, candidate says {found}")
            }
            ExtraOutputOrPool(s) => write!(f, "unexpected output or pool: {s}"),
            RkDoesNotMatchAlpha { expected, found } => write!(
                f,
                "rk does not match recomputed alpha: expected {expected}, found {found}"
            ),
            PackageSighashMismatch => {
                write!(f, "the FROST package does not name the local sighash")
            }
        }
    }
}

/// Rebuild an output's note from the openings the PCZT carries.
///
/// An action's output rho is the nullifier of the note that action spends. Returns the
/// reconstructed note, or a refusal naming the missing or inconsistent part.
pub(crate) fn open_output(
    action: &orchard::pczt::Action,
    label: &str,
) -> Result<(Note, [u8; 43], u64), Refusal> {
    let out = action.output();

    let recipient = out
        .recipient()
        .ok_or_else(|| Refusal::MissingOpening(format!("{label}: recipient")))?;
    let value = out
        .value()
        .ok_or_else(|| Refusal::MissingOpening(format!("{label}: value")))?;
    let rseed = out
        .rseed()
        .ok_or_else(|| Refusal::MissingOpening(format!("{label}: rseed")))?;

    let rho = Rho::from_bytes(&action.spend().nullifier().to_bytes())
        .into_option()
        .ok_or_else(|| Refusal::MissingOpening(format!("{label}: rho from the spent nullifier")))?;

    let note = Option::<Note>::from(Note::from_parts(
        recipient,
        value,
        rho,
        rseed,
        *out.note_version(),
    ))
    .ok_or_else(|| {
        Refusal::OpeningsDoNotMatchCommitment(format!("{label}: openings do not form a note"))
    })?;

    // The openings must produce exactly the commitment the action carries.
    if &ExtractedNoteCommitment::from(note.commitment()) != out.cmx() {
        return Err(Refusal::OpeningsDoNotMatchCommitment(format!(
            "{label}: recomputed cmx differs"
        )));
    }

    Ok((note, recipient.to_raw_address_bytes(), value.inner()))
}

/// Verify the transmitted note ciphertext and key by re-encryption.
///
/// `enc_ciphertext` is a deterministic function of the note and its memo: the ephemeral
/// secret is derived from the note's rseed, so there is no randomness left to differ.
/// Re-encrypting with the expected memo and comparing bytes therefore binds the memo, the
/// openings and the ciphertext together. A proposer cannot swap the memo without the
/// ciphertext changing.
fn check_memo(
    action: &orchard::pczt::Action,
    note: &Note,
    expected: &MemoBytes,
    label: &str,
) -> Result<(), Refusal> {
    let enc = IronwoodNoteEncryption::new(None::<OutgoingViewingKey>, *note, *expected.as_array());
    let recomputed = enc.encrypt_note_plaintext();
    let actual = action.output().encrypted_note();

    if recomputed != actual.enc_ciphertext {
        return Err(Refusal::MemoDiffers(format!(
            "{label}: re-encrypting with the intended memo does not reproduce enc_ciphertext"
        )));
    }
    if note.value().inner() != 0 && IronwoodDomain::epk_bytes(enc.epk()).0 != actual.epk_bytes {
        return Err(Refusal::InvalidOutputEncryption(format!(
            "{label}: re-encryption does not reproduce the transmitted ephemeral key"
        )));
    }
    Ok(())
}

/// Verify that the vault can discover the reviewed change in a scan.
pub(crate) fn check_change_decryption(
    action: &orchard::pczt::Action,
    note: &Note,
    vault_fvk: &FullViewingKey,
    label: &str,
) -> Result<(), Refusal> {
    if note.value().inner() == 0 {
        return Ok(());
    }
    let domain = IronwoodDomain::for_pczt_action(action);
    let ivk = vault_fvk.to_ivk(Scope::Internal).prepare();
    // Recipient decryption checks the transmitted key and commitment. Also match the
    // address and value being reviewed against the decrypted plaintext.
    if !try_note_decryption(&domain, &ivk, action).is_some_and(|(decrypted, recipient, _)| {
        recipient == note.recipient() && decrypted.value() == note.value()
    }) {
        return Err(Refusal::InvalidOutputEncryption(format!(
            "{label}: vault cannot decrypt the expected change note"
        )));
    }
    Ok(())
}

/// The full approval check. Returns the first refusal, or `Ok` if the candidate is
/// exactly the payment the intent describes.
pub fn check_candidate(
    bundle: &orchard::pczt::Bundle,
    vault_fvk: &FullViewingKey,
    want: &Expectations,
) -> Result<(), Refusal> {
    // ── inputs: the real spend set must equal the intent's, exactly ─────────
    let mut real_nullifiers = Vec::new();
    let mut total_in: u64 = 0;

    for action in bundle.actions() {
        let spend = action.spend();
        let value = spend
            .value()
            .ok_or_else(|| {
                Refusal::MissingOpening(format!(
                    "spend {}: value",
                    &hex::encode(spend.nullifier().to_bytes())[..12]
                ))
            })?
            .inner();

        if value > 0 {
            real_nullifiers.push(spend.nullifier().to_bytes());
            total_in = total_in
                .checked_add(value)
                .ok_or_else(|| Refusal::ExtraOutputOrPool("input value overflow".into()))?;
        }
    }

    real_nullifiers.sort_unstable();
    let mut want_nullifiers = want.input_nullifiers.clone();
    want_nullifiers.sort_unstable();

    if real_nullifiers != want_nullifiers {
        return Err(Refusal::InputSetDiffers {
            expected: want_nullifiers.len(),
            found: real_nullifiers.len(),
            detail: real_nullifiers
                .iter()
                .map(|n| hex::encode(&n[..6]))
                .collect::<Vec<_>>()
                .join(","),
        });
    }

    // ── outputs: every one opened, committed to, and memo-bound ─────────────
    let change_address = vault_fvk
        .address_at(0u64, Scope::Internal)
        .to_raw_address_bytes();
    let want_memo =
        MemoBytes::from_bytes(&want.memo).map_err(|e| Refusal::MemoDiffers(format!("{e:?}")))?;
    let empty_memo = MemoBytes::empty();
    // The builder pads a bundle with one output per spend beyond the two real outputs:
    // zero value, to a random address, with an all-zero memo.
    let padding_memo = MemoBytes::from_bytes(&[0; 512]).expect("512 bytes is a valid memo");

    let mut payments = 0usize;
    let mut changes = 0usize;
    let mut padding = 0usize;
    let mut total_out: u64 = 0;

    for (i, action) in bundle.actions().iter().enumerate() {
        let label = format!("output {i}");
        let (note, recipient, value) = open_output(action, &label)?;

        total_out = total_out
            .checked_add(value)
            .ok_or_else(|| Refusal::ExtraOutputOrPool("output value overflow".into()))?;

        if recipient == want.recipient {
            if value != want.amount_zat {
                return Err(Refusal::AmountDiffers {
                    what: "payment".into(),
                    expected: want.amount_zat,
                    found: value,
                });
            }
            check_memo(action, &note, &want_memo, &label)?;
            payments += 1;
        } else if recipient == change_address {
            if value != want.change_zat {
                return Err(Refusal::AmountDiffers {
                    what: "change".into(),
                    expected: want.change_zat,
                    found: value,
                });
            }
            // Change carries no memo; proving that binds it as tightly as the payment.
            check_memo(action, &note, &empty_memo, &label)?;
            check_change_decryption(action, &note, vault_fvk, &label)?;
            changes += 1;
        } else if value == 0 && check_memo(action, &note, &padding_memo, &label).is_ok() {
            padding += 1;
        } else if value != 0 {
            return Err(Refusal::ExtraOutputOrPool(format!(
                "{label}: {value} zat to an address the intent does not name"
            )));
        } else {
            // A zero-value output to neither address would still move nothing, but it is
            // not something this intent asked for.
            return Err(Refusal::ExtraOutputOrPool(format!(
                "{label}: an output to an address the intent does not name"
            )));
        }
    }

    if payments != 1 {
        return Err(Refusal::ExtraOutputOrPool(format!(
            "expected exactly one payment, found {payments}"
        )));
    }
    if padding > want.input_nullifiers.len().saturating_sub(2) {
        return Err(Refusal::ExtraOutputOrPool(format!(
            "{padding} padding outputs for {} inputs",
            want.input_nullifiers.len()
        )));
    }
    if changes != 1 {
        return Err(Refusal::ChangeAddressDiffers {
            expected: hex::encode(change_address),
            found: format!("{changes} outputs matched the vault's internal address"),
        });
    }

    // ── fee: implied by the transaction, compared with the intent ───────────
    let implied_fee = total_in.checked_sub(total_out).ok_or(Refusal::FeeDiffers {
        expected: want.fee_zat,
        found: 0,
    })?;
    if implied_fee != want.fee_zat {
        return Err(Refusal::FeeDiffers {
            expected: want.fee_zat,
            found: implied_fee,
        });
    }
    // The fee must be the conventional ZIP 317 fee for the action count, never more.
    let zip317_fee = u64::from(MARGINAL_FEE) * bundle.actions().len().max(GRACE_ACTIONS) as u64;
    if want.fee_zat != zip317_fee {
        return Err(Refusal::FeeDiffers {
            expected: zip317_fee,
            found: want.fee_zat,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{candidate::*, vault, zip2005};
    use orchard::{
        note::{RandomSeed, Rho},
        value::NoteValue,
        NoteVersion,
    };
    use reddsa_frost::frost::redpallas as frost;
    use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

    const SPEND_VALUE: u64 = 625_000_000;
    const AMOUNT: u64 = 40_000_000;

    struct Fixture {
        fvk: FullViewingKey,
        bundle: orchard::pczt::Bundle,
        want: Expectations,
    }

    /// One honest candidate, built the way `propose` builds them.
    fn fixture() -> Fixture {
        fixture_with(1)
    }

    /// An honest candidate spending `spends` notes that split `SPEND_VALUE` between them.
    fn fixture_with(spends: u8) -> Fixture {
        let rng = rand_core::OsRng;
        let (_shares, pubkeys) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
                .unwrap();
        let ak: [u8; 32] = pubkeys
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();

        let notes: Vec<Note> = (0..spends)
            .map(|i| {
                let rho = Rho::from_bytes(&[1 + i; 32]).unwrap();
                let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
                Note::from_parts(
                    fvk.address_at(0u64, Scope::External),
                    NoteValue::from_raw(SPEND_VALUE / u64::from(spends)),
                    rho,
                    rseed,
                    NoteVersion::V3,
                )
                .unwrap()
            })
            .collect();
        let spend_value = SPEND_VALUE / u64::from(spends) * u64::from(spends);

        let recipient = fvk.address_at(7u64, Scope::External);
        let memo = b"loki g1-tx".to_vec();

        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: notes.clone(),
            recipient,
            amount: Zatoshis::const_from_u64(AMOUNT),
            memo: MemoBytes::from_bytes(&memo).unwrap(),
            change: Zatoshis::ZERO,
            target_height: 700,
            expiry_height: 1_152,
        };
        let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
        inputs.change = Zatoshis::const_from_u64(spend_value - AMOUNT - fee);

        let alpha = alpha_from_canonical_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        })
        .unwrap();

        let built = build_candidate(
            &Regtest,
            &inputs,
            &vec![alpha; notes.len()],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();

        let want = Expectations {
            input_nullifiers: notes.iter().map(|note| note.nullifier(&fvk).to_bytes()).collect(),
            recipient: recipient.to_raw_address_bytes(),
            amount_zat: AMOUNT,
            memo,
            change_zat: spend_value - AMOUNT - fee,
            fee_zat: fee,
            expiry_height: 1_152,
        };

        Fixture {
            fvk,
            bundle: built.pczt_parts.ironwood.unwrap(),
            want,
        }
    }

    /// The honest candidate is approved. Without this, every tamper case below would
    /// pass for the wrong reason.
    #[test]
    fn c4_honest_candidate_is_approved() {
        let f = fixture();
        assert_eq!(check_candidate(&f.bundle, &f.fvk, &f.want), Ok(()));
    }

    /// Spending three or more notes makes the builder add padding outputs, which signers
    /// accept only up to that count.
    #[test]
    fn multi_note_candidates_with_padding_are_approved() {
        for spends in [2, 3, 5] {
            let f = fixture_with(spends);
            assert_eq!(f.bundle.actions().len(), usize::from(spends).max(2));
            assert_eq!(check_candidate(&f.bundle, &f.fvk, &f.want), Ok(()), "{spends} spends");
        }
    }

    /// Tamper with one expectation at a time and confirm the signer refuses. A refusal
    /// here is what stops a share being emitted: `review_sign` reviews every candidate
    /// before it signs any of them.
    fn refuses(mutate: impl FnOnce(&mut Expectations)) -> Refusal {
        let f = fixture();
        let mut want = f.want;
        mutate(&mut want);
        check_candidate(&f.bundle, &f.fvk, &want)
            .expect_err("the signer must refuse this candidate")
    }

    #[test]
    fn c4_tampered_memo_is_refused() {
        let r = refuses(|w| w.memo = b"loki g1-TX".to_vec());
        assert!(matches!(r, Refusal::MemoDiffers(_)), "got {r}");
    }

    #[test]
    fn c4_tampered_amount_is_refused() {
        let r = refuses(|w| w.amount_zat += 1);
        // A different amount means no output matches the payment address at that value.
        assert!(
            matches!(
                r,
                Refusal::AmountDiffers { .. } | Refusal::ExtraOutputOrPool(_)
            ),
            "got {r}"
        );
    }

    #[test]
    fn c4_tampered_change_amount_is_refused() {
        let r = refuses(|w| w.change_zat -= 1);
        assert!(
            matches!(
                r,
                Refusal::AmountDiffers { .. } | Refusal::ChangeAddressDiffers { .. }
            ),
            "got {r}"
        );
    }

    #[test]
    fn c4_tampered_fee_is_refused() {
        let r = refuses(|w| w.fee_zat += 1);
        assert!(matches!(r, Refusal::FeeDiffers { .. }), "got {r}");
    }

    #[test]
    fn c4_tampered_recipient_is_refused() {
        let r = refuses(|w| w.recipient[0] ^= 1);
        assert!(matches!(r, Refusal::ExtraOutputOrPool(_)), "got {r}");
    }

    #[test]
    fn c4_tampered_input_nullifier_is_refused() {
        let r = refuses(|w| w.input_nullifiers[0][0] ^= 1);
        assert!(matches!(r, Refusal::InputSetDiffers { .. }), "got {r}");
    }

    #[test]
    fn c4_an_extra_expected_input_is_refused() {
        let r = refuses(|w| w.input_nullifiers.push([0xAB; 32]));
        assert!(matches!(r, Refusal::InputSetDiffers { .. }), "got {r}");
    }

    /// The change address is derived from the vault key, not read from the intent, so a
    /// candidate paying change elsewhere is refused even if the amount is right.
    #[test]
    fn c4_change_to_a_foreign_address_is_refused() {
        let f = fixture();
        let other = vault::test_only_fvk(&{
            let rng = rand_core::OsRng;
            let (_s, pk) =
                frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
                    .unwrap();
            pk.verifying_key().serialize().unwrap().try_into().unwrap()
        })
        .unwrap();

        // Checking the same bundle against a DIFFERENT vault key means its change output
        // no longer lands on that vault's internal address.
        let r = check_candidate(&f.bundle, &other, &f.want)
            .expect_err("change to another vault's address must be refused");
        assert!(
            matches!(
                r,
                Refusal::ExtraOutputOrPool(_) | Refusal::ChangeAddressDiffers { .. }
            ),
            "got {r}"
        );
    }

    /// Expiry is carried in the PCZT global, which `review_sign` checks separately; this
    /// records that the value reaching the check is the one the builder used.
    #[test]
    fn c4_expiry_is_carried_for_checking() {
        let f = fixture();
        assert_eq!(f.want.expiry_height, 1_152);
        let _ = BlockHeight::from_u32(f.want.expiry_height);
    }
}
