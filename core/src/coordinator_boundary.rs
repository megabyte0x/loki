//! Keyless coordinator boundary (WS2 §4, architecture invariant #1).
//!
//! The coordinator proposes transactions, scans the chain, drives the FROST rounds,
//! aggregates partials, and broadcasts. It handles the vault address, PCZTs the signer
//! built, public protocol messages, and the signer's DKG wires (round two only as v2
//! envelopes under one-setup fresh keys it cannot open). It must never read a FROST
//! share, a signing nonce, or a spend authorization. Its code holds no viewing key, but
//! the candidate PCZTs it relays carry the vault's full viewing key in their spends.
//!
//! There is exactly ONE signer seam in this codebase — [`crate::signer::Signer`] — and the
//! coordinator talks to members only through it. This module used to define a separate
//! `SignerClient` trait for the coordinator's view; that duplicate is gone. The seam is
//! re-exported here so coordinator code keeps a single import path, and the keyless rule is
//! checked in two narrow ways (acceptance §b):
//!   * a source deny-list test (`coordinator_source_links_no_secret_type`) fails if this
//!     file ever references a share/nonce/spend-key type, and
//!   * [`assert_keyless`] queries only public vault metadata at start-up.

/// The one signer seam. The coordinator sees members only as `dyn Signer`; every method on
/// it takes and returns FROST/PCZT artifacts, DKG wires and the released address (see
/// `signer::Signer`). No share, nonce, or spend-key type is named here.
pub use crate::signer::{CandidateRef, Connection, Network, Session, Signer, VaultRef};

/// Checks that the coordinator can query public vault metadata through the signer seam.
///
/// This does not inspect opaque protocol bytes or prove that the coordinator process
/// cannot access secret-bearing modules through another path.
pub fn assert_keyless<E>(signers: &[&dyn Signer<Error = E>], session: &Session) {
    for s in signers {
        // Only the public surface is reachable: vault metadata, never a secret.
        let _public: Result<Vec<VaultRef>, E> = s.list_vaults(session);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Deny-list / module-dependency assertion (acceptance §b).
    ///
    /// Fails if the coordinator source ever references a share, nonce, or spend-key type.
    /// This is the static half of the keyless proof: the coordinator links none of the
    /// share-holding code. It greps the real source after stripping `//` lines, so the
    /// doc-comments above (which must NAME the banned concepts to explain the ban) do not
    /// trip it — only live code counts.
    #[test]
    fn coordinator_source_links_no_secret_type() {
        let src = std::fs::read_to_string(Path::new(file!()))
            .or_else(|_| std::fs::read_to_string("core/src/coordinator_boundary.rs"))
            .or_else(|_| std::fs::read_to_string("src/coordinator_boundary.rs"))
            .expect("read coordinator_boundary.rs");
        // Scan only the shipped boundary — the production code above the test module.
        let shipped = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = shipped
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        // Types/paths that would mean a secret can be read inside the coordinator.
        let forbidden = [
            "KeyPackage",          // the FROST share
            "SigningNonces",       // the single-use signing nonce
            "signing_share",       // raw share scalar accessor
            "SpendingKey",         // the orchard spend authorization
            "SpendAuthorizingKey", // ask / spend-auth secret
            "member_state",        // module that loads the sealed share
            "MemberState",         // struct bundling the share
            "signing_session",     // module that holds nonces and the share
            "read_sealed",         // sealed-store secret reader
            "SecretKey",           // any secret key import
            "SealedShare",         // the sealed share blob type
            "LocalSigner",         // the share-holding implementation
        ];
        for needle in forbidden {
            assert!(
                !code.contains(needle),
                "coordinator must not link secret type `{needle}` (keyless invariant #1)"
            );
        }
    }

    /// Viewing-key-less coordinator path (vk-less rework acceptance).
    ///
    /// The coordinator drive loop (`signer::coordination`) must build a candidate by ASKING
    /// a signer, never by holding a viewing key or selecting a note. So its shipped code must
    /// name no `FullViewingKey` / viewing-key type and must not call the note-building
    /// surface directly. Tests (below `#[cfg(test)]`) legitimately know the fvk to assert on
    /// the result, so they are stripped first — only live coordinator code counts.
    #[test]
    fn coordinator_drive_loop_is_viewing_key_less() {
        // `signer::coordination` now lives in the extracted `loki-signer-core` crate.
        let src = std::fs::read_to_string(Path::new(
            "loki-signer-core/src/signer/coordination.rs",
        ))
        .or_else(|_| {
            std::fs::read_to_string("core/loki-signer-core/src/signer/coordination.rs")
        })
        .or_else(|_| {
            std::fs::read_to_string(
                Path::new(file!())
                    .parent()
                    .unwrap()
                    .join("../loki-signer-core/src/signer/coordination.rs"),
            )
        })
        .expect("read coordination.rs");
        let shipped = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = shipped
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        // A viewing key or direct note-build on the coordinator path would mean the
        // coordinator is back to holding the fvk and selecting notes.
        let forbidden = [
            "FullViewingKey",   // the vault viewing key — must live only in the signer
            "IncomingViewingKey",
            "OutgoingViewingKey",
            "CandidateInputs",  // coordinator never assembles builder inputs itself
            "quote_fee",        // nor quotes a fee from a note it does not hold
            "intent.note",      // no note on the intent
            "vault_fvk",        // no viewing-key field anywhere on the coordinator path
        ];
        for needle in forbidden {
            assert!(
                !code.contains(needle),
                "coordinator drive loop must be viewing-key-less: found `{needle}`"
            );
        }
    }

    /// The runtime keyless assertion compiles and runs over an empty signer set: the public
    /// surface is the only thing reachable through the seam.
    #[test]
    fn assert_keyless_accepts_public_only_surface() {
        use crate::signer::{Session, VaultRef};
        // A trivial `Signer` whose Error is `()` is enough to pin the public-only surface.
        struct Dummy;
        impl crate::signer::Signer for Dummy {
            type Error = ();
            fn connect(
                &mut self,
                _: &str,
                _: crate::signer::Network,
                _: &[u8],
            ) -> Result<crate::signer::Connection, ()> {
                Err(())
            }
            fn list_vaults(&self, _: &Session) -> Result<Vec<VaultRef>, ()> {
                Ok(vec![])
            }
            fn dkg_begin(&mut self, _: &Session, _: &[u8]) -> Result<VaultRef, ()> {
                Err(())
            }
            fn dkg_step(
                &mut self,
                _: &Session,
                _: &VaultRef,
                _: &[crate::signer::DkgInput],
            ) -> Result<Vec<crate::signer::DkgWire>, ()> {
                Ok(vec![])
            }
            fn backup(&mut self, _: &Session) -> Result<Vec<crate::signer::DkgWire>, ()> {
                Err(())
            }
            fn release_address(
                &mut self,
                _: &Session,
            ) -> Result<crate::signer::ReleasedAddress, ()> {
                Err(())
            }
            fn build_candidate(
                &self,
                _: &Session,
                _: &crate::signer::CandidateRef,
                _: &crate::signer::PublicPaymentParams,
                _: &[[u8; 32]],
            ) -> Result<crate::signer::CandidatePczt, ()> {
                Err(())
            }
            fn sign_commit(
                &mut self,
                _: &Session,
                _: &crate::signer::CandidateRef,
            ) -> Result<reddsa_frost::frost::redpallas::round1::SigningCommitments, ()> {
                Err(())
            }
            fn sign_approve(
                &mut self,
                _: &Session,
                _: &crate::signer::CandidateRef,
                _: &crate::signer::PublicPaymentParams,
                _: &[u8],
                _: &reddsa_frost::frost::redpallas::SigningPackage,
                _: &[u8],
            ) -> Result<reddsa_frost::frost::redpallas::round2::SignatureShare, ()> {
                Err(())
            }
            fn rendered_payment(
                &self,
                _: &Session,
                _: &crate::signer::CandidateRef,
            ) -> Result<crate::signer::wysiwys::PaymentView, ()> {
                Err(())
            }
            fn disconnect(&mut self, _: Session) -> Result<(), ()> {
                Ok(())
            }
        }
        let d = Dummy;
        super::assert_keyless(&[&d], &Session([0u8; 32]));
    }
}
