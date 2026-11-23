//! WS1 signer: the safety-critical component that keeps the FROST share out of the
//! browser (`docs/product/ws1-signer.md`).
//!
//! - [`secure_element`]: at-rest key hierarchy — `SealedShare` sealed by a random DEK,
//!   DEK wrapped by a `SecureElement` KEK (software fallback now; Secure Enclave /
//!   StrongBox implement the same trait later). On-disk share is always ciphertext.
//! - [`nonce`]: crash-safe single-use nonce state machine (persist-before-emit in
//!   round 1; atomic burn+emit in round 2; hard-refuse reuse).
//! - [`wysiwys`]: parse a PCZT into the facts the member approves, derived from the
//!   bytes, and recompute the sighash those bytes bind to.
//! - [`local`]: [`LocalSigner`], the in-app secure-element-backed implementation of the
//!   single [`Signer`] trait below.
//!
//! The [`Signer`] trait here is the ONE seam the coordinator sees (ws1-signer §7). It
//! supersedes the earlier split `SignerApi` (WS1) / `SignerClient` (WS2) traits:
//! `coordinator_boundary` now re-exports this trait instead of defining its own.

pub mod backup;
pub mod coordination;
pub mod device_auth;
pub(crate) mod durable;
pub mod local;
#[cfg(any(test, all(feature = "apple-enclave", target_os = "macos")))]
pub mod native_member;
pub mod nonce;
pub mod recovery;
pub mod repair;
pub mod secure_element;
#[cfg(all(feature = "apple-enclave", target_os = "macos"))]
pub mod secure_element_apple;
pub mod secure_element_webauthn;
pub mod store;
pub mod wysiwys;

/// Browser-only self-test of the OPFS synchronous-store seam: write `bytes` at `path`,
/// then read them back through the same `durable` backend the signer's store uses. The
/// calling Worker must pre-open `path` (`opfsPreopenWrite`) first. Proves the wasm↔OPFS
/// sync-handle path works in a real browser before the full store rides on it.
#[cfg(target_arch = "wasm32")]
pub fn opfs_selftest(path: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().ok_or("path needs a parent directory")?;
    let name = p.file_name().and_then(|n| n.to_str()).ok_or("path needs a file name")?;
    durable::write_durable(dir, name, bytes).map_err(|e| e.to_string())?;
    durable::read_file(dir, name).map_err(|e| e.to_string())
}

/// Split a deterministic OPFS path into `(dir, name)` for the `durable` backend.
#[cfg(target_arch = "wasm32")]
fn opfs_split(path: &str) -> Result<(&std::path::Path, &str), String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().ok_or("path needs a parent directory")?;
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("path needs a file name")?;
    Ok((dir, name))
}

/// Write `bytes` to the deterministic OPFS `path` through the signer's `durable` backend.
/// `create_new` selects write-once (`true`, keeps existing content) vs. replace (`false`).
/// The calling Worker must `opfsPreopenWrite(path)` first. Used by the stateful wasm signer
/// for the pre-vault device files (`identity.sealed`, `profile.json`, `kek.salt`).
#[cfg(target_arch = "wasm32")]
pub fn opfs_put(path: &str, bytes: &[u8], create_new: bool) -> Result<(), String> {
    let (dir, name) = opfs_split(path)?;
    if create_new {
        durable::write_durable(dir, name, bytes)
    } else {
        durable::replace_durable(dir, name, bytes)
    }
    .map_err(|e| e.to_string())
}

/// Read the deterministic OPFS `path`, or `None` if absent. The calling Worker must
/// `opfsPreopenRead(path)` first.
#[cfg(target_arch = "wasm32")]
pub fn opfs_get(path: &str) -> Result<Option<Vec<u8>>, String> {
    let (dir, name) = opfs_split(path)?;
    match durable::read_file(dir, name) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Whether the deterministic OPFS `path` exists with content. The calling Worker must
/// `opfsPreopenRead(path)` first (an un-pre-opened path reads as absent).
#[cfg(target_arch = "wasm32")]
pub fn opfs_exists(path: &str) -> bool {
    match opfs_split(path) {
        Ok((dir, name)) => durable::file_exists(dir, name),
        Err(_) => false,
    }
}

pub use crate::setup_transport::{DkgWire, DkgWireKind};
use crate::signer::wysiwys::PaymentView;
use reddsa_frost::frost::redpallas as frost;

/// Opaque session handle. Carries no secret; it names an unlocked signer connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session(pub [u8; 32]);

/// Which network a coordinator is asking to connect for. Shown to the member on-device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Regtest,
    Testnet,
}

/// Public vault metadata only — names, slots, setup status. No keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRef {
    pub vault_id: [u8; 32],
    pub label: String,
    pub threshold: u16,
    pub members: u16,
    pub ready: bool,
}

/// Public identity of the connected member: its roster id, Ed25519 setup signing key and
/// long-lived X25519 encryption key (`setup_transport::Identity`). All zero for a signer
/// built from a bare share with no setup identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberIdentity {
    pub id: u16,
    pub signing: [u8; 32],
    pub encryption: [u8; 32],
}

/// A session plus the public member identity it is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub session: Session,
    pub member: MemberIdentity,
}

/// One setup message handed to a signer, tagged with the member the coordinator says sent
/// it. The tag is untrusted: the signer checks it against the message's own header and
/// the sender's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgInput {
    pub sender: u16,
    pub bytes: Vec<u8>,
}

impl DkgInput {
    /// A setup message the coordinator relayed, tagged with the sender its header names
    /// (the relay's own sender is the coordinator).
    pub fn from_relay(bytes: Vec<u8>) -> Result<Self, String> {
        let wire = DkgWire::parse(bytes)?;
        Ok(Self {
            sender: wire.sender(),
            bytes: wire.into_bytes(),
        })
    }
}

/// The vault's receive address, released by a ready signer over a session the member
/// approved on-device. Only [`Signer::release_address`] produces it. It carries no viewing
/// key: the coordinator stays viewing-key-less.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasedAddress {
    pub vault_id: [u8; 32],
    pub address: String,
}

/// An unsigned, IO-finalized candidate PCZT built by the proposer signer. Public. Only a
/// signer makes one, so it cannot carry arbitrary bytes onto the transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidatePczt(pub(crate) Vec<u8>);

impl CandidatePczt {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Names a candidate the coordinator wants this member to commit/sign to. Public.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRef {
    pub vault_id: [u8; 32],
    pub payment_id: [u8; 32],
    pub attempt_id: [u8; 32],
}

/// The PUBLIC payment effects the coordinator hands a signer to build an unsigned
/// candidate. No viewing key, no note, no spend authority — just where the money goes,
/// how much, the memo, and the validity window. The signer selects its own notes and
/// uses its own held viewing key to build.
#[derive(Clone)]
pub struct PublicPaymentParams {
    pub recipient: orchard::Address,
    pub amount: zcash_protocol::value::Zatoshis,
    pub memo: zcash_protocol::memo::MemoBytes,
    pub target_height: u32,
    pub expiry_height: u32,
}

/// The ONE keyless signer seam (ws1-signer §7). Every parameter and return type is
/// FROST/PCZT artifacts: session handles, vault metadata, setup messages ([`DkgWire`]:
/// signed round-one bodies, certificates and backup receipts, and recipient-encrypted v2
/// round-two envelopes), signing commitments, signature shares (public partial
/// signatures), and the released receive address.
///
/// There is deliberately NO method that takes or returns a FROST share, a secret nonce,
/// a viewing key, or a spend authorization (invariants #1/#4). No method returns raw
/// bytes: setup messages are [`DkgWire`], which only `setup_transport` constructs.
///
/// On-device decisions (roster code comparison, payment approval, connect approval,
/// backup passphrase) are callbacks supplied when the signer is created, never arguments
/// from the coordinator, so the trait stays object-safe and the coordinator cannot
/// confirm or cancel for the member.
///
/// When you add a method, add its return type to the `PublicArtifact` guard in the tests
/// below by hand.
///
/// Implemented by [`local::LocalSigner`] (in-app, secure-element-wrapped share) today and
/// by a FROST hardware participant later, behind this exact interface (ws1-signer §4
/// hardware path). Local IPC or `frostd` transport (WS3) sit above it.
pub trait Signer {
    type Error;

    /// Show origin + network + challenge on the signer, biometric-unlock, return a
    /// session bound to the member's PUBLIC identity. No secret crosses out.
    fn connect(
        &mut self,
        origin: &str,
        network: Network,
        challenge: &[u8],
    ) -> Result<Connection, Self::Error>;

    /// Public vault metadata the member holds a share for.
    fn list_vaults(&self, session: &Session) -> Result<Vec<VaultRef>, Self::Error>;

    /// Start a vault setup from the coordinator's roster document. The signer refuses a
    /// roster without `"setup_version": 2` before anything else, runs the roster gate
    /// (its own network and its full identity under its member number), then shows a
    /// 24-digit code derived from the roster fingerprint on the device and blocks on the
    /// member's match / no match / cancel decision under a deadline. Only a match saves
    /// the roster. The coordinator never displays, confirms or cancels.
    fn dkg_begin(&mut self, session: &Session, roster: &[u8]) -> Result<VaultRef, Self::Error>;

    /// Advance the confirmed setup with whatever peer messages have arrived, and return
    /// this member's current outgoing messages. Each step saves its state, including the
    /// exact outgoing bytes, before returning them, and a repeated call returns the saved
    /// bytes again. The share is born INSIDE the signer and sealed before the certificate
    /// is released; it is never returned. Before the share exists any mismatch is final:
    /// the setup aborts and its secrets are wiped. After it, a bad message is refused and
    /// the saved setup and share are kept.
    fn dkg_step(
        &mut self,
        session: &Session,
        vault: &VaultRef,
        in_msgs: &[DkgInput],
    ) -> Result<Vec<DkgWire>, Self::Error>;

    /// Run the on-device backup flow once every certificate matched: create the backup,
    /// have the member store it and prove it reloads, then return this member's signed
    /// backup receipt. The backup itself never crosses this seam. The vault is `ready`
    /// only once every member's receipt has arrived through [`Signer::dkg_step`].
    fn backup(&mut self, session: &Session) -> Result<Vec<DkgWire>, Self::Error>;

    /// The vault's receive address, once the vault is ready, over a session the member
    /// approved on-device at [`Signer::connect`].
    fn release_address(&mut self, session: &Session) -> Result<ReleasedAddress, Self::Error>;

    /// Round 1: after the member's on-device "prepare" ack, return PUBLIC commitments.
    /// The secret nonce is persisted internally (crash-safe) and never returned.
    fn sign_commit(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, Self::Error>;

    /// Build the UNSIGNED candidate PCZT for this payment, under the coordinator-supplied
    /// rerandomizers `alphas` (canonical 32-byte encodings, derived from the round-1
    /// commitments), one per spent note. The signer uses its OWN held viewing key and its OWN
    /// notes; the coordinator supplies only the public effects (`params`) and `alphas`. Returns
    /// the serialized, IO-finalized candidate bytes that round 2 then renders and signs. The
    /// coordinator never sees the viewing key or chooses the notes.
    fn build_candidate(
        &self,
        session: &Session,
        cand: &CandidateRef,
        params: &PublicPaymentParams,
        alphas: &[[u8; 32]],
    ) -> Result<CandidatePczt, Self::Error>;

    /// Round 2 (rerandomized): BLOCKS on in-signer parse + render + approval + sighash
    /// binding. The signer independently parses `pczt`, checks its payment effects against
    /// `params`, renders it (WYSIWYS), requires an approval decision, and VERIFIES that
    /// `pkg.message()` equals the sighash recomputed from the rendered bytes — refusing
    /// BEFORE touching the nonce/share if they differ. `params` comes from the coordinator;
    /// the approval decision must use the independently derived render.
    /// Only then is the PUBLIC partial signature produced under single-use nonce rules.
    /// `randomizer` is the 32-byte rerandomization seed (the coordinator's public per-pair
    /// seed; the randomizer scalar is regenerated from it + the commitments).
    fn sign_approve(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
        params: &PublicPaymentParams,
        pczt: &[u8],
        pkg: &frost::SigningPackage,
        randomizer: &[u8],
    ) -> Result<frost::round2::SignatureShare, Self::Error>;

    /// What the member saw on-device for this candidate (for the coordinator's UI/audit).
    /// Public facts only, derived from the PCZT.
    fn rendered_payment(
        &self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<PaymentView, Self::Error>;

    fn disconnect(&mut self, session: Session) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    //! Type guard for the named return types of the signer seam.
    //!
    //! Every `Signer` success type is asserted to implement `PublicArtifact`, a marker
    //! deliberately NOT implemented for any secret type, nor for raw bytes. Setup
    //! messages cross as `DkgWire`, which only `setup_transport` constructs from a valid
    //! setup-message frame.

    use super::*;

    /// Marker for types that are safe to cross the coordinator boundary. Implemented
    /// ONLY for public artifacts; never for shares, nonces, or viewing keys.
    trait PublicArtifact {}

    impl PublicArtifact for Connection {}
    impl PublicArtifact for Session {}
    impl PublicArtifact for MemberIdentity {}
    impl PublicArtifact for PaymentView {}
    impl PublicArtifact for frost::round1::SigningCommitments {}
    impl PublicArtifact for frost::round2::SignatureShare {}
    impl<T: PublicArtifact> PublicArtifact for Vec<T> {}
    impl PublicArtifact for VaultRef {}
    impl PublicArtifact for DkgWire {}
    impl PublicArtifact for ReleasedAddress {}
    impl PublicArtifact for CandidatePczt {}

    fn assert_public<T: PublicArtifact>() {}

    #[test]
    fn known_signer_return_types_are_public_artifacts() {
        // Each line pins one `Signer` method's current success type. Opaque bytes need
        // separate content checks; this cannot inspect newly added methods automatically.
        assert_public::<Connection>(); // connect
        assert_public::<Vec<VaultRef>>(); // list_vaults
        assert_public::<VaultRef>(); // dkg_begin
        assert_public::<Vec<DkgWire>>(); // dkg_step
        assert_public::<Vec<DkgWire>>(); // backup
        assert_public::<ReleasedAddress>(); // release_address
        assert_public::<CandidatePczt>(); // build_candidate
        assert_public::<frost::round1::SigningCommitments>(); // sign_commit
        assert_public::<frost::round2::SignatureShare>(); // sign_approve
        assert_public::<PaymentView>(); // rendered_payment
                                        // disconnect returns ()

        // Negative guard, stated in the type system: the secret types are NOT artifacts.
        // Uncommenting any line below must fail to compile:
        //   assert_public::<frost::keys::KeyPackage>();
        //   assert_public::<frost::keys::SigningShare>();
        //   assert_public::<frost::round1::SigningNonces>();
        //   assert_public::<orchard::keys::FullViewingKey>();
        //   assert_public::<Vec<u8>>();
    }
}
