//! [`LocalSigner`]: the in-app implementation of the single [`Signer`] seam.
//!
//! It holds exactly one member's FROST share for one vault, sealed at rest by the
//! [`SecureElement`] (software backend for now; Secure Enclave / StrongBox implement the
//! same trait later). The share is unsealed into memory only for the two FROST rounds and
//! the plaintext is held in a `Zeroizing` buffer.
//!
//! A signer created with [`LocalSigner::create`] owns a data directory
//! ([`crate::signer::store`]) and runs the vault setup itself: [`Signer::dkg_begin`] shows
//! the roster code on the device, and [`Signer::dkg_step`] drives the shared v2 DKG core
//! ([`crate::dkg_core`]), saving every step before it releases any message. Round-two
//! shares only ever leave as v2 envelopes between one-setup fresh keys, so nobody who
//! carries the messages (coordinator, frostd, logs) can rebuild the vault key.
//!
//! The safety-critical signing method is [`LocalSigner::sign_approve`], which binds the
//! WYSIWYS render to the exact bytes being signed (invariant #3 / threat §5.4):
//!   1. independently parse the PCZT and render it ([`wysiwys::describe_pczt`]),
//!   2. require an explicit approval decision over that render,
//!   3. recompute the sighash from the SAME bytes ([`wysiwys::sighash_of_pczt`]) and
//!      REFUSE unless `pkg.message()` equals it — BEFORE the nonce/share is touched,
//!   4. only then produce the rerandomized round-2 share under the single-use nonce rules.

use crate::dkg_core::{DkgCore, DkgPhase, DkgState};
use crate::member_state::{Roster, ValidatedRoster};
use crate::setup_transport::{DkgWire, DkgWireKind, Identity, PublicIdentity};
use crate::signing_session::{MessageKind, NonceWitness, SessionContext};
use crate::signer::backup::{self, BackupArtifact, BackupMaterial};
use crate::signer::nonce::NonceStore;
use crate::signer::secure_element::{SealedShare, SecureElement};
use crate::signer::store::{FileKind, SignerStore};
use crate::signer::wysiwys::{self, PaymentView};
use crate::signer::{
    CandidatePczt, CandidateRef, Connection, DkgInput, MemberIdentity, Network, ReleasedAddress,
    Session, Signer, VaultRef,
};
use crate::zip2005;
use orchard::keys::FullViewingKey;
use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
// std::time::Instant has no time source on wasm32-unknown-unknown; web-time maps it onto
// performance.now() with the same API, so the roster-deadline logic is unchanged.
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;
use zeroize::Zeroizing;

/// The member's on-device approval decision for a rendered payment. In a real signer this
/// is a full-screen confirmation + biometric prompt; here it is a policy callback so the
/// tests can drive approve/refuse deterministically (ws1-signer §7: "a callback/policy is
/// fine for tests").
pub type ApprovalPolicy = Box<dyn FnMut(&ApprovalRequest<'_>) -> bool + Send>;

/// What the member is asked to approve: the independently rendered payment, the candidate it
/// belongs to, and the sighash recomputed from the same PCZT bytes — so consent binds to the
/// exact thing that will be signed, not just the human-readable view.
pub struct ApprovalRequest<'a> {
    pub candidate: &'a CandidateRef,
    pub sighash: [u8; 32],
    pub view: &'a PaymentView,
}

/// The member's on-device decision on a coordinator connection, shown with the
/// coordinator's origin and network. Only an approved session may receive the address.
pub type ConnectApproval = Box<dyn FnMut(&str, Network) -> bool + Send>;

/// What the member answered after comparing the roster code with the other members.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterDecision {
    Match,
    NoMatch,
    Cancelled,
}

/// The on-device roster comparison: shows the 24-digit code and returns the member's
/// decision. The signer enforces [`DevicePrompts::roster_deadline`] around it.
pub type RosterConfirmation = Box<dyn FnMut(&str) -> RosterDecision + Send>;

/// The member's backup storage, driven on the device during [`Signer::backup`].
pub trait BackupDevice: Send {
    /// Ask the member for the backup passphrase. `None` means the member cancelled.
    fn passphrase(&mut self) -> Option<Zeroizing<String>>;
    /// Store the sealed backup where the member keeps it.
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String>;
    /// Load the stored backup back, to prove it reloads.
    fn load(&mut self) -> Result<BackupArtifact, String>;
}

/// The on-device decisions a setup-capable signer needs, supplied at construction so the
/// coordinator can never answer for the member.
pub struct DevicePrompts {
    pub connect: ConnectApproval,
    pub roster: RosterConfirmation,
    pub roster_deadline: Duration,
    pub backup: Box<dyn BackupDevice>,
    pub approval: ApprovalPolicy,
}

/// Error surface of the local signer. A refusal (member declined, or a binding failed) is
/// a first-class, non-secret outcome (ws1-signer §7).
#[derive(Debug)]
pub enum SignerError {
    /// The member declined the rendered payment on-device.
    MemberRefused,
    /// The candidate fee could not be bound to its value commitments.
    FeeUnverified(String),
    /// `pkg.message()` did not equal the sighash recomputed from the rendered PCZT. A
    /// malicious coordinator asking us to sign something other than what we rendered.
    SighashMismatch,
    /// The signer is not connected / the session is unknown.
    NoSession,
    /// No share is sealed yet (DKG not complete).
    NoShare,
    /// The member refused the coordinator connection on-device.
    ConnectRefused,
    /// The setup roster failed a check, or the member said the codes do not match.
    RosterRejected(String),
    /// The member cancelled on the device.
    Cancelled,
    /// The member did not decide before the deadline.
    TimedOut,
    /// The setup hit a mismatch or a bad message. Final: its secrets are wiped.
    SetupAborted(String),
    /// After the share exists, a setup message was refused. The saved setup and the
    /// share are kept; the step's progress is saved.
    MessageRefused(String),
    /// The vault is not ready: certificates or backup receipts are missing.
    NotReady,
    /// A protocol/parse/io failure, carried as text.
    Other(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::MemberRefused => write!(f, "member refused the rendered payment"),
            SignerError::FeeUnverified(e) => write!(f, "{e}"),
            SignerError::SighashMismatch => write!(
                f,
                "REFUSED: SigningPackage.message() != sighash(rendered pczt) — \
                 what-you-see-is-what-you-sign binding failed"
            ),
            SignerError::NoSession => write!(f, "no active session"),
            SignerError::NoShare => write!(f, "no sealed share (DKG incomplete)"),
            SignerError::ConnectRefused => write!(f, "member refused the connection"),
            SignerError::RosterRejected(e) => write!(f, "setup roster rejected: {e}"),
            SignerError::Cancelled => write!(f, "member cancelled on the device"),
            SignerError::TimedOut => write!(f, "member did not decide before the deadline"),
            SignerError::SetupAborted(e) => write!(f, "setup aborted: {e}"),
            SignerError::MessageRefused(e) => {
                write!(f, "setup message refused (setup and share kept): {e}")
            }
            SignerError::NotReady => write!(f, "vault not ready: certificates or backups missing"),
            SignerError::Other(e) => write!(f, "{e}"),
        }
    }
}
impl From<String> for SignerError {
    fn from(e: String) -> Self {
        SignerError::Other(e)
    }
}

/// The setup format version a new-path roster must declare (C9).
pub const SETUP_VERSION: u64 = 2;

/// The roster code compared on the device: 24 digits in six groups of four (about 80
/// bits), derived from the roster fingerprint. Digits, so it cannot be confused with
/// recovery words.
pub fn roster_code(fingerprint: &[u8; 32]) -> String {
    let hash = blake2b_simd::Params::new()
        .hash_length(16)
        .personal(b"Loki_roster_code")
        .hash(fingerprint);
    let value = u128::from_be_bytes(hash.as_bytes().try_into().expect("16 bytes"));
    let digits = format!("{:024}", value % 10u128.pow(24));
    digits
        .as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).expect("ASCII digits"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn kind_code(kind: DkgWireKind) -> u8 {
    match kind {
        DkgWireKind::Round1 => 1,
        DkgWireKind::Round2 => 2,
        DkgWireKind::Certificate => 3,
        DkgWireKind::BackupReceipt => 4,
    }
}

/// The incoming message kind each core phase waits for.
fn expected_kind(phase: DkgPhase) -> Option<DkgWireKind> {
    match phase {
        DkgPhase::Empty => None,
        DkgPhase::Round1 => Some(DkgWireKind::Round1),
        DkgPhase::Round2 => Some(DkgWireKind::Round2),
        DkgPhase::Certificate => Some(DkgWireKind::Certificate),
        DkgPhase::Certified => Some(DkgWireKind::BackupReceipt),
    }
}

const SETUP_MAGIC: &[u8; 8] = b"LOKISGS1";
const MAX_SETUP_WIRE: usize = 66 * 1024;

/// The signer's saved setup: the core state, the exact messages it last released, the
/// peer messages it accepted but has not consumed yet (as received, encrypted where they
/// were encrypted), and the backup receipts. Saved before any message is released.
struct SetupCheckpoint {
    core: DkgState,
    outgoing: Vec<Vec<u8>>,
    pending: BTreeMap<(u8, u16), Vec<u8>>,
    backups: BTreeMap<u16, Vec<u8>>,
    aborted: bool,
}

impl SetupCheckpoint {
    fn new() -> Self {
        Self {
            core: DkgState::empty(),
            outgoing: Vec::new(),
            pending: BTreeMap::new(),
            backups: BTreeMap::new(),
            aborted: false,
        }
    }

    fn duplicate(&self) -> Self {
        Self {
            core: self.core.duplicate(),
            outgoing: self.outgoing.clone(),
            pending: self.pending.clone(),
            backups: self.backups.clone(),
            aborted: self.aborted,
        }
    }

    /// Abort: wipe the fresh key, the FROST state and every saved message.
    fn wipe(&mut self) {
        self.core.wipe();
        self.outgoing.clear();
        self.pending.clear();
        self.aborted = true;
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        fn field(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        let mut out = Zeroizing::new(SETUP_MAGIC.to_vec());
        out.push(u8::from(self.aborted));
        field(&mut out, &self.core.encode()?);
        out.extend_from_slice(&(self.outgoing.len() as u16).to_be_bytes());
        for wire in &self.outgoing {
            field(&mut out, wire);
        }
        out.extend_from_slice(&(self.pending.len() as u16).to_be_bytes());
        for ((kind, sender), wire) in &self.pending {
            out.push(*kind);
            out.extend_from_slice(&sender.to_be_bytes());
            field(&mut out, wire);
        }
        crate::dkg_core::encode_map(&mut out, &self.backups)?;
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut reader = crate::dkg_core::Reader::new(raw);
        if reader.take(8)? != SETUP_MAGIC {
            return Err("invalid signer setup checkpoint".into());
        }
        let aborted = match reader.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err("invalid signer setup checkpoint".into()),
        };
        let core = DkgState::decode(&Zeroizing::new(reader.field(1 << 20)?.to_vec()))?;
        let count = u16::from_be_bytes(reader.take(2)?.try_into().unwrap());
        let mut outgoing = Vec::new();
        for _ in 0..count {
            outgoing.push(reader.field(MAX_SETUP_WIRE)?.to_vec());
        }
        let count = u16::from_be_bytes(reader.take(2)?.try_into().unwrap());
        let mut pending = BTreeMap::new();
        for _ in 0..count {
            let kind = reader.take(1)?[0];
            let sender = u16::from_be_bytes(reader.take(2)?.try_into().unwrap());
            pending.insert((kind, sender), reader.field(MAX_SETUP_WIRE)?.to_vec());
        }
        let backups = reader.map()?;
        reader.finish()?;
        Ok(Self {
            core,
            outgoing,
            pending,
            backups,
            aborted,
        })
    }
}

/// The share file: key package, group public package and `vs`.
pub fn encode_share(key_package: &[u8], public_package: &[u8], vs: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(&(key_package.len() as u32).to_be_bytes());
    out.extend_from_slice(key_package);
    out.extend_from_slice(&(public_package.len() as u32).to_be_bytes());
    out.extend_from_slice(public_package);
    out.extend_from_slice(vs);
    out
}

#[allow(clippy::type_complexity)]
pub fn decode_share(raw: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, [u8; 32]), String> {
    let mut reader = crate::dkg_core::Reader::new(raw);
    let key = Zeroizing::new(reader.field(64 * 1024)?.to_vec());
    let public = reader.field(64 * 1024)?.to_vec();
    let vs: [u8; 32] = reader.take(32)?.try_into().map_err(|_| "invalid share file")?;
    reader.finish()?;
    Ok((key, public, vs))
}

fn vault_network(network: crate::network::VaultNetwork) -> Network {
    match network {
        crate::network::VaultNetwork::Regtest => Network::Regtest,
        crate::network::VaultNetwork::Testnet => Network::Testnet,
    }
}

/// One member's signer for one vault: the sealed share, the public key package, the vault
/// viewing key (kept inside the signer to render and build payments), a secure element, a
/// crash-safe nonce store and the on-device prompts.
pub struct LocalSigner<SE: SecureElement> {
    member_id: u16,
    threshold: u16,
    members: u16,
    vault_id: [u8; 32],
    label: String,
    network: Network,
    se: SE,
    /// The signer's data directory. `None` for a signer built from a bare share.
    store: Option<SignerStore>,
    /// The member's setup identity (Ed25519 signing + X25519 encryption keys).
    identity: Option<Identity>,
    /// The roster the member confirmed on-device, and its exact document.
    roster: Option<(ValidatedRoster, Vec<u8>)>,
    /// The saved setup, from the roster confirmation on.
    setup: Option<SetupCheckpoint>,
    /// The member's FROST share, sealed at rest. Present once DKG completes (or when the
    /// signer is constructed from a restored/dealer-dealt share for tests).
    sealed_share: Option<SealedShare>,
    /// The group `PublicKeyPackage`, serialized. Public.
    public_package: Option<Vec<u8>>,
    /// The vault viewing key, derived from the group key and the real `vs`. Stays inside
    /// the signer: used to render payments and build candidates.
    vault_fvk: Option<FullViewingKey>,
    nonces: NonceStore,
    approval: ApprovalPolicy,
    connect_approval: Option<ConnectApproval>,
    /// External nonce witnesses claimed before each fresh signature share is released.
    nonce_witness: Option<Box<dyn NonceWitness + Send>>,
    roster_confirmation: Option<RosterConfirmation>,
    roster_deadline: Duration,
    backup_device: Option<Box<dyn BackupDevice>>,
    session: Option<Session>,
    /// The origin shown and approved on-device for the current session.
    session_origin: Option<String>,
    /// Rendered payments, keyed by candidate attempt id, for `rendered_payment`.
    rendered: BTreeMap<[u8; 32], PaymentView>,
    /// The (payment, sighash) the member last approved. Every spend of a multi-note payment
    /// signs the same sighash, so one decision covers them all.
    approved: Option<([u8; 32], [u8; 32])>,
    /// This signer's own spendable vault notes (scanned member-side with its own fvk). The
    /// proposer selects from these when it builds a candidate; the coordinator never sees
    /// them. Empty until set by the signer's owner (`set_candidate_notes`).
    candidate_notes: Vec<orchard::Note>,
}

impl<SE: SecureElement> LocalSigner<SE> {
    #[allow(clippy::too_many_arguments)]
    fn bare(
        member_id: u16,
        threshold: u16,
        members: u16,
        vault_id: [u8; 32],
        label: String,
        network: Network,
        se: SE,
        nonces: NonceStore,
        approval: ApprovalPolicy,
    ) -> Self {
        Self {
            member_id,
            threshold,
            members,
            vault_id,
            label,
            network,
            se,
            store: None,
            identity: None,
            roster: None,
            setup: None,
            sealed_share: None,
            public_package: None,
            vault_fvk: None,
            nonces,
            approval,
            connect_approval: None,
            nonce_witness: None,
            roster_confirmation: None,
            roster_deadline: Duration::ZERO,
            backup_device: None,
            session: None,
            session_origin: None,
            rendered: BTreeMap::new(),
            approved: None,
            candidate_notes: Vec::new(),
        }
    }

    /// Construct a signer that already holds a sealed share (e.g. restored from backup, or
    /// — in tests — dealt by the dealer DKG). `nonce_dir` is this member's crash-safe
    /// nonce store directory.
    #[allow(clippy::too_many_arguments)]
    pub fn with_sealed_share(
        member_id: u16,
        threshold: u16,
        members: u16,
        vault_id: [u8; 32],
        label: String,
        network: Network,
        se: SE,
        key_package_bytes: &[u8],
        public_package_bytes: Vec<u8>,
        vault_fvk: FullViewingKey,
        nonce_dir: PathBuf,
        approval: ApprovalPolicy,
    ) -> Result<Self, SignerError> {
        let nonces = NonceStore::open(&nonce_dir, vault_id, member_id)
            .map_err(|e| SignerError::Other(e.to_string()))?;
        let sealed = SealedShare::seal(&se, 0, key_package_bytes).map_err(SignerError::Other)?;
        let mut signer = Self::bare(
            member_id, threshold, members, vault_id, label, network, se, nonces, approval,
        );
        signer.sealed_share = Some(sealed);
        signer.public_package = Some(public_package_bytes);
        signer.vault_fvk = Some(vault_fvk);
        Ok(signer)
    }

    /// Build a signing-ready signer from a member's already-opened, certified vault state
    /// ([`crate::member_state::open`]). The sealed `vault.sealed` material — this member's
    /// `KeyPackage`, the group `PublicKeyPackage`, and the vault FVK — is re-sealed under
    /// this device's `se`; no new DKG runs. This is the path that drives a real funded vault
    /// through the [`Signer`] seam.
    pub fn from_vault_member(
        state: &crate::member_state::MemberState,
        se: SE,
        nonce_dir: PathBuf,
        approval: ApprovalPolicy,
    ) -> Result<Self, SignerError> {
        let mut signer = Self::with_sealed_share(
            state.identity.public().id,
            state.roster.threshold,
            state.roster.members.len() as u16,
            state.vault,
            format!("vault {}", hex::encode(&state.vault[..4])),
            vault_network(state.network),
            se,
            &Zeroizing::new(state.key.serialize().map_err(|e| SignerError::Other(e.to_string()))?),
            state.public.serialize().map_err(|e| SignerError::Other(e.to_string()))?,
            state.fvk.clone(),
            nonce_dir,
            approval,
        )?;
        let secret = Zeroizing::new(state.identity.to_secret_bytes());
        signer.identity = Some(Identity::from_secret_bytes(&secret[..]).map_err(SignerError::Other)?);
        Ok(signer)
    }

    /// Reconstruct a signer from a verified backup on a FRESH data root
    /// ([`crate::signer::backup::restore`]). The share is re-sealed under this device's
    /// `se`; `nonces` is a nonce store already opened at the bumped epoch, so any nonce
    /// committed before the restore is hard-refused (ws1-signer §8). `epoch` is carried so
    /// subsequent `sign_commit`s stamp the fresh epoch too.
    #[allow(clippy::too_many_arguments)]
    pub fn from_restored(
        member_id: u16,
        threshold: u16,
        members: u16,
        vault_id: [u8; 32],
        label: String,
        network: Network,
        se: SE,
        key_package_bytes: &[u8],
        public_package_bytes: Vec<u8>,
        vault_fvk: FullViewingKey,
        epoch: u64,
        nonces: NonceStore,
        approval: ApprovalPolicy,
        identity: Option<Identity>,
    ) -> Result<Self, SignerError> {
        let sealed = SealedShare::seal(&se, epoch, key_package_bytes).map_err(SignerError::Other)?;
        let mut signer = Self::bare(
            member_id, threshold, members, vault_id, label, network, se, nonces, approval,
        );
        signer.sealed_share = Some(sealed);
        signer.public_package = Some(public_package_bytes);
        signer.vault_fvk = Some(vault_fvk);
        signer.identity = identity;
        Ok(signer)
    }

    /// Take a member slot: create the signer's data directory under `dir`, bound to one
    /// vault and member number, and a fresh setup identity. Threshold and member count
    /// come later, from the roster the member confirms in [`Signer::dkg_begin`].
    pub fn create(
        dir: &Path,
        se: SE,
        network: Network,
        vault_id: [u8; 32],
        member_id: u16,
        label: String,
        prompts: DevicePrompts,
    ) -> Result<Self, SignerError> {
        Self::create_with_identity(dir, se, network, vault_id, member_id, label, prompts, Identity::new(member_id))
    }

    /// Use an identity enrolled before the hosted ceremony starts.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_identity(
        dir: &Path,
        se: SE,
        network: Network,
        vault_id: [u8; 32],
        member_id: u16,
        label: String,
        prompts: DevicePrompts,
        identity: Identity,
    ) -> Result<Self, SignerError> {
        if vault_id == [0; 32] || !(1..=crate::member_state::MAX_MEMBERS).contains(&member_id) {
            return Err(SignerError::Other("invalid vault id or member number".into()));
        }
        if identity.public().id != member_id {
            return Err(SignerError::Other("signer identity is for another member".into()));
        }
        let store = SignerStore::create(dir, network, vault_id, member_id)?;
        store.write(
            &se,
            FileKind::Identity,
            0,
            &Zeroizing::new(identity.to_secret_bytes())[..],
        )?;
        let nonces = NonceStore::open(&store.nonce_dir(), vault_id, member_id)
            .map_err(|e| SignerError::Other(e.to_string()))?;
        let mut signer = Self::bare(
            member_id, 0, 0, vault_id, label, network, se, nonces, prompts.approval,
        );
        signer.identity = Some(identity);
        signer.store = Some(store);
        signer.connect_approval = Some(prompts.connect);
        signer.roster_confirmation = Some(prompts.roster);
        signer.roster_deadline = prompts.roster_deadline;
        signer.backup_device = Some(prompts.backup);
        Ok(signer)
    }

    /// Reopen a signer created with [`LocalSigner::create`] after a restart. Every saved
    /// file must open under this element and belong to this vault and member; the saved
    /// setup is revalidated (without decrypting anything once the fresh key is gone), and
    /// a saved share must match the setup's certified group key.
    pub fn open(dir: &Path, se: SE, label: String, prompts: DevicePrompts) -> Result<Self, SignerError> {
        let store = SignerStore::open(dir)?;
        let (_, raw) = store
            .read(&se, FileKind::Identity)?
            .ok_or_else(|| SignerError::Other("signer has no identity".into()))?;
        let identity = Identity::from_secret_bytes(&raw).map_err(SignerError::Other)?;
        if identity.public().id != store.member() {
            return Err(SignerError::Other("signer identity is for another member".into()));
        }
        let nonces = NonceStore::open(&store.nonce_dir(), store.vault(), store.member())
            .map_err(|e| SignerError::Other(e.to_string()))?;
        let mut signer = Self::bare(
            store.member(),
            0,
            0,
            store.vault(),
            label,
            store.network(),
            se,
            nonces,
            prompts.approval,
        );
        signer.identity = Some(identity);
        signer.connect_approval = Some(prompts.connect);
        signer.roster_confirmation = Some(prompts.roster);
        signer.roster_deadline = prompts.roster_deadline;
        signer.backup_device = Some(prompts.backup);
        if let Some((_, document)) = store.read(&signer.se, FileKind::Roster)? {
            let roster = signer.check_roster(&document)?;
            signer.threshold = roster.threshold;
            signer.members = roster.member_count();
            signer.roster = Some((roster, document.to_vec()));
        }
        let setup = match store.read(&signer.se, FileKind::Setup)? {
            Some((_, raw)) => Some(SetupCheckpoint::decode(&raw)?),
            None => None,
        };
        let share = store.read(&signer.se, FileKind::Share)?;
        signer.store = Some(store);
        let mut installed = None;
        let setup = match (&signer.roster, setup) {
            // A crash between saving the confirmed roster and its empty setup.
            (Some(_), None) if share.is_none() => {
                let setup = SetupCheckpoint::new();
                signer.save_setup(&setup)?;
                Some(setup)
            }
            (_, setup) => setup,
        };
        match (&signer.roster, &setup) {
            (None, None) if share.is_none() => {}
            (Some((roster, _)), Some(setup)) => {
                let identity = signer.identity.as_ref().expect("set above");
                let core = DkgCore::new(roster, identity).map_err(SignerError::Other)?;
                if !setup.aborted {
                    core.validate(&setup.core).map_err(SignerError::Other)?;
                }
                let certified = (setup.core.phase() as u8) >= DkgPhase::Certificate as u8;
                match (&share, certified && !setup.aborted) {
                    (Some((epoch, raw)), true) => {
                        let (key, public, vs) = decode_share(raw)?;
                        installed =
                            Some(signer.checked_share(&core, &setup.core, &key, public, &vs, *epoch)?);
                    }
                    (None, false) => {}
                    // A crash after the certificate-phase setup was saved but before its
                    // share file was written: the setup holds the share.
                    (None, true) => {
                        installed = Some(
                            signer
                                .restore_share(&core, &setup.core)
                                .map_err(SignerError::Other)?,
                        );
                    }
                    // A share without a certified setup: a file was rolled back or swapped.
                    _ => {
                        return Err(SignerError::Other(
                            "signer files are inconsistent (rolled back?)".into(),
                        ))
                    }
                }
            }
            _ => {
                return Err(SignerError::Other(
                    "signer files are inconsistent (rolled back?)".into(),
                ))
            }
        }
        if let Some(share) = installed {
            signer.install(share);
        }
        signer.setup = setup;
        Ok(signer)
    }

    /// The group verifying (public) key package, once DKG has completed. Public.
    pub fn public_package_bytes(&self) -> Option<&[u8]> {
        self.public_package.as_deref()
    }

    /// Public vault metadata (group public-key package + full viewing key) for an active
    /// signer, without touching the sealed share. The hosted member records it in
    /// `vault.sealed` and scans with it; the share itself never leaves the signer.
    pub fn hosted_metadata(&self) -> Result<(frost::keys::PublicKeyPackage, FullViewingKey), SignerError> {
        self.require_ready()?;
        let public = frost::keys::PublicKeyPackage::deserialize(
            self.public_package.as_deref().ok_or(SignerError::NoShare)?,
        )
        .map_err(|e| SignerError::Other(e.to_string()))?;
        Ok((public, self.fvk()?.clone()))
    }

    /// Open a hosted signing packet for the browser's relay pump.
    pub fn open_hosted_signing(
        &self,
        sender: &PublicIdentity,
        context: &SessionContext,
        wire: &[u8],
    ) -> Result<crate::signing_session::OpenedMessage, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        if context.vault != self.vault_id || (sender.id != 0 && self.confirmed_roster()
            .and_then(|r| r.members.get(&sender.id)) != Some(sender)) {
            return Err(SignerError::Other("signing sender or vault differs from the roster".into()));
        }
        identity.open_session(sender, context, wire).map_err(SignerError::Other)
    }

    /// Seal this browser member's commitment or share to the pinned hosted coordinator.
    pub fn seal_hosted_signing(
        &self,
        coordinator: &PublicIdentity,
        context: &SessionContext,
        kind: MessageKind,
        body: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        if coordinator.id != 0 || context.vault != self.vault_id
            || !matches!(kind, MessageKind::HostedCommitment | MessageKind::HostedShare)
            || !kind.valid_hosted_body(context, body)
        {
            return Err(SignerError::Other("invalid signing message for coordinator".into()));
        }
        identity.seal_session(coordinator, context, kind, body).map_err(SignerError::Other)
    }

    /// The roster this member confirmed at setup. Peers are looked up here, never taken from
    /// keys a network reply supplies.
    pub fn confirmed_roster(&self) -> Option<&Roster> {
        self.roster.as_ref().map(|(roster, _)| roster.roster())
    }

    /// Give a signer restored from a backup ([`crate::signer::backup::restore`]) the roster
    /// document that backup carried, so it can seal and open control messages with its peers
    /// again. Only for a restored signer (no data directory, no roster or setup yet); the
    /// document passes the same roster gate as setup and must match the restored vault size.
    /// `connect` is the member's on-device connection prompt: a restored signer built from a
    /// bare share has none, so without it every session stays unapproved and the member can
    /// never release its address.
    pub fn adopt_restored_roster(&mut self, document: &[u8], connect: ConnectApproval) -> Result<(), SignerError> {
        if self.store.is_some() || self.roster.is_some() || self.setup.is_some() {
            return Err(SignerError::Other("only a restored signer adopts its backup roster".into()));
        }
        let roster = self.check_roster(document)?;
        if roster.threshold != self.threshold || roster.member_count() != self.members {
            return Err(SignerError::RosterRejected("roster differs from the restored vault".into()));
        }
        self.roster = Some((roster, document.to_vec()));
        self.connect_approval = Some(connect);
        Ok(())
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Open a message another member sealed to this one on a payment's control session. The
    /// sender is the confirmed-roster member whose relay key is `sender_relay`. Returns its
    /// member id and the message body.
    pub fn open_control(
        &self,
        session: uuid::Uuid,
        sender_relay: &[u8; 32],
        wire: &[u8],
    ) -> Result<(u16, Vec<u8>), SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let me = identity.public().id;
        let sender = self
            .confirmed_roster()
            .ok_or(SignerError::NotReady)?
            .members
            .values()
            .find(|m| &m.encryption == sender_relay && m.id != me)
            .ok_or_else(|| SignerError::Other("control message from a non-member".into()))?;
        let context = SessionContext::control(self.vault_id, session, me, sender.id);
        let opened = identity
            .open_session(sender, &context, wire)
            .map_err(SignerError::Other)?;
        if opened.kind() != MessageKind::PeerReply {
            return Err(SignerError::Other("not a control message".into()));
        }
        Ok((sender.id, opened.body().to_vec()))
    }

    /// Seal a control-session message from this member to confirmed-roster member `recipient`.
    pub fn seal_control(
        &self,
        session: uuid::Uuid,
        recipient: u16,
        body: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let peer = self
            .confirmed_roster()
            .ok_or(SignerError::NotReady)?
            .members
            .get(&recipient)
            .ok_or_else(|| SignerError::Other("recipient is not a vault member".into()))?;
        let context = SessionContext::control(self.vault_id, session, identity.public().id, recipient);
        identity
            .seal_session(peer, &context, MessageKind::PeerReply, body)
            .map_err(SignerError::Other)
    }

    /// The device-side "abandon this setup" action: wipe the setup's fresh key, FROST
    /// state and saved messages, and refuse to continue it. Also done automatically on
    /// any mismatch before the share exists.
    pub fn abandon_setup(&mut self) -> Result<(), SignerError> {
        let mut setup = self
            .setup
            .take()
            .ok_or_else(|| SignerError::Other("no setup in progress".into()))?;
        if (setup.core.phase() as u8) >= DkgPhase::Certificate as u8 && !setup.aborted {
            self.setup = Some(setup);
            return Err(SignerError::Other("the vault share already exists".into()));
        }
        setup.wipe();
        let saved = self.save_setup(&setup);
        self.setup = Some(setup);
        saved
    }

    /// Require a claim at both external nonce witnesses before every fresh signature share:
    /// a nonce whose claim is refused or already taken (for example after the local nonce
    /// files were rolled back) never signs. The local durable burn record still applies.
    pub fn set_nonce_witness(&mut self, witness: Box<dyn NonceWitness + Send>) {
        self.nonce_witness = Some(witness);
    }

    /// Browser preflight: return the original witness pair only after authenticating the
    /// pending nonce and checking that the package names that exact commitment.
    pub fn nonce_claim_pins(
        &self,
        cand: &CandidateRef,
        commitment: &frost::round1::SigningCommitments,
    ) -> Result<crate::signing_session::WitnessPins, SignerError> {
        let pins = self.nonce_witness.as_ref().ok_or_else(||
            SignerError::Other("two nonce witnesses required".into()))?.pins();
        let pending = self.nonces.pending_commitment(&self.nonce_id(cand), &self.se, pins)
            .map_err(|e| SignerError::Other(e.to_string()))?;
        if pending != *commitment {
            return Err(SignerError::Other("own commitment differs from the pending nonce".into()));
        }
        Ok(pins)
    }

    /// Sign with the active vault identity, not a transport key or a public capability.
    pub fn nonce_claim_proof(
        &self,
        (key, run, mailbox): ([u8; 32], [u8; 32], [u8; 32]),
        cid: [u8; 32],
        challenge: [u8; 32],
        record: &[u8],
    ) -> Result<loki_relay_protocol::nonce::ClaimProof, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let pin = loki_relay_protocol::types::RelayPin { key, run };
        Ok(identity.nonce_claim_proof(self.vault_id, &pin, mailbox, cid, challenge, record))
    }

    /// Install the decision for an attempt after its signing group and expiry are fixed.
    pub fn set_approval_policy(&mut self, approval: ApprovalPolicy) {
        self.approval = approval;
        self.approved = None;
    }

    /// Give this signer the vault notes it may spend. These are scanned member-side with
    /// this signer's own fvk (`wallet_store::sync_member_wallet`); they never cross the
    /// coordinator seam. The proposer signer selects from them in `build_candidate`.
    pub fn set_candidate_notes(&mut self, notes: Vec<orchard::Note>) {
        self.candidate_notes = notes;
    }

    /// Build the IO-finalized, unsigned candidate under `params`, the signer's OWN fvk, the
    /// notes its owner selected (`set_candidate_notes`), and one coordinator-supplied alpha per
    /// note. The `P` is the signer's own network parameters — never supplied by the coordinator.
    fn build_pczt<P: zcash_protocol::consensus::Parameters + Clone>(
        &self,
        params_net: &P,
        params: &crate::signer::PublicPaymentParams,
        alphas: &[[u8; 32]],
    ) -> Result<Vec<u8>, SignerError> {
        if self.candidate_notes.is_empty() {
            return Err(SignerError::Other("signer holds no spendable note".into()));
        }
        if self.candidate_notes.len() != alphas.len() {
            return Err(SignerError::Other("the coordinator sent a randomiser count that differs from the payment's notes".into()));
        }
        // The PCZT build is share-free; it lives in `crate::builder` so the untrusted
        // server-side builder (W4) runs this identical path. Only the notes and the viewing
        // key stay here.
        crate::builder::build_unsigned(self.fvk()?, params_net, params, &self.candidate_notes, alphas)
            .map_err(SignerError::Other)
    }

    fn fvk(&self) -> Result<&FullViewingKey, SignerError> {
        self.vault_fvk.as_ref().ok_or(SignerError::NoShare)
    }

    /// Unseal the member's `KeyPackage` into memory (with the Apple element, one Secure
    /// Enclave unwrap). The unwrapped bytes are a `Zeroizing` buffer wiped when this returns;
    /// the returned `KeyPackage` wipes its signing share on drop (`ZeroizeOnDrop`), so
    /// callers drop it as soon as its one use is done. It is never stored on the signer.
    fn open_key(&self) -> Result<frost::keys::KeyPackage, SignerError> {
        let sealed = self.sealed_share.as_ref().ok_or(SignerError::NoShare)?;
        let plain = sealed.open(&self.se).map_err(SignerError::Other)?;
        let key = frost::keys::KeyPackage::deserialize(&plain)
            .map_err(|e| SignerError::Other(format!("key package: {e}")));
        drop(plain);
        key
    }

    fn nonce_id(&self, cand: &CandidateRef) -> String {
        // One nonce per (payment, attempt). Hex so it is a safe filename.
        let mut s = String::with_capacity(64);
        for b in cand.payment_id.iter().chain(cand.attempt_id.iter()) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn check_session(&self, session: &Session) -> Result<(), SignerError> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        Ok(())
    }

    /// Whether every certificate and every member's backup receipt is in. A signer built
    /// from a bare share is ready by construction.
    fn is_ready(&self) -> bool {
        match (&self.setup, &self.roster) {
            (None, _) => self.sealed_share.is_some(),
            (Some(setup), Some((roster, _))) => {
                !setup.aborted
                    && setup.core.phase() == DkgPhase::Certified
                    && setup.backups.len() == roster.members.len()
            }
            (Some(_), None) => false,
        }
    }

    fn require_ready(&self) -> Result<(), SignerError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(SignerError::NotReady)
        }
    }

    /// The shared roster gate plus this signer's checks: `"setup_version": 2` first, then
    /// its own network, its vault, and its full identity under its member number.
    fn check_roster(&self, document: &[u8]) -> Result<ValidatedRoster, SignerError> {
        let reject = |e: &str| SignerError::RosterRejected(e.to_string());
        let value: serde_json::Value =
            serde_json::from_slice(document).map_err(|_| reject("roster is not JSON"))?;
        if value.get("setup_version").and_then(serde_json::Value::as_u64) != Some(SETUP_VERSION) {
            return Err(reject("roster setup_version must be 2"));
        }
        let roster = Roster::from_bytes(document).map_err(|e| reject(&e))?;
        let roster = ValidatedRoster::new(roster).map_err(|e| reject(&e.to_string()))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| reject("signer has no setup identity"))?;
        if vault_network(roster.network) != self.network {
            return Err(reject("roster is for another network"));
        }
        if roster.vault != self.vault_id {
            return Err(reject("roster is for another vault"));
        }
        if roster.members.get(&self.member_id) != Some(&identity.public()) {
            return Err(reject("roster does not hold this signer's identity"));
        }
        Ok(roster)
    }

    fn save_setup(&self, setup: &SetupCheckpoint) -> Result<(), SignerError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| SignerError::Other("signer has no data directory".into()))?;
        store
            .write(&self.se, FileKind::Setup, 0, &setup.encode()?)
            .map_err(SignerError::Other)
    }

    fn install(&mut self, share: InstalledShare) {
        self.sealed_share = Some(share.sealed);
        self.public_package = Some(share.public_package);
        self.vault_fvk = Some(share.fvk);
    }

    /// Check a share born in (or reloaded for) the certified setup: it must match the
    /// setup's group key and `vs`; the viewing key is derived from the real `vs`.
    #[allow(clippy::too_many_arguments)]
    fn checked_share(
        &self,
        core: &DkgCore<'_>,
        state: &DkgState,
        key_package: &[u8],
        public_package: Vec<u8>,
        vs: &[u8; 32],
        epoch: u64,
    ) -> Result<InstalledShare, SignerError> {
        let key = frost::keys::KeyPackage::deserialize(key_package)
            .map_err(|e| SignerError::Other(format!("key package: {e}")))?;
        let public = frost::keys::PublicKeyPackage::deserialize(&public_package)
            .map_err(|e| SignerError::Other(format!("public package: {e}")))?;
        let body = core.certificate_body(state).map_err(SignerError::Other)?;
        let completed_public = state_public_package(state)?;
        if public_package != completed_public
            || key.verifying_key() != public.verifying_key()
            || vs != state.vault_secret()
            || body.is_empty()
        {
            return Err(SignerError::Other("signer share does not match its setup".into()));
        }
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .map_err(|e| SignerError::Other(e.to_string()))?
            .try_into()
            .map_err(|_| SignerError::Other("group key is not 32 bytes".into()))?;
        Ok(InstalledShare {
            fvk: zip2005::frost_viewing_key(&ak, vs)
                .map_err(|e| SignerError::Other(format!("ZIP 2005 derivation: {e:?}")))?,
            sealed: SealedShare::seal(&self.se, epoch, key_package).map_err(SignerError::Other)?,
            public_package,
        })
    }

    /// One `dkg_step`: start round one if needed, accept the inputs, then advance through
    /// every phase whose messages are complete. Each advance is saved before the next, and
    /// `setup` always equals the last saved state, even when this returns an error.
    fn advance_setup(
        &mut self,
        setup: &mut SetupCheckpoint,
        inputs: &[DkgInput],
    ) -> Result<(), StepError> {
        let mut share = None;
        let outcome = self.progress_setup(setup, inputs, &mut share);
        if let Some(share) = share {
            self.install(share);
        }
        outcome
    }

    fn progress_setup(
        &self,
        setup: &mut SetupCheckpoint,
        inputs: &[DkgInput],
        share: &mut Option<InstalledShare>,
    ) -> Result<(), StepError> {
        // Before the share exists a failure is final; after it, the saved setup is kept.
        let fail = |state: &SetupCheckpoint, error: String| {
            if holds_share(state) {
                StepError::Kept(error)
            } else {
                StepError::Abort(error)
            }
        };
        let (roster, _) = self
            .roster
            .as_ref()
            .ok_or_else(|| fail(setup, "no confirmed roster".into()))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| fail(setup, "no setup identity".into()))?;
        let core = DkgCore::new(roster, identity).map_err(|e| fail(setup, e))?;
        let own = self.member_id;
        if holds_share(setup) && self.sealed_share.is_none() {
            // A write of the share file failed after its setup was saved: finish it now.
            *share = Some(self.restore_share(&core, &setup.core).map_err(|e| fail(setup, e))?);
        }
        if setup.core.phase() == DkgPhase::Empty {
            let (state, outgoing) = core.start().map_err(|e| fail(setup, e))?;
            let mut next = setup.duplicate();
            next.core = state;
            next.outgoing = released(&outgoing, own);
            self.save_setup(&next).map_err(|e| fail(setup, e.to_string()))?;
            *setup = next;
        }
        let mut next = setup.duplicate();
        let mut refused = Vec::new();
        for input in inputs {
            if let Err(error) = accept_input(roster, identity, own, &mut next, input) {
                if !holds_share(&next) {
                    return Err(StepError::Abort(error));
                }
                // One bad message must not cost a member the share it already holds.
                refused.push(error);
            }
        }
        let peers: Vec<u16> = roster.members.keys().copied().filter(|id| *id != own).collect();
        loop {
            let Some(kind) = expected_kind(next.core.phase()) else {
                break;
            };
            if kind == DkgWireKind::BackupReceipt {
                let expected = core.backup_body(&next.core).map_err(|e| fail(&next, e))?;
                let receipts: Vec<(u16, Vec<u8>)> = next
                    .pending
                    .iter()
                    .filter(|((k, _), _)| *k == kind_code(kind))
                    .map(|((_, sender), wire)| (*sender, wire.clone()))
                    .collect();
                for (sender, wire) in receipts {
                    next.pending.remove(&(kind_code(kind), sender));
                    match identity.verify_backup(&roster.members[&sender], &roster.vault, &wire) {
                        Ok(body) if body.as_slice() == expected => {
                            next.backups.insert(sender, wire);
                        }
                        // Dropped, so the member's real receipt can still arrive.
                        _ => refused.push(format!(
                            "member {sender}'s backup receipt is for a different vault"
                        )),
                    }
                }
                break;
            }
            let records: BTreeMap<u16, Vec<u8>> = peers
                .iter()
                .filter_map(|id| {
                    next.pending
                        .get(&(kind_code(kind), *id))
                        .map(|wire| (*id, wire.clone()))
                })
                .collect();
            if records.len() != peers.len() {
                break;
            }
            let (state, outgoing) = match core.advance(&next.core, &records) {
                Ok(advanced) => advanced,
                Err(error) if holds_share(&next) => {
                    // The certificates disagree. The vault never becomes ready, but the
                    // share and the saved setup stay for the member to inspect.
                    refused.push(error);
                    break;
                }
                Err(error) => return Err(StepError::Abort(error)),
            };
            for id in &peers {
                next.pending.remove(&(kind_code(kind), *id));
            }
            next.core = state;
            // Keep earlier phases' messages: a peer may not have them yet when this
            // member moves through several phases in one step.
            for wire in released(&outgoing, own) {
                if !next.outgoing.contains(&wire) {
                    next.outgoing.push(wire);
                }
            }
            // The certificate-phase setup holds the share, so it is saved before the share
            // file is written; `open` rebuilds a missing share file from it. Nothing is
            // released until this step returns.
            self.save_setup(&next).map_err(|e| fail(setup, e.to_string()))?;
            *setup = next.duplicate();
            if next.core.phase() == DkgPhase::Certificate {
                *share = Some(self.restore_share(&core, &next.core).map_err(|e| fail(&next, e))?);
            }
        }
        self.save_setup(&next).map_err(|e| fail(setup, e.to_string()))?;
        *setup = next;
        if refused.is_empty() {
            Ok(())
        } else {
            Err(StepError::Kept(refused.join("; ")))
        }
    }

    /// Write the share file from a certificate-phase setup and check it against that setup.
    fn restore_share(&self, core: &DkgCore<'_>, state: &DkgState) -> Result<InstalledShare, String> {
        let completed =
            crate::distributed_setup::Completed::restore_checkpoint(&state.completed_checkpoint()?)?;
        let key_package = Zeroizing::new(completed.key_package_bytes().to_vec());
        let public = completed.public_package().to_vec();
        let store = self.store.as_ref().ok_or("no data directory")?;
        store.write(
            &self.se,
            FileKind::Share,
            0,
            &encode_share(&key_package, &public, state.vault_secret()),
        )?;
        self.checked_share(core, state, &key_package, public, state.vault_secret(), 0)
            .map_err(|e| e.to_string())
    }
}

/// How a `dkg_step` failed.
enum StepError {
    /// Before the share exists: final, the setup is wiped.
    Abort(String),
    /// After the share exists: the bad messages are refused and the saved setup is kept.
    Kept(String),
}

/// Whether the share has been born in this setup (certificate phase or later).
fn holds_share(setup: &SetupCheckpoint) -> bool {
    !setup.aborted && (setup.core.phase() as u8) >= DkgPhase::Certificate as u8
}

/// Check one tagged input and queue it as pending, or drop it as a repeat.
fn accept_input(
    roster: &ValidatedRoster,
    identity: &Identity,
    own: u16,
    next: &mut SetupCheckpoint,
    input: &DkgInput,
) -> Result<(), String> {
    let vault = roster.vault;
    let wire = DkgWire::parse(input.bytes.clone())?;
    if wire.sender() != input.sender || !roster.members.contains_key(&wire.sender()) {
        return Err("setup message sender does not match its tag".into());
    }
    if wire.sender() == own {
        if !next.outgoing.contains(&input.bytes) {
            return Err("a setup message claims to be ours but is not".into());
        }
        return Ok(());
    }
    if wire.kind() == DkgWireKind::Round2 && wire.recipient() != Some(own) {
        return Err("round-two envelope addressed to another member".into());
    }
    let peer = &roster.members[&wire.sender()];
    let past = match wire.kind() {
        DkgWireKind::Round1 => next.core.round1().get(&wire.sender()),
        DkgWireKind::Round2 => next.core.round2().get(&wire.sender()),
        DkgWireKind::Certificate => next.core.certificates().get(&wire.sender()),
        DkgWireKind::BackupReceipt => next.backups.get(&wire.sender()),
    };
    if let Some(saved) = past {
        if saved != &input.bytes {
            return Err("a member sent two different messages for one phase".into());
        }
        return Ok(());
    }
    match wire.kind() {
        DkgWireKind::Round1 => {
            identity.verify_round1(peer, &vault, &input.bytes)?;
        }
        DkgWireKind::Certificate => {
            identity.verify_certificate(peer, &vault, &input.bytes)?;
        }
        DkgWireKind::BackupReceipt => {
            identity.verify_backup(peer, &vault, &input.bytes)?;
        }
        // Checked against our transcript when round two is consumed.
        DkgWireKind::Round2 => {}
    }
    let key = (kind_code(wire.kind()), wire.sender());
    match next.pending.get(&key) {
        Some(saved) if saved != &input.bytes => {
            Err("a member sent two different messages for one phase".into())
        }
        _ => {
            next.pending.insert(key, input.bytes.clone());
            Ok(())
        }
    }
}

/// A checked share ready to install: sealed under the element, with its public package
/// and the viewing key derived from the real `vs`.
struct InstalledShare {
    sealed: SealedShare,
    public_package: Vec<u8>,
    fvk: FullViewingKey,
}

/// The messages this member releases from a core step: one copy of each distinct wire,
/// without the member's own copy.
fn released(outgoing: &crate::dkg_core::Outgoing, own: u16) -> Vec<Vec<u8>> {
    let mut wires: Vec<Vec<u8>> = Vec::new();
    for (recipient, wire) in outgoing {
        if *recipient != own && !wires.contains(wire) {
            wires.push(wire.clone());
        }
    }
    wires
}

fn state_public_package(state: &DkgState) -> Result<Vec<u8>, SignerError> {
    let completed = crate::distributed_setup::Completed::restore_checkpoint(
        &state.completed_checkpoint().map_err(SignerError::Other)?,
    )
    .map_err(SignerError::Other)?;
    Ok(completed.public_package().to_vec())
}

impl<SE: SecureElement> Signer for LocalSigner<SE> {
    type Error = SignerError;

    fn connect(
        &mut self,
        origin: &str,
        network: Network,
        challenge: &[u8],
    ) -> Result<Connection, Self::Error> {
        if network != self.network {
            return Err(SignerError::Other(format!(
                "connect network {:?} does not match signer network {:?}",
                network, self.network
            )));
        }
        // A setup-capable signer shows the origin and network and asks the member. A
        // signer built from a bare share has no prompt; its sessions are never approved.
        let approved = match self.connect_approval.as_mut() {
            Some(approve) => {
                if !approve(origin, network) {
                    return Err(SignerError::ConnectRefused);
                }
                true
            }
            None => false,
        };
        // Session id binds the challenge so a replayed connect gets a distinct handle.
        let mut sid = [0u8; 32];
        let h = blake3::hash(challenge);
        sid.copy_from_slice(h.as_bytes());
        let session = Session(sid);
        self.session = Some(session.clone());
        self.session_origin = approved.then(|| origin.to_owned());
        let (signing, encryption) = match &self.identity {
            Some(identity) => {
                let public = identity.public();
                (public.signing, public.encryption)
            }
            None => ([0u8; 32], [0u8; 32]),
        };
        Ok(Connection {
            session,
            member: MemberIdentity {
                id: self.member_id,
                signing,
                encryption,
            },
        })
    }

    fn list_vaults(&self, session: &Session) -> Result<Vec<VaultRef>, Self::Error> {
        self.check_session(session)?;
        if self.store.is_some() && self.roster.is_none() {
            // A member slot with no confirmed roster yet holds no vault.
            return Ok(vec![]);
        }
        Ok(vec![VaultRef {
            vault_id: self.vault_id,
            label: self.label.clone(),
            threshold: self.threshold,
            members: self.members,
            ready: self.is_ready(),
        }])
    }

    fn dkg_begin(&mut self, session: &Session, roster: &[u8]) -> Result<VaultRef, Self::Error> {
        self.check_session(session)?;
        if self.store.is_none() || self.identity.is_none() {
            return Err(SignerError::Other("signer has no setup identity".into()));
        }
        if self.roster.is_some() || self.setup.is_some() {
            return Err(SignerError::Other("this signer's setup has already begun".into()));
        }
        // Version, roster gate, network and own identity: all before the code is shown.
        let validated = self.check_roster(roster)?;
        let code = roster_code(&validated.fingerprint());
        let confirm = self
            .roster_confirmation
            .as_mut()
            .ok_or_else(|| SignerError::Other("signer has no roster prompt".into()))?;
        let started = Instant::now();
        let decision = confirm(&code);
        if started.elapsed() > self.roster_deadline {
            return Err(SignerError::TimedOut);
        }
        match decision {
            RosterDecision::Match => {}
            RosterDecision::NoMatch => {
                return Err(SignerError::RosterRejected(
                    "the member's code did not match".into(),
                ))
            }
            RosterDecision::Cancelled => return Err(SignerError::Cancelled),
        }
        let store = self.store.as_ref().expect("checked above");
        store
            .write(&self.se, FileKind::Roster, 0, roster)
            .map_err(SignerError::Other)?;
        let setup = SetupCheckpoint::new();
        self.threshold = validated.threshold;
        self.members = validated.member_count();
        self.roster = Some((validated, roster.to_vec()));
        self.save_setup(&setup)?;
        self.setup = Some(setup);
        Ok(VaultRef {
            vault_id: self.vault_id,
            label: self.label.clone(),
            threshold: self.threshold,
            members: self.members,
            ready: false,
        })
    }

    fn dkg_step(
        &mut self,
        session: &Session,
        vault: &VaultRef,
        in_msgs: &[DkgInput],
    ) -> Result<Vec<DkgWire>, Self::Error> {
        self.check_session(session)?;
        if vault.vault_id != self.vault_id
            || vault.threshold != self.threshold
            || vault.members != self.members
        {
            return Err(SignerError::Other("DKG vault differs from this signer".into()));
        }
        let mut setup = self
            .setup
            .take()
            .ok_or_else(|| SignerError::Other("no confirmed setup roster (dkg_begin)".into()))?;
        if setup.aborted {
            self.setup = Some(setup);
            return Err(SignerError::SetupAborted("an earlier mismatch ended this setup".into()));
        }
        match self.advance_setup(&mut setup, in_msgs) {
            Ok(()) => {}
            Err(StepError::Abort(error)) => {
                // Any mismatch before the share exists is final: wipe the setup's secrets
                // and saved messages, never re-fetch and retry.
                setup.wipe();
                let _ = self.save_setup(&setup);
                self.setup = Some(setup);
                return Err(SignerError::SetupAborted(error));
            }
            Err(StepError::Kept(error)) => {
                self.setup = Some(setup);
                return Err(SignerError::MessageRefused(error));
            }
        }
        let wires = setup
            .outgoing
            .iter()
            .map(|bytes| DkgWire::parse(bytes.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(SignerError::Other);
        self.setup = Some(setup);
        wires
    }

    fn backup(&mut self, session: &Session) -> Result<Vec<DkgWire>, Self::Error> {
        self.check_session(session)?;
        let (roster, document) = self.roster.as_ref().ok_or(SignerError::NotReady)?;
        let setup = self.setup.as_ref().ok_or(SignerError::NotReady)?;
        if setup.aborted || setup.core.phase() != DkgPhase::Certified {
            return Err(SignerError::NotReady);
        }
        if let Some(receipt) = setup.backups.get(&self.member_id) {
            return Ok(vec![DkgWire::parse(receipt.clone()).map_err(SignerError::Other)?]);
        }
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let core = DkgCore::new(roster, identity).map_err(SignerError::Other)?;
        let key_package = Zeroizing::new(
            self.open_key()?
                .serialize()
                .map_err(|e| SignerError::Other(e.to_string()))?,
        );
        let material = BackupMaterial {
            member_id: self.member_id,
            threshold: self.threshold,
            members: self.members,
            network: self.network,
            vault_id: self.vault_id,
            label: self.label.clone(),
            group_sk: *setup.core.vault_secret(),
            key_package: key_package.clone(),
            public_package: self.public_package.clone().ok_or(SignerError::NoShare)?,
            backup_epoch: 0,
            identity: Zeroizing::new(identity.to_secret_bytes().to_vec()),
            roster: document.clone(),
            roster_fingerprint: roster.fingerprint(),
            birth_height: roster.birth_height,
        };
        let device = self
            .backup_device
            .as_mut()
            .ok_or_else(|| SignerError::Other("signer has no backup device".into()))?;
        let passphrase = device.passphrase().ok_or(SignerError::Cancelled)?;
        let artifact = backup::create(&material, &passphrase).map_err(SignerError::Other)?;
        device.save(&artifact).map_err(SignerError::Other)?;
        // Prove the stored backup reloads with what the member remembers.
        let reloaded = device.load().map_err(SignerError::Other)?;
        let again = device.passphrase().ok_or(SignerError::Cancelled)?;
        let back = backup::verify(&reloaded, &again, &self.vault_id).map_err(SignerError::Other)?;
        if *back.key_package != *key_package
            || back.group_sk != material.group_sk
            || *back.identity != *material.identity
            || back.roster_fingerprint != material.roster_fingerprint
            || back.member_id != self.member_id
        {
            return Err(SignerError::Other("the stored backup does not reload this vault".into()));
        }
        let body = core.backup_body(&setup.core).map_err(SignerError::Other)?;
        let receipt = identity
            .sign_backup(&self.vault_id, &body)
            .map_err(SignerError::Other)?;
        let mut next = setup.duplicate();
        next.backups.insert(self.member_id, receipt.clone());
        next.outgoing.push(receipt.clone());
        self.save_setup(&next)?;
        self.setup = Some(next);
        Ok(vec![DkgWire::parse(receipt).map_err(SignerError::Other)?])
    }

    fn release_address(&mut self, session: &Session) -> Result<ReleasedAddress, Self::Error> {
        self.check_session(session)?;
        if self.session_origin.is_none() {
            return Err(SignerError::ConnectRefused);
        }
        self.require_ready()?;
        let (roster, _) = self.roster.as_ref().ok_or(SignerError::NotReady)?;
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let address = match self.setup.as_ref() {
            Some(setup) => DkgCore::new(roster, identity)
                .and_then(|core| core.address(&setup.core))
                .map_err(SignerError::Other)?,
            // A member restored from its backup holds the vault FVK its DKG derived
            // (`frost_viewing_key(ak, vs)`, the same key `DkgCore::address` encodes), not the
            // setup transcript.
            None => crate::vault::unified_address(
                self.vault_fvk.as_ref().ok_or(SignerError::NotReady)?,
                zcash_protocol::consensus::Parameters::network_type(&roster.roster().network),
            ),
        };
        Ok(ReleasedAddress {
            vault_id: self.vault_id,
            address,
        })
    }

    fn build_candidate(
        &self,
        session: &Session,
        _cand: &CandidateRef,
        params: &crate::signer::PublicPaymentParams,
        alphas: &[[u8; 32]],
    ) -> Result<CandidatePczt, Self::Error> {
        self.check_session(session)?;
        self.require_ready()?;
        // Build under the signer's OWN network parameters: the coordinator supplied neither
        // the fvk nor a `Parameters` instance.
        match self.network {
            Network::Regtest => self.build_pczt(&crate::candidate::Regtest, params, alphas),
            Network::Testnet => {
                self.build_pczt(&zcash_protocol::consensus::TEST_NETWORK, params, alphas)
            }
        }
        .map(CandidatePczt)
    }

    fn sign_commit(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        self.require_ready()?;
        let id = self.nonce_id(cand);
        // Round 1 needs the share to derive the nonce; the key lives only for this call.
        let kp = self.open_key()?;
        let pins = self.nonce_witness.as_ref().map(|witness| witness.pins());
        let commitment = self.nonces.commit(&id, &self.se, kp.signing_share(), pins);
        drop(kp);
        commitment.map_err(|e| SignerError::Other(e.to_string()))
    }

    fn sign_approve(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
        params: &crate::signer::PublicPaymentParams,
        pczt: &[u8],
        pkg: &frost::SigningPackage,
        randomizer: &[u8],
    ) -> Result<frost::round2::SignatureShare, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }

        // 1. INDEPENDENTLY render what this PCZT pays — from the bytes, not any claim.
        self.require_ready()?;
        let view = wysiwys::describe_pczt(pczt, self.fvk()?).map_err(SignerError::Other)?;
        // The PCZT carries a branch ID, not the requested target height itself.
        let height = zcash_protocol::consensus::BlockHeight::from_u32(params.target_height);
        let branch = match self.network {
            Network::Regtest => {
                zcash_protocol::consensus::BranchId::for_height(&crate::candidate::Regtest, height)
            }
            Network::Testnet => zcash_protocol::consensus::BranchId::for_height(
                &zcash_protocol::consensus::TEST_NETWORK,
                height,
            ),
        };
        if view.to != params.recipient.to_raw_address_bytes()
            || view.amount_zat != u64::from(params.amount)
            || view.memo.as_slice() != params.memo.as_array().as_slice()
            || view.expiry_height != params.expiry_height
            || view.network_branch_id != u32::from(branch)
        {
            return Err(SignerError::Other(
                "candidate payment differs from requested payment".into(),
            ));
        }
        if !view.fee_verified {
            return Err(SignerError::FeeUnverified("candidate fee is unverified".into()));
        }
        let parsed = pczt::Pczt::parse(pczt)
            .map_err(|e| SignerError::Other(format!("pczt parse: {e:?}")))?;
        let actions = parsed.ironwood().actions().len();
        use zcash_primitives::transaction::fees::zip317::{GRACE_ACTIONS, MARGINAL_FEE};
        let zip317_fee = u64::try_from(actions.max(GRACE_ACTIONS))
            .ok()
            .and_then(|count| u64::from(MARGINAL_FEE).checked_mul(count))
            .ok_or_else(|| SignerError::Other("candidate action count is too large".into()))?;
        if view.fee_zat != zip317_fee {
            return Err(SignerError::Other(
                "candidate fee differs from ZIP-317 fee".into(),
            ));
        }
        self.rendered.insert(cand.attempt_id, view.clone());

        // 2. Recompute the sighash from the SAME bytes, so consent binds to it (not just the view).
        let local_sighash = wysiwys::checked_sighash_of_pczt(pczt, self.fvk()?)?;

        // 3. The member decides on THAT render + candidate + sighash (policy/biometric).
        //    Refusal is first-class.
        let decided = self.approved == Some((cand.payment_id, local_sighash));
        if !decided && !(self.approval)(&ApprovalRequest { candidate: cand, sighash: local_sighash, view: &view }) {
            return Err(SignerError::MemberRefused);
        }
        self.approved = Some((cand.payment_id, local_sighash));

        // 4. BINDING (the must-fix): require the SigningPackage to name exactly that sighash.
        //    Done BEFORE the nonce/share is touched, so a mismatched package can never consume
        //    a nonce or release a share.
        if pkg.message().as_slice() != local_sighash {
            return Err(SignerError::SighashMismatch);
        }

        // 4. Only now: unseal the share and produce the rerandomized partial under the
        //    single-use, crash-safe nonce rules. `randomizer` is the 32-byte seed.
        let seed: [u8; 32] = randomizer
            .try_into()
            .map_err(|_| SignerError::Other("randomizer seed is not 32 bytes".into()))?;
        let id = self.nonce_id(cand);
        let kp = self.open_key()?;
        let share = self.nonces.sign_and_burn(
            &id, &self.se, pkg, &kp, &seed, self.nonce_witness.as_deref_mut(), &|| false,
        );
        // The key is wiped here, before the partial leaves this call.
        drop(kp);
        share.map_err(|e| SignerError::Other(e.to_string()))
    }

    fn rendered_payment(
        &self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<PaymentView, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        self.rendered
            .get(&cand.attempt_id)
            .cloned()
            .ok_or_else(|| SignerError::Other("no rendered payment for candidate".into()))
    }

    fn disconnect(&mut self, session: Session) -> Result<(), Self::Error> {
        if self.session.as_ref() == Some(&session) {
            self.session = None;
        }
        Ok(())
    }
}


#[cfg(test)]
#[path = "local_setup_tests.rs"]
mod setup_tests;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::candidate::{
        alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest,
    };
    use crate::signer::secure_element::SoftwareSecureElement;
    use crate::zip2005;
    use orchard::keys::Scope;
    use orchard::note::{Note, RandomSeed, Rho};
    use orchard::value::NoteValue;
    use orchard::NoteVersion;
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    const SPEND_VALUE: u64 = 625_000_000;
    const AMOUNT: u64 = 40_000_000;

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-local-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// A one-note candidate paying `fvk.address_at(7)` from `fvk`, under `member`+`peer`
    /// commitments and a rerandomization `seed`. `finalize` toggles IO finalization, which
    /// is what populates the `rcv` trapdoors (→ `fee_verified`).
    ///
    /// Returns (pczt_bytes, signing_package, seed) where the package's message is the real
    /// sighash of the bytes.
    #[allow(clippy::type_complexity)]
    pub(crate) fn candidate_and_package(
        fvk: &FullViewingKey,
        key: &frost::keys::KeyPackage,
        public: &frost::keys::PublicKeyPackage,
        peer_id: frost::Identifier,
        peer_commit: frost::round1::SigningCommitments,
        own_commit: frost::round1::SigningCommitments,
        finalize: bool,
    ) -> (Vec<u8>, frost::SigningPackage, [u8; 32]) {
        candidate_with_fee(fvk, key, public, peer_id, peer_commit, own_commit, finalize, 0)
    }

    struct FixedFee(Zatoshis);

    impl zcash_primitives::transaction::fees::FeeRule for FixedFee {
        type Error = std::convert::Infallible;

        fn fee_required<P: zcash_protocol::consensus::Parameters>(
            &self,
            _params: &P,
            _target_height: zcash_protocol::consensus::BlockHeight,
            _transparent_inputs: impl IntoIterator<Item = zcash_primitives::transaction::fees::transparent::InputSize>,
            _transparent_outputs: impl IntoIterator<Item = usize>,
            _sapling_inputs: usize,
            _sapling_outputs: usize,
            _orchard_actions: usize,
            _ironwood_actions: usize,
        ) -> Result<Zatoshis, Self::Error> {
            Ok(self.0)
        }
    }

    /// [`candidate_and_package`] paying `extra_fee_zat` above the ZIP-317 fee: a balanced,
    /// correctly committed PCZT a dishonest proposer can build with a fixed fee rule.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn candidate_with_fee(
        fvk: &FullViewingKey,
        key: &frost::keys::KeyPackage,
        public: &frost::keys::PublicKeyPackage,
        peer_id: frost::Identifier,
        peer_commit: frost::round1::SigningCommitments,
        own_commit: frost::round1::SigningCommitments,
        finalize: bool,
        extra_fee_zat: u64,
    ) -> (Vec<u8>, frost::SigningPackage, [u8; 32]) {
        // Commitment set drives the seed-derived alpha used to randomize the single spend.
        let mut set = BTreeMap::new();
        set.insert(*key.identifier(), own_commit);
        set.insert(peer_id, peer_commit);
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &set,
            rand_core::OsRng,
        )
        .unwrap();
        let alpha = alpha_from_canonical_bytes(
            &params.randomizer().serialize().as_slice().try_into().unwrap(),
        )
        .unwrap();

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
        let params = payment_params(fvk);
        let mut inputs = CandidateInputs {
            vault_fvk: fvk,
            notes: vec![note],
            recipient: params.recipient,
            amount: params.amount,
            memo: params.memo,
            change: Zatoshis::ZERO,
            target_height: params.target_height,
            expiry_height: params.expiry_height,
        };
        let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
        inputs.change = Zatoshis::const_from_u64(SPEND_VALUE - AMOUNT - fee - extra_fee_zat);
        let built = if extra_fee_zat == 0 {
            build_candidate(
                &Regtest,
                &inputs,
                &[alpha],
                rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
            )
            .unwrap()
        } else {
            use zcash_primitives::transaction::builder::{BundlePadding, DeferredPcztBuilder};
            use zcash_protocol::consensus::BlockHeight;

            // A proposer can build a balanced PCZT with an arbitrary fixed fee.
            let mut builder = DeferredPcztBuilder::new::<std::convert::Infallible>(
                Regtest,
                BlockHeight::from_u32(inputs.target_height),
                BundlePadding::DEFAULT,
                BundlePadding::DEFAULT,
            )
            .unwrap()
            .with_expiry_height(BlockHeight::from_u32(inputs.expiry_height));
            builder
                .add_ironwood_spend_with_alpha::<std::convert::Infallible>(fvk.clone(), note, alpha)
                .unwrap();
            builder
                .add_ironwood_output::<std::convert::Infallible>(
                    None,
                    inputs.recipient,
                    inputs.amount,
                    inputs.memo,
                )
                .unwrap();
            builder
                .add_ironwood_output::<std::convert::Infallible>(
                    None,
                    fvk.address_at(0u64, Scope::Internal),
                    inputs.change,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .build_for_pczt(
                    rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
                    &FixedFee(Zatoshis::const_from_u64(fee + extra_fee_zat)),
                )
                .unwrap()
        };
        let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).unwrap();
        let pczt = if finalize {
            pczt::roles::io_finalizer::IoFinalizer::new(pczt)
                .finalize_io()
                .unwrap()
        } else {
            pczt
        };
        let bytes = pczt.serialize().unwrap();
        let sighash = wysiwys::sighash_of_pczt(&bytes, fvk).unwrap();
        let pkg = frost::SigningPackage::new(set, &sighash);
        let seed_bytes: [u8; 32] = seed.as_slice().try_into().unwrap();
        (bytes, pkg, seed_bytes)
    }

    /// A 2-of-3 dealer keyset and the vault FVK derived from its group verifying key.
    fn dealer_vault() -> (
        BTreeMap<frost::Identifier, frost::keys::SecretShare>,
        frost::keys::PublicKeyPackage,
        FullViewingKey,
    ) {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        (shares, public, fvk)
    }

    fn connect_signer<SE: SecureElement>(signer: &mut LocalSigner<SE>) -> Session {
        signer
            .connect("http://coordinator.test", Network::Regtest, b"challenge-1")
            .unwrap()
            .session
    }

    /// The coordinator's public request every test candidate is built from.
    pub(crate) fn payment_params(fvk: &FullViewingKey) -> crate::signer::PublicPaymentParams {
        crate::signer::PublicPaymentParams {
            recipient: fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::const_from_u64(AMOUNT),
            memo: MemoBytes::from_bytes(b"loki bind").unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        }
    }

    /// A ready member-1 signer with a live round-1 commitment for `attempt`, plus member 2's
    /// key and commitment that complete the package.
    #[allow(clippy::type_complexity)]
    fn committed_signer(
        attempt: u8,
    ) -> (
        LocalSigner<SoftwareSecureElement>,
        Session,
        CandidateRef,
        frost::keys::KeyPackage,
        frost::keys::KeyPackage,
        frost::round1::SigningCommitments,
        frost::round1::SigningCommitments,
        frost::keys::PublicKeyPackage,
        FullViewingKey,
    ) {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [attempt; 32],
        };
        let own = signer.sign_commit(&session, &cand).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let (_peer_nonce, peer) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        (signer, session, cand, key1, key2, own, peer, public, fvk)
    }

    #[test]
    fn sign_approve_refuses_payment_request_mismatch_without_burning_nonce() {
        let (mut signer, session, cand, key1, key2, own, peer, public, fvk) = committed_signer(8);
        let (pczt, pkg, seed) =
            candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);
        let expected = payment_params(&fvk);
        let mismatches = [
            crate::signer::PublicPaymentParams {
                recipient: fvk.address_at(8u64, Scope::External),
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                amount: Zatoshis::const_from_u64(AMOUNT + 1),
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                memo: MemoBytes::from_bytes(b"different memo").unwrap(),
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                expiry_height: expected.expiry_height + 1,
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                target_height: 0,
                ..expected.clone()
            },
        ];
        for params in &mismatches {
            let refused = signer.sign_approve(&session, &cand, params, &pczt, &pkg, &seed);
            assert!(
                matches!(&refused, Err(SignerError::Other(message)) if message == "candidate payment differs from requested payment"),
                "got {refused:?}"
            );
            assert_eq!(
                signer.nonces.state(&signer.nonce_id(&cand)),
                crate::signer::nonce::NonceState::Committed
            );
        }
        signer
            .sign_approve(&session, &cand, &expected, &pczt, &pkg, &seed)
            .expect("matching request may sign");
    }

    // A forged-VALUE candidate: a dishonest proposer builds a balanced, correctly committed
    // PCZT whose fee is 1 ZEC above ZIP-317 (the excess comes out of change). Every value
    // binding holds, so only the fee rule catches it — before approval or the nonce.
    #[test]
    fn sign_approve_refuses_valid_high_fee_before_approval_or_nonce_use() {
        let (mut signer, session, cand, key1, key2, own, peer, public, fvk) = committed_signer(18);
        let (pczt, pkg, seed) = candidate_with_fee(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer,
            own,
            true,
            100_000_000,
        );
        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        assert!(view.fee_verified);
        assert_eq!(view.fee_zat, 100_010_000);
        signer.approval = Box::new(|_| panic!("high fee reached approval"));

        let result = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(
            matches!(&result, Err(SignerError::Other(message)) if message == "candidate fee differs from ZIP-317 fee"),
            "got {result:?}"
        );
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed
        );
    }

    // A forged-FEE candidate: stripping every `rcv` trapdoor leaves the declared values
    // unbound to `cv_net`, so the rendered fee is a self-declared number (`fee_verified ==
    // false`). The signer refuses before approval, and the nonce stays unused.
    #[test]
    fn sign_approve_refuses_unverified_fee_before_approval_or_nonce_use() {
        let (mut signer, session, cand, key1, key2, own, peer, public, fvk) = committed_signer(19);
        let (pczt, pkg, seed) =
            candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);
        let pczt = pczt::roles::redactor::Redactor::new(pczt::Pczt::parse(&pczt).unwrap())
            .redact_ironwood_with(|mut bundle| bundle.redact_actions(|mut action| action.clear_rcv()))
            .finish()
            .serialize()
            .unwrap();
        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        assert!(!view.fee_verified);
        signer.approval = Box::new(|_| panic!("unverified fee reached approval"));

        let result = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(
            matches!(&result, Err(SignerError::FeeUnverified(_))),
            "got {result:?}"
        );
        assert_eq!(result.unwrap_err().to_string(), "candidate fee is unverified");
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed
        );
    }

    fn signer_with_dealer_share(
        id: u16,
        shares: &BTreeMap<frost::Identifier, frost::keys::SecretShare>,
        public: &frost::keys::PublicKeyPackage,
        fvk: &FullViewingKey,
    ) -> (LocalSigner<SoftwareSecureElement>, frost::keys::KeyPackage) {
        let ident = frost::Identifier::try_from(id).unwrap();
        let kp = frost::keys::KeyPackage::try_from(shares.get(&ident).unwrap().clone()).unwrap();
        let signer = LocalSigner::with_sealed_share(
            id,
            2,
            3,
            [id as u8; 32],
            "test vault".into(),
            Network::Regtest,
            SoftwareSecureElement::generate(),
            &kp.serialize().unwrap(),
            public.serialize().unwrap(),
            fvk.clone(),
            tempdir(&format!("m{id}")),
            Box::new(|_view| true),
        )
        .unwrap();
        (signer, kp)
    }

    // (a) sign_approve REFUSES when pkg.message() != sighash(rendered pczt), and SUCCEEDS
    //     when they match. This is the must-fix WYSIWYS→signature binding (threat §5.4).
    #[test]
    fn sign_approve_binds_package_message_to_rendered_sighash() {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };

        // Round 1 inside the signer: it persists the nonce and gives us the commitment.
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        // A peer commitment to populate the package.
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let (_n2, peer_commit) =
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);

        let (pczt, good_pkg, seed) = candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer_commit,
            own_commit,
            true,
        );

        // Tampered package: same commitments, WRONG message (not the pczt's sighash).
        let bad_pkg = frost::SigningPackage::new(
            good_pkg.signing_commitments().clone(),
            &[0xabu8; 32],
        );
        let refused = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &bad_pkg, &seed);
        assert!(
            matches!(refused, Err(SignerError::SighashMismatch)),
            "a package naming a different sighash must be REFUSED, got {refused:?}"
        );
        // And the nonce was NOT burned by the refused attempt.
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed,
            "refused binding must not touch the nonce"
        );

        // Matching package: binding passes, a real partial signature is produced.
        let share = signer
            .sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &good_pkg, &seed)
            .expect("matching sighash must sign");
        assert_eq!(share.serialize().len(), 32);
    }

    /// Both witnesses as one first-writer-wins claim set, like two relay mailboxes.
    #[derive(Clone, Default)]
    struct Witnesses(std::sync::Arc<std::sync::Mutex<Vec<[u8; 32]>>>, bool);

    impl NonceWitness for Witnesses {
        fn pins(&self) -> crate::signing_session::WitnessPins {
            [([1; 32], [2; 32], [3; 32]), ([4; 32], [5; 32], [6; 32])]
        }
        fn claim(&mut self, cid: [u8; 32], record: &[u8]) -> Result<(), String> {
            let mut claimed = self.0.lock().unwrap();
            if self.1 || claimed.contains(&cid) || record[..32] != cid {
                return Err("nonce already claimed; start a new signing attempt".into());
            }
            claimed.push(cid);
            Ok(())
        }
    }

    // The external witnesses gate every fresh share: a refused claim releases nothing and
    // keeps the nonce; a nonce whose local files were rolled back after it signed cannot
    // sign again, because its claim is already taken.
    #[test]
    fn nonce_witness_claim_gates_the_share_and_blocks_rolled_back_nonces() {
        let (shares, public, fvk) = dealer_vault();
        let key1 = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(1u16).unwrap()].clone()).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(2u16).unwrap()].clone()).unwrap();
        let nonce_dir = tempdir("witness-m1");
        let mut signer = LocalSigner::with_sealed_share(
            1, 2, 3, [1; 32], "test vault".into(), Network::Regtest, SoftwareSecureElement::generate(),
            &key1.serialize().unwrap(), public.serialize().unwrap(), fvk.clone(), nonce_dir.clone(),
            Box::new(|_| true),
        )
        .unwrap();
        let witnesses = Witnesses::default();
        signer.set_nonce_witness(Box::new(Witnesses(witnesses.0.clone(), true)));
        let session = connect_signer(&mut signer);
        let cand = CandidateRef { vault_id: [1; 32], payment_id: [7; 32], attempt_id: [9; 32] };
        let own = signer.sign_commit(&session, &cand).unwrap();
        let (_n2, peer) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, seed) = candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);
        let id = signer.nonce_id(&cand);

        // A refusing witness: no share, and the nonce is neither burned nor consumed.
        let refused = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(matches!(&refused, Err(SignerError::Other(e)) if e.contains("nonce witness refused")), "{refused:?}");
        assert_eq!(signer.nonces.state(&id), crate::signer::nonce::NonceState::Committed);

        // Two working witnesses: the claim is taken once and the share is released.
        signer.set_nonce_witness(Box::new(witnesses.clone()));
        let snapshot: Vec<_> = std::fs::read_dir(&nonce_dir).unwrap().flatten()
            .map(|e| (e.path(), std::fs::read(e.path()).unwrap())).collect();
        let share = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed).expect("claimed nonce signs");
        assert_eq!(witnesses.0.lock().unwrap().len(), 1);
        // An identical resend replays the recorded partial without a second claim.
        assert_eq!(signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed).unwrap(), share);
        assert_eq!(witnesses.0.lock().unwrap().len(), 1);

        // Roll the local nonce files back to before the burn: the witnesses refuse.
        for entry in std::fs::read_dir(&nonce_dir).unwrap().flatten() {
            std::fs::remove_file(entry.path()).unwrap();
        }
        for (path, bytes) in &snapshot {
            std::fs::write(path, bytes).unwrap();
        }
        assert_eq!(signer.nonces.state(&id), crate::signer::nonce::NonceState::Committed);
        let replayed = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(matches!(&replayed, Err(SignerError::Other(e)) if e.contains("already claimed")), "{replayed:?}");
    }

    // (a'') The browser `paymentReview` seam: it renders the candidate (describe_pczt) and
    //       INDEPENDENTLY recomputes the sighash (sighash_of_pczt) the exact same way the
    //       native path does, with NO share released. The recomputed sighash must equal the
    //       message a correct SigningPackage commits to, and a tampered candidate must not
    //       reproduce it (so sign_approve's binding would refuse to release a share).
    #[test]
    fn payment_review_recomputes_candidate_sighash_and_tamper_is_refused() {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [9u8; 32],
            attempt_id: [9u8; 32],
        };
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(
            shares.get(&frost::Identifier::try_from(2u16).unwrap()).unwrap().clone(),
        )
        .unwrap();
        let (_n2, peer_commit) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, _seed) = candidate_and_package(
            &fvk, &key1, &public, *key2.identifier(), peer_commit, own_commit, true,
        );

        // paymentReview = describe + recompute-sighash, both over the vault viewing key.
        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        let sighash = wysiwys::sighash_of_pczt(&pczt, &fvk).unwrap();
        assert_eq!(view.amount_zat, AMOUNT);
        assert!(view.fee_verified);
        // The recomputed sighash is EXACTLY what the real SigningPackage commits to.
        assert_eq!(pkg.message().as_slice(), sighash);

        // Flip a byte: the candidate no longer reproduces that sighash (refused outright, or a
        // different hash that sign_approve's `pkg.message() == sighash` gate would reject).
        let mut bad = pczt.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        match wysiwys::sighash_of_pczt(&bad, &fvk) {
            Ok(h) => assert_ne!(h, sighash, "tampered candidate must not reproduce the sighash"),
            Err(_) => {}
        }
    }

    // (a') a member refusal is first-class and does not consume the nonce.
    #[test]
    fn member_refusal_is_first_class_and_leaves_nonce() {
        let (shares, public, fvk) = dealer_vault();
        let ident = frost::Identifier::try_from(1u16).unwrap();
        let key1 = frost::keys::KeyPackage::try_from(shares.get(&ident).unwrap().clone()).unwrap();
        let mut signer = LocalSigner::with_sealed_share(
            1,
            2,
            3,
            [1u8; 32],
            "test vault".into(),
            Network::Regtest,
            SoftwareSecureElement::generate(),
            &key1.serialize().unwrap(),
            public.serialize().unwrap(),
            fvk.clone(),
            tempdir("refuse"),
            Box::new(|_view| false), // member declines
        )
        .unwrap();
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let (_n2, peer_commit) =
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, seed) = candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer_commit,
            own_commit,
            true,
        );
        let out = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(matches!(out, Err(SignerError::MemberRefused)));
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed,
        );
    }

    // (c) fee integrity: the rendered fee is only reported as trusted when every action's
    //     declared spend/output value is BOUND to its `cv_net` value commitment via `rcv`
    //     (`verify_cv_net`) — the same binding the sighash commits to. Here the real
    //     candidate carries `rcv`, so the binding runs AND passes: the fee is verified and
    //     equals total_in - total_out, not a self-declared number.
    //
    //     The opposite (`fee_verified == false`) is the guard for a PCZT whose `rcv` is
    //     absent or whose values do not match the commitment; the redactor reaches it in
    //     `sign_approve_refuses_unverified_fee_before_approval_or_nonce_use`.
    #[test]
    fn fee_is_verified_when_values_bind_to_commitments() {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [1u8; 32],
            attempt_id: [1u8; 32],
        };
        let own = signer.sign_commit(&session, &cand).unwrap();
        let (_a, peer) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, _pkg, _seed) =
            candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);

        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        assert!(
            view.fee_verified,
            "a candidate whose values bind to cv_net must report a VERIFIED fee"
        );
        // The verified fee is the real spend-minus-output difference.
        assert_eq!(view.fee_zat, SPEND_VALUE - AMOUNT - view.change_zat);
        assert!(view.fee_zat > 0);

        // Same bytes, independent check: every action's cv_net binds its declared values.
        // If any did not, describe_pczt would have cleared fee_verified above.
        let parsed = pczt::Pczt::parse(&pczt).unwrap();
        let mut all_bound = true;
        pczt::roles::verifier::Verifier::new(parsed)
            .with_ironwood::<String, _>(|bundle| {
                for action in bundle.actions() {
                    if action.verify_cv_net().is_err() {
                        all_bound = false;
                    }
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(all_bound, view.fee_verified);
    }

    // (U1) A LocalSigner built from an existing sealed vault member share (the real
    //      member_state::MemberState material) is signing-ready: it does round 1
    //      (sign_commit) and round 2 (sign_approve) on a candidate for the group key.
    #[test]
    fn signer_from_vault_member_can_sign_a_candidate() {
        use crate::member_state::{MemberState, Roster};
        use crate::network::VaultNetwork;

        let (shares, public, fvk) = dealer_vault();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let id2 = frost::Identifier::try_from(2u16).unwrap();
        let key1 = frost::keys::KeyPackage::try_from(shares.get(&id1).unwrap().clone()).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(shares.get(&id2).unwrap().clone()).unwrap();

        // Three member identities drive the certified roster; the signer is member 1.
        let identities: Vec<Identity> = (1..=3).map(Identity::new).collect();
        let vault = [7u8; 32];
        let members: Vec<_> = identities
            .iter()
            .map(|identity| {
                let peer = identity.public();
                serde_json::json!({
                    "id": peer.id,
                    "signing": hex::encode(peer.signing),
                    "encryption": hex::encode(peer.encryption),
                })
            })
            .collect();
        let roster = Roster::from_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "vault": hex::encode(vault),
                "threshold": 2,
                "members": members,
            }))
            .unwrap(),
        )
        .unwrap();
        let state = MemberState {
            vault,
            network: VaultNetwork::Regtest,
            birth_height: None,
            roster,
            identity: identities.into_iter().next().unwrap(),
            key: key1.clone(),
            public: public.clone(),
            fvk: fvk.clone(),
        };

        let mut signer = LocalSigner::from_vault_member(
            &state,
            SoftwareSecureElement::generate(),
            tempdir("from-vault-member"),
            Box::new(|_view| true),
        )
        .unwrap();
        let session = connect_signer(&mut signer);

        // list_vaults exposes the loaded vault; member 1 holds a share for it.
        let vaults = signer.list_vaults(&session).unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].vault_id, vault);

        let cand = CandidateRef {
            vault_id: vault,
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        let (_n2, peer_commit) =
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, seed) = candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer_commit,
            own_commit,
            true,
        );
        let share = signer
            .sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed)
            .expect("vault-member signer must produce a partial signature");
        assert_eq!(share.serialize().len(), 32);
    }
}
