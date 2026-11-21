mod operator_config;
pub use operator_config::{validate_endpoint, validate_peer_destination, OperatorSet, ServiceLimits};
mod crypto;
pub use crypto::{open_record, seal_record, SealContext, SealDomain};
mod descriptor;
pub use descriptor::{
    accept_descriptor, open_descriptor, seal_descriptor, AuthenticatedDescriptor, ClientConfig,
    Descriptor, DescriptorRelay, OwnerInbox, Secret32,
};
mod identity;
mod message;
pub use message::{authenticate, sign_message, AuthenticatedMessage};
mod transfer;
pub use transfer::{
    prepare_outbox, AuthenticatedTransfer, CompleteSource, ManifestRequirement, PreparedOutbox,
    RecipientObjects, RootInspection, SignedManifest, TransferAssembler,
};

pub use identity::CommIdentity;

use loki_relay_protocol::WireError;
use std::fmt;

pub type ClientResult<T> = Result<T, ClientError>;

#[derive(Clone, Eq, PartialEq)]
pub enum ClientError {
    Wire(WireError),
    Crypto,
    Identity,
    Config,
    MissingObjects(Vec<[u8; 32]>),
    SetupAgreementPending,
    Storage,
    Capacity,
    Transport,
    Receipt,
    Conflict,
    /// Entries cursor is ahead of retained history. The caller keeps its cursor.
    Cursor,
}

impl ClientError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Wire(_) => "wire",
            Self::Crypto => "crypto",
            Self::Identity => "identity",
            Self::Config => "config",
            Self::MissingObjects(_) => "missing_objects",
            Self::SetupAgreementPending => "setup_agreement_pending",
            Self::Storage => "storage",
            Self::Capacity => "capacity",
            Self::Transport => "transport",
            Self::Receipt => "receipt",
            Self::Conflict => "conflict",
            Self::Cursor => "cursor",
        }
    }
}

impl From<WireError> for ClientError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<hpke::HpkeError> for ClientError {
    fn from(_: hpke::HpkeError) -> Self {
        Self::Crypto
    }
}

impl From<ed25519_dalek::SignatureError> for ClientError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Self::Crypto
    }
}

impl From<rusqlite::Error> for ClientError {
    fn from(error: rusqlite::Error) -> Self {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
            Self::Capacity
        } else {
            Self::Storage
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(_: std::io::Error) -> Self {
        Self::Storage
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(_: reqwest::Error) -> Self {
        Self::Transport
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl fmt::Debug for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ClientError {}

mod store;
pub use store::{
    AckLink, ClientStore, CommitDisposition, ConfigReference, DiagnosticSample, DownloadRejection,
    EarlyReceived, IncomingDependency, IncomingOriginal, JournalCapture, PendingDownload,
    RecoveryLogical, RecoveryRecipient, RecoveryRequirement, RecoveryUpload, ReferencePhase,
    RouteCursor, SourceRejection, StagedRequirement, StagedSource, StorePragmas,
};

mod http;
pub use http::{RelayHttp, VerifiedEntry, VerifiedPage, VerifiedReceipt};
mod inbox;
pub use inbox::{
    authenticate_staged, committed_readiness, poll_once, poll_transport, AuthenticatedCandidate,
    CandidateReadiness, DownloadOutcome, PrerequisiteStatus, QuarantineReason,
};
mod received;
pub use received::{prepare_received, received_status, reconcile_received, ReceivedStatus};
pub use tokio::runtime::Runtime as RelayRuntime;
pub use tokio::time::timeout as relay_timeout;

mod outbox;
mod retry;
pub use outbox::{outbox_intent_digest, upload_pending, DeliveryReport, ThirdPass, UploadPass};

mod setup;
pub use setup::sign_admission_request;
pub use setup::{
    sign_roster_acceptance, AcceptedSetupRoster, AuthenticatedSetupRecord, BootstrapContext,
    SetupInvite, SetupPolicy, SetupRecordIndex,
};
pub use setup::{verify_admission_reply, AdmissionHttp, AdmissionOutcome, VerifiedAdmissionReply};

mod setup_delivery;
mod setup_store;
pub use setup_delivery::{PreparedSetup, SetupAuthority, SetupTransport};
pub use setup_store::SetupStore;

pub use setup::SetupInboxDescriptor;

mod setup_network;
pub use setup_network::{join_all, SetupNet, SetupProgress, SetupRoutes};

pub use setup::{verify_terminal_notices, VerifiedTerminalNotices};
