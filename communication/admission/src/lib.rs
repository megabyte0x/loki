use ed25519_dalek::{Signature, VerifyingKey};
use loki_relay_protocol::{
    canonical::{self, Value},
    types::Id32,
    WireError,
};
use sha2::{Digest, Sha256};
use std::fmt;

pub type AdmissionResult<T> = Result<T, AdmissionError>;
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum AdmissionError {
    Enrollment,
    Identity,
    Conflict,
    Expired,
    Terminal,
    Quota,
    Malformed,
    Storage,
    StorageBusy,
    Unavailable,
}
impl AdmissionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::Identity => "identity",
            Self::Conflict => "conflict",
            Self::Expired => "expired",
            Self::Terminal => "terminal",
            Self::Quota => "quota",
            Self::Malformed => "malformed",
            Self::Storage | Self::StorageBusy => "storage",
            Self::Unavailable => "unavailable",
        }
    }
}
impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for AdmissionError {}
impl From<WireError> for AdmissionError {
    fn from(_: WireError) -> Self {
        Self::Malformed
    }
}
impl From<rusqlite::Error> for AdmissionError {
    fn from(error: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        match error.sqlite_error_code() {
            Some(
                ErrorCode::DatabaseBusy
                | ErrorCode::DatabaseLocked
                | ErrorCode::FileLockingProtocolFailed,
            ) => Self::StorageBusy,
            _ => Self::Storage,
        }
    }
}
impl From<std::io::Error> for AdmissionError {
    fn from(_: std::io::Error) -> Self {
        Self::Storage
    }
}
impl From<ed25519_dalek::SignatureError> for AdmissionError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Self::Identity
    }
}

pub struct EnrollmentVerifier {
    issuer: Option<Id32>,
}
pub struct CreationBudget {
    grant_id: Id32,
    device_key: Id32,
    expires: u64,
    max_creations: u64,
    mailbox_budget: u64,
    config_digest: Id32,
    grant_digest: Id32,
}
impl CreationBudget {
    pub fn grant_id(&self) -> &Id32 {
        &self.grant_id
    }
    pub fn device_key(&self) -> &Id32 {
        &self.device_key
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn max_creations(&self) -> u64 {
        self.max_creations
    }
    pub fn mailbox_budget(&self) -> u64 {
        self.mailbox_budget
    }
    pub fn config_digest(&self) -> &Id32 {
        &self.config_digest
    }
    pub fn grant_digest(&self) -> &Id32 {
        &self.grant_digest
    }
}
fn fields(value: &Value, count: usize) -> AdmissionResult<&[Value]> {
    match value {
        Value::Array(f) if f.len() == count => Ok(f),
        _ => Err(AdmissionError::Malformed),
    }
}
fn bytes(value: &Value) -> AdmissionResult<&[u8]> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(AdmissionError::Malformed),
    }
}
fn id(value: &Value) -> AdmissionResult<Id32> {
    bytes(value)?
        .try_into()
        .map_err(|_| AdmissionError::Malformed)
}
fn number(value: &Value) -> AdmissionResult<u64> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| AdmissionError::Malformed),
        _ => Err(AdmissionError::Malformed),
    }
}
fn signature_input(domain: &[u8], body: &[u8]) -> AdmissionResult<Vec<u8>> {
    let size = u32::try_from(body.len()).map_err(|_| AdmissionError::Malformed)?;
    let mut input = domain.to_vec();
    input.extend_from_slice(&size.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}
impl EnrollmentVerifier {
    pub fn new(issuer: Option<Id32>) -> Self {
        Self { issuer }
    }
    pub fn verify(
        &self,
        grant_bytes: &[u8],
        device_key: &Id32,
        now: u64,
    ) -> AdmissionResult<CreationBudget> {
        let issuer = self.issuer.ok_or(AdmissionError::Enrollment)?;
        let package = canonical::decode(grant_bytes, 4096)?;
        let f = fields(&package, 2)?;
        let body = bytes(&f[0])?;
        let signature = bytes(&f[1])?;
        if signature.len() != 64 {
            return Err(AdmissionError::Enrollment);
        }
        VerifyingKey::from_bytes(&issuer)?
            .verify_strict(
                &signature_input(b"Loki_Setup_Enrollment_v1\0", body)?,
                &Signature::from_slice(signature)?,
            )
            .map_err(|_| AdmissionError::Enrollment)?;
        let value = canonical::decode(body, 2048)?;
        let f = fields(&value, 7)?;
        if number(&f[0])? != 1 {
            return Err(AdmissionError::Enrollment);
        }
        let budget = CreationBudget {
            grant_id: id(&f[1])?,
            device_key: id(&f[2])?,
            expires: number(&f[3])?,
            max_creations: number(&f[4])?,
            mailbox_budget: number(&f[5])?,
            config_digest: id(&f[6])?,
            grant_digest: Sha256::digest(grant_bytes).into(),
        };
        if budget.device_key != *device_key
            || budget.expires <= now
            || budget.expires > i64::MAX as u64
            || !(1..=100).contains(&budget.max_creations)
            || !(1..=2400).contains(&budget.mailbox_budget)
            || budget.grant_id == [0; 32]
        {
            return Err(AdmissionError::Enrollment);
        }
        Ok(budget)
    }
}
mod store;
pub use store::{AdmissionStore, ProvisionIntent};
pub mod http;
mod provision;
pub use provision::{OwnedProvisioner, ProvisionProgress};
