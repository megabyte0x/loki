//! A relay's durable, first-writer-wins claim on one FROST nonce commitment.
use crate::{
    canonical::{self, Value},
    types::{Id32, RelayPin},
    WireError, WireResult,
};
use sha2::{Digest, Sha256};

pub const SIGNATURE_DOMAIN: &[u8] = b"Loki_Relay_Nonce_v1\0";
pub const MAX_RECORD: usize = 65_536;
pub const CLAIM_SCHEME: &str = "LokiNonce ";
pub const CLAIM_PROOF_LEN: usize = 130;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Claimant {
    pub vault: Id32,
    pub slot: u16,
    pub key: Id32,
}

pub struct ClaimProof {
    pub claimant: Claimant,
    pub signature: [u8; 64],
}

impl ClaimProof {
    pub fn to_bytes(&self) -> [u8; CLAIM_PROOF_LEN] {
        let mut raw = [0; CLAIM_PROOF_LEN];
        raw[..32].copy_from_slice(&self.claimant.vault);
        raw[32..34].copy_from_slice(&self.claimant.slot.to_be_bytes());
        raw[34..66].copy_from_slice(&self.claimant.key);
        raw[66..].copy_from_slice(&self.signature);
        raw
    }

    pub fn from_bytes(raw: [u8; CLAIM_PROOF_LEN]) -> Self {
        Self {
            claimant: Claimant {
                vault: raw[..32].try_into().unwrap(),
                slot: u16::from_be_bytes(raw[32..34].try_into().unwrap()),
                key: raw[34..66].try_into().unwrap(),
            },
            signature: raw[66..].try_into().unwrap(),
        }
    }
}

/// This authorization is usable only for this enrolled vault slot, witness, and exact claim.
/// CID binds the public FROST commitment; the relay keeps authenticated CIDs slot-scoped
/// so another enrolled signer cannot consume one by submitting the same opaque ID.
pub fn claim_input(
    who: Claimant,
    pin: &RelayPin,
    mailbox: Id32,
    cid: Id32,
    challenge: Id32,
    record: &[u8],
) -> Vec<u8> {
    let mut input = b"Loki_Relay_NonceClaim_v1\0".to_vec();
    input.extend_from_slice(&who.slot.to_be_bytes());
    for field in [
        who.vault,
        who.key,
        pin.key,
        pin.run,
        mailbox,
        cid,
        challenge,
        Sha256::digest(record).into(),
    ] {
        input.extend_from_slice(&field);
    }
    input
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceReceipt {
    pub pin: RelayPin,
    pub mailbox: Id32,
    pub vault: Id32,
    pub slot: u16,
    pub cid: Id32,
    pub record_hash: Id32,
    pub challenge: Id32,
    pub created: bool,
}

pub fn encode_body(receipt: &NonceReceipt) -> WireResult<Vec<u8>> {
    canonical::encode(&Value::Array(vec![
        Value::Integer(2.into()),
        Value::Bytes(receipt.pin.key.to_vec()),
        Value::Bytes(receipt.pin.run.to_vec()),
        Value::Bytes(receipt.mailbox.to_vec()),
        Value::Bytes(receipt.cid.to_vec()),
        Value::Bytes(receipt.record_hash.to_vec()),
        Value::Bytes(receipt.challenge.to_vec()),
        Value::Integer(u64::from(receipt.created).into()),
        Value::Bytes(receipt.vault.to_vec()),
        Value::Integer(receipt.slot.into()),
    ]))
}

pub fn decode_body(raw: &[u8]) -> WireResult<NonceReceipt> {
    let value = canonical::decode(raw, 256)?;
    let Value::Array(fields) = value else {
        return Err(WireError::Schema);
    };
    if fields.len() != 10 || fields[0] != Value::Integer(2.into()) {
        return Err(WireError::Schema);
    }
    let id = |index: usize| -> WireResult<Id32> {
        let Value::Bytes(bytes) = &fields[index] else {
            return Err(WireError::Schema);
        };
        bytes.as_slice().try_into().map_err(|_| WireError::Schema)
    };
    let created = match fields[7] {
        Value::Integer(n) if n == 0.into() => false,
        Value::Integer(n) if n == 1.into() => true,
        _ => return Err(WireError::Schema),
    };
    let Value::Integer(slot) = fields[9] else {
        return Err(WireError::Schema);
    };
    Ok(NonceReceipt {
        pin: RelayPin {
            key: id(1)?,
            run: id(2)?,
        },
        mailbox: id(3)?,
        vault: id(8)?,
        slot: u16::try_from(i128::from(slot)).map_err(|_| WireError::Schema)?,
        cid: id(4)?,
        record_hash: id(5)?,
        challenge: id(6)?,
        created,
    })
}

pub fn signature_input(body: &[u8]) -> WireResult<Vec<u8>> {
    let length = u32::try_from(body.len()).map_err(|_| WireError::Bounds)?;
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 4 + body.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}
