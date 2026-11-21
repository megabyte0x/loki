use crate::{ClientError, ClientResult};
use ed25519_dalek::{Signer, SigningKey};
use hpke::{kem::X25519HkdfSha256, Deserializable, Kem, Serializable};
use loki_relay_protocol::types::MemberPublic;
use zeroize::Zeroizing;

pub struct CommIdentity {
    id: u16,
    pub(crate) signing: SigningKey,
    pub(crate) encryption: <X25519HkdfSha256 as Kem>::PrivateKey,
}

impl CommIdentity {
    pub fn from_serialized(bytes: &[u8; 66]) -> ClientResult<Self> {
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        if !(1..=loki_relay_protocol::types::MAX_MEMBERS).contains(&id) {
            return Err(ClientError::Identity);
        }
        let mut signing_seed = Zeroizing::new([0u8; 32]);
        signing_seed.copy_from_slice(&bytes[2..34]);
        Ok(Self {
            id,
            signing: SigningKey::from_bytes(&signing_seed),
            encryption: <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&bytes[34..])?,
        })
    }

    pub fn public(&self) -> MemberPublic {
        let mut encryption = [0u8; 32];
        X25519HkdfSha256::sk_to_pk(&self.encryption).write_exact(&mut encryption);
        MemberPublic {
            id: self.id,
            signing: self.signing.verifying_key().to_bytes(),
            encryption,
        }
    }

    pub fn nonce_claim_proof(
        &self,
        vault: [u8; 32],
        route: &loki_relay_protocol::types::RelayRoute,
        cid: [u8; 32],
        challenge: [u8; 32],
        record: &[u8],
    ) -> loki_relay_protocol::nonce::ClaimProof {
        use loki_relay_protocol::nonce::{self, ClaimProof, Claimant};
        let claimant = Claimant {
            vault,
            slot: self.id,
            key: self.signing.verifying_key().to_bytes(),
        };
        let signature = self
            .signing
            .sign(&nonce::claim_input(
                claimant,
                &route.pin,
                route.mailbox,
                cid,
                challenge,
                record,
            ))
            .to_bytes();
        ClaimProof {
            claimant,
            signature,
        }
    }
}
