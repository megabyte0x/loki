//! Signed, recipient-only transport for one DKG round-two share.
//! A public identity must be checked against the group's out-of-band roster first.
//!
//! Two round-two formats exist:
//! - v1 (`LOKIDKG1`, [`Identity::seal_round2`]) encrypts to the recipient's long-lived
//!   encryption key. Only the local transport (`loki_setup_member run`) still uses it.
//! - v2 (`LOKIDKG2`, [`Identity::seal_round2_v2`]) encrypts between two one-setup
//!   [`FreshKey`]s announced in the signed round-one bodies and binds the round-one
//!   transcript. The hosted engine and the new signer use only v2 (`crate::dkg_core`).

use crate::signing_session::{MessageKind, OpenedMessage, SessionContext};
use blake2b_simd::Params;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LOKIDKG1";

const MAGIC_V2: &[u8; 8] = b"LOKIDKG2";
/// v2 header: magic, vault, sender, recipient, round-one transcript, nonce, length.
const HEADER_V2: usize = 8 + 32 + 2 + 2 + 32 + 24 + 4;
const ROUND1_MAGIC: &[u8; 8] = b"LOKIR1V1";
const AGREEMENT_MAGIC: &[u8; 8] = b"LOKIAGV1";
const CERT_MAGIC: &[u8; 8] = b"LOKICRV1";
const BACKUP_MAGIC: &[u8; 8] = b"LOKIBKV1";
const FINAL_STATUS_MAGIC: &[u8; 8] = b"LOKIFSV1";
const HEADER: usize = 8 + 32 + 2 + 2 + 24 + 4;
const PUBLIC_HEADER: usize = 8 + 32 + 2 + 4;
const SIGNATURE: usize = 64;
const COURIER_PAYLOAD_LIMIT: usize = 64 * 1024;
/// Largest local courier envelope (encrypted round two, including its AEAD tag).
pub const MAX_COURIER_ENVELOPE: usize = HEADER + COURIER_PAYLOAD_LIMIT + 16 + SIGNATURE;
const SESSION_MAGIC: &[u8; 8] = b"LOKISGN1";
const SESSION_INNER: &[u8; 8] = b"LOKISGIP";
const SESSION_HEADER: usize = 8 + 1 + 24 + 4;
const SESSION_LIMIT: usize = SESSION_HEADER + 8 * 1024 * 1024 + 16;

/// A member's one-setup X25519 key for v2 round-two envelopes. Created with the
/// round-one contribution, announced in the signed round-one body, and removed once the
/// certificate state is saved.
pub struct FreshKey(StaticSecret);

impl FreshKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(OsRng))
    }

    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    /// These bytes must only be written inside a sealed checkpoint.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self(StaticSecret::from(*bytes))
    }
}

/// What a setup message is, read from its marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkgWireKind {
    /// Signed round-one body (`LOKIR1V1`), sent to every member.
    Round1,
    /// v2 recipient-encrypted, signed round-two envelope (`LOKIDKG2`).
    Round2,
    /// Signed certificate (`LOKICRV1`), sent to every member.
    Certificate,
    /// Signed backup receipt (`LOKIBKV1`), sent to every member.
    BackupReceipt,
}

/// A setup message as it leaves a signer: signed (round one, certificate, backup
/// receipt) or recipient-encrypted (round two). Only this module constructs it, and only
/// from bytes with a valid setup-message frame, so a signer cannot hand raw secret bytes
/// to the coordinator through the `Signer` seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgWire {
    kind: DkgWireKind,
    sender: u16,
    recipient: Option<u16>,
    bytes: Vec<u8>,
}

impl DkgWire {
    /// Frame-check `bytes` as a setup message. Signatures are not checked here; the
    /// receiving member verifies them against its roster.
    ///
    /// `pub` across the `loki-signer-core` → `loki-poc` seam (it was crate-private when
    /// both lived in one crate). The "only the signer constructs a DkgWire" guard is now a
    /// workspace-level convention; the wasm-bindgen API, not Rust visibility, is the
    /// boundary against untrusted JS callers.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        let kind = wire_kind(&bytes).ok_or("not a setup message")?;
        let sender = u16::from_be_bytes(bytes[40..42].try_into().unwrap());
        let recipient = if kind == DkgWireKind::Round2 {
            if bytes.len() < HEADER_V2 + 16 + SIGNATURE {
                return Err("invalid DKG envelope".into());
            }
            let size = u32::from_be_bytes(bytes[HEADER_V2 - 4..HEADER_V2].try_into().unwrap())
                as usize;
            if size > 64 * 1024 + 16 || bytes.len() != HEADER_V2 + size + SIGNATURE {
                return Err("invalid DKG envelope length".into());
            }
            Some(u16::from_be_bytes(bytes[42..44].try_into().unwrap()))
        } else {
            if bytes.len() < PUBLIC_HEADER + SIGNATURE {
                return Err("invalid setup message".into());
            }
            let size = u32::from_be_bytes(bytes[42..46].try_into().unwrap()) as usize;
            if size > 64 * 1024 || bytes.len() != PUBLIC_HEADER + size + SIGNATURE {
                return Err("invalid setup message length".into());
            }
            None
        };
        Ok(Self {
            kind,
            sender,
            recipient,
            bytes,
        })
    }

    pub fn kind(&self) -> DkgWireKind {
        self.kind
    }

    pub fn sender(&self) -> u16 {
        self.sender
    }

    /// `None` for messages sent to every member.
    pub fn recipient(&self) -> Option<u16> {
        self.recipient
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// The setup-message kind named by `bytes`' marker, if any.
pub fn wire_kind(bytes: &[u8]) -> Option<DkgWireKind> {
    if bytes.len() < PUBLIC_HEADER {
        return None;
    }
    match bytes[..8].try_into().ok()? {
        ROUND1_MAGIC => Some(DkgWireKind::Round1),
        MAGIC_V2 => Some(DkgWireKind::Round2),
        CERT_MAGIC => Some(DkgWireKind::Certificate),
        BACKUP_MAGIC => Some(DkgWireKind::BackupReceipt),
        _ => None,
    }
}

pub struct Identity {
    id: u16,
    signing: SigningKey,
    encryption: StaticSecret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub id: u16,
    pub signing: [u8; 32],
    pub encryption: [u8; 32],
}

impl Identity {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            signing: SigningKey::generate(&mut OsRng),
            encryption: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// These bytes must only be written through the sealed member store.
    pub fn to_secret_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..34].copy_from_slice(&self.signing.to_bytes());
        bytes[34..].copy_from_slice(&self.encryption.to_bytes());
        bytes
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 66 {
            return Err("invalid DKG identity length".into());
        }
        let id = u16::from_be_bytes(bytes[..2].try_into().unwrap());
        // 1..=MAX_MEMBERS are vault members; id 0 is the ephemeral frostd session coordinator
        // (never a FROST participant), which the hosted payment flow seals and reloads.
        if id != 0 && !(1..=crate::member_state::MAX_MEMBERS).contains(&id) {
            return Err("invalid DKG member id".into());
        }
        Ok(Self {
            id,
            signing: SigningKey::from_bytes(bytes[2..34].try_into().unwrap()),
            encryption: StaticSecret::from(<[u8; 32]>::try_from(&bytes[34..]).unwrap()),
        })
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            id: self.id,
            signing: self.signing.verifying_key().to_bytes(),
            encryption: PublicKey::from(&self.encryption).to_bytes(),
        }
    }

    /// Authorize a device login key using the same Ed25519 enrollment proof as recovery.
    pub fn authorize_device(&self, device_pub: &[u8]) -> [u8; 64] {
        self.signing.sign(device_pub).to_bytes()
    }

    /// Authorize replacing the coordinator's current device, for one challenge and generation.
    pub fn authorize_device_replacement(&self, origin: &str, device_pub: &[u8], challenge: &[u8; 32], generation: u64) -> [u8; 64] {
        let identity = hex::encode(self.public().signing);
        let device = hex::encode(device_pub);
        let nonce = hex::encode(challenge);
        let message = format!("loki-member-device-replacement-v1\n{origin}\n{identity}\n{device}\n{generation}\n{nonce}");
        self.signing.sign(message.as_bytes()).to_bytes()
    }

    pub fn nonce_claim_proof(
        &self,
        vault: [u8; 32],
        pin: &loki_relay_protocol::types::RelayPin,
        mailbox: [u8; 32],
        cid: [u8; 32],
        challenge: [u8; 32],
        record: &[u8],
    ) -> loki_relay_protocol::nonce::ClaimProof {
        use loki_relay_protocol::nonce::{self, Claimant, ClaimProof};
        let claimant = Claimant { vault, slot: self.id, key: self.signing.verifying_key().to_bytes() };
        let signature = self.signing.sign(&nonce::claim_input(claimant, pin, mailbox, cid, challenge, record)).to_bytes();
        ClaimProof { claimant, signature }
    }

    /// Prove control of the roster relay key without signing a frostd login challenge.
    pub fn relay_registration_proof(
        &self,
        origin: &str,
        challenge: &[u8; 32],
        coordinator_key: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        let shared = self.encryption.diffie_hellman(&PublicKey::from(*coordinator_key));
        if !shared.was_contributory() {
            return Err("invalid coordinator relay challenge key".into());
        }
        let public = self.public();
        let context = format!(
            "loki-relay-registration-v1\n{origin}\n{}\n{}\n{}",
            hex::encode(public.signing),
            hex::encode(public.encryption),
            hex::encode(challenge),
        );
        let mut proof = [0; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_bytes())
            .expand(context.as_bytes(), &mut proof)
            .map_err(|_| "invalid relay proof length")?;
        Ok(proof)
    }

    pub(crate) fn sign_recovery_backup(&self, domain_separated_payload: &[u8]) -> [u8; 64] {
        self.signing.sign(domain_separated_payload).to_bytes()
    }

    pub fn sign_setup_agreement(
        &self,
        vault: &[u8; 32],
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.sign_public(AGREEMENT_MAGIC, vault, payload)
    }
    pub fn verify_setup_agreement(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        Self::verify_public(AGREEMENT_MAGIC, sender, vault, wire)
    }

    pub fn sign_round2_self(&self, vault: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_public(b"LOKISR21", vault, payload)
    }

    pub fn sign_round1(&self, vault: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_public(ROUND1_MAGIC, vault, payload)
    }

    pub fn sign_certificate(&self, vault: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_public(CERT_MAGIC, vault, payload)
    }

    pub fn sign_backup(&self, vault: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_public(BACKUP_MAGIC, vault, payload)
    }

    pub fn sign_final_status(&self, vault: &[u8; 32]) -> Result<Vec<u8>, String> {
        self.sign_public(FINAL_STATUS_MAGIC, vault, b"final-card-checked")
    }

    fn sign_public(
        &self,
        magic: &[u8; 8],
        vault: &[u8; 32],
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        if payload.len() > 64 * 1024 {
            return Err("oversized DKG public package".into());
        }
        let mut wire = Vec::with_capacity(PUBLIC_HEADER + payload.len() + SIGNATURE);
        wire.extend_from_slice(magic);
        wire.extend_from_slice(vault);
        wire.extend_from_slice(&self.id.to_be_bytes());
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);
        wire.extend_from_slice(&self.signing.sign(&wire).to_bytes());
        Ok(wire)
    }

    pub fn verify_round1(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        Self::verify_public(ROUND1_MAGIC, sender, vault, wire)
    }

    pub fn verify_certificate(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        Self::verify_public(CERT_MAGIC, sender, vault, wire)
    }

    pub fn verify_backup(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        Self::verify_public(BACKUP_MAGIC, sender, vault, wire)
    }

    pub fn verify_final_status(
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<(), String> {
        if Self::verify_public(FINAL_STATUS_MAGIC, sender, vault, wire)?.as_slice()
            != b"final-card-checked"
        {
            return Err("invalid final backup status".into());
        }
        Ok(())
    }

    fn verify_public(
        magic: &[u8; 8],
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        if wire.len() < PUBLIC_HEADER + SIGNATURE
            || &wire[..8] != magic
            || &wire[8..40] != vault
            || u16::from_be_bytes(wire[40..42].try_into().unwrap()) != sender.id
        {
            return Err("wrong DKG round-one envelope".into());
        }
        let size = u32::from_be_bytes(wire[42..46].try_into().unwrap()) as usize;
        if size > COURIER_PAYLOAD_LIMIT || wire.len() != PUBLIC_HEADER + size + SIGNATURE {
            return Err("invalid DKG round-one length".into());
        }
        let verify = VerifyingKey::from_bytes(&sender.signing).map_err(|_| "invalid sender key")?;
        let signature = ed25519_dalek::Signature::from_bytes(
            wire[PUBLIC_HEADER + size..]
                .try_into()
                .map_err(|_| "invalid DKG signature length")?,
        );
        verify
            .verify_strict(&wire[..PUBLIC_HEADER + size], &signature)
            .map_err(|_| "DKG round-one signature failed")?;
        Ok(wire[PUBLIC_HEADER..PUBLIC_HEADER + size].to_vec())
    }

    pub fn seal_round2(
        &self,
        recipient: &PublicIdentity,
        vault: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if recipient.id == self.id || plaintext.len() > 64 * 1024 {
            return Err("invalid DKG recipient or oversized share".into());
        }
        let key = self.box_key(recipient, vault)?;
        let cipher = XChaCha20Poly1305::new(&key.into());
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(vault);
        header.extend_from_slice(&self.id.to_be_bytes());
        header.extend_from_slice(&recipient.id.to_be_bytes());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&((plaintext.len() + 16) as u32).to_be_bytes());
        let nonce = XNonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| "DKG encryption failed")?;
        header.extend_from_slice(&ciphertext);
        let signature = self.signing.sign(&header);
        header.extend_from_slice(&signature.to_bytes());
        Ok(header)
    }

    pub fn open_round2(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        if wire.len() < HEADER + 16 + SIGNATURE || &wire[..8] != MAGIC {
            return Err("invalid DKG envelope".into());
        }
        if &wire[8..40] != vault
            || u16::from_be_bytes(wire[40..42].try_into().unwrap()) != sender.id
            || u16::from_be_bytes(wire[42..44].try_into().unwrap()) != self.id
        {
            return Err("DKG envelope belongs to another vault or member".into());
        }
        let size = u32::from_be_bytes(wire[68..72].try_into().unwrap()) as usize;
        if size > COURIER_PAYLOAD_LIMIT + 16 || wire.len() != HEADER + size + SIGNATURE {
            return Err("invalid DKG envelope length".into());
        }
        let verify = VerifyingKey::from_bytes(&sender.signing).map_err(|_| "invalid sender key")?;
        let signature = ed25519_dalek::Signature::from_bytes(
            wire[HEADER + size..]
                .try_into()
                .map_err(|_| "invalid DKG signature length")?,
        );
        verify
            .verify_strict(&wire[..HEADER + size], &signature)
            .map_err(|_| "DKG sender signature failed")?;
        let key = self.box_key(sender, vault)?;
        let nonce = XNonce::from_slice(&wire[44..68]);
        XChaCha20Poly1305::new(&key.into())
            .decrypt(
                nonce,
                Payload {
                    msg: &wire[HEADER..HEADER + size],
                    aad: &wire[..HEADER],
                },
            )
            .map_err(|_| "DKG decryption failed".into())
    }

    fn box_key(&self, peer: &PublicIdentity, vault: &[u8; 32]) -> Result<[u8; 32], String> {
        let shared = self
            .encryption
            .diffie_hellman(&PublicKey::from(peer.encryption));
        if !shared.was_contributory() {
            return Err("invalid DKG encryption public key".into());
        }
        let (low, high) = if self.id < peer.id {
            (self.id, peer.id)
        } else {
            (peer.id, self.id)
        };
        let hash = Params::new()
            .hash_length(32)
            .personal(b"Loki_Dkg_Box_v1")
            .to_state()
            .update(vault)
            .update(&low.to_be_bytes())
            .update(&high.to_be_bytes())
            .update(shared.as_bytes())
            .finalize();
        Ok(hash
            .as_bytes()
            .try_into()
            .expect("BLAKE2b output is 32 bytes"))
    }

    /// v2 round-two envelope. `plaintext` is encrypted under a key derived from the two
    /// members' one-setup [`FreshKey`]s, the vault, both member ids and the round-one
    /// `transcript`. The header (vault, sender, recipient, transcript, nonce, length) is
    /// the AEAD associated data, and the whole envelope is signed with the identity key.
    pub fn seal_round2_v2(
        &self,
        fresh: &FreshKey,
        recipient: &PublicIdentity,
        recipient_fresh: &[u8; 32],
        vault: &[u8; 32],
        transcript: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if recipient.id == self.id || plaintext.len() > 64 * 1024 {
            return Err("invalid DKG recipient or oversized share".into());
        }
        let key = fresh_box_key(fresh, self.id, recipient.id, recipient_fresh, vault, transcript)?;
        let mut header = Vec::with_capacity(HEADER_V2);
        header.extend_from_slice(MAGIC_V2);
        header.extend_from_slice(vault);
        header.extend_from_slice(&self.id.to_be_bytes());
        header.extend_from_slice(&recipient.id.to_be_bytes());
        header.extend_from_slice(transcript);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&((plaintext.len() + 16) as u32).to_be_bytes());
        let ciphertext = XChaCha20Poly1305::new(&(*key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| "DKG encryption failed")?;
        header.extend_from_slice(&ciphertext);
        let signature = self.signing.sign(&header);
        header.extend_from_slice(&signature.to_bytes());
        Ok(header)
    }

    /// Check a v2 envelope's frame, header and sender signature without decrypting it.
    /// Reopen uses this once the fresh key is gone.
    pub fn verify_round2_v2(
        sender: &PublicIdentity,
        recipient: u16,
        vault: &[u8; 32],
        transcript: &[u8; 32],
        wire: &[u8],
    ) -> Result<(), String> {
        if wire.len() < HEADER_V2 + 16 + SIGNATURE || &wire[..8] != MAGIC_V2 {
            return Err("invalid DKG envelope".into());
        }
        if &wire[8..40] != vault
            || u16::from_be_bytes(wire[40..42].try_into().unwrap()) != sender.id
            || u16::from_be_bytes(wire[42..44].try_into().unwrap()) != recipient
        {
            return Err("DKG envelope belongs to another vault or member".into());
        }
        if &wire[44..76] != transcript {
            return Err("DKG envelope round-one transcript differs".into());
        }
        let size =
            u32::from_be_bytes(wire[HEADER_V2 - 4..HEADER_V2].try_into().unwrap()) as usize;
        if size > 64 * 1024 + 16 || wire.len() != HEADER_V2 + size + SIGNATURE {
            return Err("invalid DKG envelope length".into());
        }
        let verify = VerifyingKey::from_bytes(&sender.signing).map_err(|_| "invalid sender key")?;
        let signature = ed25519_dalek::Signature::from_bytes(
            wire[HEADER_V2 + size..]
                .try_into()
                .map_err(|_| "invalid DKG signature length")?,
        );
        verify
            .verify_strict(&wire[..HEADER_V2 + size], &signature)
            .map_err(|_| "DKG sender signature failed")?;
        Ok(())
    }

    /// Open a v2 envelope addressed to this member: verify the signature and header
    /// (including that its transcript equals ours), then decrypt.
    pub fn open_round2_v2(
        &self,
        fresh: &FreshKey,
        sender: &PublicIdentity,
        sender_fresh: &[u8; 32],
        vault: &[u8; 32],
        transcript: &[u8; 32],
        wire: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        Self::verify_round2_v2(sender, self.id, vault, transcript, wire)?;
        let size = wire.len() - HEADER_V2 - SIGNATURE;
        let key = fresh_box_key(fresh, self.id, sender.id, sender_fresh, vault, transcript)?;
        XChaCha20Poly1305::new(&(*key).into())
            .decrypt(
                XNonce::from_slice(&wire[76..100]),
                Payload {
                    msg: &wire[HEADER_V2..HEADER_V2 + size],
                    aad: &wire[..HEADER_V2],
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| "DKG decryption failed".into())
    }

    /// Encrypt a signing packet. All context, member IDs, type, and body are inside
    /// the AEAD. The outer envelope exposes only a version, nonce, and length bucket.
    pub fn seal_session(
        &self,
        recipient: &PublicIdentity,
        context: &SessionContext,
        kind: MessageKind,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        context.validate()?;
        if !kind.permits(context, self.id, recipient.id) || body.len() > kind.max_body() {
            return Err("invalid signing sender, recipient, or body size".into());
        }
        let version = if context.signers.len() == 2 { 1 } else { 2 };
        let mut inner = Vec::with_capacity(146 + context.signers.len() * 2 + body.len() + SIGNATURE);
        inner.extend_from_slice(SESSION_INNER);
        inner.push(version);
        inner.extend_from_slice(&context.vault);
        inner.extend_from_slice(&context.payment);
        inner.extend_from_slice(&context.attempt.0);
        for &id in &context.signers {
            inner.extend_from_slice(&id.to_be_bytes());
        }
        inner.extend_from_slice(&self.id.to_be_bytes());
        inner.extend_from_slice(&recipient.id.to_be_bytes());
        inner.push(kind as u8);
        inner.extend_from_slice(&(body.len() as u32).to_be_bytes());
        let transcript = session_transcript(&inner, body, version);
        inner.extend_from_slice(&transcript);
        inner.extend_from_slice(body);
        inner.extend_from_slice(&self.signing.sign(&inner).to_bytes());
        let bucket = (inner.len().max(1024)).next_power_of_two();
        if bucket > 8 * 1024 * 1024 {
            return Err("signing message exceeds envelope bucket".into());
        }
        inner.resize(bucket, 0);
        let mut header = Vec::with_capacity(SESSION_HEADER);
        header.extend_from_slice(SESSION_MAGIC);
        header.push(version);
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&((bucket + 16) as u32).to_be_bytes());
        let key = self.session_key(recipient, context)?;
        let ciphertext = XChaCha20Poly1305::new(&key.into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &inner,
                    aad: &header,
                },
            )
            .map_err(|_| "signing message encryption failed")?;
        header.extend_from_slice(&ciphertext);
        Ok(header)
    }

    /// Try a specific roster peer and locally selected attempt context. Wrong-context
    /// packets cannot decrypt, so a shared mailbox can carry unrelated attempts.
    pub fn open_session(
        &self,
        sender: &PublicIdentity,
        context: &SessionContext,
        wire: &[u8],
    ) -> Result<OpenedMessage, String> {
        self.open_session_inner(sender, sender, self.id, context, wire)
    }

    /// Reopen one of this member's own exact outbound wires from its sealed outbox.
    /// This lets a selected signer finish after restart without keeping nonce secrets.
    pub fn open_sent_session(
        &self,
        recipient: &PublicIdentity,
        context: &SessionContext,
        wire: &[u8],
    ) -> Result<OpenedMessage, String> {
        let own = self.public();
        self.open_session_inner(&own, recipient, recipient.id, context, wire)
    }

    fn open_session_inner(
        &self,
        sender: &PublicIdentity,
        box_peer: &PublicIdentity,
        recipient: u16,
        context: &SessionContext,
        wire: &[u8],
    ) -> Result<OpenedMessage, String> {
        context.validate()?;
        session_envelope(wire)?;
        let version = if context.signers.len() == 2 { 1 } else { 2 };
        let signers_end = 105 + context.signers.len() * 2;
        let meta_end = signers_end + 9;
        let inner_header = meta_end + 32;
        let key = self.session_key(box_peer, context)?;
        let inner = XChaCha20Poly1305::new(&key.into())
            .decrypt(
                XNonce::from_slice(&wire[9..33]),
                Payload {
                    msg: &wire[SESSION_HEADER..],
                    aad: &wire[..SESSION_HEADER],
                },
            )
            .map_err(|_| "signing message is not for this member and attempt")?;
        if wire[8] != version
            || inner.len() < inner_header + SIGNATURE
            || &inner[..8] != SESSION_INNER
            || inner[8] != version
            || inner[9..41] != context.vault
            || inner[41..73] != context.payment
            || inner[73..105] != context.attempt.0
            || inner[105..signers_end] != context.signers.iter().flat_map(|id| id.to_be_bytes()).collect::<Vec<_>>()
            || inner[signers_end..signers_end + 2] != sender.id.to_be_bytes()
            || inner[signers_end + 2..signers_end + 4] != recipient.to_be_bytes()
        {
            return Err("signing inner context mismatch".into());
        }
        let kind = MessageKind::try_from(inner[signers_end + 4])?;
        if !kind.permits(context, sender.id, recipient) {
            return Err("sender or recipient not allowed for signing message kind".into());
        }
        let size = u32::from_be_bytes(inner[signers_end + 5..meta_end].try_into().unwrap()) as usize;
        if size > kind.max_body() || inner_header + size + SIGNATURE > inner.len() {
            return Err("invalid signing body length".into());
        }
        let body = &inner[inner_header..inner_header + size];
        let transcript = session_transcript(&inner[..meta_end], body, version);
        if inner[meta_end..inner_header] != transcript {
            return Err("signing transcript mismatch".into());
        }
        let signed_end = inner_header + size;
        let signature = ed25519_dalek::Signature::from_bytes(
            inner[signed_end..signed_end + SIGNATURE]
                .try_into()
                .unwrap(),
        );
        let verify =
            VerifyingKey::from_bytes(&sender.signing).map_err(|_| "invalid signing sender key")?;
        verify
            .verify_strict(&inner[..signed_end], &signature)
            .map_err(|_| "signing message signature failed")?;
        if inner[signed_end + SIGNATURE..].iter().any(|b| *b != 0) {
            return Err("noncanonical signing envelope padding".into());
        }
        Ok(OpenedMessage {
            context: context.clone(),
            sender: sender.id,
            recipient,
            kind,
            body: body.to_vec(),
            wire_hash: blake3::hash(wire).into(),
            transcript_hash: transcript,
        })
    }

    fn session_key(
        &self,
        peer: &PublicIdentity,
        context: &SessionContext,
    ) -> Result<[u8; 32], String> {
        let shared = self
            .encryption
            .diffie_hellman(&PublicKey::from(peer.encryption));
        if !shared.was_contributory() {
            return Err("invalid signing encryption public key".into());
        }
        let mut hash = Params::new()
            .hash_length(32)
            .personal(if context.signers.len() == 2 { b"Loki_Sign_Box_v1" } else { b"Loki_Sign_Box_v2" })
            .to_state();
        hash.update(&context.vault);
        hash.update(&context.payment);
        hash.update(&context.attempt.0);
        for &id in &context.signers {
            hash.update(&id.to_be_bytes());
        }
        hash.update(shared.as_bytes());
        Ok(hash.finalize().as_bytes().try_into().unwrap())
    }
}

/// BLAKE2b key derivation for v2 round-two envelopes, over the fresh-key DH, the vault,
/// both member ids (low first) and the round-one transcript.
fn fresh_box_key(
    own: &FreshKey,
    own_id: u16,
    peer_id: u16,
    peer_fresh: &[u8; 32],
    vault: &[u8; 32],
    transcript: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let shared = own.0.diffie_hellman(&PublicKey::from(*peer_fresh));
    if !shared.was_contributory() {
        return Err("invalid DKG fresh public key".into());
    }
    let (low, high) = if own_id < peer_id {
        (own_id, peer_id)
    } else {
        (peer_id, own_id)
    };
    let hash = Params::new()
        .hash_length(32)
        .personal(b"Loki_Dkg_Box_v2")
        .to_state()
        .update(vault)
        .update(&low.to_be_bytes())
        .update(&high.to_be_bytes())
        .update(transcript)
        .update(shared.as_bytes())
        .finalize();
    Ok(Zeroizing::new(
        hash.as_bytes().try_into().expect("BLAKE2b output is 32 bytes"),
    ))
}

fn session_transcript(meta: &[u8], body: &[u8], version: u8) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key(if version == 1 { "Loki signing message transcript v1" } else { "Loki signing message transcript v2" });
    hash.update(meta);
    hash.update(body);
    hash.finalize().into()
}

/// Validate only the public bucketed envelope. All identifying data is encrypted.
pub fn session_envelope(wire: &[u8]) -> Result<(), String> {
    if wire.len() < SESSION_HEADER + 1024 + 16
        || wire.len() > SESSION_LIMIT
        || &wire[..8] != SESSION_MAGIC
        || !matches!(wire[8], 1 | 2)
    {
        return Err("invalid signing envelope or version".into());
    }
    let size = u32::from_be_bytes(wire[33..37].try_into().unwrap()) as usize;
    if size < 1024 + 16
        || size - 16 > 8 * 1024 * 1024
        || !(size - 16).is_power_of_two()
        || wire.len() != SESSION_HEADER + size
    {
        return Err("invalid signing envelope bucket".into());
    }
    Ok(())
}
