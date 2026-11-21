//! Automatic Received preparation.
//!
//! Encryption stays in memory until `ClientStore::commit_incoming` commits the original and
//! every recipient copy together. A saved acknowledgement is not encrypted again.

use crate::store::SavedRecord;
use crate::{
    prepare_outbox, AuthenticatedMessage, AuthenticatedTransfer, ClientError, ClientResult,
    ClientStore, CommIdentity, CompleteSource, PreparedOutbox, TransferAssembler,
};
use loki_relay_protocol::types::{
    Id32, LogicalKey, MemberId, MessageBody, MessageRef, Payload, Roster,
};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const ACK_REQUEST_DOMAIN: &[u8] = b"Loki_Relay_Received_Request_v1\0";

pub(crate) fn ack_request_id(author: MemberId, original: &AuthenticatedMessage) -> Id32 {
    let key = &original.body().key;
    let mut hasher = Sha256::new();
    hasher.update(ACK_REQUEST_DOMAIN);
    hasher.update(key.vault);
    hasher.update(key.roster);
    hasher.update(key.sender.to_be_bytes());
    hasher.update(key.message);
    hasher.update(original.digest());
    hasher.update(author.to_be_bytes());
    hasher.finalize().into()
}

fn original_target(original: &AuthenticatedMessage) -> MessageRef {
    MessageRef {
        sender: original.body().key.sender,
        message: original.body().key.message,
        digest: *original.digest(),
    }
}

/// Received body for one acknowledgement attempt.
///
/// `message_id` is the author's fresh random id, or the id already stored on `ack_links`.
/// The caller binding stays separate and stable. This function does not draw randomness.
pub(crate) fn received_body(
    author: MemberId,
    original: &AuthenticatedMessage,
    message_id: Id32,
) -> ClientResult<MessageBody> {
    let target = original_target(original);
    Ok(MessageBody {
        key: LogicalKey {
            vault: original.body().key.vault,
            roster: original.body().key.roster,
            sender: author,
            message: message_id,
        },
        audience: original.body().audience.clone(),
        session: original.body().session,
        prerequisites: vec![target.clone()],
        payload: Payload::Received(target),
    })
}

/// Prove this prepared outbox acknowledges the original now being committed.
///
/// The logical message id is the random id already inside the prepared key. The opened
/// author copy must use that id and this original's target, session, audience, and prerequisite.
pub(crate) fn bound_ack(
    roster: &Roster,
    identity: &CommIdentity,
    original: &AuthenticatedMessage,
    prepared: &PreparedOutbox,
) -> ClientResult<crate::outbox::ValidatedOutbox> {
    let author = identity.public().id;
    let original_key = &original.body().key;
    if prepared.key().sender != author
        || prepared.key().vault != original_key.vault
        || prepared.key().roster != original_key.roster
        || prepared.recipients().len() != roster.members.len()
    {
        return Err(ClientError::Identity);
    }
    let expected = received_body(author, original, prepared.key().message)?;
    if prepared.key() != &expected.key {
        return Err(ClientError::Identity);
    }
    let validated = crate::outbox::validate(roster, identity, prepared)?;
    if validated.kind != 2 || validated.session != original.body().session {
        return Err(ClientError::Identity);
    }
    let author_copy = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == author)
        .ok_or(ClientError::Identity)?;
    let opened = crate::outbox::authenticate_author(roster, identity, author_copy.objects())?;
    let opened_target = match &opened.body().payload {
        Payload::Received(target) => target,
        Payload::Test(_) => return Err(ClientError::Identity),
    };
    if opened.body() != &expected
        || opened.digest() != prepared.digest()
        || opened_target != &original_target(original)
        || opened.body().session != original.body().session
        || opened.body().prerequisites.as_slice() != std::slice::from_ref(opened_target)
        || opened.body().audience != original.body().audience
    {
        return Err(ClientError::Identity);
    }
    Ok(validated)
}

fn ack_blocked(store: &ClientStore, source: &CompleteSource) -> ClientResult<bool> {
    let Some(root) = source.required_hashes().first() else {
        return Ok(true);
    };
    if store.source_rejected(root)? {
        return Ok(true);
    }
    let (cached, quarantined) = store.root_journal_state(root)?;
    if quarantined && !cached {
        return Ok(true);
    }
    for hash in source.required_hashes() {
        if store.saved_object(hash)?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Prepare encrypted Received copies for every roster member for a foreign test message.
///
/// Self-delivery, an incoming Received, a partial set, and a quarantined root produce no
/// acknowledgement. A saved original also produces none: the commit reuses the saved link
/// and ciphertext instead of sealing another copy. Nothing is uploaded from here.
pub fn prepare_received(
    store: &ClientStore,
    identity: &CommIdentity,
    roster: &Roster,
    message: &AuthenticatedMessage,
    source: &CompleteSource,
) -> ClientResult<Option<PreparedOutbox>> {
    let owner = identity.public().id;
    store.check_association(roster, owner)?;
    if source.recipient() != owner
        || source.key() != &message.body().key
        || source.digest() != message.digest()
    {
        return Err(ClientError::Identity);
    }
    let foreign_test =
        message.body().key.sender != owner && matches!(message.body().payload, Payload::Test(_));
    if !foreign_test || ack_blocked(store, source)? {
        return Ok(None);
    }
    // Either digest means this identity is already saved. Conflict and duplicate both keep
    // the existing acknowledgement, so preparation must not seal or draw another message id.
    if store.incoming_saved_digest(&message.body().key)?.is_some() {
        return Ok(None);
    }
    let mut message_id = [0u8; 32];
    getrandom::fill(&mut message_id).map_err(|_| ClientError::Crypto)?;
    let body = received_body(owner, message, message_id)?;
    Ok(Some(prepare_outbox(identity, roster, &body)?))
}

/// Whole-vault Received view for one exact test digest.
///
/// Fields stay private so a relay receipt cannot be turned into an acknowledgement.
/// The author slot is the committed test message on this store. The other audience
/// members each need their own certified Received. Stored completion is a different report.
pub struct ReceivedStatus {
    key: LogicalKey,
    digest: Id32,
    session: Option<Id32>,
    author_committed: bool,
    audience: Vec<MemberId>,
    peers: BTreeSet<MemberId>,
}

impl ReceivedStatus {
    pub fn key(&self) -> &LogicalKey {
        &self.key
    }

    pub fn digest(&self) -> &Id32 {
        &self.digest
    }

    pub fn session(&self) -> Option<Id32> {
        self.session
    }

    /// The author's committed test is present. A Received from the author is not required.
    pub fn author_committed(&self) -> bool {
        self.author_committed
    }

    /// One certified signer other than the author. Repeated sources still count once.
    pub fn member_received(&self, member: MemberId) -> bool {
        member != self.key.sender && self.peers.contains(&member)
    }

    /// Authoritative local test plus every other audience member.
    ///
    /// This does not read relay receipts and does not release Stored capacity.
    pub fn whole_vault(&self) -> bool {
        self.author_committed
            && loki_relay_protocol::types::valid_member_count(self.audience.len())
            && self.audience.contains(&self.key.sender)
            && self
                .audience
                .iter()
                .filter(|member| **member != self.key.sender)
                .all(|member| self.peers.contains(member))
    }
}

#[derive(Eq, Hash, PartialEq)]
struct AckClaim {
    target: LogicalKey,
    digest: Id32,
    session: Option<Id32>,
    signer: MemberId,
}

enum AckOutcome {
    Pending,
    Rejected(&'static str),
    Bound(AckClaim),
}

struct AckObservation {
    source_root: Id32,
    body_digest: Option<Id32>,
    outcome: AckOutcome,
}

/// Process bounded, persisted work. An early acknowledgement is selected after
/// the target arrives; neither the scheduling index nor a receipt certifies it.
pub fn reconcile_received(
    store: &mut ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
) -> ClientResult<()> {
    store.check_association(roster, identity.public().id)?;
    let mut facts = HashMap::new();
    let mut certified = HashSet::new();
    let incoming = store.received_original_work(100)?;
    let local = store.received_local_work(100)?;
    let observations = incoming.iter().map(|row| (true, row.cursor, observe_incoming(store, roster, identity, row)))
        .chain(local.iter().map(|link| (false, link.cursor, observe_local(store, roster, identity, link))))
        .map(|(incoming, cursor, observation)| Ok((incoming, cursor, observation?)))
        .collect::<ClientResult<Vec<_>>>()?;
    for (incoming, cursor, observation) in observations {
        let reason = match observation.outcome {
            AckOutcome::Pending => None,
            AckOutcome::Rejected(reason) => Some(reason),
            AckOutcome::Bound(claim) => {
                let fact = match facts.entry(claim.target.clone()) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(target_fact(store, roster, identity, &claim.target)?)
                    }
                };
                match fact.as_ref().map(|fact| claim.certify(fact)) {
                    Some(Ok(())) => {
                        if !certified.contains(&claim) {
                            store.note_received_ref(&claim.target, &claim.digest, claim.session, claim.signer, &observation.source_root)?;
                            certified.insert(claim);
                        }
                        None
                    }
                    Some(Err(reason)) => Some(reason),
                    None => None,
                }
            }
        };
        if let Some(reason) = reason {
            store.reject_source_root(&observation.source_root, reason, observation.body_digest.as_ref())?;
        }
        store.connection.execute("DELETE FROM received_work WHERE incoming=?1 AND source=?2", params![incoming, cursor])?;
    }
    Ok(())
}

/// Readonly Received status. Index phase and receipt rows are not consulted.
pub fn received_status(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    key: &LogicalKey,
    digest: &Id32,
) -> ClientResult<ReceivedStatus> {
    store.check_association(roster, identity.public().id)?;
    if key.vault != roster.vault || key.roster != loki_relay_protocol::types::roster_digest(roster)?
    {
        return Err(ClientError::Identity);
    }
    let mut status = ReceivedStatus {
        key: key.clone(),
        digest: *digest,
        session: None,
        author_committed: false,
        audience: Vec::new(),
        peers: BTreeSet::new(),
    };
    let Some(fact) = target_fact(store, roster, identity, key)? else {
        return Ok(status);
    };
    if !fact.is_test || fact.digest != *digest {
        return Ok(status);
    }
    status.session = fact.session;
    status.audience = fact.audience.clone();
    status.author_committed = true;
    let owner = identity.public().id;
    for &signer in &fact.audience {
        if signer == key.sender {
            continue;
        }
        let matches = |observation: AckObservation| {
            matches!(observation.outcome, AckOutcome::Bound(claim)
                if claim.signer == signer && claim.target == *key && claim.certify(&fact).is_ok())
        };
        if signer == owner {
            if let Some(link) = store.local_ack_for_target(key, digest, owner)? {
                if matches(observe_local(store, roster, identity, &link)?) {
                    status.peers.insert(signer);
                }
            }
            continue;
        }
        let mut after = None;
        'sources: loop {
            let page = store.received_for_target(key, digest, fact.session, signer, after)?;
            let Some(last) = page.last() else { break; };
            after = Some(last.key.message);
            for row in &page {
                if matches(observe_incoming(store, roster, identity, row)?) {
                    status.peers.insert(signer);
                    break 'sources;
                }
            }
        }
    }
    Ok(status)
}

struct TargetFact {
    digest: Id32,
    session: Option<Id32>,
    audience: Vec<MemberId>,
    is_test: bool,
}

impl AckClaim {
    fn certify(&self, fact: &TargetFact) -> Result<(), &'static str> {
        if self.digest != fact.digest {
            Err("digest")
        } else if !fact.is_test {
            Err("type")
        } else if self.session != fact.session {
            Err("session")
        } else if !fact.audience.contains(&self.signer) {
            Err("audience")
        } else {
            Ok(())
        }
    }
}

fn target_fact(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    key: &LogicalKey,
) -> ClientResult<Option<TargetFact>> {
    let Some(saved) = store.saved_record(key)? else {
        return Ok(None);
    };
    let opened = match open_saved(store, roster, identity, &saved, key) {
        Ok(opened) => opened,
        Err(
            ClientError::MissingObjects(_)
            | ClientError::Crypto
            | ClientError::Identity
            | ClientError::Wire(_),
        ) => return Ok(None),
        Err(error) => return Err(error),
    };
    let body = opened.message().body();
    if &body.key != key || opened.message().digest() != &saved.digest {
        return Ok(None);
    }
    Ok(Some(TargetFact {
        digest: *opened.message().digest(),
        session: body.session,
        audience: body.audience.clone(),
        is_test: matches!(body.payload, Payload::Test(_)),
    }))
}

fn observe_incoming(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    row: &crate::IncomingOriginal,
) -> ClientResult<AckObservation> {
    let hashes = store.incoming_hashes(&row.key)?;
    if hashes.first() != Some(&row.source_root) {
        return Ok(AckObservation {
            source_root: row.source_root,
            body_digest: Some(row.digest),
            outcome: AckOutcome::Rejected("binding"),
        });
    }
    let opened = match open_hashes(store, roster, identity, &hashes, false) {
        Ok(opened) => opened,
        Err(error) => {
            return Ok(AckObservation {
                source_root: row.source_root,
                body_digest: Some(row.digest),
                outcome: outcome_from_open(error)?,
            });
        }
    };
    Ok(AckObservation {
        source_root: row.source_root,
        body_digest: Some(*opened.message().digest()),
        outcome: judge(
            roster,
            identity,
            &opened,
            &row.key,
            &row.digest,
            row.source_root,
        )?,
    })
}

fn observe_local(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    link: &crate::AckLink,
) -> ClientResult<AckObservation> {
    let ack_key = LogicalKey {
        vault: link.key.vault,
        roster: link.key.roster,
        sender: link.ack_author,
        message: link.ack_message,
    };
    let Some(saved) = store.saved_record(&ack_key)? else {
        return Err(ClientError::Storage);
    };
    let hashes = store.outgoing_hashes(&ack_key, link.ack_author)?;
    if hashes.last() != Some(&saved.source_root) {
        return Ok(AckObservation {
            source_root: saved.source_root,
            body_digest: Some(saved.digest),
            outcome: AckOutcome::Rejected("binding"),
        });
    }
    let opened = match open_hashes(store, roster, identity, &hashes, true) {
        Ok(opened) => opened,
        Err(error) => {
            return Ok(AckObservation {
                source_root: saved.source_root,
                body_digest: Some(saved.digest),
                outcome: outcome_from_open(error)?,
            });
        }
    };
    Ok(AckObservation {
        source_root: saved.source_root,
        body_digest: Some(*opened.message().digest()),
        outcome: judge(
            roster,
            identity,
            &opened,
            &ack_key,
            &saved.digest,
            saved.source_root,
        )?,
    })
}

fn outcome_from_open(error: ClientError) -> ClientResult<AckOutcome> {
    match error {
        ClientError::MissingObjects(_) => Ok(AckOutcome::Pending),
        ClientError::Crypto => Ok(AckOutcome::Rejected("signature")),
        ClientError::Identity => Ok(AckOutcome::Rejected("identity")),
        ClientError::Wire(_) => Ok(AckOutcome::Rejected("framing")),
        other => Err(other),
    }
}

fn judge(
    roster: &Roster,
    identity: &CommIdentity,
    opened: &AuthenticatedTransfer,
    expected_key: &LogicalKey,
    expected_digest: &Id32,
    root: Id32,
) -> ClientResult<AckOutcome> {
    let message = opened.message();
    let body = message.body();
    if message.digest() != expected_digest
        || &body.key != expected_key
        || opened.source().required_hashes().first() != Some(&root)
        || opened.source().recipient() != identity.public().id
    {
        return Ok(AckOutcome::Rejected("binding"));
    }
    let Payload::Received(target_ref) = &body.payload else {
        return Ok(AckOutcome::Rejected("type"));
    };
    if body.prerequisites.as_slice() != std::slice::from_ref(target_ref) {
        return Ok(AckOutcome::Rejected("prerequisite"));
    }
    if body.key.sender == target_ref.sender {
        return Ok(AckOutcome::Rejected("author"));
    }
    if !roster
        .members
        .iter()
        .any(|member| member.id == body.key.sender)
    {
        return Ok(AckOutcome::Rejected("audience"));
    }
    let target_key = LogicalKey {
        vault: body.key.vault,
        roster: body.key.roster,
        sender: target_ref.sender,
        message: target_ref.message,
    };
    Ok(AckOutcome::Bound(AckClaim {
        target: target_key,
        digest: target_ref.digest,
        session: body.session,
        signer: body.key.sender,
    }))
}

fn open_saved(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    saved: &SavedRecord,
    key: &LogicalKey,
) -> ClientResult<AuthenticatedTransfer> {
    let hashes = if saved.incoming {
        store.incoming_hashes(key)?
    } else {
        store.outgoing_hashes(key, identity.public().id)?
    };
    let root = if saved.incoming {
        hashes.first().copied()
    } else {
        hashes.last().copied()
    };
    if root != Some(saved.source_root) {
        return Err(ClientError::Storage);
    }
    open_hashes(store, roster, identity, &hashes, !saved.incoming)
}

fn open_hashes(
    store: &ClientStore,
    roster: &Roster,
    identity: &CommIdentity,
    hashes: &[Id32],
    root_at_end: bool,
) -> ClientResult<AuthenticatedTransfer> {
    if hashes.is_empty() || hashes.len() > 275 {
        return Err(ClientError::Wire(loki_relay_protocol::WireError::Bounds));
    }
    let root_index = if root_at_end { hashes.len() - 1 } else { 0 };
    let mut missing = Vec::new();
    let mut root = None;
    let mut objects = BTreeMap::new();
    for (index, hash) in hashes.iter().enumerate() {
        let Some(object) = store.saved_object(hash)? else {
            missing.push(*hash);
            continue;
        };
        if index == root_index {
            root = Some(object);
        } else {
            objects.insert(*hash, object);
        }
    }
    if !missing.is_empty() {
        return Err(ClientError::MissingObjects(missing));
    }
    TransferAssembler::open(
        roster,
        identity,
        &root.ok_or(ClientError::Storage)?,
        &objects,
    )
}
