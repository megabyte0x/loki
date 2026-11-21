//! The vault's Ironwood balance and history as reported by lightwalletd compact blocks, for a
//! signer with no wallet database (the in-browser signer). Trial decryption is zcash_client_backend's
//! `scan_block`, the scanner the native wallet runs through `scan_cached_blocks`. Spends are
//! found by matching every compact action's nullifier against the vault's own notes, so the
//! scan state is just those notes plus the last block scanned.

use std::collections::BTreeMap;

use orchard::keys::FullViewingKey;
use prost::Message;
use serde::{Deserialize, Serialize};
use zcash_client_backend::{
    data_api::BlockMetadata,
    proto::compact_formats::CompactBlock,
    scanning::{scan_block, Nullifiers, ScanningKeys},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::{BlockHash, BlockHeader};

use crate::network::VaultNetwork;

/// Validate the fields Zakura's scanner reads through infallible accessors. If a header
/// was supplied, normalize to its hashes so all later checks use the same representation.
pub fn validate_compact_block(block: &mut CompactBlock) -> Result<(), String> {
    if block.height >= u64::from(u32::MAX) {
        return Err("compact block height out of range".into());
    }
    if !block.header.is_empty() {
        let mut bytes = block.header.as_slice();
        let header = BlockHeader::read(&mut bytes).map_err(|e| format!("compact block header: {e}"))?;
        let hash = header.hash().0;
        if !bytes.is_empty()
            || (!block.hash.is_empty() && block.hash != hash)
            || (!block.prev_hash.is_empty() && block.prev_hash != header.prev_block.0)
        {
            return Err("compact block header disagrees with its hashes".into());
        }
        block.hash = hash.to_vec();
        block.prev_hash = header.prev_block.0.to_vec();
        block.header.clear();
    }
    if block.hash.len() != 32 || block.prev_hash.len() != 32 {
        return Err("compact block has an invalid hash or parent hash".into());
    }
    if block.vtx.iter().any(|tx| tx.txid.len() != 32 || u16::try_from(tx.index).is_err())
        || block.vtx.windows(2).any(|tx| tx[0].index >= tx[1].index)
    {
        return Err("compact block has invalid transaction IDs or indices".into());
    }
    if block.vtx.iter().flat_map(|tx| &tx.spends).any(|spend| spend.nf.len() != 32) {
        return Err("compact block has an invalid Sapling nullifier".into());
    }
    Ok(())
}

/// Check commitment-tree arithmetic before invoking the underlying scanner.
pub fn tree_sizes(prior: &BlockMetadata) -> [Option<u32>; 3] {
    [prior.sapling_tree_size(), prior.orchard_tree_size(), prior.ironwood_tree_size()]
}

pub fn checked_next_tree_sizes(block: &CompactBlock, sizes: [Option<u32>; 3]) -> Result<[Option<u32>; 3], String> {
    let mut counts = [0u64; 3];
    for tx in &block.vtx {
        counts[0] += tx.outputs.len() as u64;
        counts[1] += tx.actions.len() as u64;
        counts[2] += tx.ironwood_actions.len() as u64;
    }
    let reported = block.chain_metadata.as_ref().map(|m| [m.sapling_commitment_tree_size, m.orchard_commitment_tree_size, m.ironwood_commitment_tree_size]);
    let mut next = [None; 3];
    for i in 0..3 {
        let end = match (sizes[i], reported) {
            (Some(start), reported) => {
                let end = u32::try_from(u64::from(start) + counts[i]).map_err(|_| "compact block tree size overflow")?;
                if reported.is_some_and(|r| r[i] != end) {
                    return Err("compact block has inconsistent tree sizes".into());
                }
                end
            }
            (None, Some(reported)) if u64::from(reported[i]) >= counts[i] => reported[i],
            (None, Some(_)) => return Err("compact block has inconsistent tree sizes".into()),
            (None, None) => u32::try_from(counts[i]).map_err(|_| "compact block tree size overflow")?,
        };
        next[i] = Some(end);
    }
    Ok(next)
}

/// One note the vault received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Received {
    pub height: u32,
    pub txid: String,
    pub value_zat: u64,
    /// Change back to the vault (internal scope), not an incoming payment.
    pub change: bool,
    /// The transaction that spent it and its height, once seen on chain.
    pub spent_in: Option<(String, u32)>,
}

/// What one transaction did to the vault, from the chain alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TxEffect {
    pub txid: String,
    pub height: u32,
    /// Received at the vault's external address.
    pub received_zat: u64,
    /// Returned to the vault as change.
    pub change_zat: u64,
    /// Value of the vault notes this transaction spent.
    pub spent_zat: u64,
}

pub struct ChainScan {
    network: VaultNetwork,
    keys: ScanningKeys<u32, (u32, zip32::Scope)>,
    /// Keyed by each note's spend nullifier.
    notes: BTreeMap<[u8; 32], Received>,
    prior: Option<BlockMetadata>,
    /// Where a fresh scan starts: the vault's birth height.
    birth: u32,
    source: Option<String>,
}

impl ChainScan {
    pub fn new(network: VaultNetwork, fvk: &FullViewingKey, birth: u32) -> Result<Self, String> {
        let ufvk = UnifiedFullViewingKey::from_orchard_fvk(fvk.clone()).map_err(|e| format!("vault viewing key: {e:?}"))?;
        Ok(Self { network, keys: ScanningKeys::from_account_ufvks([(0u32, ufvk)]), notes: BTreeMap::new(), prior: None, birth, source: None })
    }

    /// A new provider cannot vouch for compact transactions scanned from the old one,
    /// even if both providers report identical block hashes.
    pub fn use_source(&mut self, source: &str, birth: u32) {
        if self.source.as_deref() != Some(source) || self.birth != birth {
            self.reset();
            self.birth = birth;
            self.source = Some(source.to_owned());
        }
    }

    pub fn reset(&mut self) {
        self.prior = None;
        self.notes.clear();
    }

    /// The last block scanned, if any.
    pub fn height(&self) -> Option<u32> {
        self.prior.as_ref().map(|m| m.block_height().into())
    }

    /// The height of the next block to scan.
    pub fn next_height(&self) -> u32 {
        self.height().map_or(self.birth, |h| h.saturating_add(1))
    }

    /// Check the provider's block at the persisted height without accepting any transaction data.
    pub fn matches_checkpoint(&self, bytes: &[u8]) -> Result<bool, String> {
        let prior = self.prior.as_ref().ok_or("no scanned block to check")?;
        let mut block = CompactBlock::decode(bytes).map_err(|e| format!("checkpoint block: {e}"))?;
        if block.height != u64::from(prior.block_height()) {
            return Err("lightwalletd returned an invalid scan checkpoint".into());
        }
        validate_compact_block(&mut block)?;
        Ok(block.hash() == prior.block_hash())
    }

    /// Scan the next compact block (protobuf bytes, as lightwalletd streams it). Blocks must
    /// come in order; one that does not extend the last block scanned is refused.
    pub fn scan(&mut self, block: &[u8]) -> Result<(), String> {
        self.scan_batch([block])
    }

    /// Accept the page atomically without copying the entire saved note history.
    pub fn scan_batch(&mut self, blocks: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Result<(), String> {
        let mut prior = self.prior;
        let start = self.next_height();
        let mut next = start;
        let mut forked = false;
        let mut changes = BTreeMap::new();
        for bytes in blocks {
            let mut block = CompactBlock::decode(bytes.as_ref()).map_err(|e| format!("compact block: {e}"))?;
            validate_compact_block(&mut block)?;
            if block.height != u64::from(next) {
                return Err(format!("wrong compact block height: requested {next}, got {}", block.height));
            }
            if prior.as_ref().is_some_and(|m| block.prev_hash != m.block_hash().0) {
                if next != start {
                    return Err("compact block stream has inconsistent parent hashes".into());
                }
                // Finish validating the page before asking the caller to reconcile a fork.
                forked = true;
                prior = None;
            }
            checked_next_tree_sizes(&block, prior.as_ref().map_or([None; 3], tree_sizes))?;
            let spent: Vec<([u8; 32], String)> = block.vtx.iter().flat_map(|tx| {
                let txid = tx_id(&tx.txid);
                tx.ironwood_actions.iter().filter_map(move |a| Some((a.nullifier.as_slice().try_into().ok()?, txid.clone())))
            }).collect();
            let scanned = scan_block(&self.network, block, &self.keys, &Nullifiers::empty(), prior.as_ref())
                .map_err(|e| format!("scan block: {e}"))?;
            for tx in scanned.transactions() {
                for out in tx.ironwood_outputs() {
                    let nf = out.nf().ok_or("received note without a nullifier")?.to_bytes();
                    changes.insert(nf, Received {
                        height: next,
                        txid: tx.txid().to_string(),
                        value_zat: out.note().0.value().inner(),
                        // By scope: the library's own change flag needs the spends it was not given.
                        change: out.recipient_key_scope() == Some(zip32::Scope::Internal),
                        spent_in: None,
                    });
                }
            }
            for (nf, txid) in spent {
                if let Some(note) = changes.get_mut(&nf) {
                    note.spent_in.get_or_insert((txid, next));
                } else if let Some(note) = self.notes.get(&nf) {
                    let mut note = note.clone();
                    note.spent_in.get_or_insert((txid, next));
                    changes.insert(nf, note);
                }
            }
            prior = Some(scanned.to_block_metadata());
            next += 1;
        }
        if next == start {
            return Err("compact block stream made no progress".into());
        }
        if forked {
            return Err("block does not extend the saved scan tip".into());
        }
        self.notes.append(&mut changes);
        self.prior = prior;
        Ok(())
    }

    /// The scan state to persist: the vault's notes and the last block scanned. Holds the
    /// vault's history, so the caller seals it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let tip = self.prior.as_ref().map(|m| Tip {
            height: m.block_height().into(),
            hash: hex::encode(m.block_hash().0),
            sapling: m.sapling_tree_size(),
            orchard: m.orchard_tree_size(),
            ironwood: m.ironwood_tree_size(),
        });
        let notes = self.notes.iter().map(|(nf, n)| (hex::encode(nf), n.clone())).collect();
        serde_json::to_vec(&Saved { version: 1, birth: self.birth, tip, notes, source: self.source.clone() }).expect("scan state serializes")
    }

    /// Resume from [`Self::to_bytes`].
    pub fn from_bytes(network: VaultNetwork, fvk: &FullViewingKey, saved: &[u8]) -> Result<Self, String> {
        let saved: Saved = serde_json::from_slice(saved).map_err(|e| format!("scan state: {e}"))?;
        if saved.version != 1 {
            return Err(format!("scan state version {} is not supported", saved.version));
        }
        let mut scan = Self::new(network, fvk, saved.birth)?;
        scan.source = saved.source;
        scan.prior = saved.tip.map(|t| -> Result<_, String> {
            let hash: [u8; 32] = hex::decode(&t.hash).ok().and_then(|h| h.try_into().ok()).ok_or("scan state: bad block hash")?;
            Ok(BlockMetadata::from_parts(t.height.into(), BlockHash(hash), t.sapling, t.orchard, t.ironwood))
        }).transpose()?;
        for (nf, note) in saved.notes {
            let nf: [u8; 32] = hex::decode(&nf).ok().and_then(|h| h.try_into().ok()).ok_or("scan state: bad nullifier")?;
            scan.notes.insert(nf, note);
        }
        Ok(scan)
    }

    /// Unspent Ironwood value, as `VaultWallet::ironwood_balance_zat` counts it.
    pub fn balance_zat(&self) -> u64 {
        self.notes.values().filter(|n| n.spent_in.is_none()).map(|n| n.value_zat).sum()
    }

    pub fn notes(&self) -> impl Iterator<Item = &Received> {
        self.notes.values()
    }

    /// The transaction (and height) that spent the vault note with this spend nullifier.
    pub fn spent_by(&self, nullifier: &[u8; 32]) -> Option<&(String, u32)> {
        self.notes.get(nullifier)?.spent_in.as_ref()
    }

    /// Every transaction that touched the vault, newest first.
    pub fn history(&self) -> Vec<TxEffect> {
        let mut by_tx: BTreeMap<String, TxEffect> = BTreeMap::new();
        fn entry<'a>(by_tx: &'a mut BTreeMap<String, TxEffect>, txid: &str, height: u32) -> &'a mut TxEffect {
            by_tx.entry(txid.to_owned()).or_insert_with(|| TxEffect { txid: txid.to_owned(), height, received_zat: 0, change_zat: 0, spent_zat: 0 })
        }
        for n in self.notes.values() {
            let e = entry(&mut by_tx, &n.txid, n.height);
            if n.change { e.change_zat += n.value_zat } else { e.received_zat += n.value_zat }
        }
        for n in self.notes.values() {
            if let Some((txid, height)) = &n.spent_in {
                entry(&mut by_tx, txid, *height).spent_zat += n.value_zat;
            }
        }
        let mut out: Vec<TxEffect> = by_tx.into_values().collect();
        out.sort_by(|a, b| b.height.cmp(&a.height).then_with(|| a.txid.cmp(&b.txid)));
        out
    }
}

#[derive(Serialize, Deserialize)]
struct Tip { height: u32, hash: String, sapling: Option<u32>, orchard: Option<u32>, ironwood: Option<u32> }

#[derive(Serialize, Deserialize)]
struct Saved { version: u8, birth: u32, tip: Option<Tip>, notes: Vec<(String, Received)>, source: Option<String> }

/// A compact transaction id as explorers show it (byte-reversed hex).
fn tx_id(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactOrchardAction, CompactTx};
    use zcash_note_encryption::Domain;

    const H: u64 = 4_638_988;

    fn fvk(seed: u8) -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
    }

    /// An Ironwood output to `to`, as a compact action that spends `nf_old`.
    fn action(to: &FullViewingKey, scope: Scope, value: u64, nf_old: Nullifier) -> (Note, CompactOrchardAction) {
        let note = Note::new(to.address_at(0u32, scope), NoteValue::from_raw(value), Rho::from_nf_old(nf_old), NoteVersion::V3, rand_zp::rng());
        let enc = IronwoodNoteEncryption::new(None, note, [0u8; 512]);
        (note, CompactOrchardAction {
            nullifier: nf_old.to_bytes().to_vec(),
            cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes().to_vec(),
            ephemeral_key: IronwoodDomain::epk_bytes(enc.epk()).0.to_vec(),
            ciphertext: AsRef::<[u8]>::as_ref(&enc.encrypt_note_plaintext())[..52].to_vec(),
        })
    }

    fn block(height: u64, hash: u8, prev: u8, txs: Vec<(u8, Vec<CompactOrchardAction>)>, ironwood_size: u32) -> Vec<u8> {
        CompactBlock {
            height,
            hash: vec![hash; 32],
            prev_hash: vec![prev; 32],
            vtx: txs.into_iter().enumerate().map(|(i, (id, ironwood_actions))| CompactTx { index: i as u64, txid: vec![id; 32], ironwood_actions, ..Default::default() }).collect(),
            chain_metadata: Some(ChainMetadata { ironwood_commitment_tree_size: ironwood_size, ..Default::default() }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn finds_received_notes_and_their_spends() {
        let vault = fvk(1);
        let other = fvk(2);
        let zero = Nullifier::from_bytes(&[0u8; 32]).unwrap();
        let (paid, to_vault) = action(&vault, Scope::External, 50_000, zero);
        let (_, to_other) = action(&other, Scope::External, 10_000, paid.nullifier(&other));
        let mut scan = ChainScan::new(VaultNetwork::Testnet, &vault, H as u32).unwrap();
        scan.scan(&block(H, 0xa0, 0x9f, vec![(0xaa, vec![to_vault]), (0xab, vec![to_other])], 2)).unwrap();
        assert_eq!(scan.height(), Some(H as u32));
        assert_eq!(scan.balance_zat(), 50_000);
        assert_eq!(scan.history(), vec![TxEffect { txid: "aa".repeat(32), height: H as u32, received_zat: 50_000, change_zat: 0, spent_zat: 0 }]);

        // The vault spends that note and gets change back on its internal address.
        let (_, change) = action(&vault, Scope::Internal, 39_000, paid.nullifier(&vault));
        scan.scan(&block(H + 1, 0xa1, 0xa0, vec![(0xbb, vec![change])], 3)).unwrap();
        assert_eq!(scan.balance_zat(), 39_000);
        assert_eq!(scan.history(), vec![
            TxEffect { txid: "bb".repeat(32), height: H as u32 + 1, received_zat: 0, change_zat: 39_000, spent_zat: 50_000 },
            TxEffect { txid: "aa".repeat(32), height: H as u32, received_zat: 50_000, change_zat: 0, spent_zat: 0 },
        ]);
    }

    #[test]
    fn refuses_a_block_that_does_not_extend_the_last() {
        let mut scan = ChainScan::new(VaultNetwork::Testnet, &fvk(1), H as u32).unwrap();
        scan.scan(&block(H, 0xa0, 0x9f, vec![], 0)).unwrap();
        assert!(scan.scan(&block(H + 1, 0xa1, 0x55, vec![], 0)).is_err());
        assert!(scan.scan(&block(H + 2, 0xa2, 0xa0, vec![], 0)).is_err(), "a gap is refused");
        assert_eq!(scan.next_height(), H as u32 + 1);
    }

    #[test]
    fn saved_state_resumes_where_it_stopped() {
        let vault = fvk(1);
        let zero = Nullifier::from_bytes(&[0u8; 32]).unwrap();
        let (paid, to_vault) = action(&vault, Scope::External, 50_000, zero);
        let mut scan = ChainScan::new(VaultNetwork::Testnet, &vault, H as u32).unwrap();
        scan.scan(&block(H, 0xa0, 0x9f, vec![(0xaa, vec![to_vault])], 1)).unwrap();

        let saved = scan.to_bytes();
        let mut resumed = ChainScan::from_bytes(VaultNetwork::Testnet, &vault, &saved).unwrap();
        assert_eq!(resumed.next_height(), H as u32 + 1);
        assert_eq!(resumed.balance_zat(), 50_000);
        assert_eq!(resumed.history(), scan.history());
        // The spend in the next block is found from the restored notes.
        let (_, change) = action(&vault, Scope::Internal, 39_000, paid.nullifier(&vault));
        assert_eq!(resumed.spent_by(&paid.nullifier(&vault).to_bytes()), None);
        resumed.scan(&block(H + 1, 0xa1, 0xa0, vec![(0xbb, vec![change])], 2)).unwrap();
        assert_eq!(resumed.balance_zat(), 39_000);
        assert_eq!(resumed.spent_by(&paid.nullifier(&vault).to_bytes()), Some(&("bb".repeat(32), H as u32 + 1)));
        // A block that does not extend the saved tip is still refused.
        let mut again = ChainScan::from_bytes(VaultNetwork::Testnet, &vault, &saved).unwrap();
        assert!(again.scan(&block(H + 1, 0xa1, 0x55, vec![], 1)).is_err());
        assert!(ChainScan::from_bytes(VaultNetwork::Testnet, &vault, b"not a scan").is_err());
    }
}
