use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    fs, io,
    path::Path,
    sync::Mutex,
    time::Duration,
};

use argon2::Argon2;
use async_trait::async_trait;
use incrementalmerkletree::frontier::NonEmptyFrontier;
use orchard::keys::FullViewingKey;
use orchard::{
    note::Note,
    tree::{MerkleHashOrchard, MerklePath},
};
use rand_zp::{rand_core::UnwrapErr, rngs::SysRng};
use rusqlite::{Connection, OptionalExtension};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        AccountBirthday, AccountPurpose, MaxSpendMode, OutputLockStore, WalletCommitmentTrees, WalletRead, WalletWrite,
        chain::{
            BlockCache, BlockSource, ChainState, error::Error as ScanError, scan_cached_blocks,
        },
        error::Error as FundingError,
        scanning::ScanRange,
        wallet::{
            ConfirmationsPolicy, propose_send_max_transfer, propose_transfer,
            input_selection::{GreedyInputSelector, LockedInputPolicy, NoteSelection, SpendPolicy},
        },
    },
    fees::{DustOutputPolicy, StandardFeeRule, zip317::SingleOutputChangeStrategy},
    proto::compact_formats::CompactBlock,
    wallet::{LockOwner, Note as WalletNote, OutputRef, ReceivedNote},
};
use zcash_client_sqlite::{
    ReceivedNoteId, WalletDb, util::SystemClock, wallet::init::init_wallet_db,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{PoolType, ShieldedPool, memo::MemoBytes, value::Zatoshis};
use zeroize::Zeroizing;
use zip321::{Payment, TransactionRequest};

use loki_signer_core::chain_scan::{checked_next_tree_sizes, tree_sizes};
use zcash_client_backend::proto::service::{BlockId, ChainSpec, Empty, ShieldedProtocol};
use zcash_protocol::consensus::Parameters;

use crate::{member_state::MemberState, network::VaultNetwork};

mod lightwalletd;
pub use lightwalletd::Lightwalletd;

type Database = WalletDb<Connection, VaultNetwork, SystemClock, UnwrapErr<SysRng>>;

pub struct VaultWallet {
    db: Database,
    network: VaultNetwork,
}

/// What the wallet's input selector chose to fund one payment.
pub struct Funding {
    pub notes: Vec<Note>,
    pub amount_zat: u64,
    pub fee_zat: u64,
    pub change_zat: u64,
}

struct Blocks<'a>(&'a [CompactBlock]);

#[derive(Default)]
struct DownloadedBlocks(Mutex<BTreeMap<u32, CompactBlock>>);

impl BlockSource for DownloadedBlocks {
    type Error = io::Error;

    fn with_blocks<F, E>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ScanError<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ScanError<E, Self::Error>>,
    {
        let blocks = self.0.lock().map_err(|_| {
            ScanError::BlockSource(io::Error::other("compact block cache poisoned"))
        })?;
        for (_, block) in blocks
            .range(from_height.map(u32::from).unwrap_or(0)..)
            .take(limit.unwrap_or(usize::MAX))
        {
            with_block(block.clone())?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for DownloadedBlocks {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        Ok(blocks
            .keys()
            .rev()
            .find(|height| {
                range.is_none_or(|range| {
                    range
                        .block_range()
                        .contains(&BlockHeight::from_u32(**height))
                })
            })
            .copied()
            .map(BlockHeight::from_u32))
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        (u32::from(range.block_range().start)..u32::from(range.block_range().end))
            .map(|height| {
                blocks
                    .get(&height)
                    .cloned()
                    .ok_or_else(|| io::Error::other(format!("missing compact block {height}")))
            })
            .collect()
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        for block in compact_blocks {
            let height = u32::try_from(block.height)
                .map_err(|_| io::Error::other("compact block height overflow"))?;
            blocks.insert(height, block);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let mut blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        blocks.retain(|height, _| {
            !range
                .block_range()
                .contains(&BlockHeight::from_u32(*height))
        });
        Ok(())
    }
}

impl BlockSource for Blocks<'_> {
    type Error = Infallible;

    fn with_blocks<F, E>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ScanError<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ScanError<E, Self::Error>>,
    {
        let blocks = self
            .0
            .iter()
            .filter(|block| from_height.is_none_or(|height| block.height >= u64::from(height)));
        for block in blocks.take(limit.unwrap_or(usize::MAX)) {
            with_block(block.clone())?;
        }
        Ok(())
    }
}

/// A lightwalletd endpoint: HTTPS, or plain HTTP only on this machine.
pub fn lightwalletd_endpoint(url: &str) -> Result<tonic::transport::Endpoint, String> {
    let endpoint = tonic::transport::Endpoint::from_shared(url.to_owned())
        .map_err(|e| format!("lightwalletd URL: {e}"))?;
    let uri = endpoint.uri();
    if uri.scheme_str() != Some("https")
        && !(uri.scheme_str() == Some("http")
            && matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]")))
    {
        return Err("lightwalletd must use HTTPS, except on localhost".into());
    }
    // tonic needs the webpki roots configured explicitly; the https scheme alone is not TLS.
    if uri.scheme_str() == Some("https") {
        return endpoint
            .tls_config(tonic::transport::ClientTlsConfig::new().with_webpki_roots())
            .map_err(|e| format!("lightwalletd TLS: {e}"));
    }
    Ok(endpoint)
}

/// Agreement with the configured lightwalletd is not independent chain verification.
pub const PROVIDER_REPORTED: &str = "provider_reported";

async fn provider_tip(client: &mut Lightwalletd) -> Result<BlockHeight, String> {
    let tip = tokio::time::timeout(Duration::from_secs(30), client.get_latest_block(ChainSpec {}))
        .await.map_err(|_| "lightwalletd latest block deadline exceeded")?
        .map_err(|e| format!("lightwalletd latest block: {e}"))?
        .into_inner().height;
    if tip >= u64::from(u32::MAX) {
        return Err("lightwalletd tip height out of range".into());
    }
    Ok(BlockHeight::from_u32(tip as u32))
}

async fn provider_block_hash(client: &Lightwalletd, height: BlockHeight) -> Result<BlockHash, String> {
    let blocks = client.blocks(height, height).await?;
    Ok(blocks[0].hash())
}

/// The lightwalletd a member syncs from: `LOKI_LIGHTWALLETD`, or on regtest the one THS runs
/// beside the `LOKI_RPC` node (THS shifts RPC 18232 and lightwalletd 9067 by one offset).
pub fn lightwalletd_url(network: VaultNetwork) -> Option<String> {
    if let Ok(url) = std::env::var("LOKI_LIGHTWALLETD") {
        return Some(url);
    }
    if network != VaultNetwork::Regtest {
        return None;
    }
    let rpc = std::env::var("LOKI_RPC").unwrap_or_else(|_| "127.0.0.1:18232".into());
    let (host, port) = rpc.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?.checked_sub(18232 - 9067)?;
    Some(format!("http://{host}:{port}"))
}

/// Opens this member's wallet, creating it at the vault's birth if needed, and scans it to
/// lightwalletd's tip.
pub async fn sync_member_wallet(
    member: &MemberState,
    owner: &Path,
    passphrase: &str,
    url: &str,
) -> Result<(VaultWallet, Lightwalletd), String> {
    // rustls 0.23 has no default crypto provider; install one before any TLS handshake.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let channel = lightwalletd_endpoint(url)?
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("connect to lightwalletd: {e}"))?;
    let mut client = Lightwalletd::new(channel);
    let birth = member.wallet_birth();
    let info = client
        .get_lightd_info(Empty {})
        .await
        .map_err(|e| format!("lightwalletd info: {e}"))?
        .into_inner();
    member
        .network
        .require_lightwalletd_chain(&info.chain_name, info.sapling_activation_height)?;
    if info.block_height < u64::from(birth) {
        return Err(format!("lightwalletd is below this vault's birth height {birth}"));
    }
    let prior = client
        .get_tree_state(BlockId { height: u64::from(birth - 1), hash: vec![] })
        .await
        .map_err(|e| format!("birth tree state: {e}"))?
        .into_inner();
    if prior.height != u64::from(birth - 1) || prior.network != info.chain_name {
        return Err("lightwalletd returned a different birth checkpoint".into());
    }
    let birthday = AccountBirthday::from_treestate(prior, None)
        .map_err(|e| format!("parse birth tree state: {e}"))?;
    let wallet = VaultWallet::open_and_sync(
        owner,
        member.network,
        &member.fvk,
        &birthday,
        passphrase,
        &mut client,
        url,
    ).await?;
    Ok((wallet, client))
}

impl VaultWallet {
    pub(crate) async fn open_and_sync(
        owner: &Path,
        network: VaultNetwork,
        fvk: &FullViewingKey,
        birthday: &AccountBirthday,
        passphrase: &str,
        client: &mut Lightwalletd,
        url: &str,
    ) -> Result<Self, String> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let sync_lock = options.open(owner.join("wallet.sqlite.sync.lock"))
            .map_err(|e| format!("open wallet sync lock: {e}"))?;
        // The host drops its per-request runtime on stop; a blocking OS lock would
        // hold that shutdown open. Wait asynchronously without losing cancellation.
        loop {
            match sync_lock.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(e) => return Err(format!("lock wallet for provider sync: {e}")),
            }
        }
        let mut wallet = Self::open(&owner.join("wallet.sqlite"), network, fvk, birthday, passphrase)?;
        wallet.sync_from_provider(client, birthday, url).await?;
        Ok(wallet)
    }

    async fn sync(&mut self, client: &mut Lightwalletd, tip: BlockHeight) -> Result<(), String> {
        let deadline = Duration::from_secs(30);
        self.db.put_sapling_subtree_roots(0, &client.subtree_roots(ShieldedProtocol::Sapling, tip).await?)
            .map_err(|e| format!("save Sapling roots: {e}"))?;
        self.db.put_orchard_subtree_roots(0, &client.subtree_roots(ShieldedProtocol::Orchard, tip).await?)
            .map_err(|e| format!("save Orchard roots: {e}"))?;
        self.db.put_ironwood_subtree_roots(0, &client.subtree_roots(ShieldedProtocol::Ironwood, tip).await?)
            .map_err(|e| format!("save Ironwood roots: {e}"))?;
        self.db.update_chain_tip(tip).map_err(|e| format!("save chain tip: {e}"))?;

        // Follow Zakura's scan priorities, but finish and validate a bounded page before
        // passing it to the scanner. Re-read the queue after commits or a rewind.
        let mut last_page = None;
        let mut last_rewind = None;
        while let Some(range) = self.db.suggest_scan_ranges().map_err(|e| e.to_string())?
            .into_iter().find(|range| !range.is_empty())
        {
            let start = range.block_range().start;
            let end = range.block_range().end.min(BlockHeight::from_u32(u32::from(start).saturating_add(100)));
            let page = ScanRange::from_parts(start..end, range.priority());
            if last_page.as_ref() == Some(&page) {
                return Err("wallet scan range did not advance".into());
            }
            let blocks = client.blocks(start, end - 1).await?;
            let previous = start - 1;
            let state = tokio::time::timeout(deadline, client.get_tree_state(BlockId { height: previous.into(), hash: vec![] }))
                .await.map_err(|_| "lightwalletd tree state deadline exceeded")?
                .map_err(|e| format!("lightwalletd tree state: {e}"))?.into_inner().to_chain_state()
                .map_err(|e| format!("parse lightwalletd tree state: {e}"))?;
            if state.block_height() != previous || blocks[0].prev_hash != state.block_hash().0 {
                return Err("lightwalletd tree state does not match the requested block range".into());
            }
            let prior = self.db.block_metadata(previous).map_err(|e| e.to_string())?
                .filter(|m| m.block_hash() == state.block_hash());
            let checkpoint_sizes = [state.final_sapling_tree().tree_size(), state.final_orchard_tree().tree_size(), state.final_ironwood_tree().tree_size()];
            if checkpoint_sizes.iter().any(|&size| size > u64::from(u32::MAX)) {
                return Err("lightwalletd checkpoint tree size out of range".into());
            }
            let mut sizes = prior.as_ref().map_or(checkpoint_sizes.map(|size| Some(size as u32)), tree_sizes);
            for block in &blocks {
                sizes = checked_next_tree_sizes(block, sizes)?;
            }
            let cache = DownloadedBlocks::default();
            cache.insert(blocks).await.map_err(|e| e.to_string())?;
            match scan_cached_blocks(&self.network, &cache, &mut self.db, start, &state, page.len()) {
                Ok(_) => last_page = Some(page),
                Err(ScanError::Scan(zcash_client_backend::scanning::ScanError::PrevHashMismatch { at_height })) => {
                    let rewind = at_height.saturating_sub(10);
                    if last_rewind.is_some_and(|last| rewind >= last) {
                        return Err("wallet scan did not progress after rewinding".into());
                    }
                    self.db.truncate_to_height(rewind).map_err(|e| format!("rewind wallet: {e}"))?;
                    last_rewind = Some(rewind);
                    last_page = None;
                }
                Err(e) => return Err(format!("sync wallet: {e}")),
            }
        }
        Ok(())
    }

    pub fn open(
        path: &Path,
        network: VaultNetwork,
        fvk: &FullViewingKey,
        birthday: &AccountBirthday,
        passphrase: &str,
    ) -> Result<Self, String> {
        Self::open_inner(path, network, fvk, Some(birthday), passphrase)
    }

    pub fn open_existing(
        path: &Path,
        network: VaultNetwork,
        fvk: &FullViewingKey,
        birth_height: u32,
        passphrase: &str,
    ) -> Result<Self, String> {
        if !path.is_file() {
            return Err("wallet database is missing; run loki_wallet_sync first".into());
        }
        let wallet = Self::open_inner(path, network, fvk, None, passphrase)?;
        let account = wallet.account()?;
        if wallet
            .db
            .get_account_birthday(account)
            .map_err(|e| e.to_string())?
            != BlockHeight::from_u32(birth_height)
        {
            return Err("wallet database has a different vault birth height".into());
        }
        Ok(wallet)
    }

    fn open_inner(
        path: &Path,
        network: VaultNetwork,
        fvk: &FullViewingKey,
        birthday: Option<&AccountBirthday>,
        passphrase: &str,
    ) -> Result<Self, String> {
        if !path.exists() {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .map_err(|e| format!("create wallet database: {e}"))?;
        }
        let conn = Connection::open(path).map_err(|e| format!("open wallet database: {e}"))?;
        let salt = blake3::derive_key("Loki wallet database salt v1", &fvk.to_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt[..16], key.as_mut())
            .map_err(|e| format!("derive wallet database key: {e}"))?;
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex::encode(*key)));
        conn.execute_batch(&pragma)
            .map_err(|e| format!("unlock wallet database: {e}"))?;
        let _: String = conn
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|e| format!("SQLCipher unavailable: {e}"))?;
        conn.query_row("SELECT name FROM sqlite_master LIMIT 1", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(|e| format!("wrong wallet passphrase or damaged database: {e}"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ext_loki_chain_source (
                id INTEGER PRIMARY KEY CHECK (id = 0), fingerprint TEXT NOT NULL
            )",
        )
        .map_err(|e| format!("initialize wallet chain source: {e}"))?;
        rusqlite::vtab::array::load_module(&conn)
            .map_err(|e| format!("initialize wallet array queries: {e}"))?;

        let mut db = WalletDb::from_connection(conn, network, SystemClock, UnwrapErr(SysRng));
        init_wallet_db(&mut db, None).map_err(|e| format!("initialize wallet database: {e}"))?;
        let keys = db
            .get_unified_full_viewing_keys()
            .map_err(|e| format!("read wallet accounts: {e}"))?;
        if keys.is_empty() {
            let birthday = birthday.ok_or("wallet database has no vault account")?;
            let ufvk = UnifiedFullViewingKey::from_orchard_fvk(fvk.clone())
                .map_err(|e| format!("vault viewing key: {e:?}"))?;
            db.import_account_ufvk(
                "Loki vault",
                &ufvk,
                birthday,
                AccountPurpose::Spending { derivation: None },
                None,
            )
            .map_err(|e| format!("import vault viewing key: {e}"))?;
        } else if keys.len() != 1
            || keys
                .values()
                .next()
                .and_then(UnifiedFullViewingKey::orchard)
                .map(|saved| saved.to_bytes())
                != Some(fvk.to_bytes())
        {
            return Err("wallet database belongs to another vault".into());
        }
        let account = db
            .get_account_ids()
            .map_err(|e| format!("read wallet accounts: {e}"))?
            .into_iter()
            .next()
            .ok_or("wallet database has no vault account")?;
        if let Some(birthday) = birthday {
            if db
                .get_account_birthday(account)
                .map_err(|e| format!("read wallet birthday: {e}"))?
                != birthday.height()
            {
                return Err("wallet database has a different vault birth height".into());
            }
        }
        Ok(Self { db, network })
    }

    pub fn viewing_key(&self) -> Result<FullViewingKey, String> {
        let keys = self
            .db
            .get_unified_full_viewing_keys()
            .map_err(|e| format!("read vault viewing key: {e}"))?;
        let fvk = keys
            .values()
            .next()
            .and_then(UnifiedFullViewingKey::orchard)
            .ok_or("wallet database has no vault viewing key")?;
        Ok(fvk.clone())
    }

    pub fn account_count(&self) -> Result<usize, String> {
        self.db
            .get_account_ids()
            .map(|ids| ids.len())
            .map_err(|e| format!("read wallet accounts: {e}"))
    }

    pub fn sync_blocks(
        &mut self,
        previous: &ChainState,
        blocks: &[CompactBlock],
    ) -> Result<(), String> {
        if blocks.is_empty() {
            return Ok(());
        }
        let first = blocks.first().expect("nonempty blocks");
        if first.height != u64::from(previous.block_height()) + 1
            || first.prev_hash != previous.block_hash().0
            || blocks.windows(2).any(|pair| {
                pair[1].height != pair[0].height + 1 || pair[1].prev_hash != pair[0].hash
            })
        {
            return Err("compact blocks do not extend the supplied chain state".into());
        }
        scan_cached_blocks(
            &self.network,
            &Blocks(blocks),
            &mut self.db,
            BlockHeight::try_from(first.height).map_err(|_| "block height overflow")?,
            previous,
            blocks.len(),
        )
        .map_err(|e| format!("scan Ironwood blocks: {e}"))?;
        let last = blocks.last().expect("nonempty blocks");
        self.db
            .update_chain_tip(
                BlockHeight::try_from(last.height).map_err(|_| "block height overflow")?,
            )
            .map_err(|e| format!("save chain tip: {e}"))?;
        self.release_confirmed_reservations()
    }

    pub fn scanned_height(&self) -> Result<Option<u32>, String> {
        self.db
            .block_fully_scanned()
            .map(|block| block.map(|metadata| u32::from(metadata.block_height())))
            .map_err(|e| format!("read scan height: {e}"))
    }

    pub fn scanned_hash(&self, height: BlockHeight) -> Result<String, String> {
        self.db
            .get_block_hash(height)
            .map_err(|e| format!("read scanned block hash: {e}"))?
            .map(|hash| hash.to_string())
            .ok_or_else(|| "wallet has no hash for its scanned height".into())
    }

    async fn sync_from_provider(
        &mut self,
        client: &mut Lightwalletd,
        birthday: &AccountBirthday,
        url: &str,
    ) -> Result<(), String> {
        let tip = provider_tip(client).await?;
        if tip < birthday.height() {
            return Err("lightwalletd tip is below this vault's birth".into());
        }
        let source = blake3::hash(url.as_bytes()).to_hex().to_string();
        let matches_source = self.db.transactionally_with_extension(|_, ext| {
            let saved = ext.query_row(
                "SELECT fingerprint FROM ext_loki_chain_source WHERE id = 0",
                [],
                |row| row.get::<_, String>(0),
            ).optional()?;
            Ok::<_, rusqlite::Error>(saved.as_deref() == Some(source.as_str()))
        }).map_err(|e| format!("read wallet chain source: {e}"))?;

        let saved = self.db.get_max_height_hash()
            .map_err(|e| format!("read wallet scan checkpoint: {e}"))?;
        let rewind = match saved {
            // Legacy or different provider: matching block hashes would not vouch for the
            // compact transactions the old provider supplied. Rescan from the vault birth.
            Some(_) if !matches_source => true,
            Some((height, _)) if height > tip => true,
            Some((height, hash)) => provider_block_hash(client, height).await? != hash,
            None => false,
        };
        if rewind || !matches_source {
            use zcash_client_sqlite::error::SqliteClientError;
            self.db.transactionally_with_extension(|db, ext| {
                if rewind {
                    db.truncate_to_chain_state(birthday.prior_chain_state().clone())?;
                }
                ext.execute(
                    "INSERT OR REPLACE INTO ext_loki_chain_source (id, fingerprint) VALUES (0, ?1)",
                    [&source],
                )?;
                Ok::<_, SqliteClientError>(())
            }).map_err(|e| format!("prepare wallet rescan without replacing the database: {e}"))?;
        }

        self.sync(client, tip).await?;
        let scanned = self.db.block_fully_scanned()
            .map_err(|e| format!("read fully scanned block: {e}"))?
            .ok_or("wallet did not scan any blocks")?;
        let height = scanned.block_height();
        if height != tip {
            return Err("wallet has not fully scanned the reported chain tip".into());
        }
        if height > provider_tip(client).await?
            || provider_block_hash(client, height).await? != scanned.block_hash()
        {
            return Err("lightwalletd chain changed during the scan; retry sync".into());
        }
        self.release_confirmed_reservations()
    }

    pub fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, String> {
        self.db.get_tx_height(txid)
            .map_err(|e| format!("read indexed transaction height: {e}"))
    }

    pub fn ironwood_balance_zat(&self) -> Result<u64, String> {
        let height = BlockHeight::from_u32(
            self.scanned_height()?
                .ok_or("wallet has no scanned balance yet")?,
        );
        let account = self.account()?;
        self.db
            .get_unspent_ironwood_notes_at_historical_height(account, height)
            .map_err(|e| format!("read Ironwood notes: {e}"))?
            .iter()
            .try_fold(0u64, |sum, note| {
                sum.checked_add(note.note().value().inner())
                    .ok_or_else(|| "vault balance exceeds u64".to_string())
            })
    }

    pub fn ironwood_note_count(&self, height: BlockHeight) -> Result<usize, String> {
        let account = self.account()?;
        self.db
            .get_unspent_ironwood_notes_at_historical_height(account, height)
            .map(|notes| notes.len())
            .map_err(|e| format!("read Ironwood notes: {e}"))
    }

    /// A payment's input notes, in nullifier order, with witnesses to `frontier` at `height`.
    pub fn ironwood_inputs_at(
        &self,
        height: BlockHeight,
        frontier: NonEmptyFrontier<MerkleHashOrchard>,
        nullifiers: &[[u8; 32]],
    ) -> Result<Vec<(Note, MerklePath)>, String> {
        let notes = self.unspent_notes(height, nullifiers)?;
        let positions = notes
            .iter()
            .map(ReceivedNote::note_commitment_tree_position)
            .collect::<Vec<_>>();
        let witnesses = self
            .db
            .generate_ironwood_witnesses_at_historical_height(&positions, frontier, height)
            .map_err(|e| format!("generate Ironwood witnesses: {e}"))?;
        if notes.len() != witnesses.len() {
            return Err("wallet returned a different number of witnesses than notes".into());
        }
        Ok(notes
            .iter()
            .map(|note| *note.note())
            .zip(witnesses.into_iter().map(MerklePath::from))
            .collect())
    }

    /// The unspent vault notes with these nullifiers at `height`, in the same order.
    fn unspent_notes(
        &self,
        height: BlockHeight,
        nullifiers: &[[u8; 32]],
    ) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, String> {
        let fvk = self.viewing_key()?;
        let mut notes = self
            .db
            .get_unspent_ironwood_notes_at_historical_height(self.account()?, height)
            .map_err(|e| format!("read Ironwood notes: {e}"))?;
        nullifiers
            .iter()
            .map(|nf| {
                notes
                    .iter()
                    .position(|note| note.note().nullifier(&fvk).to_bytes() == *nf)
                    .map(|index| notes.swap_remove(index))
                    .ok_or_else(|| format!("payment input {} is not an unspent vault note", hex::encode(nf)))
            })
            .collect()
    }

    /// Funds a payment from unreserved Ironwood notes with the wallet library's ZIP 317
    /// selector: as many notes as `amount` needs (`None` spends all spendable notes), one
    /// change output, and the library's default confirmation depths.
    pub fn propose(
        &mut self,
        recipient: orchard::Address,
        amount: Option<Zatoshis>,
        memo: MemoBytes,
    ) -> Result<Funding, String> {
        self.propose_with_confirmation_wait(recipient, amount, memo, false)
    }

    pub(crate) fn propose_with_confirmation_wait(
        &mut self,
        recipient: orchard::Address,
        amount: Option<Zatoshis>,
        memo: MemoBytes,
        explain_wait: bool,
    ) -> Result<Funding, String> {
        let account = self.account()?;
        let recipient = ZcashAddress::try_from_encoded(&crate::vault::unified_receiver(
            recipient.to_raw_address_bytes(),
            self.network.network_type(),
        ))
        .map_err(|e| format!("recipient: {e}"))?;
        let confirmations = ConfirmationsPolicy::default();
        let proposal = match amount {
            Some(amount) => {
                let payment = Payment::new(recipient, Some(amount), Some(memo), None, None, vec![])
                    .map_err(|e| format!("payment request: {e:?}"))?;
                let request = TransactionRequest::new(vec![payment])
                    .map_err(|e| format!("payment request: {e:?}"))?;
                let network = &self.network;
                let propose = |db: &mut Database, policy, selection| {
                    propose_transfer::<_, _, _, _, Infallible>(
                        db,
                        network,
                        account,
                        &GreedyInputSelector::new(),
                        &SingleOutputChangeStrategy::new(
                            StandardFeeRule::Zip317,
                            None,
                            ShieldedPool::Ironwood,
                            DustOutputPolicy::default(),
                        ),
                        request.clone(),
                        policy,
                        &SpendPolicy::shielded_pools([ShieldedPool::Ironwood])
                            .with_note_selection(selection),
                        None,
                        None,
                    )
                };
                propose(&mut self.db, confirmations, NoteSelection::PreferConsolidation)
                    .map_err(|error| {
                        // The native host can sign only one input. Check whether lowering just
                        // the confirmation depths would fund it, without reserving any notes.
                        let covers_one_note = |db: &mut Database, policy| {
                            propose(db, policy, NoteSelection::PreferSingle).is_ok_and(|proposal| {
                                proposal.steps().first().shielded_inputs()
                                    .is_some_and(|inputs| inputs.notes().len() == 1)
                            })
                        };
                        if explain_wait && matches!(error, FundingError::InsufficientFunds { .. })
                            && covers_one_note(&mut self.db, ConfirmationsPolicy::MIN)
                            && !covers_one_note(&mut self.db, confirmations)
                        {
                            format!("Funds for this payment are waiting for confirmations. Incoming deposits need {} confirmations before they can be spent.", confirmations.untrusted())
                        } else {
                            format!("fund payment: {error}")
                        }
                    })?
            }
            None => propose_send_max_transfer::<_, _, _, Infallible>(
                &mut self.db,
                &self.network,
                account,
                &[ShieldedPool::Ironwood],
                &StandardFeeRule::Zip317,
                recipient,
                Some(memo),
                MaxSpendMode::MaxSpendable,
                confirmations,
                &LockedInputPolicy::Exclude,
                None,
            )
            .map_err(|e| format!("fund sweep: {e}"))?,
        };
        let step = proposal.steps().first();
        let change = step.balance().proposed_change();
        if proposal.steps().len() != 1
            || !step.transparent_inputs().is_empty()
            || change.len() > 1
            || change.iter().any(|output| output.output_pool() != PoolType::IRONWOOD)
        {
            return Err("wallet proposed a payment shape this vault cannot sign".into());
        }
        let notes = step
            .shielded_inputs()
            .ok_or("wallet proposed a payment without inputs")?
            .notes()
            .iter()
            .map(|input| match input.note() {
                WalletNote::Orchard { note, pool: orchard::ValuePool::Ironwood } => Ok(*note),
                _ => Err("wallet proposed a non-Ironwood input".to_string()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Funding {
            notes,
            amount_zat: step
                .transaction_request()
                .total()
                .ok()
                .flatten()
                .ok_or("wallet proposed an invalid payment total")?
                .into(),
            fee_zat: step.balance().fee_required().into(),
            change_zat: change.first().map_or(0, |output| output.value().into()),
        })
    }

    /// The most one payment can send right now, or `None` when nothing is spendable or a
    /// full sweep would need more than `max_inputs` notes.
    pub fn max_spendable(&mut self, max_inputs: usize) -> Option<u64> {
        let own = self.viewing_key().ok()?.address_at(0u64, orchard::keys::Scope::External);
        let funding = self.propose(own, None, MemoBytes::empty()).ok()?;
        (funding.notes.len() <= max_inputs).then_some(funding.amount_zat)
    }

    /// Reserves a payment's inputs for `owner` until `expiry_height`, so no other proposal on
    /// this device selects them. Fails if another owner already holds one of them.
    pub fn reserve_inputs(
        &mut self,
        owner: LockOwner,
        nullifiers: &[[u8; 32]],
        expiry_height: u32,
    ) -> Result<(), String> {
        let height = self
            .scanned_height()?
            .ok_or("wallet has not scanned any blocks")?;
        if nullifiers.is_empty() || expiry_height <= height {
            return Err("payment has no inputs or has expired".into());
        }
        let outputs = self.input_refs(nullifiers)?;
        self.db
            .lock_outputs(&outputs, owner, BlockHeight::from_u32(expiry_height))
            .map_err(|e| format!("reserve payment inputs: {e:?}"))?;
        Ok(())
    }

    /// Transfer a draft's locks to its finalized transaction as one write. Finishers can also
    /// acquire unreserved inputs, and retries can renew locks already owned by this txid.
    pub fn reserve_broadcast_inputs(
        &mut self,
        attempt: LockOwner,
        txid: TxId,
        nullifiers: &[[u8; 32]],
        expiry_height: u32,
    ) -> Result<(), String> {
        let outputs = self.input_refs(nullifiers)?;
        let account = self.account()?;
        self.db
            .transactionally_with_extension(|db, _| {
                let tip = db.block_fully_scanned()?.ok_or("wallet has not scanned any blocks")?;
                if outputs.is_empty() || expiry_height <= u32::from(tip.block_height()) {
                    return Err("payment has no inputs or has expired".into());
                }
                let notes = db.get_unspent_ironwood_notes_at_historical_height(account, tip.block_height())?;
                for output in &outputs {
                    if !notes.iter().any(|note| {
                        note.txid() == output.txid() && u32::from(note.output_index()) == output.output_index()
                    }) {
                        return Err("payment input is no longer unspent".into());
                    }
                    db.unlock_output(output, attempt)?;
                }
                db.lock_outputs(&outputs, txid.into(), BlockHeight::from_u32(expiry_height))
                    .map_err(|e| io::Error::other(format!("reserve payment inputs: {e:?}")))?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
            .map_err(|e| e.to_string())
    }

    /// Releases `owner`'s reservation of a payment's still-unspent inputs.
    pub fn release_inputs(&mut self, owner: LockOwner, nullifiers: &[[u8; 32]]) -> Result<(), String> {
        for output in self.input_refs(nullifiers)? {
            self.db
                .unlock_output(&output, owner)
                .map_err(|e| format!("release payment inputs: {e}"))?;
        }
        Ok(())
    }

    /// Makes this wallet's reservations match `live`, the notes that payments still in flight
    /// spend: each is reserved for its owner until the given height unless a reservation already
    /// holds it, and every other reservation is released.
    pub fn set_reservations(
        &mut self,
        live: &BTreeMap<[u8; 32], (LockOwner, u32)>,
    ) -> Result<(), String> {
        let mut held = BTreeSet::new();
        let locked = self
            .db
            .get_locked_outputs(self.account()?)
            .map_err(|e| format!("read reserved inputs: {e}"))?;
        for output in locked.iter().filter(|output| output.pool() == PoolType::IRONWOOD) {
            let (nf, owner) = self
                .db
                .transactionally_with_extension(|_, ext| {
                    ext.query_row(
                        "SELECT rn.nf, rn.lock_owner FROM ironwood_received_notes rn \
                         JOIN transactions t ON t.id_tx = rn.transaction_id \
                         WHERE t.txid = ?1 AND rn.action_index = ?2",
                        rusqlite::params![output.txid().as_ref(), output.output_index()],
                        |row| Ok((row.get::<_, Option<[u8; 32]>>(0)?, row.get::<_, Option<[u8; 32]>>(1)?)),
                    )
                })
                .map_err(|e: rusqlite::Error| format!("read reservation: {e}"))?;
            match (nf, owner) {
                (Some(nf), Some(_)) if live.contains_key(&nf) => {
                    held.insert(nf);
                }
                (_, Some(owner)) => {
                    self.db
                        .unlock_output(output, LockOwner::new(owner))
                        .map_err(|e| format!("release payment inputs: {e}"))?;
                }
                _ => {}
            }
        }
        for (nf, (owner, expiry)) in live.iter().filter(|(nf, _)| !held.contains(*nf)) {
            // A note this wallet has not scanned yet, has seen spent, or that is past the
            // payment's expiry is not one a new draft could select either.
            let _ = self.reserve_inputs(*owner, &[*nf], *expiry);
        }
        Ok(())
    }

    /// The transaction in a scanned block that spent the vault note with this nullifier, if
    /// any. Transactions that are only in the mempool never count.
    pub fn mined_spend(&mut self, nullifier: &[u8; 32]) -> Result<Option<TxId>, String> {
        self.db
            .transactionally_with_extension(|_, ext| {
                ext.query_row(
                    "SELECT t.txid FROM ironwood_received_notes rn \
                     JOIN ironwood_received_note_spends s ON s.ironwood_received_note_id = rn.id \
                     JOIN transactions t ON t.id_tx = s.transaction_id \
                     WHERE rn.nf = ?1 AND t.mined_height IS NOT NULL LIMIT 1",
                    [nullifier.as_slice()],
                    |row| row.get::<_, [u8; 32]>(0),
                )
                .optional()
            })
            .map(|txid| txid.map(TxId::from_bytes))
            .map_err(|e: rusqlite::Error| format!("read note spend: {e}"))
    }

    /// The unspent vault note with this nullifier at the scanned height.
    pub fn unspent_note(&self, nullifier: &[u8; 32]) -> Result<Note, String> {
        let height = self
            .scanned_height()?
            .ok_or("wallet has not scanned any blocks")?;
        Ok(*self.unspent_notes(BlockHeight::from_u32(height), &[*nullifier])?[0].note())
    }

    fn input_refs(&self, nullifiers: &[[u8; 32]]) -> Result<Vec<OutputRef>, String> {
        let height = self
            .scanned_height()?
            .ok_or("wallet has not scanned any blocks")?;
        Ok(self
            .unspent_notes(BlockHeight::from_u32(height), nullifiers)?
            .iter()
            .map(|note| OutputRef::new(*note.txid(), PoolType::IRONWOOD, note.output_index().into()))
            .collect())
    }

    fn account(&self) -> Result<zcash_client_sqlite::AccountUuid, String> {
        self.db
            .get_account_ids()
            .map_err(|e| format!("read vault account: {e}"))?
            .into_iter()
            .next()
            .ok_or_else(|| "wallet has no vault account".into())
    }

    fn release_confirmed_reservations(&mut self) -> Result<(), String> {
        let account = self.account()?;
        let locked = self
            .db
            .get_locked_outputs(account)
            .map_err(|e| format!("read reserved inputs: {e}"))?;
        if locked.is_empty() {
            return Ok(());
        }
        self.db
            .transactionally_with_extension(|db, ext| {
                for output in locked
                    .iter()
                    .filter(|output| output.pool() == PoolType::IRONWOOD)
                {
                    let owner: Option<Vec<u8>> = ext
                        .query_row(
                            "SELECT rn.lock_owner FROM ironwood_received_notes rn \
                     JOIN transactions t ON t.id_tx = rn.transaction_id \
                     WHERE t.txid = ?1 AND rn.action_index = ?2",
                            rusqlite::params![output.txid().as_ref(), output.output_index()],
                            |row| row.get(0),
                        )
                        .optional()?
                        .flatten();
                    if let Some(owner) = owner {
                        let owner: [u8; 32] = owner
                            .try_into()
                            .map_err(|_| io::Error::other("invalid payment reservation owner"))?;
                        if db.get_tx_height(TxId::from_bytes(owner))?.is_some() {
                            db.unlock_output(output, LockOwner::new(owner))?;
                        }
                    }
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            })
            .map_err(|e| format!("release confirmed payment inputs: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::frontier::Frontier;
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use zcash_client_backend::data_api::scanning::ScanPriority;
    use zcash_client_backend::proto::compact_formats::{
        ChainMetadata, CompactOrchardAction, CompactTx,
    };
    use zcash_note_encryption::Domain;
    use zcash_primitives::block::BlockHash;

    fn locked(wallet: &VaultWallet) -> usize {
        wallet.db.get_locked_outputs(wallet.account().unwrap()).unwrap().len()
    }

    #[test]
    fn plaintext_lightwalletd_is_only_allowed_on_loopback() {
        assert!(lightwalletd_endpoint("https://wallet.example").is_ok());
        assert!(lightwalletd_endpoint("http://localhost:9067").is_ok());
        assert!(lightwalletd_endpoint("http://127.0.0.1:9067").is_ok());
        assert!(lightwalletd_endpoint("http://wallet.example").is_err());
        assert!(lightwalletd_endpoint("http://127.0.0.1.evil.example").is_err());
    }

    #[test]
    fn downloaded_blocks_must_be_contiguous_and_can_be_replaced() {
        let cache = DownloadedBlocks::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let range = ScanRange::from_parts(
            BlockHeight::from_u32(7)..BlockHeight::from_u32(10),
            ScanPriority::Historic,
        );
        runtime.block_on(async {
            cache
                .insert(vec![
                    CompactBlock {
                        height: 7,
                        ..Default::default()
                    },
                    CompactBlock {
                        height: 9,
                        ..Default::default()
                    },
                ])
                .await
                .unwrap();
            assert!(cache.read(&range).await.is_err());
            cache
                .insert(vec![CompactBlock {
                    height: 8,
                    ..Default::default()
                }])
                .await
                .unwrap();
            assert_eq!(cache.read(&range).await.unwrap().len(), 3);
            cache
                .insert(vec![CompactBlock {
                    height: 8,
                    hash: vec![42; 32],
                    ..Default::default()
                }])
                .await
                .unwrap();
            assert_eq!(cache.read(&range).await.unwrap()[1].hash, vec![42; 32]);
            cache.truncate(BlockHeight::from_u32(8)).await.unwrap();
            assert_eq!(
                cache.get_tip_height(None).unwrap(),
                Some(BlockHeight::from_u32(8))
            );
        });
    }

    #[test]
    fn broadcast_reservation_expires_and_reorg_releases_confirmed_spend() {
        let fvk = FullViewingKey::from(&SpendingKey::from_bytes([3; 32]).unwrap());
        let height = crate::network::TESTNET_NU7_BIRTH;
        let prior = ChainState::empty(BlockHeight::from_u32(height - 1), BlockHash([7; 32]));
        let birthday = AccountBirthday::from_parts(prior.clone(), None);
        let path = std::env::temp_dir().join(format!(
            "loki-wallet-reorg-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rho = Rho::from_bytes(&[4; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([5; 32], &rho).unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(50_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let enc = IronwoodNoteEncryption::new(None, note, [0; 512]);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let funded = CompactBlock {
            height: u64::from(height),
            hash: vec![8; 32],
            prev_hash: vec![7; 32],
            vtx: vec![CompactTx {
                txid: vec![6; 32],
                index: 1,
                ironwood_actions: vec![CompactOrchardAction {
                    nullifier: vec![4; 32],
                    cmx: cmx.to_bytes().to_vec(),
                    ephemeral_key: IronwoodDomain::epk_bytes(enc.epk()).0.to_vec(),
                    ciphertext: enc.encrypt_note_plaintext()[..52].to_vec(),
                }],
                ..Default::default()
            }],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut wallet =
            VaultWallet::open(&path, VaultNetwork::Testnet, &fvk, &birthday, "pass").unwrap();
        wallet.sync_blocks(&prior, &[funded]).unwrap();
        drop(wallet);
        let mut wallet =
            VaultWallet::open_existing(&path, VaultNetwork::Testnet, &fvk, height, "pass").unwrap();
        assert_eq!(
            wallet.scanned_hash(BlockHeight::from_u32(height)).unwrap(),
            BlockHash([8; 32]).to_string()
        );
        assert_eq!(
            wallet.mined_height(TxId::from_bytes([6; 32])).unwrap(),
            Some(BlockHeight::from_u32(height))
        );
        assert_eq!(wallet.ironwood_balance_zat().unwrap(), 50_000);
        assert_eq!(
            wallet
                .ironwood_note_count(BlockHeight::from_u32(height))
                .unwrap(),
            1
        );
        let mut frontier = Frontier::<MerkleHashOrchard, 32>::empty();
        assert!(frontier.append(MerkleHashOrchard::from_cmx(&cmx)));
        let nullifier = note.nullifier(&fvk).to_bytes();
        let inputs = wallet
            .ironwood_inputs_at(
                BlockHeight::from_u32(height),
                frontier.value().unwrap().clone(),
                &[nullifier],
            )
            .unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].1.root(cmx).to_bytes(), frontier.root().to_bytes());
        let payment_txid = TxId::from_bytes([10; 32]);
        wallet
            .reserve_inputs(payment_txid.into(), &[nullifier], height + 1)
            .unwrap();
        assert!(wallet
            .reserve_inputs(TxId::from_bytes([11; 32]).into(), &[nullifier], height + 1)
            .is_err());
        drop(wallet);
        let mut wallet =
            VaultWallet::open_existing(&path, VaultNetwork::Testnet, &fvk, height, "pass").unwrap();
        assert_eq!(locked(&wallet), 1);

        let funded_state = ChainState::new(
            BlockHeight::from_u32(height),
            BlockHash([8; 32]),
            Frontier::empty(),
            Frontier::empty(),
            frontier.clone(),
        );
        let empty = CompactBlock {
            height: u64::from(height + 1),
            hash: vec![9; 32],
            prev_hash: vec![8; 32],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        wallet.sync_blocks(&funded_state, &[empty]).unwrap();
        assert_eq!(locked(&wallet), 0);

        wallet
            .reserve_inputs(payment_txid.into(), &[nullifier], height + 10)
            .unwrap();
        assert_eq!(locked(&wallet), 1);
        let before_spend = ChainState::new(
            BlockHeight::from_u32(height + 1),
            BlockHash([9; 32]),
            Frontier::empty(),
            Frontier::empty(),
            frontier.clone(),
        );
        let spent = CompactBlock {
            height: u64::from(height + 2),
            hash: vec![10; 32],
            prev_hash: vec![9; 32],
            vtx: vec![CompactTx {
                txid: payment_txid.as_ref().to_vec(),
                index: 1,
                ironwood_actions: vec![CompactOrchardAction {
                    nullifier: nullifier.to_vec(),
                    cmx: vec![0; 32],
                    ephemeral_key: vec![0; 32],
                    ciphertext: vec![0; 52],
                }],
                ..Default::default()
            }],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 2,
                ..Default::default()
            }),
            ..Default::default()
        };
        wallet.sync_blocks(&before_spend, &[spent]).unwrap();
        assert_eq!(wallet.mined_spend(&nullifier).unwrap(), Some(payment_txid));
        assert_eq!(
            wallet.mined_height(payment_txid).unwrap(),
            Some(BlockHeight::from_u32(height + 2))
        );
        assert_eq!(
            wallet
                .ironwood_note_count(BlockHeight::from_u32(height + 2))
                .unwrap(),
            0
        );
        assert_eq!(locked(&wallet), 0);
        wallet
            .db
            .truncate_to_chain_state(before_spend.clone())
            .unwrap();
        let replacement_spend = CompactBlock {
            height: u64::from(height + 2),
            hash: vec![11; 32],
            prev_hash: vec![9; 32],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        wallet
            .sync_blocks(&before_spend, &[replacement_spend])
            .unwrap();
        assert_eq!(wallet.mined_height(payment_txid).unwrap(), None);
        assert_eq!(locked(&wallet), 0);
        assert_eq!(wallet.mined_spend(&nullifier).unwrap(), None);
        assert_eq!(
            wallet
                .ironwood_note_count(BlockHeight::from_u32(height + 2))
                .unwrap(),
            1
        );

        wallet.db.truncate_to_chain_state(prior.clone()).unwrap();
        let replacement = CompactBlock {
            height: u64::from(height),
            hash: vec![9; 32],
            prev_hash: vec![7; 32],
            chain_metadata: Some(ChainMetadata::default()),
            ..Default::default()
        };
        wallet.sync_blocks(&prior, &[replacement]).unwrap();
        assert_eq!(
            wallet.scanned_hash(BlockHeight::from_u32(height)).unwrap(),
            BlockHash([9; 32]).to_string()
        );
        assert_eq!(
            wallet.mined_height(TxId::from_bytes([6; 32])).unwrap(),
            None
        );
        assert_eq!(
            wallet
                .ironwood_note_count(BlockHeight::from_u32(height))
                .unwrap(),
            0
        );
        assert_eq!(wallet.ironwood_balance_zat().unwrap(), 0);
        drop(wallet);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn payment_combines_small_notes_and_skips_reserved_ones() {
        let fvk = FullViewingKey::from(&SpendingKey::from_bytes([3; 32]).unwrap());
        let height = crate::network::TESTNET_NU7_BIRTH;
        let prior = ChainState::empty(BlockHeight::from_u32(height - 1), BlockHash([7; 32]));
        let path = std::env::temp_dir().join(format!(
            "loki-wallet-notes-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let notes: Vec<Note> = (0..3u8)
            .map(|i| {
                let rho = Rho::from_bytes(&[20 + i; 32]).unwrap();
                Note::from_parts(
                    fvk.address_at(0u64, Scope::External),
                    NoteValue::from_raw(50_000),
                    rho,
                    RandomSeed::from_bytes([30 + i; 32], &rho).unwrap(),
                    NoteVersion::V3,
                )
                .unwrap()
            })
            .collect();
        let actions = notes
            .iter()
            .enumerate()
            .map(|(i, note)| {
                let enc = IronwoodNoteEncryption::new(None, *note, [0; 512]);
                CompactOrchardAction {
                    nullifier: vec![20 + i as u8; 32],
                    cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes().to_vec(),
                    ephemeral_key: IronwoodDomain::epk_bytes(enc.epk()).0.to_vec(),
                    ciphertext: enc.encrypt_note_plaintext()[..52].to_vec(),
                }
            })
            .collect();
        // Funding block, then enough empty blocks for the default ten confirmations.
        let mut blocks: Vec<CompactBlock> = (0..10u8)
            .map(|i| CompactBlock {
                height: u64::from(height) + u64::from(i),
                hash: vec![8 + i; 32],
                prev_hash: vec![7 + i; 32],
                chain_metadata: Some(ChainMetadata {
                    ironwood_commitment_tree_size: 3,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect();
        blocks[0].vtx = vec![CompactTx { txid: vec![6; 32], index: 1, ironwood_actions: actions, ..Default::default() }];
        let mut wallet = VaultWallet::open(
            &path,
            VaultNetwork::Testnet,
            &fvk,
            &AccountBirthday::from_parts(prior.clone(), None),
            "pass",
        )
        .unwrap();
        wallet.sync_blocks(&prior, &blocks).unwrap();
        let recipient = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap())
            .address_at(0u64, Scope::External);
        let pay = |wallet: &mut VaultWallet, zat| {
            wallet.propose(recipient, Some(Zatoshis::const_from_u64(zat)), MemoBytes::empty())
        };

        // No single 50,000 note covers 100,000, so all three are spent in one payment.
        let funding = pay(&mut wallet, 100_000).unwrap();
        assert_eq!(funding.notes.len(), 3);
        assert_eq!((funding.amount_zat, funding.fee_zat, funding.change_zat), (100_000, 15_000, 35_000));
        assert_eq!(wallet.max_spendable(3), Some(135_000));
        assert_eq!(wallet.max_spendable(2), None);

        // A note reserved by another draft is not offered again.
        let reserved = notes[0].nullifier(&fvk).to_bytes();
        let draft = LockOwner::new([1; 32]);
        wallet.reserve_inputs(draft, &[reserved], height + 100).unwrap();
        assert!(pay(&mut wallet, 100_000).is_err());
        let funding = pay(&mut wallet, 60_000).unwrap();
        assert_eq!(funding.notes.len(), 2);
        assert!(funding.notes.iter().all(|note| note.nullifier(&fvk).to_bytes() != reserved));
        // Reservations follow the payments still in flight: a note one of them spends stays
        // reserved by whoever holds it, and every other reservation is released.
        let second = notes[1].nullifier(&fvk).to_bytes();
        let other = LockOwner::new([2; 32]);
        let live = |nfs: &[[u8; 32]]| -> BTreeMap<_, _> {
            nfs.iter().map(|nf| (*nf, (other, height + 100))).collect()
        };
        wallet.set_reservations(&live(&[reserved, second])).unwrap();
        assert_eq!(locked(&wallet), 2);
        assert!(wallet.reserve_inputs(other, &[reserved], height + 100).is_err());
        assert!(pay(&mut wallet, 60_000).is_err());
        wallet.set_reservations(&live(&[second])).unwrap();
        assert_eq!(locked(&wallet), 1);
        let funding = pay(&mut wallet, 60_000).unwrap();
        assert!(funding.notes.iter().all(|note| note.nullifier(&fvk).to_bytes() != second));
        wallet.set_reservations(&BTreeMap::new()).unwrap();
        assert_eq!(locked(&wallet), 0);
        assert_eq!(pay(&mut wallet, 100_000).unwrap().notes.len(), 3);
        drop(wallet);
        std::fs::remove_file(path).unwrap();
    }
}
