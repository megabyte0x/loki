//! Device-bound custody of a hosted vault's signing share.
//!
//! The share (key package, group public package and the vault secret `vs`) lives only in the
//! signer store, `vaults/<id>/signer/share.sealed`, sealed under the configured secure element:
//! the Secure Enclave for `--secure-element apple`, the passphrase-wrapped software KEK for
//! `software`. `vault.sealed` holds public vault metadata only. Payments reopen the store with
//! that element ([`open_signer`]); balance scans take the viewing key from the opened signer
//! once per process ([`viewing_key`]), so neither ever needs the share outside the store.
//!
//! [`migrate`] upgrades a vault written before this: its `vault.sealed` carried the key
//! package and `vs` under the profile passphrase alone, and the hosted DKG sealed the store
//! under the software element whatever `--secure-element` said.

use std::path::Path;

use icu_properties::{props::{BidiClass, QuotationMark}, CodePointMapData, CodePointSetData};
use orchard::keys::FullViewingKey;
use reddsa_frost::frost::redpallas as frost;
use serde_json::Value;
use zcash_protocol::consensus::Parameters;

use super::state::{AppState, HostedSecureElement};
use crate::{
    network::VaultNetwork,
    signer::{
        local::{decode_share, encode_share, ApprovalPolicy, LocalSigner},
        nonce::NonceStore,
        secure_element::{SecureElement, SoftwareSecureElement},
        store::{FileKind, SignerStore},
        Network,
    },
    vault, zip2005,
};

pub(super) type HostedSigner = LocalSigner<HostedSecureElement>;

const FILES: [FileKind; 4] = [FileKind::Identity, FileKind::Roster, FileKind::Setup, FileKind::Share];

/// A missing metadata file does not make a directory with sealed signer data new.
pub(super) fn has_signer_data(dir: &Path) -> Result<bool, String> {
    for file in ["signer.meta", "identity.sealed", "roster.sealed", "setup.sealed", "share.sealed"] {
        if dir.join(file).try_exists().map_err(|_| "LokiSigner could not access the signer folder.")? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| "expected 32 bytes of hex".into())
}

fn signer_network(network: VaultNetwork) -> Network {
    match network {
        VaultNetwork::Regtest => Network::Regtest,
        VaultNetwork::Testnet => Network::Testnet,
    }
}

fn group_viewing_key(public: &frost::keys::PublicKeyPackage, vs: &[u8; 32]) -> Result<FullViewingKey, String> {
    let ak: [u8; 32] = public.verifying_key().serialize().map_err(|e| e.to_string())?
        .try_into().map_err(|_| "group key length")?;
    zip2005::frost_viewing_key(&ak, vs).map_err(|e| format!("group viewing key: {e:?}"))
}

/// Open member `slot`'s signer for `vault` from its store, under the configured element. A
/// DKG-made store is revalidated against its certified setup ([`LocalSigner::open`]); a store
/// restored from the recovery words holds only the share and opens from it.
pub(super) fn open_signer(
    st: &AppState,
    data: &Path,
    pass: &str,
    vault: &str,
    slot: u16,
    approval: ApprovalPolicy,
) -> Result<HostedSigner, String> {
    open_signer_with_reason(st, data, pass, vault, slot, approval, None)
}

pub(super) fn open_signer_with_reason(
    st: &AppState,
    data: &Path,
    pass: &str,
    vault: &str,
    slot: u16,
    approval: ApprovalPolicy,
    reason: Option<&str>,
) -> Result<HostedSigner, String> {
    let sdir = super::ceremony::signer_dir(data, vault)?;
    let store = SignerStore::open(&sdir)?;
    if store.vault() != hex32(vault)? || store.member() != slot {
        return Err("this vault's signer belongs to another vault or member".into());
    }
    let se = st.config.open_secure_element_with_reason(&sdir, pass, reason)?;
    if sdir.join("setup.sealed").exists() {
        let prompts = super::ceremony::hosted_prompts(&sdir, pass, approval);
        return LocalSigner::open(&sdir, se, vault.to_owned(), prompts).map_err(|e| e.to_string());
    }
    let (epoch, raw) = store.read(&se, FileKind::Share)?.ok_or("this vault's signer holds no share")?;
    let (key, public_bytes, vs) = decode_share(&raw)?;
    let public = frost::keys::PublicKeyPackage::deserialize(&public_bytes).map_err(|e| e.to_string())?;
    let threshold = public.min_signers().ok_or("share has no threshold")?;
    let members = u16::try_from(public.verifying_shares().len()).map_err(|_| "member count")?;
    let fvk = group_viewing_key(&public, &vs)?;
    let nonces = NonceStore::open_at_epoch(&sdir.join("nonces"), epoch, store.vault(), slot)
        .map_err(|e| e.to_string())?;
    LocalSigner::from_restored(
        slot, threshold, members, store.vault(), vault.to_owned(), store.network(), se,
        &key, public_bytes, fvk, epoch, nonces, approval, None,
    )
    .map_err(|e| e.to_string())
}

#[derive(Clone, Copy)]
pub(super) enum VaultOpen {
    Read,
    Retry,
    Payment,
}

const NEEDS_TOUCH_ID: &str = "Touch ID is required to open this vault.";
const CANCELLED_TOUCH_ID: &str = "Touch ID was cancelled.";

/// The vault's group viewing key, from the opened signer (one store open per process, then
/// cached in memory), checked against the public metadata in `vault.sealed` (`sealed`).
/// Migrates a pre-fix `vault.sealed` first.
pub(super) fn viewing_key(
    st: &AppState,
    data: &Path,
    pass: &str,
    vault: &str,
    slot: u16,
    sealed: &Value,
    mode: VaultOpen,
    open: impl FnOnce() -> Result<SignerViewingKey, String>,
) -> Result<FullViewingKey, String> {
    let mut cache = st.viewing_keys.lock().map_err(|e| e.to_string())?;
    if let Some(Some(fvk)) = cache.get(vault) {
        return Ok(fvk.clone());
    }
    if matches!(mode, VaultOpen::Read) && cache.contains_key(vault) {
        return Err(NEEDS_TOUCH_ID.into());
    }
    let key = (|| {
        if is_legacy(sealed) {
            migrate(st, data, pass, vault, slot, sealed)?;
        }
        open()
    })().map_err(|error| {
        // Keep the cancellation under the same lock as the open so queued reads can't reprompt.
        if !matches!(mode, VaultOpen::Payment) && st.config.native && st.config.secure_element == "apple"
            && error.rsplit(": ").next() == Some(CANCELLED_TOUCH_ID)
        {
            cache.insert(vault.to_owned(), None);
            return NEEDS_TOUCH_ID.into();
        }
        error
    })?;
    key.checked_address(sealed, VaultNetwork::parse(sealed["network"].as_str().unwrap_or(""))?)?;
    cache.insert(vault.to_owned(), Some(key.fvk.clone()));
    Ok(key.fvk)
}

fn opened_viewing_key(
    st: &AppState,
    data: &Path,
    pass: &str,
    vault: &str,
    slot: u16,
    sealed: &Value,
) -> Result<FullViewingKey, String> {
    let signer = open_signer(st, data, pass, vault, slot, Box::new(|_| false))?;
    let (key, _) = SignerViewingKey::from_signer(&signer)?;
    let network = VaultNetwork::parse(sealed["network"].as_str().unwrap_or(""))?;
    key.checked_address(sealed, network)?;
    Ok(key.fvk)
}

pub(super) fn vault_touch_id_reason(st: &AppState, action: &str, vault: &str, name: Option<&str>) -> Option<String> {
    if !st.config.native || st.config.secure_element != "apple" { return None; }
    let label = super::vault_label(name.unwrap_or_default());
    let quotes = CodePointSetData::new::<QuotationMark>();
    let bidi = CodePointMapData::<BidiClass>::new();
    Some(if label == super::HIDDEN_VAULT_NAME || label.trim().is_empty() || label.chars().any(|c| {
        quotes.contains(c) || matches!(bidi.get(c), BidiClass::RightToLeft | BidiClass::ArabicLetter | BidiClass::ArabicNumber)
    }) {
        format!("{action} vault {}", &vault[..8])
    } else {
        format!("{action} vault “{label}”")
    })
}

/// Store-derived values, kept together so the native window can recheck a fresh seal on cache hits.
#[derive(Clone)]
pub(super) struct SignerViewingKey {
    fvk: FullViewingKey,
    public_package: String,
}

impl SignerViewingKey {
    pub(super) fn open(
        st: &AppState, data: &Path, pass: &str, vault: &str, slot: u16, reason: Option<&str>,
    ) -> Result<(Self, VaultNetwork), String> {
        // Never signs or enters a cache: only the viewing key outlives this open.
        let signer = open_signer_with_reason(st, data, pass, vault, slot, Box::new(|_| false), reason)?;
        Self::from_signer(&signer)
    }

    pub(super) fn from_signer(signer: &HostedSigner) -> Result<(Self, VaultNetwork), String> {
        let (public, fvk) = signer.hosted_metadata().map_err(|e| e.to_string())?;
        let network = match signer.network() {
            Network::Regtest => VaultNetwork::Regtest,
            Network::Testnet => VaultNetwork::Testnet,
        };
        let public_package = hex::encode(public.serialize().map_err(|e| e.to_string())?);
        Ok((Self { fvk, public_package }, network))
    }

    pub(super) fn checked_address(&self, sealed: &Value, network: VaultNetwork) -> Result<String, String> {
        let address = vault::unified_address(&self.fvk, network.network_type());
        if sealed["public_package"].as_str() != Some(&self.public_package)
            || sealed["group_address"].as_str() != Some(&address)
        {
            return Err("the signer's share differs from this vault's public metadata".into());
        }
        Ok(address)
    }
}

/// Whether `vault.sealed` still carries the share or the vault secret.
pub(super) fn is_legacy(sealed: &Value) -> bool {
    sealed.get("key_package").is_some() || sealed.get("vault_secret").is_some()
}

/// One-time upgrade of a vault whose `vault.sealed` carries the share and `vs`. Needs the
/// profile passphrase (to read both) and this device (the configured element). It:
///
/// 1. makes sure the signer store holds that same share under the configured element: a store
///    sealed under the software element is resealed under the Enclave when `apple` is
///    configured, file by file, and a store with no share gets the one from `vault.sealed`;
///    a store whose share differs from `vault.sealed` stops the migration with nothing changed;
/// 2. opens the signer from the store and checks it yields the same public package and vault
///    address, so signing works without `vault.sealed`'s copy;
/// 3. only then rewrites `vault.sealed` (atomically) without `key_package` and `vault_secret`,
///    deletes the software KEK the store no longer uses (apple), and deletes the passphrase-only
///    `backup.sealed` only after publishing a verified replacement to confirmed words.
///
/// Recovery is untouched: `recovery.backup` and the words open exactly as before. Limits: the
/// old files are unlinked, not securely erased, so a copy taken before migration (or a disk
/// image) still holds the share under the passphrase alone; and a vault without a recovery
/// backup keeps `backup.sealed` until recovery is set up, which then seals and deletes it.
pub(super) fn migrate(
    st: &AppState,
    data: &Path,
    pass: &str,
    vault: &str,
    slot: u16,
    sealed: &Value,
) -> Result<(), String> {
    let field = |name: &str| sealed[name].as_str().ok_or_else(|| format!("legacy vault.sealed: missing {name}"));
    let key = zeroize::Zeroizing::new(hex::decode(field("key_package")?).map_err(|e| e.to_string())?);
    let public = hex::decode(field("public_package")?).map_err(|e| e.to_string())?;
    let vs = zeroize::Zeroizing::new(hex32(field("vault_secret")?)?);
    let legacy = encode_share(&key, &public, &vs);
    let network = VaultNetwork::parse(field("network")?)?;

    let sdir = super::ceremony::signer_dir(data, vault)?;
    let id = hex32(vault)?;
    let network = signer_network(network);
    let store = has_signer_data(&sdir)?.then(|| SignerStore::open(&sdir)).transpose()?;
    if store.as_ref().is_some_and(|store| store.vault() != id || store.member() != slot || store.network() != network) {
        return Err("this vault's signer belongs to another vault or member".into());
    }
    let software_kek = sdir.join("kek.sealed");
    let old = if st.config.secure_element == "apple" && software_kek.exists() {
        Some(SoftwareSecureElement::persistent(&sdir, pass)?)
    } else {
        None
    };
    // A partially migrated store already relies on its Enclave key. Only allow a fresh key
    // when no signer exists or every file still opens with the original software KEK.
    let new_key = store.as_ref().is_none_or(|store| {
        old.as_ref().is_some_and(|old| FILES.iter().all(|&file| store.read(old, file).is_ok()))
    });
    let se = if new_key {
        st.config.create_secure_element(&sdir, pass, None, data)?
    } else {
        st.config.open_secure_element(&sdir, pass)?
    };
    let store = match store {
        Some(store) => store,
        None => SignerStore::create(&sdir, network, id, slot)?,
    };
    if let Some(old) = &old {
        reseal(&store, old, &se)?;
    }
    match store.read(&se, FileKind::Share)? {
        Some((_, raw)) if !same_share(&raw, &legacy)? => {
            return Err("this vault's signer holds a different share than vault.sealed; not migrating".into())
        }
        Some(_) => {}
        None => store.write(&se, FileKind::Share, 0, &legacy)?,
    }
    opened_viewing_key(st, data, pass, vault, slot, sealed)?;

    let mut stripped = sealed.clone();
    let object = stripped.as_object_mut().ok_or("vault.sealed is not an object")?;
    object.remove("key_package");
    object.remove("vault_secret");
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&stripped).map_err(|e| e.to_string())?);
    // `write_sealed` never replaces a file: seal to a temporary name, then rename over.
    let vdir = super::ceremony::dir(data, vault)?;
    let temp = format!(".vault.sealed.{}.migrate", uuid::Uuid::new_v4());
    vdir.write_sealed(&temp, &bytes, pass).map_err(|e| e.to_string())?;
    std::fs::rename(vdir.path().join(&temp), vdir.path().join("vault.sealed"))
        .and_then(|_| std::fs::File::open(vdir.path())?.sync_all())
        .map_err(|e| {
            let _ = std::fs::remove_file(vdir.path().join(&temp));
            format!("rewrite vault.sealed: {e}")
        })?;
    if old.is_some() {
        std::fs::remove_file(&software_kek).map_err(|e| format!("remove software KEK: {e}"))?;
    }
    // The migrated vault is usable even if an old backup is corrupt. Keep that backup
    // and report the conversion error, rather than treating presence as verification.
    if let Err(e) = super::recovery::seal_vault_backup(data, &sdir, &id, pass) {
        eprintln!("recovery backup not converted for vault {vault}: {e}");
    }
    Ok(())
}

/// Whether two share files hold the same key package, public package and `vs`.
fn same_share(a: &[u8], b: &[u8]) -> Result<bool, String> {
    let ((ka, pa, va), (kb, pb, vb)) = (decode_share(a)?, decode_share(b)?);
    let key = |k: &[u8]| frost::keys::KeyPackage::deserialize(k).map_err(|e| e.to_string());
    let public = |p: &[u8]| frost::keys::PublicKeyPackage::deserialize(p).map_err(|e| e.to_string());
    Ok(key(&ka)? == key(&kb)? && public(&pa)? == public(&pb)? && va == vb)
}

/// Reseal every store file `from` still opens under `to`, keeping its epoch. Files already
/// under `to` are skipped, so an interrupted run resumes; a file neither opens is an error.
fn reseal(store: &SignerStore, from: &impl SecureElement, to: &impl SecureElement) -> Result<(), String> {
    for kind in FILES {
        if store.read(to, kind).is_ok() {
            continue;
        }
        if let Some((epoch, plain)) = store.read(from, kind)? {
            store.write(to, kind, epoch, &plain)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_apple() -> AppState {
        let config = super::super::native_config_from_args(&["--data".into(), "unused".into(), "--port".into(), "0".into()]).unwrap();
        AppState::new(config)
    }

    #[test]
    fn cancelled_vault_open_requires_explicit_retry_and_then_caches() {
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        assert_eq!(CANCELLED_TOUCH_ID, crate::signer::secure_element_apple::KeyFailure::Cancelled.message());

        let st = native_apple();
        let vault = "3d".repeat(32);
        let other_vault = "f2".repeat(32);
        let (_, public) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng,
        ).unwrap();
        let fvk = group_viewing_key(&public, &[23; 32]).unwrap();
        let address = vault::unified_address(&fvk, VaultNetwork::Regtest.network_type());
        let key = SignerViewingKey { fvk, public_package: hex::encode(public.serialize().unwrap()) };
        let sealed = serde_json::json!({
            "network": "regtest", "public_package": key.public_package, "group_address": address,
        });
        let needs_touch_id = Some("Touch ID is required to open this vault.");
        assert_eq!(viewing_key(&st, &st.config.data, "unused", &vault, 1, &sealed, VaultOpen::Read,
            || Err(CANCELLED_TOUCH_ID.into())).err().as_deref(), needs_touch_id);
        assert_eq!(viewing_key(&st, &st.config.data, "unused", &vault, 1, &sealed, VaultOpen::Read,
            || panic!("a queued read must not open again")).err().as_deref(), needs_touch_id);
        assert_eq!(viewing_key(&st, &st.config.data, "unused", &other_vault, 1, &sealed, VaultOpen::Read,
            || Err("another vault was not suppressed".into())).err().as_deref(), Some("another vault was not suppressed"));
        let fvk = viewing_key(&st, &st.config.data, "unused", &vault, 1, &sealed, VaultOpen::Retry,
            || Ok(key.clone())).unwrap();
        let cached = viewing_key(&st, &st.config.data, "unused", &vault, 1, &sealed, VaultOpen::Read,
            || panic!("a warm read must not open again")).unwrap();
        assert_eq!(cached.to_bytes(), fvk.to_bytes());
    }

    #[test]
    fn touch_id_reason_only_quotes_safely_delimited_names() {
        let st = native_apple();
        let vault = format!("{}{}", "a09df1c4", "0".repeat(56));
        for name in [None, Some("Reserve” is verified"), Some("'Reserve'"), Some("«Reserve»"),
            Some("Reserve שלום"), Some("Reserve سجل"), Some("Reserve ١٢"), Some("Hidden\nname")]
        {
            assert_eq!(vault_touch_id_reason(&st, "open", &vault, name).as_deref(), Some("open vault a09df1c4"));
        }
        assert_eq!(vault_touch_id_reason(&st, "open", &vault, Some("Élodie Reserve")).as_deref(),
            Some("open vault “Élodie Reserve”"));
    }

    #[test]
    fn reseal_moves_every_store_file_to_the_new_element_and_resumes() {
        let dir = std::env::temp_dir().join(format!("loki-reseal-{}", uuid::Uuid::new_v4()));
        let store = SignerStore::create(&dir, Network::Regtest, [5; 32], 2).unwrap();
        let (old, new) = (SoftwareSecureElement::generate(), SoftwareSecureElement::generate());
        store.write(&old, FileKind::Identity, 0, b"identity").unwrap();
        store.write(&old, FileKind::Share, 3, b"share").unwrap();
        // An interrupted earlier run already moved the identity.
        store.write(&new, FileKind::Identity, 0, b"identity").unwrap();
        reseal(&store, &old, &new).unwrap();
        assert_eq!(&**store.read(&new, FileKind::Identity).unwrap().unwrap().1, b"identity");
        let (epoch, share) = store.read(&new, FileKind::Share).unwrap().unwrap();
        assert_eq!((epoch, &**share), (3, &b"share"[..]));
        assert!(store.read(&old, FileKind::Share).is_err(), "the old element no longer opens the share");
        assert!(store.read(&new, FileKind::Roster).unwrap().is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
