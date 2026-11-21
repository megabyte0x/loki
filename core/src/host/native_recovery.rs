//! Local-only restore. Neither the words nor backup bytes are submitted to the coordinator.

use std::{fs, io::{self, Read}, path::{Path, PathBuf}};

use serde::Deserialize;
use zeroize::Zeroizing;

use super::{ceremony::{self, RecoveryBackup}, recovery, registration::{self, PublicMember, RESTORE_PENDING}, state::{write_native_key_scope, Shared, NATIVE_KEY_SCOPE}, Config, FetchedConfig, RegistrationConfig};
use crate::{setup_transport::{Identity, PublicIdentity}, signer::{backup::BackupArtifact, recovery::RecoveryKey, Network}, state::MemberDir};
#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
use {super::state::{restored_key_tag, RESTORED_KEY}, crate::signer::secure_element_apple::{AppleSecureElement, KeyFailure}};

// Stable restore reply codes; Recovery.swift owns the member-facing copy.
pub(crate) const REFUSED: &str = "restore-refused";
pub(super) const LOCKED: &str = "profile-locked";
const BAD_FILE: &str = "invalid-backup";
const BAD_FINGERPRINT: &str = "backup-fingerprint-mismatch";
const WRONG_PROFILE: &str = "wrong-profile";
const ALREADY_PRESENT: &str = "vault-exists";
const NOT_FRESH: &str = "profile-not-fresh";
const DATA_LOCATION: &str = "data-folder-unavailable";
const ROSTER_UNAVAILABLE: &str = "roster-unavailable";
const ROSTER_MISMATCH: &str = "roster-mismatch";
#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
const KEYCHAIN_STAGE: &str = "restore-keychain-stage";

fn open_backup(file: &Path, words: Zeroizing<Vec<u8>>, fingerprint: &str) -> Result<RecoveryBackup, &'static str> {
    const LIMIT: u64 = 256 * 1024;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Export { vault: String, backup: String }

    if !fs::metadata(file).is_ok_and(|m| m.is_file() && m.len() <= LIMIT) { return Err(BAD_FILE); }
    let file = fs::File::open(file).map_err(|_| BAD_FILE)?;
    if !file.metadata().is_ok_and(|m| m.is_file()) { return Err(BAD_FILE); }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).map_err(|_| BAD_FILE)?;
    if bytes.len() as u64 > LIMIT { return Err(BAD_FILE); }
    let export: Export = serde_json::from_slice(&bytes).map_err(|_| BAD_FILE)?;
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if export.vault.len() != 64 || !export.vault.bytes().all(is_hex) || !export.backup.bytes().all(is_hex) {
        return Err(BAD_FILE);
    }
    let artifact = BackupArtifact(hex::decode(export.backup).map_err(|_| BAD_FILE)?);
    artifact.check_fingerprint(fingerprint).map_err(|_| BAD_FINGERPRINT)?;
    let key = RecoveryKey::from_words(std::str::from_utf8(&words).map_err(|_| REFUSED)?).map_err(|_| REFUSED)?;
    drop(words);
    RecoveryBackup::open(&export.vault, key, artifact.0).map_err(|_| REFUSED)
}

/// Stage beside the destination so a same-filesystem rename is the only publication step.
/// A failed or interrupted restore cannot leave an active half-written vault/profile.
struct Stage {
    path: PathBuf,
    _active: fs::File,
}

impl Stage {
    fn new(parent: &Path) -> Result<Self, &'static str> {
        let path = parent.join(format!(".loki-restore-{}", uuid::Uuid::new_v4()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|_| REFUSED)?;
        let active = fs::File::open(&path).map_err(|_| REFUSED)?;
        active.try_lock().map_err(|_| REFUSED)?;
        // A concurrent startup may have reclaimed the empty directory before we locked it.
        if !path.is_dir() { return Err(REFUSED); }
        Ok(Self { path, _active: active })
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    fn prepare_keys(&self, dirs: &[&Path]) -> Result<(), &'static str> {
        let id = staging_id(&self.path).ok_or(REFUSED)?.to_string();
        for dir in dirs {
            MemberDir::create(dir, "").and_then(|dir| dir.write_text(RESTORED_KEY, &id)).map_err(|_| REFUSED)?;
        }
        // Reserve the attempt's tags durably before the first Keychain operation.
        // The journal moves with the directory at the same publication commit point.
        let journal = self.path.join(KEYCHAIN_STAGE);
        fs::write(&journal, id).and_then(|_| fs::File::open(&journal)?.sync_all())
            .and_then(|_| self._active.sync_all())
            .and_then(|_| fs::File::open(parent(&self.path))?.sync_all()).map_err(|_| REFUSED)
    }

    fn publish(&self, dest: &Path, _signer_dir: &Path, prepare_dest: impl FnOnce() -> Result<(), &'static str>) -> Result<(), &'static str> {
        fn sync_tree(dir: &Path) -> std::io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() { sync_tree(&entry.path())?; }
                else { fs::File::open(entry.path())?.sync_all()?; }
            }
            fs::File::open(dir)?.sync_all()
        }
        sync_tree(&self.path).map_err(|_| REFUSED)?;
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        if self.path.join(KEYCHAIN_STAGE).try_exists().map_err(|_| REFUSED)? {
            verify_staged_signer(_signer_dir)?;
        }
        prepare_dest()?;
        fs::rename(&self.path, dest).map_err(|_| REFUSED)?;
        // Once published, don't ask the member to retry by reporting a failed flush.
        let _ = fs::File::open(dest.parent().expect("restore destination has a parent")).and_then(|f| f.sync_all());
        Ok(())
    }
}

impl Drop for Stage {
    fn drop(&mut self) { discard_stage(&self.path); }
}

#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
fn verify_staged_signer(dir: &Path) -> Result<(), &'static str> {
    use super::state::{open_apple_element, HostedSecureElement};
    use crate::signer::store::{FileKind, SignerStore};

    let se = open_apple_element(dir, false, None, None, "", None).map_err(KeyFailure::message)?;
    if let HostedSecureElement::Apple(key, _) = &se {
        key.confirm_staged_biometry(None).map_err(KeyFailure::message)?;
    }
    let store = SignerStore::open(dir).map_err(|_| REFUSED)?;
    let _share = store.read(&se, FileKind::Share)
        .map_err(|e| super::state::member_key_message(&e).unwrap_or(REFUSED))?.ok_or(REFUSED)?;
    if let HostedSecureElement::Apple(key, _) = &se {
        let state = dir.join("biometry-state");
        key.confirm_staged_biometry(Some(&state)).map_err(KeyFailure::message)?;
        fs::File::open(state).and_then(|f| f.sync_all())
            .and_then(|_| fs::File::open(dir)?.sync_all()).map_err(|_| REFUSED)?;
    }
    Ok(())
}

// Called only with the staging directory locked, never on a published path.
fn discard_stage(path: &Path) {
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    match fs::read_to_string(path.join(KEYCHAIN_STAGE)) {
        Ok(journal) => {
            let Some(id) = staging_id(path).filter(|id| id.to_string() == journal) else { return };
            #[cfg(test)]
            let stand_in = super::state::apple_test::fixture(path).is_some();
            #[cfg(not(test))]
            let stand_in = false;
            if !stand_in {
                let mut cleaned = true;
                for role in ["signer", "device-auth"] {
                    cleaned &= AppleSecureElement::discard_staged(&restored_key_tag(id, role)).is_ok();
                }
                if !cleaned {
                    eprintln!("restore staging: could not discard a staged key; will retry on startup");
                    return;
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(_) => return,
    }
    let _ = fs::remove_dir_all(path);
}

fn absent(path: &Path) -> Result<bool, &'static str> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(REFUSED),
    }
}

fn entries(path: &Path) -> Result<impl Iterator<Item = Result<fs::DirEntry, &'static str>>, &'static str> {
    let entries = match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Some(fs::read_dir(path).map_err(|_| REFUSED)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        _ => return Err(REFUSED),
    };
    Ok(entries.into_iter().flatten().map(|e| e.map_err(|_| REFUSED)))
}

fn staging_id(path: &Path) -> Option<uuid::Uuid> {
    let suffix = path.file_name()?.to_str()?.strip_prefix(".loki-restore-")?;
    uuid::Uuid::parse_str(suffix).ok().filter(|id| id.get_version_num() == 4 && id.to_string() == suffix)
}

fn staging_dir(entry: &fs::DirEntry) -> bool {
    entry.file_type().is_ok_and(|kind| kind.is_dir()) && staging_id(&entry.path()).is_some()
}

fn parent(data: &Path) -> &Path {
    data.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

fn data_location(data: &Path) -> Result<PathBuf, &'static str> {
    // The configured root may be a symlink. Don't follow symlinks among its contents.
    if let Some(name) = data.file_name() {
        let link = parent(data).join(name); // Inspect the last component without a trailing slash.
        if fs::symlink_metadata(&link).is_ok_and(|m| m.is_symlink()) {
            return link.canonicalize().ok().filter(|path| path.is_dir()).ok_or(DATA_LOCATION);
        }
    }
    Ok(data.to_owned())
}

pub(crate) fn clean_staging(data: &Path) {
    let Ok(data) = data_location(data) else { return };
    let paths = [(parent(&data).canonicalize().ok(), data.file_name()), (Some(data.join("vaults")), None)];
    for (dir, skip) in paths {
        let Some(dir) = dir else { continue };
        let Ok(entries) = entries(&dir) else { continue };
        for entry in entries.flatten() {
            if Some(entry.file_name().as_os_str()) != skip && staging_dir(&entry) {
                let Ok(active) = fs::File::open(entry.path()) else { continue };
                // A different signer launch using the same parent may be restoring now.
                if active.try_lock().is_ok() { discard_stage(&entry.path()); }
            }
        }
    }
}

/// Treat even partial ceremonies and unreadable vaults as belonging to the member.
pub(crate) fn profile_state(data: &Path) -> Result<&'static str, &'static str> {
    let mut material = false;
    for entry in entries(&data_location(data)?)? {
        let entry = entry?;
        let name = entry.file_name();
        let kind = entry.file_type().map_err(|_| REFUSED)?;
        match name.to_str() {
            Some("vaults") => {
                if !kind.is_dir() { return Ok("vault"); }
                for child in entries(&entry.path())? {
                    if !staging_dir(&child?) { return Ok("vault"); }
                }
            }
            Some("card" | "vault.card" | "vault.sealed" | "share.sealed") => return Ok("vault"),
            Some("profile" | "device-auth") => {
                material |= !kind.is_dir() || entries(&entry.path())?.next().transpose()?.is_some();
            }
            // Allow only known files left by an interrupted native startup; everything else
            // requires explicit confirmation, even when we don't understand its contents.
            Some(NATIVE_KEY_SCOPE | "paired-coordinator.json.tmp" | "signer-config.json.tmp" | "nonce-witnesses.json.tmp") if kind.is_file() => {},
            _ => material = true,
        }
    }
    Ok(if material { "profile" } else { "fresh" })
}

fn archive(data: &Path) -> Result<(), &'static str> {
    let name = data.file_name().and_then(|n| n.to_str()).ok_or(REFUSED)?;
    let date = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| REFUSED)?.as_secs();
    let archive = data.with_file_name(format!("{name}-set-aside-{date}-{}", uuid::Uuid::new_v4()));
    fs::rename(data, archive).map_err(|_| REFUSED)
}

pub(super) fn set_aside(data: &Path, key_gone: bool) -> Result<(), &'static str> {
    let dest = data_location(data)?;
    match profile_state(&dest)? {
        state if state == "profile" || (state == "vault" && key_gone) => {
            archive(&dest)?;
            // Preserve a root symlink and give it a fresh target to pair or restore into.
            if dest != data { MemberDir::create(&dest, "").map_err(|_| REFUSED)?; }
            Ok(())
        }
        "vault" => Err("vault"),
        _ => Err(REFUSED),
    }
}

pub(super) fn read_roster(origin: &str, signing: &[u8; 32]) -> Result<Vec<PublicMember>, &'static str> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| ROSTER_UNAVAILABLE)?;
    runtime.block_on(async {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15)).build().map_err(|_| ROSTER_UNAVAILABLE)?;
        // The lookup sends only the derived public identity, never recovery words or backup data.
        registration::fetch_roster(&client, origin, &hex::encode(signing)).await.map_err(|_| ROSTER_UNAVAILABLE)
    })
}

pub(super) fn restored_slot(identity: &PublicIdentity, members: &[PublicMember]) -> Result<u32, &'static str> {
    let (signing, relay) = (hex::encode(identity.signing), hex::encode(identity.encryption));
    let mut matches = members.iter().filter(|m| m.signing_pubkey == signing && m.relay_pubkey == relay);
    match (matches.next(), matches.next()) {
        (Some(m), None) if registration::valid_slot(m.slot) => Ok(m.slot),
        _ => Err(ROSTER_MISMATCH),
    }
}

pub(crate) fn restore_new(
    config: &mut Config, pass: &str, words: Zeroizing<Vec<u8>>, file: &Path, fingerprint: &str,
    origin: &str, fetched: Option<&FetchedConfig>,
) -> Result<(), &'static str> {
    let backup = open_backup(file, words, fingerprint)?;
    if pass.is_empty() || config.registration.is_some() { return Err(REFUSED); }
    if profile_state(&config.data)? != "fresh" { return Err(NOT_FRESH); }
    let origin = registration::plain_origin(origin, config.development_http).map_err(|_| ROSTER_UNAVAILABLE)?;
    let network = match backup.material.network { Network::Regtest => "regtest", Network::Testnet => "testnet" };
    if network != config.network { return Err(REFUSED); }
    let identity = Identity::from_secret_bytes(&backup.material.identity).map_err(|_| REFUSED)?.public();
    let slot = restored_slot(&identity, &read_roster(&origin, &identity.signing)?)?;

    let name = "Member";
    let data = data_location(&config.data)?;
    let parent = parent(&data);
    fs::create_dir_all(parent).map_err(|_| REFUSED)?;
    let parent = parent.canonicalize().map_err(|_| REFUSED)?;
    let dest = parent.join(data.file_name().ok_or(NOT_FRESH)?);
    let staged = Stage::new(&parent)?;
    let vault = hex::encode(backup.material.vault_id);
    let vault_dir = MemberDir::open(&staged.path.join("vaults"), &vault);
    let signer = vault_dir.path().join("signer");
    let final_key_dir = dest.join("vaults").join(&vault).join("signer");
    crate::profile::create(&staged.path, pass, name).map_err(|_| REFUSED)?;
    write_native_key_scope(&staged.path).map_err(|_| REFUSED)?;
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    if config.secure_element == "apple" {
        staged.prepare_keys(&[&signer, &staged.path.join("device-auth")])?;
    }
    ceremony::restore_opened_backup(backup, &staged.path, &vault_dir, pass, config, Some(&final_key_dir))
        .map_err(|e| super::state::member_key_message(&e).unwrap_or(REFUSED))?;
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    if config.secure_element == "apple" {
        registration::DeviceKey::create_staged(config, &staged.path, &dest)
            .map_err(|e| super::state::member_key_message(&e.to_string()).unwrap_or(REFUSED))?;
    }
    registration::save_coordinator(&staged.path, &origin, slot).map_err(|_| REFUSED)?;
    if let Some(fetched) = fetched { fetched.save_unlocked(&staged.path).map_err(|_| REFUSED)?; }
    fs::write(staged.path.join(RESTORE_PENDING), []).map_err(|_| REFUSED)?;
    staged.publish(&dest, &signer, || {
        if profile_state(&dest)? != "fresh" { return Err(NOT_FRESH); }
        // Preserve leftovers separately, only after the new profile has been verified.
        if entries(&dest)?.next().transpose()?.is_some() { archive(&dest)?; }
        Ok(())
    })?;
    config.registration = Some(RegistrationConfig {
        coordinator: origin, slot: Some(slot), passphrase_file: None, name: name.into(), pairing_challenge: None,
    });
    Ok(())
}

pub(super) fn restore_running(st: &Shared, words: Zeroizing<Vec<u8>>, file: &Path, fingerprint: &str) -> Result<(), &'static str> {
    let backup = open_backup(file, words, fingerprint)?;
    let session = st.session.blocking_read();
    let session = session.as_ref().ok_or(LOCKED)?;
    let (data, pass) = (&session.data, &session.passphrase);
    let _guard = st.ceremony.lock().map_err(|_| REFUSED)?;
    if !matches!(recovery::check_recovery(data, &backup.key), Ok(false)) { return Err(WRONG_PROFILE); }
    let existing = Zeroizing::new(MemberDir::open(data, "").read_sealed("identity.sealed", pass).map_err(|_| WRONG_PROFILE)?);
    if existing.len() != 66 || existing.get(2..) != backup.material.identity.get(2..) { return Err(WRONG_PROFILE); }

    let vault = hex::encode(backup.material.vault_id);
    let parent = data.join("vaults");
    fs::create_dir_all(&parent).map_err(|_| REFUSED)?;
    let parent = parent.canonicalize().map_err(|_| REFUSED)?;
    let dest = parent.join(&vault);
    let ensure_absent = || {
        // Re-resolve the alias after staged key verification, which can wait for Touch ID.
        let existing = ceremony::dir(data, &vault).map_err(|_| REFUSED)?;
        if absent(existing.path())? && absent(&dest)? { Ok(()) } else { Err(ALREADY_PRESENT) }
    };
    ensure_absent()?;
    let staged = Stage::new(&parent)?;
    let vault_dir = MemberDir::open(&staged.path, "");
    let signer = vault_dir.path().join("signer");
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    if st.config.secure_element == "apple" {
        staged.prepare_keys(&[&signer])?;
    }
    ceremony::restore_opened_backup(backup, data, &vault_dir, pass, &st.config, Some(&dest.join("signer")))
        .map_err(|e| super::state::member_key_message(&e).unwrap_or(REFUSED))?;
    staged.publish(&dest, &signer, ensure_absent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_state_accepts_leftovers_but_not_profile_identity_or_vault_material() {
        let root = std::env::temp_dir().join(format!("loki-fresh-{}", uuid::Uuid::new_v4()));
        let data = root.join("LokiSigner");
        assert_eq!(profile_state(&data), Ok("fresh"));
        fs::create_dir_all(&data).unwrap();
        assert_eq!(profile_state(&data), Ok("fresh"));
        for dir in ["profile", "device-auth", "vaults"] { fs::create_dir(data.join(dir)).unwrap(); }
        write_native_key_scope(&data).unwrap();
        assert_eq!(profile_state(&data), Ok("fresh"));
        for name in ["profile/profile.sealed", "identity.sealed", "recovery.pub", "device-auth/login.sealed", "devices.json", RESTORE_PENDING] {
            fs::write(data.join(name), []).unwrap();
            assert_eq!(profile_state(&data), Ok("profile"), "{name}");
            fs::remove_file(data.join(name)).unwrap();
        }
        fs::create_dir(data.join("vaults/partial-vault")).unwrap();
        assert_eq!(profile_state(&data), Ok("vault"));
        fs::remove_dir_all(data.join("vaults")).unwrap();
        fs::create_dir(data.join("card")).unwrap();
        assert_eq!(profile_state(&data), Ok("vault"), "legacy card directory");
        fs::remove_dir(data.join("card")).unwrap();
        for name in ["vault.card", "vault.sealed", "share.sealed", "vaults"] {
            fs::write(data.join(name), []).unwrap();
            assert_eq!(profile_state(&data), Ok("vault"), "{name}");
            fs::remove_file(data.join(name)).unwrap();
        }
        fs::create_dir(data.join("signer")).unwrap();
        fs::write(data.join("signer/share.sealed"), b"unrecognised layout").unwrap();
        assert_eq!(profile_state(&data), Ok("profile"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn set_aside_preserves_every_file_and_refuses_a_vault_before_renaming() {
        let root = std::env::temp_dir().join(format!("loki-set-aside-{}", uuid::Uuid::new_v4()));
        let data = root.join("LokiSigner");
        let pass = "archived profile fixture";
        crate::profile::create(&data, pass, "Old member").unwrap();
        let original = fs::read(data.join("profile/profile.sealed")).unwrap();
        fs::write(data.join("identity.sealed"), b"old identity fixture").unwrap();
        write_native_key_scope(&data).unwrap();
        let scope = fs::read(data.join(NATIVE_KEY_SCOPE)).unwrap();
        let vault = data.join("vaults/member-vault/signer");
        fs::create_dir_all(&vault).unwrap();
        fs::write(vault.join("share.sealed"), b"share fixture").unwrap();
        assert_eq!(set_aside(&data, false), Err("vault"));
        assert_eq!(fs::read(vault.join("share.sealed")).unwrap(), b"share fixture");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(data.join("vaults")).unwrap();

        set_aside(&data, false).unwrap();
        assert!(!data.exists());
        let archived = fs::read_dir(&root).unwrap().next().unwrap().unwrap();
        assert!(archived.file_name().to_string_lossy().starts_with("LokiSigner-set-aside-"));
        assert_eq!(fs::read(archived.path().join("profile/profile.sealed")).unwrap(), original);
        assert_eq!(fs::read(archived.path().join("identity.sealed")).unwrap(), b"old identity fixture");
        assert_eq!(fs::read(archived.path().join(NATIVE_KEY_SCOPE)).unwrap(), scope);
        write_native_key_scope(&data).unwrap();
        assert_ne!(fs::read(data.join(NATIVE_KEY_SCOPE)).unwrap(), scope);
        assert_eq!(profile_state(&data), Ok("fresh"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_removes_only_exact_staging_directories_at_both_levels() {
        let root = std::env::temp_dir().join(format!("loki-stage-cleanup-{}", uuid::Uuid::new_v4()));
        let data = root.join("LokiSigner");
        let staging = format!(".loki-restore-{}", uuid::Uuid::new_v4());
        let preserved = format!(".loki-restore-{}", uuid::Uuid::new_v4());
        for dir in [&root, &data.join("vaults")] {
            fs::create_dir_all(dir.join(&staging)).unwrap();
            fs::write(dir.join(&staging).join("sample.sealed"), []).unwrap();
            fs::create_dir(dir.join(format!("{staging}-extra"))).unwrap();
            fs::create_dir(dir.join(".loki-restore-important")).unwrap();
            fs::write(dir.join(&preserved), b"not a directory").unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(dir.join(".loki-restore-important"),
                dir.join(format!(".loki-restore-{}", uuid::Uuid::new_v4()))).unwrap();
        }
        let active = Stage::new(&root).unwrap();
        clean_staging(&data);
        assert!(active.path.is_dir());
        for dir in [&root, &data.join("vaults")] {
            assert!(!dir.join(&staging).exists());
            assert!(dir.join(format!("{staging}-extra")).is_dir());
            assert!(dir.join(".loki-restore-important").is_dir());
            assert_eq!(fs::read(dir.join(&preserved)).unwrap(), b"not a directory");
            #[cfg(unix)]
            assert!(fs::read_dir(dir).unwrap().any(|e| e.unwrap().file_type().unwrap().is_symlink()));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn startup_resolves_a_symlinked_parent_before_cleaning_staging() {
        let root = std::env::temp_dir().join(format!("loki-stage-parent-link-{}", uuid::Uuid::new_v4()));
        let actual = root.join("actual");
        let alias = root.join("alias");
        let stale = actual.join(format!(".loki-restore-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&stale).unwrap();
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        let data = alias.join("LokiSigner");
        clean_staging(&data);
        assert!(!stale.exists());
        assert_eq!(profile_state(&data), Ok("fresh"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_data_root_stays_usable_after_cleanup_and_set_aside() {
        let root = std::env::temp_dir().join(format!("loki-data-link-{}", uuid::Uuid::new_v4()));
        let target = root.join("actual/LokiSigner");
        let alias = root.join("alias");
        let stale = target.join("vaults").join(format!(".loki-restore-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        assert_eq!(profile_state(&alias), Err("data-folder-unavailable"));
        fs::create_dir_all(&stale).unwrap();
        clean_staging(&alias);
        assert!(!stale.exists());
        assert_eq!(profile_state(&alias), Ok("fresh"));
        crate::profile::create(&target, "old passphrase", "Old member").unwrap();
        assert_eq!(profile_state(&alias), Ok("profile"));
        set_aside(&alias, false).unwrap();
        assert_eq!(fs::read_link(&alias).unwrap(), target);
        assert_eq!(profile_state(&alias), Ok("fresh"));
        let archived = fs::read_dir(parent(&target)).unwrap().map(|e| e.unwrap().path()).find(|p| *p != target).unwrap();
        assert!(crate::profile::open(&archived, "old passphrase").is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
