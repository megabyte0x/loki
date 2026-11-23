use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{watch, RwLock};
use zeroize::Zeroizing;

use crate::signer::secure_element::{OpenError, SecureElement, SoftwareSecureElement, WrappedDek};
#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
use crate::signer::secure_element_apple::{AppleSecureElement, KeyFailure};

/// Launch configuration for one member coordinator (one process per member).
pub struct Config {
    pub registration: Option<super::RegistrationConfig>,
    /// The GUI entry points own local recovery and may use a profile-scoped Apple key tag.
    pub(super) native: bool,
    pub data: PathBuf,
    pub port: u16,
    pub bind: std::net::IpAddr,
    pub(super) peer_port: Option<u16>,
    pub advertise_url: Option<String>,
    pub network: String,
    pub lightwalletd: Option<String>,
    pub transport: String,
    pub secure_element: String,
    pub operator_bundle: Option<PathBuf>,
    /// Two pinned external nonce-witness mailboxes; required for hosted signing.
    pub nonce_witnesses: Option<PathBuf>,
    pub operator_key: Option<String>,
    pub enrollment_issuer: Option<PathBuf>,
    pub development_http: bool,
    /// Headless capability, printed in the signer link. Empty for LokiSigner, which
    /// authenticates only with individually approved wallet-tab tokens.
    pub token: String,
    pub frostd_url: String,
    /// Operator URL allowlist for remote peers; vault slots never resolve through this map.
    pub peers: BTreeMap<u16, String>,
    /// Operator opt-in: admit new loopback peer origins outside regtest, for a co-located
    /// demo where every signer runs on this host. Off by default so real deployments stay locked.
    pub loopback_peers: bool,
}

impl Config {
    pub(super) fn lokisigner_url(&self) -> Option<String> {
        if !self.native || self.port == 0 { return None; }
        let host = match self.bind {
            std::net::IpAddr::V4(ip) if ip == std::net::Ipv4Addr::LOCALHOST => "127.0.0.1",
            std::net::IpAddr::V6(ip) if ip.is_loopback() => "[::1]",
            _ => return None,
        };
        Some(format!("http://{host}:{}", self.port))
    }

    pub(super) fn base_url(&self) -> String {
        self.advertise_url.clone().unwrap_or_else(|| format!("http://{}", std::net::SocketAddr::new(self.bind, self.port)))
            .trim_end_matches('/').to_owned()
    }

    pub(super) fn validate_peer_url(&self, base: &str) -> Result<reqwest::Url, String> {
        let url = reqwest::Url::parse(base).map_err(|_| "invalid member base URL")?;
        let origin = url.origin().ascii_serialization();
        let explicit_default = if url.port().is_none() {
            format!("{origin}:{}", if url.scheme() == "https" { 443 } else { 80 })
        } else {
            origin.clone()
        };
        if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty()
            || url.password().is_some() || url.query().is_some() || url.fragment().is_some()
            || url.path() != "/" || (origin != base && explicit_default != base) {
            return Err("member URL must be a plain HTTP(S) origin".into());
        }
        // The co-located regtest demo, or an explicit operator opt-in, admits new loopback origins.
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
        let local = loopback && (self.network == "regtest" || self.loopback_peers)
            && url.port().is_some_and(|p| p >= 1024);
        // Outside the local demo, authenticate the locally configured peer name with TLS.
        if local || (!loopback && url.scheme() == "https"
            && self.peers.values().any(|allowed| allowed == &origin || allowed == &explicit_default))
        {
            Ok(url)
        } else {
            Err("member URL is not an allowed peer".into())
        }
    }

    pub fn validate_secure_element(&self) -> Result<(), String> {
        match self.secure_element.as_str() {
            "software" => Ok(()),
            "apple" if cfg!(all(target_os = "macos", feature = "apple-enclave")) => Ok(()),
            "apple" => Err("--secure-element apple requires macOS and the apple-enclave feature".into()),
            _ => Err("--secure-element must be software or apple".into()),
        }
    }

    pub(super) fn open_secure_element(&self, dir: &Path, pass: &str) -> Result<HostedSecureElement, String> {
        self.open_secure_element_with_reason(dir, pass, None)
    }

    pub(super) fn open_secure_element_with_reason(&self, dir: &Path, pass: &str, reason: Option<&str>) -> Result<HostedSecureElement, String> {
        let result = self.open_element(dir, pass, false, None, &self.data, reason);
        eprintln!("secure-element open: {}", if result.is_ok() { "ok" } else { "error" });
        result
    }

    // A staged vault must use the same Enclave key after its directory is published.
    pub(super) fn create_secure_element(&self, dir: &Path, pass: &str, published: Option<&Path>, profile: &Path) -> Result<HostedSecureElement, String> {
        self.open_element(dir, pass, true, published, profile, None)
    }

    fn open_element(&self, dir: &Path, pass: &str, _create: bool, _published: Option<&Path>, _profile: &Path, _reason: Option<&str>) -> Result<HostedSecureElement, String> {
        #[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
        let reason = _reason.filter(|_| self.native);
        #[cfg(test)]
        if self.secure_element == "apple" {
            if let Some(result) = scope_test::open(dir, pass, reason) {
                return result.map(HostedSecureElement::Software);
            }
        }
        self.validate_secure_element()?;
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        if self.secure_element == "apple" {
            let (scope, role) = vault_key_scope(self, _profile, dir, _published, _create)
                .map_err(|_| KeyFailure::Other.to_string())?;
            if _create && scope.is_some() {
                crate::state::MemberDir::create(dir, "").map_err(|_| KeyFailure::Other.to_string())?;
                match std::fs::OpenOptions::new().write(true).create_new(true).open(dir.join(SCOPED_VAULT_KEY)) {
                    Ok(file) => file.sync_all().and_then(|_| std::fs::File::open(dir)?.sync_all())
                        .map_err(|_| KeyFailure::Other.to_string())?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                    Err(_) => return Err(KeyFailure::Other.to_string()),
                }
            }
            let element = open_apple_element(dir, _create, _published, scope, &role, reason);
            #[cfg(feature = "relay-communication")]
            let element = if self.native && !_create {
                match element {
                    Err(failure) if failure.is_gone() => {
                        super::native_member::report_vault_key_gone(_profile);
                        Err(failure)
                    },
                    Ok(HostedSecureElement::Apple(key, _)) => Ok(HostedSecureElement::Apple(key, Some(_profile.to_owned()))),
                    other => other,
                }
            } else { element };
            return element.map_err(|e| e.to_string());
        }
        SoftwareSecureElement::persistent(dir, pass).map(HostedSecureElement::software)
    }
}

pub(super) const NATIVE_KEY_SCOPE: &str = "native-key-scope";

pub(super) fn write_native_key_scope(data: &Path) -> Result<(), String> {
    let dir = crate::state::MemberDir::create(data, "").map_err(|e| e.to_string())?;
    dir.write_text(NATIVE_KEY_SCOPE, &uuid::Uuid::new_v4().to_string()).map_err(|e| e.to_string())
}

#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
pub(super) fn read_native_key_scope(data: &Path) -> Result<Option<uuid::Uuid>, String> {
    match std::fs::read_to_string(data.join(NATIVE_KEY_SCOPE)) {
        Ok(scope) => uuid::Uuid::parse_str(&scope).map(Some).map_err(|_| "invalid native key scope".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
pub(super) fn key_scope(config: &Config, profile: &Path) -> Result<Option<uuid::Uuid>, String> {
    if config.native { read_native_key_scope(profile) } else { Ok(None) }
}

#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
const SCOPED_VAULT_KEY: &str = "native-scoped-vault-key";

#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
pub(super) const RESTORED_KEY: &str = "native-restored-key";

#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
pub(super) fn restored_key_tag(restore: uuid::Uuid, role: &str) -> Vec<u8> {
    format!("cash.loki.member.kek.restore.v1:{restore}:{role}").into_bytes()
}

#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
fn vault_key_scope(config: &Config, profile: &Path, key_dir: &Path, published: Option<&Path>, create: bool) -> Result<(Option<uuid::Uuid>, String), String> {
    let mut scope = key_scope(config, profile)?;
    // The first release with profile scopes used them only for device keys. Existing
    // vault seals without this marker still use their original path tag.
    if scope.is_some() && !create && !key_dir.join(SCOPED_VAULT_KEY).try_exists().map_err(|e| e.to_string())? {
        scope = None;
    }
    // Only the vault ID (the parent of signer/) is part of the role, never a staging name.
    let role = if scope.is_some() {
        let id = published.unwrap_or(key_dir).parent().and_then(Path::file_name).and_then(|name| name.to_str()).ok_or("invalid vault key directory")?;
        format!("vault:{id}")
    } else { String::new() };
    Ok((scope, role))
}

/// The scoped form survives a folder move. For a staged restore, pass the scope read from
/// the staged profile and use the published directory only as the legacy fallback.
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
pub(super) fn apple_key_tag(dir: &Path, scope: Option<uuid::Uuid>, role: &str) -> Vec<u8> {
    if let Some(scope) = scope {
        return format!("cash.loki.member.kek.v2:{scope}:{role}").into_bytes();
    }
    let mut tag = b"cash.loki.member.kek.v1:".to_vec();
    tag.extend_from_slice(dir.as_os_str().as_encoded_bytes());
    tag
}

#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
pub(super) fn open_apple_element(dir: &Path, create: bool, published: Option<&Path>, scope: Option<uuid::Uuid>, role: &str, reason: Option<&str>) -> Result<HostedSecureElement, KeyFailure> {
    use std::os::unix::fs::DirBuilderExt;
    if create {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|_| KeyFailure::Other)?;
    }
    let restore = match std::fs::read_to_string(dir.join(RESTORED_KEY)) {
        Ok(id) => Some(uuid::Uuid::parse_str(&id).map_err(|_| KeyFailure::Other)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(KeyFailure::Other),
    };
    let tag = if let Some(restore) = restore {
        restored_key_tag(restore, dir.file_name().and_then(|name| name.to_str()).ok_or(KeyFailure::Other)?)
    } else {
        let legacy = if scope.is_none() { legacy_key_dir(dir, published)? } else { PathBuf::new() };
        apple_key_tag(&legacy, scope, role)
    };
    #[cfg(test)]
    if let Some(lookup) = apple_test::fixture(dir) {
        lookup(dir, &tag, create)?;
        return SoftwareSecureElement::persistent(dir, "Apple test stand-in")
            .map(HostedSecureElement::software).map_err(|_| KeyFailure::Other);
    }
    let state = dir.join("biometry-state");
    let key = match reason {
        Some(reason) => AppleSecureElement::open_payment(&tag, Some(&state), reason),
        None if create && restore.is_some() => AppleSecureElement::create_staged(&tag, &state),
        None if create => AppleSecureElement::create_persistent(&tag, Some(&state)),
        None => AppleSecureElement::open_persistent(&tag, Some(&state)),
    };
    key.map(|key| HostedSecureElement::Apple(key, None))
}

#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
fn legacy_key_dir(dir: &Path, published: Option<&Path>) -> Result<PathBuf, KeyFailure> {
    // Keep existing tags compatible, including the eventual location of a staged key.
    Ok(match published {
        Some(path) => path.to_owned(),
        None => match dir.canonicalize() {
            Ok(path) => path,
            // The login key can exist even if its directory was never published or was removed.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && dir.file_name().is_some() => {
                let parent = dir.parent().ok_or(KeyFailure::Other)?.canonicalize().map_err(|_| KeyFailure::Other)?;
                parent.join(dir.file_name().unwrap())
            }
            Err(_) => return Err(KeyFailure::Other),
        },
    })
}

#[cfg(all(test, target_os = "macos", feature = "apple-enclave"))]
pub(super) mod apple_test {
    use super::*;
    use std::sync::{Arc, Mutex};

    type Lookup = Arc<dyn Fn(&Path, &[u8], bool) -> Result<(), KeyFailure> + Send + Sync>;
    static FIXTURES: Mutex<Vec<(PathBuf, Lookup)>> = Mutex::new(Vec::new());

    pub(crate) struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            FIXTURES.lock().unwrap().retain(|(path, _)| *path != self.0);
        }
    }

    pub(crate) fn install(root: &Path, lookup: impl Fn(&Path, &[u8], bool) -> Result<(), KeyFailure> + Send + Sync + 'static) -> Fixture {
        FIXTURES.lock().unwrap().push((root.to_owned(), Arc::new(lookup)));
        Fixture(root.to_owned())
    }

    pub(in crate::host) fn fixture(dir: &Path) -> Option<Lookup> {
        FIXTURES.lock().unwrap().iter().find(|(path, _)| dir.starts_with(path)).map(|(_, lookup)| lookup.clone())
    }
}

pub(super) fn member_key_message(_error: &str) -> Option<&'static str> {
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    return crate::signer::secure_element_apple::member_key_message(_error);
    #[cfg(not(all(target_os = "macos", feature = "apple-enclave")))]
    None
}

#[cfg(not(test))]
type HostedSoftware = SoftwareSecureElement;
#[cfg(test)]
type HostedSoftware = scope_test::Software;

pub(super) enum HostedSecureElement {
    Software(HostedSoftware),
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    Apple(AppleSecureElement, Option<PathBuf>),
}

impl HostedSecureElement {
    fn software(se: SoftwareSecureElement) -> Self {
        #[cfg(test)]
        let se = scope_test::Software::plain(se);
        Self::Software(se)
    }
}

impl SecureElement for HostedSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        match self {
            Self::Software(se) => se.wrap_dek(dek),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(se, _) => se.wrap_dek(dek),
        }
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, OpenError> {
        let result = match self {
            Self::Software(se) => se.unwrap_dek(wrapped),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(se, _profile) => {
                let result = se.unwrap_dek(wrapped);
                #[cfg(feature = "relay-communication")]
                if let (Some(profile), Err(OpenError::Element(error))) = (_profile, &result) {
                    if error == KeyFailure::Missing.message() { super::native_member::report_vault_key_gone(profile); }
                }
                result
            },
        };
        let outcome = match &result {
            Ok(_) => "ok",
            Err(OpenError::WrongBinding(_)) => "error (wrong binding)",
            Err(OpenError::Element(_)) => "error (secure element)",
        };
        eprintln!("secure-element unwrap: {outcome}");
        result
    }
}

#[cfg(test)]
pub(super) mod scope_test {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(in crate::host) struct Scope {
        pub reason: Option<String>,
        pub unwraps: usize,
        pub closed: bool,
    }

    type Scopes = Arc<Mutex<Vec<Scope>>>;
    static FIXTURES: Mutex<Vec<(PathBuf, Scopes)>> = Mutex::new(Vec::new());

    pub(in crate::host) struct Fixture(PathBuf, Scopes);

    impl Fixture {
        pub fn install(root: &Path) -> Self {
            let scopes = Scopes::default();
            FIXTURES.lock().unwrap().push((root.to_owned(), scopes.clone()));
            Self(root.to_owned(), scopes)
        }

        pub fn scopes(&self) -> Vec<Scope> { self.1.lock().unwrap().clone() }
    }

    impl Drop for Fixture {
        fn drop(&mut self) { FIXTURES.lock().unwrap().retain(|(path, _)| *path != self.0); }
    }

    pub(in crate::host) struct Software {
        inner: SoftwareSecureElement,
        scope: Option<(Scopes, usize)>,
    }

    impl Software {
        pub(super) fn plain(inner: SoftwareSecureElement) -> Self { Self { inner, scope: None } }
    }

    pub(super) fn open(dir: &Path, pass: &str, reason: Option<&str>) -> Option<Result<Software, String>> {
        let scopes = FIXTURES.lock().unwrap().iter().find(|(path, _)| dir.starts_with(path))?.1.clone();
        Some(SoftwareSecureElement::persistent(dir, pass).map(|inner| {
            let mut events = scopes.lock().unwrap();
            let index = events.len();
            events.push(Scope { reason: reason.map(str::to_owned), unwraps: 0, closed: false });
            drop(events);
            Software { inner, scope: Some((scopes, index)) }
        }))
    }

    impl SecureElement for Software {
        fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> { self.inner.wrap_dek(dek) }

        fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, OpenError> {
            if let Some((scopes, i)) = &self.scope { scopes.lock().unwrap()[*i].unwraps += 1; }
            self.inner.unwrap_dek(wrapped)
        }
    }

    impl Drop for Software {
        fn drop(&mut self) {
            if let Some((scopes, i)) = &self.scope { scopes.lock().unwrap()[*i].closed = true; }
        }
    }
}

/// The unlocked profile. Holds only the passphrase + data root (no live connections);
/// the hosted relay runtime is a process-wide singleton in `setup_relay`. Mirrors
/// `member_service::Service` but shaped for the HTTP + `spawn_blocking` model.
pub struct Session {
    pub passphrase: Zeroizing<String>,
    pub data: PathBuf,
}

impl Session {
    /// Validate the sealed profile without activating the session or its cache.
    pub fn unlock(
        data: PathBuf,
        passphrase: Zeroizing<String>,
    ) -> Result<(Self, serde_json::Value), String> {
        let profile = crate::profile::open(&data, &passphrase)?;
        Ok((Self { passphrase, data }, profile))
    }
}

pub struct AppState {
    pub config: Config,
    pub(super) registration: RwLock<Option<super::registration::PublicMember>>,
    /// The last failed registration attempt, reported locally while registration retries.
    pub(super) registration_error: RwLock<Option<String>>,
    pub session: RwLock<Option<Session>>,
    /// A native member never unlocks in place after stopping; each launch has its own signal.
    pub(super) stopping: watch::Sender<bool>,
    // Lock and activation both modify session state under the session write lock.
    pub(super) session_generation: AtomicU64,
    pub ceremony: std::sync::Mutex<()>,
    pub payment: std::sync::Mutex<()>,
    pub active_payments: std::sync::Mutex<BTreeSet<String>>,
    /// Logged-in relay connections for control messages, by login key (see `payment::RelayLease`).
    pub(super) relays: std::sync::Mutex<BTreeMap<[u8; 32], super::payment::CachedRelay>>,
    /// Per vault: held while that vault's control mailbox is being drained and applied.
    pub(super) control_receivers: std::sync::Mutex<BTreeMap<String, std::sync::Arc<std::sync::Mutex<()>>>>,
    /// Per vault: the background control sync's state, reported to the wallet.
    pub(super) control_status: std::sync::Mutex<BTreeMap<String, super::payment::ControlStatus>>,
    /// Per (vault, frostd session): the roster member who owns it, or `None` for a session that
    /// isn't this vault's control mailbox. A session's owner and members never change.
    pub(super) control_sessions: std::sync::Mutex<BTreeMap<(String, uuid::Uuid), Option<u16>>>,
    pub active_dkgs: std::sync::Mutex<BTreeSet<String>>,
    /// The creator's frostd loop answering joiners is running (`ceremony::spawn_join_relay`).
    pub(super) join_relay: std::sync::atomic::AtomicBool,
    /// Device login registry, built lazily from `data/recovery.pub` + `data/devices.json` once
    /// a recovery identity exists. Holds outstanding challenges in-process across requests.
    pub(super) device_auth: std::sync::Mutex<Option<super::device::DeviceState>>,
    /// The member's native payment decision; `None` (headless) refuses every payment.
    pub approval: Option<super::LocalApproval>,
    pub(super) notice: Option<super::LocalNotice>,
    /// The member's native roster-code comparison; `None` (headless) trusts the caller of
    /// `/api/agree`.
    pub roster_confirmation: Option<super::LocalRosterConfirmation>,
    /// The vault whose roster code the native app is asking about; it asks about one at a time.
    pub(super) roster_asking: std::sync::Mutex<Option<String>>,
    /// Vaults whose codes the member said differ, refused until the app restarts.
    pub(super) roster_refused: std::sync::Mutex<BTreeSet<String>>,
    pub(super) wallet_tabs: Option<super::connect::WalletTabs>,
    /// Each opened vault's viewing key; `None` means a cancelled open needs an explicit retry.
    pub(super) viewing_keys: std::sync::Mutex<BTreeMap<String, Option<orchard::keys::FullViewingKey>>>,
    /// LokiSigner's confirmed launch snapshot. Fresh settings without overrides are saved on unlock.
    pub(super) fetched_config: Option<super::FetchedConfig>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            registration: RwLock::new(None),
            registration_error: RwLock::new(None),
            session: RwLock::new(None),
            stopping: watch::Sender::new(false),
            session_generation: AtomicU64::new(0),
            ceremony: std::sync::Mutex::new(()),
            payment: std::sync::Mutex::new(()),
            active_payments: std::sync::Mutex::new(BTreeSet::new()),
            relays: std::sync::Mutex::new(BTreeMap::new()),
            control_receivers: std::sync::Mutex::new(BTreeMap::new()),
            control_status: std::sync::Mutex::new(BTreeMap::new()),
            control_sessions: std::sync::Mutex::new(BTreeMap::new()),
            active_dkgs: std::sync::Mutex::new(BTreeSet::new()),
            join_relay: std::sync::atomic::AtomicBool::new(false),
            device_auth: std::sync::Mutex::new(None),
            approval: None,
            notice: None,
            roster_confirmation: None,
            roster_asking: std::sync::Mutex::new(None),
            roster_refused: std::sync::Mutex::new(BTreeSet::new()),
            wallet_tabs: None,
            viewing_keys: std::sync::Mutex::new(BTreeMap::new()),
            fetched_config: None,
        }
    }
    pub(super) fn is_stopping(&self) -> bool {
        *self.stopping.borrow()
    }

    pub(super) async fn wait_for_stop(&self) {
        let _ = self.stopping.subscribe().wait_for(|stopping| *stopping).await;
    }

    pub(super) fn session_generation(&self) -> u64 {
        self.session_generation.load(Ordering::Acquire)
    }

    pub(super) async fn activate_session(self: &std::sync::Arc<Self>, generation: u64, session: Session) -> bool {
        let mut current = self.session.write().await;
        if self.session_generation() != generation || self.is_stopping() { return false; }
        crate::seal_kdf::enable_session_cache(&session.passphrase);
        let waiting = !super::ceremony::waiting_for_joiners(&session.data, &session.passphrase).is_empty();
        *current = Some(session);
        drop(current);
        // A creator restarted mid-setup answers joiners again without anyone opening the vault.
        if waiting {
            super::ceremony::spawn_join_relay(self);
        }
        true
    }

    pub(super) async fn lock_session(self: &std::sync::Arc<Self>) {
        let mut current = self.session.write().await;
        *current = None;
        if let Some(tabs) = &self.wallet_tabs { tabs.revoke_all(); }
        crate::seal_kdf::clear_session_cache();
        self.session_generation.fetch_add(1, Ordering::Release);
        drop(current);
        #[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
        super::native_member::clear_addresses_on_lock(self);
    }
}

pub type Shared = std::sync::Arc<AppState>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::secure_element::SealedShare;

    #[test]
    fn apple_tags_keep_legacy_identity_and_scope_new_keys_to_the_profile_and_role() {
        let data = std::env::temp_dir().join(format!("loki-device-tag-{}", uuid::Uuid::new_v4()));
        let device = data.join("device-auth");
        let legacy_vault = data.join("vaults/older/signer");
        let vault = data.join("vaults/example/signer");
        let mut config = config("apple");
        config.native = true;
        let legacy = |path: &Path| format!("cash.loki.member.kek.v1:{}", path.display()).into_bytes();
        let tags = |config: &Config, root: &Path, device: &Path, vault: &Path, create: bool| {
            let (scope, role) = vault_key_scope(config, root, vault, None, create).unwrap();
            (apple_key_tag(device, key_scope(config, root).unwrap(), "device-auth"), apple_key_tag(vault, scope, &role))
        };
        assert_eq!(tags(&config, &data, &device, &legacy_vault, false), (legacy(&device), legacy(&legacy_vault)));
        write_native_key_scope(&data).unwrap();
        std::fs::create_dir_all(&legacy_vault).unwrap();
        std::fs::write(legacy_vault.join("share.sealed"), b"already sealed with #93").unwrap();
        let scope = read_native_key_scope(&data).unwrap().unwrap();
        let scoped = tags(&config, &data, &device, &vault, true);
        assert_eq!(scoped.0, format!("cash.loki.member.kek.v2:{scope}:device-auth").as_bytes());
        assert_eq!(scoped.1, format!("cash.loki.member.kek.v2:{scope}:vault:example").as_bytes());
        assert_eq!(tags(&config, &data, &device, &vault, false), (scoped.0.clone(), legacy(&vault)));
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join(SCOPED_VAULT_KEY), []).unwrap();
        assert_eq!(tags(&config, &data, &device, &vault, false), scoped);
        assert_eq!(tags(&config, &data, &device, &legacy_vault, false), (scoped.0.clone(), legacy(&legacy_vault)));
        config.native = false;
        assert_eq!(tags(&config, &data, &device, &vault, false), (legacy(&device), legacy(&vault)));
        config.native = true;
        let moved = data.with_extension("moved");
        std::fs::rename(&data, &moved).unwrap();
        assert_eq!(scoped, tags(&config, &moved, &moved.join("device-auth"), &moved.join("vaults/example/signer"), false));
        write_native_key_scope(&data).unwrap();
        let replacement = tags(&config, &data, &device, &vault, true);
        assert_ne!(scoped.0, replacement.0);
        assert_ne!(scoped.1, replacement.1);
        std::fs::remove_dir_all(data).unwrap();
        std::fs::remove_dir_all(moved).unwrap();
    }

    fn config(secure_element: &str) -> Config {
        Config {
            registration: None, native: false,
            bind: "127.0.0.1".parse().unwrap(), peer_port: None, advertise_url: None,
            data: PathBuf::new(), port: 3001, network: "regtest".into(),
            lightwalletd: None, transport: "local".into(), secure_element: secure_element.into(),
            operator_bundle: None, nonce_witnesses: None, operator_key: None, enrollment_issuer: None,
            development_http: false, token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(), peers: BTreeMap::new(),
            loopback_peers: false,
        }
    }

    #[test]
    fn cli_network_is_testnet_or_regtest_only() {
        let args = |network: Option<&str>| {
            let mut args: Vec<String> = ["--data", "unused", "--port", "0"].map(Into::into).to_vec();
            args.extend(network.map(|n| ["--network".into(), n.into()]).into_iter().flatten());
            super::super::config_from_args(&args).map(|c| c.network)
        };
        assert_eq!(args(None).unwrap(), "regtest");
        assert_eq!(args(Some("testnet")).unwrap(), "testnet");
        for refused in ["mainnet", "main", "Mainnet", "", "test"] {
            assert!(args(Some(refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn peer_urls_allow_regtest_loopback_and_operator_origins_only() {
        let mut c = config("software");
        for url in ["http://127.0.0.1:42783", "http://[::1]:42784"] {
            assert!(c.validate_peer_url(url).is_ok(), "{url}");
        }
        for url in ["http://169.254.169.254", "http://10.0.0.1:4000", "http://example.com",
            "http://localhost:4000", "http://127.0.0.1:80", "http://127.0.0.1:4000/path",
            "http://127.0.0.1:4000?url=evil", "http://127.0.0.1:4000#evil",
            "http://user@127.0.0.1:4000", "file:///etc/passwd", "http://127.1:4000"] {
            assert!(c.validate_peer_url(url).is_err(), "{url}");
        }
        c.network = "testnet".into();
        assert!(c.validate_peer_url("http://127.0.0.1:42783").is_err());
        c.loopback_peers = true;
        assert!(c.validate_peer_url("http://127.0.0.1:42783").is_ok());
        assert!(c.validate_peer_url("http://127.0.0.1:80").is_err());
        c.loopback_peers = false;
        c.peers.insert(9, "https://signer.example".into());
        assert!(c.validate_peer_url("https://signer.example").is_ok());
        assert!(c.validate_peer_url("https://signer.example:443").is_ok());
        c.peers.insert(9, "https://signer.example:443".into());
        assert!(c.validate_peer_url("https://signer.example").is_ok());
        assert!(c.validate_peer_url("https://signer.example:444").is_err());
    }

    #[test]
    fn secure_element_selection_rejects_invalid_or_unavailable_backends() {
        assert!(config("software").validate_secure_element().is_ok());
        assert_eq!(
            config("apple").validate_secure_element().is_ok(),
            cfg!(all(target_os = "macos", feature = "apple-enclave")),
        );
        let dir = std::env::temp_dir().join(format!("loki-invalid-se-{}", uuid::Uuid::new_v4()));
        for name in ["", "unknown", "Software"] {
            assert!(config(name).validate_secure_element().is_err());
            assert!(config(name).open_secure_element(&dir, "pass").is_err());
        }
        #[cfg(not(all(target_os = "macos", feature = "apple-enclave")))]
        assert!(config("apple").open_secure_element(&dir, "pass").is_err());
        assert!(!dir.exists());
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[test]
    fn marked_scoped_vault_with_no_key_is_not_created_on_open() {
        let root = std::env::temp_dir().join(format!("loki-marked-with-no-key-{}", uuid::Uuid::new_v4()));
        let dir = root.join("vaults/new/signer");
        write_native_key_scope(&root).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = config("apple");
        cfg.native = true;
        cfg.data = root.clone();
        let scope = read_native_key_scope(&root).unwrap().unwrap();
        let expected = format!("cash.loki.member.kek.v2:{scope}:vault:new");
        let intents = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let accesses = intents.clone();
        let _fixture = apple_test::install(&root, move |dir, tag, create| {
            assert!(dir.join(SCOPED_VAULT_KEY).is_file(), "write the marker before touching the Keychain");
            assert_eq!(tag, expected.as_bytes());
            accesses.lock().unwrap().push(create);
            Err(if create { KeyFailure::Cancelled } else { KeyFailure::Missing })
        });
        assert_eq!(cfg.create_secure_element(&dir, "unused", None, &root).err().as_deref(), Some(KeyFailure::Cancelled.message()));
        assert_eq!(cfg.open_secure_element(&dir, "unused").err().as_deref(), Some(KeyFailure::Missing.message()));
        assert_eq!(*intents.lock().unwrap(), [true, false]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[test]
    fn staged_apple_vault_uses_the_existing_canonical_tag_after_publication() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(uuid::Uuid::new_v4().to_string());
        let dest = root.join("published").join("signer");
        let cfg = config("apple");
        let expected = [b"cash.loki.member.kek.v1:", dest.as_os_str().as_encoded_bytes()].concat();
        let stage = root.join("stage");
        let pending = stage.join("signer");
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let accesses = calls.clone();
        let _fixture = apple_test::install(&root, move |_, tag, create| {
            assert_eq!(tag, expected);
            accesses.lock().unwrap().push(create);
            if create { Ok(()) } else { Err(KeyFailure::Missing) }
        });
        for _ in 0..2 {
            cfg.create_secure_element(&pending, "unused", Some(&dest), &stage).unwrap();
            assert!(!dest.exists(), "staging leaves the published profile absent");
            std::fs::remove_dir_all(&stage).unwrap();
        }
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        assert_eq!(cfg.open_secure_element(&dest, "unused").err().as_deref(), Some(KeyFailure::Missing.message()));
        assert!(!dest.exists(), "an open with no key must not create a directory");
        assert_eq!(*calls.lock().unwrap(), [true, true, false]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn software_secure_element_preserves_existing_seals_and_kek() {
        let dir = std::env::temp_dir().join(format!("loki-software-se-{}", uuid::Uuid::new_v4()));
        let old = SoftwareSecureElement::persistent(&dir, "pass").unwrap();
        let kek = std::fs::read(dir.join("kek.sealed")).unwrap();
        let sealed = SealedShare::seal(&old, 0, b"share").unwrap();
        let configured = config("software").open_secure_element(&dir, "pass").unwrap();
        assert_eq!(&**sealed.open(&configured).unwrap(), b"share");
        let sealed = SealedShare::seal(&configured, 0, b"share").unwrap();
        assert_eq!(&**sealed.open(&old).unwrap(), b"share");
        let reopened = config("software").open_secure_element(&dir, "pass").unwrap();
        assert_eq!(&**sealed.open(&reopened).unwrap(), b"share");
        assert!(config("software").open_secure_element(&dir, "wrong pass").is_err());
        assert_eq!(std::fs::read(dir.join("kek.sealed")).unwrap(), kek);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
