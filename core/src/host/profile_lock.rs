//! One LokiSigner process per profile. Every native launch (the Runner, the standalone app's
//! native and serve modes, pairing, restore and witness approval) takes an exclusive `flock` on
//! `<canonical data path>.lock` and holds it until the process exits. While it is held, no other
//! process can pair, restore, unlock or write that profile's configuration. The lock file sits
//! beside the folder, so a fresh folder stays fresh, and it is keyed on the resolved absolute
//! path, so a symlink, `.` or a relative spelling of one profile all contend on the same lock.
//! Once locked, the session reads and writes the profile only through that canonical path
//! ([`locked_args`]), so moving a symlink afterwards can't redirect it to another profile.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Another process holds the profile.
pub(crate) const PROFILE_IN_USE: &str = "profile-in-use";
/// macOS `O_NOFOLLOW` (`<sys/fcntl.h>`): never lock through a planted symlink.
const O_NOFOLLOW: i32 = 0x0100;

static HELD: Mutex<Option<(PathBuf, File)>> = Mutex::new(None);

/// Take this process's lock on the profile at `data`, or confirm it already holds it, and return
/// the canonical path it holds. A process holds at most one profile; asking for another,
/// including through a symlink that now points elsewhere, is refused.
pub(crate) fn lock(data: &Path) -> Result<PathBuf, String> {
    let profile = canonical(data)?;
    let mut held = HELD.lock().map_err(|_| "LokiSigner could not lock its profile")?;
    match held.as_ref() {
        Some((path, _)) if *path == profile => return Ok(profile),
        Some(_) => return Err("this LokiSigner process already opened a different profile".into()),
        None => {},
    }
    let (Some(parent), Some(name)) = (profile.parent(), profile.file_name()) else {
        return Err("LokiSigner could not lock its profile".into());
    };
    let mut lock = name.to_owned();
    lock.push(".lock");
    let failed = |e: std::io::Error| format!("LokiSigner could not lock its profile: {e}");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(O_NOFOLLOW);
    }
    let file = options.open(parent.join(lock)).map_err(failed)?;
    match file.try_lock() {
        Ok(()) => {},
        Err(std::fs::TryLockError::WouldBlock) => return Err(PROFILE_IN_USE.into()),
        Err(std::fs::TryLockError::Error(e)) => return Err(failed(e)),
    }
    *held = Some((profile.clone(), file));
    Ok(profile)
}

/// Lock the profile a launch's `--data` names and return the launch arguments with `--data`
/// replaced by the locked canonical path, for every profile read and write that follows.
pub(crate) fn locked_args(args: &[String]) -> Result<Vec<String>, String> {
    let index = args.iter().position(|arg| arg == "--data").map(|i| i + 1)
        .filter(|&i| i < args.len()).ok_or("--data <dir> is required")?;
    let profile = lock(Path::new(&args[index]))?;
    let mut args = args.to_vec();
    args[index] = profile.into_os_string().into_string().map_err(|_| "LokiSigner's profile path is not valid UTF-8")?;
    Ok(args)
}

/// The profile's absolute location with every symlink resolved. A folder that doesn't exist
/// yet resolves through its parent, which is created so the lock file has a home.
fn canonical(data: &Path) -> Result<PathBuf, String> {
    let failed = |e: std::io::Error| format!("LokiSigner could not resolve its profile folder: {e}");
    let absolute = if data.is_absolute() { data.to_owned() } else { std::env::current_dir().map_err(failed)?.join(data) };
    match absolute.canonicalize() {
        Ok(path) => Ok(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let absolute: PathBuf = absolute.components().collect();
            let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) else { return Err(failed(e)) };
            std::fs::create_dir_all(parent).map_err(failed)?;
            Ok(parent.canonicalize().map_err(failed)?.join(name))
        }
        Err(e) => Err(failed(e)),
    }
}
