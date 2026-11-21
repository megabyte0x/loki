//! In-process executor for hosted setup commands (`loki_member_service`).
//!
//! The member app starts one service per unlocked profile and talks to it over the
//! child's stdin and stdout only, one JSON object per line:
//!
//! * The first frame is `{"op":"unlock","data":<data root>,"passphrase":…}`. The
//!   passphrase is checked by opening `profile/profile.sealed` and is then held only in
//!   this process's memory. The reply is `{"unlocked":true}`; a wrong passphrase ends
//!   the service.
//! * Each later frame is `{"id":…,"op":<setup command>,"args":[…]}` with the same
//!   arguments as `loki_setup_member <op>`, except that the passphrase argument is
//!   `@session`, private input is `@private` (bytes in `private_hex`) and backup words
//!   are `@words` (text in `words`). A vault target is a lowercase 32-byte hex ID
//!   or its full path under `<data>/vaults`. Explicit input and export paths keep
//!   their CLI meanings. The reply is `{"id":…,"ok":true,"result":…}` or
//!   `{"id":…,"ok":false,"error":…}`, with the CLI's result and error strings.
//!   Only scalar request IDs are echoed; missing or compound IDs yield `null`.
//! * `{"op":"lock"}` or end of stdin stops the service: no new work is accepted,
//!   commands in flight get [`STOP_GRACE`] to finish, then the session key cache and
//!   the passphrase are zeroized and the process exits. A command still running then
//!   is abandoned exactly as when the app kills a CLI process.
//!
//! Only [`ALLOWED`] commands run. Each command opens its setup, holds the vault's
//! `.setup.lock` only while it runs and drops it, as the CLI does, so other tools see
//! the same locks. What the service adds is one process: the Tokio runtime, relay
//! connections and endpoint checks, and the Argon2id keys for this passphrase stay
//! warm between commands. The passphrase never reaches a file, argv, the
//! environment or stderr.

use crate::setup_ceremony::journal;
use crate::setup_relay::{backup_command_with, command_with, BackupCommandOutput, Inputs};
use crate::state::MemberDir;
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// The hosted setup commands the service runs. Anything else is refused.
pub const ALLOWED: &[&str] = &[
    "setup-config-check",
    "setup-status",
    "setup-info",
    "setup-evidence",
    "setup-create",
    "setup-join",
    "setup-invite",
    "setup-fingerprint",
    "setup-agree",
    "setup-step",
    "setup-abort",
    "setup-backup-create",
    "setup-backup-verify",
    "setup-backup-finalize",
];
/// Commands running at once; the app schedules at most two vaults plus user actions.
pub const MAX_IN_FLIGHT: usize = 4;
/// How long commands in flight may finish after Lock or end of input.
pub const STOP_GRACE: Duration = Duration::from_secs(4);
/// Longest accepted frame, in bytes.
const FRAME_LIMIT: usize = 64 * 1024;

pub struct Service {
    passphrase: Zeroizing<String>,
    data: PathBuf,
    vaults: PathBuf,
}

fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(fields) => {
            for (mut name, mut field) in std::mem::take(fields) {
                name.zeroize();
                wipe(&mut field);
            }
        }
        _ => {}
    }
}

struct SensitiveFrame(Value);

impl SensitiveFrame {
    fn parse(line: &str) -> Option<Self> {
        let frame = Self(serde_json::from_str(line).ok()?);
        frame.0.is_object().then_some(frame)
    }

    fn take_id(&mut self) -> Value {
        match self.0.get_mut("id") {
            Some(id @ (Value::Bool(_) | Value::Number(_) | Value::String(_))) => std::mem::take(id),
            _ => Value::Null,
        }
    }

    fn take_string(&mut self, name: &str) -> Option<String> {
        match self.0.get_mut(name) {
            Some(Value::String(text)) => Some(std::mem::take(text)),
            _ => None,
        }
    }
}

impl Drop for SensitiveFrame {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn command_reply(id: Value, result: Result<Value, String>) -> Value {
    let mut reply = json!({"ok":result.is_ok()});
    reply["id"] = id;
    match result {
        Ok(result) => reply["result"] = result,
        Err(error) => reply["error"] = Value::String(error),
    }
    reply
}

impl Service {
    /// Check an unlock frame against the profile and enable the session key cache.
    pub fn unlock(line: &str) -> Result<Self, String> {
        let mut frame = SensitiveFrame::parse(line).ok_or("service_frame")?;
        let passphrase = Zeroizing::new(frame.take_string("passphrase").unwrap_or_default());
        if frame.0.get("op").and_then(Value::as_str) != Some("unlock")
            || passphrase.is_empty()
            || passphrase.len() > 4096
        {
            return Err("service_frame".into());
        }
        let data = PathBuf::from(frame.take_string("data").ok_or("service_frame")?);
        drop(frame);
        if !data.is_absolute() {
            return Err("service_frame".into());
        }
        let resolved = data.canonicalize().map_err(|_| "service_unlock")?;
        let profile = MemberDir::open(&resolved, "profile");
        journal::check_private_root(profile.path()).map_err(|_| "service_unlock")?;
        journal::checked_file(&profile.path().join("profile.sealed"))
            .map_err(|_| "service_unlock")?;
        // The profile key is the first cached derivation; a failed check forgets it.
        crate::seal_kdf::enable_session_cache(&passphrase);
        let checked = profile
            .read_sealed("profile.sealed", &passphrase)
            .ok()
            .map(Zeroizing::new)
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
            .is_some_and(|profile| profile["version"] == 1);
        if !checked {
            crate::seal_kdf::clear_session_cache();
            return Err("service_unlock".into());
        }
        Ok(Self {
            passphrase,
            data,
            vaults: resolved.join("vaults"),
        })
    }

    pub fn data(&self) -> &Path {
        &self.data
    }

    fn vault_root(&self, target: &str, joining: bool) -> Result<String, String> {
        const ERROR: &str = "setup_vault_path";
        let target = Path::new(target);
        let id = target
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ERROR)?;
        if id.len() != 64 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(ERROR.into());
        }
        let root = self.vaults.join(id);
        if target != Path::new(id) && target != root && target != self.data.join("vaults").join(id)
        {
            return Err(ERROR.into());
        }
        // Build from the unlocked profile, never from a request path. Private-root
        // checks reject symlinks at either level as well as public directories.
        for path in [&self.vaults, &root] {
            if joining {
                #[cfg(unix)]
                match rustix::fs::mkdir(path, rustix::fs::Mode::RWXU) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(ERROR.into()),
                }
            }
            journal::check_private_root(path).map_err(|_| ERROR)?;
        }
        root.into_os_string()
            .into_string()
            .map_err(|_| ERROR.into())
    }

    /// Run one request frame and return its reply.
    pub fn handle(&self, line: &str) -> Value {
        self.handle_frame(SensitiveFrame::parse(line))
    }

    fn handle_frame(&self, frame: Option<SensitiveFrame>) -> Value {
        let Some(mut frame) = frame else {
            return command_reply(Value::Null, Err("service_frame".into()));
        };
        let id = frame.take_id();
        let reply = |result| command_reply(id, result);
        let op = frame.0["op"].as_str();
        let Some(op) = ALLOWED.iter().copied().find(|&allowed| Some(allowed) == op) else {
            return reply(Err("service_command".into()));
        };
        let Some(raw_args) = frame.0.get_mut("args").and_then(Value::as_array_mut) else {
            return reply(Err("setup_arguments".into()));
        };
        let mut args = Zeroizing::new(Vec::with_capacity(raw_args.len()));
        for arg in raw_args {
            let Value::String(arg) = arg else {
                return reply(Err("setup_arguments".into()));
            };
            args.push(std::mem::take(arg));
        }
        let needs_passphrase = !matches!(op, "setup-config-check" | "setup-status");
        if needs_passphrase && args.get(1).map(String::as_str) != Some("@session") {
            return reply(Err("setup_arguments".into()));
        }
        let words = frame.take_string("words").map(Zeroizing::new);
        let private = match frame.take_string("private_hex").map(Zeroizing::new) {
            Some(text) => {
                let mut bytes = Zeroizing::new(vec![0; text.len() / 2]);
                if hex::decode_to_slice(text.as_bytes(), &mut bytes[..]).is_err() {
                    return reply(Err("setup_file".into()));
                }
                Some(bytes)
            }
            None => None,
        };
        drop(frame);
        if op != "setup-config-check" {
            let Some(root) = args.first_mut() else {
                return reply(Err("setup_arguments".into()));
            };
            match self.vault_root(root, op == "setup-join") {
                Ok(path) => {
                    root.zeroize();
                    *root = path;
                }
                Err(error) => return reply(Err(error)),
            }
        }
        let inputs = Inputs {
            passphrase: needs_passphrase.then(|| self.passphrase.clone()),
            private,
            words,
        };
        reply(if op.starts_with("setup-backup-") {
            backup_command_with(op, &args, &inputs).map(|output| match output {
                BackupCommandOutput::Words(mut words) => {
                    let mut result = json!({});
                    result["words"] = Value::String(std::mem::take(&mut *words));
                    result
                }
                BackupCommandOutput::Public(status) => status,
            })
        } else {
            command_with(op, &args, &inputs)
        })
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        crate::seal_kdf::clear_session_cache();
    }
}

/// Read one line of at most [`FRAME_LIMIT`] bytes into a zeroizing buffer. `None` at
/// end of input or on an oversized or unreadable frame.
fn read_frame(input: &mut impl BufRead) -> Option<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    match input
        .by_ref()
        .take(FRAME_LIMIT as u64 + 1)
        .read_line(&mut line)
    {
        Ok(0) | Err(_) => None,
        Ok(_) if line.len() > FRAME_LIMIT || !line.ends_with('\n') => None,
        Ok(_) => Some(line),
    }
}

fn write_frame(output: &Mutex<Box<dyn Write + Send>>, mut value: Value) {
    let mut text = Zeroizing::new(value.to_string());
    wipe(&mut value);
    text.push('\n');
    if let Ok(mut output) = output.lock() {
        let _ = output.write_all(text.as_bytes());
        let _ = output.flush();
    }
}

/// Serve frames from `input` until Lock or end of input. Returns once no command is in
/// flight or [`STOP_GRACE`] has passed; the session cache is cleared either way.
pub fn serve(mut input: impl BufRead, output: Box<dyn Write + Send>) -> Result<(), String> {
    let output = Arc::new(Mutex::new(output));
    let Some(first) = read_frame(&mut input) else {
        return Err("service_frame".into());
    };
    let service = match Service::unlock(&first) {
        Ok(service) => Arc::new(service),
        Err(error) => {
            write_frame(&output, json!({"unlocked":false,"error":error}));
            return Err(error);
        }
    };
    drop(first);
    write_frame(&output, json!({"unlocked":true}));
    let running = Arc::new((Mutex::new(0usize), Condvar::new()));
    while let Some(line) = read_frame(&mut input) {
        let mut frame = SensitiveFrame::parse(&line);
        drop(line);
        if frame.as_ref().and_then(|f| f.0["op"].as_str()) == Some("lock") {
            break;
        }
        {
            let mut count = running.0.lock().map_err(|_| "service_state")?;
            if *count >= MAX_IN_FLIGHT {
                let id = frame.as_mut().map_or(Value::Null, SensitiveFrame::take_id);
                drop(frame);
                write_frame(&output, command_reply(id, Err("service_busy".into())));
                continue;
            }
            *count += 1;
        }
        let (service, output, running) = (service.clone(), output.clone(), running.clone());
        std::thread::spawn(move || {
            write_frame(&output, service.handle_frame(frame));
            if let Ok(mut count) = running.0.lock() {
                *count -= 1;
                running.1.notify_all();
            }
        });
    }
    let deadline = Instant::now() + STOP_GRACE;
    if let Ok(mut count) = running.0.lock() {
        while *count > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match running.1.wait_timeout(count, left) {
                Ok((next, _)) => count = next,
                Err(_) => break,
            }
        }
    }
    crate::seal_kdf::clear_session_cache();
    // Threads still running hold their own clone; the process exits right after this.
    if let Ok(mut service) = Arc::try_unwrap(service) {
        service.passphrase.zeroize();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_frames_discard_nested_private_strings() {
        let mut frame = json!({"words":"abandon art", "extra":[{"private_hex":"deadbeef"}]});
        wipe(&mut frame);
        assert_eq!(frame, json!({}));
    }

    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn profile(passphrase: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "loki-service-{}-{}",
            std::process::id(),
            passphrase.len()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        MemberDir::create(&root, "profile")
            .unwrap()
            .write_sealed(
                "profile.sealed",
                br#"{"version":1,"name":"alice","id":"00"}"#,
                passphrase,
            )
            .unwrap();
        root
    }

    fn run(frames: &[String]) -> (Result<(), String>, Vec<Value>) {
        let input = frames.iter().map(|f| format!("{f}\n")).collect::<String>();
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let result = serve(
            std::io::Cursor::new(input.into_bytes()),
            Box::new(Shared(buffer.clone())),
        );
        let text = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        (
            result,
            text.lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
        )
    }

    // The session cache is process-wide; the cases run in one test so they never interleave.
    #[test]
    fn service_unlocks_runs_only_allowed_commands_and_clears_keys_on_stop() {
        let _serial = crate::seal_kdf::TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::seal_kdf::TEST_OPT_IN.with(|opt_in| opt_in.set(true));
        crate::seal_kdf::clear_session_cache();
        let root = profile("service pass");
        let unlock = |pass: &str| {
            json!({"op":"unlock","data":root.to_str().unwrap(),"passphrase":pass}).to_string()
        };
        // A wrong passphrase is refused and nothing else runs.
        let (result, replies) = run(&[
            unlock("wrong pass"),
            json!({"id":1,"op":"setup-status","args":["x"]}).to_string(),
        ]);
        assert_eq!(result, Err("service_unlock".into()));
        assert_eq!(
            replies,
            vec![json!({"unlocked":false,"error":"service_unlock"})]
        );
        assert_eq!(crate::seal_kdf::cache_len(), 0);

        // Unlock caches the profile key; dropping the service clears it.
        let service = Service::unlock(&unlock("service pass")).unwrap();
        assert_eq!(crate::seal_kdf::cache_len(), 1);
        drop(service);
        assert_eq!(crate::seal_kdf::cache_len(), 0);

        // Unknown and non-setup commands are refused; allowed ones get the CLI's
        // own errors; Lock stops before later frames and clears the key cache.
        let missing = root.join("no-such-vault");
        let (result, replies) = run(&[
            unlock("service pass"),
            json!({"id":1,"op":"profile-open","args":[root.to_str().unwrap()]}).to_string(),
            json!({"id":2,"op":"setup-step","args":[missing.to_str().unwrap(),"/tmp/passfile"]})
                .to_string(),
            json!({"id":3,"op":"setup-status","args":[missing.to_str().unwrap()]}).to_string(),
            json!({"id":4,"op":"setup-step","args":"not a list"}).to_string(),
            json!({"op":"lock"}).to_string(),
            json!({"id":5,"op":"setup-status","args":[missing.to_str().unwrap()]}).to_string(),
        ]);
        assert_eq!(result, Ok(()));
        assert_eq!(replies[0], json!({"unlocked":true}));
        let mut replies = replies[1..].to_vec();
        replies.sort_by_key(|reply| reply["id"].as_u64());
        assert_eq!(replies.len(), 4, "nothing runs after Lock: {replies:?}");
        assert_eq!(
            replies[0],
            json!({"id":1,"ok":false,"error":"service_command"})
        );
        // The service never reads a passphrase file.
        assert_eq!(
            replies[1],
            json!({"id":2,"ok":false,"error":"setup_arguments"})
        );
        assert_eq!(replies[2]["ok"], false);
        assert_eq!(
            replies[3],
            json!({"id":4,"ok":false,"error":"setup_arguments"})
        );
        assert_eq!(
            crate::seal_kdf::cache_len(),
            0,
            "Lock zeroizes the key cache"
        );

        // End of input stops the service the same way.
        let (result, replies) = run(&[unlock("service pass")]);
        assert_eq!(result, Ok(()));
        assert_eq!(replies, vec![json!({"unlocked":true})]);
        assert_eq!(crate::seal_kdf::cache_len(), 0);

        // A first frame that is not an unlock is refused.
        let (result, _) = run(&[json!({"id":1,"op":"setup-status","args":["x"]}).to_string()]);
        assert_eq!(result, Err("service_frame".into()));
        std::fs::remove_dir_all(root).unwrap();
    }
}
