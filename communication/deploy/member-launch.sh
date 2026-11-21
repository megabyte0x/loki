# Shared by the two headless launchers (Bash on Linux/macOS).
set +ax # Never auto-export or trace the bearer.
unset pairing_link
umask 077

launch_error() { printf '%s\n' "$*" >&2; exit 1; }

lock_launch() {
  local dir=$1
  [[ ! -L $dir && -d $dir && -O $dir && $(find "$dir" -prune -perm 700 -print) == "$dir" ]] \
    || launch_error "launch directory must be an owned, non-symlink directory with mode 0700: $dir"
  # Lock the directory inode. The actual services inherit fd 9, so the lock survives the launcher.
  exec 9<"$dir"
  python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null \
    || launch_error "could not lock $dir (already running, or Python 3/flock unavailable)"
}

check_launch_file() {
  [[ ! -L $1 && ( ! -e $1 || ( -f $1 && -O $1 ) ) ]] \
    || launch_error "refusing a symlink, non-regular file, or file owned by another user: $1"
}

private_output() {
  check_launch_file "$1"
  # Replace, rather than truncate, an old inode that may be broadly readable or hard-linked.
  rm -f -- "$1"
  (set -C; : > "$1")
}

ensure_passphrase() {
  local pass=$1 tmp
  check_launch_file "$pass"
  if [[ -e $pass ]]; then
    [[ $(find "$pass" -prune -perm 600 -print) == "$pass" ]] \
      || launch_error "passphrase file must have mode 0600: $pass"
    return
  fi
  tmp=$(mktemp "${pass%/*}/.unlock-XXXXXXXX")
  if ! openssl rand -hex 16 > "$tmp" || ! mv -- "$tmp" "$pass"; then
    rm -f -- "$tmp"
    launch_error "could not publish passphrase file: $pass"
  fi
}

cleanup_launch() {
  # Never use a persisted PID list as authority to signal processes.
  local pid
  for pid in $(jobs -pr) $(jobs -ps); do kill "$pid" 2>/dev/null || true; done
}

start_member() {
  local port=$1 log=$2 pids=$3 ready dir prefix
  shift 3
  dir=${log%/*}
  private_output "$log"
  ready=$(mktemp -d "$dir/.ready-XXXXXXXX")
  mkfifo "$ready/link"
  # Open both ends before the spawn so even early child failure has a bounded wait.
  exec 8<>"$ready/link"
  rm -- "$ready/link"
  rmdir -- "$ready"
  "$@" --pairing-stdout >&8 8>&- 7>&- 2>"$log" &
  printf '%s\n' "$!" >> "$pids"

  prefix="http://127.0.0.1:$port/#"
  if ! IFS= read -r -t 36 pairing_link <&8 || [[ $pairing_link != "$prefix"* ]]; then
    launch_error "member on port $port did not send a private pairing link; see $log (use an updated member binary)"
  fi
  exec 8>&-
  [[ ${pairing_link#"$prefix"} =~ ^[A-Za-z0-9_-]{43}$ ]] \
    || launch_error "member on port $port sent an invalid pairing link"
}
