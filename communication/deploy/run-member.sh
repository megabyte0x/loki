#!/usr/bin/env bash
# Run one self-custody member against a public coordinator, from a packaged binary.
#
#   run-member.sh <coordinator-url> <slot>
#
# Self-registers to the coordinator (the browser-origin middleware only accepts the
# coordinator URL the member was launched with), then prints the local pairing link
# to open in a browser. The binary needs no Rust toolchain.
#
# Remote ceremony peers use a free cloudflared quick tunnel to the member's separate,
# ceremony-only loopback listener. Never tunnel the private member API on PORT.
#
# frostd must be reachable on loopback (https off loopback is enforced): forward the
# shared relay first, e.g.  ssh -N -L 2744:localhost:2744 omarchy
#
# Env:
#   MEMBER_BIN   path to loki_member_app  (default <repo>/core/target/release/loki_member_app)
#   DATA         member data dir          (default <repo>/loki-state/member-<slot>)
#   PORT         local member port        (default 3610 + slot)
#   PEER_PORT    ceremony backend port    (default 4610 + slot)
#   FROSTD_URL   frostd loopback url       (default http://127.0.0.1:2744)
#   LWD_URL      lightwalletd base url     (default https://testnet.zec.rocks:443)
#   NETWORK      vault network             (default testnet)
#   ADVERTISE_URL  use your own TLS proxy to PEER_PORT (default: own cloudflared tunnel)
#   NO_TUNNEL=1    skip the per-member tunnel
set -euo pipefail

if [[ $# != 2 || $1 != http* || ! $2 =~ ^[0-9]+$ ]]; then
  echo 'usage: run-member.sh <coordinator-url> <slot>' >&2
  exit 2
fi
coordinator=${1%/}
slot=$2
deploy=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$deploy/../.." && pwd -P)
source "$deploy/member-launch.sh"

member_bin=${MEMBER_BIN:-$repo/core/target/release/loki_member_app}
if [[ -z ${DATA:-} && ( -e $PWD/loki-member-$slot || -L $PWD/loki-member-$slot ) ]]; then
  launch_error "legacy member state found: set DATA=./loki-member-$slot to reuse its existing passphrase and state"
fi
data=${DATA:-$repo/loki-state/member-$slot}
[[ $data == /* ]] || data=$PWD/$data
while [[ $data == */ && $data != / ]]; do data=${data%/}; done
port=${PORT:-$((3610 + slot))}
peer_port=${PEER_PORT:-$((4610 + slot))}
frostd=${FROSTD_URL:-http://127.0.0.1:2744}
lwd=${LWD_URL:-https://testnet.zec.rocks:443}
network=${NETWORK:-testnet}
cloudflared=/opt/homebrew/bin/cloudflared

[[ -x $member_bin ]] || { echo "member binary not found: $member_bin (build with: cargo build --release --features relay-communication --bin loki_member_app)" >&2; exit 1; }
advertise=${ADVERTISE_URL:-}
if [[ -n $advertise || ${NO_TUNNEL:-} != 1 ]]; then
  if ! [[ $port =~ ^[0-9]{1,5}$ && $peer_port =~ ^[0-9]{1,5}$ ]] ||
     (( 10#$peer_port == 0 || 10#$peer_port > 65535 || 10#$peer_port == 10#$port )); then
    echo 'PEER_PORT must be a valid port distinct from the private PORT' >&2
    exit 2
  fi
fi
{ exec 7>/dev/tty; } 2>/dev/null || launch_error "a terminal is required to show the private pairing link"
if [[ -z ${DATA:-} ]]; then
  root=${data%/*}
  [[ -e $root || -L $root ]] || mkdir -p -- "$root"
  [[ ! -L $root && -d $root && -O $root && $(find "$root" -prune -perm 700 -print) == "$root" ]] \
    || launch_error "default state root must be an owned, non-symlink directory with mode 0700: $root"
fi
mkdir -p "$data"
lock_launch "$data"
[[ ! -L $data/state && ( ! -e $data/state || ( -d $data/state && -O $data/state ) ) ]] \
  || launch_error "refusing a symlink, non-directory, or state directory owned by another user: $data/state"
pass="$data/local.pass"
ensure_passphrase "$pass"
private_output "$data/pids"
trap cleanup_launch EXIT
trap 'exit 1' INT TERM

if [[ -z $advertise && ${NO_TUNNEL:-} != 1 ]]; then
  echo "== cloudflared quick tunnel -> 127.0.0.1:$peer_port (ceremony only) =="
  private_output "$data/cloudflared.log"
  "$cloudflared" tunnel --url "http://127.0.0.1:$peer_port" >"$data/cloudflared.log" 2>&1 7>&- &
  echo $! >> "$data/pids"
  for _ in {1..80}; do
    advertise=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$data/cloudflared.log" | head -1 || true)
    [[ -n $advertise ]] && break; sleep 0.5
  done
  [[ -n $advertise ]] || { echo "member tunnel never came up; see $data/cloudflared.log" >&2; exit 1; }
  echo "advertising peer url: $advertise"
fi

echo "== member slot $slot on :$port -> $coordinator =="
start_member "$port" "$data/member.log" "$data/pids" \
  "$member_bin" --data "$data/state" --port "$port" --network "$network" \
  --lightwalletd-url "$lwd" --frostd-url "$frostd" --secure-element software \
  --coordinator-url "$coordinator" --local-passphrase-file "$pass" \
  --registration-slot "$slot" --profile-name "Member $slot" \
  ${advertise:+--peer-port "$peer_port" --advertise-url "$advertise"}

# The member serves locally even when the coordinator refuses or is unreachable; it keeps
# retrying registration and logs each failure to member.log.
curl -sf --max-time 10 "$coordinator/api/members" | grep -q "\"slot\": *$slot\|\"slot\":$slot" \
  || { echo "warning: slot $slot not yet visible in $coordinator/api/members; registration retries, see $data/member.log" >&2; }

echo "=============================================================="
echo "member slot $slot running; registering with $coordinator"
printf 'Private pairing link (do not share or log): %s\n' "$pairing_link" >&7
unset pairing_link
echo "Set up recovery in the wallet if needed; save the words privately, then confirm."
echo "Keep this launcher in the foreground for local roster confirmation. Press Ctrl-C to stop."
echo "=============================================================="
wait
