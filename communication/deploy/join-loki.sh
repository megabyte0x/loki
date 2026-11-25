#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || $1 != https://* ]]; then
  echo 'usage: join-loki.sh <https-coordinator-url> [slot]' >&2
  exit 2
fi
coordinator=${1%/}
slot=${2:-}
[[ -z $slot || ( $slot =~ ^[1-9][0-9]{0,9}$ && $slot -le 4294967295 ) ]] || { echo "slot must be a positive coordinator slot number" >&2; exit 2; }

deploy=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$deploy/../.." && pwd -P)
member_bin=${MEMBER_BIN:-$repo/core/target/release/loki_member_app}
frostd=${FROSTD_URL:-http://127.0.0.1:2744}
frostd_host=${FROSTD_HOST:-omarchy}

if [[ ! -x $member_bin && -z ${MEMBER_BIN:-} ]]; then
  echo "== building loki_member_app (first run, a few minutes) =="
  ( cd "$repo/core" && cargo build --release --features relay-communication --bin loki_member_app )
fi
[[ -x $member_bin ]] || { echo "member binary not found: $member_bin" >&2; exit 1; }

reachable() { curl -s -o /dev/null --max-time 3 "$frostd/challenge"; }
if reachable; then
  echo "frostd reachable at $frostd"
else
  echo "opening ssh tunnel to $frostd_host"
  ssh -f -N -L 2744:localhost:2744 "$frostd_host" || true
  reachable || { echo "frostd unreachable at $frostd (forward it: ssh -N -L 2744:localhost:2744 $frostd_host)" >&2; exit 1; }
  echo "frostd reachable via tunnel"
fi

body='{}'
if [[ -n $slot ]]; then body="{\"slot\":$slot}"; fi
if ! reservation=$(printf '%s' "$body" |
    curl -qfsS --globoff --proto '=https' --max-time 10 --max-filesize 4096 --data-binary @- -H 'Content-Type: application/json' "$coordinator/api/members/pairing" |
    python3 -c '
import json, re, sys
try:
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        sys.exit(1)
    entry = json.loads(raw)
    slot, challenge = entry["slot"], entry["challenge"]
    if type(slot) is not int or not 1 <= slot <= 4294967295 or (sys.argv[1] and str(slot) != sys.argv[1]):
        sys.exit(1)
    if not re.fullmatch(r"[0-9a-f]{64}", challenge):
        sys.exit(1)
except (KeyError, TypeError, ValueError):
    sys.exit(1)
print(slot, challenge)
' "$slot"); then
  echo "could not reserve a member slot at $coordinator" >&2
  exit 1
fi
read -r slot claim <<<"$reservation"

echo "== joining $coordinator as slot $slot =="
NO_TUNNEL=1 MEMBER_BIN="$member_bin" FROSTD_URL="$frostd" LOKI_PAIRING_CLAIM="$claim" exec "$deploy/run-member.sh" "$coordinator" "$slot"
