#!/usr/bin/env bash
# One command to join a Loki vault against a public coordinator.
#
#   join-loki.sh <coordinator-url> [slot]
#
# Builds the member binary if missing, ensures frostd is reachable on loopback,
# reserves a slot at the coordinator, then launches a member
# via run-member.sh and prints the local pairing link to paste into the
# coordinator web UI. Peer-over-frostd is on main, so members need zero inbound
# (NO_TUNNEL=1) — no per-member tunnel.
#
# Env:
#   LOKI_ONBOARDING_GRANT  one-use grant from the coordinator operator (required)
#   FROSTD_URL   frostd loopback url     (default http://127.0.0.1:2744)
#   FROSTD_HOST  ssh host for the tunnel (default omarchy)
# Plus anything run-member.sh honours (DATA, PORT, LWD_URL, NETWORK, MEMBER_BIN).
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || $1 != https://* ]]; then
  echo 'usage: join-loki.sh <https-coordinator-url> [slot]' >&2
  exit 2
fi
coordinator=${1%/}
slot=${2:-}
[[ -z $slot || $slot =~ ^([1-9]|1[0-6])$ ]] || { echo "slot must be in 1..16" >&2; exit 2; }
[[ ${LOKI_ONBOARDING_GRANT:-} =~ ^[0-9a-f]{64}$ ]] || { echo "an onboarding grant from the coordinator operator is required" >&2; exit 2; }
grant=$LOKI_ONBOARDING_GRANT
unset LOKI_ONBOARDING_GRANT

deploy=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$deploy/../.." && pwd -P)
member_bin=${MEMBER_BIN:-$repo/core/target/release/loki_member_app}
frostd=${FROSTD_URL:-http://127.0.0.1:2744}
frostd_host=${FROSTD_HOST:-omarchy}

# 1. Build the member binary on first run.
if [[ ! -x $member_bin && -z ${MEMBER_BIN:-} ]]; then
  echo "== building loki_member_app (first run, a few minutes) =="
  ( cd "$repo/core" && cargo build --release --features relay-communication --bin loki_member_app )
fi
[[ -x $member_bin ]] || { echo "member binary not found: $member_bin" >&2; exit 1; }

# 2. frostd must be reachable on loopback (https off loopback is enforced).
reachable() { curl -s -o /dev/null --max-time 3 "$frostd/challenge"; }
if reachable; then
  echo "frostd reachable at $frostd"
else
  echo "opening ssh tunnel to $frostd_host"
  ssh -f -N -L 2744:localhost:2744 "$frostd_host" || true
  reachable || { echo "frostd unreachable at $frostd (forward it: ssh -N -L 2744:localhost:2744 $frostd_host)" >&2; exit 1; }
  echo "frostd reachable via tunnel"
fi

# 3. Let the coordinator choose and reserve a slot, or reserve the grant's explicit slot.
requested_slot=
if [[ -n $slot ]]; then requested_slot=",\"slot\":$slot"; fi
if ! reservation=$(printf '{"onboarding_grant":"%s"%s}' "$grant" "$requested_slot" |
    curl -qfsS --globoff --proto '=https' --max-time 10 --max-filesize 4096 --data-binary @- -H 'Content-Type: application/json' "$coordinator/api/members/pairing" |
    python3 -c '
import json, re, sys
try:
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        sys.exit(1)
    entry = json.loads(raw)
    slot, challenge = entry["slot"], entry["challenge"]
    if type(slot) is not int or not 1 <= slot <= 16 or (sys.argv[1] and str(slot) != sys.argv[1]):
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

# 4. Launch via run-member.sh (no per-member tunnel; peer-over-frostd is on main).
echo "== joining $coordinator as slot $slot =="
NO_TUNNEL=1 MEMBER_BIN="$member_bin" FROSTD_URL="$frostd" LOKI_PAIRING_CLAIM="$claim" exec "$deploy/run-member.sh" "$coordinator" "$slot"
