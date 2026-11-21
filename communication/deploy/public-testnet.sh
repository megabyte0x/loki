#!/usr/bin/env bash
# Public HTTPS bringup for the self-custody coordinator (frostd stack on main).
#
# Stands up ONLY the shared public-roster web coordinator, over a free cloudflared
# quick tunnel (https://*.trycloudflare.com), and ensures frostd is reachable on
# loopback. It does NOT launch members — testers run `run-member.sh <coordinator-url>
# <slot>` on their own machines. This is the "nobody hosts anything but the one shared
# coordinator" path; selfcustody-testnet.sh is the all-on-one-host loopback TEST.
#
# Set PUBLIC_ORIGIN to the tunnel URL so Next verifies self-registration against the
# public HTTPS origin, not the coordinator's private loopback listener.
#
# Env:
#   FROSTD_URL   frostd loopback url       (default http://127.0.0.1:2744)
#   FROSTD_HOST  ssh host for the tunnel   (default omarchy)
#   WEB_PORT     coordinator port          (default 3011)
# frostd (2744) is shared and supports concurrent sessions; the loopback TEST stack's
# own ports are left alone by the 3011 default.
set -euo pipefail

if [[ $# != 1 || $1 != /* || -e $1 ]]; then
  echo 'usage: public-testnet.sh /absolute/new/root' >&2
  exit 2
fi
root=$1
deploy=$(cd "$(dirname "$0")" && pwd -P)
workspace=$(cd "$deploy/.." && pwd -P)
repo=$(cd "$workspace/.." && pwd -P)
web="$repo/web/wallet"

frostd=${FROSTD_URL:-http://127.0.0.1:2744}
frostd_host=${FROSTD_HOST:-omarchy}
web_port=${WEB_PORT:-3011}
cloudflared=/opt/homebrew/bin/cloudflared

mkdir -p "$root"
: > "$root/pids"

cleanup() { while read -r pid; do kill -INT "$pid" 2>/dev/null || true; done < "$root/pids"; }
trap cleanup EXIT
trap 'exit 1' INT TERM

# frostd answers /challenge on POST (GET is 405) — any HTTP reply means reachable.
reachable() { curl -s -o /dev/null --max-time 3 "$frostd/challenge"; }

echo "== frostd =="
if reachable; then
  echo "frostd reachable at $frostd"
else
  echo "opening ssh tunnel to $frostd_host"
  ssh -f -N -L 2744:localhost:2744 "$frostd_host" || true
  if ! reachable; then
    echo "starting frostd on $frostd_host"
    ssh "$frostd_host" 'systemd-run --user --unit=frostd --collect /home/abix/frost-tools/target/debug/frostd -n -p 2744' || true
    ssh -f -N -L 2744:localhost:2744 "$frostd_host" || true
    for _ in {1..25}; do reachable && break; sleep 0.4; done
  fi
  reachable || { echo "frostd still unreachable" >&2; exit 1; }
  echo "frostd reachable via tunnel"
fi

echo "== cloudflared quick tunnel -> 127.0.0.1:$web_port =="
"$cloudflared" tunnel --url "http://127.0.0.1:$web_port" >"$root/cloudflared.log" 2>&1 &
echo $! >> "$root/pids"
coordinator=""
for _ in {1..80}; do
  coordinator=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$root/cloudflared.log" | head -1 || true)
  [[ -n $coordinator ]] && break; sleep 0.5
done
[[ -n $coordinator ]] || { echo "tunnel never came up; see $root/cloudflared.log" >&2; exit 1; }
echo "coordinator public URL: $coordinator"

echo "== coordinator (node server.js) PUBLIC_ORIGIN=$coordinator =="
( cd "$web" && export PUBLIC_ORIGIN="$coordinator" PORT="$web_port" LOKI_REGISTRY="$root/registry.json" \
  && exec node server.js >"$root/coordinator.log" 2>&1 ) &
echo $! >> "$root/pids"
for _ in {1..75}; do curl -sf --max-time 1 "http://127.0.0.1:$web_port/api/members" >/dev/null && break; sleep 0.2; done
curl -sf --max-time 2 "http://127.0.0.1:$web_port/api/members" >/dev/null \
  || { echo "coordinator did not start; see $root/coordinator.log" >&2; exit 1; }
# Confirm it is actually served over the tunnel too (trycloudflare edge can take ~30-60s).
for _ in {1..120}; do curl -sf --max-time 5 "$coordinator/api/members" >/dev/null && break; sleep 1; done
curl -sf --max-time 5 "$coordinator/api/members" >/dev/null \
  || { echo "coordinator not reachable over the tunnel yet; see $root/cloudflared.log" >&2; exit 1; }

echo "=============================================================="
echo "coordinator LIVE:  $coordinator"
echo "join URL (open in a browser): $coordinator"
echo "run a member:  communication/deploy/run-member.sh $coordinator <slot>"
echo "roster:        $coordinator/api/members"
echo "=============================================================="
trap - EXIT INT TERM
echo "stack still running; stop with: kill \$(cat $root/pids)"
