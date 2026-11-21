#!/usr/bin/env bash
# Single-host self-custody bringup for the v2 (frostd) stack on main.
#
# Stands up the public-roster web coordinator plus N member apps that self-register,
# then drives a t-of-n DKG ceremony to `active` and prints the shared testnet address.
# Each member holds its own share; the coordinator only ever sees public roster data.
#
# This is NOT the owned-relay operator toolkit (bringup.sh) — main's ceremony speaks
# frostd, not the owned relays. Point FROSTD_URL at a reachable frostd. frostd must be
# https off loopback (transport::require_tls_off_loopback); for a remote plaintext dev
# relay, forward it to loopback first, e.g. `ssh -N -L 2744:localhost:2744 host` and use
# the default http://127.0.0.1:2744.
#
# Env:
#   FROSTD_URL   frostd base url           (default http://127.0.0.1:2744)
#   LWD_URL      lightwalletd base url     (default https://testnet.zec.rocks:443)
#   NETWORK      vault network             (default testnet)
#   MEMBERS      member count n            (default 3)
#   THRESHOLD    approvals t               (default 2)
#   WEB_PORT     coordinator port          (default 3001)
#   BASE_PORT    first member port         (default 3601)
set -euo pipefail

if [[ $# != 1 || $1 != /* ]]; then
  echo 'usage: selfcustody-testnet.sh /absolute/new/root' >&2
  exit 2
fi
root=$1
while [[ $root == */ && $root != / ]]; do root=${root%/}; done
deploy=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$deploy/../.." && pwd -P)
source "$deploy/member-launch.sh"
core="$repo/core"
web="$repo/web/wallet"

frostd=${FROSTD_URL:-http://127.0.0.1:2744}
lwd=${LWD_URL:-https://testnet.zec.rocks:443}
network=${NETWORK:-testnet}
members=${MEMBERS:-3}
threshold=${THRESHOLD:-2}
web_port=${WEB_PORT:-3001}
base_port=${BASE_PORT:-3601}
coordinator="http://localhost:$web_port"
[[ $members =~ ^([3-9]|1[0-6])$ ]] || launch_error "MEMBERS must be in 3..16"

mkdir -p -- "$(dirname -- "$root")"
mkdir -- "$root" || launch_error "the stack requires a new root: $root"
lock_launch "$root"
private_output "$root/pids"
trap cleanup_launch EXIT
trap 'exit 1' INT TERM

echo "== build =="
( cd "$core" && cargo build --release --locked --features relay-communication --bin loki_member_app )
member_bin="$core/target/release/loki_member_app"
( cd "$web" && npm run build >/dev/null )

echo "== coordinator on :$web_port =="
private_output "$root/coordinator.log"
grants='{'
for n in $(seq 1 "$members"); do
  grant=$(openssl rand -hex 32)
  onboarding[n]=$grant
  digest=$(printf '%s' "$grant" | openssl dgst -sha256 -r)
  grants+="\"${digest%% *}\":$n,"
done
grants="${grants%,}}"
( cd "$web" && export HOSTNAME=localhost PORT="$web_port" PUBLIC_PORT="$web_port" LOKI_REGISTRY="$root/registry.json" \
  LOKI_ONBOARDING_GRANTS="$grants" \
  && exec node server.js >"$root/coordinator.log" 2>&1 ) &
echo $! >> "$root/pids"
for _ in {1..50}; do curl -sf --max-time 1 "$coordinator/api/members" >/dev/null && break; sleep 0.2; done
curl -sf --max-time 2 "$coordinator/api/members" >/dev/null || { echo "coordinator did not start; see $root/coordinator.log" >&2; exit 1; }

echo "== $members members self-registering =="
unset tokens
declare -a tokens ports
for n in $(seq 1 "$members"); do
  port=$((base_port + n - 1))
  ports[n]=$port
  pass="$root/member-$n.pass"
  ensure_passphrase "$pass"
  LOKI_ONBOARDING_GRANT="${onboarding[n]}" start_member "$port" "$root/member-$n.log" "$root/pids" \
    "$member_bin" --data "$root/member-$n" --port "$port" --network "$network" \
    --lightwalletd-url "$lwd" --frostd-url "$frostd" \
    --allow-loopback-peers --secure-element software --development-http \
    --coordinator-url "$coordinator" --local-passphrase-file "$pass" \
    --registration-slot "$n" --profile-name "Member $n"
  tokens[n]=${pairing_link##*#}
  unset pairing_link
done
unset onboarding grant

# Readiness means the local API is ready, not that background registration has finished.
registered=0
for _ in {1..75}; do
  registered=$(curl -sf --max-time 1 "$coordinator/api/members" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["slots"]))' 2>/dev/null) || registered=0
  [[ $registered == "$members" ]] && break
  sleep 0.4
done
[[ $registered == "$members" ]] || { echo "roster has $registered of $members members" >&2; exit 1; }
echo "roster: $registered/$members members self-registered"

api() { # api <member> <method> <path> [json-body]
  local member=$1 method=$2 path=$3 body=${4:-}
  local args=(-X "$method")
  if [[ -n $body ]]; then args+=(-H 'content-type: application/json' -d "$body"); fi
  # curl reads the bearer from stdin, never from its process arguments.
  printf 'x-loki-token: %s\n' "${tokens[member]}" | curl -q -s --noproxy '*' --max-time "$([[ $path == /api/agree ]] && echo 130 || echo 30)" \
    -H @- "${args[@]}" "http://127.0.0.1:${ports[member]}$path"
}
jq_py() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

echo "== ceremony: $threshold-of-$members DKG =="
create=$(api 1 POST /api/create "{\"name\":\"TestnetVault\",\"members\":$members,\"threshold\":$threshold}")
vault=$(echo "$create" | jq_py 'd["vault"]')
[[ ${#vault} == 64 ]] || { echo "create failed: $create" >&2; exit 1; }
echo "vault: $vault"
for n in $(seq 2 "$members"); do
  code=$(echo "$create" | python3 -c "import sys,json;print([i for i in json.load(sys.stdin)['invites'] if i['slot']==$n][0]['code'])")
  join=$(api "$n" POST /api/join "{\"invite\":\"$code\"}")
  echo "$join" | grep -q "$vault" || { echo "member $n join failed: $join" >&2; exit 1; }
done

for _ in {1..20}; do
  status=$(api 1 GET "/api/status?vault=$vault")
  fp=$(echo "$status" | jq_py 'd.get("fingerprint") or ""')
  roster_code=$(echo "$status" | jq_py 'd.get("roster_code") or ""')
  [[ -n $fp && -n $roster_code ]] && break; sleep 2
done
[[ -n $fp && -n $roster_code ]] || { echo "roster never converged" >&2; exit 1; }
echo "roster fingerprint: $fp"
for n in $(seq 1 "$members"); do
  ok=$(api "$n" POST /api/agree "{\"vault\":\"$vault\",\"fingerprint\":\"$fp\",\"roster_code\":\"$roster_code\"}" | jq_py 'd.get("ok")')
  [[ $ok == True ]] || { echo "member $n agree failed" >&2; exit 1; }
done

phase=""
for _ in {1..30}; do
  status=$(api 1 GET "/api/status?vault=$vault")
  phase=$(echo "$status" | jq_py 'd.get("phase")')
  echo "  phase: $phase"
  [[ $phase == active ]] && break
  [[ $phase == setup_interrupted ]] && { echo "DKG interrupted: $(echo "$status" | jq_py 'd.get("error")')" >&2; exit 1; }
  sleep 4
done
[[ $phase == active ]] || { echo "ceremony did not reach active" >&2; exit 1; }

address=$(api 1 GET "/api/address?vault=$vault" | jq_py 'd["address"]')
unset tokens
echo "=============================================================="
echo "vault $vault is ACTIVE ($threshold-of-$members, $network)"
echo "address: $address"
echo "coordinator: $coordinator   members: ${ports[*]}"
echo "=============================================================="
trap - EXIT INT TERM
printf 'Stack still running; stop with: kill $(cat -- %q)\n' "$root/pids"
