#!/usr/bin/env bash
# Native end to end on one Mac: three LokiSigner app instances pair with a local coordinator,
# create a 2-of-3 vault, receive funds, and send a payment that members 1 and 2 approve in
# LokiSigner's own dialog. Where a person must act in an app the script prints ">> YOU:" and
# carries on by itself once it sees the result.
#
#   NETWORK=regtest bash core/scripts/native_e2e.sh /abs/new/root   # local THS v0.3.0 chain
#   NETWORK=testnet bash core/scripts/native_e2e.sh /abs/new/root   # testnet.zec.rocks
#   bash core/scripts/native_e2e.sh stop /abs/root                  # quit its apps and services
#
# Starts frostd, two nonce-witness relays and the coordinator (web/wallet) itself; the chain
# (THS for regtest, lightwalletd for testnet) must already be reachable.
# Env: APP (default core/signer-app/out/LokiSigner.app, built with build.sh when missing),
# LIGHTWALLETD_URL, RPC_URL and THS_URL (regtest node and faucet), WEB_PORT (3001),
# BASE_PORT (3600; members listen on +1..+3), AMOUNT_ZAT, RECIPIENT (default: the vault
# itself, so only the fee is spent), FUNDING_TIMEOUT, CONFIRM_TIMEOUT (seconds).
set -euo pipefail

poc="$(cd "$(dirname "$0")/.." && pwd -P)"
repo="$(cd "$core/.." && pwd -P)"
say() { printf '\n== %s\n' "$*"; }
act() { printf '\n>> YOU: %s\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }
killtree() { local c; for c in $(pgrep -P "$1"); do killtree "$c"; done; kill "$1" 2>/dev/null || true; }

if [[ ${1:-} == stop ]]; then
  root=${2:?usage: native_e2e.sh stop /abs/root}
  pkill -f -- "--data $root/m" || true
  if [[ -f $root/pids ]]; then while read -r p; do killtree "$p"; done <"$root/pids"; fi
  echo "stopped; member data kept in $root"
  exit 0
fi
[[ $# == 1 && $1 == /* && ! -e $1 ]] || { echo 'usage: native_e2e.sh /absolute/new/root | stop /abs/root' >&2; exit 2; }
root=$1

network=${NETWORK:-testnet}
case $network in
  regtest) lwd=${LIGHTWALLETD_URL:-http://127.0.0.1:9067}; amount=${AMOUNT_ZAT:-100000000}
    rpc=${RPC_URL:-http://127.0.0.1:18232}; ths=${THS_URL:-http://127.0.0.1:32805}
    confirm_timeout=${CONFIRM_TIMEOUT:-300} ;;
  testnet) lwd=${LIGHTWALLETD_URL:-https://testnet.zec.rocks:443}; amount=${AMOUNT_ZAT:-100000}
    confirm_timeout=${CONFIRM_TIMEOUT:-3600} ;;
  *) fail "NETWORK must be regtest or testnet" ;;
esac
funding_timeout=${FUNDING_TIMEOUT:-3600}
web_port=${WEB_PORT:-3001}
base_port=${BASE_PORT:-3600}
coord="http://127.0.0.1:$web_port"
frostd_url=http://127.0.0.1:2744
app=${APP:-$core/signer-app/out/LokiSigner.app}

say "preflight ($network)"
for tool in curl jq nc cargo npm openssl pbcopy pbpaste open; do
  command -v "$tool" >/dev/null || fail "$tool is required (see the runbook's prerequisites)"
done
command -v frostd >/dev/null || fail 'frostd is not on PATH: cargo install --git https://github.com/ZcashFoundation/frost-zcash-demo frostd --locked'
if [[ ! -d $app ]]; then
  ruby -e 'require "xcodeproj"' 2>/dev/null || fail "the xcodeproj gem is missing for $(command -v ruby) (Ruby $(ruby -e 'print RUBY_VERSION')).
  With macOS's system Ruby: /usr/bin/gem install --user-install xcodeproj --no-document
  Check: /usr/bin/ruby -e 'require \"xcodeproj\"' prints nothing and exits 0."
  say "building $app (signer-app/build.sh; its selftest asks for Touch ID)"
  bash "$core/signer-app/build.sh"
fi
[[ -x $app/Contents/MacOS/LokiSigner ]] || fail "no LokiSigner app at $app"
hostport=${lwd#*://}; hostport=${hostport%%/*}
nc -z -w 5 "${hostport%:*}" "${hostport##*:}" 2>/dev/null || fail "lightwalletd $lwd is not reachable"
if [[ $network == regtest ]]; then
  rpc_call() { curl -sf -m 30 -H 'Content-Type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "$rpc"; }
  branch=$(rpc_call getblockchaininfo | jq -r '.result.consensus.nextblock') || fail "no regtest node at $rpc; start THS v0.3.0 first (ths --name loki start --no-open)"
  [[ $branch == 37a5165b ]] || fail "the regtest node is on branch $branch, but LokiSigner signs regtest payments for NU6.3 (37a5165b). THS v0.4+ activates NU7; use THS v0.3.0."
  mine() { rpc_call generate "[$1]" >/dev/null || fail "mining $1 blocks failed"; }
fi
for port in 39301 39302 "$web_port" $((base_port+1)) $((base_port+2)) $((base_port+3)); do
  nc -z 127.0.0.1 "$port" 2>/dev/null && fail "port $port is in use; stop the previous run (native_e2e.sh stop <its root>)"
done
echo "app: $app"
echo "lightwalletd: $lwd"

mkdir -p "$root"; chmod 700 "$root"; : >"$root/pids"
bg() { local log=$1; shift; nohup "$@" >"$root/$log.log" 2>&1 & echo $! >>"$root/pids"; }
wait_for() { # wait_for <seconds> <what> <command...>
  local secs=$1 what=$2 n; shift 2
  for ((n=0; n<secs; n+=2)); do "$@" && return; sleep 2; done
  fail "$what (waited ${secs}s)"
}

say "services: frostd, two nonce-witness relays, coordinator"
if nc -z 127.0.0.1 2744 2>/dev/null; then echo "frostd: reusing the one on :2744"; else bg frostd frostd --no-tls-very-insecure -p 2744; fi
relay="$repo/communication/target/debug/loki-relay-server"
[[ -x $relay ]] || cargo build --manifest-path "$repo/communication/Cargo.toml" --locked --bin loki-relay-server
relay_pids=()
for n in 1 2; do
  head -c 32 /dev/urandom >"$root/relay-$n.secret"; chmod 600 "$root/relay-$n.secret"
  "$relay" init --root "$root/relay-$n" --listen "127.0.0.1:$((39300+n))" --provision-capability-file "$root/relay-$n.secret" \
    --total-bytes 268435456 --mailbox-bytes 67108864 --mailbox-count 1024 >/dev/null
  cp "$root/relay-$n.secret" "$root/relay-$n/provision.secret"
  bg "relay-$n" "$relay" serve --root "$root/relay-$n" --listen "127.0.0.1:$((39300+n))"
  relay_pids+=("$!")
done
listening() { nc -z 127.0.0.1 "$1" 2>/dev/null; }
wait_for 30 'witness relays did not start' listening 39302
witnesses="$root/witnesses.json"
echo "provisioning nonce witnesses (the first run compiles the tool for a few minutes)"
( cd "$core" && cargo run -q --features relay-communication --example provision_nonce_witnesses -- \
    --relay-root "$root/relay-1" --relay-root "$root/relay-2" --out "$witnesses" --development-http ) >"$root/provision.log" 2>&1 \
  || fail "provisioning the nonce witnesses failed; see $root/provision.log"
echo "nonce witnesses: $witnesses"
kill "${relay_pids[@]}"
for pid in "${relay_pids[@]}"; do wait "$pid"; done
awk -v a="${relay_pids[0]}" -v b="${relay_pids[1]}" '$0 != a && $0 != b' "$root/pids" >"$root/pids.next"
mv "$root/pids.next" "$root/pids"
[[ -d $repo/web/wallet/node_modules ]] || ( cd "$repo/web/wallet" && { npm ci || npm ci --legacy-peer-deps; } )
for n in 1 2 3; do
  onboarding[n]=$(openssl rand -hex 32)
  digest=$(printf '%s' "${onboarding[n]}" | openssl dgst -sha256 -r)
  ( cd "$repo/web/wallet" && LOKI_REGISTRY="$root/registry.json" node scripts/grants.ts register "${digest%% *}" --slot "$n" )
done
( cd "$repo/web/wallet" && LOKI_REGISTRY="$root/registry.json" LOKI_DEV_FAUCET=1 \
    exec nohup npx next dev --hostname 127.0.0.1 --port "$web_port" ) >"$root/coordinator.log" 2>&1 &
echo $! >>"$root/pids"
wait_for 180 "coordinator did not start; see $root/coordinator.log" curl -sf -m 5 "$coord/api/members" -o /dev/null
echo "coordinator: $coord (roster $root/registry.json)"

api() { # api <member> GET|POST <path> [json]
  local n=$1 method=$2 path=$3 body=${4:-}
  local args=(--fail-with-body -sS -m 600 -H "X-Loki-Token: $(cat "$root/m$n.token")")
  [[ $method == POST ]] && args+=(-X POST -H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}" "http://127.0.0.1:$((base_port+n))$path"
}
clip_is_link() { [[ $(pbpaste) == "http://127.0.0.1:$1/#"* ]]; }
registered() { curl -sf -m 5 "$coord/api/members" | jq -e --argjson s "$1" 'any(.slots[]; .slot == $s)' >/dev/null; }

for n in 1 2 3; do
  port=$((base_port+n))
  say "pair member $n (slot $n, local API :$port)"
  link=$(printf '{"slot":%d,"onboarding_grant":"%s"}' "$n" "${onboarding[n]}" |
    curl -qsf -m 10 -H 'Content-Type: application/json' --data-binary @- "$coord/api/members/pairing" | jq -er .url) \
    || fail "the coordinator issued no pairing link for slot $n"
  unset 'onboarding[n]'
  printf '' | pbcopy
  printf '%s\n' "$link" | "$app/Contents/MacOS/LokiSigner" native --pairing-stdin --development-http --data "$root/m$n" --port "$port" \
    --network "$network" --lightwalletd-url "$lwd" --frostd-url "$frostd_url" \
    --nonce-witnesses "$witnesses" --allow-loopback-peers >"$root/m$n.log" 2>&1 &
  echo $! >>"$root/pids"
  unset link
  act "a LokiSigner window asks \"Pair this device with slot $n?\" (coordinator $coord). Within 2 minutes:
   1. type a new passphrase for member $n and click Pair            [Touch ID may be asked]
   2. write down the 24 recovery words, click \"I saved these words\"
   3. click \"Copy private link\" (the script reads it from the clipboard)"
  wait_for 300 "no session link for member $n on the clipboard; read the LokiSigner alert" clip_is_link "$port"
  ( umask 077; pbpaste | sed 's|.*#||' >"$root/m$n.token" ); printf '' | pbcopy
  wait_for 330 "member $n did not register with the coordinator" registered "$n"
  echo "member $n paired; roster: $(curl -sf "$coord/api/members" | jq -c '[.slots[].slot]')"
done

say "create the 2-of-3 vault"
created=$(api 1 POST /api/create '{"name":"Native end to end","members":3,"threshold":2}') || fail "create: $created"
vault=$(jq -er .vault <<<"$created") || fail "create: $created"
echo "$vault" >"$root/vault"
for n in 2 3; do
  code=$(jq -er --argjson s "$n" '.invites[] | select(.slot == $s) | .code' <<<"$created")
  api "$n" POST /api/join "$(jq -nc --arg i "$code" '{invite:$i}')" | jq -e --arg v "$vault" '.vault == $v' >/dev/null || fail "member $n could not join"
done
phase() { api "$1" GET "/api/status?vault=$vault" | jq -r '.phase'; }
all_phase() { local n; for n in 1 2 3; do [[ $(phase "$n") == "$1" ]] || return 1; done; }
wait_for 120 'the roster did not converge' all_phase compare_roster
fingerprint=$(api 1 GET "/api/status?vault=$vault" | jq -er .fingerprint)
echo "roster fingerprint: $fingerprint"
for n in 1 2 3; do
  [[ $(api "$n" GET "/api/status?vault=$vault" | jq -r .fingerprint) == "$fingerprint" ]] || fail "member $n sees another roster"
  api "$n" POST /api/agree "$(jq -nc --arg v "$vault" --arg f "$fingerprint" '{vault:$v,fingerprint:$f}')" | jq -e '.ok' >/dev/null || fail "member $n could not agree"
done
act "the three apps now create their keys.                         [Touch ID may be asked in each]"
dkg_done() {
  local n s
  for n in 1 2 3; do
    s=$(api "$n" GET "/api/status?vault=$vault")
    [[ $(jq -r .phase <<<"$s") != setup_interrupted ]] || fail "key creation stopped at member $n: $(jq -r .error <<<"$s")"
    [[ $(jq -r .phase <<<"$s") == active ]] || return 1
  done
}
wait_for 600 'the vault did not become active' dkg_done
for n in 1 2; do
  mailbox=$(jq -er --argjson i "$((n-1))" '.[$i].mailbox | map((. / 16 | floor), (. % 16)) |
    map(. as $nibble | "0123456789abcdef"[$nibble:$nibble + 1]) | join("")' "$witnesses")
  for i in 1 2 3; do
    # These three local apps just confirmed their roster, using these same profile keys.
    key=$(api "$i" GET /api/registration | jq -er --argjson slot "$i" 'select(.slot == $slot) | .signing_pubkey')
    "$relay" enroll-nonce --root "$root/relay-$n" --mailbox "$mailbox" --vault "$vault" \
      --slot "$i" --signing-key "$key" --quota-bytes 1048576 || fail "witness $n enrollment for member $i"
  done
  bg "relay-$n" "$relay" serve --root "$root/relay-$n" --listen "127.0.0.1:$((39300+n))"
  wait_for 30 "witness $n did not restart after enrollment" listening "$((39300+n))"
done
address=$(api 1 GET "/api/address?vault=$vault" | jq -er .address)
for n in 2 3; do [[ $(api "$n" GET "/api/address?vault=$vault" | jq -r .address) == "$address" ]] || fail "member $n shows another address"; done
echo "vault $vault is active"
echo "address: $address"

say "fund the vault"
balance() { api 1 POST /api/balance "$(jq -nc --arg v "$vault" '{vault:$v}')" | jq -r '.balance_zat // 0'; }
if [[ $network == regtest ]]; then
  key="native-e2e-$(date +%s)"
  paid=$(curl -sf -m 120 -X POST "$ths/api/v1/faucet/address" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg a "$address" --arg k "$key" '{address:$a,amount_zatoshi:500000000,idempotency_key:$k}')") \
    || fail "the THS faucet at $ths refused"
  # THS v0.3.0 answers once the payment is mined (block_hash set); later versions answer early.
  faucet_mined() {
    jq -e '.block_hash != null or .status == "confirmed"' <<<"$paid" >/dev/null && return
    paid=$(curl -sf -m 10 "$ths/api/v1/faucet/address?idempotency_key=$key") || true
    return 1
  }
  wait_for 300 'the faucet payment was not mined' faucet_mined
  mine 10
  echo "faucet sent 5 ZEC and 10 blocks were mined"
else
  act "send a single Ironwood note of at least $((amount + 200000)) zat (testnet ZEC) to
   $address
   from a wallet that supports testnet NU7 Ironwood. Blocks come about every 75 seconds;
   the script checks the vault balance every 30 seconds for up to ${funding_timeout}s."
fi
funded() { local b; b=$(balance); (( ${b:-0} > amount + 100000 )); }
for ((t=0; ; t+=30)); do funded && break; (( t < funding_timeout )) || fail 'no funds scanned'; sleep 30; done
echo "balance: $(balance) zat"

say "propose a payment of $amount zat"
recipient=${RECIPIENT:-$address}
for ((t=0; ; t+=30)); do
  draft=$(api 1 POST /api/payment-draft "$(jq -nc --arg v "$vault" --arg r "$recipient" --arg a "$amount" \
    '{vault:$v,recipient:$r,amount_zat:$a,memo:"native end to end"}')") && break
  (( t < funding_timeout )) || fail "draft: $draft"
  echo "no spendable note yet: $draft"
  [[ $network == regtest ]] && mine 1
  sleep 30
done
attempt=$(jq -er .attempt <<<"$draft")
echo "attempt $attempt (fee $(jq -r .fee_zat <<<"$draft") zat)"
pair() { jq -nc --arg v "$vault" --arg a "$attempt" '{vault:$v,attempt:$a}'; }
api 1 POST /api/payment-publish "$(pair)" | jq -e '.phase == "signing"' >/dev/null || fail 'publish'
pending() { api "$1" GET "/api/pending?vault=$vault" | jq -e --arg a "$attempt" 'any(.pending[]; .attempt == $a)' >/dev/null; }
wait_for 120 'member 2 did not receive the request' pending 2
for n in 2 1; do
  review=$(api "$n" POST /api/payment-review "$(pair)") || fail "review $n: $review"
  jq -e --arg r "$recipient" --arg a "$amount" '.recipient == $r and .amount_zat == $a' <<<"$review" >/dev/null || fail "member $n reviewed other values: $review"
  token=$(jq -er .review_token <<<"$review")
  api "$n" POST /api/payment-approve "$(jq -nc --arg v "$vault" --arg a "$attempt" --arg t "$token" '{vault:$v,attempt:$a,review_token:$t}')" \
    | jq -e '.phase == "signing"' >/dev/null || fail "member $n could not approve"
  echo "member $n approved through its local API (the wallet step)"
done
act "members 1 and 2 each show \"Approve this payment?\". Check recipient, amount ($amount zat),
   fee and network against what you intended, then click \"Approve and sign\" in both.
   [Touch ID may be asked before each dialog.] Refuse, closing the dialog or 2 minutes
   without an answer refuses, and the payment fails."
payment() { api 1 GET "/api/payments?vault=$vault" | jq -c --arg a "$attempt" '.payments[] | select(.attempt == $a)'; }
sent() {
  local p; p=$(payment)
  [[ $(jq -r .phase <<<"$p") != failed ]] || fail "payment failed: $p"
  jq -e '.phase == "broadcast" or .phase == "confirmed"' <<<"$p" >/dev/null
}
wait_for 600 'the payment was not sent; see the members'"'"' alerts and GET /api/payments' sent
txid=$(payment | jq -er .txid)
echo "broadcast txid: $txid (signers $(payment | jq -c .signers))"

say "wait for confirmation"
verify() { api 1 POST /api/payment-verify "$(jq -nc --arg v "$vault" --arg a "$attempt" --arg t "$txid" '{vault:$v,attempt:$a,txid:$t}')"; }
for ((t=0; ; t+=15)); do
  [[ $network == regtest ]] && mine 1
  out=$(verify) && [[ $(jq -r .phase <<<"$out") == confirmed ]] && break
  (( t < confirm_timeout )) || fail "not confirmed: $out"
  sleep 15
done
echo "confirmed at height $(jq -r .mined_height <<<"$out")"
echo "balance after: $(balance) zat"

say "PASS"
echo "roster: $(curl -sf "$coord/api/members" | jq -c '[.slots[].slot]')"
echo "vault: $vault"
echo "address: $address"
echo "txid: $txid"
echo "member data, tokens and logs: $root"
echo "the apps and services keep running; stop them with: bash core/scripts/native_e2e.sh stop $root"
