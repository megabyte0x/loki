#!/usr/bin/env bash
# Testnet end to end: a member moves to a new device with its recovery words and exported
# backup, re-registers with the coordinator to its old slot with a new device key, and signs a
# payment that is broadcast and confirmed. Also shows that a member started against an
# unreachable coordinator keeps serving its local API.
#
#   1. Three members register with the coordinator (slots 1..3) and create a 2-of-3 vault.
#      Their output goes to log files, so none of them mints recovery words at startup.
#      Members 1 and 2 set up recovery before the vault; member 3 only after it is active,
#      and still ends up with a recovery backup.
#   2. Member 3 exports its backup, is stopped, and its data directory is deleted.
#   3. A fresh profile on a new data directory, started WITHOUT --coordinator-url, restores
#      from the words and the exported file, then restarts with --coordinator-url and
#      re-registers to slot 3 under the same identity with a new device key.
#   4. Member 1 proposes a payment; the restored member 3 approves and signs it; it is
#      broadcast and confirms.
#   5. A fourth member started against an unreachable coordinator serves its local API.
#
# Run in a private terminal: you will confirm recovery for three disposable members and
# re-enter member 3's original words during the restore. Do not record the terminal session.
# Needs a running frostd and the web app as the coordinator. Configure three grants
# pinned to slots 1..3 (see web/wallet/README.md), and set LOKI_ONBOARDING_GRANT_1,
# LOKI_ONBOARDING_GRANT_2, and LOKI_ONBOARDING_GRANT_3 to the respective bearers.
set -euo pipefail

cd "$(dirname "$0")/.."
: "${AMOUNT_ZAT:?set AMOUNT_ZAT to the amount in zat}"
: "${LIGHTWALLETD_URL:?set LIGHTWALLETD_URL to a Testnet lightwalletd endpoint}"
: "${LOKI_REGISTRY:?set LOKI_REGISTRY to the roster file the coordinator web app uses}"

bin="${LOKI_MEMBER_APP_BIN:-$PWD/target/debug/loki_member_app}"
frostd="${FROSTD_URL:-http://127.0.0.1:2744}"
coordinator="${COORDINATOR_URL:-http://localhost:3001}"
base_port="${BASE_PORT:-3400}"
funding_timeout="${FUNDING_TIMEOUT:-3600}"
confirm_timeout="${CONFIRM_TIMEOUT:-3600}"
tmp="${TMP_DIR:-$(mktemp -d)}"
mkdir -p "$tmp"
declare -A pid dir

cleanup() {
  for p in "${pid[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  echo "member data preserved: $tmp"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $1" >&2
  for i in 1 2 3 4; do tail -20 "$tmp/$i.log" 2>/dev/null || true; done
  exit 1
}
command -v jq >/dev/null || fail 'jq is required'
[[ -x "$bin" ]] || fail "missing $bin; build loki_member_app first"
curl -sf -m 10 "$coordinator/api/members" >/dev/null || fail "coordinator not reachable at $coordinator"

api_raw() {
  local i="$1" method="$2" path="$3" body="${4:-}" token
  token="$(cat "$tmp/$i.token")"
  if [[ "$method" == POST ]]; then
    curl -sS -m 600 -X POST "http://127.0.0.1:$((base_port+i))$path" \
      -H "X-Loki-Token: $token" -H 'Content-Type: application/json' -d "$body" -w '\n%{http_code}'
  else
    curl -sS -m 600 "http://127.0.0.1:$((base_port+i))$path" -H "X-Loki-Token: $token" -w '\n%{http_code}'
  fi
}
# Body of a 2xx reply; fails the call otherwise.
api() {
  local out code
  out="$(api_raw "$@")"
  code="${out##*$'\n'}"
  out="${out%$'\n'*}"
  echo "$out"
  [[ "$code" == 2* ]]
}
passphrase() { printf 'testnet restore member %s' "$1"; }

# start <slot> <data dir> [extra args...]: start a member on BASE_PORT+slot and save its token.
start() {
  local i="$1" data="$2" token=''
  shift 2
  : >"$tmp/$i.log"
  "$bin" --data "$data" --port "$((base_port+i))" --network testnet \
    --lightwalletd-url "$LIGHTWALLETD_URL" --frostd-url "$frostd" \
    --peer "1=http://127.0.0.1:$((base_port+1))" \
    --peer "2=http://127.0.0.1:$((base_port+2))" \
    --peer "3=http://127.0.0.1:$((base_port+3))" "$@" >>"$tmp/$i.log" 2>&1 &
  pid[$i]=$!
  dir[$i]="$data"
  for _ in {1..300}; do
    token="$(grep -oE "http://127.0.0.1:$((base_port+i))/#[A-Za-z0-9_-]+" "$tmp/$i.log" | tail -1 | sed 's|.*/#||' || true)"
    [[ -n "$token" ]] && break
    kill -0 "${pid[$i]}" 2>/dev/null || fail "member $i exited at startup"
    sleep 0.1
  done
  [[ -n "$token" ]] || fail "member $i did not start"
  printf '%s' "$token" >"$tmp/$i.token"
}
stop() { kill "${pid[$1]}"; wait "${pid[$1]}" 2>/dev/null || true; unset "pid[$1]"; }
# with_coordinator <slot> <data dir>: start registering with the coordinator to that slot.
with_coordinator() {
  local i="$1" data="$2" pass="$tmp/$1.pass"
  [[ -f "$pass" ]] || { passphrase "$i" >"$pass"; chmod 600 "$pass"; }
  start "$i" "$data" --coordinator-url "$coordinator" --development-http \
    --local-passphrase-file "$pass" --registration-slot "$i" --profile-name "Member $i"
}
registered() { api "$1" GET /api/registration | jq -e --argjson slot "$1" '.slot == $slot' >/dev/null; }
wait_for() {
  local what="$1" tries="$2"
  shift 2
  for ((n=0; n<tries; n++)); do "$@" && return; sleep 1; done
  fail "$what"
}
roster_entry() { curl -sf -m 10 "$coordinator/api/members" | jq -c --argjson slot "$1" '.slots[] | select(.slot == $slot)'; }
device_of() { jq -r --argjson slot "$1" '.devices[] | select(.slot == $slot) | .device_pubkey' "$LOKI_REGISTRY"; }

echo "== three members register with $coordinator and create a 2-of-3 vault"
for i in 1 2 3; do
  grant_var="LOKI_ONBOARDING_GRANT_$i"
  onboarding[i]=${!grant_var:?set $grant_var}
  unset "$grant_var"
done
for i in 1 2 3; do LOKI_ONBOARDING_GRANT="${onboarding[i]}" with_coordinator "$i" "$tmp/$i"; done
unset onboarding
for i in 1 2 3; do
  wait_for "member $i registers to slot $i" 60 registered "$i"
  grep -q 'recovery words not set up' "$tmp/$i.log" || fail "member $i did not report the skipped recovery words"
  [[ ! -e "$tmp/$i/recovery.pub" ]] || fail "member $i minted recovery words into a log"
done
echo "registered slots 1..3; no recovery words were minted into the member logs"
setup_recovery() {
  local i="$1" data="${dir[$1]}"
  stop "$i"
  echo "Set up recovery for disposable member $i (profile passphrase: $(passphrase "$i"))"
  "$bin" recovery-setup --data "$data" || fail "local recovery setup $i"
  with_coordinator "$i" "$data"
  wait_for "member $i re-registers" 60 registered "$i"
}
for i in 1 2; do setup_recovery "$i"; done
created="$(api 1 POST /api/create '{"name":"Testnet restore vault","members":3,"threshold":2}')" || fail "create: $created"
vault="$(jq -er '.vault' <<<"$created")" || fail vault
for i in 2 3; do
  code="$(jq -er --argjson slot "$i" '.invites[] | select(.slot == $slot) | .code' <<<"$created")" || fail "invite $i"
  api "$i" POST /api/join "$(jq -nc --arg invite "$code" '{invite:$invite}')" | jq -e --arg vault "$vault" '.vault == $vault' >/dev/null || fail "join $i"
done
phase_is() { [[ "$(api "$1" GET "/api/status?vault=$vault" | jq -r '.phase')" == "$2" ]]; }
for i in 1 2 3; do wait_for "roster $i" 30 phase_is "$i" compare_roster; done
for i in 1 2 3; do
  fingerprint="$(api "$i" GET "/api/status?vault=$vault" | jq -er '.fingerprint')" || fail "fingerprint $i"
  roster_code="$(api "$i" GET "/api/status?vault=$vault" | jq -er '.roster_code')" || fail "roster code $i"
  api "$i" POST /api/agree "$(jq -nc --arg vault "$vault" --arg fingerprint "$fingerprint" --arg roster_code "$roster_code" '{vault:$vault,fingerprint:$fingerprint,roster_code:$roster_code}')" | jq -e '.ok == true' >/dev/null || fail "agree $i"
done
for i in 1 2 3; do wait_for "DKG member $i" 120 phase_is "$i" active; done
echo "vault $vault active"
recovery() { api "$1" GET "/api/recovery-status?vault=$vault"; }
for i in 1 2; do recovery "$i" | jq -e '.recovery_identity and .recovery_backup' >/dev/null || fail "member $i has no backup at activation"; done

echo "== member 3 sets up recovery only after the vault is active"
recovery 3 | jq -e '(.recovery_identity | not) and (.recovery_backup | not)' >/dev/null || fail "member 3 already has recovery"
setup_recovery 3
recovery 3 | jq -e '.recovery_identity and .recovery_backup' >/dev/null || fail "member 3 has no backup after recovery setup"
echo "member 3 has a recovery backup after setting up recovery late"
api 3 GET "/api/recovery-backup?vault=$vault" >"$tmp/backup.json" || fail 'export backup'
fingerprint="$(openssl dgst -sha256 -r "$tmp/3/vaults/$vault/signer/recovery.backup" | cut -d' ' -f1)"
cp "$tmp/3/recovery.pub" "$tmp/recovery-3.pub"
old_roster="$(roster_entry 3)"
old_device="$(device_of 3)"
[[ -n "$old_device" ]] || fail 'no device binding for slot 3'

echo "== member 3 loses its device: process stopped, data directory deleted"
stop 3
rm -rf "$tmp/3"
[[ ! -e "$tmp/3" ]] || fail 'data directory still present'

echo "== a fresh profile on a new data directory restores from the words and the exported file"
new="$tmp/3-new-device"
start 3 "$new"
api 3 POST /api/profile-create "$(jq -nc --arg passphrase "$(passphrase 3)" '{name:"Member 3",passphrase:$passphrase}')" >/dev/null || fail 'profile 3'
stop 3
echo "Enter member 3's original words (profile passphrase: $(passphrase 3))"
"$bin" recovery-restore --data "$new" --network testnet --frostd-url "$frostd" \
  --backup "$tmp/backup.json" --fingerprint "$fingerprint" || fail 'local restore 3'
cmp "$new/recovery.pub" "$tmp/recovery-3.pub" || fail 'restore used a different recovery identity'
start 3 "$new"
api 3 POST /api/unlock "$(jq -nc --arg passphrase "$(passphrase 3)" '{passphrase:$passphrase}')" >/dev/null || fail 'unlock profile 3'
phase_is 3 active || fail 'restored vault is not active'
recovery 3 | jq -e '.recovery_identity and .recovery_backup' >/dev/null || fail 'restore did not bring the recovery identity'
echo "restored; the profile's recovery identity is the restored words"

echo "== the restored member restarts with --coordinator-url and re-registers to slot 3"
stop 3
with_coordinator 3 "$new"
wait_for 'restored member registers to slot 3' 60 registered 3
[[ "$(roster_entry 3)" == "$old_roster" ]] || fail "slot 3 changed: $old_roster -> $(roster_entry 3)"
new_device="$(device_of 3)"
[[ -n "$new_device" && "$new_device" != "$old_device" ]] || fail 'slot 3 still bound to the old device key'
echo "slot 3 keeps its identity and relay key; device key ${old_device:0:16}… -> ${new_device:0:16}…"
phase_is 3 active || fail 'restored vault is not active after restart'

echo "== the restored member approves and signs a payment"
address="$(api 1 GET "/api/address?vault=$vault" | jq -er '.address')" || fail address
recipient="${RECIPIENT:-$address}"
echo "Fund this vault with an Ironwood note worth more than amount plus fee: $address"
ready=false
for ((n=0; n<funding_timeout; n+=30)); do
  balance="$(api 1 POST /api/balance "$(jq -nc --arg vault "$vault" '{vault:$vault}')")" || fail "balance: $balance"
  if (( $(jq -r '.balance_zat // 0' <<<"$balance") > AMOUNT_ZAT + 100000 )); then ready=true; break; fi
  sleep 30
done
[[ "$ready" == true ]] || fail "funding not scanned within $funding_timeout seconds"
echo "balance: $(jq -r '.balance_zat' <<<"$balance") zat"
pair() { jq -nc --arg vault "$vault" --arg attempt "$1" '{vault:$vault,attempt:$attempt}'; }
draft=''
for ((n=0; n<funding_timeout; n+=30)); do
  draft="$(api 1 POST /api/payment-draft "$(jq -nc --arg vault "$vault" --arg recipient "$recipient" --arg amount_zat "$AMOUNT_ZAT" '{vault:$vault,recipient:$recipient,amount_zat:$amount_zat,memo:"signed by a restored member"}')")" && break
  echo "no spendable note yet: $draft" >&2
  draft=''
  sleep 30
done
attempt="$(jq -er '.attempt' <<<"$draft")" || fail "draft: $draft"
echo "attempt $attempt"
api 1 POST /api/payment-publish "$(pair "$attempt")" | jq -e '.phase == "signing"' >/dev/null || fail publish
pending() { api 3 GET "/api/pending?vault=$vault" | jq -e --arg attempt "$attempt" 'any(.pending[]; .attempt == $attempt)' >/dev/null; }
wait_for 'restored member sees the request' 60 pending
approve() {
  local i="$1" review
  review="$(api "$i" POST /api/payment-review "$(pair "$attempt")")" || fail "review $i: $review"
  jq -e --arg recipient "$recipient" --arg amount "$AMOUNT_ZAT" '.recipient == $recipient and .amount_zat == $amount' <<<"$review" >/dev/null || fail "review values $i: $review"
  api "$i" POST /api/payment-approve "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg review_token "$(jq -er '.review_token' <<<"$review")" --arg intent_hash "$(jq -er '.intent_hash' <<<"$review")" '{vault:$vault,attempt:$attempt,review_token:$review_token,intent_hash:$intent_hash}')" \
    | jq -e '.phase == "signing"' >/dev/null || fail "approve $i"
  echo "member $i approved"
}
proposer_has() { api 1 GET "/api/payments?vault=$vault" | jq -e --arg attempt "$attempt" "any(.payments[]; .attempt == \$attempt and ($1))" >/dev/null; }
# The restored member approves first, so it joins the proposer in the signing group.
approve 3
wait_for 'proposer records member 3' 60 proposer_has '.approvals == [3]'
approve 1
wait_for 'signing group [1,3]' 60 proposer_has '.signers == [1,3]'
# The proposer sends on its own once the signatures combine, after sealing a copy to every member.
wait_for 'proposer did not send' 600 proposer_has '.phase == "broadcast" or .phase == "confirmed"'
txid="$(api 1 GET "/api/payments?vault=$vault" | jq -er --arg attempt "$attempt" '.payments[] | select(.attempt == $attempt) | .txid')" || fail txid
echo "broadcast txid: $txid (signed by members 1 and restored 3)"
restored_holds() { api 3 GET "/api/payments?vault=$vault" | jq -e --arg attempt "$attempt" --arg txid "$txid" 'any(.payments[]; .attempt == $attempt and .txid == $txid and (.phase == "broadcast" or .phase == "confirmed"))' >/dev/null; }
wait_for 'restored member holds the sent transaction' 60 restored_holds
echo "the restored member holds the signed transaction"
verify() { api 1 POST /api/payment-verify "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg txid "$txid" '{vault:$vault,attempt:$attempt,txid:$txid}')"; }
verified=''
for ((n=0; n<confirm_timeout; n+=30)); do
  verified="$(verify)" || fail "verify: $verified"
  [[ "$(jq -r '.phase' <<<"$verified")" == confirmed ]] && break
  sleep 30
done
jq -e '.phase == "confirmed"' <<<"$verified" >/dev/null || fail "not confirmed within $confirm_timeout seconds: $verified"
height="$(jq -r '.mined_height' <<<"$verified")"
echo "confirmed at height $height"

echo "== a member started against an unreachable coordinator keeps serving"
pass4="$tmp/4.pass"
passphrase 4 >"$pass4"; chmod 600 "$pass4"
start 4 "$tmp/4" --coordinator-url http://127.0.0.1:9 --development-http --local-passphrase-file "$pass4" --registration-slot 4
api 4 GET /api/status | jq -e '.phase == "home"' >/dev/null || fail 'member 4 is not unlocked'
retrying() { api_raw 4 GET /api/registration | grep -q 'retrying after: registration challenge'; }
wait_for 'member 4 reports the failed registration' 30 retrying
sleep 10
kill -0 "${pid[4]}" || fail 'member 4 exited'
api 4 GET /api/status | jq -e '.phase == "home"' >/dev/null || fail 'member 4 stopped serving'
grep -q 'coordinator registration failed, retrying' "$tmp/4.log" || fail 'member 4 did not log the failure'
echo "member 4 serves its local API while registration retries"

echo "PASS: restored member re-registered to slot 3 and signed $txid (confirmed at height $height)"
