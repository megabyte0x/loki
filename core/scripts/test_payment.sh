#!/usr/bin/env bash
# Testnet end to end: an open payment request signed by the first approvers and broadcast,
# with a seven-day expiry; a failed payment that another member retries on the same note,
# which a member that approved the failed one approves without being asked; then a request
# that the proposer cancels.
#
# By default this starts three members and creates a new 2-of-3 vault. With VAULT and
# TOKEN_DIR it reuses three running members on BASE_PORT+1..3 that are already in that
# active vault; TOKEN_DIR holds each member's API token as <i>.token, its log as <i>.log,
# and the members must have been started with `--approve-from TOKEN_DIR/<i>.approvals`.
#
# Members sign only with an approval channel and two nonce witnesses. This script starts
# two witness relays (or uses NONCE_WITNESSES, which needs separate operator enrollment) and runs each
# member with `--approve-from`: it reads the signer's own `approval-request` summary from the
# member's log and approves only the recipient, amount and network it proposed.
set -euo pipefail

cd "$(dirname "$0")/.."
: "${AMOUNT_ZAT:?set AMOUNT_ZAT to the amount in zat}"

bin="${LOKI_MEMBER_APP_BIN:-$PWD/target/debug/loki_member_app}"
frostd="${FROSTD_URL:-http://127.0.0.1:2744}"
base_port="${BASE_PORT:-3300}"
funding_timeout="${FUNDING_TIMEOUT:-3600}"
vault="${VAULT:-}"
if [[ -n "$vault" ]]; then
  : "${TOKEN_DIR:?set TOKEN_DIR to the directory with the <i>.token file of each running member}"
  tmp="$TOKEN_DIR"
else
  : "${LIGHTWALLETD_URL:?set LIGHTWALLETD_URL to a Testnet lightwalletd endpoint}"
  tmp="$(mktemp -d)"
fi
pids=()
witness_pids=()
held=()
cleanup() {
  # Release what this run reserved and did not get to spend.
  for attempt in "${held[@]}"; do api 1 POST /api/payment-discard "$(pair "$attempt")" >/dev/null 2>&1 || true; done
  for pid in "${pids[@]}" "${witness_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${VAULT:-}" ]] || echo "member data preserved: $tmp"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $1" >&2
  for i in 1 2 3; do tail -20 "$tmp/$i.log" 2>/dev/null || true; done
  exit 1
}
command -v jq >/dev/null || fail 'jq is required'
api() {
  local i="$1" method="$2" path="$3" body="${4:-}" token
  token="$(cat "$tmp/$i.token")"
  if [[ "$method" == POST ]]; then
    curl --fail-with-body -sS -m 600 -X POST "http://127.0.0.1:$((base_port+i))$path" \
      -H "X-Loki-Token: $token" -H 'Content-Type: application/json' -d "$body"
  else
    curl --fail-with-body -sS -m 600 "http://127.0.0.1:$((base_port+i))$path" -H "X-Loki-Token: $token"
  fi
}
passphrase() { printf 'testnet payment member %s' "$1"; }
pair() { jq -nc --arg vault "$vault" --arg attempt "$1" '{vault:$vault,attempt:$attempt}'; }

if [[ -n "$vault" ]]; then
  for i in 1 2 3; do
    if [[ "$(api "$i" GET /api/status | jq -r '.phase')" == locked ]]; then
      api "$i" POST /api/unlock "$(jq -nc --arg passphrase "$(passphrase "$i")" '{passphrase:$passphrase}')" | jq -e '.unlocked' >/dev/null || fail "unlock $i"
    fi
    api "$i" GET "/api/status?vault=$vault" | jq -e '.phase == "active"' >/dev/null || fail "member $i is not active in vault $vault"
  done
else
[[ -x "$bin" ]] || fail "missing $bin; build loki_member_app first"
witnesses="${NONCE_WITNESSES:-}"
if [[ -z "$witnesses" ]]; then
  relay="$PWD/../communication/target/debug/loki-relay-server"
  [[ -x "$relay" ]] || cargo build --manifest-path ../communication/Cargo.toml --target-dir ../communication/target \
    --locked --bin loki-relay-server || fail 'build loki-relay-server'
  witness_port="${WITNESS_BASE_PORT:-39400}"
  for n in 1 2; do
    head -c 32 /dev/urandom >"$tmp/relay-$n.secret"; chmod 600 "$tmp/relay-$n.secret"
    "$relay" init --root "$tmp/relay-$n" --listen "127.0.0.1:$((witness_port+n))" \
      --provision-capability-file "$tmp/relay-$n.secret" \
      --total-bytes 268435456 --mailbox-bytes 67108864 --mailbox-count 1024 >/dev/null || fail "witness relay $n init"
    cp "$tmp/relay-$n.secret" "$tmp/relay-$n/provision.secret"
    "$relay" serve --root "$tmp/relay-$n" --listen "127.0.0.1:$((witness_port+n))" >"$tmp/relay-$n.log" 2>&1 &
    witness_pids+=("$!")
  done
  for n in 1 2; do
    for _ in {1..100}; do nc -z 127.0.0.1 "$((witness_port+n))" 2>/dev/null && break; sleep 0.1; done
    nc -z 127.0.0.1 "$((witness_port+n))" 2>/dev/null || fail "witness relay $n did not start"
  done
  witnesses="$tmp/witnesses.json"
  cargo run -q --locked --features relay-communication --example provision_nonce_witnesses -- \
    --relay-root "$tmp/relay-1" --relay-root "$tmp/relay-2" --out "$witnesses" --development-http \
    >"$tmp/provision.log" 2>&1 || fail "provisioning the nonce witnesses failed; see $tmp/provision.log"
  kill "${witness_pids[@]}"
  for pid in "${witness_pids[@]}"; do wait "$pid"; done
  witness_pids=()
fi
echo "nonce witnesses: $witnesses"
for i in 1 2 3; do
  port=$((base_port+i))
  "$bin" --data "$tmp/$i" --port "$port" --network testnet \
    --lightwalletd-url "$LIGHTWALLETD_URL" --frostd-url "$frostd" \
    --nonce-witnesses "$witnesses" --development-http --approve-from "$tmp/$i.approvals" \
    --peer "1=http://127.0.0.1:$((base_port+1))" \
    --peer "2=http://127.0.0.1:$((base_port+2))" \
    --peer "3=http://127.0.0.1:$((base_port+3))" >"$tmp/$i.log" 2>&1 &
  pids+=("$!")
done
for i in 1 2 3; do
  token=''
  for _ in {1..100}; do
    token="$(sed -n 's|.*Signer: http://127.0.0.1:[0-9]*/#||p' "$tmp/$i.log" | head -1)"
    [[ -n "$token" ]] && break
    sleep 0.1
  done
  [[ -n "$token" ]] || fail "member $i did not start"
  printf '%s' "$token" >"$tmp/$i.token"
done
for i in 1 2 3; do
  api "$i" POST /api/profile-create "$(jq -nc --arg name "Member $i" --arg passphrase "$(passphrase "$i")" '{name:$name,passphrase:$passphrase}')" | jq -e '.name' >/dev/null || fail "profile $i"
done
created="$(api 1 POST /api/create '{"name":"Testnet payment vault","members":3,"threshold":2}')" || fail create
vault="$(jq -er '.vault' <<<"$created")" || fail vault
for i in 2 3; do
  code="$(jq -er --argjson slot "$i" '.invites[] | select(.slot == $slot) | .code' <<<"$created")" || fail "invite $i"
  api "$i" POST /api/join "$(jq -nc --arg invite "$code" '{invite:$invite}')" | jq -e --arg vault "$vault" '.vault == $vault' >/dev/null || fail "join $i"
done
for i in 1 2 3; do
  ready=false
  for _ in {1..100}; do
    status="$(api "$i" GET "/api/status?vault=$vault")"
    [[ "$(jq -r '.phase' <<<"$status")" == compare_roster ]] && { ready=true; break; }
    sleep 0.1
  done
  [[ "$ready" == true ]] || fail "roster $i: $status"
done
for i in 1 2 3; do
  fingerprint="$(api "$i" GET "/api/status?vault=$vault" | jq -er '.fingerprint')" || fail "fingerprint $i"
  roster_code="$(api "$i" GET "/api/status?vault=$vault" | jq -er '.roster_code')" || fail "roster code $i"
  api "$i" POST /api/agree "$(jq -nc --arg vault "$vault" --arg fingerprint "$fingerprint" --arg roster_code "$roster_code" '{vault:$vault,fingerprint:$fingerprint,roster_code:$roster_code}')" | jq -e '.ok == true' >/dev/null || fail "agree $i"
done
for i in 1 2 3; do
  active=false
  for _ in {1..300}; do
    status="$(api "$i" GET "/api/status?vault=$vault")"
    [[ "$(jq -r '.phase' <<<"$status")" == active ]] && { active=true; break; }
    [[ "$(jq -r '.error // empty' <<<"$status")" == '' ]] || fail "DKG member $i: $status"
    sleep 0.1
  done
  [[ "$active" == true ]] || fail "DKG member $i: $status"
done
echo "Back up all three member directories before funding: $tmp"
if [[ -z ${NONCE_WITNESSES:-} ]]; then
  # This isolated run created the vault, controls both witnesses and just confirmed the roster.
  joined=$(jq -ce '.invites[] | select(.slot == 2) | .code | gsub("-"; "+") | gsub("_"; "/") |
    . + ("=" * ((4 - length % 4) % 4)) | @base64d | fromjson | {vault, slot, token}' <<<"$created")
  roster=$(api 1 POST /api/roster "$joined" | jq -er --arg f "$fingerprint" 'select(.fingerprint == $f) | .roster')
  for n in 1 2; do
    mailbox=$(jq -er --argjson i "$((n-1))" '.[$i].mailbox | map((. / 16 | floor), (. % 16)) |
      map(. as $nibble | "0123456789abcdef"[$nibble:$nibble + 1]) | join("")' "$witnesses")
    for i in 1 2 3; do
      key=$(jq -er --arg i "$i" '.[$i].signing' <<<"$roster")
      "$relay" enroll-nonce --root "$tmp/relay-$n" --mailbox "$mailbox" --vault "$vault" \
        --slot "$i" --signing-key "$key" --quota-bytes 1048576 || fail "witness $n enrollment for member $i"
    done
    "$relay" serve --root "$tmp/relay-$n" --listen "127.0.0.1:$((witness_port+n))" >>"$tmp/relay-$n.log" 2>&1 &
    witness_pids+=("$!")
    for _ in {1..100}; do nc -z 127.0.0.1 "$((witness_port+n))" 2>/dev/null && break; sleep 0.1; done
    nc -z 127.0.0.1 "$((witness_port+n))" 2>/dev/null || fail "witness $n did not restart after enrollment"
  done
else
  echo "Enroll vault $vault on both external witnesses before funding (see communication/deploy/README.md)."
fi
fi
address="$(api 1 GET "/api/address?vault=$vault" | jq -er '.address')" || fail address
# Without RECIPIENT the vault pays itself, so the test spends nothing but fees.
recipient="${RECIPIENT:-$address}"
echo "vault $vault"
echo "Fund this vault with an Ironwood note worth more than amount plus fee: $address"
ready=false
for ((n=0; n<funding_timeout; n+=30)); do
  balance="$(api 1 POST /api/balance "$(jq -nc --arg vault "$vault" '{vault:$vault}')")" || fail "balance: $balance"
  if (( $(jq -r '.balance_zat // 0' <<<"$balance") > AMOUNT_ZAT + 100000 )); then ready=true; break; fi
  sleep 30
done
[[ "$ready" == true ]] || fail "funding not scanned within $funding_timeout seconds"
echo "balance: $(jq -r '.balance_zat' <<<"$balance") zat"

# Each member's signer asks before it signs; answer from the summary it derived itself.
review_signing() {
  local i="$1" seen=' ' summary sighash
  while sleep 1; do
    while read -r summary; do
      sighash="$(jq -r '.sighash' <<<"$summary")"
      [[ "$seen" == *" $sighash "* ]] && continue
      seen+="$sighash "
      if jq -e --arg recipient "$recipient" --arg amount "$AMOUNT_ZAT" \
        '.recipient == $recipient and (.amount_zat | tostring) == $amount and .network == "testnet" and .fee_verified' \
        <<<"$summary" >/dev/null; then
        echo "approve $sighash" >>"$tmp/$i.approvals"
      else
        echo "refuse $sighash" >>"$tmp/$i.approvals"
        echo "member $i signer refused a payment it was not asked for: $summary" >&2
      fi
    done < <(sed -n 's/^approval-request //p' "$tmp/$i.log")
  done
}
for i in 1 2 3; do review_signing "$i" & pids+=("$!"); done

draft() {
  api 1 POST /api/payment-draft "$(jq -nc --arg vault "$vault" --arg recipient "$recipient" --arg amount_zat "$AMOUNT_ZAT" --arg memo "$1" '{vault:$vault,recipient:$recipient,amount_zat:$amount_zat,memo:$memo}')"
}
# A received note becomes spendable only after enough confirmations; retry until it is.
draft_when_spendable() {
  local out=''
  for ((n=0; n<funding_timeout; n+=30)); do
    out="$(draft "$1")" && { echo "$out"; return; }
    echo "no spendable note yet: $out" >&2
    sleep 30
  done
  fail "draft: $out"
}
publish() {
  api 1 POST /api/payment-publish "$(pair "$1")" | jq -e '.phase == "signing"' >/dev/null || fail "publish $1"
}
approve() {
  local i="$1" attempt="$2" review token
  review="$(api "$i" POST /api/payment-review "$(pair "$attempt")")" || fail "review $i: $review"
  jq -e --arg recipient "$recipient" --arg amount "$AMOUNT_ZAT" '.recipient == $recipient and .amount_zat == $amount' <<<"$review" >/dev/null || fail "review values $i"
  token="$(jq -er '.review_token' <<<"$review")"
  api "$i" POST /api/payment-approve "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg review_token "$token" --arg intent_hash "$(jq -er '.intent_hash' <<<"$review")" '{vault:$vault,attempt:$attempt,review_token:$review_token,intent_hash:$intent_hash}')" | jq -e '.phase == "signing"' >/dev/null || fail "approve $i"
  echo "member $i approved"
}
phase() { api "$1" GET "/api/payment-status?vault=$vault&attempt=$2" | jq -r '.phase'; }
has_phase() { [[ "$(phase "$1" "$2")" == "$3" ]]; }
pending() { api "$1" GET "/api/pending?vault=$vault" | jq -e --arg attempt "$2" 'any(.pending[]; .attempt == $attempt)' >/dev/null; }
# The proposer's view; listing also drains its control messages.
proposer_has() { api 1 GET "/api/payments?vault=$vault" | jq -e --arg attempt "$1" "any(.payments[]; .attempt == \$attempt and ($2))" >/dev/null; }
wait_for() {
  local what="$1" tries="$2"
  shift 2
  for ((n=0; n<tries; n++)); do "$@" && return; sleep 1; done
  fail "$what"
}
phases() { for i in 1 2 3; do echo "  member $i: $(phase "$i" "$1")"; done; }
# The transaction member $1 holds for payment $2 expires about seven days (8,064 blocks) after
# the tip it was signed at, below the approved bound; prints its expiry height.
check_expiry() {
  local p
  p="$(api "$1" GET "/api/payments?vault=$vault" | jq -c --arg attempt "$2" '.payments[] | select(.attempt == $attempt)')"
  jq -e '.tx_expiry != null and .tx_expiry == .signing_expiry and .tx_expiry < .expiry_height
    and (.tx_expiry - .target_height - 2) >= 8064 and (.tx_expiry - .target_height - 2) < 8064 + 1152' <<<"$p" >/dev/null \
    || fail "member $1 holds no seven-day transaction for $2: $p"
  jq -r '"\(.tx_expiry) (signed at tip \(.target_height + 2), approved bound \(.expiry_height))"' <<<"$p"
}
unlock() { api "$1" POST /api/unlock "$(jq -nc --arg passphrase "$(passphrase "$1")" '{passphrase:$passphrase}')" | jq -e '.unlocked' >/dev/null || fail "unlock $1"; }

echo "== open request: any member may approve; member 3 approves before member 2"
attempt="$(draft_when_spendable "${MEMO:-testnet payment}" | jq -er '.attempt')"
echo "attempt $attempt"
publish "$attempt"
for i in 2 3; do wait_for "member $i sees the request" 60 pending "$i" "$attempt"; done
phases "$attempt"
approve 3 "$attempt"
wait_for 'proposer records member 3' 60 proposer_has "$attempt" '.approvals == [3]'
approve 2 "$attempt"
wait_for 'proposer records member 2' 60 proposer_has "$attempt" '.approvals == [3,2]'
approve 1 "$attempt"
wait_for 'signing group [1,3]' 60 proposer_has "$attempt" '.signers == [1,3]'
wait_for 'member 2 is not selected' 300 has_phase 2 "$attempt" not_selected
! pending 2 "$attempt" || fail 'member 2 still lists the request'
echo "signing group [1,3]; member 2 not_selected and off its pending list"
# The proposer sends on its own once the signatures combine, after sealing a copy to every member.
wait_for 'proposer did not send' 600 proposer_has "$attempt" '.phase == "broadcast" or .phase == "confirmed"'
phases "$attempt"
txid="$(api 1 GET "/api/payments?vault=$vault" | jq -er --arg attempt "$attempt" '.payments[] | select(.attempt == $attempt) | .txid')" || fail txid
echo "broadcast txid: $txid"
verified="$(api 1 POST /api/payment-verify "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg txid "$txid" '{vault:$vault,attempt:$attempt,txid:$txid}')")" || fail "verify: $verified"
jq -e '.phase == "broadcast" or .phase == "confirmed"' <<<"$verified" >/dev/null || fail "verify result: $verified"
member_sent() { api "$1" GET "/api/payments?vault=$vault" | jq -e --arg attempt "$2" --arg txid "$txid" 'any(.payments[]; .attempt == $attempt and .txid == $txid and (.phase == "broadcast" or .phase == "confirmed"))' >/dev/null; }
for i in 2 3; do wait_for "member $i holds the sent transaction" 60 member_sent "$i" "$attempt"; done
phases "$attempt"
echo "transaction expires at $(check_expiry 2 "$attempt")"
first_txid="$txid"

echo "== retry: member 3 retries a failed payment; member 2 approved it and approves the retry unasked"
attempt="$(draft_when_spendable 'retried payment' | jq -er '.attempt')"
echo "attempt $attempt"
publish "$attempt"
for i in 2 3; do wait_for "member $i sees the request" 60 pending "$i" "$attempt"; done
approve 2 "$attempt"
wait_for 'proposer records member 2' 60 proposer_has "$attempt" '.approvals == [2]'
# Member 2 goes away after approving, so the round the proposer starts with it fails.
api 2 POST /api/lock '{}' | jq -e '.locked' >/dev/null || fail 'lock 2'
approve 1 "$attempt"
wait_for 'signing group [1,2]' 60 proposer_has "$attempt" '.signers == [1,2]'
wait_for 'the round fails without member 2' 600 proposer_has "$attempt" '.phase == "failed"'
unlock 2
for i in 2 3; do wait_for "member $i hears the failure" 300 has_phase "$i" "$attempt" failed; done
phases "$attempt"
replaced="$(api 3 POST /api/payment-replace "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" '{vault:$vault,attempt:$attempt,mode:"retry"}')")" || fail "replace: $replaced"
retry="$(jq -er '.attempt' <<<"$replaced")"
echo "member 3 retries it as $retry"
api 3 POST /api/payment-publish "$(pair "$retry")" | jq -e '.phase == "signing" and (.approved | not)' >/dev/null || fail 'publish retry'
retry_seen() { api 2 GET "/api/payments?vault=$vault" | jq -e --arg attempt "$retry" 'any(.payments[]; .attempt == $attempt)' >/dev/null; }
wait_for 'member 2 sees the retry' 60 retry_seen
# No approve call for member 2: its app approves the retry when it reads the request.
! pending 2 "$retry" || fail 'member 2 was asked to approve the retry'
api 2 GET "/api/payments?vault=$vault" | jq -e --arg attempt "$retry" 'any(.payments[]; .attempt == $attempt and .approval_requested)' >/dev/null || fail 'member 2 did not approve the retry'
echo "member 2 approved the retry by itself"
retry_by() { api 3 GET "/api/payments?vault=$vault" | jq -e --arg attempt "$retry" "any(.payments[]; .attempt == \$attempt and ($1))" >/dev/null; }
approve_retry() {
  local review token
  review="$(api 3 POST /api/payment-review "$(pair "$retry")")" || fail "review 3: $review"
  token="$(jq -er '.review_token' <<<"$review")"
  api 3 POST /api/payment-approve "$(jq -nc --arg vault "$vault" --arg attempt "$retry" --arg review_token "$token" --arg intent_hash "$(jq -er '.intent_hash' <<<"$review")" '{vault:$vault,attempt:$attempt,review_token:$review_token,intent_hash:$intent_hash}')" | jq -e '.phase == "signing"' >/dev/null || fail 'approve 3'
}
approve_retry
echo "member 3 approved its retry"
wait_for 'retry signing group [3,2]' 120 retry_by '.signers == [3,2]'
# Member 2 lists payments as its screen does, which starts its signing.
retry_sent() { api 2 GET "/api/payments?vault=$vault" >/dev/null; retry_by '.phase == "broadcast" or .phase == "confirmed"'; }
wait_for 'retry was not sent' 600 retry_sent
txid="$(api 3 GET "/api/payments?vault=$vault" | jq -er --arg attempt "$retry" '.payments[] | select(.attempt == $attempt) | .txid')" || fail txid
echo "retry broadcast txid: $txid"
retry_txid="$txid"
member_sent() { api "$1" GET "/api/payments?vault=$vault" | jq -e --arg attempt "$2" --arg txid "$retry_txid" 'any(.payments[]; .attempt == $attempt and .txid == $txid and (.phase == "broadcast" or .phase == "confirmed"))' >/dev/null; }
wait_for 'member 2 holds the retry' 60 member_sent 2 "$retry"
echo "retry expires at $(check_expiry 2 "$retry")"
mined() {
  local out
  out="$(api "$1" POST /api/payment-verify "$(jq -nc --arg vault "$vault" --arg attempt "$retry" --arg txid "$retry_txid" '{vault:$vault,attempt:$attempt,txid:$txid}')")" || return 1
  jq -e '.phase == "confirmed"' <<<"$out" >/dev/null && echo "$out"
}
for ((n=0; n<funding_timeout; n+=30)); do out="$(mined 3)" && break; sleep 30; done
[[ "$(jq -r .phase <<<"$out")" == confirmed ]] || fail "retry not mined: $out"
echo "retry confirmed at height $(jq -r '.mined_height' <<<"$out")"
for i in 1 2 3; do wait_for "member $i settles the failed payment as replaced" 120 has_phase "$i" "$attempt" replaced; done
phases "$attempt"

echo "== cancel: member 1 cancels its request after member 2 approved"
first="$(draft_when_spendable 'cancelled payment')"
attempt="$(jq -er '.attempt' <<<"$first")"
held+=("$attempt")
echo "attempt $attempt"
publish "$attempt"
for i in 2 3; do wait_for "member $i sees the request" 60 pending "$i" "$attempt"; done
approve 2 "$attempt"
wait_for 'proposer records member 2' 60 proposer_has "$attempt" '.approvals == [2] and .can_discard'
phases "$attempt"
# Reserve every other note that could fund this amount, so only the cancel can free one.
while other="$(draft 'reserves another note')"; do
  held+=("$(jq -er '.attempt' <<<"$other")")
  (( ${#held[@]} <= 20 )) || fail 'too many spendable notes'
done
echo "reserved $(( ${#held[@]} - 1 )) other notes; a further draft is refused: $other"
cancelled="$(api 1 POST /api/payment-discard "$(pair "$attempt")")" || fail "cancel: $cancelled"
jq -e '.phase == "cancelled"' <<<"$cancelled" >/dev/null || fail "cancel result: $cancelled"
has_phase 1 "$attempt" cancelled || fail 'proposer copy is not cancelled'
for i in 2 3; do
  wait_for "member $i hears the cancel" 60 has_phase "$i" "$attempt" cancelled
  ! pending "$i" "$attempt" || fail "member $i still lists the cancelled request"
done
phases "$attempt"
again="$(draft 'after cancel')" || fail "draft after cancel: $again"
held+=("$(jq -er '.attempt' <<<"$again")")
[[ "$(jq -r '.change_zat' <<<"$again")" == "$(jq -r '.change_zat' <<<"$first")" ]] || fail "draft after cancel spends another note: $again"
echo "the draft after cancel spends the released note"
for held_attempt in "${held[@]:1}"; do
  api 1 POST /api/payment-discard "$(pair "$held_attempt")" | jq -e '.phase == "cancelled"' >/dev/null || fail "discard draft $held_attempt"
done
held=()
echo "PASS: Testnet payment $first_txid broadcast ($(jq -r '.phase' <<<"$verified")); retry $retry_txid mined in place of the failed payment; cancelled request released its note"
