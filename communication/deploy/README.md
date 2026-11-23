# feat(setup): hosted operator deployment

## Single-host loopback TEST bringup

This toolkit runs three owned relays and one admission service on one host at
`127.0.0.1:39101`–`39104`. Use a new absolute directory each time; it contains
private operator capabilities and the test enrollment issuer seed. Bash, Cargo,
Python 3, and curl are required.

```sh
communication/deploy/bringup.sh /absolute/new/test-stack
communication/deploy/teardown.sh /absolute/new/test-stack
```

Bringup builds the release binaries with `--locked`, generates random TEST keys,
initializes three separate relay roots and the admission root, signs a canonical
development bundle, starts all four services, and checks each `/health` endpoint.
It refuses an existing root. Teardown sends the services SIGINT and preserves the
roots, logs, and operator inputs for inspection. The admission executable in this
checkout has `serve` only: input generation creates its root and signing key.
Each relay's `init` creates its signing key and run identity. Relay provision
files are numbered in **bundle signing-key order**, which admission requires;
the relay roots remain numbered by listener port.

The generated paths are:

| Path under the root | Use |
| --- | --- |
| `inputs/bundle`, `inputs/config-key` | Member operator bundle and trusted 32-byte configuration public key |
| `inputs/config-signing-key` | Private TEST configuration seed; keep on operator host |
| `inputs/issuer-public-key`, `inputs/issuer-signing-key` | Admission enrollment verifier and private TEST issuer seed |
| `inputs/relay-{1,2,3}-provision` | Private relay capabilities for admission, in bundle order |
| `relay-{1,2,3}/`, `admission/` | Persistent service roots |
| `issue-enrollment` | TEST issuer executable for a member app on this host |

For an existing owned stack, upgrade all three relays before admission. New
payment handoff mailboxes are usable before the activation vote, but their
reserved bytes count against the grant on each relay and the relay's provisional
budget. Admission promotes them after unanimous activation or retires them after
an abandoned ceremony; keep the admission worker running to reconcile either
decision. Relay expiry alone disables use without deleting data. Legacy payment
mailboxes keep their previous durable lifecycle, and no nonce history is migrated
or deleted. Do not roll back to relay binaries that do not enforce reservations.

## Single-host self-custody member stack (frostd)

The audited DKG/signing on `main` runs over **frostd** (`FrostdTransport`), not the
owned relays above. `selfcustody-testnet.sh` stands up the full self-custody stack on
one host — the public-roster web coordinator plus N `loki_member_app` processes that
self-register — then drives a t-of-n DKG to `active` and prints the shared address.
Bash, Cargo, Node.js 24+, Python 3, curl 7.55+, and OpenSSL are required.

```sh
communication/deploy/selfcustody-testnet.sh /absolute/new/member-stack
kill $(cat /absolute/new/member-stack/pids)   # stop
```

It builds `loki_member_app` (`--features relay-communication`) and the web coordinator,
starts the coordinator on `:3001` with `LOKI_REGISTRY` pointed at the stack root, starts
N members (software device storage, self-registering to the coordinator), waits for the
roster to fill, then creates/joins/agrees the ceremony and reports the `utest1…` address.
Tunables are environment variables (`FROSTD_URL`, `LWD_URL`, `NETWORK`, `MEMBERS`,
`THRESHOLD`, `WEB_PORT`, `BASE_PORT`); defaults are a testnet 2-of-3 against
`http://127.0.0.1:2744` and `https://testnet.zec.rocks:443`.

**frostd must be https off loopback** (`transport::require_tls_off_loopback`): a plaintext
dev relay (`frostd -n -p 2744`) is only accepted on loopback, so forward a remote one first
and keep the default `FROSTD_URL`:

```sh
ssh -N -L 2744:localhost:2744 your-frostd-host   # then run selfcustody-testnet.sh
```

One member app on its own (for first enrollment, set `LOKI_ONBOARDING_GRANT` to
an [operator-issued grant](../../web/wallet/README.md#onboarding-grants) pinned to slot 1):

```sh
core/target/release/loki_member_app --data /absolute/member-1 --port 3601 \
  --network testnet --lightwalletd-url https://testnet.zec.rocks:443 \
  --frostd-url http://127.0.0.1:2744 --allow-loopback-peers \
  --secure-element software --development-http \
  --coordinator-url http://localhost:3001 \
  --local-passphrase-file /absolute/member-1.pass --registration-slot 1
```

`--allow-loopback-peers` is required on testnet when members are co-located on loopback
(the SSRF guard otherwise rejects loopback peer URLs). The local-passphrase file must be
mode 0600. This is a one-host TEST setup, not production HTTPS or independent operators.

## Nonce witness enrollment and upgrades

Signing needs fresh receipts from two independently operated witnesses. For a new pair,
provision the mailboxes with `core/examples/provision_nonce_witnesses.rs`. For an existing
pair, **reuse both relay roots and their existing mailboxes**; do not run `init` again,
replace the output configuration, or restore an older copy of `relay.sqlite3`.

Stop both witnesses before upgrading. At each stopped relay, enroll each signer using the
vault ID, FROST slot and Ed25519 signing key from the member-confirmed vault roster (not an
unverified coordinator registry or a relay login key). Use that relay's existing mailbox ID
from the witness configuration. Standalone payment signers use their own configured inboxes
as witnesses, so enroll each signer on the two inboxes it uses.

```sh
loki-relay-server enroll-nonce --root /path/to/relay-root \
  --mailbox "$MAILBOX_HEX" --vault "$VAULT_HEX" --slot "$FROST_SLOT" \
  --signing-key "$ED25519_PUBLIC_KEY_HEX" --quota-bytes 1048576
```

Enrollment installs the new policy in place, without deleting or reassigning any legacy
claim. Legacy CIDs still block fresh receipts for that mailbox, regardless of who presents
them. The relay reserves claim capacity separately from ordinary objects, using the existing
mailbox and relay byte limits as ceilings for the claim ledger. Size the budgets for both
ledgers; each claim consumes its record bytes plus a 512-byte row allowance. Legacy records
also count against the claim budget. An enrollment that would exceed either ceiling fails
without changing the root. A repeat with the same key can leave or increase its quota,
but cannot replace that key or reset its usage. If a legacy ledger is already over budget,
keep it intact and keep signing paused rather than creating an empty replacement.

Restart the upgraded witnesses and update the native clients and both browser WASM packages
before resuming signing. Receipt format v2 requires a lockstep upgrade of both witnesses and
all native and browser clients; mixed versions cannot sign. The public configuration contains
only endpoints and pins. A `read` field in an old witness file is ignored by signing clients;
the provisioning tool can still use it to check the mailbox. Read capabilities no longer
authorize claims. For browser use, the witness TLS proxy must allow the signer origin, `PUT`,
and the `Authorization`,
`Content-Type`, and `X-Loki-Challenge` headers. Do not downgrade or roll either witness back.

## frostd behind TLS + CORS for the in-browser signer (`frostd-tls.sh`)

The in-browser (wasm) signer (`core/wasm-transport`, W3) runs frostd's POST contract from
the page itself over the Fetch API. A browser can reach frostd **only** over https/wss and
**only** if the reply carries CORS headers for the wallet origin. The loopback-plaintext dev
relay (`frostd -n -p 2744`) fails both: `http://127.0.0.1:2744` is mixed content from an
https page, and frostd emits no CORS headers, so the `fetch()` is blocked before the signer
sees any reply. The ssh-tunnel path (`ssh -N -L 2744:localhost:2744`) only helps a
server-side `FrostdTransport` dialing out; it does nothing for code running in the browser.

`require_tls_off_loopback` (in both the native and wasm transports) already demands https
off loopback — so the wasm signer must point at a TLS front, not the tunnel.

`frostd-tls.sh` runs Caddy as a TLS-terminating reverse proxy in front of the loopback
frostd and injects CORS (including the OPTIONS preflight, which it answers itself since
frostd would 405 it) for one site origin:

```sh
# real host + ACME cert, public:
ORIGIN=https://wallet.example FRONT=relay.example communication/deploy/frostd-tls.sh
# -> wasm signer points at https://relay.example

# local https (Caddy internal CA), for dev against a localhost wallet origin:
ORIGIN=https://localhost:3011 communication/deploy/frostd-tls.sh
# -> wasm signer points at https://localhost:8443
```

Use `UPSTREAM=127.0.0.1:2744` (the default), `[::1]:2744`, or a local Caddy socket
address such as `unix//run/frostd.sock` for plaintext. Use literal IPs, not `localhost`
or other DNS names. For a remote relay, use `UPSTREAM=https://frostd.example:2744`;
Caddy verifies the upstream certificate and hostname against its system trust store.

cloudflared works the same way for the public case (a `trycloudflare` tunnel to
`127.0.0.1:2744` gives https), but it does not add CORS, so Caddy in front of frostd is
still needed for the CORS headers; put cloudflared in front of Caddy, or use Caddy's own
ACME. CORS is per-origin: list the exact wallet origin (scheme+host+port, no trailing
slash), not `*` — `*` is incompatible with the `authorization` bearer header browsers send.

## lightwalletd behind gRPC-web + CORS for the in-browser signer (`lightwalletd-grpcweb.sh`)

The in-browser signer scans the chain for its vault balance itself, from the signer page. A
browser cannot make native gRPC calls (HTTP/2 trailers). `lightwalletd-grpcweb.sh` uses
Node.js 22+ to translate binary gRPC-web to native gRPC over verified TLS. It enables CORS
for the exact signer origin, not the wallet origin, and forwards only `GetLatestBlock` and
height-only `GetBlockRange` (up to 500 blocks inclusive).

The proxy allows four simultaneous RPCs per peer IP and 32 overall, after validating each
request, with a 25-second deadline through the end of the response. A TLS terminator or tunnel
shares the peer budget by default. Set `TRUST_FORWARDED=1` only when a trusted loopback proxy
is the only caller and sets or appends the actual downstream client's IP as the rightmost
`X-Forwarded-For` entry. Requests from non-loopback socket addresses never use that header.

```sh
ORIGIN=http://localhost:3002 communication/deploy/lightwalletd-grpcweb.sh
# -> the signer calls http://127.0.0.1:9068 (UPSTREAM defaults to testnet.zec.rocks:443)
```

Check it answers the preflight for the signer origin and a gRPC-web call:

```sh
curl -si -X OPTIONS http://127.0.0.1:9068/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock \
  -H 'Origin: http://localhost:3002' -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type,x-grpc-web' | grep -i access-control
printf '\0\0\0\0\0' | curl -s -X POST http://127.0.0.1:9068/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock \
  -H 'Origin: http://localhost:3002' -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' \
  --data-binary @- | strings | head -3
```

The listener is plaintext and defaults to `LISTEN=127.0.0.1:9068`. For a public signer,
keep it on loopback and put it behind a TLS terminator.

## Public HTTPS bringup (`public-testnet.sh`)

Hosts ONLY the shared coordinator over a free cloudflared quick tunnel, so testers on
other machines/networks join without hosting anything. It ensures frostd is reachable
(ssh tunnel to `FROSTD_HOST`, default `omarchy`), opens
`cloudflared tunnel --url http://127.0.0.1:$WEB_PORT`, captures the printed
`https://*.trycloudflare.com` URL, and starts the loopback-only coordinator with
`PUBLIC_ORIGIN` set to that URL. Requires `/opt/homebrew/bin/cloudflared`.

```sh
communication/deploy/public-testnet.sh /absolute/new/pub-stack
# -> coordinator LIVE:  https://<random>.trycloudflare.com   (open in a browser)
kill $(cat /absolute/new/pub-stack/pids)   # stop
```

When configuring another TLS proxy, point it at `127.0.0.1:$PORT` and set `PUBLIC_ORIGIN`
to the exact public HTTPS origin (no path, trailing slash or default port). This replaces
`HOSTNAME` and `PUBLIC_PORT`. Self-registration signs over that public origin; the coordinator
doesn't trust request-supplied forwarding headers to choose it. `WEB_PORT` defaults to
`3011` to avoid the loopback test stack on `:3001`. frostd (`:2744`) supports concurrent sessions.

Share vault invites as `/#invite=…`, never as `/?invite=…`. The wallet rejects the
old query form before rendering. It cannot prevent the first request from reaching a
proxy or its access logs: redact query strings at ingress and restrict existing logs
that may contain invites. Treat tokens sent as query parameters as exposed. For an
unfinished setup, stop using the affected ceremony and create a fresh vault ceremony
with new tokens; merely changing `?` to `#` does not rotate a token. Keep any existing
funded vault and its backups intact and investigate unexpected members with your group.

## Packaged member (`run-member.sh`)

Testers run a member from an updated release binary with Bash, Python 3, and OpenSSL
(no Rust toolchain needed). Run from a terminal that is not being recorded:

```sh
ssh -N -L 2744:localhost:2744 omarchy   # frostd must be reachable on loopback
communication/deploy/run-member.sh https://<coordinator>.trycloudflare.com 1
kill $(cat ./loki-state/member-1/pids)   # stop
```

New launches default to the ignored, owner-only `loki-state/member-<slot>` under the
repository root. For a member launched with the old default, keep its directory and
passphrase together and set `DATA` to that existing directory before restarting (for
example, `DATA=./loki-member-1` from the original working directory).

Paste the private pairing link shown on the terminal into the wallet. Do not capture
or share the link; the fragment authorizes the local API for the member process's lifetime.
If recovery is not set up, use the wallet to set it up and save the words privately.

It self-registers to the coordinator URL (slot = 2nd arg), using `software` device storage.
For first enrollment, set `LOKI_ONBOARDING_GRANT` to a grant pinned to that slot, or
use `join-loki.sh <https-coordinator-url> [slot]` with the grant to reserve an eligible slot
before launch. Existing members can restart with `run-member.sh` without a grant.
The wrapper advertises an HTTPS tunnel to the ceremony-only listener on
`127.0.0.1:$PEER_PORT` (default `4610 + slot`). Only enrollment, roster, agreement
and session peer requests reach that listener; the full member API on `PORT` stays private.
To use your own local TLS proxy instead, set `ADVERTISE_URL` to its public HTTPS origin and
forward it only to `127.0.0.1:$PEER_PORT`. Choose an unused port distinct from `PORT`.
For a local-only run, leave `ADVERTISE_URL` unset and set `NO_TUNNEL=1`.
Other tunables: `MEMBER_BIN`, `DATA`, `FROSTD_URL`, `LWD_URL`, `NETWORK`.

### Upgrade from a version that logged pairing links

Both launchers now use a private pipe and keep diagnostics separate from pairing. Use an
owned, mode-0700 data directory on a local filesystem, under a parent you trust. Keep its
passphrase file at mode 0600; never replace it to rotate a session token.

Stop affected member processes before restarting with the updated launcher and binary.
Stopping the old process revokes its bearer, and the new process generates a fresh one;
replace any saved wallet pairing link. Without opening or copying their contents, restrict
or dispose of old member logs and any captured launcher output according to your retention
policy. Preserve the profile state and its existing passphrase. Before reusing a legacy
`run-member.sh` data directory, confirm that it and its passphrase are owned by you and
are not symlinks, then restrict them to modes 0700 and 0600 respectively. The test-stack
launcher still requires a new root; keep any old root needed for custody or recovery.

### Binaries

Build the macOS arm64 member binary (what `run-member.sh` defaults to):

```sh
( cd core && cargo build --release --features relay-communication --bin loki_member_app )
# -> core/target/release/loki_member_app   (Mach-O arm64)
```

Linux x64 is **not cross-built here** — this Mac has no x86_64-linux C cross-linker, and the
crate has native deps, so a bare `cargo build --target x86_64-unknown-linux-gnu` fails at link.
Build it on a Linux x64 box, or on this Mac via Docker (present):

```sh
# native, on a Linux x64 host:
cargo build --release --features relay-communication --bin loki_member_app

# or cross-build from macOS with Docker:
docker run --rm -v "$PWD":/src -w /src/core rust:1.91 \
  cargo build --release --features relay-communication --bin loki_member_app
# -> core/target/release/loki_member_app   (ELF x86_64); point run-member.sh at it with MEMBER_BIN=
```

### Owned-relay operator kit (above)

The `bringup.sh` relay/admission stack is the operator-side enrollment/admission toolkit
and is independent of the frostd DKG path. For a member app that uses it, pass the relay
kit (`--operator-bundle inputs/bundle`, `--operator-key $(xxd -p -c 256 inputs/config-key)`,
`--enrollment-issuer <root>/issue-enrollment`, `--development-http`). The bundle, key, and
issuer executable are the member's relay kit; never copy the private operator seeds or
provision files into a member root. A member app on another machine cannot use these
literal loopback origins.

`compose.hosted-test.yml` is an alternative runner for already initialized
roots. It requires `LOKI_OWNED_RELAY_IMAGE`, `LOKI_OWNED_RELAY_{1,2,3}_ROOT`,
`LOKI_OWNED_ADMISSION_IMAGE`, `LOKI_OWNED_ADMISSION_ROOT`, and
`LOKI_OWNED_OPERATOR_INPUTS`; the final variable names the generated `inputs/`
directory. The image variables need operator-built images containing the two
service binaries. The scripts above run the binaries directly and do not need
those environment variables.

Build the communication workspace with Rust 1.89 and the PoC signer with Rust 1.91. Enable `relay-communication` for the signer. `setup-fault-injection` is an opt-in debug acceptance feature; release compilation rejects it. Never deploy that acceptance build.

Each of the three relay stores has its own persistent root, signing key, run identifier and provisioning capability. Serve its private loopback listener through a TLS reverse proxy. Initialize with an immutable HTTPS public origin matching the proxy hostname; neither forwarded headers nor redirects change the trusted endpoint. Clients verify the platform certificate chain and hostname and the signed relay challenge against the operator bundle. Listen/private origin and signed/public origin are separate settings.

The owned relay and admission listeners cap open HTTP/1 connections at 128 each,
request headers at 16 KiB, and header reads at five seconds. Admission gives
unverified body reads up to three seconds in a separate pool (four per TCP peer).
`/health` does not use the request or body pools, but shares the connection cap.
The backend counts the socket peer, not `Forwarded` or `X-Forwarded-For`, so
clients behind a proxy share its backend allowance. Enforce per-client connection
and body limits at the TLS proxy using client identity established at that boundary.

The admission service requires a signed operator bundle, its trusted configuration key, its own signing key and the three provisioning files. Keep operator capabilities exclusively on the service hosts, outside any member data root. Give them mode 0600 and their parent directories mode 0700. Admission provisioning records contain owner-generated verifiers; the service never creates member read/admin secrets. Store the admission SQLite database and its tombstones on durable encrypted storage. Back up the database coherently, including its WAL or a SQLite backup, and test recovery before operating it. Reusing an operation ID with changed bytes is refused.

Configure an enrollment verifier explicitly. Creation is denied when no issuer is configured. Production enrollment issuance is an integration with the chosen authentication and abuse-control system; this branch does not choose or deploy that provider. The signer supports a scoped grant for its saved creator identity or a configured issuer executable. The executable receives only the public device signing key, operator bundle path and policy and returns a signed grant on stdout. Do not put issuer private keys or operator capabilities in the signer. Issuance failure retains the pending identity, and native setup persists the exact successful grant before an admission request. Owned fixtures use test keys solely in private disposable roots.

Mailbox quotas, setup deadlines and invitation first-claim expiry come from signed configuration. A successful same-identity claim remains retrievable after invitation expiry. Admission terminal state does not erase certified payment mailboxes or nonce claims: setup inboxes retire separately, and existing payment retention remains unchanged. Activation requires every certified member's signed vote and two common physically provisioned relay identities. An admission outage leaves saved setup pending; it does not authorize payment readiness, replace the operator bundle or rerun DKG.

Renew TLS certificates without changing the signed hostname or relay key/run. Changes to relay identities, public origins, admission keys or configuration trust require an explicitly reviewed rotation. Existing ceremonies retain their recorded bundle and pins; retries never select replacement operators silently. Monitor quota pressure, provisioning retries, terminal retirement and admission backups without logging bearer capabilities, invitation secrets, recovery words, DKG packages or sealed-state plaintext.

The supplied compose file describes one owned loopback acceptance environment with three separately initialized persistent relay roots and one admission root. Set each `LOKI_OWNED_RELAY_1_ROOT`, `LOKI_OWNED_RELAY_2_ROOT` and `LOKI_OWNED_RELAY_3_ROOT` to a different new private root; initialize its own key/run and use ports 39101–39103 in the signed development bundle. It is not evidence of operator independence or separate-device HTTPS acceptance. Production deployment remains gated on operator/enrollment decisions, distinct-host TLS acceptance and independent review of invitation trust, checkpoint serialization, backup and payment handoff. Regtest acceptance does not approve mainnet custody.
