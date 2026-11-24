# S4a keyless coordinator

Next publishes a **public roster** and the UI. It does not start signers, unlock profiles,
store member capabilities, proxy device calls, or perform signing. `core/src/host/payment.rs`
runs in each **member-owned process**, including share loading and S1 consent. DKG and
payment relay traffic still goes directly from those processes to frostd; S2 share storage,
S3 nonce state and the two Gap-C witnesses are unchanged.

## Co-located development

Use Node.js 24 or newer. For a disposable software-signer stack, see
[`selfcustody-testnet.sh`](../../communication/deploy/README.md). For a separate local
coordinator, start Next in this directory (see [admission and rate limits](#admission-and-rate-limits)):

```sh
LOKI_REGISTRY=/absolute/path/public-roster.json npx next dev --hostname localhost -p 3001
```

To pair a native LokiSigner, type this coordinator's address in LokiSigner. For a direct
headless start, see the [member binary example](../../communication/deploy/README.md)
and configure both nonce witness routes. Keep each member's data and local unlock
file separate. Save recovery words privately when shown.

The member process creates/unlocks its profile **locally**, then authorizes its P-256 device
key with its existing Ed25519 identity. It requests a one-use challenge and signs a transcript
binding the coordinator origin, requested slot, identity keys, advertised endpoint and nonce.
Replacing a registered device also requires a fresh identity signature for that coordinator,
new key, challenge, and next generation. The coordinator saves the new device, consumed proof,
and public roster together; a former device cannot rotate back using its old enrollment proof.
This proves key possession, **not hardware attestation**. The software development backend
and an Enclave key produce the same wire proofs.

Open `http://localhost:3001`. For the headless member or an older app, paste its **local
pairing link into the pairing field**, never into the address bar or a message to an operator.
For an updated LokiSigner, select its slot and choose **Connect LokiSigner**; compare the
code and allow in the app instead of pasting a link. The tab stores the capability in
`sessionStorage` (duplicating a tab can copy it) and calls that loopback endpoint with
`X-Loki-Token`; no capability is sent to Next. The member restricts browser access to the
configured origin, and the wallet checks the member's public identity against the roster.
A roster update cannot silently retarget a connected tab. Logout locks the device and, on
updated LokiSigner, revokes all wallet-tab grants. A web restart does not restart members.

A LokiSigner member compares the roster code in LokiSigner, not on this page: **Compare in
LokiSigner** opens LokiSigner's dialog, and only its **Codes match** records the agreement
(see `core/signer-app/README.md`). The page knows LokiSigner asks because the member's vault
status reports `roster_dialog`. A headless member paired with this tab (`loki_member_app`,
`LokiSigner serve`) does not, so the page shows the signer's 24-digit code. Compare all 24
digits before confirming. After confirming the roster, a member stays on **Verify members**
until the creator has all confirmations and publishes the relay session. Waiting
for people has no key-generation timeout. A creator lock or temporary disconnect can be retried before key generation starts;
an unlocked member restarted during that wait retains its confirmation. Once key generation
has started, an interruption requires **Create a new vault**, new invitations, and a new code
comparison by every member. The failed vault and its diagnostic error remain available.

`LOKI_DEV_FAUCET=1` enables the optional local-origin regtest faucet; it receives only a public
regtest address. It is off by default, and the supplied launcher binds Next to localhost.

## Production coordinator behind TLS

After building, use `npm start` (the custom server). It listens on `127.0.0.1:$PORT`
(`3001` by default), with `http://localhost:$PORT` as the local development origin.
Point a same-host TLS proxy or tunnel at that loopback address and set `PUBLIC_ORIGIN`
to the exact external HTTPS origin, for example `https://wallet.example`. This replaces
`HOSTNAME` and `PUBLIC_PORT`. The coordinator uses `PUBLIC_ORIGIN`, not client forwarding
headers, to reconstruct the origin for member registration.

## In-browser signer: enroll → discover → DKG

An in-browser signer (`src/lib/signer.ts`, the wasm core in `core/loki-signer-wasm`) has no
local HTTP server, so it enrolls as a **frostd-only member with no `advertise_url`** — peer
traffic goes over the frostd relay (peer-over-frostd), and the roster stores `advertise_url: ""`
for it. Native members still advertise their loopback origin and enroll exactly as before; both
coexist in one roster. A browser member has completed a real **2-of-3 DKG** over the live relay.

**Serving the signer.** `scripts/copy-signer.mjs` (wired to `predev`/`prebuild`) stages the built
`core/loki-signer-wasm/{pkg,signer-worker.js,signer-client.js}` and `core/wasm-transport/pkg` into
`public/signer/` (gitignored), keeping the worker's relative `./pkg/...` + OPFS-snippet imports
intact. `signer.ts` then defaults to the served worker at `/signer/signer-worker.js`: a HEAD
probe confirms the asset before binding the `Worker`, so `browserSigner` is the default whenever
the bundles are present and a build without them degrades cleanly to the in-memory mock. Build
the bundles first — `RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target
web` in `core/loki-signer-wasm`, and `wasm-pack build --target web` in `core/wasm-transport`.

1. **Create / unlock** the signer (passkey or passphrase). The device `Identity` is held in the
   Worker.
2. **Enroll** — `enroll(coordinatorOrigin?)` (default: same origin):
   - the Worker returns `enrollMaterial()` → `{signing_pubkey, relay_pubkey}` (the relay key is
     the frostd-login pubkey);
   - the browser generates a non-extractable **WebCrypto P-256 device key** (persisted in
     IndexedDB, reused on re-enroll) and the Worker's `authorizeDevice()` signs it with the
     member identity — the same Ed25519/P-256 proof as `core/src/host/registration.rs`;
   - `POST /api/members/challenge` → the browser signs the
     registration transcript with the device key and proves possession of the relay key against
     the coordinator's one-use X25519 challenge → `POST /api/members` returns the member and slot.
3. **Discover** the ceremony params. The public coordinator (this Next app) owns only the roster;
   the DKG session is run by the vault **creator** (slot 1), which serves `vaultHex`, the setup
   doc (`rosterHex`, `setup_version: 2`), the frostd `sessionId` and `coordinatorPeer` from its
   ceremony endpoints (`/api/roster`, `/api/session`, see `core/src/host/ceremony.rs`). The UI/parent
   supplies these to the signer. **Not built here:** a browser-reachable discovery surface for the
   creator's session (CORS/TLS + invite delivery, or a vault-announcement endpoint in this app) —
   see the handoff below.
4. **DKG** — `request("dkg", {vaultHex, slot, label, network, rosterHex, coordinatorPeer,
   sessionId})` drives `driveDkg()` to an active vault + address. `signer.ts` folds `frostdUrl`
   and `transportUrl` into every ceremony/payment call from **deployment config**: set the TLS
   relay with `NEXT_PUBLIC_FROSTD_URL`, and `transportUrl` defaults to the served
   `/signer/wasm-transport/pkg/loki_wasm_transport.js` (override with
   `NEXT_PUBLIC_SIGNER_TRANSPORT_URL`). The frostd endpoint must be reachable over **https/wss
   with CORS** — a browser cannot use a loopback-plaintext relay.

Onboarding (create/unlock → Home) works standalone; the full ceremony above needs that live
coordinator + frostd. Payment review/approve are wired through `request()` the same way.

## Registry and limits

`/api/members` returns only public roster rows: `{slot, signing_pubkey, relay_pubkey,
advertise_url, lokisigner_url?}`. The optional signed `lokisigner_url` field tells everyone
reading `/api/members` that the slot uses LokiSigner and which loopback port it currently
listens on. It is not a capability. Deploy this coordinator and wallet before updating
LokiSigner; see the [version matrix](../../core/signer-app/README.md#build-and-pair). A visited
website can use the port and the open ceremony routes to learn whether LokiSigner is running,
subject to local network permission.
Safari may block the wallet's loopback request; this has not been verified.

Native setup and recovery use `GET /api/members?signing_pubkey=<lowercase hex>` to look up
at most one public row without downloading the roster.

The coordinator stores the roster, device generations, recent sign-up times, and challenges in one owner-only
snapshot at `.access.json` (or `LOKI_REGISTRY`). Before upgrading, stop all old coordinator
workers and back up the registry and any legacy `.devices` sidecar together. Update signer
clients for the relay proof, and reissue pairing links. Do not run old and new workers on the
same registry or roll back to the old split-file format. Older registries containing hosted
secrets still fail closed. Legacy out-of-range rows are preserved but cannot re-enroll. The
adjacent `.mutex.sqlite` file serializes writes; SQLite releases the lock when a process exits.
Do not remove it while any process uses the registry. The roster is discovery, not authority to spend.

Device-local login challenges expire after two minutes, with at most 16 issues per device
session grant and 256 overall in that window. To renew a revoked key, an authorized local
client requests its generation from `POST /api/device-renewal` with `device_pub`. It signs
that generation and public key offline with `RecoveryKey::authorize_device_renewal` and submits
the authorization to `POST /api/device-enroll`. Never send recovery words to the coordinator.

LokiSigner sends a tab its device session only after the member allows that tab's code in
the native app. The coordinator-served JavaScript can still read a grant held by its own tab;
device-side consent remains required for signing. Co-location under one OS account is not
independent custody against that OS operator.

### Admission and rate limits

Anyone who knows the coordinator's address can pair a member: there is no operator step.
A member types the address (for example `loki.megabyte.sh`) in LokiSigner, which asks
`POST /api/members/pairing` for a `loki://pair` link and continues with the usual review,
passphrase and Touch ID. The wallet's own pairing-link step still works the same way.

The coordinator admits at most 16 active members in slots 1–16. A pairing link reserves the
lowest free slot (or the slot it names, to finish a pairing that never registered) for two
minutes, and so does a new identity that enrolls directly (the in-browser signer). Together
these unfinished new-identity reservations can hold at most eight distinct slots, so they
never fill the roster; a further request gets "too many pending registrations". At most 32
registration challenges can be pending in all.
Funds stay protected without an admission gate: joining a vault still needs the creator's
private invite and the roster-code comparison.

The limits below apply only to requests that could admit a **new** identity: a pairing link,
and direct enrollment of an identity the registry doesn't know (claiming a pairing link
spends the reservation its link was counted for). A registered member's roster refresh at
unlock, recovery and device replacement are exempt, but only because the request's
`authorization`, that identity's own signature over its device key, verifies first;
registering then still needs the device signature and the relay proof.

Registry writes come from two separate budgets. New-identity work (pairing links, enrolling,
resuming or claiming for an identity the registry doesn't know) uses one. A registered
member's refresh or replacement, completing an issued proof and operator tools use the other,
so new-identity traffic can never make an existing member wait for "registration is busy". The
per-address check and every cheap refusal (a malformed request, a full roster, no pending
slot, the sign-up cap, a taken slot, an unknown proof) happen before either budget or the
registry lock is spent. Those checks use a parsed copy of the registry kept in memory and
re-read only when the file changes; the locked write checks everything again.

Every request to the direct registration routes (`POST /api/members/challenge` and
`POST /api/members`), members' included, also counts in a generous per-address attempt limit
before any registry access. An unlock is two requests and background retries back off from
five seconds, so only a client hammering the routes reaches it. An identical retry of a
pending registration gets the same challenge without touching the registry lock; other
retries of one pending registration are limited to six a minute for that identity.

The coordinator reads these settings from its own process environment. Changing a service's
environment file or exporting a variable in a shell doesn't reach a running coordinator:
restart it to apply a change.

| Setting | Default | Limits |
| --- | --- | --- |
| `LOKI_SIGNUPS_PER_HOUR` | 6 | New identities registered in a rolling hour, across the coordinator. Stored in the registry. Refreshing or replacing a registered member's device and resuming a pending registration don't count. |
| `LOKI_IP_PAIRING_PER_MINUTE` | 5 | New-identity requests (above) per client address per minute. |
| `LOKI_IP_PAIRING_PER_DAY` | 30 | The same requests per client address per rolling day. |
| `LOKI_IP_REGISTRATION_PER_MINUTE` | 60 | Any direct registration-challenge or proof request per client address per minute, members included. |
| `LOKI_CLIENT_IP_HEADER` | unset | The one header your proxy sets to the client address, for example `cf-connecting-ip` behind a Cloudflare tunnel. |

The per-address counts live in memory, use the process's monotonic clock (a wall-clock
step changes nothing) and reset when the coordinator restarts. The hourly sign-up times are
wall-clock and stored in the registry; a time later than the current clock still counts
until the clock passes it. They track at
most 10,000 addresses. When that's full, addresses idle for a day are dropped oldest first,
and if none are, new addresses share one overflow bucket with the same limits, so they're
still admitted. The coordinator reads only the header named by `LOKI_CLIENT_IP_HEADER`,
takes its first value and accepts it only if it's an IP address. IPv6 addresses are counted
in one canonical spelling, and an IPv4-mapped IPv6 address counts as its IPv4 address. It never trusts `X-Forwarded-For` or any other
client header on its own. Without the setting, or when the header is missing or invalid,
every request shares one bucket, so the limits still apply to everyone together. Set it
only when a proxy you run always overwrites that header.

A refused request gets HTTP 429 with a short plain message and a `Retry-After` header: the
seconds until the exhausted window admits again (up to a day for the daily limit). The coordinator logs one fixed
line per refusal reason, never the client address. A value that isn't a whole number stops
admission until it's fixed. These limits slow spam but don't stop it: the 16 slots can
still fill up.

To permanently retire a roster identity and release its slot, use the same registry path
as the coordinator: `LOKI_REGISTRY=/path/to/registry.json node scripts/retire-member.ts <signing_pubkey>`.
This retains the identity and device tombstones. It does not revoke vault shares or delete
member recovery data.

## Checks

```sh
node --experimental-strip-types --test tests/*.test.mjs scripts/wallet-ui.test.mjs
npx tsc --noEmit
npx next build
```

The end-to-end local registration/restart smoke test is in
`core/scripts/test_self_registration.mjs` (starts isolated member processes explicitly, outside
Next). Run it after building `loki_member_app` with `relay-communication` and the web bundle.

The confirmation regression starts three disposable testnet member processes against a live
`frostd`, delays the remaining confirmations for 22 seconds, locks and restarts the creator,
restarts the waiting member, then checks that all three activate the same vault. From the
repository root, after building `loki_member_app`:

```sh
FROSTD_URL=http://127.0.0.1:2744 node --test core/scripts/test_confirmation_wait.mjs
```

## Payment approval and recovery

### Headless member recovery

The wallet can check recovery status and download an encrypted backup. It cannot display,
confirm, or take recovery words. Use a private terminal on the signer, without logging or recording it.

1. Create a member profile as usual, then stop the member process. Run
   `loki_member_app recovery-setup --data /path/to/member`. Enter the profile passphrase,
   save the 24 words offline, and type `YES` to confirm. Cancelling before `YES` leaves setup
   uncommitted. Already-confirmed words are not shown or replaced. For an unconfirmed legacy
   profile, the command asks for its original words; keep the passphrase backup if you don't
   have them. Interactive startup with `--coordinator-url` still offers setup.
2. Restart the signer. After a vault has a backup, save its **Download encrypted backup** JSON
   off-device. Separately record the SHA-256 fingerprint from the original signer: run
   `shasum -a 256 /path/to/member/vaults/<vault-id>/signer/recovery.backup` on that machine.
   The fingerprint is of the encrypted bytes, not the JSON file. Do not trust a fingerprint
   supplied alongside an untrusted download.
3. On the replacement device, create a fresh profile by starting the member app **without**
   `--coordinator-url`, then stop it. In its private terminal run:

   ```sh
   loki_member_app recovery-restore --data /path/to/new-member \
     --backup /path/to/loki-recovery-export.json --fingerprint <saved-sha256>
   ```

   Use the signer's normal `--network testnet`, `--secure-element apple`, or `--frostd-url`
   settings when applicable. Enter the new profile's passphrase and the original 24 words at
   the hidden prompts. Restart the member app normally and reconnect the wallet using the new
   pairing link. The backup must match the independently saved fingerprint and the vault's roster.

The browser signer displays its own fingerprint during export and asks for it on restore.
For a legacy browser backup, hash the trusted offline `.bin` file.
Existing browser profiles must re-enter their original words in the signer before making new
backups. This does not rewrite existing backup files.

Publishing creates separate encrypted control and signing relay sessions. Each selected member’s
approval inbox discovers pending requests over the control session without a copied attempt ID.
Review the full recipient, amount and fee, then approve on each selected member. Waiting for people
does not start a signing timeout or create a nonce. After quorum, the proposer prepares wallet inputs
and starts the bounded signing round automatically. A saved signed PCZT is required for **Ready to
send**; the proposer can then use **Review & send** and **Confirm and send**. A delayed final send
does not require another signing round. Peer status notices do not establish chain confirmation;
each wallet verifies that locally.

Consent waiting can resume after a member restart. A started signing round cannot restart under
the same attempt ID. Failed attempts retain their diagnostic state and nonce journal. The proposer
can **Discard failed payment** only when no signature share was released and no signed or raw
transaction exists. Discard closes relay sessions, saves a cancellation record, and releases that
attempt’s reserved input; the next payment gets a fresh ID. Ambiguous signed outcomes stay reserved
for recovery. Broadcast retries reuse the saved raw transaction and move input reservations atomically.

The payment regressions use disposable testnet identities and synthetic notes with the live relay;
they never broadcast a transaction:

```sh
FROSTD_URL=http://127.0.0.1:2744 cargo test --manifest-path core/Cargo.toml --locked --offline --features relay-communication --lib host::payment::tests
```

## Browser signer (separate signer origin)

The in-browser signer runs on its **own origin**, not the wallet's. `core/loki-signer-wasm/serve.mjs`
serves the signer page, Worker, wasm and transport. The wallet embeds that page in an iframe and
exchanges only public data with it over postMessage. The passkey PRF ceremony, the passphrase,
the roster-code comparison and every payment approval happen on the signer page. The share
stays in that origin's OPFS.

Local development uses two ports. Build the wasm once (both pkgs are gitignored):

```sh
# in core/loki-signer-wasm
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target web
# in core/wasm-transport
wasm-pack build --target web
```

Then, in web/wallet:

```sh
LOKI_FROSTD_URL=http://127.0.0.1:2744 npm run signer   # signer origin  → http://localhost:3002
npm run dev                                           # wallet         → http://localhost:3001
```

`next dev` points at `http://localhost:3002` by default. A production deploy **must** set
`LOKI_SIGNER_ORIGIN` in the coordinator's environment. It is read at request time and rendered into
the page, so moving the signer needs a restart, not a rebuild. `NEXT_PUBLIC_SIGNER_ORIGIN`, inlined
at build, is still honoured as a fallback. Without either, every signer call fails. There is no
mock fallback in a browser.

`serve.mjs` listens on `127.0.0.1` unless `LOKI_SIGNER_HOST` says otherwise, so publish it through a
reverse proxy or tunnel on the same host. It needs `core/loki-signer-wasm/pkg`; the browser relay
transport (`core/wasm-transport/pkg`) is served only when it was built, which a deployment with
only LokiSigner members can skip.

What a deploy must provide on the signer server (`serve.mjs` env):

| variable | meaning |
|---|---|
| `LOKI_WALLET_ORIGIN` | the one wallet origin allowed to frame and message the signer (`frame-ancestors`, postMessage check) |
| `LOKI_FROSTD_URL` | the frostd relay the signer logs in to. It is shown to the member and not settable from the wallet page. One relay only. |
| `LOKI_RP_ID` | WebAuthn rpId. It **must stay the same across deploys** or passkeys stop unlocking. |
| `LOKI_NONCE_WITNESSES` | the two nonce-witness routes every signature is claimed at (the native `--nonce-witnesses` file). Both witnesses must [enroll each vault signer](../../communication/deploy/README.md#nonce-witness-enrollment-and-upgrades); `config.json` serves only endpoints and pins. |
| `LOKI_NETWORK` | `testnet` (default) or `regtest`; mainnet is refused at startup. A regtest stack **must** set `regtest`, or LokiSigner is told testnet. |
| `LOKI_LIGHTWALLETD_URL` | the lightwalletd native members sync from |
| `LOKI_LIGHTWALLETD_GRPCWEB_URL` | lightwalletd behind gRPC-web + CORS for the signer origin (`communication/deploy/lightwalletd-grpcweb.sh`); the browser signer scans the chain through it for its vault balance and history |
| `LOKI_SIGNER_PORT` | listen port (default 3002) |

Wallet chain results carry `chain_trust: "provider_reported"`. The native and browser
signers check their saved block against the configured lightwalletd, even with no new
blocks. A fork, shorter chain, changed endpoint, or legacy scan with no recorded
endpoint can require a rescan from the vault's birth. The browser tracks the gRPC-web
URL; if the proxy's upstream changes, change the configured URL to trigger a rescan.
These checks do not independently authenticate compact transactions or prove consensus
or inclusion. Use a lightwalletd backed by a node you trust for balances and mining status.

The coordinator (this app) serves the same values to the native signer at
`GET /api/signer-config`: network, frostd, lightwalletd and the witnesses, read from
`${LOKI_SIGNER_ORIGIN}/config.json` on each request. Nothing is copied into the wallet's own configuration. The route answers 502 with an error when the signer origin is unset,
unreachable, redirects, or serves a configuration it cannot validate, and it never serves
mainnet. LokiSigner shows these values when it pairs and saves them (see
`core/signer-app/README.md`).

The signer origin itself must be **stable**. The share (OPFS), the device-login key (IndexedDB)
and the passkey (rpId) are all bound to it. A new hostname per run (for example a fresh
trycloudflare URL) gives an empty signer that cannot open the old share. Only one tab per
storage partition may run the signer: a Web Lock guards the Worker, its share and its nonce
store. Other tabs using that partition refuse signer operations until the first one closes.

Before sharing a browser vault's receive address, choose **Verify on signer** in the vault
and **Open signer address** in the signer prompt. Check the new tab's origin in the browser
address bar, then copy from that tab or compare the full vault ID and address. The read-only
tab cannot be framed. The signer worker derives the address in the wallet's storage partition
and passes only the public vault ID, network and address to the new tab.

To remove a browser signer, save the 24 recovery words and download every vault's recovery
backup before opening **Manage browser signer** in the unlocked wallet. Use **Open signer
controls**, check the separate tab's address is the signer origin, and confirm removal with a
fresh passkey verification or passphrase. Keep the wallet tab open until removal succeeds.
The confirmation page cannot be embedded and does not open browser custody storage. It talks
only to the signer frame that opened it, whose lock-owning worker verifies the credential and removes
the shares from the wallet's actual storage partition. Use the wallet's recovery flow to restore
from the saved words and backup.

When joining a vault, use **Open signer tab** for the member list and again for the roster
code. Check that the tab is on the signer origin at `/approve-roster` before confirming.
For browser recovery setup, backup downloads, and restores, check the signer origin at
`/recovery`. Enter recovery words and verify or record the backup fingerprint only in that
tab. Downloads go directly to the browser, not to the wallet page. Keep the wallet tab open
while using either flow.

For browser payments, use **Open signer tab** and check that the separate tab's address is on
the signer origin at `/approve-payment`. Review the request there if prompted. When the
transaction is ready, open the signer tab to check the transaction details and verify with a passkey or
passphrase. The wallet's embedded signer cannot approve the terms or collect the signing
credential for a payment. Keep the wallet tab open while reviewing and signing.

Before the first payment approval and after a witness identity changes, the signer asks for the
[independently supplied witness fingerprint](../../core/signer-app/README.md#verify-the-witness-pair)
and fresh passkey or passphrase verification. Get the fingerprint from the witness operators
through a trusted channel, not the wallet. Start a fresh signing attempt if the original pair
is unavailable or the pending nonce predates the upgrade.

The signer origin sends a strict CSP: only its own scripts, `wasm-unsafe-eval` for wasm, and connections only to itself, the relay and `LOKI_CEREMONY_ORIGINS`. It answers only from the snapshot it read at startup. `node core/loki-signer-wasm/serve.mjs --hash` prints the published build hash (per-file SHA-256 plus one bundle hash), and a running signer serves the same thing at `/build-hash.json`. Publish the bundle hash with each release so the deployed signer can be compared against it.
