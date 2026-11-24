# LokiSigner — member-owned native signer

The native app claims a `loki://pair` link, sets up a persistent Secure Enclave P-256 device
key for a new profile (or opens the existing key), and runs S4a self-registration. The coordinator receives public enrollment
and a challenge signature. Profile passphrases, local session capabilities and FROST shares
stay on the member device. The FROST share is encrypted with an Enclave-wrapped key; it is
opened in signer memory for signing.

## Build and pair

```sh
LOKI_DEV_TEAM=B399KAT22M bash core/signer-app/build.sh
open core/signer-app/out/LokiSigner.app
```

On the wallet's sign-in screen open **Use a native member app instead**. It has two steps.

1. **Pair a new native signer**: choose **Get a pairing link**. The wallet shows the reserved
   slot, the time left on the link, an **Open LokiSigner** button and **Copy link** (to open
   it on the member's Mac yourself). LokiSigner then asks, in this order:
   - On first launch, LokiSigner checks that Touch ID is available, enrolled and not locked out.
     Setup stops if it isn't ready. Read the fingerprint-change warning and choose **Pair a new
     signer** (or see restore below if this is a replacement Mac).
   - "Pair this device with slot N?" with the coordinator origin. Choose **Continue** only if
     it is the wallet's address.
   - "Pair this device with slot N?" again, with the network and endpoints that coordinator
     chose (see below). Enter a local profile passphrase and choose **Pair**. Approve the
     Enclave prompt if macOS shows one.
   - For a new profile, "Save your recovery words privately". Write them down, then choose
     **I saved these words**.
   - "LokiSigner is running". Choose **Done**.

   The coordinator and pairing configuration dialogs ignore input for the first second after
   taking focus. Return and Enter do not confirm either dialog; Escape cancels.

   While the link is out the wallet watches the public roster. Once the slot appears there,
   the wallet says so and you can continue to step 2. The roster alone cannot tell you whose
   app registered the slot. Compare the code on your own Mac before allowing the tab. When the two
   minutes run out first, the link and copy button go away; **Get a new link** asks for the
   same slot again. A lapsed slot can go to another member: the wallet then says the slot was
   taken, and the next link uses another slot. The wallet never asks for a new link by itself,
   because each one reserves a slot.
2. **Connect this wallet tab**: on **that same Mac**, unlock LokiSigner, select its slot in
   the wallet, and choose **Connect LokiSigner**. If the app is still registering, the tab
   retries for up to a minute, then offers **Try again**. When LokiSigner asks, check the
   wallet origin and match the six-digit code in the app to the one in the tab, then choose
   **Allow**. If they do not match, choose **Refuse**. The dialog ignores input for the first
   second after taking focus. Tab starts on **Refuse**, Space activates the focused button,
   Escape refuses, and Return and Enter do not answer. Nothing is copied. Allow local
   network access if your browser asks.

The app stays running for ceremony, payment review and signing using the existing device
consent and nonce-witness paths. Connect separately in each new tab and after a relaunch. In
the **LokiSigner** menu, **Disconnect all wallet tabs** withdraws existing grants without
quitting or locking the app. Wallet logout locks the profile and revokes all wallet-tab grants.
Quit also invalidates every grant; launch again to unlock and register with the saved public
coordinator/slot, without reusing the claim.

With saved settings, you can unlock and use local features such as **Vault addresses…** and
**Restore a vault…** while the coordinator is offline. If registration fails or is refused,
LokiSigner shows a warning, stays unlocked and keeps trying in the background. A launch with
a new pairing link waits for the registration result before reporting success.

If you cancel, enter the wrong passphrase, or LokiSigner cannot start, choose **Try again**
or **Quit**. If the coordinator refuses a pairing, retry the saved pairing or get a new link
from the wallet. When the existing profile has no vault data, **Start over…** lets you set it
aside before pairing or restoring. Choose it from the **LokiSigner** menu or a retry dialog.
Opening a pairing link while the signer is running does not interrupt it or replace its profile.
LokiSigner moves the whole data folder to a dated sibling;
it deletes neither the folder nor its old keys in the Keychain. New and restored native profiles
save a public random `native-key-scope`. The device login key and each new vault key use that
scope and a distinct role, so they keep the same tags when the folder moves on the same Mac and
do not reuse the prior profile's keys at the same path. Existing path-based tags stay unchanged,
including vaults written when only the device key used the scope. An empty `native-scoped-vault-key`
marker beside a new vault's seals records that it uses the scoped tag. Keep both files with the
profile if you move it.

After a validated Apple device registration, LokiSigner writes an empty
`device-registration-confirmed` marker in the profile. It contains no secrets and is not
written during restore staging. Without that marker, a missing device key may be created
only if the saved coordinator's roster can be read and does not list this profile’s identity.
An unreadable roster does not authorize key creation.

New Secure Enclave keys record the public LocalAuthentication enrolment state in a
`biometry-state` file beside the corresponding sealed data. LokiSigner uses a change in that
state to distinguish a fingerprint change from a failed match; it never stores fingerprints.
When setup reuses a key left by an interrupted attempt, it verifies one private-key use
before sealing new data under that key.

`NativeSigner.start` checks Touch ID once when it sees a fresh profile, before pairing or
first-run recovery asks for a passphrase or words. **Restore a vault…** checks it before
collecting words in an unlocked profile. Neither check runs in `serve` or the headless binary.

Adding or removing a fingerprint invalidates this Mac's signer keys. Copying a profile to
another Mac does not copy its keys. LokiSigner does not create a replacement when opening
sealed data. If you only moved an older profile that uses path-based tags on the same Mac,
putting the folder back at its original path can recover access. A cancelled Touch ID prompt
does not invalidate the key.

**Update the coordinator and wallet before updating LokiSigner.**

| Coordinator and wallet | LokiSigner | What the member sees |
| --- | --- | --- |
| Old | Old | Paste the private link displayed by LokiSigner. |
| New | Old | The wallet still offers the paste flow for an older app. |
| Old | New | First pairing shows a refusal; a saved profile opens with a registration warning and retries. The old wallet offers only paste, and the new app has no link to paste. |
| New | New | Select the member slot, choose **Connect LokiSigner**, and compare the code before allowing. |

`loki_member_app` and `LokiSigner serve` still use their printed pairing link. Once a new
LokiSigner has registered, **do not roll back the coordinator** without removing the roster
rows containing `lokisigner_url`. The old coordinator rejects those rows as an “unexpected
registration field,” breaking `/api/members` for everyone, not just those slots.

The signed `lokisigner_url` roster field tells everyone who can read `/api/members` that the
slot uses LokiSigner and which local port it currently listens on. The field is separate
from the peer endpoint and contains no tab token. If your browser allows local network
requests, another website may be able to tell that LokiSigner is running. Four ceremony
routes accept requests from other origins so browser signers can join a vault, but require
a valid invite to take part. Their replies can also reveal whether the profile is locked.
Blocking other origins from reading responses would not by itself hide the local listener.

Only the paired coordinator's website can ask to connect from a browser. LokiSigner cannot
tell another program on your Mac apart from the wallet when it asks to connect. It can open
a dialog as often as every five seconds, but it still needs an **Allow** in LokiSigner.
Refuse any request you didn't start. While a dialog is pending or fewer than five seconds
have passed since the last request started, your own tab may also have to wait.

The grant stays in the approved page's memory. Duplicating a tab or reloading the page
requires a new **Allow**. The wallet remembers the last slot so you can reconnect. The
coordinator serves the page but never receives the grant during registration. Safari may
block the HTTPS wallet's request to LokiSigner on this Mac; this has not been verified.

## Back up and restore a vault

After your vault is active, choose **Download encrypted backup** in the wallet's **Recovery**
card. The ciphertext is stored in your LokiSigner profile on this Mac, not by the coordinator.
**Keep the downloaded JSON somewhere other than this Mac.** If you lose the Mac and the file,
the 24 words alone cannot recover the vault. Export one file per vault and store your words
privately, separately from the files. Independently save each backup’s SHA-256 fingerprint
from the original export. You’ll need it to authenticate the backup at restore time.

For older exports, get the fingerprint from the original signer, or calculate it from an
offline copy you already trust: hex-decode the JSON `backup` value, then SHA-256 the resulting
ciphertext bytes (not the JSON file or the hex text). Use that fingerprint with the same
exported ciphertext. A hash computed from an untrusted download, or supplied with it, does
not establish authenticity. If you have neither an independent fingerprint nor a trusted
copy or original signer, LokiSigner cannot safely restore that backup.

On a new Mac, open LokiSigner without a pairing link. Choose **Restore from recovery words**,
enter the original coordinator's HTTPS origin, confirm it, and review the signer configuration.
Choose one backup file in LokiSigner, enter its independently saved fingerprint and 24 words,
and set a new local profile passphrase. LokiSigner checks the fingerprint before opening the
backup, then checks that both recovered public identity keys identify
exactly one slot in the coordinator's roster. It saves the recovered vault and identity together,
then registers the new Mac in that slot without reserving a new one. If the connection fails
after saving, keep LokiSigner running or reopen and unlock it to retry. If the coordinator
refuses the slot before the first successful registration, LokiSigner checks the member list
again and uses a different slot only when exactly one entry matches both public identity keys.
You won't need the words again to reconnect. Use **Connect LokiSigner** to connect each
wallet tab on the new Mac.

Restore can reuse an absent or empty data folder, or one with only recognized leftovers: empty
`profile/` or `device-auth/` directories, the public `native-key-scope` file, incomplete
pairing or signer-settings `.tmp` files, and an empty `vaults/` directory or one holding only
generated restore staging directories. Restore preserves these leftovers in a dated sibling.
Anything unrecognized requires you to confirm **Start over…** before it is moved. Any other
entry in `vaults/`, a `vaults` file, a legacy `card` entry, or top-level `vault.card`,
`vault.sealed`, or `share.sealed` protects the profile from ordinary set-aside. LokiSigner tries
to clear expired `.loki-restore-<UUID>` directories at startup, both in `vaults/` and beside
the data folder. Symlinks to the data folder still work; set-aside keeps the link pointing to
the newly emptied location and archives the old contents beside its target.

If you already paired a different member by mistake, choose **Start over…** from the retry
dialog or when **Restore a vault…** says the backup does not match the running profile. Confirm
**Set aside and start over**, then choose **Restore from recovery words**. A profile with vault
data is protected from this ordinary action. To restore a different member in that case, use
another Mac or macOS account.

When LokiSigner confirms that a vault or device key is missing or invalidated, it offers
**Set aside profile…** even if the profile holds vault data. This stops the signer and renames
the old folder without deleting it or any Keychain record. Choose **Restore from recovery words**
to restore into the original folder with fresh keys. Keep the archived folder until you have
verified every restored vault. A failed match, cancellation, or lockout does not grant this
exception. For older keys without enrolment metadata, a failed match can only offer a recovery
hint, not confirm that the key is gone.

A key that macOS cannot find counts as gone. That can also happen if you moved a profile
created before #95 (whose key tags depended on the folder path), or if you opened it with an
app signed by a different Apple developer team. Try the original path and signing team before
restoring. If you already set the profile aside, quit LokiSigner and rename the archived folder
back to its original name and location to undo the set-aside. If a new profile now occupies that
location, move it out of the way without deleting it first.

Restore each additional backup from **LokiSigner → Restore a vault…** in the unlocked app.
It needs the same independent fingerprint check and must belong to the same member and recovery
words. It will not replace an existing vault.
After the replacement registers, the coordinator's device binding and advertised endpoint
point to the new Mac; the member slot and identity keys stay the same. This does not erase or
revoke the old Mac's local share. Quit and retire the old signer if you still have it: a Mac
that still holds the identity can register another device binding again.

LokiSigner refuses HTTP recovery setup and restore. It continues serving recovery status and
the encrypted backup. The headless `loki_member_app` and `LokiSigner serve` **do** keep HTTP
setup and restore for automation; their authenticated callers handle the words directly.
The native restore field is masked, with spell checking and autocorrection off. LokiSigner
clears the field and Rust wipes the writable FFI buffer after copying it. Swift/AppKit do not
guarantee that transient string or text-editor copies are wiped from process memory. Do not
copy your words into the system clipboard or type them into the wallet.

## Verify a receive address

In the **LokiSigner** menu, open **Vault addresses…**. Each active vault shows its network,
your member slot, and the full vault ID and receive address with a **Copy address** button.
macOS may ask for Touch ID when LokiSigner first opens a vault's signer store. Use **Refresh**
if you finish setting up a vault while the window is open. The window clears when the signer locks.

Give senders the address copied from LokiSigner, or expand **Vault ID** and **Address** in the
wallet and compare both full values before sharing. A page served by the coordinator could substitute a different
address and redirect deposits. LokiSigner derives the address from the device-bound signer's
group viewing key and checks it against the local public metadata. If it cannot verify a
vault's address, it shows an error and offers nothing to copy. Vault names are creator-supplied
labels, not instructions from LokiSigner.

## Roster code

Before key generation every member compares the vault's 24-digit roster code with the others,
so a coordinator cannot swap a member in. For a LokiSigner member the wallet page cannot agree
to a roster by itself. When the member chooses **Compare in LokiSigner** on the wallet's
**Verify members** step, LokiSigner shows "Do the roster codes match?" with the threshold,
the member count, the member's slot, the network and the code. Rust derives the code from the
same setup document the signer checks in `dkg_begin`. The vault name comes from the creator's
invite. It follows the same rule as in **Vault addresses…**: it is shown as written, in its own
one-line box, or replaced whole by "Name hidden (unsupported characters)" when it is longer
than 80 characters or holds a control, format, default-ignorable or line-breaking character
or a run of more than three combining marks. A name without a letter is also hidden, so a name
made of digits and spaces cannot look like a second roster code.

- **Codes match** records the agreement and tells the creator.
- **Codes differ** records nothing, and LokiSigner refuses that vault until it restarts, so a
  page cannot reopen the dialog until the member gives in. If you choose **Codes differ** by
  mistake, restart LokiSigner to clear the refusal and compare again.
- Pressing Escape, closing the dialog or leaving it unanswered for 10 minutes records nothing;
  the member can ask again.

LokiSigner shows one roster dialog at a time. While it is open the member's other requests
continue, and when the roster or the setup changed in the meantime the answer is refused.

The roster and payment dialogs come to the front, but their buttons are disabled for the first
second each time the dialog takes focus. Clicks and keystrokes during that second are ignored.
Once the buttons are enabled, click a button or use Tab (or Shift-Tab) to focus it and press
Space. No button starts focused. The first Tab reaches **Codes differ** or **Refuse** so that
Tab then Space cannot agree to a roster or approve a payment. Return and Enter never answer.
Escape refuses a payment and dismisses a roster comparison without recording an answer.

When LokiSigner starts signing a payment, macOS asks for Touch ID once for that attempt.
The reason is “unlock signing for <amount> ZEC to <short recipient>”. It names the reviewed
amount and recipient, not the memo or vault name. Touch ID unlocks the signing key; it does
not approve the payment. Check the full recipient and other details LokiSigner reads from the
transaction, then choose **Approve and sign** or **Refuse**. A mismatch cannot be signed.
Cancelling Touch ID fails the attempt, and a new attempt (even a retry) asks again. Opening a
vault or using **Vault addresses…** may ask for Touch ID separately.

The roster dialog and the payment dialog are both modal on the app's main thread. A payment
request that arrives while the roster dialog is open waits until the member answers it or it
times out, and only then shows its own dialog. Ten minutes may be longer than the
coordinator waits for this member's approval, so answer the roster dialog before approving
payments.

The headless member (`loki_member_app`, `LokiSigner serve`) has no screen. It keeps the earlier
behaviour: `POST /api/agree` with the right code agrees, so it trusts whoever holds its session
token to have compared the code with the other members.

## Signer configuration

LokiSigner needs no terminal or flags. The coordinator proposes the network, frostd relay,
lightwalletd and two nonce witnesses at `GET <origin>/api/signer-config`. They are the
values its signer origin gives the browser signer (`LOKI_NETWORK`, `LOKI_FROSTD_URL`,
`LOKI_LIGHTWALLETD_URL` and `LOKI_NONCE_WITNESSES` in `core/loki-signer-wasm/serve.mjs`).

- **Coordinator first.** Opening a pairing link first shows only the coordinator origin and
  slot, read from the link by Rust without any network request. LokiSigner contacts that
  coordinator only after the member confirms it is the one they intended.
- **Shown before saved.** It then fetches the configuration and shows the network and every
  endpoint beside the coordinator origin, with the passphrase field. LokiSigner runs with
  exactly the values shown, without fetching again.
- **Checked locally.** LokiSigner treats the reply as untrusted. It refuses unknown fields,
  mainnet, remote endpoints without TLS (loopback HTTP only with `--development-http`),
  endpoints containing whitespace, control or non-ASCII characters, and witnesses that hosted
  signing would refuse. The request follows no redirect and times out. The app shows a fixed
  message on failure, not the coordinator’s reply or HTTP status.
- **Saved once unlocked, and pinned.** The configuration is saved only after the local profile
  unlocks. The coordinator origin, network, endpoints, witness pair and its fingerprint are
  atomically saved together in the owner-only (0600) `signer-config.json`. A legacy `nonce-witnesses.json`
  is never used with the new configuration. A wrong passphrase saves nothing. LokiSigner refuses
  configuration from another coordinator without changing the saved configuration. A new pairing
  link for the same coordinator and slot refreshes it once the member confirms and unlocks.
  Quit the running signer before opening a link to refresh its configuration.
- **Unlock.** A plain launch shows and uses the saved configuration. A profile paired before
  configurations were saved fetches it once from its paired coordinator.
- **Flags.** An explicit `--network`, `--frostd-url`, `--lightwalletd-url` or
  `--nonce-witnesses` overrides the value for that field **for this launch only**. When a flag
  overrides a fetched value, nothing is saved, because the member was shown the flag's value
  and not the coordinator's.
- **Nothing to run with.** When a launch still lacks the network, frostd, lightwalletd (on
  testnet) or the witnesses, LokiSigner reports that it couldn’t load settings. It never
  falls back to regtest defaults.
- **Regtest deployments.** The signer origin's `LOKI_NETWORK` defaults to `testnet`. A regtest
  stack must set `LOKI_NETWORK=regtest` on the signer origin, or LokiSigner is told testnet.

This applies only to the native app's pairing and unlock. `LokiSigner serve` and the headless
`loki_member_app` keep their flags and defaults.

Pairing reserves a slot for 120 seconds. Both claim and registration are consumed once,
including failed proofs; claiming does not extend the deadline. If it expires while saving
recovery words, choose **Get a new link** in the wallet, which asks for the same slot (or,
if another member took it meanwhile, a new one). After
a lost response, choose **Try again** and unlock; an outstanding reservation may need to expire before
retry. Public device bindings prevent a different identity or slot from reusing the enrolled
key.

The default data directory is `~/Library/Application Support/LokiSigner`; default listener
is a dynamically chosen loopback port. Production coordinator links require HTTPS. Local
HTTP coordinators need an explicit development launch:

```sh
core/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner native --development-http
# Or launch with member configuration, then click Open LokiSigner in the wallet:
core/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner native \
  --data /path/to/member --port 3601 --development-http \
  --frostd-url http://127.0.0.1:2744 --nonce-witnesses /path/to/witnesses.json
```

Do not pass a pairing link on a command line. Automation can launch `native --pairing-stdin`
and supply a single link followed by a newline over standard input from a private pipe.

Other member flags are the existing `loki_member_app` flags: network, lightwalletd, relay,
nonce witnesses, and peer allowlist. Each overrides the coordinator's value for its field,
for that launch only. Members on separate Macs join over frostd: the invite names the creator's
identity, each joiner seals its requests to the creator on the shared relay, and the creator
answers while it is unlocked. The creator exposes no endpoint for this, but every member must
use the same frostd (`--frostd-url`). Older invites without the creator's identity still join
over HTTP. For that HTTP ceremony, the creator needs a reachable
HTTPS `--advertise-url` and a separate `--peer-port`. Terminate TLS on a same-host proxy
forwarding only to the ceremony listener at `127.0.0.1:<peer-port>`. Confirm that origin with
the creator separately from the invite, then add it to each joiner's `--peer <slot=origin>`
allowlist.
The origin must resolve to public addresses; the joiner verifies TLS and does not follow redirects.
Loopback origins on non-privileged ports are for co-located regtest or deliberate
`--allow-loopback-peers` runs only.
Never forward the private browser API listener (`--port`); it requires a loopback bind.
The link contains only origin, slot and a random claim, never runtime configuration or keys;
the configuration comes from that origin, as described above.
The native passphrase is passed to Rust in memory and the Swift byte buffer is immediately
zeroed. `serve` retains S4a's local-file unlock for development automation only.

### Nonce witness changes

Members never type a witness fingerprint. LokiSigner trusts the coordinator's witness pair
only while the profile has no paired coordinator yet: a first pairing or a fresh restore. That
pin is saved before the profile can sign, with the coordinator's full witness pair (keys, run
IDs, mailboxes and URLs), even when launch-only flags keep the endpoints themselves unsaved; if
the save fails, pairing or restore stops. A `--nonce-witnesses` file is launch-only too: that
launch signs with it, but the pin is always the coordinator's pair. Unlocks run with the saved pair, so keeping it never
depends on the coordinator. A paired profile with no saved pin treats any pair as a change.
An existing pin is replaced only by a change the member approved with Touch ID, never by a
retry, a refresh or a `--nonce-witnesses` launch (which keeps the saved pin). First use applies
only when no pin exists. A pin that changed after the configuration was shown, or an approved
change that can't be saved, stops startup and LokiSigner says so. If the new record is in place
but its save can't be confirmed durable, LokiSigner says that the next unlock will most likely
use it. With launch flags, the review shows which pair this launch signs with and which pair the
next launch without flags uses.

Every native launch (the wallet app, and the standalone app's native and serve modes, pairing,
restore and witness approval) holds an exclusive lock on `<profile>.lock`, beside the profile
folder, for its whole life. The lock is keyed on the folder's resolved absolute path, so a
symlink, `.` or relative path to the same profile shares it. While one process holds it, no
other can pair, restore, unlock or write that profile. After locking, the session reads and
writes the profile only through the resolved path, so moving a symlink can't redirect it. Later:

- **After each unlock** LokiSigner asks the paired coordinator once, in the background, for its
  current `/api/signer-config`. A failed request is only logged; signing continues.
- **A different pair** opens "The coordinator changed its nonce witnesses" with the saved and
  new fingerprints (short form, full value selectable). **Keep current witnesses** is the
  default and the Escape action and changes nothing; the screen may appear again after a later
  unlock. Like a payment request, it never activates the app and waits for the member to focus it.
- **Trust new witnesses** needs Touch ID. LokiSigner then fetches the configuration again and
  saves the new pair only if the coordinator still serves exactly that pair and the saved
  configuration is still the one this unlock runs with. Only the pair and its fingerprint change. The running signer
  keeps the saved pair until the member locks and unlocks again. Nothing switches silently.
- **A pairing link or refresh** that brings a different pair for the same coordinator shows
  the same screen before the configuration review; pairing continues only after Touch ID.
- A `--nonce-witnesses` launch flag overrides the pair for that launch and never prompts. With
  any launch flag override, the background check is skipped, because nothing would be saved.
- An approval applies only to the profile that is still running. If LokiSigner locks or the
  profile is set aside before the save, nothing is written.

Payments already in progress keep the pair they started with: their nonce records are bound to
it. Operators can compute a pair's fingerprint from their trusted `--nonce-witnesses` JSON file,
for members who want to compare it with the screen:

```sh
node -e '
const pair = JSON.parse(require("node:fs").readFileSync(process.argv[1]));
const hash = require("node:crypto").createHash("sha256");
hash.update("Loki_nonce_witness_pins_v1\0");
for (const { key, run, mailbox } of pair) {
  for (const field of [key, run, mailbox]) hash.update(Buffer.from(field));
}
console.log(hash.digest("hex"));
' /path/to/witnesses.json
```

Tell members before you rotate witnesses, through a channel they trust independently of the
wallet. The fingerprint covers both witnesses' relay keys, run IDs and mailbox IDs in file order, not
their URLs or credentials. An explicit local `--nonce-witnesses` file is itself trusted operator
configuration. Outstanding attempts using legacy nonce records or a different pair need a fresh
signing attempt, even after the replacement is approved. Do not delete existing burn records or
relay claim history when upgrading or rotating witnesses.

## Verification

With a built wallet (`cd web/wallet && npm run build`) and Rust member binary:

```sh
node core/scripts/test_self_registration.mjs --pairing
# Exercise the signed app instead; approve the local Enclave prompts:
LOKI_NATIVE_SIGNER=1 \
LOKI_MEMBER_APP_BIN="$PWD/core/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner" \
node core/scripts/test_self_registration.mjs --pairing
```

For a complete real paired signing/payment run, use a running web coordinator, frostd,
lightwalletd, nonce witnesses, and the existing funded testnet fixture. This test **broadcasts
a testnet payment**, keeps member state in the printed private temporary directory, and
requires native consent/Touch ID:

```sh
LOKI_NATIVE_SIGNER=1 \
LOKI_MEMBER_APP_BIN="$PWD/core/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner" \
LOKI_COORDINATOR=http://localhost:3001 \
LOKI_NONCE_WITNESSES=/path/to/witnesses.json \
FROSTD_URL=http://127.0.0.1:2744 \
LIGHTWALLETD_URL=https://testnet.zec.rocks:443 \
RECIPIENT='<testnet Orchard address>' AMOUNT_ZAT=100000 \
bash core/scripts/test_payment.sh
```

## One-time setup (done)
- Apple ID in Xcode → Settings → Accounts.
- **Apple WWDR intermediate** installed (otherwise the Dev cert is "invalid"):
  `curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer && security import AppleWWDRCAG3.cer -k ~/Library/Keychains/login.keychain-db`
- Team: `B399KAT22M`. Touch ID present (biometric mode works).

## Build + run (the one GUI step that provisions a free-team profile)
```sh
cd core/signer-app && ruby gen.rb        # regenerates LokiSigner.xcodeproj (needs the xcodeproj gem)
open LokiSigner.xcodeproj               # in Xcode: select the LokiSigner scheme, Product → Run (⌘R)
```
The first GUI **Run** registers this Mac as a dev device and generates the provisioning
profile (free teams can't do this headlessly). The console prints:
```
SIGNER-APP ENCLAVE PASS: persistent wrap/unwrap of a signer DEK
```
After that first run the profile exists; subsequent `xcodebuild … -allowProvisioningUpdates`
builds work headlessly.

- `LokiSigner persist`   — create + reload a persistent SE key, wrap/unwrap (no biometric).
- `LokiSigner biometric` — same, gated by **Touch ID** on unwrap (interactive).

## Native signer: the real Rust signer seals its share in the Enclave

`./build.sh` builds the Rust signer as a static lib (`libloki_poc.a`, `--features
apple-enclave`), links it + the Swift Enclave backend into the app, and runs:

```
RUST SIGNER ENCLAVE PASS: FROST share sealed + reloaded under the persistent Secure Enclave key
```

The app calls `loki_signer_enclave_selftest()` (`core/src/enclave_ffi.rs`), which runs the
actual signer path — `SealedShare::seal` under `AppleSecureElement::create_persistent` — so the
member's FROST share is held in a persistent, device-bound, biometric-capable Secure Enclave
key, **inside the provisioned app**. Built entirely on the Mac (crates.io + Enclave + Xcode).
Arch must be `arm64` (matches the Rust lib). `libs/` is regenerated by `build.sh`, not committed.
