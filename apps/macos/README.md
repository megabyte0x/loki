# Build the macOS runner

Use an Apple Silicon Mac with Xcode 26 or later, native `aarch64-apple-darwin` Rust, CMake and Flutter (3.50.1 on the satellite). The sidebar uses AppKit Liquid Glass on macOS 26 and Flutter blur on older supported macOS versions. From the repository root:

```sh
export PATH="$HOME/tools/flutter/bin:$HOME/.cargo/bin:$PATH"
cd apps
flutter pub get
flutter build macos --debug --config-only
```

`--config-only` prepares the Flutter configuration, plugin package and `macos/Flutter/ephemeral/Flutter{Inputs,Outputs}.xcfilelist` without building or signing the app. Run it before invoking `xcodebuild` on a fresh checkout. If your Flutter SDK omits the empty file lists, seed them once with `touch macos/Flutter/ephemeral/FlutterInputs.xcfilelist macos/Flutter/ephemeral/FlutterOutputs.xcfilelist`; Flutter's Xcode phase fills them on the first build.

Xcode builds the Rust library with `apple-enclave,relay-communication`, stages the matching Swift Enclave dylib under Derived Data, and embeds/signs it in the app. Debug uses the Cargo `dev` profile; Profile and Release use `release`. The app and standalone signer use the same profile path by default; quit one before opening the other on that profile.

## Provisioned testnet build

Set `LOKI_DEV_TEAM` to the Apple Developer team used for the standalone signer. That team needs the `cash.loki.signer` App ID and the same Keychain access group (`$(AppIdentifierPrefix)cash.loki.signer`). Sign in to the team in Xcode and allow it to provision this Mac:

```sh
: "${LOKI_DEV_TEAM:?Set the Apple Developer Team ID for cash.loki.signer}"
xcodebuild -workspace macos/Runner.xcworkspace -scheme Runner -configuration Debug \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$PWD/build/native-provisioned" \
  -allowProvisioningUpdates DEVELOPMENT_TEAM="$LOKI_DEV_TEAM" build
app="$PWD/build/native-provisioned/Build/Products/Debug/loki_signer.app"
codesign --verify --deep --strict "$app"
codesign -d --entitlements - "$app"
open "$app"
```

For a provisioned Release build, prepare with `flutter build macos --release --config-only`, then use `-configuration Release` in the Xcode command and `Build/Products/Release` for the app path. Do not pass the ad-hoc signing or visual-only overrides below to a provisioned build.

Pair with the one-use `loki://pair` link the coordinator's wallet issues for your member slot. Paste it in **Pair this Mac**; LokiSigner checks the whole link without a network request and shows its coordinator origin and slot before it contacts anything. A bare origin admits no one. The coordinator must serve a **testnet** `/api/signer-config` with HTTPS endpoints for frostd, lightwalletd and both nonce witnesses. The embedded app rejects loopback HTTP even on the same Mac. Real pairing, restore and signing use the existing Secure Enclave/Touch ID policy. A valid signature and matching provisioning profile are needed for the existing profile's Keychain items. An existing profile unlocks and reconnects without a new link.

Pairing never asks for a witness fingerprint. LokiSigner trusts the coordinator's nonce witness pair the first time and saves it. After each unlock it checks the coordinator once in the background; if the coordinator now serves a different pair, LokiSigner shows **The coordinator changed its nonce witnesses** with both fingerprints. Signing keeps the saved pair until you choose **Trust new witnesses** and confirm with Touch ID; the new pair applies from the next unlock. Only trust it if the coordinator's operator told you the witnesses changed. Otherwise choose **Keep current witnesses** and contact the operator.

The workspace footer shows the active signer's pinned origin as **Paired coordinator**. It is read-only and does not indicate whether the coordinator is reachable.

### Vaults across Macs

New vaults use relay invites. Each invite carries the creator's identity, and every member reaches the creator through **its own** configured frostd relay. Neither the creator's HTTP port nor the relay or endpoint named in the invite is contacted, so the creator needs no reverse proxy or `--peer` flag, and a loopback creator endpoint in the invite is expected. LokiSigner refuses a relay invite with a missing or malformed creator identity, or when this signer has no usable relay, instead of falling back to HTTP. The creator must be unlocked while members join and set up; locking ends its setup work and unlocking resumes it.

In **Set up vault**, **Copy invite** copies `https://<paired coordinator>/#invite=<code>` (the code alone if no HTTPS origin is pinned). Send each member their own link privately. A joiner pastes the link or the bare code in **Join vault**. The query form `/?invite=…` is refused, as in the web wallet. The review shows the vault name, policy and slot from the invite; they are unverified until the signer enrolls. Joining approves no payment, and the roster comparison stays a separate step that every member completes over a trusted channel.

An older invite without a creator identity, or a joiner on a LokiSigner build without relay invites, reaches the creator over HTTPS instead. The creator then serves only the four ceremony routes (`/api/enroll`, `/api/roster`, `/api/agreed`, `/api/session`) on a second loopback listener, `--peer-port`. Put a TLS reverse proxy for its public origin in front of that port and nothing else. Never forward `--port`: it is the private member API. `--peer-port` and `--advertise-url` must be given together, and the advertised origin is also the creator endpoint written into its invites. Pass flags as separate arguments, with canonical HTTPS origins, no trailing slash, path, query or credentials:

```sh
# On the creator (quit an existing LokiSigner instance before relaunching).
# The TLS proxy for https://creator-peer.example forwards to 127.0.0.1:3611 only.
open "$app" --args --peer-port 3611 --advertise-url https://creator-peer.example

# On a joiner holding an older invite from that creator:
open "$app" --args --peer 1=https://creator-peer.example
```

For legacy invites the joiner must configure the exact creator origin with `--peer`, even if that origin is also its paired coordinator. A pasted invite cannot set a new network destination. The Runner also accepts `--data /absolute/path` to select a different local profile. Quit the app before changing launch flags. Relay invites need none of these flags.

### Several members on one Mac (testnet)

To test a 2-of-3 vault alone, run one LokiSigner process per member profile:

```sh
apps/macos/scripts/run-members.sh 3   # or APP=/path/to/loki_signer.app apps/macos/scripts/run-members.sh 3
```

Member 1 uses the default profile and members 2 and up use `~/Library/Application Support/LokiSigner-memberN`. Once paired, each window is titled **LokiSigner — Member N** in Mission Control, the Window menu and the Dock. Each profile folder can be open in only one process at a time: a second LokiSigner on the same `--data` folder refuses to pair or unlock and says the profile is already open. The lock file sits next to the folder (`<folder>.lock`).

### Opening invite links in the app (operator setup)

Pasting the link into **Join vault** always works. Opening `https://<coordinator>/#invite=…` directly in LokiSigner additionally needs a verified association between the coordinator's domain and a signed build; this repository does not ship one, and self-hosted coordinators without it keep using paste. There is deliberately no custom URL scheme for invites, because any app could claim it. To associate a domain you operate:

1. Add `com.apple.developer.associated-domains` with `applinks:<coordinator host>` to the entitlements of your provisioned build, and enable Associated Domains for the App ID. Do not add a domain you do not control.
2. Serve `https://<coordinator host>/.well-known/apple-app-site-association` as `application/json` without redirects:

   ```json
   {"applinks": {"details": [{"appIDs": ["<TEAM_ID>.<bundle id>"], "components": [{"/": "/", "#": "invite=*"}]}]}}
   ```

LokiSigner accepts an opened link only when its host, port and scheme equal this profile's paired coordinator, with no query, path or extra fragment fields. It keeps at most one such invite in memory, never logs or saves it, and does not raise its window. After you unlock, the invite opens in **Join vault** for review once you leave any form you were filling in. Locking, cancelling unlock, pairing or restoring drops it, and leaving that review discards it. A link never pairs a signer, changes its relay, joins without your confirmation or approves a payment.

## Ad-hoc build and window capture

Use a separate bundle identity and the explicit visual-only compiler flag. This build still links the real backend, but it cannot pair, unlock or restore and does not access the production profile or its Keychain group.

```sh
xcodebuild -workspace macos/Runner.xcworkspace -scheme Runner -configuration Debug \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath "$PWD/build/native-visual" \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM= PROVISIONING_PROFILE_SPECIFIER= \
  CODE_SIGN_ENTITLEMENTS=Runner/Visual.entitlements PRODUCT_BUNDLE_IDENTIFIER=cash.loki.signer.visual \
  'SWIFT_ACTIVE_COMPILATION_CONDITIONS=DEBUG LOKI_VISUAL_ONLY' build
app="$PWD/build/native-visual/Build/Products/Debug/loki_signer.app"
codesign --verify --deep --strict "$app"
open "$app"
mkdir -p ../.amp/in/artifacts
screencapture -i -w -o ../.amp/in/artifacts/lokisigner-window.png
```

In the Mac desktop session, click the LokiSigner window when the camera cursor appears. Do not capture any passphrase, recovery words or backup dialogs from the provisioned build.
