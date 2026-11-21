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

The workspace footer shows the active signer's pinned origin as **Paired coordinator**. It is read-only and does not indicate whether the coordinator is reachable.

### Vaults across Macs

The coordinator origin is separate from the creator's peer endpoint. The creator places `--peer 1=...` in new invites; without it, those invites name the creator's loopback port and are unusable from a different Mac. Use a reachable TLS reverse proxy to forward the peer routes (`/api/enroll`, `/api/roster`, `/api/agreed`, `/api/session`) to the creator's fixed local port. `--advertise-url` is the member's own registration address; it does **not** set the invite URL. Pass flags as separate arguments, with canonical HTTPS origins, no trailing slash, path, query or credentials:

```sh
# On the creator (quit an existing LokiSigner instance before relaunching):
open "$app" --args --port 3601 \
  --advertise-url https://creator-peer.example --peer 1=https://creator-peer.example

# On a joiner (use its own advertised endpoint if it has one):
open "$app" --args --port 3602 \
  --advertise-url https://joiner-peer.example --peer 1=https://creator-peer.example
```

The joiner must trust the exact creator origin from its own `--peer` flag or its already-paired coordinator; a pasted invite cannot set a new network destination. The Runner also accepts `--data /absolute/path` to select a different local profile. Quit the app before changing launch flags. Keep the member listener on loopback and do not expose unrelated member routes in the reverse proxy.

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
