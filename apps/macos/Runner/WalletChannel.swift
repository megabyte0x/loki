import AppKit
import FlutterMacOS
import UniformTypeIdentifiers

@_silgen_name("loki_member_app_wallet_request")
private func loki_member_app_wallet_request(_ path: UnsafePointer<CChar>, _ body: UnsafePointer<CChar>?,
    _ export: Int32) -> UnsafeMutablePointer<CChar>?

@MainActor
final class WalletChannel {
    private let channel: FlutterMethodChannel
    private let signer: NativeSigner
    private let validLaunch: Bool
    /// Why this launch can't open a profile, shown instead of pairing or unlocking.
    private let launchProblem: String?
    private weak var window: NSWindow?
    /// Held for the life of the process; see `lockProfile`.
    private static var profileLock: Int32 = -1
    // At most one invite claim from an associated-domain link, held in memory only and never
    // logged. It is bound to the pinned coordinator and slot and never invokes a wallet method.
    private var claim: (code: String, coordinator: String, slot: Int)?
    private static weak var current: WalletChannel?
    private static var early: URL?

    init(messenger: FlutterBinaryMessenger, window: NSWindow) {
        channel = FlutterMethodChannel(name: "cash.loki/wallet", binaryMessenger: messenger)
        #if LOKI_VISUAL_ONLY
        let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let args: [String]? = ["--data", root.appendingPathComponent("LokiSignerVisual").path]
        #else
        let args = Self.launchArguments(CommandLine.arguments.dropFirst())
        #endif
        let signerArgs = nativeSignerArguments(args ?? [])
        if args == nil {
            launchProblem = "Invalid LokiSigner launch arguments."
        } else if let index = signerArgs.firstIndex(of: "--data"), index + 1 < signerArgs.count,
                  !Self.lockProfile(signerArgs[index + 1]) {
            launchProblem = "This profile is already open in another LokiSigner window. Use that window, or quit it first."
        } else {
            launchProblem = nil
        }
        validLaunch = launchProblem == nil
        self.window = window
        #if !LOKI_VISUAL_ONLY
        // Connects the member's fixed diagnostic events to ~/Library/Logs/LokiSigner.
        SignerLog.start()
        #endif
        signer = NativeSigner(args: signerArgs, link: nil, walletWindow: window)
        signer.promptChanged = { [weak channel] active in
            channel?.invokeMethod("nativePromptChanged", arguments: active)
        }
        // Any end of an unlocked session drops a claim held for it. A link that arrives later,
        // while locked, stays for the next explicit unlock.
        signer.sessionEnded = { [weak self] in self?.claim = nil }
        channel.setMethodCallHandler { [weak self] call, result in
            DispatchQueue.main.async {
                guard let self else { result(FlutterMethodNotImplemented); return }
                self.handle(call, result: result)
            }
        }
        Self.current = self
        if let url = Self.early { Self.early = nil; _ = offer(url) }
    }

    /// The app delegate passes HTTPS links here, on cold launch or while running.
    static func receive(_ url: URL) -> Bool {
        guard let current else { early = url; return true }
        return current.offer(url)
    }

    private func offer(_ url: URL) -> Bool {
        #if LOKI_VISUAL_ONLY
        return false
        #else
        guard validLaunch, let target = signer.pairedTarget,
              let code = Self.inviteCode(url, origin: target.coordinator) else { return false }
        claim = (code, target.coordinator, target.slot)
        channel.invokeMethod("inviteArrived", arguments: nil)
        return true
        #endif
    }

    /// Only `https://<pinned coordinator>/#invite=<code>` is a claim. The query form, other hosts,
    /// paths, credentials and extra fragment fields are ignored, like the web wallet does.
    static func inviteCode(_ url: URL, origin: String) -> String? {
        guard let link = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let pinned = URLComponents(string: origin),
              link.scheme == "https", pinned.scheme == "https",
              let host = link.host?.lowercased(), host == pinned.host?.lowercased(), link.port == pinned.port,
              link.user == nil, link.password == nil, link.query == nil, link.path.isEmpty || link.path == "/",
              let fragment = link.percentEncodedFragment, fragment.hasPrefix("invite="),
              let code = String(fragment.dropFirst(7)).removingPercentEncoding,
              (1...4096).contains(code.utf8.count),
              code.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 })
        else { return nil }
        return code
    }

    /// Dart takes the claim once the profile is unlocked; a claim for another profile is dropped.
    private func takeInvite() -> String? {
        guard let held = claim, signer.walletReady else { return nil }
        claim = nil
        guard let target = signer.pairedTarget, target.coordinator == held.coordinator, target.slot == held.slot else { return nil }
        return held.code
    }

    /// One process per profile folder: two LokiSigners on one profile would run two signers on the
    /// same nonce and payment state. The lock file sits beside the folder, so a fresh folder stays
    /// fresh. Returns false only when another process holds the lock.
    private static func lockProfile(_ data: String) -> Bool {
        let path = (data as NSString).standardizingPath + ".lock"
        let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        // A folder whose parent can't hold a lock file fails later with its own error.
        guard fd >= 0 else { return true }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(fd); return false }
        profileLock = fd
        return true
    }

    private static func launchArguments(_ arguments: ArraySlice<String>) -> [String]? {
        // Only process launch arguments may configure peers; ignore Flutter/Launch Services flags.
        var flags: [String] = []
        var rest = arguments.makeIterator()
        while let option = rest.next() {
            let supported = ["--data", "--port", "--peer", "--peer-port", "--advertise-url"]
            if supported.contains(where: { option.hasPrefix($0 + "=") }) { return nil }
            if !supported.contains(option) { continue }
            guard let value = rest.next(), !value.isEmpty, !value.hasPrefix("--") else { return nil }
            flags.append(contentsOf: [option, value])
        }
        return flags
    }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any]
        let noArgs = call.arguments == nil || call.arguments is NSNull
        let invalid = failure(400, "Invalid wallet method arguments.")
        let busy = failure(409, "Finish the current LokiSigner review or operation first.")
        switch call.method {
        case "nativePromptActive":
            guard noArgs else { result(invalid); return }
            result(signer.nativePromptActive)
        case "leaveNativePrompt":
            guard noArgs else { result(invalid); return }
            signer.leaveNativePrompt()
            result(nil)
        case "nativeNotice":
            guard noArgs else { result(invalid); return }
            result(signer.walletNotice)
        case "profile":
            guard noArgs else { result(invalid); return }
            guard validLaunch else { result(failure(400, launchProblem ?? "Invalid LokiSigner launch arguments.")); return }
            var profile = signer.walletProfile()
            profile["can_recover_wallet_key"] = signer.canRecoverWalletKey
            profile["reduce_motion"] = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
            if #available(macOS 26, *) { profile["liquid_glass"] = true }
            // Several signers on one Mac: name each window by its member slot (Mission Control,
            // the Window menu and the Dock list it even though the title bar hides it).
            window?.title = (profile["slot"] as? NSNumber).map { "LokiSigner — Member \($0)" } ?? "LokiSigner"
            if profile["profile"] is String { result(profile) }
            else { result(failure(500, SignerStartFailure.dataFolderUnavailable.message)) }
        case "pendingInvite":
            guard noArgs else { result(invalid); return }
            result(takeInvite())
        case "unlock", "pair", "restore", "recoverWalletKey", "discardPendingProfile":
            let link = args?["link"] as? String
            guard call.method == "pair" ? (link != nil && args?.count == 1) : noArgs else { result(invalid); return }
            guard validLaunch else { result(failure(400, launchProblem ?? "Invalid LokiSigner launch arguments.")); return }
            #if LOKI_VISUAL_ONLY
            result(failure(403, "This visual-only build cannot unlock, pair or restore a signer."))
            #else
            // A new or restored profile must not inherit a claim bound to the old one.
            if call.method != "unlock" { claim = nil }
            guard signer.beginWalletOperation({ error in
                if error == .cancelled { self.claim = nil }
                if let error {
                    let status = error == .cancelled ? 499 : (error == .unlock ? 401 : 400)
                    result(self.failure(status, error.message))
                } else { result(nil) }
            }) else { result(busy); return }
            if let link { signer.pairWallet(link: link.trimmingCharacters(in: .whitespacesAndNewlines)) }
            else if call.method == "restore" { signer.restoreWallet() }
            else if call.method == "recoverWalletKey" { signer.recoverWalletKey() }
            else if call.method == "discardPendingProfile" { signer.discardPendingProfile() }
            else { signer.unlockWallet() }
            #endif
        case "lock":
            guard noArgs else { result(invalid); return }
            claim = nil
            if !signer.lockWallet({ result(nil) }) { result(busy) }
        case "addresses":
            guard noArgs else { result(invalid); return }
            run(result, work: { nativeReply(loki_member_app_vault_addresses()) }) { reply in
                guard loki_member_app_can_view_addresses() != 0 else {
                    result(self.failure(401, "LokiSigner is locked.")); return
                }
                guard let rows = reply["vaults"] as? [[String: Any]] else {
                    result(self.failure(500, reply["error"] as? String ?? "Couldn’t check vault addresses.")); return
                }
                result(rows.map { row -> [String: Any] in
                    guard row["address"] != nil, row["network"] as? String != "testnet" else { return row }
                    var row = row
                    row.removeValue(forKey: "address")
                    row["error"] = "This vault is not on testnet."
                    return row
                })
            }
        case "request":
            guard let path = args?["path"] as? String, !path.isEmpty, path.utf8.count <= 256, !path.contains("\0"),
                  args?.keys.allSatisfy({ $0 == "path" || $0 == "body" }) == true else { result(invalid); return }
            let body = args?["body"]
            var json: String?
            if let body, !(body is NSNull) {
                guard let map = body as? [String: Any], JSONSerialization.isValidJSONObject(map),
                      let data = try? JSONSerialization.data(withJSONObject: map), data.count <= 1024 * 1024 else {
                    result(invalid); return
                }
                json = String(decoding: data, as: UTF8.self)
            }
            request(path: path, body: json, result: result) { result($0) }
        case "export":
            guard let vault = args?["vault"] as? String, args?.count == 1, isHexID(vault) else { result(invalid); return }
            let id = vault.lowercased()
            request(path: "recovery-backup?vault=\(id)", export: true, result: result) { reply in
                guard reply["vault"] as? String == id, let backup = reply["backup"] as? String, !backup.isEmpty,
                      let data = try? JSONSerialization.data(withJSONObject: ["vault": id, "backup": backup]),
                      data.count <= 256 * 1024 else { result(self.failure(500, "Invalid encrypted backup.")); return }
                guard !self.signer.walletDialogOpen else { result(busy); return }
                let panel = NSSavePanel()
                panel.title = "Save encrypted LokiSigner backup"
                panel.allowedContentTypes = [.json]
                panel.nameFieldStringValue = "loki-recovery-\(id).json"
                guard panel.runModal() == .OK, let file = panel.url else { result(self.failure(499, "Backup save cancelled.")); return }
                guard self.signer.walletReady else { result(self.failure(401, "LokiSigner is locked.")); return }
                do {
                    try data.write(to: file, options: .atomic)
                    result(nil)
                } catch { result(self.failure(500, "Couldn’t save the encrypted backup.")) }
            }
        case "explorer":
            guard let txid = args?["txid"] as? String, args?.count == 1, isHexID(txid),
                  let url = URL(string: "https://testnet.zecblock.com/tx/\(txid.lowercased())") else { result(invalid); return }
            if NSWorkspace.shared.open(url) { result(nil) }
            else { result(failure(500, "Couldn’t open the transaction explorer.")) }
        case "appearance":
            guard let mode = args?["mode"] as? String, args?.count == 1 else { result(invalid); return }
            switch mode {
            case "light": NSApp.appearance = NSAppearance(named: .aqua)
            case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
            case "system": NSApp.appearance = nil
            default: result(invalid); return
            }
            result(nil)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func request(path: String, body: String? = nil, export: Bool = false, result: @escaping FlutterResult,
                         complete: @escaping ([String: Any]) -> Void) {
        run(result, work: {
            nativeReply(path.withCString { path in
                if let body { return body.withCString { loki_member_app_wallet_request(path, $0, export ? 1 : 0) } }
                return loki_member_app_wallet_request(path, nil, export ? 1 : 0)
            })
        }) { reply in
            let status = reply["status"] as? Int ?? 500
            let data = reply["data"] as? [String: Any] ?? [:]
            if (200..<300).contains(status) { complete(data) }
            // Backend text can quote a relay or lightwalletd; neutralise it before Flutter shows it.
            else { result(self.failure(status, untrustedText(data["error"] as? String ?? "LokiSigner request failed."),
                                       code: data["code"] as? String)) }
        }
    }

    private func run(_ result: @escaping FlutterResult, work: @escaping () -> [String: Any],
                     complete: @escaping ([String: Any]) -> Void) {
        if !signer.performWalletWork(work, complete: { reply in
            if let reply { complete(reply) }
            else { result(self.failure(401, "LokiSigner is locked.")) }
        }) { result(failure(401, "LokiSigner is locked.")) }
    }

    /// `code` is the host's stable error code; the wallet maps it to its own wording.
    private func failure(_ status: Int, _ message: String, code: String? = nil) -> FlutterError {
        FlutterError(code: String(status), message: message, details: code)
    }

    private func isHexID(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }
    }
}
