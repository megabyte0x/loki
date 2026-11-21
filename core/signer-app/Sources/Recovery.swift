import AppKit
import LocalAuthentication
import UniformTypeIdentifiers

enum SignerStartFailure: Error, Equatable {
    case cancelled, pairingLinkNeeded, invalidLink, differentPairing, configuration, coordinatorOrigin
    case savedEndpointsRefreshFailed
    case invalidProfileName, emptyPassphrase, unlock, deviceKey, registrationRefused, registrationFailed, unexpected
    case missingRecoveryInput, missingRecoveryWords, invalidBackup, backupMismatch, badBackupFingerprint, wrongProfile
    case vaultExists, rosterUnavailable, rosterMismatch, restoredButStopped, unlockToRestore
    case notFresh, dataFolderUnavailable, protectedProfile, setAsideFailed
    case key(String), keyGone(String), registrationRosterUnavailable, testnetOnly

    var keyIsGone: Bool {
        if case .keyGone = self { return true }
        return false
    }

    var message: String {
        switch self {
        case .cancelled: return "You cancelled. Try again to continue setting up or unlocking LokiSigner."
        case .pairingLinkNeeded: return "Open a pairing link from the wallet, then try again."
        case .invalidLink: return "This pairing link isn’t valid. Get a new link from the wallet and open it in LokiSigner."
        case .differentPairing: return "This link is for a different coordinator or member slot. Unlock your existing profile or use a link for its slot."
        case .configuration: return "LokiSigner couldn’t load its settings. Check your connection and try again."
        case .testnetOnly: return "The LokiSigner wallet only supports testnet. This coordinator did not provide a testnet configuration."
        case .savedEndpointsRefreshFailed: return "A saved server address contains a path LokiSigner no longer supports. LokiSigner couldn’t load updated settings from your paired coordinator. Check that you can reach the coordinator, or ask its operator for help, then try again."
        case .coordinatorOrigin: return "Enter the original coordinator’s HTTPS address, without a page or path, and try again."
        case .invalidProfileName: return "Choose a short, single-line profile name without invisible formatting characters, or leave it blank to use Member."
        case .emptyPassphrase: return "Enter your local profile passphrase and try again."
        case .unlock: return "LokiSigner couldn’t unlock this profile. Check your passphrase and try again."
        case .deviceKey: return "This Mac couldn’t use the device key LokiSigner needs to connect. Try again, or set aside the profile if it has no vaults."
        case .registrationRefused: return "The coordinator refused this pairing. Try again to use the saved slot. If it has gone to another member, ask the coordinator for a new pairing link."
        case .registrationFailed: return "LokiSigner couldn’t finish connecting to the coordinator. Check your connection and try again."
        case .registrationRosterUnavailable: return "LokiSigner couldn’t reach the coordinator. Check your connection, then try again."
        case .key(let message), .keyGone(let message): return message
        case .unexpected: return "LokiSigner couldn’t finish this step. Try again."
        case .missingRecoveryInput: return "Enter your recovery words and a new local passphrase, then try again."
        case .missingRecoveryWords: return "Enter your recovery words and try again."
        case .invalidBackup: return "Choose a valid LokiSigner recovery backup file and try again."
        case .backupMismatch: return "LokiSigner couldn’t restore this vault. Check the recovery words and backup, then try again."
        case .badBackupFingerprint: return "Enter the matching 64-character SHA-256 fingerprint from your original signer or a known-good offline copy. Don’t use a fingerprint supplied with an untrusted file."
        case .wrongProfile: return "These recovery words or this backup don’t match the unlocked profile. Check that they belong to this member and try again."
        case .vaultExists: return "This vault already has data in the profile. LokiSigner didn’t replace it. Choose a different backup."
        case .rosterUnavailable: return "LokiSigner couldn’t read the coordinator’s member list. Check the coordinator and your connection, then try again."
        case .rosterMismatch: return "The coordinator’s member list doesn’t show exactly one slot for this backup. Check that you entered the original coordinator and try again."
        case .restoredButStopped: return "Your vault was saved. Try unlocking again; you don’t need your recovery words."
        case .unlockToRestore: return "Unlock LokiSigner before restoring another vault."
        case .notFresh: return "This data folder is no longer ready for a first restore. If the profile has no vaults, set it aside and try again."
        case .dataFolderUnavailable: return "LokiSigner’s data folder points to a location this Mac can’t open. Reconnect the drive or fix the folder link, then try again."
        case .protectedProfile: return "This profile holds vault data that may include a share. LokiSigner won’t set it aside. To restore a different member, use another Mac or macOS account."
        case .setAsideFailed: return "LokiSigner couldn’t set aside this profile. Try again."
        }
    }
}

@_silgen_name("loki_member_app_restore_vault")
func loki_member_app_restore_vault(_ words: UnsafeMutablePointer<UInt8>?, _ count: Int,
    _ file: UnsafePointer<CChar>, _ fingerprint: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_restore_profile")
func loki_member_app_restore_profile(_ launch: UnsafePointer<CChar>,
    _ words: UnsafeMutablePointer<UInt8>?, _ wordCount: Int,
    _ pass: UnsafeMutablePointer<UInt8>?, _ passCount: Int, _ file: UnsafePointer<CChar>,
    _ fingerprint: UnsafePointer<CChar>,
    _ notify: NativeNotice,
    _ approve: ApprovalDecision,
    _ confirmRoster: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ connect: ConnectDecision) -> UnsafeMutablePointer<CChar>?

func touchIDSetupAlert(_ error: NSError?) -> NSAlert {
    let code = error.flatMap { $0.domain == LAError.errorDomain ? LAError.Code(rawValue: $0.code) : nil }
    let alert = NSAlert()
    alert.alertStyle = .warning
    switch code {
    case .biometryNotAvailable:
        alert.messageText = "Touch ID is not available right now"
        alert.informativeText = "If you’re using a MacBook, open its lid and try again. To set up LokiSigner, you need a Mac or an accessory with Touch ID."
    case .biometryDisconnected:
        alert.messageText = "Your Touch ID accessory is disconnected"
        alert.informativeText = "Reconnect it and try again."
    case .biometryNotPaired:
        alert.messageText = "No Touch ID accessory is paired"
        alert.informativeText = "Pair it with this Mac and try again."
    case .biometryNotEnrolled:
        alert.messageText = "No fingerprint is enrolled for Touch ID"
        alert.informativeText = "Add a fingerprint in System Settings, then try again."
    case .biometryLockout:
        alert.messageText = "Touch ID is locked out"
        alert.informativeText = "Unlock your Mac with its password, then try again."
    default:
        alert.messageText = "Touch ID cannot be used right now"
        alert.informativeText = "Unlock your Mac and try again in LokiSigner."
    }
    alert.addButton(withTitle: "OK")
    return alert
}

private func touchIDSetupAlertIfNeeded() -> NSAlert? {
    var error: NSError?
    let context = LAContext()
    guard !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return nil }
    return touchIDSetupAlert(error)
}

func touchIDSetupFailure() -> SignerStartFailure? {
    guard let alert = touchIDSetupAlertIfNeeded() else { return nil }
    return .key("\(alert.messageText)\n\n\(alert.informativeText)")
}

func canSetUpWithTouchID() -> Bool {
    guard let alert = touchIDSetupAlertIfNeeded() else { return true }
    alert.runModal()
    return false
}

func firstRunChoice() -> NSApplication.ModalResponse {
    let alert = NSAlert()
    alert.messageText = "Set up LokiSigner"
    alert.informativeText = """
        Pair a new signer, or restore your existing member using its 24 recovery words and an encrypted vault backup file.

        Adding or removing a Touch ID fingerprint makes this Mac’s signer keys unusable. To get your vault back, you’ll need your recovery words and the encrypted backup file downloaded from the wallet.
        """
    alert.addButton(withTitle: "Pair a new signer")
    alert.addButton(withTitle: "Restore from recovery words")
    alert.addButton(withTitle: "Cancel")
    return alert.runModal()
}

// After the main thread hands this off, only the restore worker accesses these buffers.
final class RecoveryInput: @unchecked Sendable {
    let file: String
    let fingerprint: String
    var words: [UInt8]
    var pass: [UInt8]

    init(file: String, fingerprint: String, words: [UInt8], pass: [UInt8]) {
        self.file = file
        self.fingerprint = fingerprint
        self.words = words
        self.pass = pass
    }
}

private func recoveryBackupPicker() -> NSOpenPanel {
    let picker = NSOpenPanel()
    picker.title = "Choose a LokiSigner recovery backup"
    picker.prompt = "Choose backup"
    picker.allowedContentTypes = [.json]
    return picker
}

private struct RecoveryPrompt {
    let fingerprint: NSTextField
    let words: NSSecureTextField
    let pass: NSSecureTextField
    private let newProfile: Bool

    init(newProfile: Bool) {
        self.newProfile = newProfile
        fingerprint = NSTextField(frame: NSRect(x: 0, y: newProfile ? 60 : 30, width: 400, height: 22))
        fingerprint.placeholderString = "Independently saved backup fingerprint (64 hex characters)"
        fingerprint.setAccessibilityLabel("Independently saved backup fingerprint")
        words = NSSecureTextField(frame: NSRect(x: 0, y: newProfile ? 30 : 0, width: 400, height: 22))
        words.placeholderString = "24 recovery words, separated by spaces"
        words.setAccessibilityLabel("24 recovery words")
        pass = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 400, height: 22))
        pass.placeholderString = "New local profile passphrase"
        pass.setAccessibilityLabel("New local profile passphrase")
    }

    var fields: [NSTextField] { newProfile ? [fingerprint, words, pass] : [fingerprint, words] }

    func standaloneAlert() -> NSAlert {
        let alert = NSAlert()
        alert.messageText = "Restore a vault"
        alert.informativeText = "Enter the SHA-256 fingerprint you saved from your original signer or a known-good offline copy, not one supplied with this file. Enter your recovery words here, never on the wallet page."
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: newProfile ? 82 : 52))
        view.addSubview(fingerprint)
        view.addSubview(words)
        fingerprint.nextKeyView = words
        if newProfile { view.addSubview(pass); words.nextKeyView = pass }
        alert.accessoryView = view
        alert.addButton(withTitle: "Restore vault")
        alert.addButton(withTitle: "Cancel")
        return alert
    }

    func review() -> SignerReview {
        let r = SignerReview.self
        let entry = r.field("Backup fingerprint · saved independently", fingerprint) + r.field("24 recovery words", words)
            + (newProfile ? r.field("New local profile passphrase", pass) : [])
        return SignerReview(section: newProfile ? "Recovery · fresh profile" : "Recovery · unlocked profile",
            title: newProfile ? "Restore your signer" : "Restore another vault",
            intro: "Use the backup and words that match this signer’s identity.", content: [
                r.card("Encrypted backup file", [r.label("Backup selected", weight: .semibold),
                    r.label("Selected using the macOS file picker. Its contents stay local.", tone: r.muted)]),
                r.card("Private entry on this Mac", entry + [
                    r.label("Use the fingerprint from your original signer or a known-good offline copy, never one supplied with this file.", tone: r.muted),
                    r.label("Existing vault data will not be overwritten.", tone: r.muted)]),
            ], hint: newProfile ? "Recovery words stay in the local signer." : "Your unlocked profile is kept.",
            actions: [newProfile ? "Restore signer" : "Restore vault", "Cancel"], primary: 0)
    }

    func input(_ response: NSApplication.ModalResponse, file: URL) -> Result<RecoveryInput, SignerStartFailure> {
        guard response == .alertFirstButtonReturn else { return .failure(.cancelled) }
        let anchor = fingerprint.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard anchor.utf8.count == 64, anchor.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            return .failure(.badBackupFingerprint)
        }
        guard !words.stringValue.isEmpty, !newProfile || !pass.stringValue.isEmpty else {
            return .failure(newProfile ? .missingRecoveryInput : .missingRecoveryWords)
        }
        return .success(RecoveryInput(file: file.path, fingerprint: anchor, words: Array(words.stringValue.utf8), pass: Array(pass.stringValue.utf8)))
    }

    func clear() {
        fingerprint.stringValue = ""
        words.stringValue = ""
        pass.stringValue = ""
    }
}

func restoreInput(newProfile: Bool) -> Result<RecoveryInput, SignerStartFailure> {
    // First-run restore was already checked before presenting the setup choice.
    guard newProfile || canSetUpWithTouchID() else { return .failure(.cancelled) }
    // Choose a file before collecting any secret, so the picker never shares a field editor with it.
    let picker = recoveryBackupPicker()
    guard picker.runModal() == .OK, let file = picker.url else { return .failure(.cancelled) }

    let prompt = RecoveryPrompt(newProfile: newProfile)
    let alert = prompt.standaloneAlert()
    let words = prompt.words
    alert.window.initialFirstResponder = prompt.fingerprint
    if let editor = alert.window.fieldEditor(true, for: words) as? NSTextView {
        editor.isContinuousSpellCheckingEnabled = false
        editor.isGrammarCheckingEnabled = false
        editor.isAutomaticSpellingCorrectionEnabled = false
        editor.isAutomaticTextReplacementEnabled = false
        editor.allowsUndo = false
    }
    let result = alert.runModal()
    defer {
        alert.window.endEditing(for: words)
        alert.window.endEditing(for: prompt.pass)
        prompt.clear()
    }
    return prompt.input(result, file: file)
}

@MainActor
func restoreInput(newProfile: Bool, signer: NativeSigner, complete: @escaping (Result<RecoveryInput, SignerStartFailure>) -> Void) {
    // NativeSigner preflights a fresh profile before starting the setup flow.
    if !newProfile, let failure = touchIDSetupFailure() {
        complete(.failure(failure))
        return
    }
    let picker = recoveryBackupPicker()
    picker.begin { response in
        guard response == .OK, let file = picker.url else { complete(.failure(.cancelled)); return }

        let prompt = RecoveryPrompt(newProfile: newProfile)
        signer.presentPrompt(prompt.review(), fields: prompt.fields) { response in
            let input = prompt.input(response, file: file)
            prompt.clear()
            complete(input)
        }
    }
}

func recoveryError(_ reply: UnsafeMutablePointer<CChar>?) -> SignerStartFailure? {
    defer { loki_member_app_free(reply) }
    if let reply,
       let result = try? JSONSerialization.jsonObject(with: Data(String(cString: reply).utf8)) as? [String: Any] {
        if result["restored"] as? Bool == true { return nil }
        switch result["error"] as? String {
        case "key-error":
            if let message = result["key_error"] as? String { return .key(message) }
        case "invalid-backup": return .invalidBackup
        case "backup-fingerprint-mismatch": return .badBackupFingerprint
        case "wrong-profile": return .wrongProfile
        case "vault-exists": return .vaultExists
        case "profile-not-fresh": return .notFresh
        case "data-folder-unavailable": return .dataFolderUnavailable
        case "roster-unavailable": return .rosterUnavailable
        case "roster-mismatch": return .rosterMismatch
        case "restored-but-stopped": return .restoredButStopped
        case "profile-locked": return .unlockToRestore
        case "restore-refused": return .backupMismatch
        default: break
        }
    }
    return .unexpected
}

func showRecoveryResult(error: SignerStartFailure?) {
    let alert = NSAlert()
    alert.messageText = error == nil ? "Vault restored" : "Could not restore vault"
    alert.informativeText = error?.message ?? "LokiSigner rebuilt your share on this Mac. Reopen your vault list in the wallet to see the restored vault."
    alert.addButton(withTitle: "OK")
    alert.runModal()
}
