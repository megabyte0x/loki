import AppKit
import UserNotifications

typealias ConnectCancellation = @convention(c) (UnsafeRawPointer?) -> Int32
typealias ConnectDecision = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?,
    UnsafeRawPointer?, ConnectCancellation) -> Int32
typealias NativeNotice = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Int32
typealias ApprovalDecision = @convention(c) (UnsafePointer<CChar>?, UnsafeRawPointer?, ConnectCancellation) -> Int32

@_silgen_name("loki_member_app_pair")
func loki_member_app_pair(_ launch: UnsafePointer<CChar>, _ pass: UnsafeMutablePointer<CChar>,
    _ notify: NativeNotice,
    _ approve: ApprovalDecision,
    _ confirmRoster: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ connect: ConnectDecision) -> Int32

@_silgen_name("loki_member_app_disconnect_wallet_tabs")
func loki_member_app_disconnect_wallet_tabs()

@_silgen_name("loki_member_app_pairing_target")
func loki_member_app_pairing_target(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_configuration")
func loki_member_app_configuration(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_profile")
func loki_member_app_profile(_ launch: UnsafePointer<CChar>, _ action: UInt32) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_stop")
func loki_member_app_stop() -> Int32

@_silgen_name("loki_member_app_free")
func loki_member_app_free(_ value: UnsafeMutablePointer<CChar>?)

/// One Rust query on this launch: `{"<answer>": ...}` or `{"error": ...}`. Every value shown
/// to the member comes from Rust, which checked it; nothing is parsed from the link here.
private func nativeQuery(_ query: (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?, _ launch: [String: Any]) -> [String: Any] {
    guard let json = try? JSONSerialization.data(withJSONObject: launch), let request = String(data: json, encoding: .utf8) else {
        return ["error": "invalid launch"]
    }
    let reply = request.withCString { query($0) }
    return nativeReply(reply)
}

func nativeReply(_ reply: UnsafeMutablePointer<CChar>?) -> [String: Any] {
    defer { loki_member_app_free(reply) }
    guard let reply = reply,
          let parsed = try? JSONSerialization.jsonObject(with: Data(String(cString: reply).utf8)) as? [String: Any]
    else { return ["error": "invalid reply"] }
    return parsed
}

func retryAlert(_ failure: SignerStartFailure, profile: String?) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = failure == .cancelled ? "LokiSigner paused" : "LokiSigner couldn’t continue"
    alert.informativeText = profile == "vault" && failure == .notFresh
        ? SignerStartFailure.protectedProfile.message : failure.message
    if profile == "vault", [.differentPairing, .wrongProfile, .registrationRefused].contains(failure) {
        alert.informativeText += "\n\n" + SignerStartFailure.protectedProfile.message
    }
    alert.addButton(withTitle: "Try again")
    alert.addButton(withTitle: "Quit")
    if profile == "profile" || (profile == "vault" && failure.keyIsGone) {
        alert.addButton(withTitle: failure.keyIsGone ? "Set aside profile…" : "Start over…")
    }
    return alert
}

func setAsideAlert(recover: Bool = false) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = "Set aside this LokiSigner profile?"
    alert.informativeText = recover
        ? "LokiSigner will rename the entire local data folder, including any vault data. Nothing will be deleted. To restore your vault in the original location, choose “Restore from recovery words”. You’ll need your recovery words and downloaded backup file."
        : "LokiSigner will rename the entire local data folder, including this profile’s identity and pairing settings. Nothing will be deleted. You can then pair a new signer or choose “Restore from recovery words”. To restore, you’ll need your recovery words and downloaded backup file."
    alert.addButton(withTitle: "Cancel")
    alert.addButton(withTitle: "Set aside and start over")
    return alert
}

func registrationWarningAlert(_ message: String, key: Bool = false, recover: Bool = false) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = key ? "LokiSigner is still running" : "LokiSigner is running"
    alert.informativeText = message
    alert.addButton(withTitle: "OK")
    if recover { alert.addButton(withTitle: "Set aside profile…") }
    return alert
}

@_silgen_name("loki_signer_approval_selftest")
func loki_signer_approval_selftest(_ approve: ApprovalDecision) -> Int32

/// Presents a decision requested by the wallet, without accepting input carried over from
/// another window. Keep native buttons so assistive technology can still press them.
func runDecisionAlert(_ alert: NSAlert, timeout: TimeInterval? = nil,
                      escape: NSApplication.ModalResponse,
                      fields: [NSTextField] = [], cancelled: (() -> Bool)? = nil,
                      timeoutResponse: NSApplication.ModalResponse = .abort) -> NSApplication.ModalResponse {
    guard (NSApp.delegate as? NativeSigner)?.lockingForAbsence != true else { return escape }
    alert.layout()
    let window = alert.window
    let buttons = alert.buttons
    var controls: [NSView] = buttons
    controls.append(contentsOf: fields)
    let field = fields.first
    for button in buttons {
        button.keyEquivalent = ""
        button.isEnabled = false
    }
    window.defaultButtonCell = nil
    window.initialFirstResponder = field

    var acceptsInputSince = TimeInterval.infinity
    var enable: Timer?
    let center = NotificationCenter.default
    let becameKey = center.addObserver(forName: NSWindow.didBecomeKeyNotification,
                                       object: window, queue: nil) { _ in
        window.makeFirstResponder(field)
        let deadline = ProcessInfo.processInfo.systemUptime + 1
        let timer = Timer(timeInterval: 1, repeats: false) { _ in
            guard window.isKeyWindow, window.isVisible else { return }
            acceptsInputSince = deadline
            for button in buttons { button.isEnabled = true }
        }
        enable = timer
        RunLoop.main.add(timer, forMode: .modalPanel)
    }
    let resignedKey = center.addObserver(forName: NSWindow.didResignKeyNotification,
                                         object: window, queue: nil) { _ in
        enable?.invalidate()
        acceptsInputSince = .infinity
        for button in buttons { button.isEnabled = false }
    }

    let input = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .leftMouseUp]) { event in
        guard event.window === window else { return event }
        guard event.timestamp >= acceptsInputSince else { return nil }
        guard event.type == .keyDown else { return event }

        let focused = window.firstResponder
        let editing = fields.firstIndex { $0 === focused || (focused != nil && $0.currentEditor() === focused) }
        switch event.keyCode {
        case 36, 76: // Return, keypad Enter
            return nil
        case 48: // Tab / Shift-Tab
            // Keep the field reachable even when macOS Keyboard Navigation is off.
            guard !event.isARepeat else { return nil }
            let reverse = event.modifierFlags.contains(.shift)
            let current = editing.map { buttons.count + $0 } ?? controls.firstIndex { $0 === focused }
            let next = current.map { ($0 + (reverse ? controls.count - 1 : 1)) % controls.count }
                ?? (reverse ? controls.count - 1 : 0)
            window.makeFirstResponder(controls[next])
            return nil
        case 49: // Space
            if editing != nil { return event }
            if !event.isARepeat { buttons.first { $0 === focused }?.performClick(nil) }
            return nil
        case 53: // Escape
            if !event.isARepeat { NSApp.stopModal(withCode: escape) }
            return nil
        default:
            return event
        }
    }

    NSApp.activate(ignoringOtherApps: true)
    let deadline = timeout.map { ProcessInfo.processInfo.systemUptime + $0 }
    let interval = cancelled == nil ? timeout : 0.1
    let expiry = interval.map { seconds in
        let timer = Timer(timeInterval: seconds, repeats: cancelled != nil) { _ in
            if let cancelled {
                guard NSApp.modalWindow === window else { return }
                if cancelled() { NSApp.abortModal(); return }
                guard let deadline, ProcessInfo.processInfo.systemUptime >= deadline else { return }
            }
            NSApp.stopModal(withCode: timeoutResponse)
        }
        RunLoop.main.add(timer, forMode: .modalPanel)
        return timer
    }
    defer {
        expiry?.invalidate()
        enable?.invalidate()
        center.removeObserver(becameKey)
        center.removeObserver(resignedKey)
        if let input = input { NSEvent.removeMonitor(input) }
    }
    return alert.runModal()
}

/// The signer callback runs on a worker. The main thread remains free for wallet navigation.
private func walletDecision(timeout: TimeInterval, escape: NSApplication.ModalResponse,
                            makeReview: @escaping () -> SignerReview?,
                            makeAlert: @escaping () -> NSAlert) -> NSApplication.ModalResponse {
    guard !Thread.isMainThread else { return .abort }
    let done = DispatchSemaphore(value: 0)
    var answer: NSApplication.ModalResponse = .abort
    DispatchQueue.main.async {
        guard NativeSigner.walletDecisionAllowed else { done.signal(); return }
        guard let signer = NativeSigner.embeddedSigner else {
            answer = runDecisionAlert(makeAlert(), timeout: timeout, escape: escape)
            done.signal()
            return
        }
        guard let review = makeReview() else { done.signal(); return }
        signer.presentPrompt(review, timeout: timeout, escape: escape) { response in
            answer = response
            done.signal()
        }
    }
    done.wait()
    return answer
}

/// An unanswered payment request times out after this long, or sooner if the round ends.
private let approvalTimeout: TimeInterval = 120
private let approvalTimedOut = NSApplication.ModalResponse(rawValue: 1003)

private final class ApprovalNotifications: NSObject, UNUserNotificationCenterDelegate {
    static let shared = ApprovalNotifications()

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler complete: @escaping (UNNotificationPresentationOptions) -> Void) {
        // The wallet-triggered alert may have activated the app since we asked for attention.
        complete(notification.request.identifier.hasPrefix("payment-approval-") ? [.banner, .list] : [])
    }
}

// Keep the last unanswered request visible even with system notifications disabled.
private var approvalEndedWindow: NSPanel?

private func showApprovalEnded(_ state: Int32) {
    let reason: String
    switch state {
    case 2: reason = "You did not answer the payment request in time."
    case 3: reason = "Another member did not answer the payment request in time."
    case 4: reason = "Another member refused the payment."
    case 5: reason = "The signing round timed out waiting for members."
    default: reason = "This payment attempt ended before LokiSigner could complete it."
    }
    if NativeSigner.embeddedMode {
        if let signer = NativeSigner.embeddedSigner, signer.walletReady {
            signer.walletNotice = reason + " LokiSigner did not approve it."
        }
        return
    }
    let frame = NSRect(x: 0, y: 0, width: 360, height: 72)
    let panel = approvalEndedWindow ?? NSPanel(contentRect: frame, styleMask: [.titled, .closable],
        backing: .buffered, defer: false)
    panel.title = state == 2 ? "Payment approval timed out" : "Payment request ended"
    panel.isReleasedWhenClosed = false
    panel.hidesOnDeactivate = false
    let label = NSTextField(wrappingLabelWithString: reason + " LokiSigner did not approve it.")
    panel.contentView = NSView(frame: frame)
    label.frame = frame.insetBy(dx: 16, dy: 12)
    panel.contentView?.addSubview(label)
    if approvalEndedWindow == nil { panel.center() }
    approvalEndedWindow = panel
    panel.orderFront(nil)
}

private func zec(_ zat: UInt64) -> String {
    return String(format: "%llu.%08llu ZEC", zat / 100_000_000, zat % 100_000_000)
}

private struct PaymentReview: Decodable {
    let recipient: String
    let amount_zat: UInt64
    let fee_zat: UInt64
    let fee_verified: Bool
    let change_zat: UInt64
    let memo: String
    let network: String
    let branch_id: String
    let expiry_height: UInt32
    let member: UInt16
    let vault: String
    let vault_name: String
    let payment: String
    let attempt: String
    let sighash: String

    var valid: Bool {
        network == "testnet" && member > 0 && !recipient.isEmpty &&
            recipient.utf8.allSatisfy { (48...57).contains($0) || (97...122).contains($0) } &&
            branch_id.range(of: "\\A[0-9a-f]{8}\\z", options: .regularExpression) != nil &&
            [vault, payment, attempt, sighash].allSatisfy {
                $0.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil
            }
    }

    func page() -> SignerReview {
        let r = SignerReview.self
        let full = r.label(recipient, size: 13, weight: .semibold, mono: true, selectable: true)
        let destination = r.card("Destination", [r.label("Shielded recipient", weight: .semibold), full] +
            (memo.isEmpty ? [] : [r.label("Memo · sender’s text", size: 12, tone: r.muted), r.quote(memo)]))
        let breakdown = r.card("Transaction breakdown", [
            r.row("Network fee", zec(fee_zat)),
            r.label("✓  Fee verified by signer", size: 11, weight: .semibold, tone: r.mint),
            r.row("Change to vault", zec(change_zat)), r.row("Network", "Testnet"), r.row("Branch ID", branch_id),
            r.row("Expiry height", String(expiry_height)),
        ])
        let amountValue = zec(amount_zat)
        let amountText = r.label(amountValue, size: 31, weight: .semibold, tone: r.gold, mono: true, wrap: false)
        let styled = NSMutableAttributedString(string: amountValue, attributes: [.font: amountText.font!, .foregroundColor: r.gold])
        styled.addAttributes([.font: NSFont.monospacedSystemFont(ofSize: 16, weight: .medium), .foregroundColor: r.muted],
                             range: NSRange(location: styled.length - 3, length: 3))
        amountText.attributedStringValue = styled
        let amount = r.column([r.caption("Amount to recipient"), amountText], spacing: 4)
        amountText.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let memberInfo = r.column([r.label("Member \(member)", weight: .semibold), r.label("Signing on this Mac", size: 11, tone: r.muted)])
        let summary = NSStackView(views: [amount, memberInfo])
        memberInfo.widthAnchor.constraint(equalToConstant: 122).isActive = true
        memberInfo.trailingAnchor.constraint(equalTo: summary.trailingAnchor).isActive = true
        summary.alignment = .centerY
        let identifiers = r.disclosure("Signing identifiers · 4", [
            r.row("Vault ID", vault, wide: true), r.row("Payment ID", payment, wide: true),
            r.row("Attempt ID", attempt, wide: true), r.row("Signature hash", sighash, wide: true),
        ])
        return SignerReview(section: "Approvals", title: "Review payment",
            intro: "Compare the transaction read by this Mac with the payment you intend.",
            content: [r.surface(summary, padding: 17, tone: r.hero, radius: 14), r.split(destination, breakdown),
                      r.card("Vault name", [r.quote(vault_name)]), identifiers],
            hint: "No answer in 2 minutes: this signer refuses.", actions: ["Refuse", "Approve and sign"], primary: 1)
    }
}

/// The member's decision on one payment, called by the signer from a worker thread just
/// before it would release its signature share. The cancellation context is borrowed until
/// this call returns. Returns 1 only for an explicit approval and 2 for a local timeout.
private func nativeApprove(_ summary: UnsafePointer<CChar>?, _ context: UnsafeRawPointer?,
                           _ cancellation: ConnectCancellation) -> Int32 {
    guard let summary, let context,
          let payment = try? JSONDecoder().decode(PaymentReview.self, from: Data(String(cString: summary).utf8))
    else { return 0 }
    // The core already refuses before consent. Reject an unverified callback at this boundary too.
    guard payment.fee_verified else {
        DispatchQueue.main.async { NativeSigner.embeddedSigner?.showBlockedFee() }
        return 0
    }
    return waitForApprovalDialog(cancellation: { cancellation(context) }, timeout: approvalTimeout, walletReview: {
        payment.valid ? payment.page() : nil
    }) { remaining, cancelled in
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Approve this payment?"
        let memo = payment.memo
        alert.informativeText = """
            Recipient: \(payment.recipient)
            Amount: \(zec(payment.amount_zat))
            Fee: \(zec(payment.fee_zat))
            Change back to the vault: \(zec(payment.change_zat))
            Network: \(payment.network) (branch \(payment.branch_id))
            Expiry height: \(payment.expiry_height)

            Member: \(payment.member)
            Payment: \(payment.payment)
            Attempt: \(payment.attempt)
            Signs: \(payment.sighash)

            Approve only if the transaction matches the payment you intend.
            Unanswered requests time out after \(Int(approvalTimeout / 60)) minutes.
            """
        let nameLabel = NSTextField(labelWithString: "Vault name (ID \(payment.vault.prefix(12))):")
        let name = untrustedLine(payment.vault_name)
        var details: [NSView] = [nameLabel, name]
        let width: CGFloat = 420
        if !memo.isEmpty {
            let box = NSScrollView()
            box.borderType = .bezelBorder
            box.hasVerticalScroller = true
            let memoText = NSTextView(frame: NSRect(x: 0, y: 0, width: width, height: 84))
            // Only LF is a layout character, and only within this clipped scroll view.
            memoText.string = memo.components(separatedBy: "\n").map(untrustedText).joined(separator: "\n")
            memoText.isEditable = false
            memoText.isRichText = false
            memoText.isVerticallyResizable = true
            memoText.autoresizingMask = [.width]
            memoText.textContainer?.widthTracksTextView = true
            memoText.font = .systemFont(ofSize: NSFont.systemFontSize)
            box.documentView = memoText
            box.widthAnchor.constraint(equalToConstant: width).isActive = true
            box.heightAnchor.constraint(equalToConstant: 84).isActive = true
            details += [NSTextField(labelWithString: "Memo (payment sender’s text):"), box]
        }
        let stack = NSStackView(views: details)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        name.widthAnchor.constraint(equalToConstant: width).isActive = true
        stack.frame = NSRect(x: 0, y: 0, width: width, height: memo.isEmpty ? 45 : 152)
        alert.accessoryView = stack
        alert.addButton(withTitle: "Refuse")
        alert.addButton(withTitle: "Approve and sign")
        return runDecisionAlert(alert, timeout: remaining, escape: .alertFirstButtonReturn,
            cancelled: cancelled, timeoutResponse: approvalTimedOut)
    }
}

/// Poll from the caller, not the main thread; a different alert's modal loop must be
/// free to finish. The same deadline bounds both the queue and the decision.
private func waitForApprovalDialog(cancellation: @escaping () -> Int32, timeout: TimeInterval,
                                   walletReview: (() -> SignerReview?)? = nil,
                                   present: @escaping (TimeInterval, @escaping () -> Bool) -> NSApplication.ModalResponse) -> Int32 {
    // Connect and roster alerts can occupy the main dispatch queue while they run modally.
    func onMainRunLoop<T>(_ body: @escaping () -> T) -> T {
        var result: T?
        let work = DispatchWorkItem { result = body() }
        RunLoop.main.perform(inModes: [.default, .modalPanel]) { work.perform() }
        work.wait()
        return result!
    }

    let deadline = ProcessInfo.processInfo.systemUptime + timeout
    let stopNotice = onMainRunLoop { () -> (() -> Void)? in
        if cancellation() == 0 && !NSApp.isActive {
            let attention = NSApp.requestUserAttention(.informationalRequest)
            let center = UNUserNotificationCenter.current()
            center.delegate = ApprovalNotifications.shared
            let id = "payment-approval-\(UUID())"
            var waiting = true
            center.requestAuthorization(options: [.alert]) { granted, _ in
                guard granted else { return }
                RunLoop.main.perform(inModes: [.default, .modalPanel]) {
                    guard waiting else { return }
                    let content = UNMutableNotificationContent()
                    content.title = "LokiSigner payment request"
                    content.body = "Open LokiSigner to review a payment awaiting approval."
                    center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil)) { _ in
                        RunLoop.main.perform(inModes: [.default, .modalPanel]) {
                            if !waiting { center.removeDeliveredNotifications(withIdentifiers: [id]) }
                        }
                    }
                }
            }
            return {
                waiting = false
                NSApp.cancelUserAttentionRequest(attention)
                center.removePendingNotificationRequests(withIdentifiers: [id])
                center.removeDeliveredNotifications(withIdentifiers: [id])
            }
        }
        return nil
    }
    defer { onMainRunLoop { stopNotice?() } }

    var walletAnswer: NSApplication.ModalResponse?
    var walletPresenter: NativeSigner?
    while true {
        if let answer = onMainRunLoop({ () -> Int32? in
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            let state = cancellation()
            if state != 0 || remaining <= 0 {
                if walletAnswer == nil { walletPresenter?.leaveNativePrompt() }
                showApprovalEnded(state == 0 ? 2 : state)
                return state == 0 || state == 2 ? 2 : 0
            }
            if let walletReview, NativeSigner.embeddedMode {
                if let walletAnswer { return walletAnswer == .alertSecondButtonReturn ? 1 : 0 }
                guard let signer = NativeSigner.embeddedSigner, signer.walletReady else { return 0 }
                if walletPresenter == nil && NativeSigner.walletDecisionAllowed {
                    guard let review = walletReview() else { return 0 }
                    walletPresenter = signer
                    // The worker owns the deadline, so time spent queued counts against it.
                    signer.presentPrompt(review, escape: .alertFirstButtonReturn) { walletAnswer = $0 }
                }
                return nil
            }
            guard NSApp.modalWindow == nil else { return nil }
            let result = present(remaining, { cancellation() != 0 })
            let finalState = cancellation()
            if finalState != 0 || result == approvalTimedOut || ProcessInfo.processInfo.systemUptime >= deadline {
                showApprovalEnded(finalState == 0 ? 2 : finalState)
                return finalState == 0 || finalState == 2 ? 2 : 0
            }
            return result == .alertSecondButtonReturn ? 1 : 0
        }) {
            return answer
        }
        Thread.sleep(forTimeInterval: 0.1)
    }
}

/// An unanswered roster comparison is refused after this long; members compare by phone.
private let rosterTimeout: TimeInterval = 600

/// The most combining marks shown in a row; the rest are dropped so text stays in its line.
private let combiningMarksShown = 3

/// Another party's text, such as a vault name from the creator, as one plain line. Rust already
/// hides a name with control, format, default-ignorable or line-breaking characters or with a
/// long run of combining marks (`vault_label`). This is the second layer: any such character
/// that still arrives becomes U+FFFD, and a run of combining marks is cut to three.
func untrustedText(_ text: String) -> String {
    let replaced: Set<Unicode.GeneralCategory> = [.control, .format, .lineSeparator, .paragraphSeparator]
    let marks: Set<Unicode.GeneralCategory> = [.nonspacingMark, .enclosingMark]
    var scalars = String.UnicodeScalarView()
    var run = 0
    for scalar in text.unicodeScalars {
        let category = scalar.properties.generalCategory
        if replaced.contains(category) || scalar.properties.isDefaultIgnorableCodePoint {
            scalars.append("\u{FFFD}")
            run = 0
        } else if marks.contains(category) {
            run += 1
            if run <= combiningMarksShown { scalars.append(scalar) }
        } else {
            scalars.append(scalar)
            run = 0
        }
    }
    return String(scalars)
}

/// A bordered one-line box holding another party's text, apart from the app's own wording.
/// The text is truncated at the box's edge and its drawing is clipped to the box.
func untrustedLine(_ text: String) -> NSTextField {
    let field = NSTextField(labelWithString: untrustedText(text))
    field.isBordered = true
    field.drawsBackground = true
    field.backgroundColor = .textBackgroundColor
    field.usesSingleLineMode = true
    field.maximumNumberOfLines = 1
    field.cell?.wraps = false
    field.lineBreakMode = .byTruncatingTail
    field.isSelectable = true
    if #available(macOS 14, *) { field.clipsToBounds = true }
    return field
}

/// The member's comparison of a vault's roster code, called by the member from a worker thread
/// when the wallet asks to agree to a roster. The code is the one Rust derived from the setup
/// document key generation will use. Returns 1 for an explicit "Codes match" and 2 for
/// "Codes differ"; closing the dialog, a malformed request or the timeout return 0.
private func nativeConfirmRoster(_ summary: UnsafePointer<CChar>?) -> Int32 {
    guard let summary = summary,
          let request = try? JSONSerialization.jsonObject(with: Data(String(cString: summary).utf8)) as? [String: Any],
          let code = request["roster_code"] as? String,
          code.range(of: "\\A[0-9]{4}( [0-9]{4}){5}\\z", options: .regularExpression) != nil,
          let name = request["vault_name"] as? String,
          let threshold = (request["threshold"] as? NSNumber)?.intValue,
          let members = (request["members"] as? NSNumber)?.intValue,
          let member = (request["member"] as? NSNumber)?.intValue,
          let network = request["network"] as? String, ["regtest", "testnet"].contains(network)
    else { return 0 }
    let answer = walletDecision(timeout: rosterTimeout, escape: .abort, makeReview: {
        guard network == "testnet", member > 0, threshold > 0, members >= threshold else { return nil }
        let r = SignerReview.self
        let codeCard = r.card("Roster code · computed on this Mac", [
            r.tiles(code.components(separatedBy: " ")),
            r.label("Choose Codes match only if everyone reads back the same code.", tone: r.muted),
        ], emphasized: true)
        let policyNumber = r.column([r.label("\(threshold) of \(members)", size: 26, weight: .semibold, mono: true),
                                     r.label("Approvals required", size: 12, tone: r.muted)], spacing: 4)
        let slotNumber = r.column([r.label(String(format: "%02d", member), size: 26, weight: .semibold, mono: true),
                                   r.label("Your member slot", size: 12, tone: r.muted)], spacing: 4)
        let facts = NSStackView(views: [policyNumber, slotNumber])
        facts.distribution = .fillEqually
        let policy = r.card("Vault policy", [facts,
            r.label("Vault name · set by creator", size: 12, tone: r.muted), r.quote(name)])
        let mismatch = r.card("If one group differs", [r.label("Stop the setup", weight: .semibold),
            r.label("A different code may mean a member was substituted. Choose Codes differ and check the roster together.", tone: r.muted),
            r.row("Network", "Testnet")])
        return SignerReview(section: "Vault setup", title: "Compare roster codes",
            intro: "Compare all six groups with every other member, by phone or in person.",
            content: [codeCard, r.split(policy, mismatch)], hint: "No answer in 10 minutes: no match is recorded.",
            actions: ["Codes differ", "Codes match"], primary: 1)
    }) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Do the roster codes match?"
        alert.informativeText = """
            A vault needs \(threshold) of \(members) members to approve. You are member \(member). Network: \(network).

            Compare the code below with every other member over a channel you already trust, \
            such as a phone call or in person. Choose Codes match only if every member sees \
            the same code. If any code differs, someone may have been swapped into this vault: \
            choose Codes differ.

            Unanswered requests are refused after \(Int(rosterTimeout / 60)) minutes.
            """
        let codeLabel = NSTextField(labelWithString: "Roster code")
        codeLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        let codeField = NSTextField(labelWithString: code)
        codeField.font = .monospacedDigitSystemFont(ofSize: 20, weight: .semibold)
        codeField.isSelectable = true
        let nameLabel = NSTextField(labelWithString: "Vault name (set by creator):")
        nameLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        let nameField = untrustedLine(name)
        let stack = NSStackView(views: [codeLabel, codeField, nameLabel, nameField])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.setCustomSpacing(12, after: codeField)
        stack.frame = NSRect(x: 0, y: 0, width: 420, height: 96)
        nameField.widthAnchor.constraint(equalToConstant: 420).isActive = true
        alert.accessoryView = stack
        alert.addButton(withTitle: "Codes differ")
        alert.addButton(withTitle: "Codes match")
        return alert
    }
    switch answer {
    case .alertSecondButtonReturn: return 1
    case .alertFirstButtonReturn: return 2
    default: return 0
    }
}

private func nativeConnect(_ origin: UnsafePointer<CChar>?, _ code: UnsafePointer<CChar>?,
                           _ context: UnsafeRawPointer?, _ cancelled: ConnectCancellation) -> Int32 {
    guard let origin, let code, let context else { return 0 }
    let coordinator = String(cString: origin), comparison = String(cString: code)
    return DispatchQueue.main.sync {
        guard NativeSigner.embeddedSigner == nil else { return 0 }
        return showConnectDialog(origin: coordinator, code: comparison, cancelled: { cancelled(context) != 0 }) ? 1 : 0
    }
}

/// Only answer the request whose code matches the wallet tab. The borrowed cancellation
/// check is used only while the C callback is live, including during the modal run loop.
func showConnectDialog(origin: String, code: String, cancelled: @escaping () -> Bool) -> Bool {
    guard !cancelled(), NSApp.modalWindow == nil else { return false }
    let alert = NSAlert()
    alert.messageText = "Connect this wallet tab?"
    alert.informativeText = """
        Wallet: \(origin)

        Choose Allow only if you clicked Connect LokiSigner and the code below matches the one in that tab.
        Unanswered requests are refused in under two minutes.
        """
    let comparison = NSTextField(labelWithString: code)
    comparison.font = .monospacedDigitSystemFont(ofSize: 24, weight: .semibold)
    comparison.frame = NSRect(x: 0, y: 0, width: 230, height: 30)
    alert.accessoryView = comparison
    alert.addButton(withTitle: "Refuse")
    alert.addButton(withTitle: "Allow")
    let window = alert.window
    let timer = Timer(timeInterval: 0.1, repeats: true) { _ in
        if cancelled() && NSApp.modalWindow === window { NSApp.abortModal() }
    }
    RunLoop.main.add(timer, forMode: .modalPanel)
    defer { timer.invalidate() }
    return runDecisionAlert(alert, escape: .alertFirstButtonReturn) == .alertSecondButtonReturn && !cancelled()
}

private func nativeNotice(_ kind: UnsafePointer<CChar>?, _ message: UnsafePointer<CChar>?) -> Int32 {
    guard let kind = kind, let message = message else { return 0 }
    let event = String(cString: kind), text = String(cString: message)
    if event == "payment-fee-unverified" {
        DispatchQueue.main.async { NativeSigner.embeddedSigner?.showBlockedFee() }
        return 0
    }
    if event == "locked" {
        RunLoop.main.perform(inModes: [.common, .modalPanel]) {
            NativeSigner.current?.didLock()
        }
        return 0
    }
    if event == "registration-warning" || event == "registration-key" || event == "registration-key-gone" {
        // Rust supplies fixed copy here. Don't block its retry loop on an open dialog.
        DispatchQueue.main.async { NativeSigner.current?.warnRegistration(event, message: text) }
        return 0
    }
    if event == "startup-key" || event == "startup-key-gone" {
        DispatchQueue.main.async { NativeSigner.current?.startupKeyFailure = event == "startup-key-gone" ? .keyGone(text) : .key(text) }
        return 0
    }
    // Do not finish pairing unless the member explicitly confirms saving the words.
    if event == "recovery" {
        guard !Thread.isMainThread else { return 0 }
        let done = DispatchSemaphore(value: 0)
        var acknowledged = false
        DispatchQueue.main.async {
            if let signer = NativeSigner.embeddedSigner {
                let r = SignerReview.self
                let words = text.split(separator: " ").map(String.init)
                let numbered = words.enumerated().map { String(format: "%02d", $0.offset + 1) + " " + $0.element }
                let review = SignerReview(section: "Recovery", title: "Save your recovery words",
                    intro: "Write all 24 words down privately, in their numbered order.", content: [
                        r.card("One-time recovery words", [r.tiles(numbered, secret: true)]),
                        r.info("You need two things to restore", "Keep your written words and the encrypted backup file for each vault. Never share either in chat."),
                    ], hint: "Only explicit acknowledgment finishes this step.", actions: ["I saved these words"], primary: 0)
                signer.presentPrompt(review, escape: nil) { answer in
                    acknowledged = answer == .alertFirstButtonReturn
                    done.signal()
                }
            } else if !NativeSigner.embeddedMode {
                let signer = NativeSigner.current
                signer?.showingRecoveryWords = true
                defer { signer?.showingRecoveryWords = false; done.signal() }
                let alert = NSAlert()
                alert.messageText = "Save your recovery words privately"
                alert.informativeText = text
                alert.addButton(withTitle: "I saved these words")
                acknowledged = runDecisionAlert(alert, escape: .abort) == .alertFirstButtonReturn
            } else {
                done.signal()
            }
        }
        done.wait()
        return acknowledged ? 1 : 0
    }
    return DispatchQueue.main.sync {
        let signer = NativeSigner.current
        if event == "pairing-claim-attempted" {
            signer?.markPairingClaimAttempted(text)
            return 0
        }
        if event == "ready" || event == "restore-ready" || event == "restore-pending" {
            guard signer?.lockingForAbsence != true else { return 0 }
            if let signer = NativeSigner.embeddedSigner {
                signer.didStart()
                if event != "ready" {
                    signer.walletNotice = event == "restore-pending"
                        ? "Your vault is saved on this Mac. LokiSigner will keep trying to reconnect without your recovery words."
                        : "Vault restored on this Mac."
                }
                return 0
            }
            let alert = NSAlert()
            alert.messageText = event == "ready" ? "LokiSigner is running" : "Vault restored"
            let connect = "On this Mac, choose Connect LokiSigner in the wallet. If the wallet only offers to paste a link, ask the coordinator to update it. Keep LokiSigner running to approve and sign."
            alert.informativeText = event == "restore-pending"
                ? "Your vault is saved on this Mac. LokiSigner will keep trying to reconnect, without your recovery words.\n\n\(connect)"
                : connect
            alert.addButton(withTitle: "Done")
            alert.runModal()
            signer?.didStart()
        }
        return 0
    }
}

final class NativeSigner: NSObject, NSApplicationDelegate, NSMenuItemValidation {
    fileprivate private(set) static var embeddedMode = false
    fileprivate static weak var embeddedSigner: NativeSigner?
    fileprivate static var current: NativeSigner? { embeddedSigner ?? (NSApp.delegate as? NativeSigner) }
    fileprivate static var walletDecisionAllowed: Bool { !embeddedMode || embeddedSigner?.canShowWalletDecision == true }
    private let embedded: Bool
    private weak var walletWindow: NSWindow?
    private var promptPage: SignerPromptPage?
    var promptChanged: ((Bool) -> Void)?
    var sessionEnded: (() -> Void)?
    var walletNotice: String?
    private(set) var canRecoverWalletKey = false
    var nativePromptActive: Bool { promptPage != nil }
    static var awaitingRecoveryAcknowledgment: Bool { embeddedSigner?.promptPage?.requiresAcknowledgment == true }
    private var ready = false
    private var stopping = false
    private var walletCompletion: ((SignerStartFailure?) -> Void)?
    private var lockCompletions: [() -> Void] = []
    private let walletWork = DispatchGroup()
    private var running = false
    private var prompting = false {
        didSet {
            if !prompting && !registrationWarnings.isEmpty { DispatchQueue.main.async { self.showNextRegistrationWarning() } }
        }
    }
    private var registrationWarnings: [(event: String, message: String)] = []
    fileprivate var startupKeyFailure: SignerStartFailure?
    private var opened = false
    private var cleanupNeeded = true
    private var retryLink: String?
    private var queuedLink: String?
    private var attemptedPairingClaims: Set<String> = []
    private var startingOver = false
    private var recoveringKey = false
    private var discardingPending = false
    fileprivate private(set) var lockingForAbsence = false
    fileprivate var showingRecoveryWords = false
    private var lockTimer: Timer?
    private var presence: SignerPresence?
    private var lastStartError: String?
    private let args: [String]
    private var initialLink: String?
    let vaultAddresses = VaultAddressesWindow()
    private lazy var statusWindow = SignerStatusWindow(load: { [args = self.args] in
        nativeQuery(loki_member_app_status, ["args": args])
    }, localError: { [weak self] in self?.lastStartError }, canUnlock: { [weak self] in
        guard let self else { return false }
        return !self.running && !self.prompting
    }, unlock: { [weak self] in
        guard let self else { return }
        self.start(self.queuedLink ?? self.retryLink)
    })

    init(args: [String], link: String?, walletWindow: NSWindow? = nil) {
        self.args = args
        self.initialLink = link
        self.walletWindow = walletWindow
        embedded = walletWindow != nil
        super.init()
        if embedded { Self.embeddedMode = true; Self.embeddedSigner = self }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        presence = SignerPresence { [weak self] in self?.lockForAbsence() }
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async {
            guard !self.opened else { return }
            self.opened = true
            let link = self.initialLink
            self.initialLink = nil
            if link == nil, self.profile()["profile"] as? String == "fresh" {
                self.showStatus(nil)
            } else {
                self.start(link)
            }
        }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        // An external event must never interrupt a live signer or offer to replace its profile.
        guard !running, !lockingForAbsence else { return }
        var failure = SignerStartFailure.invalidLink
        for url in urls {
            guard let link = unusedPairingLink(url.absoluteString) else { continue }
            let reply = nativeQuery(loki_member_app_pairing_target, ["args": args, "pairing_url": link])
            if reply["target"] != nil {
                opened = true
                initialLink = nil
                if prompting || NSApp.modalWindow != nil { queuedLink = link }
                else { start(link) }
                return
            }
            if reply["error"] as? String == "different-pairing" { failure = .differentPairing }
        }
        guard !urls.isEmpty, !prompting, NSApp.modalWindow == nil else { return }
        opened = true
        initialLink = nil
        lastStartError = failure.message
        showStatus(nil)
    }

    private func unusedPairingLink(_ link: String?) -> String? {
        guard let link else { return nil }
        let items = URLComponents(string: link)?.queryItems ?? []
        return items.contains { $0.name == "challenge" && $0.value.map(attemptedPairingClaims.contains) == true } ? nil : link
    }

    fileprivate func markPairingClaimAttempted(_ claim: String) {
        attemptedPairingClaims.insert(claim)
        queuedLink = unusedPairingLink(queuedLink)
        retryLink = unusedPairingLink(retryLink)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showStatus(nil)
        return false
    }

    private func lockForAbsence() {
        guard running, !startingOver, !lockingForAbsence else { return }
        lockingForAbsence = true
        didLock()
        SignerLog.write("LokiSigner locked because the Mac was unattended.")
        finishLockRequest()
        // The Swift worker can be starting before Rust installs its stop handle. Also unwind
        // any stacked decision panels without discarding the one-time recovery words.
        let timer = Timer(timeInterval: 0.1, repeats: true) { [weak self] _ in self?.finishLockRequest() }
        RunLoop.main.add(timer, forMode: .common)
        RunLoop.main.add(timer, forMode: .modalPanel)
        lockTimer = timer
    }

    private func finishLockRequest() {
        _ = loki_member_app_stop()
        if !showingRecoveryWords && NSApp.modalWindow != nil { NSApp.abortModal() }
    }

    private func profile(_ action: UInt32 = 0) -> [String: Any] {
        nativeQuery({ loki_member_app_profile($0, action) }, ["args": args])
    }

    private func startupProfile() -> [String: Any] {
        let location = profile(cleanupNeeded ? 1 : 0)
        if location["profile"] != nil { cleanupNeeded = false }
        return location
    }

    var walletReady: Bool { ready && !stopping && !startingOver }
    var walletDialogOpen: Bool { nativePromptActive || NSApp.modalWindow != nil }
    private var canShowWalletDecision: Bool { walletReady && !prompting && !walletDialogOpen && walletWindow?.isVisible == true }

    func presentPrompt(_ review: SignerReview, fields: [NSTextField] = [], timeout: TimeInterval? = nil,
                       escape: NSApplication.ModalResponse? = .abort,
                       completion: @escaping (NSApplication.ModalResponse) -> Void) {
        // Recovery words must remain available if the user minimized the window during setup.
        guard let parent = walletWindow, (parent.isVisible || escape == nil), !walletDialogOpen else { completion(.abort); return }
        let page = SignerPromptPage(review, fields: fields, timeout: timeout, escape: escape) { [weak self] answer in
            self?.promptPage = nil
            self?.promptChanged?(false)
            completion(answer)
        }
        promptPage = page
        promptChanged?(true)
        page.attach(to: parent)
    }

    func leaveNativePrompt() { promptPage?.leave() }

    fileprivate func showBlockedFee() {
        guard walletReady else { return }
        let r = SignerReview.self
        if !canShowWalletDecision {
            walletNotice = "Payment blocked: the signer could not verify the fee. This Mac did not sign."
            return
        }
        presentPrompt(SignerReview(section: "Approvals", title: "Payment blocked",
            intro: "This Mac could not verify the fee from the transaction.", content: [
                r.info("Fee not verified", "The declared fee is not proven by the transaction. The signer stopped before asking for a signature.", warning: true),
                r.card("Signing decision", [r.label("No signature was requested", weight: .semibold),
                    r.label("There’s nothing to approve on this Mac. Return to the payment to check its status.", tone: r.muted)]),
            ], hint: "No override is available.", actions: ["Back to approvals"])) { _ in }
    }

    private func canSetUp() -> Bool {
        if !embedded { return canSetUpWithTouchID() }
        guard let failure = touchIDSetupFailure() else { return true }
        finishWalletOperation(failure)
        return false
    }

    var pairedTarget: (coordinator: String, slot: Int)? {
        let saved = profile()
        guard let origin = saved["coordinator"] as? String, let slot = (saved["slot"] as? NSNumber)?.intValue else { return nil }
        return (origin, slot)
    }

    func walletProfile() -> [String: Any] {
        var value = profile()
        value["running"] = walletReady
        return value
    }

    func beginWalletOperation(_ completion: @escaping (SignerStartFailure?) -> Void) -> Bool {
        guard !prompting, !stopping, !running || walletReady,
              walletCompletion == nil, !walletDialogOpen else { return false }
        walletNotice = nil
        walletCompletion = completion
        return true
    }

    private func finishWalletOperation(_ failure: SignerStartFailure? = nil) {
        prompting = false
        retryLink = nil
        let completion = walletCompletion
        walletCompletion = nil
        completion?(failure)
    }

    func unlockWallet() {
        if walletReady { finishWalletOperation(); return }
        start(nil)
    }

    func pairWallet(link: String) {
        guard !running else { finishWalletOperation(.differentPairing); return }
        prompting = true
        let state = startupProfile()
        guard let profile = state["profile"] as? String else { retry(.dataFolderUnavailable, link: nil); return }
        if profile == "fresh", !canSetUp() { return }
        guard let link = unusedPairingLink(link) else { finishWalletOperation(.invalidLink); return }
        loadConfiguration(link: link)
    }

    func restoreWallet() {
        if walletReady { restoreVault(nil); return }
        prompting = true
        switch startupProfile()["profile"] as? String {
        case "fresh":
            if canSetUp() { beginRecovery() }
        case "profile":
            confirmSetAside()
        case "vault":
            finishWalletOperation(.unlockToRestore)
        default:
            finishWalletOperation(.dataFolderUnavailable)
        }
    }

    func lockWallet(_ completion: @escaping () -> Void) -> Bool {
        if stopping { lockCompletions.append(completion); return true }
        guard !prompting, !startingOver, NSApp.modalWindow == nil else { return false }
        guard running else { completion(); return true }
        stopping = true
        walletNotice = nil
        canRecoverWalletKey = false
        lockCompletions.append(completion)
        // If Rust already exited, its queued stopped() callback still drains and completes lock.
        _ = loki_member_app_stop()
        didLock()
        leaveNativePrompt()
        return true
    }

    func performWalletWork(_ work: @escaping () -> [String: Any],
                           complete: @escaping ([String: Any]?) -> Void) -> Bool {
        guard walletReady else { return false }
        walletWork.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            let value = work()
            DispatchQueue.main.async {
                complete(self.walletReady ? value : nil)
                self.walletWork.leave()
                self.resumeWalletWarnings()
            }
        }
        return true
    }

    private func retry(_ failure: SignerStartFailure, link: String?) {
        guard !lockingForAbsence else { return }
        if failure != .cancelled {
            lastStartError = failure.message
            SignerLog.write("LokiSigner couldn’t finish setup or unlock. Check the app for details.")
        }
        if embedded {
            if failure.keyIsGone, let state = profile()["profile"] as? String, ["profile", "vault"].contains(state) {
                walletNotice = failure.message
                canRecoverWalletKey = true
            }
            finishWalletOperation(failure)
            return
        }
        prompting = true
        retryLink = link
        let alert = retryAlert(failure, profile: profile()["profile"] as? String)
        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertSecondButtonReturn:
            NSApp.terminate(nil)
        case .alertThirdButtonReturn:
            if confirmStandaloneSetAside(recover: failure.keyIsGone) { return }
        default: break
        }
        // Don't nest modal panels or keep a previous passphrase field alive on retry.
        DispatchQueue.main.async {
            self.prompting = false
            self.start(self.queuedLink ?? (failure == .differentPairing ? nil : self.retryLink))
        }
    }

    func recoverWalletKey() {
        guard canRecoverWalletKey else { finishWalletOperation(.cancelled); return }
        confirmSetAside(recover: true)
    }

    /// A pairing whose registration never finished left a profile without recovery words or
    /// vaults. Set it aside (renamed, not deleted) so the member can pair this Mac again.
    func discardPendingProfile() {
        prompting = true
        let state = startupProfile()
        guard !running, state["profile"] as? String == "profile", state["pairing_pending"] as? Bool == true else {
            finishWalletOperation(.setAsideFailed)
            return
        }
        guard canSetUp() else { return }
        let r = SignerReview.self
        presentPrompt(SignerReview(section: "Pairing", title: "Remove this unregistered profile?",
            intro: "The coordinator never accepted this Mac’s registration, so this profile has no recovery words or vaults yet.",
            content: [r.info("Nothing is deleted", "LokiSigner renames the local data folder and returns to Pair this Mac. Pair again with a new link from the wallet.")],
            hint: "Cancel keeps this profile.", actions: ["Cancel", "Remove and pair again"], primary: 1, destructive: true)) { answer in
            guard answer == .alertSecondButtonReturn else { self.finishWalletOperation(.cancelled); return }
            self.discardingPending = true
            self.setAside(recover: false)
        }
    }

    private func confirmSetAside(recover: Bool = false) {
        prompting = true
        guard canSetUp() else { return }
        let r = SignerReview.self
        presentPrompt(SignerReview(section: "Profile recovery", title: "Set aside this profile?",
            intro: recover ? "The secure key for this profile is no longer available." : "Set aside this local profile to start recovery.",
            content: [r.info("This moves the entire profile", "LokiSigner renames the local data folder, including identity, pairing and any vault data. Nothing is deleted.", warning: true),
                r.card("Before starting over", [r.label("Locate your encrypted backup file for each vault you want to recover."),
                    r.label("Check that you also have the matching written recovery words.")])],
            hint: "Cancel leaves this profile where it is.", actions: ["Cancel", "Set aside and start over"], primary: 1, destructive: true)) { answer in
            guard answer == .alertSecondButtonReturn else { self.finishWalletOperation(.cancelled); return }
            self.setAside(recover: recover)
        }
    }

    private func confirmStandaloneSetAside(recover: Bool = false) -> Bool {
        guard setAsideAlert(recover: recover).runModal() == .alertSecondButtonReturn else { return false }
        setAside(recover: recover)
        return true
    }

    private func setAside(recover: Bool) {
        recoveringKey = recover
        if running {
            startingOver = loki_member_app_stop() != 0
            if startingOver { didLock() }
            else {
                DispatchQueue.main.async {
                    if self.running { self.retry(.setAsideFailed, link: self.retryLink) }
                }
            }
        } else {
            finishSetAside()
        }
    }

    private func finishSetAside() {
        let recover = recoveringKey
        recoveringKey = false
        let reply = profile(recover ? 3 : 2)
        if discardingPending {
            discardingPending = false
            if reply["profile"] as? String == "fresh" { finishWalletOperation() }
            else { retry(reply["error"] as? String == "vault" ? .protectedProfile : .setAsideFailed, link: nil) }
            return
        }
        if reply["profile"] as? String != "fresh" {
            retry(reply["error"] as? String == "vault" ? .protectedProfile : .setAsideFailed, link: retryLink)
        } else {
            canRecoverWalletKey = false
            walletNotice = nil
            let link = recover ? nil : queuedLink ?? retryLink
            DispatchQueue.main.async {
                if self.embedded {
                    if self.canSetUp() { self.beginRecovery() }
                } else {
                    self.prompting = false
                    self.start(link)
                }
            }
        }
    }

    fileprivate func didStart() {
        guard !lockingForAbsence, !stopping else { return }
        lastStartError = nil
        ready = true
        prompting = false
        queuedLink = nil
        vaultAddresses.setUnlocked(true)
        if embedded { finishWalletOperation() }
    }

    fileprivate func didLock() {
        if ready { sessionEnded?() }
        ready = false
        vaultAddresses.setUnlocked(false)
    }

    fileprivate func warnRegistration(_ event: String, message: String) {
        guard running, !startingOver, !lockingForAbsence, !stopping else { return }
        if embedded {
            walletNotice = message
            if event == "registration-key-gone" { canRecoverWalletKey = true }
            return
        }
        registrationWarnings.append((event, message))
        showNextRegistrationWarning()
    }

    fileprivate func resumeWalletWarnings() {
        DispatchQueue.main.async { self.showNextRegistrationWarning() }
    }

    private func showNextRegistrationWarning() {
        guard running, !startingOver, !lockingForAbsence, !stopping, !prompting, !registrationWarnings.isEmpty else { return }
        prompting = true
        let warning = registrationWarnings.removeFirst()
        let recover = warning.event == "registration-key-gone"
        let alert = registrationWarningAlert(warning.message, key: warning.event != "registration-warning", recover: recover)
        if alert.runModal() == .alertSecondButtonReturn, recover, confirmStandaloneSetAside(recover: true) { return }
        prompting = false
    }

    private func stopped(_ failure: SignerStartFailure, link: String?) {
        didLock()
        if embedded {
            walletWork.notify(queue: .main) { self.finishStopped(failure, link: link) }
        } else {
            finishStopped(failure, link: link)
        }
    }

    private func finishStopped(_ failure: SignerStartFailure, link: String?) {
        running = false
        registrationWarnings.removeAll()
        if lockingForAbsence {
            lockTimer?.invalidate()
            lockTimer = nil
            lockingForAbsence = false
            // Resume only on an explicit Unlock, never from the consumed pairing claim.
            queuedLink = nil
            retryLink = nil
            prompting = false
        } else if stopping {
            stopping = false
            prompting = false
            let completions = lockCompletions
            lockCompletions.removeAll()
            completions.forEach { $0() }
        } else if startingOver {
            startingOver = false
            finishSetAside()
        } else {
            retry(failure, link: link)
        }
    }

    private func start(_ link: String?) {
        guard !running, !prompting, !lockingForAbsence, NSApp.modalWindow == nil else { return }
        let link = unusedPairingLink(link)
        var launch: [String: Any] = ["args": args]
        var target: (origin: String, slot: String)?
        if let link {
            launch["pairing_url"] = link
            let reply = nativeQuery(loki_member_app_pairing_target, launch)
            guard let checked = reply["target"] as? [String: Any], let origin = checked["coordinator"] as? String,
                  let slot = (checked["slot"] as? NSNumber)?.stringValue else {
                lastStartError = (reply["error"] as? String == "different-pairing"
                    ? SignerStartFailure.differentPairing : .invalidLink).message
                showStatus(nil)
                return
            }
            target = (origin, slot)
        }
        prompting = true
        queuedLink = nil
        retryLink = link
        NSApp.activate(ignoringOtherApps: true)
        let location = startupProfile()
        guard let state = location["profile"] as? String else {
            retry(location["error"] as? String == "data-folder-unavailable" ? .dataFolderUnavailable : .unexpected, link: link)
            return
        }
        if state == "fresh" {
            if embedded { finishWalletOperation(.pairingLinkNeeded); return }
            guard canSetUpWithTouchID() else { prompting = false; return }
            switch firstRunChoice() {
            case .alertSecondButtonReturn:
                beginRecovery()
                return
            case .alertFirstButtonReturn:
                if link == nil { retry(.pairingLinkNeeded, link: nil); return }
            default:
                retry(.cancelled, link: link)
                return
            }
        }
        if let target {
            confirmCoordinator(target.origin, slot: target.slot) { answer in
                guard answer == .alertFirstButtonReturn else { self.retry(.cancelled, link: link); return }
                self.fetchConfiguration(link: link, launch: launch)
            }
        } else {
            fetchConfiguration(link: link, launch: launch)
        }
    }

    private func loadConfiguration(link: String?) {
        var launch: [String: Any] = ["args": args]
        if let link = link {
            launch["pairing_url"] = link
            // Validate the link locally before asking the member to fetch configuration.
            let reply = nativeQuery(loki_member_app_pairing_target, launch)
            guard let target = reply["target"] as? [String: Any], let origin = target["coordinator"] as? String,
                  let slot = (target["slot"] as? NSNumber)?.stringValue else {
                let different = reply["error"] as? String == "different-pairing"
                retry(different ? .differentPairing : .invalidLink, link: link)
                return
            }
            confirmCoordinator(origin, slot: slot) { answer in
                guard answer == .alertFirstButtonReturn else { self.retry(.cancelled, link: link); return }
                self.fetchConfiguration(link: link, launch: launch)
            }
        } else {
            fetchConfiguration(link: link, launch: launch)
        }
    }

    private func fetchConfiguration(link: String?, launch: [String: Any]) {
        let fresh = link != nil && profile()["profile"] as? String == "fresh"
        // A pairing link, or an unlock with nothing saved, asks the coordinator; keep the UI live.
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = nativeQuery(loki_member_app_configuration, launch)
            DispatchQueue.main.async { self.confirm(link: link, launch: launch, reply: reply, fresh: fresh) }
        }
    }

    private func confirmCoordinator(_ origin: String, slot: String? = nil,
                                    then: @escaping (NSApplication.ModalResponse) -> Void) {
        if embedded {
            let r = SignerReview.self
            let review: SignerReview
            if let slot {
                review = SignerReview(section: "Signer setup · 03 / 04", title: "Confirm member slot",
                    intro: "Check which slot this Mac will use.", content: [
                        r.origin("Coordinator", origin, "Only continue if this is the origin you intended."),
                        r.card("Returned slot", [r.label("Member \(slot)", size: 26, weight: .semibold, mono: true),
                            r.label("Continue to fetch the signer configuration. Nothing has been saved.", tone: r.muted)]),
                    ], hint: "Check the member slot before continuing.", actions: ["Continue", "Cancel"], primary: 0)
            } else {
                review = SignerReview(section: "Recovery · fresh profile", title: "Confirm original coordinator",
                    intro: "Use the same HTTPS coordinator as the profile you are restoring.", content: [
                        r.origin("Original coordinator", origin, "Check this full address before contacting it."),
                        r.info("Why the original coordinator matters", "LokiSigner uses its roster to find the identity in your backup. It cannot transfer the profile to a different coordinator."),
                    ], hint: "Continue requests its configuration.", actions: ["Continue", "Cancel"], primary: 0)
            }
            presentPrompt(review, escape: .alertSecondButtonReturn, completion: then)
            return
        }
        let alert = NSAlert()
        alert.messageText = slot.map { "Pair this device with slot \($0)?" } ?? "Restore with this coordinator?"
        alert.informativeText = "Coordinator: \(origin)\n\nOnly continue if this is the coordinator you intended. LokiSigner then asks it for the signer configuration and shows it to you before anything is saved."
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        then(runDecisionAlert(alert, escape: .alertSecondButtonReturn))
    }

    private func configurationText(_ config: [String: Any]) -> String {
        let text = { (key: String) in config[key] as? String ?? "none" }
        let witnesses = (config["nonce_witnesses"] as? [String])?.joined(separator: "\n  ") ?? "none"
        return """
            Coordinator: \(text("coordinator"))
            Network: \(text("network"))
            frostd: \(text("frostd_url"))
            lightwalletd: \(text("lightwalletd_url"))
            Nonce witnesses:
              \(witnesses)

            The coordinator above chose these endpoints, except any you set with launch flags \
            (those apply to this launch only, and then nothing is saved).
            """
    }

    private func endpointRows(_ config: [String: Any]) -> [NSView] {
        let r = SignerReview.self
        let field = { (key: String) in config[key] as? String ?? "None" }
        let rows = [r.row("FROST relay", field("frostd_url")), r.row("Lightwalletd", field("lightwalletd_url"))]
        return rows + (config["nonce_witnesses"] as? [String] ?? []).enumerated().map {
            r.row("Nonce witness \($0.offset + 1)", $0.element)
        }
    }

    private var launchOverrideNotice: [NSView] {
        let flags = ["--network", "--frostd-url", "--lightwalletd-url", "--nonce-witnesses"].filter { args.contains($0) }
        return flags.isEmpty ? [] : [SignerReview.info("Launch-only settings", "Overrides: \(flags.joined(separator: ", ")). The configuration shown is not saved.", warning: true)]
    }

    private func confirmWitnesses(_ config: [String: Any], mismatch: Bool = false,
                                  then: @escaping (String?) -> Void) {
        guard let expected = config["witness_fingerprint"] as? String else { then(nil); return }
        let instruction = "Paste the 64-character pair fingerprint from the witness operators through a channel you trust, not from the wallet. An old signing attempt cannot use replacement witnesses."
        let warning = "That fingerprint does not match. Check it independently before approving."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        field.placeholderString = "Witness fingerprint"
        field.setAccessibilityLabel("Witness fingerprint")
        if embedded {
            let r = SignerReview.self
            let error = mismatch ? [r.info("Fingerprint mismatch", warning, warning: true)] : []
            presentPrompt(SignerReview(section: "Signer configuration", title: "Verify the nonce witnesses",
                intro: instruction, content: error + [r.card("Witness fingerprint", [field])],
                hint: "Cancel leaves your configuration unchanged.", actions: ["Approve witnesses", "Cancel"], primary: 0),
                fields: [field], completion: { answer in
                    guard answer == .alertFirstButtonReturn else { then(nil); return }
                    let code = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    if code == expected { then(code) }
                    else { self.confirmWitnesses(config, mismatch: true, then: then) }
                })
            return
        }
        let alert = NSAlert()
        alert.messageText = "Verify the nonce witnesses"
        alert.informativeText = instruction
        alert.accessoryView = field
        alert.addButton(withTitle: "Approve witnesses")
        alert.addButton(withTitle: "Cancel")
        while runDecisionAlert(alert, escape: .alertSecondButtonReturn, fields: [field]) == .alertFirstButtonReturn {
            let code = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if code == expected { then(code); return }
            alert.informativeText = warning
        }
        then(nil)
    }

    /// Shows the configuration before anything is saved; the member continues with exactly it.
    private func confirm(link: String?, launch: [String: Any], reply: [String: Any], fresh: Bool) {
        guard let config = reply["config"] as? [String: Any] else {
            let refreshFailed = reply["error"] as? String == "saved-endpoints-refresh-failed"
            retry(refreshFailed ? .savedEndpointsRefreshFailed : .configuration, link: link)
            return
        }
        if embedded, config["network"] as? String != "testnet" { retry(.testnetOnly, link: link); return }
        if config["confirm_witness_fingerprint"] as? Bool == true, launch["witness_confirmation"] == nil {
            confirmWitnesses(config) { code in
                guard let code else { self.retry(.cancelled, link: link); return }
                var verified = launch
                verified["witness_confirmation"] = code
                self.confirm(link: link, launch: verified, reply: reply, fresh: fresh)
            }
            return
        }
        let slot = (config["slot"] as? NSNumber)?.stringValue ?? "?"
        let password = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        password.placeholderString = "Local profile passphrase"
        password.setAccessibilityLabel("Local profile passphrase")
        let nameField: NSTextField? = fresh && link != nil ? NSTextField(frame: NSRect(x: 0, y: 34, width: 420, height: 26)) : nil
        nameField?.placeholderString = "Profile name (optional)"
        nameField?.setAccessibilityLabel("Profile name (optional)")
        let fields: [NSTextField] = nameField.map { [$0, password] } ?? [password]
        let confirmed: (NSApplication.ModalResponse) -> Void = { answer in
            guard answer == .alertFirstButtonReturn else {
                password.stringValue = ""
                self.retry(.cancelled, link: link)
                return
            }
            guard !password.stringValue.isEmpty, !password.stringValue.contains("\0") else {
                password.stringValue = ""
                self.retry(.emptyPassphrase, link: link)
                return
            }
            var namedLaunch = launch
            if let name = nameField?.stringValue, !name.isEmpty { namedLaunch["profile_name"] = name }
            self.startConfirmed(link: link, launch: namedLaunch, config: config, password: password)
        }
        if embedded {
            let r = SignerReview.self
            let pairing = link != nil
            let origin = r.origin(pairing ? "Coordinator" : "Paired coordinator", config["coordinator"] as? String ?? "",
                                  "Member slot \(slot) · Testnet")
            let local = (nameField.map { r.field("Profile name (optional)", $0) } ?? []) + r.field("Local profile passphrase", password)
            let content = pairing
                ? [r.split(r.card("Signer endpoints", endpointRows(config)), r.card("Local profile",
                      [r.label("Protect this signer", weight: .semibold)] + local + [r.label("Your passphrase stays on this Mac. Configuration is saved only after unlock, unless overridden for this launch.", tone: r.muted)]))]
                : [r.split(r.card("Profile access", local), r.card("Touch ID", [r.label("Keep your recovery backup", weight: .semibold),
                      r.label("Changing enrolled fingerprints can make these keys unusable. Keep your words and encrypted backup to recover them.", tone: r.muted)])),
                   r.disclosure("Signer endpoints", endpointRows(config))]
            presentPrompt(SignerReview(section: pairing ? "Signer setup · 04 / 04" : "This Mac",
                title: pairing ? "Review configuration" : "Unlock signer",
                intro: pairing ? "Check the endpoints chosen by the coordinator before pairing this Mac."
                    : "Unlocking opens the local profile. It never approves a payment.",
                content: [origin] + content + launchOverrideNotice,
                hint: pairing ? "Pairing is not a payment approval." : "The coordinator address is read-only.",
                actions: [pairing ? "Pair" : "Unlock", "Cancel"], primary: 0), fields: fields,
                escape: .alertSecondButtonReturn, completion: confirmed)
        } else {
            let alert = NSAlert()
            let endpoints = configurationText(config)
            alert.messageText = link == nil ? "Unlock your paired signer" : "Pair this device with slot \(slot)?"
            alert.informativeText = link == nil
                ? "\(endpoints)\nFor a new device, cancel and open a pairing link from the wallet. Your passphrase stays in this app."
                : "\(endpoints)\nCreate or unlock your local profile below. These values are saved once it unlocks."
            if let nameField {
                let group = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 60))
                group.addSubview(nameField)
                group.addSubview(password)
                alert.accessoryView = group
            } else {
                alert.accessoryView = password
            }
            alert.addButton(withTitle: link == nil ? "Unlock" : "Pair")
            alert.addButton(withTitle: "Cancel")
            let answer: NSApplication.ModalResponse
            if link == nil {
                NSApp.activate(ignoringOtherApps: true)
                alert.window.initialFirstResponder = password
                answer = alert.runModal()
            } else {
                answer = runDecisionAlert(alert, escape: .alertSecondButtonReturn, fields: fields)
            }
            alert.window.endEditing(for: password)
            confirmed(answer)
        }
    }

    private func startConfirmed(link: String?, launch: [String: Any], config: [String: Any], password: NSSecureTextField) {
        var confirmed = launch
        confirmed["config"] = config
        if embedded { confirmed["embedded"] = true }
        guard let json = try? JSONSerialization.data(withJSONObject: confirmed), let request = String(data: json, encoding: .utf8) else {
            password.stringValue = ""
            retry(.unexpected, link: link)
            return
        }
        var secret = Array(password.stringValue.utf8CString)
        password.stringValue = ""
        running = true
        DispatchQueue.global(qos: .userInitiated).async {
            defer { _ = secret.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            let code = request.withCString { request in
                secret.withUnsafeMutableBufferPointer { pass in loki_member_app_pair(request, pass.baseAddress!, nativeNotice, nativeApprove, nativeConfirmRoster, nativeConnect) }
            }
            DispatchQueue.main.async {
                let failure: SignerStartFailure
                switch code {
                case 3: failure = .unlock
                case 4: failure = .deviceKey
                case 5: failure = .registrationRefused
                case 6: failure = .registrationFailed
                case 7: failure = self.startupKeyFailure ?? .deviceKey
                case 8: failure = .registrationRosterUnavailable
                case 9: failure = .invalidProfileName
                case 10: failure = .cancelled
                default: failure = .unexpected
                }
                self.startupKeyFailure = nil
                // A local failure before the claim was sent leaves the link usable.
                self.stopped(failure, link: code == 0 ? nil : self.unusedPairingLink(link))
            }
        }
    }

    private func beginRecovery() {
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        field.placeholderString = "https://wallet.example"
        field.setAccessibilityLabel("Original coordinator HTTPS address")
        let next: (NSApplication.ModalResponse) -> Void = { answer in
            guard answer == .alertFirstButtonReturn else { self.retry(.cancelled, link: self.retryLink); return }
            self.loadRecoveryConfiguration(origin: field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        if embedded {
            let r = SignerReview.self
            presentPrompt(SignerReview(section: "Recovery · fresh profile", title: "Enter original coordinator",
                intro: "Use the HTTPS origin this signer was paired with.", content: [
                    r.card("Original coordinator HTTPS origin", [field]),
                    r.info("Next: check the address", "Continue shows the canonical origin for you to confirm before contacting it."),
                ], hint: "Use the origin without a page or path.", actions: ["Continue", "Cancel"], primary: 0), fields: [field], completion: next)
            return
        }
        let alert = NSAlert()
        alert.messageText = "Enter your original coordinator"
        alert.informativeText = "Use the HTTPS origin of the wallet that your old Mac was paired with."
        alert.accessoryView = field
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        next(alert.runModal())
    }

    private func loadRecoveryConfiguration(origin entered: String) {
        let launch: [String: Any] = ["args": args, "restore_origin": entered]
        let reply = nativeQuery(loki_member_app_pairing_target, launch)
        guard let target = reply["target"] as? [String: Any], let origin = target["coordinator"] as? String else {
            retry(.coordinatorOrigin, link: retryLink)
            return
        }
        confirmCoordinator(origin) { answer in
            guard answer == .alertFirstButtonReturn else { self.retry(.cancelled, link: self.retryLink); return }
            DispatchQueue.global(qos: .userInitiated).async {
                let reply = nativeQuery(loki_member_app_configuration, launch)
                DispatchQueue.main.async { self.confirmRecovery(launch: launch, reply: reply) }
            }
        }
    }

    private func confirmRecovery(launch: [String: Any], reply: [String: Any]) {
        guard let config = reply["config"] as? [String: Any] else {
            retry(.configuration, link: retryLink)
            return
        }
        if embedded, config["network"] as? String != "testnet" { retry(.testnetOnly, link: retryLink); return }
        if config["confirm_witness_fingerprint"] as? Bool == true, launch["witness_confirmation"] == nil {
            confirmWitnesses(config) { code in
                guard let code else { self.retry(.cancelled, link: self.retryLink); return }
                var verified = launch
                verified["witness_confirmation"] = code
                self.confirmRecovery(launch: verified, reply: reply)
            }
            return
        }
        let next: (NSApplication.ModalResponse) -> Void = { answer in
            guard answer == .alertFirstButtonReturn else { self.retry(.cancelled, link: self.retryLink); return }
            self.restoreProfile(launch: launch, config: config)
        }
        if embedded {
            let r = SignerReview.self
            presentPrompt(SignerReview(section: "Recovery · fresh profile", title: "Review recovery configuration",
                intro: "Confirm the network and endpoints before choosing the encrypted backup.", content: [
                    r.origin("Original coordinator", config["coordinator"] as? String ?? "", "Testnet · Member slot is resolved from the backup and roster."),
                    r.card("Signer endpoints", endpointRows(config)),
                ] + launchOverrideNotice, hint: "Continue opens the macOS file picker.", actions: ["Continue", "Cancel"], primary: 0), completion: next)
            return
        }
        let alert = NSAlert()
        alert.messageText = "Review the signer configuration"
        alert.informativeText = configurationText(config)
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        next(alert.runModal())
    }

    private func restoreProfile(launch: [String: Any], config: [String: Any]) {
        var confirmed = launch
        confirmed["config"] = config
        if embedded { confirmed["embedded"] = true }
        guard let json = try? JSONSerialization.data(withJSONObject: confirmed), let request = String(data: json, encoding: .utf8) else {
            retry(.unexpected, link: retryLink)
            return
        }
        collectRestoreInput(newProfile: true) { result in
            switch result {
            case .failure(let failure): self.retry(failure, link: self.retryLink)
            case .success(let input): self.runProfileRestore(request: request, input: input)
            }
        }
    }

    private func collectRestoreInput(newProfile: Bool, complete: @escaping (Result<RecoveryInput, SignerStartFailure>) -> Void) {
        if embedded {
            MainActor.assumeIsolated { restoreInput(newProfile: newProfile, signer: self, complete: complete) }
        } else {
            complete(restoreInput(newProfile: newProfile))
        }
    }

    private func runProfileRestore(request: String, input: RecoveryInput) {
        running = true
        DispatchQueue.global(qos: .userInitiated).async {
            let error = request.withCString { request in
                input.file.withCString { file in
                    input.words.withUnsafeMutableBufferPointer { words in
                        input.pass.withUnsafeMutableBufferPointer { pass in
                            input.fingerprint.withCString { fingerprint in
                                recoveryError(loki_member_app_restore_profile(request, words.baseAddress, words.count,
                                    pass.baseAddress, pass.count, file, fingerprint, nativeNotice, nativeApprove, nativeConfirmRoster, nativeConnect))
                            }
                        }
                    }
                }
            }
            DispatchQueue.main.async {
                self.stopped(error ?? .unexpected, link: error == .restoredButStopped ? nil : self.retryLink)
            }
        }
    }

    @objc func restoreVault(_ sender: Any?) {
        guard !prompting else { return }
        guard running else {
            if profile()["profile"] as? String == "fresh" { start(queuedLink ?? retryLink) }
            else { retry(.unlockToRestore, link: nil) }
            return
        }
        prompting = true
        collectRestoreInput(newProfile: false) { result in
            switch result {
            case .failure(let failure):
                if self.embedded { self.finishWalletOperation(failure) }
                else {
                    if failure != .cancelled { showRecoveryResult(error: failure) }
                    self.prompting = false
                }
            case .success(let input): self.runVaultRestore(input)
            }
        }
    }

    private func runVaultRestore(_ input: RecoveryInput) {
        if embedded { walletWork.enter() }
        DispatchQueue.global(qos: .userInitiated).async {
            let error = input.file.withCString { file in
                input.words.withUnsafeMutableBufferPointer { words in
                    input.fingerprint.withCString { fingerprint in
                        recoveryError(loki_member_app_restore_vault(words.baseAddress, words.count, file, fingerprint))
                    }
                }
            }
            DispatchQueue.main.async {
                defer { if self.embedded { self.walletWork.leave() } }
                if self.embedded {
                    if error == .wrongProfile, self.profile()["profile"] as? String == "profile" {
                        self.presentPrompt(SignerReview(section: "Recovery", title: "Could not restore vault",
                            intro: SignerStartFailure.wrongProfile.message, content: [
                                SignerReview.info("Your profile is unchanged", "Try a matching backup, or review starting over if you intended to restore a different profile."),
                            ], hint: "Nothing has moved or been replaced.", actions: ["Back", "Review starting over"], primary: 1)) { answer in
                            if answer == .alertSecondButtonReturn { self.confirmSetAside() }
                            else { self.finishWalletOperation(error) }
                        }
                        return
                    }
                    if error == nil { self.walletNotice = "Vault restored on this Mac." }
                    self.finishWalletOperation(error)
                    return
                }
                if error == .wrongProfile {
                    let state = self.profile()["profile"] as? String
                    let alert = NSAlert()
                    alert.messageText = "Could not restore vault"
                    alert.informativeText = SignerStartFailure.wrongProfile.message
                    if state == "vault" { alert.informativeText += "\n\n" + SignerStartFailure.protectedProfile.message }
                    alert.addButton(withTitle: "OK")
                    if state == "profile" { alert.addButton(withTitle: "Start over…") }
                    self.retryLink = nil
                    if alert.runModal() == .alertSecondButtonReturn, self.confirmStandaloneSetAside() { return }
                } else {
                    showRecoveryResult(error: error)
                }
                self.prompting = false
            }
        }
    }

    @objc func disconnectWalletTabs(_ sender: Any?) {
        loki_member_app_disconnect_wallet_tabs()
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(startOver(_:)) {
            return !prompting && !lockingForAbsence && NSApp.modalWindow == nil && profile()["profile"] as? String == "profile"
        }
        return true
    }

    @objc fileprivate func startOver(_ sender: NSMenuItem) {
        guard validateMenuItem(sender) else { return }
        prompting = true
        if !confirmStandaloneSetAside() { prompting = false }
    }

    @objc func showStatus(_ sender: Any?) { statusWindow.show() }

    @objc func showLog(_ sender: Any?) { SignerLog.showInFinder() }
}

func nativeSignerArguments(_ arguments: [String]) -> [String] {
    var args = arguments
    if !args.contains("--data") {
        let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("LokiSigner")
        args += ["--data", root.path]
    }
    if !args.contains("--port") { args += ["--port", "0"] }
    return args
}

func runNativeSigner(arguments: [String], link: String?) -> Never {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let menu = NSMenu()
    let item = NSMenuItem()
    let actions = NSMenu(title: "LokiSigner")
    let delegate = NativeSigner(args: nativeSignerArguments(arguments), link: link)
    let status = actions.addItem(withTitle: "Status…", action: #selector(NativeSigner.showStatus(_:)), keyEquivalent: "")
    status.target = delegate
    let showAddresses = actions.addItem(withTitle: "Vault addresses…", action: #selector(VaultAddressesWindow.show(_:)), keyEquivalent: "")
    showAddresses.target = delegate.vaultAddresses
    let restore = actions.addItem(withTitle: "Restore a vault…", action: #selector(NativeSigner.restoreVault(_:)), keyEquivalent: "")
    restore.target = delegate
    let startOver = actions.addItem(withTitle: "Start over…", action: #selector(NativeSigner.startOver(_:)), keyEquivalent: "")
    startOver.target = delegate
    let log = actions.addItem(withTitle: "Show Log in Finder", action: #selector(NativeSigner.showLog(_:)), keyEquivalent: "")
    log.target = delegate
    actions.addItem(.separator())
    let disconnect = actions.addItem(withTitle: "Disconnect all wallet tabs", action: #selector(NativeSigner.disconnectWalletTabs(_:)), keyEquivalent: "")
    disconnect.target = delegate
    actions.addItem(withTitle: "Quit and lock LokiSigner", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    item.submenu = actions
    menu.addItem(item)
    app.mainMenu = menu
    app.delegate = delegate
    withExtendedLifetime(delegate) { app.run() }
    exit(0)
}

/// `LokiSigner approve`: a real 2-of-3 DKG and payment whose quorum members each ask the
/// payment dialog above before signing. Exit 0 = signed after approval, 3 = refused.
final class ApprovalSelftest: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        if CommandLine.arguments.contains("--queued-approval") {
            let expire = CommandLine.arguments.contains("--expire")
            DispatchQueue.main.async { self.checkQueuedApproval(expire: expire) }
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let rc = loki_signer_approval_selftest(nativeApprove)
            print(rc == 0 ? "APPROVAL SELFTEST PASS: payment signed only after native approval"
                : rc == 3 ? "APPROVAL SELFTEST REFUSED: the member refused; no signature share was released"
                : "APPROVAL SELFTEST FAILED (code \(rc))")
            fflush(stdout)
            exit(rc)
        }
    }

    /// Exercise the same main-queue modal ownership as Connect and roster.
    private func checkQueuedApproval(expire: Bool) {
        let blocker = NSAlert()
        blocker.messageText = "Existing dialog (approval self-test)"
        blocker.addButton(withTitle: "Close")
        let launch = Timer(timeInterval: 0.05, repeats: false) { _ in
            precondition(NSApp.modalWindow === blocker.window)
            DispatchQueue.global(qos: .userInitiated).async {
                let result = waitForApprovalDialog(cancellation: { 0 }, timeout: expire ? 0.4 : 3) { remaining, _ in
                    precondition(!expire && NSApp.modalWindow == nil && remaining < 2.8)
                    return .alertSecondButtonReturn
                }
                precondition(result == (expire ? 2 : 1))
                if expire {
                    let checked = DispatchWorkItem {
                        precondition(NSApp.modalWindow === blocker.window)
                        precondition(approvalEndedWindow?.title == "Payment approval timed out")
                        print("APPROVAL QUEUE SELFTEST PASS: timed out while the other dialog was open")
                        exit(0)
                    }
                    RunLoop.main.perform(inModes: [.modalPanel]) { checked.perform() }
                } else {
                    print("APPROVAL QUEUE SELFTEST PASS: presented after the other dialog closed")
                    exit(0)
                }
            }
        }
        let close = Timer(timeInterval: 0.9, repeats: false) { _ in
            precondition(!expire, "queued approval did not time out while modal")
            NSApp.stopModal()
        }
        let watchdog = Timer(timeInterval: 5, repeats: false) { _ in
            fatalError("queued approval self-test did not finish")
        }
        RunLoop.main.add(launch, forMode: .modalPanel)
        RunLoop.main.add(close, forMode: .modalPanel)
        RunLoop.main.add(watchdog, forMode: .common)
        _ = blocker.runModal()
    }
}

func runApprovalSelftest() -> Never {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let delegate = ApprovalSelftest()
    app.delegate = delegate
    withExtendedLifetime(delegate) { app.run() }
    exit(0)
}
