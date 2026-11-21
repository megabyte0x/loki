import AppKit
import CoreGraphics

@_silgen_name("loki_member_app_status")
func loki_member_app_status(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

final class SignerStatusWindow: NSObject, NSWindowDelegate {
    private let load: () -> [String: Any]
    private let localError: () -> String?
    private let canUnlock: () -> Bool
    private let unlock: () -> Void
    private let values = (0..<6).map { _ in NSTextField(wrappingLabelWithString: "—") }
    private lazy var button = NSButton(title: "Unlock…", target: self, action: #selector(unlockClicked))
    private lazy var window = makeWindow()
    private var refreshTimer: Timer?
    private var refreshing = false

    init(load: @escaping () -> [String: Any], localError: @escaping () -> String?,
         canUnlock: @escaping () -> Bool, unlock: @escaping () -> Void) {
        self.load = load
        self.localError = localError
        self.canUnlock = canUnlock
        self.unlock = unlock
    }

    func show() {
        window.makeKeyAndOrderFront(nil)
        refresh()
        if refreshTimer == nil {
            let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in self?.refresh() }
            RunLoop.main.add(timer, forMode: .common)
            RunLoop.main.add(timer, forMode: .modalPanel)
            refreshTimer = timer
        }
    }

    func windowWillClose(_ notification: Notification) {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    @objc private func unlockClicked() {
        guard canUnlock() else { return }
        button.isEnabled = false
        unlock()
    }

    private func refresh() {
        guard window.isVisible else { return }
        button.isEnabled = canUnlock()
        guard !refreshing else { return }
        refreshing = true
        DispatchQueue.global(qos: .userInitiated).async {
            let status = self.load()["status"] as? [String: Any]
            DispatchQueue.main.async {
                self.refreshing = false
                guard self.window.isVisible else { return }
                let unlocked = status?["unlocked"] as? Bool == true
                self.button.title = status != nil && !unlocked && status?["coordinator"] as? String == nil ? "Set Up…" : "Unlock…"
                let text = [
                    status == nil ? "Unavailable" : unlocked ? "Unlocked" : "Not unlocked",
                    status?["registered"] as? Bool == true ? "Registered" : unlocked ? "Not registered" : "Not checked while locked",
                    status?["coordinator"] as? String ?? "Not paired",
                    (status?["slot"] as? NSNumber)?.stringValue ?? "—",
                    (status?["wallet_tabs"] as? NSNumber)?.stringValue ?? "—",
                    (status?["vaults"] as? NSNumber)?.stringValue ?? "—",
                ]
                for (field, value) in zip(self.values, text) where field.stringValue != value { field.stringValue = value }
                self.lastError.stringValue = status == nil ? "LokiSigner couldn’t read its status."
                    : self.localError() ?? status?["last_error"] as? String ?? "None this launch"
            }
        }
    }

    private let lastError = NSTextField(wrappingLabelWithString: "—")

    private func makeWindow() -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 500, height: 285),
            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "LokiSigner Status"
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()

        values[2].lineBreakMode = .byCharWrapping
        let labels = ["Profile", "Registration", "Coordinator", "Member slot", "Wallet tabs", "Active vaults", "Last error"]
        let grid = NSGridView(views: zip(labels, values + [lastError]).map { title, value in
            let label = NSTextField(labelWithString: title)
            label.textColor = .secondaryLabelColor
            value.isSelectable = true
            value.setAccessibilityLabel(title)
            return [label, value]
        })
        grid.rowSpacing = 8
        grid.columnSpacing = 16
        grid.column(at: 0).xPlacement = .leading
        grid.column(at: 0).width = 108
        grid.column(at: 1).xPlacement = .fill
        grid.yPlacement = .top

        let content = NSStackView(views: [grid, button])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 18
        content.translatesAutoresizingMaskIntoConstraints = false
        let root = window.contentView!
        root.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            content.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            content.topAnchor.constraint(equalTo: root.topAnchor, constant: 20),
            content.bottomAnchor.constraint(lessThanOrEqualTo: root.bottomAnchor, constant: -16),
            grid.widthAnchor.constraint(equalTo: content.widthAnchor),
        ])
        return window
    }
}

final class SignerPresence: NSObject {
    private let workspace = NSWorkspace.shared.notificationCenter
    private let distributed = DistributedNotificationCenter.default()
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private let timer: Timer
    private let lock: () -> Void

    init(lock: @escaping () -> Void) {
        self.lock = lock
        let anyInput = CGEventType(rawValue: UInt32.max)!
        timer = Timer(timeInterval: 5, repeats: true) { _ in
            if Self.screenIsLocked || CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyInput) >= 15 * 60 {
                lock()
            }
        }
        super.init()
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append((workspace, workspace.addObserver(forName: name, object: nil, queue: .main) { _ in lock() }))
        }
        let screenLock = Notification.Name("com.apple.screenIsLocked")
        // Distributed delivery must not wait until the user returns to the app.
        distributed.addObserver(self, selector: #selector(screenLocked(_:)), name: screenLock,
            object: nil, suspensionBehavior: .deliverImmediately)
        RunLoop.main.add(timer, forMode: .common)
        RunLoop.main.add(timer, forMode: .modalPanel)
    }

    private static var screenIsLocked: Bool {
        // CoreGraphics reports the WindowServer session's lock bit; the distributed
        // notification alone is not evidence, and this key is not a public constant.
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        return session?["CGSSessionScreenIsLocked"] as? Bool == true
    }

    @objc private func screenLocked(_ notification: Notification) {
        guard Self.screenIsLocked else { return }
        if Thread.isMainThread { lock() }
        else { RunLoop.main.perform(inModes: [.common, .modalPanel], block: lock) }
    }

    deinit {
        timer.invalidate()
        for (center, observer) in observers { center.removeObserver(observer) }
        distributed.removeObserver(self)
    }
}
