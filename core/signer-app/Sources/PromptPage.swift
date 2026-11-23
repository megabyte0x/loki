import AppKit

// These are native document components; their contents and actions never cross the wallet bridge.
struct SignerReview {
    let section: String
    let title: String
    let intro: String
    let content: [NSView]
    let hint: String
    let actions: [String]
    var primary: Int? = nil
    var destructive = false

    static let mint = color(0x2fd8a8, 0x087e65)
    static let ink = color(0xe8eaf0, 0x141822)
    static let muted = color(0x9ba5b8, 0x526074)
    static let gold = color(0xe8b44a, 0x8c5a10)
    static let panel = color(0x13161d, 0xffffff)
    static let soft = color(0x181c25, 0xeef1f3)
    static let line = color(0x30343d, 0xd2d8dd)
    static let hero = color(0x142022, 0xf4f9f8)

    static func color(_ dark: UInt32, _ light: UInt32) -> NSColor {
        NSColor(name: nil) { appearance in
            let rgb = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat(rgb >> 16) / 255, green: CGFloat((rgb >> 8) & 255) / 255,
                           blue: CGFloat(rgb & 255) / 255, alpha: 1)
        }
    }

    static func label(_ text: String, size: CGFloat = 13, weight: NSFont.Weight = .regular,
                      tone: NSColor = ink, mono: Bool = false, wrap: Bool = true,
                      selectable: Bool = false) -> NSTextField {
        let label = wrap ? NSTextField(wrappingLabelWithString: text) : NSTextField(labelWithString: text)
        label.font = mono ? .monospacedSystemFont(ofSize: size, weight: weight) : .systemFont(ofSize: size, weight: weight)
        label.textColor = tone
        label.isSelectable = selectable
        if wrap { label.lineBreakMode = mono ? .byCharWrapping : .byWordWrapping }
        return label
    }

    static func caption(_ text: String) -> NSView {
        let field = label(text.uppercased(), size: 10, weight: .medium, tone: mint, mono: true)
        field.attributedStringValue = NSAttributedString(string: field.stringValue, attributes: [
            .font: field.font!, .foregroundColor: mint, .kern: 1.1,
        ])
        return field
    }

    static func column(_ views: [NSView], spacing: CGFloat = 9) -> NSStackView {
        let stack = PromptDocument(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = spacing
        for view in views { view.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true }
        return stack
    }

    static func card(_ title: String, _ views: [NSView], emphasized: Bool = false) -> NSView {
        surface(column([caption(title)] + views), padding: 17, tone: emphasized ? hero : panel, radius: 14)
    }

    static func surface(_ content: NSView, padding: CGFloat, tone: NSColor, radius: CGFloat) -> NSView {
        let box = ReviewSurface(tone: tone, radius: radius)
        content.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(content)
        let snug = content.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -padding)
        snug.priority = .defaultHigh
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: box.topAnchor, constant: padding),
            content.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: padding),
            content.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -padding),
            content.bottomAnchor.constraint(lessThanOrEqualTo: box.bottomAnchor, constant: -padding),
            snug,
        ])
        return box
    }

    static func split(_ left: NSView, _ right: NSView) -> NSView {
        let stack = NSStackView(views: [left, right])
        stack.orientation = .horizontal
        stack.alignment = .top
        stack.spacing = 12
        stack.distribution = .fillEqually
        left.heightAnchor.constraint(equalTo: right.heightAnchor).isActive = true
        return stack
    }

    static func row(_ name: String, _ value: String, wide: Bool = false) -> NSView {
        let title = label(name, size: 12, tone: muted, wrap: false)
        let detail = label(value, size: 12, weight: .medium, mono: true, selectable: true)
        if wide { return column([title, detail], spacing: 4) }
        title.setContentCompressionResistancePriority(.required, for: .horizontal)
        detail.setContentHuggingPriority(.defaultLow, for: .horizontal)
        detail.alignment = .right
        let stack = NSStackView(views: [title, detail])
        stack.alignment = .firstBaseline
        stack.spacing = 10
        detail.trailingAnchor.constraint(equalTo: stack.trailingAnchor).isActive = true
        return stack
    }

    static func quote(_ text: String) -> NSView {
        let field = untrustedLine(text)
        field.isBordered = false
        field.drawsBackground = false
        field.textColor = ink
        return surface(field, padding: 8, tone: soft, radius: 8)
    }

    static func origin(_ title: String, _ value: String, _ detail: String) -> NSView {
        card(title, [label(value, size: 22, weight: .semibold, mono: true, selectable: true),
                     label(detail, tone: muted)], emphasized: true)
    }

    static func info(_ title: String, _ text: String, warning: Bool = false) -> NSView {
        surface(column([label(title, weight: .semibold, tone: warning ? gold : ink), label(text, tone: muted)],
                       spacing: 5), padding: 14, tone: panel, radius: 12)
    }

    static func tiles(_ strings: [String], columns: Int = 6, secret: Bool = false) -> NSView {
        let rows = stride(from: 0, to: strings.count, by: columns).map { start in
            let row = NSStackView(views: strings[start ..< min(start + columns, strings.count)].map { value in
                let text = label(value, size: secret ? 11 : 21, weight: .semibold, mono: true, wrap: false)
                text.alignment = .center
                text.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
                return surface(text, padding: 8, tone: soft, radius: 8)
            })
            row.spacing = 7
            row.distribution = .fillEqually
            return row
        }
        return column(rows, spacing: 6)
    }

    static func field(_ title: String, _ field: NSTextField) -> [NSView] {
        field.font = .systemFont(ofSize: 13)
        field.controlSize = .large
        field.heightAnchor.constraint(greaterThanOrEqualToConstant: 30).isActive = true
        return [label(title, size: 12, tone: muted), field]
    }

    static func disclosure(_ title: String, _ rows: [NSView]) -> NSView {
        let contents = column(rows, spacing: 12)
        contents.isHidden = true
        return surface(column([ReviewDisclosure(title: title, contents: contents), contents]),
                       padding: 12, tone: panel, radius: 12)
    }
}

private final class ReviewSurface: NSView {
    let tone: NSColor
    let radius: CGFloat
    init(tone: NSColor, radius: CGFloat) {
        self.tone = tone
        self.radius = radius
        super.init(frame: .zero)
        wantsLayer = true
    }
    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }
    override var wantsUpdateLayer: Bool { true }
    override func viewDidChangeEffectiveAppearance() { super.viewDidChangeEffectiveAppearance(); needsDisplay = true }
    override func updateLayer() {
        layer?.cornerRadius = radius
        layer?.borderWidth = 1
        layer?.masksToBounds = true
        layer?.backgroundColor = tone.cgColor
        layer?.borderColor = SignerReview.line.cgColor
    }
}

private final class ReviewDisclosure: NSButton {
    private let contents: NSView
    init(title: String, contents: NSView) {
        self.contents = contents
        super.init(frame: .zero)
        self.title = title
        image = NSImage(systemSymbolName: "chevron.down", accessibilityDescription: nil)
        imagePosition = .imageTrailing
        alignment = .left
        isBordered = false
        font = .systemFont(ofSize: 13, weight: .semibold)
        target = self
        action = #selector(toggle)
        setAccessibilityLabel(title)
        setAccessibilityRole(.disclosureTriangle)
        setAccessibilityValue(false)
    }
    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }
    @objc private func toggle() {
        contents.isHidden.toggle()
        image = NSImage(systemSymbolName: contents.isHidden ? "chevron.down" : "chevron.up", accessibilityDescription: nil)
        setAccessibilityValue(!contents.isHidden)
        if !contents.isHidden {
            enclosingScrollView?.layoutSubtreeIfNeeded()
            contents.scrollToVisible(contents.bounds)
        }
    }
}

/// When a native prompt may take input, kept apart from AppKit. Input counts only after the window
/// has stayed key for `delay` (anti-clickjacking), and a click that focuses the window or starts the
/// delay never reaches a control.
struct PromptArming {
    static let delay: TimeInterval = 1

    /// Uptime from which input counts; infinity until armed.
    private(set) var acceptsInput = TimeInterval.infinity
    private var pending: TimeInterval?

    enum Click: Equatable {
        /// The window isn't key: make it key and drop the click.
        case focusWindow
        /// The window is key but the delay never started (a missed notification): start it and drop the click.
        case arm
        case deliver
        case drop
    }

    var armed: Bool { acceptsInput.isFinite }

    /// The window became key at `now`. Returns how long to wait before calling `delayElapsed`.
    mutating func becameKey(at now: TimeInterval) -> TimeInterval {
        acceptsInput = .infinity
        pending = now + Self.delay
        return Self.delay
    }

    /// Arms only if the window is still key and visible when the delay ends. Otherwise the delay is
    /// spent, so the next click in a key window starts a new one instead of being dropped forever.
    mutating func delayElapsed(windowIsKey: Bool, visible: Bool) -> Bool {
        guard let deadline = pending else { return false }
        pending = nil
        guard windowIsKey, visible else { return false }
        acceptsInput = deadline
        return true
    }

    mutating func resignedKey() {
        pending = nil
        acceptsInput = .infinity
    }

    func accepts(_ time: TimeInterval) -> Bool { time >= acceptsInput }

    /// A mouse-down inside the prompt, at event time `time`.
    func click(at time: TimeInterval, windowIsKey: Bool) -> Click {
        guard windowIsKey else { return .focusWindow }
        if accepts(time) { return .deliver }
        return armed || pending != nil ? .drop : .arm
    }
}

/// A regular document view in the wallet window. No modal session or Flutter decision channel.
final class SignerPromptPage: NSView {
    private let fields: [NSTextField]
    private let buttons: [NSButton]
    private let expiry: TimeInterval
    private let escape: NSApplication.ModalResponse?
    private var complete: ((NSApplication.ModalResponse) -> Void)?
    private var arming = PromptArming()
    private let hint: NSTextField
    private let readyHint: String
    /// Shown while the prompt ignores input, so a locked prompt says how to unlock it.
    static let waitingHint = "Click here to review this request."
    private var enable: Timer?
    private var timeout: Timer?
    private var monitor: Any?
    private var observers: [NSObjectProtocol] = []
    private weak var previousResponder: NSResponder?
    private weak var closeButton: NSButton?
    private var closeWasEnabled = false
    let requiresAcknowledgment: Bool

    init(_ review: SignerReview, fields: [NSTextField], timeout: TimeInterval?,
         escape: NSApplication.ModalResponse?, complete: @escaping (NSApplication.ModalResponse) -> Void) {
        self.fields = fields
        self.escape = escape
        requiresAcknowledgment = escape == nil
        self.complete = complete
        expiry = timeout.map { ProcessInfo.processInfo.systemUptime + $0 } ?? .infinity
        readyHint = review.hint
        hint = SignerReview.label(Self.waitingHint, size: 11, tone: SignerReview.muted)
        buttons = review.actions.enumerated().map { index, title in
            let button = NSButton(title: title, target: nil, action: nil)
            button.tag = index
            button.bezelStyle = .rounded
            button.controlSize = .large
            button.font = .systemFont(ofSize: 13, weight: .semibold)
            if review.primary == index {
                button.bezelColor = review.destructive ? .systemRed : SignerReview.mint
            }
            button.isEnabled = false
            button.setAccessibilityElement(true)
            button.setAccessibilityRole(.button)
            button.setAccessibilityLabel(title)
            return button
        }
        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false
        let kicker = SignerReview.caption(review.section + "  /  Local signer")
        let title = SignerReview.label(review.title, size: 31, weight: .semibold)
        let detail = SignerReview.label(review.intro, tone: SignerReview.muted)
        let body = SignerReview.column([kicker, title, detail] + review.content, spacing: 11)
        body.setCustomSpacing(4, after: kicker)
        body.setCustomSpacing(7, after: title)
        body.setCustomSpacing(16, after: detail)
        body.translatesAutoresizingMaskIntoConstraints = false

        let scroll = NSScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.documentView = body
        let ordered = buttons.filter { $0.tag != review.primary } + buttons.filter { $0.tag == review.primary }
        let actions = NSStackView(views: ordered)
        actions.spacing = 10
        actions.setHuggingPriority(.required, for: .horizontal)
        actions.translatesAutoresizingMaskIntoConstraints = false
        hint.translatesAutoresizingMaskIntoConstraints = false
        for button in buttons {
            button.target = self
            button.action = #selector(choose(_:))
            button.heightAnchor.constraint(greaterThanOrEqualToConstant: 34).isActive = true
            button.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        addSubview(scroll)
        addSubview(actions)
        addSubview(hint)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: topAnchor, constant: 16),
            scroll.leadingAnchor.constraint(equalTo: leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: trailingAnchor, constant: 12),
            scroll.bottomAnchor.constraint(equalTo: actions.topAnchor, constant: -14),
            body.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            body.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            body.widthAnchor.constraint(equalTo: scroll.widthAnchor, constant: -12),
            actions.trailingAnchor.constraint(equalTo: trailingAnchor),
            actions.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -14),
            hint.leadingAnchor.constraint(equalTo: leadingAnchor),
            hint.trailingAnchor.constraint(lessThanOrEqualTo: actions.leadingAnchor, constant: -16),
            hint.centerYAnchor.constraint(equalTo: actions.centerYAnchor),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    override var acceptsFirstResponder: Bool { true }
    func attach(to parent: NSWindow) {
        guard let host = parent.contentView else { finish(.abort); return }
        previousResponder = parent.firstResponder
        host.addSubview(self, positioned: .above, relativeTo: nil)
        // Match the Flutter content slot; leave its sidebar, title controls, and footer usable.
        NSLayoutConstraint.activate([
            leadingAnchor.constraint(equalTo: host.leadingAnchor, constant: 230),
            trailingAnchor.constraint(equalTo: host.trailingAnchor, constant: -26),
            topAnchor.constraint(equalTo: host.topAnchor, constant: 43),
            bottomAnchor.constraint(equalTo: host.bottomAnchor, constant: -36),
        ])
        if requiresAcknowledgment, let button = parent.standardWindowButton(.closeButton) {
            closeButton = button
            closeWasEnabled = button.isEnabled
            button.isEnabled = false
        }
        let center = NotificationCenter.default
        observers = [
            center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: parent, queue: nil) { [weak self] _ in self?.arm() },
            center.addObserver(forName: NSWindow.didResignKeyNotification, object: parent, queue: nil) { [weak self] _ in self?.disarm() },
            center.addObserver(forName: NSWindow.willCloseNotification, object: parent, queue: nil) { [weak self] _ in self?.finish(.abort) },
            // A prompt that became key while minimized couldn't arm; arm when it is shown again.
            center.addObserver(forName: NSWindow.didDeminiaturizeNotification, object: parent, queue: nil) { [weak self, weak parent] _ in
                if parent?.isKeyWindow == true { self?.arm() }
            },
        ]
        for field in fields where field is NSSecureTextField {
            observers.append(center.addObserver(forName: NSControl.textDidBeginEditingNotification, object: field, queue: nil) { _ in
                guard let editor = field.currentEditor() as? NSTextView else { return }
                editor.isContinuousSpellCheckingEnabled = false
                editor.isGrammarCheckingEnabled = false
                editor.isAutomaticSpellingCorrectionEnabled = false
                editor.isAutomaticTextReplacementEnabled = false
                editor.allowsUndo = false
            })
        }
        monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .leftMouseUp]) { [weak self] event in
            guard let self else { return event }
            return filtered(event)
        }
        if expiry.isFinite {
            let timer = Timer(timeInterval: max(0, expiry - ProcessInfo.processInfo.systemUptime), repeats: false) { [weak self] _ in self?.finish(.abort) }
            timeout = timer
            RunLoop.main.add(timer, forMode: .common)
        }
        if parent.isKeyWindow {
            arm()
        } else {
            SignerLog.write("A LokiSigner prompt is waiting for its window to be focused.")
        }
    }

    private func arm() {
        disarm()
        window?.makeFirstResponder((fields.first as NSView?) ?? self)
        hint.stringValue = readyHint
        let wait = arming.becameKey(at: ProcessInfo.processInfo.systemUptime)
        let timer = Timer(timeInterval: wait, repeats: false) { [weak self] _ in
            guard let self, arming.delayElapsed(windowIsKey: window?.isKeyWindow == true, visible: window?.isVisible == true) else { return }
            buttons.forEach { $0.isEnabled = true }
        }
        enable = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    private func disarm() {
        enable?.invalidate()
        arming.resignedKey()
        buttons.forEach { $0.isEnabled = false }
        hint.stringValue = Self.waitingHint
    }

    /// Makes the prompt's window key in response to the user's own click. The click is dropped;
    /// `didBecomeKey` then starts the usual delay. Unsolicited prompts never call this.
    private func focusWindow(_ window: NSWindow) {
        if !NSApp.isActive { NSApp.activate(ignoringOtherApps: true) }
        window.makeKeyAndOrderFront(nil)
    }

    private func filtered(_ event: NSEvent) -> NSEvent? {
        guard let window, event.window === window else { return event }
        if event.type != .keyDown {
            guard bounds.contains(convert(event.locationInWindow, from: nil)) else { return event }
            let click = arming.click(at: event.timestamp, windowIsKey: window.isKeyWindow)
            guard event.type == .leftMouseDown else { return click == .deliver ? event : nil }
            switch click {
            case .deliver: return event
            case .drop: return nil
            case .focusWindow: focusWindow(window); return nil
            case .arm: arm(); return nil
            }
        }
        if event.modifierFlags.contains(.command), event.keyCode == 12 || event.keyCode == 13 {
            return requiresAcknowledgment ? nil : event // Quit / Close
        }
        if event.keyCode == 53 { // Escape never accepts.
            if let escape, arming.accepts(event.timestamp), !event.isARepeat { finish(escape) }
            return nil
        }
        let focused = window.firstResponder
        let editing = fields.first { $0 === focused || (focused != nil && $0.currentEditor() === focused) }
        guard editing != nil || focused === self || (focused as? NSView)?.isDescendant(of: self) == true else { return event }
        guard arming.accepts(event.timestamp) else { return nil }
        switch event.keyCode {
        case 36, 76: return nil // Never default to a decision.
        case 48:
            guard !event.isARepeat else { return nil }
            let controls: [NSView] = fields.map { $0 as NSView } + buttons.map { $0 as NSView } + disclosures(in: self)
            let reverse = event.modifierFlags.contains(.shift)
            let current = controls.firstIndex { $0 === ((editing as NSResponder?) ?? focused) }
            let next = current.map { ($0 + (reverse ? controls.count - 1 : 1)) % controls.count }
                ?? (reverse ? controls.count - 1 : 0)
            window.makeFirstResponder(controls[next])
            return nil
        case 49 where editing == nil:
            if !event.isARepeat { (focused as? NSButton)?.performClick(nil) }
            return nil
        default: return event
        }
    }

    private func disclosures(in view: NSView) -> [NSView] {
        view.subviews.flatMap { $0 is ReviewDisclosure ? [$0] : disclosures(in: $0) }
    }

    @objc private func choose(_ sender: NSButton) {
        let now = ProcessInfo.processInfo.systemUptime
        guard arming.accepts(now), window?.isKeyWindow == true else { return }
        finish(now >= expiry ? .abort : NSApplication.ModalResponse(rawValue: NSApplication.ModalResponse.alertFirstButtonReturn.rawValue + sender.tag))
    }

    // Recovery words are shown once: require acknowledgment instead of letting navigation discard them.
    func leave() { if escape != nil { finish(.abort) } }

    func finish(_ answer: NSApplication.ModalResponse) {
        guard let complete else { return }
        self.complete = nil
        disarm()
        timeout?.invalidate()
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        if let monitor { NSEvent.removeMonitor(monitor) }
        for field in fields { window?.endEditing(for: field) }
        closeButton?.isEnabled = closeWasEnabled
        let parent = window
        removeFromSuperview()
        if let previousResponder { parent?.makeFirstResponder(previousResponder) }
        complete(answer)
    }
}

private final class PromptDocument: NSStackView {
    override var isFlipped: Bool { true }
}
