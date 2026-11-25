import AppKit

@_silgen_name("loki_member_app_vault_addresses")
func loki_member_app_vault_addresses() -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_can_view_addresses")
func loki_member_app_can_view_addresses() -> Int32

private struct VaultAddressReply: Decodable {
    struct Vault: Decodable {
        let vault: String?
        let name: String?
        let slot: UInt16?
        let network: String?
        let address: String?
        let error: String?
    }

    let vaults: [Vault]?
    let error: String?

    static func load() -> Self? {
        let reply = loki_member_app_vault_addresses()
        defer { loki_member_app_free(reply) }
        guard let reply else { return nil }
        return try? JSONDecoder().decode(Self.self, from: Data(String(cString: reply).utf8))
    }
}

private final class VaultListDocument: NSView {
    override var isFlipped: Bool { true }
}

final class VaultAddressesWindow: NSObject {
    private lazy var window = makeWindow()
    private let rows = NSStackView()
    private lazy var refreshButton = NSButton(title: "Refresh", target: self, action: #selector(refresh(_:)))
    private var session: UUID?
    private var addresses: [String] = []

    @objc func show(_ sender: Any?) {
        window.makeKeyAndOrderFront(sender)
        NSApp.activate(ignoringOtherApps: true)
        if session != nil { refresh(sender) }
        else { showLocked() }
    }

    func setUnlocked(_ unlocked: Bool) {
        session = unlocked ? UUID() : nil
        if unlocked {
            refreshButton.isEnabled = true
            if rows.window?.isVisible == true { refresh(nil) }
        } else {
            showLocked()
        }
    }

    private func showLocked() {
        session = nil
        refreshButton.isEnabled = false
        rows.window?.endEditing(for: nil)
        clearRows()
        rows.addArrangedSubview(NSTextField(labelWithString: "Unlock LokiSigner to view vault addresses."))
    }

    private func makeWindow() -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 390),
            styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Vault addresses"
        window.isReleasedWhenClosed = false
        window.center()

        let intro = NSTextField(wrappingLabelWithString:
            "Share an address copied from LokiSigner, or match the vault ID and full address with the wallet before sharing. macOS may ask for Touch ID to verify an address.")
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .lineBorder
        let document = VaultListDocument()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document
        rows.orientation = .vertical
        rows.alignment = .leading
        rows.spacing = 16
        rows.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        rows.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(rows)

        let content = NSStackView(views: [intro, scroll, refreshButton])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 12
        content.translatesAutoresizingMaskIntoConstraints = false
        let root = window.contentView!
        root.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 20),
            content.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -20),
            content.topAnchor.constraint(equalTo: root.topAnchor, constant: 16),
            content.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -16),
            intro.widthAnchor.constraint(equalTo: content.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: content.widthAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            rows.leadingAnchor.constraint(equalTo: document.leadingAnchor),
            rows.trailingAnchor.constraint(equalTo: document.trailingAnchor),
            rows.topAnchor.constraint(equalTo: document.topAnchor),
            rows.bottomAnchor.constraint(equalTo: document.bottomAnchor),
        ])
        return window
    }

    @objc private func refresh(_ sender: Any?) {
        guard let session, refreshButton.isEnabled else { return }
        refreshButton.isEnabled = false
        render(nil, loading: true)
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = VaultAddressReply.load()
            DispatchQueue.main.async {
                guard self.session == session else { return }
                guard loki_member_app_can_view_addresses() != 0 else { self.showLocked(); return }
                self.render(reply, loading: false)
                self.refreshButton.isEnabled = true
            }
        }
    }

    private func clearRows() {
        rows.arrangedSubviews.forEach { $0.removeFromSuperview() }
        addresses.removeAll()
    }

    private func render(_ reply: VaultAddressReply?, loading: Bool) {
        clearRows()
        guard let vaults = reply?.vaults, !vaults.isEmpty else {
            let message = loading ? "Checking vault addresses…" : reply?.error
                ?? (reply?.vaults != nil ? "This member has no active vaults." : "LokiSigner could not list vaults.")
            rows.addArrangedSubview(NSTextField(labelWithString: message))
            return
        }

        for vault in vaults {
            let row = NSStackView()
            row.orientation = .vertical
            row.alignment = .leading
            row.spacing = 6
            let label = NSTextField(labelWithString: "Vault name (set by creator):")
            label.textColor = .secondaryLabelColor
            let name = untrustedLine(vault.name ?? "Unavailable")
            name.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            let nameLine = NSStackView(views: [label, name])
            nameLine.spacing = 5
            row.addArrangedSubview(nameLine)

            if let slot = vault.slot {
                let network = vault.network.map { "Network: \($0)    ·    " } ?? ""
                row.addArrangedSubview(NSTextField(labelWithString: "\(network)Member \(slot) in this vault"))
            }
            if let id = vault.vault, let address = vault.address, vault.error == nil {
                row.addArrangedSubview(NSTextField(labelWithString: "Vault ID:"))
                let identifier = NSTextField(wrappingLabelWithString: id)
                identifier.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
                identifier.lineBreakMode = .byCharWrapping
                identifier.isSelectable = true
                identifier.setAccessibilityLabel("Vault ID")
                row.addArrangedSubview(identifier)
                identifier.widthAnchor.constraint(equalTo: row.widthAnchor).isActive = true
                let field = NSTextField(wrappingLabelWithString: address)
                field.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
                field.lineBreakMode = .byCharWrapping
                field.isSelectable = true
                field.setAccessibilityLabel("Receive address")
                row.addArrangedSubview(field)
                field.widthAnchor.constraint(equalTo: row.widthAnchor).isActive = true
                let copy = NSButton(title: "Copy address", target: self, action: #selector(copyAddress(_:)))
                copy.tag = addresses.count
                addresses.append(address)
                row.addArrangedSubview(copy)
            } else {
                row.addArrangedSubview(NSTextField(labelWithString: vault.error ?? "LokiSigner could not verify this vault’s receive address."))
            }
            rows.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: rows.widthAnchor, constant: -28).isActive = true
            nameLine.widthAnchor.constraint(lessThanOrEqualTo: row.widthAnchor).isActive = true
        }
    }

    @objc private func copyAddress(_ sender: NSButton) {
        guard session != nil, loki_member_app_can_view_addresses() != 0 else { showLocked(); return }
        guard let window = rows.window, sender.window === window, addresses.indices.contains(sender.tag) else { return }
        NSPasteboard.general.clearContents()
        if NSPasteboard.general.setString(addresses[sender.tag], forType: .string) {
            sender.title = "Copied"
        }
    }
}
