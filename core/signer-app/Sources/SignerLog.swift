import AppKit
import Darwin

@_silgen_name("loki_member_app_set_log_sink")
private func loki_member_app_set_log_sink(_ sink: @convention(c) (UnsafePointer<CChar>) -> Void)

enum SignerLog {
    private static let lock = NSLock()
    private static let directory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/LokiSigner", isDirectory: true)
    private static let current = directory.appendingPathComponent("LokiSigner.log")
    private static let older = directory.appendingPathComponent("LokiSigner.previous.log")
    private static let limit = 256 * 1024

    static func start() {
        loki_member_app_set_log_sink { event in SignerLog.write(String(cString: event)) }
        write("LokiSigner opened.")
    }

    static func write(_ event: String) {
        lock.lock()
        defer { lock.unlock() }
        let line = Data("\(ISO8601DateFormatter().string(from: Date())) \(event)\n".utf8)
        guard line.count <= limit else { return }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        guard let file = openLog() else { return }
        defer { try? file.close() }
        guard let size = try? file.seekToEnd() else { return }
        if size + UInt64(line.count) <= UInt64(limit) {
            try? file.write(contentsOf: line)
        } else if rename(current.path, older.path) == 0, let next = openLog() {
            defer { try? next.close() }
            try? next.write(contentsOf: line)
        }
    }

    private static func openLog() -> FileHandle? {
        var folder = stat()
        guard lstat(directory.path, &folder) == 0, folder.st_mode & S_IFMT == S_IFDIR,
              folder.st_uid == geteuid(), folder.st_mode & 0o077 == 0 else { return nil }
        let fd = open(current.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return nil }
        var file = stat()
        guard fstat(fd, &file) == 0, file.st_mode & S_IFMT == S_IFREG, file.st_uid == geteuid(),
              file.st_nlink == 1, file.st_mode & 0o077 == 0 else {
            close(fd)
            return nil
        }
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    static func showInFinder() {
        guard let file = openLog() else {
            let alert = NSAlert()
            alert.messageText = "LokiSigner couldn’t open its log"
            alert.informativeText = "Check that LokiSigner can write to your Library’s Logs folder."
            alert.runModal()
            return
        }
        try? file.close()
        NSWorkspace.shared.activateFileViewerSelecting([current])
    }
}
