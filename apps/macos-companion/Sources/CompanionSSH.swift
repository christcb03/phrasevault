import AppKit
import Foundation

/// Reverse-forward the local companion socket over SSH (desktop SSO).
/// Remote sessions get `PVFS_COMPANION_SOCKET` pointing at this machine's agent.
enum CompanionSSH {
    private static let hostKey = "sshDefaultHost"
    private static let remoteSocketKey = "sshRemoteSocket"
    private static let recentHostsKey = "sshRecentHosts"
    private static let maxRecent = 8

    /// Empty (default) → unique path per session under /tmp (avoids "remote port
    /// forwarding failed" when a previous socket is still bound or left behind).
    static let defaultRemoteSocketHint = "(auto unique per session)"

    static var defaultHost: String {
        get { UserDefaults.standard.string(forKey: hostKey) ?? "" }
        set { UserDefaults.standard.set(newValue.trimmingCharacters(in: .whitespacesAndNewlines), forKey: hostKey) }
    }

    /// Fixed remote socket path override. Empty = auto unique path each connect.
    static var remoteSocketPath: String {
        get { UserDefaults.standard.string(forKey: remoteSocketKey) ?? "" }
        set {
            UserDefaults.standard.set(
                newValue.trimmingCharacters(in: .whitespacesAndNewlines),
                forKey: remoteSocketKey
            )
        }
    }

    static var recentHosts: [String] {
        UserDefaults.standard.stringArray(forKey: recentHostsKey) ?? []
    }

    static func rememberHost(_ host: String) {
        let h = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !h.isEmpty else { return }
        var list = recentHosts.filter { $0 != h }
        list.insert(h, at: 0)
        if list.count > maxRecent { list = Array(list.prefix(maxRecent)) }
        UserDefaults.standard.set(list, forKey: recentHostsKey)
        if defaultHost.isEmpty { defaultHost = h }
    }

    /// Open Terminal with SSH reverse-forward of `localSocket` to the given host.
    static func openSession(host: String, localSocket: String) throws {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else {
            throw SSHError.message("No SSH host configured.")
        }
        guard FileManager.default.fileExists(atPath: localSocket) else {
            throw SSHError.message(
                "Companion socket not found at \(localSocket).\nStart the agent first."
            )
        }

        let remoteSock: String = {
            let fixed = remoteSocketPath
            if !fixed.isEmpty { return fixed }
            let id = String(UUID().uuidString.prefix(8)).lowercased()
            return "/tmp/pvfs-companion-fwd-\(id).sock"
        }()

        // -t: allocate a TTY so the remote shell is interactive (shows a prompt).
        // StreamLocalBindUnlink: replace a stale remote socket file if present.
        // Unique remote path by default avoids clashes with a still-open first session.
        let remoteShell = """
        export PVFS_COMPANION_SOCKET=\(shellSingleQuote(remoteSock)); \
        trap 'rm -f -- "$PVFS_COMPANION_SOCKET" 2>/dev/null' EXIT; \
        printf '%s\\n' "pvfs: companion SSO active → $PVFS_COMPANION_SOCKET"; \
        printf '%s\\n' "pvfs: remote pvfs will use this socket for signing (approve on your Mac)."; \
        exec "${SHELL:-/bin/bash}" -il
        """
        let ssh = [
            "ssh",
            "-t",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "StreamLocalBindUnlink=yes",
            "-R", "\(remoteSock):\(localSocket)",
            host,
            remoteShell,
        ]
        let commandLine = ssh.map(shellSingleQuote).joined(separator: " ")

        rememberHost(host)
        try runInTerminal(commandLine)
    }

    /// Prompt for host (pre-filled with default) and open a session.
    static func openSessionInteractive(localSocket: String) {
        let alert = NSAlert()
        alert.messageText = "SSH with companion"
        alert.informativeText =
            "Reverse-forwards your local companion into the remote session.\n" +
            "Remote pvfs will use this Mac for signing (approve prompts appear here)."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Connect")
        alert.addButton(withTitle: "Cancel")

        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.stringValue = defaultHost.isEmpty ? (recentHosts.first ?? "") : defaultHost
        field.placeholderString = "user@host  (e.g. chris@presubuntu)"
        alert.accessoryView = field
        alert.window.initialFirstResponder = field

        AppActivation.bringToFront()
        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else { return }

        let host = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else {
            presentError("Enter an SSH host (user@hostname).")
            return
        }
        defaultHost = host
        do {
            try openSession(host: host, localSocket: localSocket)
        } catch {
            presentError(error.localizedDescription)
        }
    }

    static func openDefaultOrPrompt(localSocket: String) {
        let host = defaultHost
        if host.isEmpty {
            openSessionInteractive(localSocket: localSocket)
            return
        }
        do {
            try openSession(host: host, localSocket: localSocket)
        } catch {
            presentError(error.localizedDescription)
        }
    }

    // MARK: - helpers

    private static func runInTerminal(_ commandLine: String) throws {
        // Avoid AppleScript → Terminal (needs Automation permission and fails for
        // ad-hoc signed apps). Write a disposable .command script and open it via
        // Launch Services — Terminal (or the user's default) runs it without AE.
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pvfs-companion-ssh", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let scriptURL = dir.appendingPathComponent("ssh-\(UUID().uuidString).command")
        let body = """
        #!/bin/bash
        # PVFS Companion — desktop SSO SSH session (auto-generated; safe to delete)
        clear
        \(commandLine)
        status=$?
        echo
        if [ "$status" -ne 0 ]; then
          echo "pvfs: ssh exited with status $status"
          if [ "$status" -eq 255 ]; then
            echo "pvfs: tip — if you saw 'remote port forwarding failed', a previous"
            echo "      session may still hold the remote socket. Close other SSH"
            echo "      windows, or leave Remote socket path empty (auto unique)."
          fi
          read -r -p "Press Return to close… "
        fi
        rm -f -- \(shellSingleQuote(scriptURL.path))
        exit "$status"
        """
        try body.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: scriptURL.path
        )

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        proc.arguments = ["-a", "Terminal", scriptURL.path]
        do {
            try proc.run()
            proc.waitUntilExit()
            if proc.terminationStatus == 0 { return }
        } catch {
            // fall through
        }
        let ok = NSWorkspace.shared.open(scriptURL)
        if !ok {
            throw SSHError.message(
                "Could not open a terminal for the SSH session.\n" +
                "You can run manually:\n\(commandLine)"
            )
        }
    }

    private static func shellSingleQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private static func presentError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "SSH with companion"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        AppActivation.bringToFront()
        alert.runModal()
    }

    enum SSHError: LocalizedError {
        case message(String)
        var errorDescription: String? {
            switch self {
            case .message(let s): return s
            }
        }
    }
}
