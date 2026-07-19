import AppKit
import SwiftUI

/// Main console: Status · Origins · Audit · Settings
struct ConsoleView: View {
    @ObservedObject var agent: AgentController
    @State private var tab = 0
    @State private var showPasswordSheet = false
    @State private var vaultPassword = ""

    var body: some View {
        VStack(spacing: 0) {
            header
            Picker("", selection: $tab) {
                Text("Status").tag(0)
                Text("Origins").tag(1)
                Text("Audit").tag(2)
                Text("Settings").tag(3)
            }
            .pickerStyle(.segmented)
            .padding()

            Group {
                switch tab {
                case 0: statusTab
                case 1: originsTab
                case 2: auditTab
                default: settingsTab
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(minWidth: 560, minHeight: 420)
        .sheet(isPresented: $showPasswordSheet) {
            passwordSheet
        }
        .onAppear { agent.refresh() }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(nsImage: MenuBarIcon.image(running: agent.agentRunning))
                .resizable()
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text("PVFS Companion").font(.headline)
                Text(agent.statusLine)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if agent.agentRunning {
                Button("Lock") { agent.lockAgent() }
                Button("Stop") { agent.stopAgent() }
            } else if !agent.needsSetup {
                Button("Start") { startAgent() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var statusTab: some View {
        Form {
            Section("Agent") {
                LabeledContent("State", value: agent.agentRunning ? "Running" : "Stopped")
                LabeledContent("Sealing", value: sealingLabel)
                if !agent.identityFull.isEmpty {
                    LabeledContent("Identity") {
                        Text(agent.identityFull)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                if !agent.socketPath.isEmpty {
                    LabeledContent("Socket", value: agent.socketPath)
                }
                if !agent.webAgentURL.isEmpty {
                    LabeledContent("Sign-in URL") {
                        Text(agent.webAgentURL)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                LabeledContent("Vault") {
                    Text(agent.vaultPath.path)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            Section("Approvals") {
                Text("High-authority signing (admit/revoke, etc.) shows a **system dialog** from the agent process (`--prompt desktop`). Approve or deny there — that is the security boundary.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let err = agent.lastError, !err.isEmpty {
                Section("Last error") {
                    Text(err).foregroundStyle(.red).font(.caption)
                }
            }
            if !agent.statusDetail.isEmpty {
                Section("Raw status") {
                    Text(agent.statusDetail)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
        .padding(.bottom)
    }

    private var originsTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Connected web origins (Sign in with PVFS)")
                    .font(.headline)
                Spacer()
                Button("Refresh") { agent.refreshOrigins() }
            }
            .padding()
            if agent.origins.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "globe")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("No connected origins").font(.headline)
                    Text("When a local web app asks to sign in, you approve its origin once.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding()
            } else {
                List {
                    ForEach(agent.origins) { g in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(g.origin).font(.body.monospaced())
                                Text(g.expiry).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Revoke", role: .destructive) {
                                agent.revokeOrigin(g.origin)
                            }
                        }
                    }
                }
            }
        }
    }

    private var auditTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Signature audit log")
                    .font(.headline)
                Spacer()
                Button("Refresh") { agent.refreshAudit() }
                Button("Reveal in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([agent.auditPath])
                }
            }
            .padding()
            Text(agent.auditPath.path)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .padding(.horizontal)
            if agent.auditEntries.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "list.bullet.rectangle")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("No audit entries yet").font(.headline)
                    Text("Approvals, denials, lock, and unlock events appear here.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding()
            } else {
                List(agent.auditEntries) { e in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(e.summary).font(.body)
                        Text(e.line)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private var settingsTab: some View {
        Form {
            Section("Startup") {
                Toggle("Open at login", isOn: Binding(
                    get: { agent.openAtLogin },
                    set: { agent.setOpenAtLogin($0) }
                ))
                Text(LoginItem.statusDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let note = agent.loginItemNote {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                Text("macOS may ask you to allow this under System Settings → General → Login Items.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("SSH with companion (desktop SSO)") {
                TextField("Default host (user@host)", text: Binding(
                    get: { CompanionSSH.defaultHost },
                    set: { CompanionSSH.defaultHost = $0 }
                ))
                TextField("Remote socket (empty = auto unique)", text: Binding(
                    get: { CompanionSSH.remoteSocketPath },
                    set: { CompanionSSH.remoteSocketPath = $0 }
                ))
                .font(.system(.body, design: .monospaced))
                Text("Leave remote socket empty so each session gets a unique path (avoids “forwarding failed” if a previous window is still open). Menu bar → SSH opens Terminal with the companion reverse-forwarded.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if agent.agentRunning {
                    Button("Open SSH session…") {
                        let sock = agent.socketPath
                        if !sock.isEmpty, FileManager.default.fileExists(atPath: sock) {
                            CompanionSSH.openSessionInteractive(localSocket: sock)
                        } else {
                            CompanionSSH.openSessionInteractive(localSocket: sock)
                        }
                    }
                } else {
                    Text("Start the agent to enable SSH with companion.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Section("Paths") {
                LabeledContent("App bundle") {
                    Text(Bundle.main.bundlePath)
                        .font(.caption2.monospaced())
                        .textSelection(.enabled)
                }
                LabeledContent("Companion binary") {
                    Text(agent.companionBinary.path)
                        .font(.caption2.monospaced())
                        .textSelection(.enabled)
                }
            }
            Section("Setup") {
                Button("Open setup wizard…") {
                    // Handled by parent openWindow — use notification
                    NotificationCenter.default.post(name: .openSetup, object: nil)
                }
            }
        }
        .formStyle(.grouped)
    }

    private var passwordSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Vault password").font(.headline)
            Text("Enter the vault password (not your 24-word recovery phrase).")
                .font(.callout)
                .foregroundStyle(.secondary)
            SecureField("Password", text: $vaultPassword)
            HStack {
                Button("Cancel") { showPasswordSheet = false }
                Spacer()
                Button("Start") {
                    do {
                        try agent.startAgent(vaultPassword: vaultPassword)
                        vaultPassword = ""
                        showPasswordSheet = false
                    } catch {
                        agent.lastError = error.localizedDescription
                    }
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private var sealingLabel: String {
        switch agent.sealing {
        case .keychain: return "macOS Keychain"
        case .passphrase: return "Vault password"
        case .none: return "—"
        case .unknown: return "Unknown"
        }
    }

    private func startAgent() {
        do {
            try agent.startAgent()
        } catch AgentError.needsPassword {
            showPasswordSheet = true
        } catch {
            if agent.sealing == .passphrase {
                showPasswordSheet = true
            } else {
                agent.lastError = error.localizedDescription
            }
        }
    }
}

extension Notification.Name {
    static let openSetup = Notification.Name("pvfs.openSetup")
}

/// Load custom menu-bar / window icon from the app bundle Resources.
enum MenuBarIcon {
    static func image(running: Bool) -> NSImage {
        let name = "MenuBarIcon"
        if let url = Bundle.main.url(forResource: name, withExtension: "png"),
           let img = NSImage(contentsOf: url) {
            img.isTemplate = true
            // Filled look when running: slightly larger; template still monochrome
            img.size = NSSize(width: running ? 18 : 16, height: running ? 18 : 16)
            return img
        }
        // Fallback SF Symbol via AppKit
        let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
        let sym = NSImage(systemSymbolName: running ? "lock.shield.fill" : "lock.shield", accessibilityDescription: "PVFS")
        sym?.isTemplate = true
        return sym?.withSymbolConfiguration(config) ?? NSImage()
    }
}
