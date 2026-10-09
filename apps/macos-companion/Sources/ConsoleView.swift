import AppKit
import SwiftUI

/// Main console (PVOS D226): Status · Keys · Sign-ins · Audit · Details ·
/// Settings. Information has tabs of its own; Settings holds only what can
/// be set. Keys' history, the audit log and Revoke ask for Touch ID.
struct ConsoleView: View {
    @ObservedObject var agent: AgentController
    @StateObject private var unlocker = Unlocker()
    @State private var tab = 0
    @State private var showPasswordSheet = false
    @State private var vaultPassword = ""

    var body: some View {
        VStack(spacing: 0) {
            header
            Picker("", selection: $tab) {
                Text("Status").tag(0)
                Text("Keys").tag(1)
                Text("Sign-ins").tag(2)
                Text("Audit").tag(3)
                Text("Details").tag(4)
                Text("Settings").tag(5)
            }
            .pickerStyle(.segmented)
            .padding()

            Group {
                switch tab {
                case 0: statusTab
                case 1: keysTab
                case 2: signInsTab
                case 3: auditTab
                case 4: detailsTab
                default: settingsTab
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(minWidth: 600, minHeight: 460)
        .sheet(isPresented: $showPasswordSheet) {
            passwordSheet
        }
        .onAppear { agent.refresh() }
        // One unlock lasts while the window is open and the agent unlocked.
        .onDisappear { unlocker.lock() }
        .onChange(of: agent.agentRunning) { running in
            if !running { unlocker.lock() }
        }
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
                Button("Lock") {
                    agent.lockAgent()
                    unlocker.lock()
                }
                Button("Stop") { agent.stopAgent() }
            } else if !agent.needsSetup {
                Button("Start") { startAgent() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: Status — how it is now.

    private var statusTab: some View {
        Form {
            Section("Agent") {
                LabeledContent("State", value: agent.agentRunning ? "Running" : "Stopped")
                LabeledContent("Phrases served", value: phrasesServed)
                LabeledContent("Sealing", value: sealingLabel)
            }
            if agent.restartNeeded && agent.agentRunning {
                restartSection
            }
            if let err = agent.lastError, !err.isEmpty {
                Section("Last error") {
                    Text(err).foregroundStyle(.red).font(.caption).textSelection(.enabled)
                }
            }
            Section("Approvals") {
                Text("High-authority signing (admitting or revoking a device, promotions) always shows a **system dialog** from the agent. Approve or deny there — that is the security boundary.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .onAppear { agent.refreshKeys() }
    }

    private var phrasesServed: String {
        guard let r = agent.keysReport else { return "—" }
        let served = r.phrases.filter(\.served).count
        return "\(served) of \(r.phrases.count)"
    }

    // MARK: Keys — public keys; their history behind Touch ID.

    private var keysTab: some View {
        Form {
            KeysSections(agent: agent, unlocker: unlocker)
            Section {
                Button("Set up another phrase…") {
                    NotificationCenter.default.post(name: .openSetup, object: nil)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { agent.refreshKeys() }
    }

    // MARK: Sign-ins — the web origins it signs in to.

    private var signInsTab: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Connected web sign-ins (Sign in with PVFS)")
                    .font(.headline)
                Spacer()
                Button("Refresh") { agent.refreshOrigins() }
            }
            .padding()
            if let e = unlocker.lastError {
                Text(e).font(.caption).foregroundStyle(.red).padding(.horizontal)
            }
            if agent.origins.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "globe")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("No connected sign-ins").font(.headline)
                    Text("When a web app asks to sign in, you approve its origin once.")
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
                            Button(unlocker.unlocked ? "Revoke" : "Revoke 🔒", role: .destructive) {
                                unlocker.unlock("revoke the sign-in for \(g.origin)") {
                                    agent.revokeOrigin(g.origin)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: Audit — behind Touch ID.

    @ViewBuilder
    private var auditTab: some View {
        if !unlocker.unlocked {
            LockedPlaceholder(what: "The audit log", unlocker: unlocker)
        } else {
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
    }

    // MARK: Details — where things are, for troubleshooting.

    private var detailsTab: some View {
        Form {
            Section("This companion") {
                LabeledContent("Build", value: agent.companionVersion.isEmpty ? "—" : agent.companionVersion)
                if !agent.identityFull.isEmpty {
                    LabeledContent("Identity") {
                        Text(agent.identityFull).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }
                if !agent.socketPath.isEmpty {
                    LabeledContent("Socket") {
                        Text(agent.socketPath).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
                if !agent.webAgentURL.isEmpty {
                    LabeledContent("Sign-in URL") {
                        Text(agent.webAgentURL).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
            }
            Section("Files") {
                LabeledContent("Log file") {
                    VStack(alignment: .trailing, spacing: 4) {
                        Text(agent.logFileURL.path).font(.caption2.monospaced()).textSelection(.enabled)
                        HStack {
                            Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([agent.logFileURL]) }
                            Button("Open in Console") {
                                let console = URL(fileURLWithPath: "/System/Applications/Utilities/Console.app")
                                NSWorkspace.shared.open([agent.logFileURL], withApplicationAt: console, configuration: NSWorkspace.OpenConfiguration())
                            }
                        }
                    }
                }
                LabeledContent("Vault") {
                    Text(agent.vaultPath.path).font(.caption2.monospaced()).textSelection(.enabled)
                }
                ForEach(agent.extraVaultPaths, id: \.self) { v in
                    LabeledContent("Vault") {
                        Text(v.path).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
                LabeledContent("Audit log") {
                    Text(agent.auditPath.path).font(.caption2.monospaced()).textSelection(.enabled)
                }
                LabeledContent("App bundle") {
                    Text(Bundle.main.bundlePath).font(.caption2.monospaced()).textSelection(.enabled)
                }
                LabeledContent("Companion binary") {
                    Text(agent.companionBinary.path).font(.caption2.monospaced()).textSelection(.enabled)
                }
            }
            if !agent.statusDetail.isEmpty {
                Section {
                    DisclosureGroup("Raw status") {
                        Text(agent.statusDetail)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { agent.refreshCompanionVersion() }
    }

    // MARK: Settings — only what can be set.

    private var settingsTab: some View {
        Form {
            Section("Startup") {
                Toggle("Open at login", isOn: Binding(
                    get: { agent.openAtLogin },
                    set: { agent.setOpenAtLogin($0) }
                ))
                if let note = agent.loginItemNote {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            Section {
                Picker("Lock after idle", selection: $agent.idleLockMinutes) {
                    Text("Never").tag(0)
                    Text("5 minutes").tag(5)
                    Text("15 minutes").tag(15)
                    Text("30 minutes").tag(30)
                    Text("1 hour").tag(60)
                }
                Picker("Signatures per minute", selection: $agent.rateLimit) {
                    Text("No limit").tag(0)
                    Text("30").tag(30)
                    Text("60").tag(60)
                    Text("120").tag(120)
                }
            } header: {
                Text("Security")
            } footer: {
                Text("Applies when the agent restarts.").font(.caption).foregroundStyle(.secondary)
            }
            LoggingSection(agent: agent)
            Section("SSH with companion") {
                TextField("Default host (user@host)", text: Binding(
                    get: { CompanionSSH.defaultHost },
                    set: { CompanionSSH.defaultHost = $0 }
                ))
                TextField("Remote socket (empty = a new one each session)", text: Binding(
                    get: { CompanionSSH.remoteSocketPath },
                    set: { CompanionSSH.remoteSocketPath = $0 }
                ))
                .font(.system(.body, design: .monospaced))
            }
            if agent.restartNeeded && agent.agentRunning {
                restartSection
            }
        }
        .formStyle(.grouped)
    }

    private var restartSection: some View {
        Section {
            HStack {
                Text("Settings changed — the agent uses them once it restarts.")
                    .font(.callout)
                Spacer()
                Button("Restart agent") { restartAgent() }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private func restartAgent() {
        do {
            try agent.restartAgent()
        } catch AgentError.needsPassword {
            showPasswordSheet = true
        } catch {
            agent.lastError = error.localizedDescription
        }
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
