import AppKit
import SwiftUI

/// Menu-bar app: setup, console (status/origins/audit/settings), embedded agent.
///
/// This is an agent (`LSUIElement`): no Dock icon. Look for the shield in the menu bar.
/// On first launch (no vault), the setup window opens automatically.
@main
struct PVFSCompanionApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var agent = AgentController()

    var body: some Scene {
        MenuBarExtra {
            MenuBarRoot(agent: agent)
        } label: {
            // Bootstrap must live on the *label* (status item), not the menu content.
            // Menu content's onAppear only runs after the user clicks the icon — so a
            // first-run setup window would never appear and it would look like a no-op.
            Image(nsImage: MenuBarIcon.image(running: agent.agentRunning))
                .accessibilityLabel("PVFS Companion")
                .modifier(LaunchBootstrap(agent: agent))
        }
        .menuBarExtraStyle(.menu)

        Window("PVFS Companion Setup", id: "setup") {
            SetupView(agent: agent)
        }
        .defaultSize(width: 520, height: 440)

        Window("PVFS Companion", id: "console") {
            ConsoleView(agent: agent)
        }
        .defaultSize(width: 600, height: 480)
    }
}

/// Bring an accessory (menu-bar) app to the foreground so SwiftUI windows are visible.
enum AppActivation {
    static func bringToFront() {
        NSApp.activate(ignoringOtherApps: true)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // If the user double-clicks the app while an instance is already running,
        // macOS usually reuses the process — but ad-hoc / different paths can start
        // a second agent. Prefer a single status item.
        let mine = Bundle.main.bundleIdentifier ?? "com.phrasevault.companion"
        let peers = NSWorkspace.shared.runningApplications.filter {
            $0.bundleIdentifier == mine && $0.processIdentifier != ProcessInfo.processInfo.processIdentifier
        }
        if let other = peers.first {
            other.activate(options: [.activateIgnoringOtherApps])
            NSApp.terminate(nil)
            return
        }
        NotificationCenter.default.post(name: .appDidFinishLaunching, object: nil)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        // Dock-less agent: clicking the app in Finder / reopen should surface UI.
        NotificationCenter.default.post(name: .appShouldReopen, object: nil)
        return true
    }
}

extension Notification.Name {
    static let appDidFinishLaunching = Notification.Name("pvfs.appDidFinishLaunching")
    static let appShouldReopen = Notification.Name("pvfs.appShouldReopen")
}

/// One-shot launch work attached to the menu-bar status item (appears at process start).
private struct LaunchBootstrap: ViewModifier {
    @ObservedObject var agent: AgentController
    @Environment(\.openWindow) private var openWindow
    @State private var didBootstrap = false

    func body(content: Content) -> some View {
        content
            .task { await bootstrapIfNeeded() }
            .onReceive(NotificationCenter.default.publisher(for: .appDidFinishLaunching)) { _ in
                Task { await bootstrapIfNeeded() }
            }
            .onReceive(NotificationCenter.default.publisher(for: .appShouldReopen)) { _ in
                Task { @MainActor in
                    agent.refresh()
                    if agent.needsSetup {
                        openWindow(id: "setup")
                    } else {
                        openWindow(id: "console")
                    }
                    AppActivation.bringToFront()
                }
            }
            .onReceive(NotificationCenter.default.publisher(for: .openSetup)) { _ in
                openWindow(id: "setup")
                AppActivation.bringToFront()
            }
    }

    @MainActor
    private func bootstrapIfNeeded() async {
        guard !didBootstrap else { return }
        didBootstrap = true
        agent.startPolling()
        // refresh() runs inside startPolling; needsSetup is set when vault is missing.
        if agent.needsSetup {
            openWindow(id: "setup")
            AppActivation.bringToFront()
        } else if agent.sealing == .keychain && !agent.agentRunning {
            try? agent.startAgent()
        }
    }
}

struct MenuBarRoot: View {
    @ObservedObject var agent: AgentController
    @Environment(\.openWindow) private var openWindow
    @State private var showPasswordSheet = false
    @State private var vaultPassword = ""

    var body: some View {
        Group {
            Text(agent.statusLine)
            if !agent.identityPreview.isEmpty {
                Text("id \(agent.identityPreview)")
            }
            Text(sealingText)
            Divider()
            if agent.needsSetup {
                Button("Setup…") {
                    openWindow(id: "setup")
                    AppActivation.bringToFront()
                }
            } else if agent.agentRunning {
                Button("Lock keys") { agent.lockAgent() }
                Button("Stop agent") { agent.stopAgent() }
            } else {
                Button("Start agent") { startAgent() }
            }
            Button("Open Companion…") {
                openWindow(id: "console")
                AppActivation.bringToFront()
            }
            Button("Refresh") { agent.refresh() }
            if !agent.needsSetup {
                Button("Setup wizard…") {
                    openWindow(id: "setup")
                    AppActivation.bringToFront()
                }
            }
            Divider()
            if agent.agentRunning {
                let hostLabel = CompanionSSH.defaultHost.isEmpty
                    ? "SSH with companion…"
                    : "SSH to \(CompanionSSH.defaultHost)…"
                Button(hostLabel) {
                    openSSH(prompt: CompanionSSH.defaultHost.isEmpty)
                }
                if !CompanionSSH.defaultHost.isEmpty {
                    Button("SSH to other host…") { openSSH(prompt: true) }
                }
                ForEach(CompanionSSH.recentHosts.filter { $0 != CompanionSSH.defaultHost }.prefix(4), id: \.self) { host in
                    Button("SSH to \(host)") {
                        openSSH(host: host)
                    }
                }
            }
            Divider()
            Toggle("Open at login", isOn: Binding(
                get: { agent.openAtLogin },
                set: { agent.setOpenAtLogin($0) }
            ))
            Divider()
            Button("Quit PVFS Companion") {
                agent.stopAgent()
                NSApp.terminate(nil)
            }
        }
        .sheet(isPresented: $showPasswordSheet) {
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
            .frame(width: 340)
        }
    }

    private var sealingText: String {
        switch agent.sealing {
        case .keychain: return "Keychain"
        case .passphrase: return "Password vault"
        case .none: return "No vault"
        case .unknown: return "Vault"
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

    private func localCompanionSocket() -> String? {
        let path = agent.socketPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !path.isEmpty, FileManager.default.fileExists(atPath: path) {
            return path
        }
        // Match pvfs-companion default when status hasn't filled socketPath yet.
        if let runtime = ProcessInfo.processInfo.environment["XDG_RUNTIME_DIR"], !runtime.isEmpty {
            let p = (runtime as NSString).appendingPathComponent("pvfs-companion.sock")
            if FileManager.default.fileExists(atPath: p) { return p }
        }
        let user = NSUserName()
        let tmp = "/tmp/pvfs-companion-\(user).sock"
        if FileManager.default.fileExists(atPath: tmp) { return tmp }
        return path.isEmpty ? nil : path
    }

    private func openSSH(prompt: Bool = false, host: String? = nil) {
        guard let sock = localCompanionSocket() else {
            let alert = NSAlert()
            alert.messageText = "SSH with companion"
            alert.informativeText = "Start the agent first so a companion socket is available."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            AppActivation.bringToFront()
            alert.runModal()
            return
        }
        if let host {
            do {
                try CompanionSSH.openSession(host: host, localSocket: sock)
            } catch {
                let alert = NSAlert()
                alert.messageText = "SSH with companion"
                alert.informativeText = error.localizedDescription
                alert.alertStyle = .warning
                alert.addButton(withTitle: "OK")
                AppActivation.bringToFront()
                alert.runModal()
            }
            return
        }
        if prompt {
            CompanionSSH.openSessionInteractive(localSocket: sock)
        } else {
            CompanionSSH.openDefaultOrPrompt(localSocket: sock)
        }
    }
}
