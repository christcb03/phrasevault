import AppKit
import Foundation
import SwiftUI

struct OriginGrant: Identifiable, Hashable {
    var id: String { origin }
    var origin: String
    var expiry: String
}

struct AuditEntry: Identifiable {
    let id = UUID()
    var line: String
    var summary: String
}

/// Talks to the embedded `pvfs-companion` binary: vault setup, serve lifecycle, status.
@MainActor
final class AgentController: ObservableObject {
    enum Sealing: String {
        case none
        case keychain
        case passphrase
        case unknown
    }

    @Published var vaultExists = false
    @Published var sealing: Sealing = .none
    @Published var agentRunning = false
    @Published var identityPreview: String = ""
    @Published var identityFull: String = ""
    @Published var webAgentURL: String = ""
    @Published var socketPath: String = ""
    @Published var statusLine: String = "Starting…"
    @Published var statusDetail: String = ""
    @Published var lastError: String?
    @Published var needsSetup = false
    @Published var needsVaultPassword = false
    @Published var origins: [OriginGrant] = []
    @Published var auditEntries: [AuditEntry] = []
    @Published var openAtLogin = false
    @Published var loginItemNote: String?
    /// PVOS D189 — Settings → Phrases & keys.
    @Published var keysReport: KeysReport?
    @Published var keysError: String?
    /// PVOS D226 — Settings → Logging.
    @Published var logDestinations: [LogDestinationRow] = []
    @Published var logError: String?
    @Published var logTestResults: [String: String] = [:]
    /// Details → Build.
    @Published var companionVersion: String = ""
    /// PVOS D226 — Settings → Security and Logging, passed to `serve` when it
    /// starts; a change while it runs asks for a restart.
    @Published var idleLockMinutes: Int = UserDefaults.standard.object(forKey: "idleLockMinutes") as? Int ?? 15 {
        didSet { UserDefaults.standard.set(idleLockMinutes, forKey: "idleLockMinutes"); markRestartNeeded() }
    }
    @Published var rateLimit: Int = UserDefaults.standard.object(forKey: "rateLimit") as? Int ?? 60 {
        didSet { UserDefaults.standard.set(rateLimit, forKey: "rateLimit"); markRestartNeeded() }
    }
    @Published var logLevel: String = UserDefaults.standard.string(forKey: "logLevel") ?? "info" {
        didSet { UserDefaults.standard.set(logLevel, forKey: "logLevel"); markRestartNeeded() }
    }
    @Published var restartNeeded = false

    private func markRestartNeeded() {
        if agentRunning { restartNeeded = true }
    }

    private var agentProcess: Process?
    private var statusTimer: Timer?
    /// Kept only in memory for re-unlock after lock on password vaults (never written to disk).
    private var sessionVaultPassword: String?

    var vaultPath: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/pvfs/companion.vault")
    }

    var auditPath: URL {
        vaultPath.deletingLastPathComponent().appendingPathComponent("companion.audit.jsonl")
    }

    /// PVOS D189 — every other keychain-sealed vault beside the default one
    /// (`media2.vault`, …): served by the same companion, which picks the
    /// phrase per request by the key the client names (a forest's root).
    /// Password-sealed ones are left out: the one password the app holds is
    /// the default vault's.
    var extraVaultPaths: [URL] {
        let dir = vaultPath.deletingLastPathComponent()
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return files
            .filter { $0.pathExtension == "vault" && $0.lastPathComponent != vaultPath.lastPathComponent }
            .filter { url in
                guard let data = try? Data(contentsOf: url),
                      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                else { return false }
                return (obj["sealing"] as? String) == "keychain"
            }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    var companionBinary: URL {
        if let exec = Bundle.main.executableURL {
            let sibling = exec.deletingLastPathComponent().appendingPathComponent("pvfs-companion")
            if FileManager.default.isExecutableFile(atPath: sibling.path) {
                return sibling
            }
        }
        let inBundle = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/pvfs-companion")
        if FileManager.default.isExecutableFile(atPath: inBundle.path) {
            return inBundle
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("target/release/pvfs-companion")
    }

    func refresh() {
        openAtLogin = LoginItem.isEnabled
        vaultExists = FileManager.default.fileExists(atPath: vaultPath.path)
        needsSetup = !vaultExists
        if !vaultExists {
            sealing = .none
            agentRunning = false
            statusLine = "Not set up — open Setup"
            identityPreview = ""
            identityFull = ""
            webAgentURL = ""
            origins = []
            statusDetail = ""
            return
        }
        if let text = runCompanion(args: ["status", "--vault", vaultPath.path], env: [:]) {
            parseStatus(text)
            statusDetail = text
        }
        refreshOrigins()
        refreshAudit()
    }

    func startPolling() {
        refresh()
        statusTimer?.invalidate()
        statusTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refresh()
            }
        }
    }

    func stopPolling() {
        statusTimer?.invalidate()
        statusTimer = nil
    }

    // MARK: - Setup

    func generatePhrase() throws -> String {
        guard let out = runCompanion(args: ["phrase-new"], env: [:]) else {
            throw AgentError.message(lastError ?? "phrase-new failed")
        }
        let phrase = out.trimmingCharacters(in: .whitespacesAndNewlines)
        guard phrase.split(separator: " ").count == 24 else {
            throw AgentError.message("unexpected phrase output")
        }
        return phrase
    }

    enum SealResult {
        case keychain
        case needsPassphrase(reason: String)
    }

    func trySealWithKeychain(phrase: String) throws -> SealResult {
        prepareVaultDir()
        if vaultExists {
            throw AgentError.message("A vault already exists at \(vaultPath.path). Remove it to re-setup.")
        }
        let env = ProcessInfo.processInfo.environment
        let result = runCompanionCapturing(
            args: ["init", "--vault", vaultPath.path, "--keychain"],
            env: env,
            stdin: phrase + "\n"
        )
        if result.exitCode == 0 {
            vaultExists = true
            sealing = .keychain
            needsSetup = false
            return .keychain
        }
        let err = result.stderr.isEmpty ? result.stdout : result.stderr
        return .needsPassphrase(reason: err)
    }

    func sealWithVaultPassword(phrase: String, vaultPassword: String) throws {
        prepareVaultDir()
        if FileManager.default.fileExists(atPath: vaultPath.path) {
            throw AgentError.message("A vault already exists. Remove it to re-setup.")
        }
        var env = ProcessInfo.processInfo.environment
        env["PVFS_COMPANION_PASSPHRASE"] = vaultPassword
        let result = runCompanionCapturing(
            args: ["init", "--vault", vaultPath.path, "--passphrase"],
            env: env,
            stdin: phrase + "\n"
        )
        guard result.exitCode == 0 else {
            throw AgentError.message(result.stderr.isEmpty ? result.stdout : result.stderr)
        }
        vaultExists = true
        sealing = .passphrase
        needsSetup = false
        sessionVaultPassword = vaultPassword
    }

    // MARK: - Agent lifecycle

    func startAgent(vaultPassword: String? = nil) throws {
        guard vaultExists else {
            throw AgentError.message("No vault — complete Setup first")
        }
        if agentProcess?.isRunning == true {
            return
        }
        // Prefer newly supplied password, then session cache
        let pass = vaultPassword ?? sessionVaultPassword
        if sealing == .passphrase, pass == nil || pass?.isEmpty == true {
            needsVaultPassword = true
            throw AgentError.needsPassword
        }
        if let pass, !pass.isEmpty {
            sessionVaultPassword = pass
        }

        let proc = Process()
        proc.executableURL = companionBinary
        var args = ["serve", "--vault", vaultPath.path]
        for extra in extraVaultPaths {
            args += ["--vault", extra.path]
        }
        args += ["--prompt", "desktop"]
        // PVOS D226 — Settings → Security.
        args += ["--idle-lock-secs", String(idleLockMinutes * 60), "--rate-limit", String(rateLimit)]
        proc.arguments = args
        var env = ProcessInfo.processInfo.environment
        if let pass, !pass.isEmpty {
            env["PVFS_COMPANION_PASSPHRASE"] = pass
        }
        // PVOS D226 — Settings → Logging → Level.
        env["PVFS_LOG_LEVEL"] = logLevel
        proc.environment = env
        // PVOS D222c — the companion's log (its records, the audit events it
        // logs since D222b) goes to ~/Library/Logs/PVFS/companion.log, which
        // Console.app shows, instead of nowhere.
        let log = Self.companionLogHandle()
        proc.standardOutput = log ?? FileHandle.nullDevice
        proc.standardError = log ?? FileHandle.nullDevice
        try proc.run()
        agentProcess = proc
        needsVaultPassword = false
        restartNeeded = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            self?.refresh()
        }
    }

    /// PVOS D222c — `~/Library/Logs/PVFS/companion.log`, opened for append
    /// (the daemon is a child; its stderr is this file). Over 10 MB at a
    /// start it becomes `.1`, the old `.1` becomes `.2`, and a fresh file
    /// begins. `nil` if the file cannot be opened (logging is never a reason
    /// not to start).
    static func companionLogHandle() -> FileHandle? {
        let fm = FileManager.default
        let dir = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/PVFS", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("companion.log")
        if let size = (try? fm.attributesOfItem(atPath: file.path))?[.size] as? NSNumber,
           size.int64Value > 10 * 1024 * 1024 {
            let one = dir.appendingPathComponent("companion.log.1")
            let two = dir.appendingPathComponent("companion.log.2")
            try? fm.removeItem(at: two)
            try? fm.moveItem(at: one, to: two)
            try? fm.moveItem(at: file, to: one)
        }
        if !fm.fileExists(atPath: file.path) {
            fm.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        guard let handle = try? FileHandle(forWritingTo: file) else { return nil }
        handle.seekToEndOfFile()
        return handle
    }

    func stopAgent() {
        agentProcess?.terminate()
        agentProcess = nil
        agentRunning = false
        statusLine = "Stopped"
    }

    /// Restart affordance (roadmap 2026-07-21): spawn a fresh `serve`. The
    /// binary's singleton takeover kills whichever instance holds the socket —
    /// including one this app didn't start (a stray CLI `serve`).
    func restartAgent() throws {
        agentProcess?.terminate()
        agentProcess = nil
        agentRunning = false
        try startAgent()
    }

    func lockAgent() {
        _ = runCompanion(args: ["lock"], env: [:])
        refresh()
    }

    // MARK: - Origins & audit

    func refreshOrigins() {
        guard let text = runCompanion(
            args: ["origins", "--vault", vaultPath.path],
            env: [:]
        ) else {
            origins = []
            return
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed.contains("(no connected origins)") {
            origins = []
            return
        }
        origins = trimmed.split(separator: "\n").compactMap { line in
            let parts = line.split(whereSeparator: { $0.isWhitespace })
            guard let first = parts.first else { return nil }
            let origin = String(first)
            if origin.hasPrefix("(") { return nil }
            let expiry = parts.dropFirst().joined(separator: " ")
            return OriginGrant(origin: origin, expiry: expiry.isEmpty ? "—" : expiry)
        }
    }

    /// PVOS D189 — every phrase, its keys and what uses them
    /// (`pvfs-companion keys --json`). Read on demand, not on the 2 s poll.
    func refreshKeys() {
        let r = runCompanionCapturing(args: ["keys", "--json"], env: [:], stdin: nil)
        guard r.exitCode == 0 else {
            keysError = r.stderr.isEmpty ? "keys: exit \(r.exitCode)" : r.stderr
            return
        }
        do {
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            keysReport = try decoder.decode(KeysReport.self, from: Data(r.stdout.utf8))
            keysError = nil
        } catch {
            keysError = "Could not read the phrase list: \(error.localizedDescription)"
        }
    }

    func revokeOrigin(_ origin: String) {
        _ = runCompanion(
            args: ["origins", "--vault", vaultPath.path, "revoke", origin],
            env: [:]
        )
        refreshOrigins()
    }

    func refreshAudit(limit: Int = 80) {
        guard FileManager.default.fileExists(atPath: auditPath.path),
              let data = try? String(contentsOf: auditPath, encoding: .utf8)
        else {
            auditEntries = []
            return
        }
        let lines = data.split(separator: "\n", omittingEmptySubsequences: true).suffix(limit)
        auditEntries = lines.reversed().map { line in
            let s = String(line)
            return AuditEntry(line: s, summary: Self.summarizeAudit(s))
        }
    }

    private static func summarizeAudit(_ json: String) -> String {
        // Lightweight: pull common fields without full JSON dependency
        func field(_ key: String) -> String? {
            guard let r = json.range(of: "\"\(key)\":\"") else {
                // try non-string
                if let r = json.range(of: "\"\(key)\":") {
                    let rest = json[r.upperBound...]
                    let end = rest.firstIndex(where: { $0 == "," || $0 == "}" }) ?? rest.endIndex
                    return String(rest[..<end]).trimmingCharacters(in: .whitespaces)
                }
                return nil
            }
            let rest = json[r.upperBound...]
            if let end = rest.firstIndex(of: "\"") {
                return String(rest[..<end])
            }
            return nil
        }
        let event = field("event") ?? "?"
        if event == "sign" {
            let decision = field("decision") ?? "?"
            let rt = field("request_type") ?? ""
            let origin = field("origin") ?? "local"
            return "sign \(rt) → \(decision) (\(origin))"
        }
        if event == "lock" || event == "unlock" || event == "serve_start" {
            return event
        }
        return event
    }

    // MARK: - Login item

    func setOpenAtLogin(_ enabled: Bool) {
        if let err = LoginItem.setEnabled(enabled) {
            loginItemNote = err
            // Still refresh status (may be requiresApproval)
            openAtLogin = LoginItem.isEnabled
        } else {
            loginItemNote = nil
            openAtLogin = LoginItem.isEnabled
            if LoginItem.mainStatusRequiresApproval {
                loginItemNote = LoginItem.statusDescription
            }
        }
    }

    // MARK: - Internals

    private func prepareVaultDir() {
        let dir = vaultPath.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    private func parseStatus(_ text: String) {
        if text.contains("keychain-sealed") {
            sealing = .keychain
        } else if text.contains("passphrase-sealed") {
            sealing = .passphrase
        } else if vaultExists {
            sealing = .unknown
        } else {
            sealing = .none
        }
        agentRunning = text.contains("agent : running")
        if let range = text.range(of: "identity ") {
            let rest = text[range.upperBound...]
            let hex = rest.prefix(while: { $0.isHexDigit })
            identityFull = String(hex)
            identityPreview = hex.isEmpty ? "" : String(hex.prefix(16)) + "…"
        } else {
            identityFull = ""
            identityPreview = ""
        }
        if let range = text.range(of: "http://") {
            let rest = text[range.lowerBound...]
            webAgentURL = String(rest.prefix(while: { !$0.isWhitespace && $0 != "\n" }))
        } else {
            webAgentURL = ""
        }
        if let range = text.range(of: "running on ") {
            let rest = text[range.upperBound...]
            let path = rest.prefix(while: { $0 != " " && $0 != "\n" && $0 != "(" })
            socketPath = String(path)
        } else if let range = text.range(of: "would serve on ") {
            let rest = text[range.upperBound...]
            socketPath = String(rest.prefix(while: { $0 != "\n" }))
        }
        if agentRunning {
            statusLine = "Agent running"
        } else if vaultExists {
            statusLine = "Vault ready — agent not running"
        }
        lastError = nil
    }

    private func runCompanion(args: [String], env: [String: String]) -> String? {
        let r = runCompanionCapturing(args: args, env: env, stdin: nil)
        if r.exitCode != 0 {
            lastError = r.stderr.isEmpty ? r.stdout : r.stderr
            return r.stdout.isEmpty ? nil : r.stdout
        }
        return r.stdout
    }

    struct CmdResult {
        var exitCode: Int32
        var stdout: String
        var stderr: String
    }

    func runCompanionCapturing(
        args: [String],
        env: [String: String],
        stdin: String?
    ) -> CmdResult {
        let proc = Process()
        proc.executableURL = companionBinary
        proc.arguments = args
        var fullEnv = ProcessInfo.processInfo.environment
        for (k, v) in env {
            fullEnv[k] = v
        }
        proc.environment = fullEnv

        let out = Pipe()
        let err = Pipe()
        proc.standardOutput = out
        proc.standardError = err
        if let stdin {
            let inp = Pipe()
            proc.standardInput = inp
            if let data = stdin.data(using: .utf8) {
                inp.fileHandleForWriting.write(data)
            }
            try? inp.fileHandleForWriting.close()
        } else {
            proc.standardInput = FileHandle.nullDevice
        }

        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            lastError = error.localizedDescription
            return CmdResult(exitCode: 127, stdout: "", stderr: error.localizedDescription)
        }
        let stdout = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return CmdResult(exitCode: proc.terminationStatus, stdout: stdout, stderr: stderr)
    }
}

enum AgentError: LocalizedError {
    case message(String)
    case needsPassword

    var errorDescription: String? {
        switch self {
        case .message(let s): return s
        case .needsPassword: return "Vault password required"
        }
    }
}
