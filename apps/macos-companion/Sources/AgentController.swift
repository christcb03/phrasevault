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
        proc.arguments = [
            "serve",
            "--vault", vaultPath.path,
            "--prompt", "desktop",
        ]
        var env = ProcessInfo.processInfo.environment
        if let pass, !pass.isEmpty {
            env["PVFS_COMPANION_PASSPHRASE"] = pass
        }
        proc.environment = env
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        agentProcess = proc
        needsVaultPassword = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            self?.refresh()
        }
    }

    func stopAgent() {
        agentProcess?.terminate()
        agentProcess = nil
        agentRunning = false
        statusLine = "Stopped"
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

    private struct CmdResult {
        var exitCode: Int32
        var stdout: String
        var stderr: String
    }

    private func runCompanionCapturing(
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
