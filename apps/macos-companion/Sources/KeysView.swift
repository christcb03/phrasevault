import AppKit
import SwiftUI

/// PVOS D189 — what `pvfs-companion keys --json` reports: every recovery
/// phrase, its public keys, and what each key is used for.
struct KeysReport: Decodable {
    let agent: String
    let phrases: [PhraseReport]
}

struct PhraseReport: Decodable, Identifiable {
    var id: String { path }
    let vault: String
    let path: String
    let isDefault: Bool
    let served: Bool
    let sealing: String
    let locked: Bool?
    let keys: PublicKeys?
    let forests: [ForestUse]
    let pairings: [PairingRow]
    let origins: [OriginRow]
    let approvals: [ApprovalRow]
    let rootSignatures: [RootSignature]
}

struct PublicKeys: Decodable {
    let root: String
    let identity: String
    let encryption: String
}

struct ForestUse: Decodable, Identifiable {
    var id: String { forestId + key }
    let forestId: String
    let label: String
    let key: String
    let role: String
    let firstMs: UInt64
    let lastMs: UInt64
    let uses: UInt64
    let lastAction: String
}

struct PairingRow: Decodable, Identifiable {
    var id: String { name + serverPubkey }
    let name: String
    let serverPubkey: String
    let createdMs: UInt64
    let origins: [String]
}

struct OriginRow: Decodable, Identifiable {
    var id: String { origin }
    let origin: String
    let expiresMs: UInt64
}

struct ApprovalRow: Decodable, Identifiable {
    var id: String { kind + "|" + who + "|" + action }
    let kind: String
    let who: String
    let action: String
    let count: UInt64
    let lastMs: UInt64
}

struct RootSignature: Decodable, Identifiable {
    var id: String { "\(atMs)|\(summary)" }
    let summary: String
    let atMs: UInt64
}

/// Settings → Phrases & keys: for each phrase, each of its keys and exactly
/// what uses it — the forests (recorded as tools use the phrase, or linked),
/// the servers paired with it, the sign-ins and approvals it gave — and the
/// root signatures it has made (devices admitted or revoked, promotions).
struct KeysSections: View {
    @ObservedObject var agent: AgentController

    var body: some View {
        Group {
            Section {
                Text("Every recovery phrase this companion holds, its public keys, and what each key is used for. Forests are recorded when a tool (pvfs, promote.sh) uses a phrase for one; `pvfs-companion keys link` records an older one. Public keys only — no phrase ever leaves its vault.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text(agentLine).font(.caption)
                    Spacer()
                    Button("Refresh") { agent.refreshKeys() }
                }
                if let err = agent.keysError {
                    Text(err).font(.caption).foregroundStyle(.red)
                }
            } header: {
                Text("Phrases & keys")
            }
            if let report = agent.keysReport {
                ForEach(report.phrases) { p in
                    PhraseSection(phrase: p)
                }
            }
        }
    }

    private var agentLine: String {
        switch agent.keysReport?.agent {
        case "running": return "Companion running — keys shown for every phrase it serves."
        case "older": return "This companion predates the phrase list — restart it."
        case "not running": return "Companion not running — start it to see the keys."
        default: return "Not read yet."
        }
    }
}

private struct PhraseSection: View {
    let phrase: PhraseReport

    var body: some View {
        Section {
            LabeledContent("State", value: stateLine)
            LabeledContent("Vault") {
                Text(phrase.path).font(.caption2.monospaced()).textSelection(.enabled)
            }
            if let k = phrase.keys {
                KeyBlock(title: "Root key", hex: k.root,
                         note: "Signs a forest's device certificates, promotions and root rotations.",
                         forests: phrase.forests.filter { $0.role == "root" },
                         extra: AnyView(RootGrants(signatures: phrase.rootSignatures)))
                KeyBlock(title: "Identity key", hex: k.identity,
                         note: "Signs you in and approves app actions.",
                         forests: phrase.forests.filter { $0.role == "identity" },
                         extra: AnyView(IdentityUses(pairings: phrase.pairings, origins: phrase.origins, approvals: phrase.approvals)))
                KeyBlock(title: "Encryption key", hex: k.encryption,
                         note: "Opens the keys of secure nodes sealed to this phrase.",
                         forests: phrase.forests.filter { $0.role == "encryption" },
                         extra: AnyView(EmptyView()))
            } else {
                Text(phrase.served ? "Keys unavailable." : "Not served by the running companion — its keys show when it is.")
                    .font(.caption).foregroundStyle(.secondary)
                if !phrase.forests.isEmpty {
                    ForEach(phrase.forests) { f in ForestRow(use: f, showRole: true) }
                }
                IdentityUses(pairings: phrase.pairings, origins: phrase.origins, approvals: phrase.approvals)
                RootGrants(signatures: phrase.rootSignatures)
            }
        } header: {
            Text("Phrase “\(phrase.vault)”\(phrase.isDefault ? " (default)" : "")")
        }
    }

    private var stateLine: String {
        let sealing = phrase.sealing == "keychain" ? "macOS Keychain" : (phrase.sealing == "passphrase" ? "Vault password" : "Unreadable vault")
        let served: String
        if !phrase.served {
            served = "not served now"
        } else if phrase.locked == true {
            served = "served · locked (unlocks on use)"
        } else {
            served = "served · unlocked"
        }
        return "\(sealing) · \(served)"
    }
}

private struct KeyBlock: View {
    let title: String
    let hex: String
    let note: String
    let forests: [ForestUse]
    let extra: AnyView

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(.headline)
                Spacer()
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(hex, forType: .string)
                }
                .buttonStyle(.borderless)
            }
            Text(hex)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            Text(note).font(.caption).foregroundStyle(.secondary)
            if forests.isEmpty {
                Text("No forest recorded for this key.").font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(forests) { f in ForestRow(use: f, showRole: false) }
            }
            extra
        }
        .padding(.vertical, 4)
    }
}

private struct ForestRow: View {
    let use: ForestUse
    let showRole: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Forest: \(use.label.isEmpty ? "unnamed" : use.label)\(showRole ? " — \(use.role) key" : "")")
                .font(.callout.weight(.semibold))
            Text(use.forestId).font(.caption2.monospaced()).textSelection(.enabled)
            Text("\(use.uses) use\(use.uses == 1 ? "" : "s") · first \(when(use.firstMs)) · last \(when(use.lastMs))")
                .font(.caption).foregroundStyle(.secondary)
            if !use.lastAction.isEmpty {
                Text("Last: \(use.lastAction)").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.leading, 12)
    }
}

private struct IdentityUses: View {
    let pairings: [PairingRow]
    let origins: [OriginRow]
    let approvals: [ApprovalRow]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(pairings) { p in
                VStack(alignment: .leading, spacing: 1) {
                    Text("Paired server: \(p.name)").font(.callout.weight(.semibold))
                    Text("server key \(p.serverPubkey) · since \(when(p.createdMs))")
                        .font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
                .padding(.leading, 12)
            }
            ForEach(origins) { o in
                Text("Web sign-in: \(o.origin) · expires \(when(o.expiresMs))")
                    .font(.caption).padding(.leading, 12)
            }
            ForEach(approvals) { a in
                Text("\(a.kind.capitalized) × \(a.count) — \(a.who)\(a.action.isEmpty ? "" : " (\(a.action))") · last \(when(a.lastMs))")
                    .font(.caption).padding(.leading, 12)
            }
        }
    }
}

private struct RootGrants: View {
    let signatures: [RootSignature]

    var body: some View {
        if signatures.isEmpty {
            Text("No root signatures in this phrase's audit log.").font(.caption).foregroundStyle(.secondary)
        } else {
            VStack(alignment: .leading, spacing: 2) {
                Text("Root signatures (\(signatures.count))").font(.callout.weight(.semibold))
                ForEach(signatures.prefix(20)) { s in
                    Text("\(when(s.atMs)) — \(s.summary)").font(.caption).textSelection(.enabled)
                }
            }
            .padding(.leading, 12)
        }
    }
}

private let whenFormatter: DateFormatter = {
    let f = DateFormatter()
    f.dateStyle = .medium
    f.timeStyle = .short
    return f
}()

/// A local date and time for a millisecond timestamp.
private func when(_ ms: UInt64) -> String {
    ms == 0 ? "—" : whenFormatter.string(from: Date(timeIntervalSince1970: Double(ms) / 1000))
}
