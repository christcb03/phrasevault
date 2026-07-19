import AppKit
import SwiftUI

/// First-run wizard: create or enter a 24-word recovery phrase, then seal
/// (Keychain preferred; vault password only if Keychain sealing is unavailable).
struct SetupView: View {
    @ObservedObject var agent: AgentController
    @Environment(\.dismiss) private var dismiss

    enum Mode {
        case choose
        case createShow
        case createConfirm
        case importPhrase
        case vaultPassword
    }

    @State private var mode: Mode = .choose
    @State private var generatedPhrase = ""
    @State private var importText = ""
    @State private var confirmChecked = false
    @State private var vaultPassword = ""
    @State private var vaultPassword2 = ""
    @State private var pendingPhrase = ""
    @State private var error: String?
    @State private var busy = false
    @State private var keychainFailReason = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("PVFS Companion Setup")
                .font(.title2.bold())
            Text("This seals your recovery phrase into a local vault. The phrase is shown once if you create a new one — write it down.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            switch mode {
            case .choose:
                chooseBody
            case .createShow:
                createShowBody
            case .createConfirm:
                createConfirmBody
            case .importPhrase:
                importBody
            case .vaultPassword:
                vaultPasswordBody
            }

            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.callout)
            }
        }
        .padding(24)
        .frame(minWidth: 480, minHeight: 360)
    }

    private var chooseBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button("Create a new recovery phrase") {
                error = nil
                busy = true
                do {
                    generatedPhrase = try agent.generatePhrase()
                    mode = .createShow
                } catch {
                    self.error = error.localizedDescription
                }
                busy = false
            }
            .buttonStyle(.borderedProminent)
            .disabled(busy)

            Button("I already have a recovery phrase") {
                error = nil
                mode = .importPhrase
            }
            .buttonStyle(.bordered)
        }
    }

    private var createShowBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Write these 24 words down offline. They are not stored until you continue.")
                .font(.callout)
            Text(generatedPhrase)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .padding(12)
                .background(Color(nsColor: .textBackgroundColor))
                .cornerRadius(8)
            Toggle("I have written down my recovery phrase", isOn: $confirmChecked)
            HStack {
                Button("Back") { mode = .choose; confirmChecked = false }
                Spacer()
                Button("Continue") {
                    pendingPhrase = generatedPhrase
                    seal(phrase: generatedPhrase)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!confirmChecked || busy)
            }
        }
    }

    private var createConfirmBody: some View {
        EmptyView()
    }

    private var importBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste your 24-word recovery phrase")
            TextEditor(text: $importText)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 100)
                .border(Color.gray.opacity(0.3))
            HStack {
                Button("Back") { mode = .choose }
                Spacer()
                Button("Continue") {
                    let p = importText
                        .lowercased()
                        .split(whereSeparator: { $0.isWhitespace || $0.isNewline })
                        .joined(separator: " ")
                    guard p.split(separator: " ").count == 24 else {
                        error = "Expected exactly 24 words"
                        return
                    }
                    pendingPhrase = p
                    seal(phrase: p)
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy)
            }
        }
    }

    private var vaultPasswordBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Keychain sealing was not available")
                .font(.headline)
            Text(keychainFailReason)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Choose a vault password (not your recovery phrase). You will enter this when the companion starts if Keychain is not used.")
                .fixedSize(horizontal: false, vertical: true)
            SecureField("Vault password", text: $vaultPassword)
            SecureField("Confirm vault password", text: $vaultPassword2)
            HStack {
                Button("Back") { mode = .choose }
                Spacer()
                Button("Create vault") {
                    error = nil
                    guard vaultPassword == vaultPassword2, !vaultPassword.isEmpty else {
                        error = "Passwords must match and not be empty"
                        return
                    }
                    busy = true
                    do {
                        try agent.sealWithVaultPassword(phrase: pendingPhrase, vaultPassword: vaultPassword)
                        try agent.startAgent(vaultPassword: vaultPassword)
                        dismiss()
                    } catch {
                        self.error = error.localizedDescription
                    }
                    busy = false
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy)
            }
        }
    }

    private func seal(phrase: String) {
        error = nil
        busy = true
        do {
            switch try agent.trySealWithKeychain(phrase: phrase) {
            case .keychain:
                try agent.startAgent()
                dismiss()
            case .needsPassphrase(let reason):
                keychainFailReason = reason
                mode = .vaultPassword
            }
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }
}
