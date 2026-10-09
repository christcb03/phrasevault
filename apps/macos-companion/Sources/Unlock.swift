import LocalAuthentication
import SwiftUI

/// PVOS D226 — Touch ID (or the Mac's password) before the window shows a
/// key's history or the audit log, or revokes a sign-in. One unlock lasts
/// until the window closes or the agent locks.
@MainActor
final class Unlocker: ObservableObject {
    @Published var unlocked = false
    @Published var lastError: String?

    /// Ask once; `then` runs when (or if already) unlocked.
    func unlock(_ reason: String, then: (() -> Void)? = nil) {
        if unlocked {
            then?()
            return
        }
        let ctx = LAContext()
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            lastError = err?.localizedDescription ?? "This Mac cannot ask for Touch ID or its password."
            return
        }
        ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, error in
            Task { @MainActor in
                if ok {
                    self.unlocked = true
                    self.lastError = nil
                    then?()
                } else if let error, (error as? LAError)?.code != .userCancel {
                    self.lastError = error.localizedDescription
                }
            }
        }
    }

    func lock() {
        unlocked = false
    }
}

/// What a locked view shows instead of its content.
struct LockedPlaceholder: View {
    let what: String
    @ObservedObject var unlocker: Unlocker

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
            Text(what).font(.headline)
            Button("Unlock with Touch ID…") { unlocker.unlock("show \(what.lowercased())") }
                .buttonStyle(.borderedProminent)
            if let e = unlocker.lastError {
                Text(e).font(.caption).foregroundStyle(.red)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
