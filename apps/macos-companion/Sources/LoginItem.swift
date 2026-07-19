import Foundation
import ServiceManagement

/// Open-at-login via `SMAppService` (macOS 13+).
enum LoginItem {
    static var isEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    static var mainStatusRequiresApproval: Bool {
        SMAppService.mainApp.status == .requiresApproval
    }

    /// Register or unregister as a login item. Returns an error string on failure.
    @discardableResult
    static func setEnabled(_ enabled: Bool) -> String? {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    static var statusDescription: String {
        switch SMAppService.mainApp.status {
        case .enabled: return "Enabled"
        case .notRegistered: return "Off"
        case .notFound: return "Not found — run from the built .app (not a raw binary)"
        case .requiresApproval: return "Needs approval in System Settings → Login Items"
        @unknown default: return "Unknown"
        }
    }
}
