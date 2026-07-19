# PVFS Companion (macOS menu-bar app)

Native menu-bar app for the **Rust** `pvfs-companion` agent (not the old Node agent).

## Features

| Feature | Notes |
|---------|--------|
| **Setup wizard** | Create or import a 24-word recovery phrase |
| **Keychain first** | Seals with macOS Keychain; vault password only if Keychain fails |
| **Menu bar** | Custom shield icon; start/stop/lock; open at login toggle |
| **Console window** | Status, connected **origins** (revoke), **audit** log, settings |
| **Approvals** | High-authority prompts via macOS system dialogs (`--prompt desktop`) |
| **Open at login** | `SMAppService` (may need System Settings approval) |
| **SSH with companion** | Menu item reverse-forwards the local agent socket into an SSH session (desktop SSO) |
| **DMG packaging** | `package-dmg.sh` (+ optional Developer ID / notarize) |

## Build & run

```bash
./apps/macos-companion/build.sh
open "dist/PVFS Companion.app"
```

Optional: copy to `/Applications` (recommended for login items).

## DMG

```bash
./apps/macos-companion/build.sh
./apps/macos-companion/package-dmg.sh
# → dist/PVFS-Companion-1.1.0.dmg
```

### Sign & notarize (needs Apple Developer account)

```bash
export SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="you@example.com"
export TEAM_ID="YOURTEAMID"
export APP_PASSWORD="app-specific-password"   # appleid.apple.com → App-Specific Passwords

./apps/macos-companion/build.sh
# Re-sign is done inside package-dmg when SIGNING_IDENTITY is set:
./apps/macos-companion/package-dmg.sh
```

Without those env vars you still get a local DMG (ad-hoc / unsigned) for your own machines.

## First launch

**This is a menu-bar app** (`LSUIElement`): it does **not** appear in the Dock. After you open it, look in the **menu bar** (top-right) for a small shield icon.

1. On first run (no `~/.config/pvfs/companion.vault`), the **Setup** window opens automatically.
2. Later launches: only the menu-bar icon — click it → **Open Companion…** for status, origins, audit, and settings.
3. Re-opening the app from Finder (or double-clicking again) brings Setup or the console to the front.

If “nothing happens,” check the menu bar (and quit any duplicate `PVFS Companion` process in Activity Monitor).

## Layout

```
apps/macos-companion/
  Sources/          SwiftUI app
  Resources/        Menu bar PNG + AppIcon.icns
  build.sh          → dist/PVFS Companion.app
  package-dmg.sh    → dist/PVFS-Companion-*.dmg
  Info.plist
```
