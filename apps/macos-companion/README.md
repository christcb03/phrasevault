# PVFS Companion (macOS menu-bar app)

Native menu-bar app for the **Rust** `pvfs-companion` agent (not the old Node agent).

## Features

| Feature | Notes |
|---------|--------|
| **Setup wizard** | Create or import a 24-word recovery phrase |
| **Keychain first** | Seals with macOS Keychain; vault password only if Keychain fails |
| **Menu bar** | Custom shield icon; start/stop/lock; open at login toggle |
| **Console window** | Status, connected **origins** (revoke), **audit** log, settings |
| **Phrases & keys** | Settings → Phrases & keys (PVOS D189): every recovery phrase the companion holds, its public keys, and what each is used for — forests, paired servers, sign-ins and approvals, root signatures. What `pvfs-companion keys --json` reports; public keys only |
| **Several phrases** | Every other keychain-sealed `*.vault` beside `companion.vault` in `~/.config/pvfs/` is served by the same agent (the app passes each as a `--vault`); a request picks its phrase by the key it names. Password-sealed extra vaults are left out |
| **Approvals** | High-authority prompts via macOS system dialogs (`--prompt desktop`) |
| **Open at login** | `SMAppService` (may need System Settings approval) |
| **SSH with companion** | Menu item reverse-forwards the local agent socket into an SSH session (desktop SSO) |
| **DMG packaging** | `package-dmg.sh` (+ optional Developer ID / notarize) |

## Build & run

Needs, on the Mac that builds it:

- **Apple Silicon** — `build.sh` compiles the Swift side for `arm64` only;
- **macOS 13 or later** (the app's minimum);
- **Rust** (`cargo`, via [rustup](https://rustup.rs)) for the embedded `pvfs-companion`;
- **Xcode, or the Command Line Tools** (`swiftc`, `xcrun`). With only the
  Command Line Tools, the newest SDK's SwiftUI may not compile (its macro
  plugins ship with Xcode): `build.sh` then tries the next older installed
  SDK by itself. `PVFS_MACOS_SDK=<path to an SDK>` names one outright and
  turns that fallback off.

Run from the repo root:

```bash
./apps/macos-companion/build.sh
open "dist/PVFS Companion.app"
```

Optional: copy to `/Applications` (recommended for login items).

### Updating an installed copy

`updateCompanion.sh`, at the repo root, rebuilds the app, replaces
`/Applications/PVFS Companion.app` with it and opens it. Run it from the repo
root:

```bash
./updateCompanion.sh
```

Two things to know (2026-10-04):

- **The old agent keeps running.** The script quits the app with `killall`,
  which does not stop the `pvfs-companion serve` the old app started, and the
  new app starts an agent only when none is running. So the old build goes on
  serving until you choose **Restart agent** in the menu.
- **A failed build still replaces the app.** The script does not stop on an
  error: when `build.sh` fails it goes on to delete the installed app and
  copy whatever is in `dist/`. If the build printed an error, build again
  before trusting what is in `/Applications`.

## DMG

```bash
./apps/macos-companion/build.sh
./apps/macos-companion/package-dmg.sh
# → dist/PVFS-Companion-<version>.dmg
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

The embedded agent is a **singleton per user**: starting it (menu-bar **Start
agent**, **Restart agent**, or a CLI `pvfs-companion serve`/`restart`) takes
over from whichever instance currently holds the socket — no more two copies
fighting over `/tmp/pvfs-companion-<user>.sock`.

## Layout

```
apps/macos-companion/
  Sources/          SwiftUI app
  Resources/        Menu bar PNG + AppIcon.icns
  build.sh          → dist/PVFS Companion.app
  package-dmg.sh    → dist/PVFS-Companion-*.dmg
  Info.plist
```
