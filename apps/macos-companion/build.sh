#!/usr/bin/env bash
# Build PVFS Companion.app: release Rust companion + Swift menu-bar UI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$ROOT/dist/PVFS Companion.app}"
MACOS_DIR="$OUT/Contents/MacOS"
RES_DIR="$OUT/Contents/Resources"

echo "==> Building pvfs-companion (release, os-keychain)"
(cd "$ROOT" && cargo build --release -p pvfs-companion)

echo "==> Assembling app bundle at: $OUT"
rm -rf "$OUT"
mkdir -p "$MACOS_DIR" "$RES_DIR"
cp "$APP_SRC/Info.plist" "$OUT/Contents/Info.plist"
cp "$ROOT/target/release/pvfs-companion" "$MACOS_DIR/pvfs-companion"
chmod +x "$MACOS_DIR/pvfs-companion"

# Icons & resources
cp "$APP_SRC/Resources/MenuBarIcon.png" "$RES_DIR/"
cp "$APP_SRC/Resources/MenuBarIcon@2x.png" "$RES_DIR/" 2>/dev/null || true
cp "$APP_SRC/Resources/AppIcon.icns" "$RES_DIR/" 2>/dev/null || true

SDK="$(xcrun --show-sdk-path)"
MIN_VER="13.0"
SWIFT_FILES=(
  "$APP_SRC/Sources/LoginItem.swift"
  "$APP_SRC/Sources/AgentController.swift"
  "$APP_SRC/Sources/CompanionSSH.swift"
  "$APP_SRC/Sources/SetupView.swift"
  "$APP_SRC/Sources/ConsoleView.swift"
  "$APP_SRC/Sources/AppRoot.swift"
)

echo "==> Compiling Swift (MenuBarExtra, macOS $MIN_VER+)"
swiftc -O \
  -sdk "$SDK" \
  -target "arm64-apple-macosx${MIN_VER}" \
  -parse-as-library \
  -framework ServiceManagement \
  -framework AppKit \
  -framework SwiftUI \
  "${SWIFT_FILES[@]}" \
  -o "$MACOS_DIR/PVFS Companion"

chmod +x "$MACOS_DIR/PVFS Companion"

# PkgInfo
echo -n 'APPL????' > "$OUT/Contents/PkgInfo"

if command -v codesign >/dev/null; then
  echo "==> Ad-hoc codesign"
  codesign --force --deep --sign - "$OUT" 2>/dev/null || true
fi

echo ""
echo "Built: $OUT"
echo "Run:   open \"$OUT\""
echo "DMG:   ./apps/macos-companion/package-dmg.sh"
