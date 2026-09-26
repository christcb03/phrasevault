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

MIN_VER="13.0"
SWIFT_FILES=(
  "$APP_SRC/Sources/LoginItem.swift"
  "$APP_SRC/Sources/AgentController.swift"
  "$APP_SRC/Sources/CompanionSSH.swift"
  "$APP_SRC/Sources/SetupView.swift"
  "$APP_SRC/Sources/ConsoleView.swift"
  "$APP_SRC/Sources/AppRoot.swift"
)

compile_swift() {
  swiftc -O \
    -sdk "$1" \
    -target "arm64-apple-macosx${MIN_VER}" \
    -parse-as-library \
    -framework ServiceManagement \
    -framework AppKit \
    -framework SwiftUI \
    "${SWIFT_FILES[@]}" \
    -o "$MACOS_DIR/PVFS Companion"
}

# The macOS 27 SDK's SwiftUI makes @State a macro whose plugin ships only with
# Xcode: with just the Command Line Tools it fails ("plugin for module
# 'SwiftUIMacros' not found"). Then build against the newest older SDK that
# is installed (the app still targets macOS $MIN_VER+). PVFS_MACOS_SDK names
# an SDK outright and turns the fallback off.
SDK="${PVFS_MACOS_SDK:-$(xcrun --show-sdk-path)}"
echo "==> Compiling Swift (MenuBarExtra, macOS $MIN_VER+) against $(basename "$SDK")"
SWIFT_ERR="$(mktemp)"
trap 'rm -f "$SWIFT_ERR"' EXIT
if ! compile_swift "$SDK" 2>"$SWIFT_ERR"; then
  if [ -n "${PVFS_MACOS_SDK:-}" ] || ! grep -q "SwiftUIMacros" "$SWIFT_ERR"; then
    cat "$SWIFT_ERR" >&2
    exit 1
  fi
  built=""
  for older in $(ls -d "$(dirname "$SDK")"/MacOSX[0-9]*.sdk 2>/dev/null | sort -V -r); do
    [ "$(cd "$older" && pwd -P)" = "$(cd "$SDK" && pwd -P)" ] && continue
    echo "    $(basename "$SDK")'s SwiftUI needs Xcode's macro plugins; trying $(basename "$older")"
    if compile_swift "$older" 2>"$SWIFT_ERR"; then
      built="$older"
      break
    fi
  done
  if [ -z "$built" ]; then
    cat "$SWIFT_ERR" >&2
    echo "No installed SDK compiles the app: install Xcode, or set PVFS_MACOS_SDK" >&2
    exit 1
  fi
fi

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
