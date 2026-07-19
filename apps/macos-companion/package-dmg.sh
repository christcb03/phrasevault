#!/usr/bin/env bash
# Create a distributable DMG from dist/PVFS Companion.app
# Optional signing/notarization: set SIGNING_IDENTITY, and for notarize:
#   APPLE_ID, TEAM_ID, APP_PASSWORD (app-specific password)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="${1:-$ROOT/dist/PVFS Companion.app}"
STAGE="$ROOT/dist/dmg-stage"
DMG="$ROOT/dist/PVFS-Companion-1.1.0.dmg"
VOL="PVFS Companion"

if [[ ! -d "$APP" ]]; then
  echo "App not found: $APP"
  echo "Run ./apps/macos-companion/build.sh first."
  exit 1
fi

echo "==> Staging"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"

# Optional: Developer ID sign before packaging
if [[ -n "${SIGNING_IDENTITY:-}" ]]; then
  echo "==> Codesign with: $SIGNING_IDENTITY"
  codesign --force --deep --options runtime --sign "$SIGNING_IDENTITY" \
    "$STAGE/PVFS Companion.app/Contents/MacOS/pvfs-companion"
  codesign --force --deep --options runtime --sign "$SIGNING_IDENTITY" \
    "$STAGE/PVFS Companion.app"
  codesign --verify --verbose "$STAGE/PVFS Companion.app"
fi

echo "==> Creating DMG"
rm -f "$DMG"
hdiutil create \
  -volname "$VOL" \
  -srcfolder "$STAGE" \
  -ov -format UDZO \
  "$DMG"

rm -rf "$STAGE"

if [[ -n "${SIGNING_IDENTITY:-}" ]]; then
  echo "==> Sign DMG"
  codesign --force --sign "$SIGNING_IDENTITY" "$DMG" || true
fi

if [[ -n "${APPLE_ID:-}" && -n "${TEAM_ID:-}" && -n "${APP_PASSWORD:-}" ]]; then
  echo "==> Notarize (this can take several minutes)"
  xcrun notarytool submit "$DMG" \
    --apple-id "$APPLE_ID" \
    --team-id "$TEAM_ID" \
    --password "$APP_PASSWORD" \
    --wait
  xcrun stapler staple "$DMG" || true
  echo "Notarized and stapled: $DMG"
else
  echo ""
  echo "DMG ready (unsigned/local): $DMG"
  echo "To sign + notarize, rebuild then:"
  echo "  SIGNING_IDENTITY='Developer ID Application: …' \\"
  echo "  APPLE_ID=… TEAM_ID=… APP_PASSWORD=… \\"
  echo "  ./apps/macos-companion/package-dmg.sh"
fi
