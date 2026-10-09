#!/usr/bin/env bash
# Build the companion app and install it in /Applications.
set -euo pipefail
cd "$(dirname "$0")"
./apps/macos-companion/build.sh
killall "PVFS Companion" 2>/dev/null || true
# The app's agent (`pvfs-companion serve`) is a child that outlives the
# window app; left running, it is the OLD build serving on the socket.
pkill -f "PVFS Companion.app/Contents/MacOS/pvfs-companion serve" 2>/dev/null || true
sleep 1
rm -rf "/Applications/PVFS Companion.app"
cp -R "dist/PVFS Companion.app" /Applications/
# Right after the copy, LaunchServices may still be registering the new
# bundle and refuse the launch (error -600): try a few times.
for i in 1 2 3 4 5; do
  if open "/Applications/PVFS Companion.app" 2>/dev/null; then
    echo "PVFS Companion installed and started. macOS asks for the Keychain once per phrase after a rebuild: choose Always Allow."
    exit 0
  fi
  sleep "$i"
done
echo "Installed, but macOS would not start it yet: open \"/Applications/PVFS Companion.app\"" >&2
exit 1
