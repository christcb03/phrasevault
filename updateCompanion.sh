./apps/macos-companion/build.sh
killall "PVFS Companion" 2>/dev/null || true
rm -rf "/Applications/PVFS Companion.app"
cp -R "dist/PVFS Companion.app" /Applications/
open "/Applications/PVFS Companion.app"
