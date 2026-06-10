#!/usr/bin/env bash
# MediaForest Companion — installer
# Installs the companion agent and sets it to start at login.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/christcb03/phrasevault/main/agent/install.sh | bash
#   - OR -
#   cd phrasevault-repo && bash agent/install.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
AGENT_SCRIPT="$REPO_DIR/agent/companion.mjs"
CONFIG_DIR="$HOME/.config/phrasevault"
PLIST_NAME="com.phrasevault.companion"
PLIST_DEST="$HOME/Library/LaunchAgents/$PLIST_NAME.plist"

# ── Detect OS ────────────────────────────────────────────────────────────────

OS="$(uname -s)"

# ── Check / install Node.js ───────────────────────────────────────────────────

install_node() {
  if [ "$OS" = "Darwin" ]; then
    if command -v brew &>/dev/null; then
      echo "  Installing Node.js via Homebrew…"
      brew install node
    else
      echo "  Homebrew not found. Install Node.js from https://nodejs.org/ (v18+) then re-run this script."
      exit 1
    fi
  elif [ "$OS" = "Linux" ]; then
    # Detect package manager
    if command -v apt-get &>/dev/null; then
      echo "  Installing Node.js 20 LTS via NodeSource…"
      curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
      sudo apt-get install -y nodejs
    elif command -v dnf &>/dev/null; then
      echo "  Installing Node.js via dnf…"
      sudo dnf install -y nodejs
    elif command -v yum &>/dev/null; then
      echo "  Installing Node.js via yum…"
      curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
      sudo yum install -y nodejs
    elif command -v pacman &>/dev/null; then
      echo "  Installing Node.js via pacman…"
      sudo pacman -Sy --noconfirm nodejs npm
    else
      echo "  Cannot detect package manager. Install Node.js from https://nodejs.org/ (v18+) then re-run."
      exit 1
    fi
  else
    echo "  Unsupported OS. Install Node.js from https://nodejs.org/ (v18+) then re-run."
    exit 1
  fi
}

if ! command -v node &>/dev/null; then
  echo "✗ Node.js not found."
  read -r -p "  Install it now? [Y/n] " yn
  yn="${yn:-Y}"
  if [[ "$yn" =~ ^[Yy] ]]; then
    install_node
  else
    echo "  Skipping. Re-run this script after installing Node.js v18+ from https://nodejs.org/"
    exit 1
  fi
fi

NODE_VERSION="$(node --version | sed 's/v//' | cut -d. -f1)"
if [ "$NODE_VERSION" -lt 18 ]; then
  echo "✗ Node.js v$NODE_VERSION is too old (need v18+)."
  read -r -p "  Upgrade it now? [Y/n] " yn
  yn="${yn:-Y}"
  if [[ "$yn" =~ ^[Yy] ]]; then
    install_node
  else
    echo "  Skipping. Re-run after upgrading Node.js to v18+ from https://nodejs.org/"
    exit 1
  fi
fi

echo "✓ Node.js $(node --version) found at $(which node)"

# ── Check companion script ────────────────────────────────────────────────────

if [ ! -f "$AGENT_SCRIPT" ]; then
  echo "✗ companion.mjs not found at $AGENT_SCRIPT"
  echo "  Run this script from inside the cloned phrasevault-repo directory."
  exit 1
fi

NODE_BIN="$(which node)"
echo "✓ Companion script: $AGENT_SCRIPT"

# ── Install npm dependencies ──────────────────────────────────────────────────

if [ ! -d "$REPO_DIR/node_modules/@noble" ]; then
  echo
  echo "Installing dependencies (npm install)…"
  npm install --prefix "$REPO_DIR" --omit=dev --silent
  echo "✓ Dependencies installed"
fi

# ── macOS: launchd ────────────────────────────────────────────────────────────

if [ "$OS" = "Darwin" ]; then
  echo
  echo "Setting up launchd autostart (macOS)..."

  mkdir -p "$HOME/Library/LaunchAgents"

  cat > "$PLIST_DEST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$PLIST_NAME</string>

  <key>ProgramArguments</key>
  <array>
    <string>$NODE_BIN</string>
    <string>$AGENT_SCRIPT</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>PV_AGENT_PORT</key>
    <string>8765</string>
  </dict>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/tmp/phrasevault-companion.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/phrasevault-companion.log</string>
</dict>
</plist>
EOF

  # Unload existing if present
  launchctl unload "$PLIST_DEST" 2>/dev/null || true
  echo "✓ LaunchAgent plist written to $PLIST_DEST"

# ── Linux: systemd user unit ──────────────────────────────────────────────────

elif [ "$OS" = "Linux" ]; then
  echo
  echo "Setting up systemd user service (Linux)..."

  SYSTEMD_DIR="$HOME/.config/systemd/user"
  SERVICE_FILE="$SYSTEMD_DIR/phrasevault-companion.service"
  mkdir -p "$SYSTEMD_DIR"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MediaForest Companion Agent
After=network.target

[Service]
Type=simple
ExecStart=$NODE_BIN $AGENT_SCRIPT
Restart=on-failure
RestartSec=5
Environment=PV_AGENT_PORT=8765

[Install]
WantedBy=default.target
EOF

  systemctl --user daemon-reload
  systemctl --user enable phrasevault-companion.service 2>/dev/null || true
  echo "✓ Systemd service written to $SERVICE_FILE"

else
  echo "⚠ Autostart not configured for $OS — you'll need to start the companion manually:"
  echo "  node $AGENT_SCRIPT"
fi

# ── Run setup wizard ──────────────────────────────────────────────────────────

echo
echo "─────────────────────────────────────────────────────"
echo " Running setup wizard…"
echo "─────────────────────────────────────────────────────"
echo

node "$AGENT_SCRIPT"

# ── Start via launchd/systemd after setup ────────────────────────────────────

echo
if [ "$OS" = "Darwin" ]; then
  launchctl load "$PLIST_DEST" 2>/dev/null && echo "✓ Companion loaded via launchd — will start at login automatically." || true
elif [ "$OS" = "Linux" ]; then
  systemctl --user start phrasevault-companion.service 2>/dev/null && echo "✓ Companion started via systemd — will start at login automatically." || true
fi

echo
echo "✓ Done! Open MediaForest in your browser — it will sign you in automatically."
