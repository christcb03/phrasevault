# MediaForest Companion — Install Guide

The companion is a small background app that holds your identity key and signs logins automatically. Once it's running, opening MediaForest in any browser on your machine logs you in instantly — no passphrase or password needed.

## Requirements

- Node.js v18 or newer — [nodejs.org](https://nodejs.org/)
- macOS or Linux

## One-line install (recommended)

**If you have the repo cloned:**
```bash
bash ~/Projects/phrasevault-repo/agent/install.sh
```

**If you don't have the repo yet:**
```bash
git clone https://github.com/christcb03/phrasevault.git ~/phrasevault-repo
bash ~/phrasevault-repo/agent/install.sh
```

The install script:
1. Checks your Node.js version
2. Runs the setup wizard (passphrase + server URL + optional registration)
3. Sets up autostart at login (launchd on macOS, systemd on Linux)

---

## What the setup wizard asks

**Passphrase** — your identity. This is the key that signs your logins. It never leaves your machine. Pick something long and memorable. 8+ characters.

**Server URL** — the address of your MediaForest server, e.g. `https://mymediaforest.example.com` or `http://192.168.1.100:8080`.

The wizard will test the connection:

- **"Signed in successfully"** — you're already registered and the companion is linked.
- **"Server has no accounts yet"** or **"Not registered"** — the wizard asks if you want to register. Just say yes:
  - **Display name** (optional)
  - **Account password** — strongly recommended. This lets you log in from any device (phone, new computer) without the companion. Think of it as your backup login.
  - **Invite token** — only needed if the server is in "closed" mode. Ask the server owner for one.

---

## After install

The companion starts automatically at login. You can check its status:

```bash
node ~/phrasevault-repo/agent/companion.mjs --status
```

Stop it:
```bash
node ~/phrasevault-repo/agent/companion.mjs --stop
```

Re-run setup (add a server, change passphrase):
```bash
node ~/phrasevault-repo/agent/companion.mjs --setup
```

View logs:
```bash
tail -f /tmp/phrasevault-companion.log
```

---

## Logging in without the companion

If you're on a device where the companion isn't installed (phone, friend's computer, etc.):

1. Open your MediaForest server in the browser
2. The login page shows a **"Sign in with password"** option
3. Enter the account password you set during registration

This is secure — the server only stores a hash of your password and never uses it to decrypt anything.

---

## Troubleshooting

**"Port 8765 in use"** — the companion is already running. Check with `--status`.

**"Passphrase not registered"** after moving to a new machine — run `--setup` again on the new machine. Use the same passphrase. The wizard will detect you're not registered and offer to register.

**Wrong passphrase** — if you see a mismatch warning in the logs, run `--setup` and enter the correct passphrase. The companion derives your key fresh from the passphrase each time — there's nothing to "recover" on the companion side.

**Lost passphrase** — use "Sign in with password" on the MediaForest login page, then go to Settings to generate a new invite or recover your account.
