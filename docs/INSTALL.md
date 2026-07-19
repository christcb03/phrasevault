# Installing and testing PVFS

This guide is for someone comfortable with a terminal, SSH, and copying commands — you do not need to be a Rust developer.

**PVFS** is a command-line program (`pvfs`) plus an optional per-user daemon (`pvfsd`), a companion signing agent (`pvfs-companion`), and a data directory (SQLite log + index). Version **`1.1.0`** (tagged `v1.1`) is the current release. It includes:

- **P0–P1.5** — core engine (forest, signed nodes/links, event log), storage ops (bind/scan/verified reads/watcher), mounts & host registry
- **P2** — multi-user access: per-node ACLs, per-key tags, member-signed writes and live admin over `pvfsd`, concurrent raw-bytes `cat`, `pvfs audit`, graceful daemon shutdown
- **P3** — secure (encrypted-at-rest) nodes with companion-gated decryption
- **Companion** — local key vault + signer + “Sign in with PVFS” agent (doc 14 / 16)
- **1.1** — PVOS-facing daemon ops (`AddNode` / `Payload` via `pvfs-client`, `stat` parent) and security/error-code fixes (see [CHANGELOG.md](../CHANGELOG.md))

Replace placeholders such as `<repository-url>`, `<user>`, and `<host>` with your values.

---

## What you need

| Platform | Requirements |
|----------|----------------|
| **Linux or macOS** (local dev) | Git, a C compiler (`build-essential` / Xcode CLI tools), `curl`, `pkg-config`, **Rust** (via [rustup](https://rustup.rs)) |
| **Remote Linux server** (optional) | SSH access, same build deps (or use the [Ansible pipeline](../deploy/ansible/README.md)) |

There is no Docker image for the new PVFS — you build one native binary from source.

---

## Option A — Build on your own machine

### 1. Clone the repo

```bash
git clone <repository-url>
cd phrasevault
```

### 2. Install Rust (one time)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 3. Build and run tests

```bash
cargo build --release --workspace
cargo test --workspace
```

Binaries land under `target/release/`:

| Binary | Role |
|--------|------|
| `pvfs` | CLI |
| `pvfsd` | Per-forest daemon |
| `pvfs-companion` | Local key vault / signing agent |

### 4. Create a forest and try a few commands

```bash
export PVFS_DATA_DIR="$HOME/pvfs-test-forest"

# First run: generates a 24-word recovery phrase — write it down
pvfs init

# Add a folder and file under the root tree
ROOT=$(pvfs info | sed -n 's/root_node_id: //p')
DIR=$(pvfs add "$ROOT" --kind folder --label docs)
FILE=$(pvfs add "$DIR" --kind file --label readme.txt --size 0)

# Point the file node at a real path (storage URI)
pvfs loc add "$FILE" "file:///etc/hostname"

pvfs ls "$ROOT"
pvfs walk "$ROOT"
pvfs verify "$FILE"
```

To open an existing forest on this machine later:

```bash
export PVFS_DATA_DIR="$HOME/pvfs-test-forest"
pvfs info    # uses the device key stored in the data dir
```

If you lose the data dir but kept the mnemonic:

```bash
export PVFS_DATA_DIR="$HOME/pvfs-test-forest"
pvfs recover   # prompts for the 24 words
```

Run the automated CLI smoke suite locally:

```bash
PVFS_BIN=target/release/pvfs bash deploy/ansible/files/smoke-test.sh
```

---

## Option B — Remote Linux server (manual build + manual tests)

Use any Linux host where you have SSH and can install Rust (Ubuntu/Debian examples below).

| Item | Example |
|------|---------|
| SSH | `<user>@<host>` |
| Forest data | `$HOME/pvfs-data/my-forest` or `/var/lib/pvfs/my-forest` |

### 1. SSH in

```bash
ssh <user>@<host>
```

### 2. Clone and build (on the server)

Install build dependencies once (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y build-essential pkg-config curl git
```

Install Rust if needed — see [rustup.rs](https://rustup.rs) — then:

```bash
git clone <repository-url>
cd phrasevault
git pull   # if the directory already exists

source "$HOME/.cargo/env"
cargo build --release --workspace
```

Binary: `target/release/pvfs`. Either call it by path or install system-wide:

```bash
sudo install -m 755 target/release/pvfs /usr/local/bin/pvfs
pvfs --help
```

Optional — run the smoke script before manual tests:

```bash
PVFS_BIN=target/release/pvfs bash deploy/ansible/files/smoke-test.sh
```

### 3. Manual tests

```bash
export PVFS_DATA_DIR="$HOME/pvfs-data/my-forest"
pvfs init
ROOT=$(pvfs info | awk '/root_node_id/ { print $2 }')

mkdir -p ~/test-data && echo hello > ~/test-data/sample.txt

pvfs bind "$ROOT" ~/test-data --recursive
pvfs scan "$ROOT" ~/test-data

pvfs ls "$ROOT"
pvfs walk "$ROOT"

# use a node id from ls/walk output
pvfs stat <node-id>
pvfs cat <node-id>

# optional background watcher
pvfs serve --bind "$ROOT" ~/test-data
```

Use `pvfs --help` and `pvfs <command> --help` for all subcommands.

### Alternative — Ansible pipeline from your laptop

If you prefer rsync + build + test + install in one shot from your machine, copy [`deploy/ansible/inventory.example.ini`](../deploy/ansible/inventory.example.ini) to `inventory.ini`, set your host and user, then:

```bash
cd deploy/ansible
ansible-galaxy collection install ansible.posix
ansible-playbook -i inventory.ini pipeline.yml
```

Details: [deploy/ansible/README.md](../deploy/ansible/README.md).

---

## Option C — Run `pvfsd` as a systemd user service

To share a forest with other users on a host, run the daemon (`pvfsd`) under
systemd. The template unit and a tmpfiles snippet live in
[`deploy/ansible/files/`](../deploy/ansible/files/).

### 1. Install the binaries and the socket directory

```bash
install -m 755 target/release/pvfs  ~/.local/bin/pvfs
install -m 755 target/release/pvfsd ~/.local/bin/pvfsd

# Socket directory, created once by root (world-traversable + sticky, like /tmp).
sudo install -m 644 deploy/ansible/files/pvfs-tmpfiles.conf /etc/tmpfiles.d/pvfs.conf
sudo systemd-tmpfiles --create        # creates /run/pvfs (mode 1777)
```

Sockets are deliberately placed in a **shared, world-traversable** directory so
other users can reach a served forest — access is gated by per-node **ACLs**, not
by socket permissions (doc 06 §2). The unit sets `PVFS_SOCKET_DIR=/run/pvfs`;
**clients must export the same value** to discover a running daemon (see below).

### 2. Enable a per-forest instance

The unit is templated on the mount directory name under `~/pvfs-mounts/`:

```bash
mkdir -p ~/pvfs-mounts
ln -s /path/to/my-forest ~/pvfs-mounts/myforest    # or put the mount here directly

install -m 644 deploy/ansible/files/pvfsd@.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now pvfsd@myforest

systemctl --user status pvfsd@myforest
```

`pvfsd` traps `SIGTERM`/`SIGINT`, checkpoints its write-ahead log, and removes its
socket on exit, so `systemctl --user stop pvfsd@myforest` is a clean shutdown.

### 3. Reach the daemon as a client

```bash
export PVFS_SOCKET_DIR=/run/pvfs       # add to ~/.profile so it's always set
pvfs remote --forest /path/to/my-forest info
# or, with the forest registered:  pvfs remote --forest myforest ls <node>
```

For a quick test without systemd, run `PVFS_SOCKET_DIR=/run/pvfs pvfsd --mount
/path/to/my-forest` in one terminal and the client (same env) in another. By
default — with `PVFS_SOCKET_DIR` unset — both the daemon and clients fall back to
`/tmp/pvfs`, which also works for cross-user sharing without any root setup.

---

## Option D — The companion: sign without ever typing your phrase again

The companion (`pvfs-companion`) keeps your recovery phrase sealed on disk and
signs high-authority operations for you — admitting or revoking devices and
members, and your cross-machine identity (doc 14). Set it up once; no flags
needed for normal use.

### macOS menu-bar app (optional)

On a Mac you can use a native menu-bar app instead of the CLI:

```bash
./apps/macos-companion/build.sh
open "dist/PVFS Companion.app"
# optional installer image:
./apps/macos-companion/package-dmg.sh   # → dist/PVFS-Companion-1.1.0.dmg
```

Setup (create/import recovery phrase), Keychain sealing, menu-bar agent, console (origins/audit), open-at-login. See [apps/macos-companion/README.md](../apps/macos-companion/README.md).

### 1. Seal your phrase (one time, CLI)

```bash
pvfs-companion init
```

It prompts for your recovery phrase (the words shown once at `forest init`) and
checks them — a typo is caught here, not later. Then it picks the safest place
for the vault key available on your machine:

- **Desktop (macOS/Linux/Windows):** the key goes into the **OS keychain** — no
  passphrase to remember; your login session unlocks it.
- **Headless server / no keychain:** it says so and asks you to **choose a vault
  passphrase** instead (typed twice, never shown).

The vault lands at `~/.config/pvfs/companion.vault`. Your phrase is still the
real recovery — the vault is a convenience layer, not a new thing to back up.

### 2. Run the agent

```bash
pvfs-companion serve
```

You'll see `serving on …/pvfs-companion.sock`. Keychain vaults unlock silently;
passphrase vaults prompt once. Leave it running (a user systemd unit works the
same way as `pvfsd@` — see Option C).

### 3. Use it (no phrase, no flags)

```bash
# New forest on this machine: if companion is running, confirm to reuse its
# seed (no new phrase). Or force either path:
#   pvfs forest init --via-companion
#   pvfs forest init --new-phrase
pvfs forest init --mount ~/media

pvfs device authorize-identity      # your one identity across machines
pvfs device authorize-member --via-companion --pubkey <hex>
pvfs device revoke --via-companion --pubkey <hex>
pvfs tag add <member> <tag> --via-companion
```

The `pvfs` CLI finds the running companion automatically.

### 3b. Desktop companion as SSO for remote hosts

The companion only listens on a **local** Unix socket. To use **this machine’s**
companion when operating on a server (e.g. presubuntu), reverse-forward the
socket over SSH from the desktop:

```bash
# companion running on the desktop, then:
pvfs ssh chris@presubuntu
# → remote shell with PVFS_COMPANION_SOCKET pointed at your desktop agent

pvfs ssh chris@presubuntu -- pvfs forest init --mount ~/media --via-companion
# → forest on the server, root-signed by the desktop companion (approve on desktop)
```

Plain `ssh` into the server without this forward still only sees a companion
**on the server**, not your desktop.

### 4. Check on it

```bash
pvfs-companion status
```

Shows where the vault is and how it's sealed, whether the agent is running, and
warns if a keychain-sealed vault's key has gone missing.

### 5. Approvals, locking, and the audit trail

When something high-authority is requested (admitting or revoking a device),
the companion **asks you first** — a dialog on desktops, a yes/no question in
the `serve` terminal otherwise. Headless servers say no unless `serve` was
started with `--allow-root` (an explicit automation opt-in).

```bash
pvfs-companion lock
```

drops your seed from the agent's memory right now; it also happens on its own
after 15 idle minutes. The next operation re-unlocks it — silently from the OS
keychain, or by prompting for the passphrase. Every signature and lock is
recorded in `companion.audit.jsonl` next to the vault, so you can always see
what was signed, when, and from where.

### 6. "Sign in with PVFS" (web apps)

While `serve` runs, PVFS-backed web apps can sign you in with no password: the
first time an app asks, the companion shows a connect prompt naming the site —
approve it once and sign-ins are automatic for 30 days. Only sign-in signatures
are ever available to websites; nothing a site does can admit or revoke devices.

```bash
pvfs-companion origins                     # who's connected, and until when
pvfs-companion origins revoke <origin>     # disconnect one immediately
```

### If something goes wrong

| Problem | What it looks like | Recovery |
|---------|--------------------|----------|
| Typo'd phrase at `init` | `that is not a valid recovery phrase` | Re-run `init`; nothing was written. |
| Forgot the vault passphrase | `unlock failed: wrong passphrase or corrupt vault` | Delete the vault file, re-run `init` with your written-down phrase. |
| Keychain entry deleted / OS reinstalled | `status` warns the key is not retrievable | Delete the vault file, re-run `init` with your phrase. |
| `no companion running at …` | Any `--via-companion` command | Start it: `pvfs-companion serve`. |
| Machine died entirely | — | On the new machine: `pvfs recover --mnemonic "<phrase>"`, then `pvfs-companion init` with the same phrase. Your identity key derives identically, so memberships and tags carry over. |
| Identity key compromised | a machine that held the unlocked companion was breached | `pvfs identity replace` — one command: new key, old grants re-issued, prints a handoff for other forests (their owners run `pvfs member replace <file>`). |

---

## Environment variables

| Variable | Meaning |
|----------|---------|
| `PVFS_DATA_DIR` | Path to the forest data directory (`log.db`, `index.db`, device key). **Required** for the low-level `init`/`recover` flow; interactive use prefers `--forest` or running inside a mount. |
| `PVFS_SOCKET_DIR` | Directory holding daemon sockets (`<forest_id>.sock`). The daemon binds here and clients look here; both default to `/tmp/pvfs`. Set the **same** value on both sides (e.g. `/run/pvfs`). |
| `PVFS_REGISTRY_DIR` | Override the host forest registry (default `/etc/pvfs`, which needs `sudo` to write). A user-writable path gives a rootless registry. |
| `PVFS_COMPANION_VAULT` | Companion vault file (default `~/.config/pvfs/companion.vault`). For scripts; interactive use never needs it. |
| `PVFS_COMPANION_SOCKET` | Companion signer socket (default `$XDG_RUNTIME_DIR/pvfs-companion.sock`). Both `pvfs-companion serve` and the `pvfs` CLI honor it. |
| `PVFS_COMPANION_PASSPHRASE` | Vault passphrase for **non-interactive** use (pipelines, systemd). Interactive use prompts instead. |
| `PVFS_BIN` | Used only by `smoke-test.sh` — path to the `pvfs` binary to test. |

---

## Troubleshooting

| Problem | What to try |
|---------|-------------|
| `cargo: command not found` | Run `source "$HOME/.cargo/env"` or open a new terminal after rustup. |
| SSH connection fails | Check VPN/firewall, correct `<host>`, and that your key is authorized for `<user>`. |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | The server was reinstalled or keys rotated. `ssh-keygen -R <host>` then reconnect. |
| `pvfs init` says forest exists | Use a new `PVFS_DATA_DIR` or remove the old directory (destroys data). |
| Pipeline tests fail | Read `deploy/ansible/artifacts/<hostname>/` logs; fix locally with `cargo test` first. |

---

## Further reading

- **Status & roadmap:** [08-roadmap-and-status.md](08-roadmap-and-status.md)
- **User manual:** [USER-MANUAL.md](USER-MANUAL.md)
- **Changelog / versions:** [CHANGELOG.md](../CHANGELOG.md) · [VERSIONING.md](../VERSIONING.md)
- Design specs: [00](00-architecture-decisions.md) · [01](01-core-engine-design.md) · [02](02-p0-core-engine-spec.md) · [03](03-federation-trust-and-uris.md) · [04](04-p1-storage-and-fs-ops-spec.md)
- Version scheme: [VERSIONING.md](../VERSIONING.md)
- Ansible pipeline: [deploy/ansible/README.md](../deploy/ansible/README.md)
