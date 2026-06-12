# Installing and testing PVFS

This guide is for someone comfortable with a terminal, SSH, and copying commands — you do not need to be a Rust developer.

**PVFS** is a single command-line program (`pvfs`) plus a data directory (SQLite log + index). Version **0.1** today includes the **P0 core engine** (forest, signed nodes/links, event log) and **P1 storage ops** (bind real folders, scan, read files with hash verification, background watcher).

---

## What you need

| Platform | Requirements |
|----------|----------------|
| **Linux or macOS** (local dev) | Git, a C compiler (`build-essential` / Xcode CLI tools), `curl`, `pkg-config`, **Rust** (via [rustup](https://rustup.rs)) |
| **presubuntu test server** | VPN to the home lab, SSH to `192.168.0.184` as `chris` (Rust + build tools installed by Homelab bootstrap) |

There is no Docker image for the new PVFS — you build one native binary from source.

---

## Option A — Build on your own machine

### 1. Clone the repo

```bash
git clone https://github.com/christcb03/phrasevault.git
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

The `pvfs` binary is at `target/release/pvfs`.

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

## Option B — presubuntu (manual build + manual tests)

**presubuntu** is the Ubuntu test VM (Proxmox VM 101). Bootstrap (Rust, `build-essential`, `/opt/pvfs/data`) comes from the Homelab reset — see [PRESUBUNTU_RESET.md](https://github.com/christcb03/Homelab/blob/main/docs/PRESUBUNTU_RESET.md) if you need a fresh host.

| Item | Value |
|------|--------|
| Host (on VPN) | `192.168.0.184` |
| SSH user | `chris` |
| Forest data (suggested) | `/opt/pvfs/data/my-forest` |

### 1. SSH in

```bash
ssh chris@192.168.0.184
```

### 2. Clone and build (on the server)

```bash
git clone https://github.com/christcb03/phrasevault.git
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
export PVFS_DATA_DIR=/opt/pvfs/data/my-forest
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

If you prefer rsync + build + test + install in one shot from your machine:

```bash
cd ~/Projects/phrasevault/deploy/ansible
cp inventory.example.ini inventory.ini
ansible-galaxy collection install ansible.posix
ansible-playbook -i inventory.ini pipeline.yml
```

Details: [deploy/ansible/README.md](../deploy/ansible/README.md).

---

## Environment variables

| Variable | Meaning |
|----------|---------|
| `PVFS_DATA_DIR` | Path to the forest data directory (`log.db`, `index.db`, device key). **Required** for every command except `init`. |
| `PVFS_BIN` | Used only by `smoke-test.sh` — path to the `pvfs` binary to test. |

---

## Troubleshooting

| Problem | What to try |
|---------|-------------|
| `cargo: command not found` | Run `source "$HOME/.cargo/env"` or open a new terminal after rustup. |
| SSH to presubuntu times out | VPN up? `ping 192.168.0.184`. After a VM rebuild, IP or host key may have changed — see Homelab [PRESUBUNTU_RESET.md](https://github.com/christcb03/Homelab/blob/main/docs/PRESUBUNTU_RESET.md). |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | `ssh-keygen -R 192.168.0.184` then reconnect. |
| `pvfs init` says forest exists | Use a new `PVFS_DATA_DIR` or remove the old directory (destroys data). |
| Pipeline tests fail | Read `artifacts/presubuntu/pvfs-test-results.txt`; fix locally with `cargo test` first. |

---

## Further reading

- Design specs: [00](00-architecture-decisions.md) · [01](01-core-engine-design.md) · [02](02-p0-core-engine-spec.md) · [03](03-federation-trust-and-uris.md) · [04](04-p1-storage-and-fs-ops-spec.md)
- Version scheme: [VERSIONING.md](../VERSIONING.md)
- Ansible pipeline: [deploy/ansible/README.md](../deploy/ansible/README.md)
- VM reset: [Homelab PRESUBUNTU_RESET.md](https://github.com/christcb03/Homelab/blob/main/docs/PRESUBUNTU_RESET.md)
