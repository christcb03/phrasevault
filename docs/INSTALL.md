# Installing and testing PVFS

This guide is for someone comfortable with a terminal, SSH, and copying commands — you do not need to be a Rust developer.

**PVFS** is a single command-line program (`pvfs`) plus a data directory (SQLite log + index). Version **0.1** today includes the **P0 core engine** (forest, signed nodes/links, event log) and **P1 storage ops** (bind real folders, scan, read files with hash verification, background watcher).

---

## What you need

| Platform | Requirements |
|----------|----------------|
| **Linux or macOS** (local dev) | Git, a C compiler (`build-essential` / Xcode CLI tools), `curl`, `pkg-config`, **Rust** (via [rustup](https://rustup.rs)) |
| **presubuntu test server** | VPN to the home lab (see below), SSH key, Ansible on your laptop |

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

## Option B — presubuntu test server (recommended for “real server” testing)

**presubuntu** is a clean Ubuntu VM (Proxmox VM 101) used to build, test, and install PVFS the same way every time.

| Item | Value |
|------|--------|
| Host (on VPN) | `192.168.0.184` |
| SSH user | `chris` (your SSH key from Terraform cloud-init) |
| Installed binary | `/usr/local/bin/pvfs` |
| Source copy on server | `/opt/pvfs/src` |

You need **VPN access** to the prodlab network before SSH or Ansible will work.

### Step 1 — Reset the VM to a clean Ubuntu host (when starting fresh)

From the **Homelab** repo (not phrasevault):

```bash
cd ~/Projects/Homelab
./scripts/presubuntu-reset.sh
```

Type `presubuntu` when prompted. This destroys VM 101 and recreates it from Terraform, then bootstraps Rust and `/opt/pvfs/data` — **no old Docker stack**.

Prerequisites: `terraform/proxmox/.env.terraform` exists (see Homelab `docs/PRESUBUNTU_RESET.md`).

### Step 2 — Deploy, test, and install PVFS from your laptop

From the **phrasevault** repo:

```bash
cd ~/Projects/phrasevault/deploy/ansible
cp inventory.example.ini inventory.ini   # edit if your SSH alias differs
ansible-galaxy collection install ansible.posix

ansible-playbook -i inventory.ini pipeline.yml
```

The pipeline will:

1. Install build tools and Rust (if missing)
2. Rsync the repo to `/opt/pvfs/src`
3. `cargo build --release` and `cargo test --workspace`
4. Run the CLI smoke script
5. Install `pvfs` to `/usr/local/bin/pvfs`

Test logs are copied to `deploy/ansible/artifacts/<host>/` on your machine.

To redeploy after code changes without rebuilding the VM:

```bash
ansible-playbook -i inventory.ini pipeline.yml --tags deploy,build,test,smoke,install
```

### Step 3 — Manual tests over SSH

```bash
ssh chris@192.168.0.184

export PVFS_DATA_DIR=/opt/pvfs/data/my-forest
pvfs init
ROOT=$(pvfs info | awk '/root_node_id/ { print $2 }')

# Bind a real directory (P1): index files without copying them
pvfs bind "$ROOT" /home/chris/some-folder --recursive

# One-shot scan + reconcile
pvfs scan "$ROOT" /home/chris/some-folder

# Read a file through PVFS (verifies hash if set)
pvfs stat <node-id>
pvfs cat <node-id>

# Background watcher (optional)
pvfs serve --bind "$ROOT" /home/chris/some-folder
```

Use `pvfs --help` and `pvfs <command> --help` for all subcommands.

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
| SSH to presubuntu times out | Connect to VPN; ping `192.168.0.184`. |
| Ansible “permission denied” | User must be `chris`; key at `~/.ssh/id_ed25519`. |
| `pvfs init` says forest exists | Use a new `PVFS_DATA_DIR` or remove the old directory (destroys data). |
| Pipeline tests fail | Read `artifacts/presubuntu/pvfs-test-results.txt`; fix locally with `cargo test` first. |

---

## Further reading

- Design specs: [00](00-architecture-decisions.md) · [01](01-core-engine-design.md) · [02](02-p0-core-engine-spec.md) · [03](03-federation-trust-and-uris.md) · [04](04-p1-storage-and-fs-ops-spec.md)
- Version scheme: [VERSIONING.md](../VERSIONING.md)
- Ansible pipeline: [deploy/ansible/README.md](../deploy/ansible/README.md)
- VM reset: [Homelab PRESUBUNTU_RESET.md](https://github.com/christcb03/Homelab/blob/main/docs/PRESUBUNTU_RESET.md)
