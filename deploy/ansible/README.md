# PVFS Ansible pipeline

Automated **build → test → smoke → install** for a remote Linux host.

**Manual install on a server:** [docs/INSTALL.md](../../docs/INSTALL.md) Option B.

## One-time setup

```sh
cp inventory.example.ini inventory.ini   # set <host> and <user>
ansible-galaxy collection install ansible.posix
```

Requires `rsync` on both ends (the playbook installs it on the target).

## Run the full pipeline

```sh
ansible-playbook -i inventory.ini pipeline.yml
```

Stages (also usable as `--tags`):

| Tag | What it does |
|---|---|
| `prepare` | apt build deps + rustup (stable, minimal profile) |
| `deploy` | rsync the repo to `/opt/pvfs/src` (excludes `.git`, `old/`, `v0.0-concept/`, `target/`) |
| `build` | `cargo build --release --workspace` |
| `test` | `cargo test --workspace` — the full spec §14 suite; **fails the pipeline on any failure** |
| `smoke` | `files/smoke-test.sh` — every CLI function end-to-end incl. exit-code contracts |
| `install` | copy the release binary to `/usr/local/bin/pvfs` |
| `report` | fetch `pvfs-test-results.txt` / `pvfs-smoke-results.txt` into `./artifacts/<host>/` |

Re-run just the checks after a code change:

```sh
ansible-playbook -i inventory.ini pipeline.yml --tags deploy,build,test,smoke,report
```

## Notes

- The smoke suite creates its forest under `mktemp -d` and cleans up after
  itself; it never touches an existing data dir.
- The pipeline is idempotent: rustup is only installed if missing, rsync only
  ships changes, and install always reflects the binary that passed the tests
  in this run (tests run before install).
