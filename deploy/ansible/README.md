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
| `daemon` | run `pvfsd` as a **systemd user service** (INSTALL.md Option C, automated): installs `pvfs`/`pvfsd`/`pvfs-companion` to `~/.local/bin`, the `pvfsd@` user unit + `/run/pvfs` tmpfiles snippet, inits a test forest at `~/pvfs-mounts/smoke`, then proves the lifecycle — enable → client answers over `/run/pvfs` → clean stop (socket removed) → restart. **Leaves the service enabled + running** as a standing daemon testbed |
| `report` | fetch `pvfs-test-results.txt` / `pvfs-smoke-results.txt` / `pvfsd-journal.txt` into `./artifacts/<host>/` |

Re-run just the checks after a code change:

```sh
ansible-playbook -i inventory.ini pipeline.yml --tags deploy,build,test,smoke,report
```

Re-test just the daemon service (redeploys the unit + binaries from the last build):

```sh
ansible-playbook -i inventory.ini pipeline.yml --tags daemon,report
```

## Notes

- The smoke suite creates its forest under `mktemp -d` and cleans up after
  itself; it never touches an existing data dir.
- The pipeline is idempotent: rustup is only installed if missing, rsync only
  ships changes, and install always reflects the binary that passed the tests
  in this run (tests run before install).
- The `daemon` stage's test forest (`~/pvfs-mounts/smoke`) is disposable — its
  recovery phrase is printed into the ansible log on first init, so never point
  the stage at a real forest. Delete the directory to get a fresh one.
- After the run, poke the daemon from the host with
  `PVFS_SOCKET_DIR=/run/pvfs pvfs remote --forest ~/pvfs-mounts/smoke info`
  or watch it with `journalctl --user -fu pvfsd@smoke`.
