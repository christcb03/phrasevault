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

### One build slot per session

Several sessions work in this repo at once. Pass `-e session=<name>` and the
run builds in `/opt/pvfs-<name>/src` instead of the shared `/opt/pvfs/src`:

```sh
ansible-playbook -i inventory.ini pipeline.yml -e session=d99-my-change
```

Without it, concurrent runs rsync into the same directory with `delete: true`
and replace each other's source mid-compile — the resulting errors point at
code that is plainly correct. Run the pipeline from your session's worktree
with the same name you gave the worktree, and delete `/opt/pvfs-<name>` on the
test host when the work merges.

Stages (also usable as `--tags`):

| Tag | What it does |
|---|---|
| `prepare` | apt build deps + rustup pinned to **1.96.0** (matches CI; minimal profile) — installed only when cargo is absent; an existing host keeps whatever toolchain it has (doc 26, D124) |
| `deploy` | rsync the repo to `/opt/pvfs/src` — or `/opt/pvfs-<session>/src`, see above (excludes `.git`, `old/`, `v0.0-concept/`, `target/`, `.claude/`) |
| `build` | `cargo build --release --workspace` |
| `test` | `cargo test --workspace` — the full spec §14 suite; **fails the pipeline on any failure** |
| `lint` | `cargo clippy --all-targets --workspace -- -D warnings` (D121; also runs under `test`) |
| `reap` | delete `/opt/pvfs-<session>` slots idle for 2+ days, never this run's or `/opt/pvfs` (D121; also runs under `report`) |
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
- The pipeline is idempotent: rustup is only installed if missing (and never
  upgraded or re-pinned — see doc 26), rsync only
  ships changes, and install always reflects the binary that passed the tests
  in this run (tests run before install).
- The `daemon` stage's test forest (`~/pvfs-mounts/smoke`) is disposable — its
  recovery phrase is printed into the ansible log on first init, so never point
  the stage at a real forest. Delete the directory to get a fresh one.
- After the run, poke the daemon from the host with
  `PVFS_SOCKET_DIR=/run/pvfs pvfs remote --forest ~/pvfs-mounts/smoke info`
  or watch it with `journalctl --user -fu pvfsd@smoke`.

## Where the suite runs, and why it is fast (D132, 2026-09-11)

The tests, clippy and the smoke run on ONE host (`pvfs_runs_suite`, default
true; set it false on a second identical VM so it only builds and installs).
The test and smoke tasks put their temp files on tmpfs (`TMPDIR=/dev/shm`):
every event append and projection commit fsyncs, the build VMs' virtual disks
take 65–80 ms per fsync, and that alone made the same 558 tests take 38 min
on disk against 107 s on tmpfs. `sccache` wraps rustc so a fresh session
slot does not recompile the dependency tree; `CARGO_INCREMENTAL=0` keeps the
artifacts cacheable. The suite's config dir (`XDG_CONFIG_HOME`) is a
per-session throwaway, so no test reads the box's real instance registry.
