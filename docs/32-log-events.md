# 32 — Log records and event names

Since PVOS D222, every PVFS daemon (pvfsd, the `pvfs mount` view, the
companion's `serve`) writes its log through one crate, `pvfs-log`, which PVOS
uses too. A person reading the journal or `pvfsd.log` sees the same lines as
before; a log server gets a record around each one. This page is the
reference for that record and the list of event names. The list is checked
by a test (`crates/pvfs-log/tests/events.rs`): a name logged in the code but
missing here, or listed here but no longer logged, fails the pipeline.

## The record (schema 1)

| Field | What |
|---|---|
| `ts` | UTC, RFC 3339 with milliseconds and `Z`. Never local time: the boxes are in different zones. |
| `id` | 128-bit random hex: lets a receiver drop a resent duplicate. |
| `seq` | per-process counter, orders records within one millisecond. |
| `host`, `service`, `pid` | the box, `pvfsd` / `pvfs-mount` / `pvfs-companion` (PVOS: `pvosd`, `app:<id>`), the process. |
| `severity` | RFC 5424: `error`, `warning`, `notice`, `info` (and `debug`, unused so far). |
| `event` | a stable name from the list below. |
| `category` | `system`, `audit` or `security`. |
| `outcome` | `success` or `failure`, when it applies. |
| `component`, `msg` | the line a person reads is `component: msg` — today's text. |
| `via` | set when pvosd relays a child's line (`pvosd/app[iac] err`). |
| `fields` | named values; each has a privacy class (below). |

## Where it goes (`PVFS_LOG_FORMAT`)

- `auto` (default): when stderr is the journal (a systemd unit), the record
  is sent with journald's native protocol: `MESSAGE` is the line, `PRIORITY`
  the severity, and `PV_SCHEMA=1`, `PV_ID`, `PV_EVENT`, `PV_CATEGORY`,
  `PV_OUTCOME`, `PV_SERVICE`, `PV_COMPONENT`, `PV_VIA` plus one `PV_<NAME>`
  per field. `journalctl -u pvfsd-replica2` reads as before; `journalctl
  PV_EVENT=pvfs.job.failed` and `-o json` work too. Anywhere else (the NAS's
  wrapper, a terminal, a test) the output is the plain line.
- `text`, `journal`, `json` (one schema-1 object per line), `logfmt`.

`PVFS_LOG_LEVEL` (`error`/`warning`/`notice`/`info`/`debug`, default `info`)
drops records below it. `PVFS_LOG_PRIVACY` (`full`/`identified`/`minimal`,
default `full` on the box itself) and `PVFS_LOG_PSEUDONYM_KEY_FILE` (32 bytes,
raw or hex) are below.

## Privacy

Every field has a class, and each output has a level:

| Class | Examples | `full` | `identified` | `minimal` |
|---|---|---|---|---|
| `meta` | counts, durations, job, ids, hostnames of fleet boxes | kept | kept | kept |
| `actor` | a member's or device's key | kept | pseudonym `a:…` | pseudonym `a:…` |
| `net` | a connecting client's address | kept | kept | only on audit/security events |
| `content` | paths, file names, titles, labels, error texts | kept | `h:…` | `h:…` |
| `identity` | a person's name or email | kept | kept | out |

What a level takes out of the fields it also takes out of the sentence
(`‹path›`, or the actor's pseudonym). Pseudonyms are a BLAKE3 keyed hash with
the instance's key: stable across one fleet, not linkable across
organisations. Without a key, `actor` and `content` values are taken out
instead. The box's own journal is `full`; destinations off the box default
to `minimal` (PVOS D222d).

## Audit and security events (PVOS D222b)

Two categories are for a SIEM:

- **`security`** — something was refused. These are logged where the
  answer leaves the daemon, so every gate is covered:
  - a request (`pvfs.access.denied`);
  - a revoked key (`pvfs.access.revoked_key`);
  - a signature (`pvfs.access.bad_signature`);
  - a handshake (`pvfs.auth.refused`, with `reason`);
  - a TLS handshake (`pvfs.tls.handshake_failed`; a client that connects
    and leaves without a byte is not logged);
  - the companion's web agent (`pvfs.agent.refused`).

  Each carries the op, the `principal` and the client's `peer_addr` (`local`
  for the Unix socket). They are rate-limited per peer: ten a minute, then
  the next one that goes out says how many were dropped (`suppressed`).
- **`audit`** — a change of authority, logged once by the daemon that
  commits it, with author, subject and log `seq`:
  `pvfs.authority.device_authorized`, `device_revoked`, `acl_set`,
  `member_tagged`, `root_rotated`, `recovery_key_registered`/`_revoked`,
  `certificates_bound`. The companion's signing decisions (`audit.jsonl`)
  are `pvfs.agent.audit`.

The signed log is still the record of authority; these lines are how a
SIEM hears of it. Our log server keeps both categories 90 days and alerts on
a burst of refusals and on a revoked key used (HomeLab `docs/LOGGING.md`).

## From the logging library itself (PVOS D225)

Every daemon logs these through `pvfs-log`, so they are not in the table
below (it lists the names each crate logs; doc 33 lists the shipping ones):

- **`pvfs.process.started`** (notice, system): the first record of pvfsd,
  the mount and the companion (`process_started`, after their arguments
  are parsed: `--version` logs nothing), with `build` and `pid`, e.g. `pvfsd: build 1.4.0 (v1.4-592-g…) starting (pid 4131)`. A log
  read after an upgrade or a crash says which build wrote it. pvosd has its
  own, `pvos.boot.started`.
- **`pvfs.thread.panicked`** (critical, system, outcome failure): a thread
  panicked. Fields: `thread`, `at` (file:line) and `message` (content: it
  can hold a path). It goes to the journal or file and to the
  destinations, and Rust's own report follows it as before. It is
  installed by `init_daemon`, so every daemon has it, pvosd too.

## Event names

`pvfs.<area>.<what>`. Renaming or removing one is a breaking change for
anyone searching or alerting on it: say so in the CHANGELOG.

| Event | Severity | Category | Meaning |
|---|---|---|---|
| `pvfs.access.bad_signature` | warning | security | A signed event carried a signature that does not verify. |
| `pvfs.access.denied` | warning | security | A request was refused (`forbidden`): who, from where, which op, why. Rate-limited per peer. |
| `pvfs.access.revoked_key` | warning | security | A key the forest once admitted and has revoked tried to act (or a signed event by an author that is not an active device). |
| `pvfs.agent.audit` | notice | audit | A companion audit entry (signing decisions, connects, pairings, locks), as also written to `audit.jsonl`; a decision other than `approved` is the failure outcome. |
| `pvfs.agent.listening` | notice | system | The companion's socket, web agent or tenant socket is serving. |
| `pvfs.agent.origin_revoked` | notice | audit | A web origin's sign-in grant was revoked. |
| `pvfs.agent.phrase` | info | system | At start: one phrase the companion serves, with its root key prefix. |
| `pvfs.agent.refused` | warning | security | The companion's web agent refused a request (a wrong token, an origin not connected, a connect the person denied). |
| `pvfs.agent.settings` | notice | system | At start: prompt backend, idle lock and audit files. |
| `pvfs.auth.refused` | warning | security | A connection was refused at the handshake: `challenge_reused`, `challenge_expired`, `bad_signature`, `malformed` or `protocol`. |
| `pvfs.authority.acl_set` | notice | audit | An ACL entry was set (node, grantee, rights, expiry). |
| `pvfs.authority.certificates_bound` | notice | audit | Certificates were bound to this forest. |
| `pvfs.authority.device_authorized` | notice | audit | A device or member key was authorized (author, device, log seq). |
| `pvfs.authority.device_revoked` | notice | audit | A device or member key was revoked. |
| `pvfs.authority.member_tagged` | notice | audit | A membership tag was granted to or removed from a key. |
| `pvfs.authority.recovery_key_registered` | notice | audit | A recovery key was registered. |
| `pvfs.authority.recovery_key_revoked` | notice | audit | A recovery key was revoked. |
| `pvfs.authority.root_rotated` | notice | audit | The forest's root key was rotated. |
| `pvfs.catalogue.claim_refused` | warning | system | A peer's region claim was refused. |
| `pvfs.catalogue.fetch_failed` | warning | system | A region is still behind after the pass. |
| `pvfs.catalogue.fetched` | info | system | A catalogue region was fetched at a head. |
| `pvfs.catalogue.head_committed` | notice | system | A head published while the owner was away is now committed. |
| `pvfs.catalogue.head_held` | info | system | The owner already holds that head or a newer one. |
| `pvfs.catalogue.head_taken` | notice | system | A provisional head was taken from a region's box. |
| `pvfs.catalogue.heads_pending` | warning | system | Pending heads could not be committed yet. |
| `pvfs.companion.audit_unwritten` | error | system | An audit.jsonl entry could not be appended. |
| `pvfs.companion.failed` | error | system | A companion command ended with an error. |
| `pvfs.companion.ledger_unwritten` | warning | system | A key-ledger entry could not be written. |
| `pvfs.companion.orphaned` | warning | system | An older companion with no pidfile still answers. |
| `pvfs.companion.prompt` | info | system | An interactive prompt or retry hint at the terminal. |
| `pvfs.companion.runtime_file` | notice | system | A runtime file was rewritten, or left to another instance. |
| `pvfs.companion.runtime_file_failed` | warning | system | A runtime file could not be read, touched or rewritten; retried later. |
| `pvfs.companion.took_over` | notice | system | A running instance was stopped and replaced. |
| `pvfs.daemon.config` | notice | system | At start: the forest, the role (owner/replica), the enabled jobs, the regions by kind, the listen address (D228). |
| `pvfs.engine.close_failed` | warning | system | The runner's own engine did not close cleanly. |
| `pvfs.fence.diverged` | warning | system | A routed write was refused: its log diverges from this owner's. |
| `pvfs.fence.fenced` | error | system | This owner is FENCED: a peer holds a longer log. |
| `pvfs.fence.not_believed` | warning | security | A peer without root admin claimed a longer log; not believed, not fenced. |
| `pvfs.health.first_pass_done` | notice | system | The first health pass is done; taking network writes. |
| `pvfs.health.first_pass_late` | warning | system | No first pass in time; taking network writes anyway. |
| `pvfs.health.first_pass_waiting` | notice | system | Waiting for the first health pass before taking network writes (reads are served). |
| `pvfs.health.peer_down` | warning | system | A fleet peer is not answering. |
| `pvfs.health.tip_unjudged` | warning | system | A peer's log tip could not be judged. |
| `pvfs.ingest.save_failed` | error | system | ingest.sessions was not saved. |
| `pvfs.ingest.sessions_unreadable` | error | system | ingest.sessions cannot be read; the daemon exits. |
| `pvfs.job.failed` | warning | system | A job's pass, session, thread or trash step failed (once per run and per text). |
| `pvfs.job.recovered` | notice | system | A job's run of failures ended. |
| `pvfs.job.reload_failed` | warning | system | serve.jobs could not be reloaded; the old config is kept. |
| `pvfs.lease.released` | notice | system | The write lease was released. |
| `pvfs.lease.taken` | notice | system | A connection holds the write lease. |
| `pvfs.mount.bytes_refused` | warning | system | A holder served bytes with the wrong hash. |
| `pvfs.mount.cache` | info | system | The read-through cache's report: files opened, verified and kept, bytes fetched, evictions; when anything moved, at most every 5 min. |
| `pvfs.mount.delete_failed` | error | system | A delete through the view failed (EIO). |
| `pvfs.mount.delete_refused` | warning | system | A delete was refused: this box's copy is not the file shown. |
| `pvfs.mount.deleted` | info | system | A delete through the view succeeded. |
| `pvfs.mount.dir_removed` | info | system | An rmdir was done on the boxes that held the folder. |
| `pvfs.mount.gone` | info | system | A file's bytes are gone everywhere; hidden for now. |
| `pvfs.mount.ingest_stream` | info | system | Reads proxy an in-flight ingest. |
| `pvfs.mount.punch_failed` | warning | system | Read pieces could not be given back to the disk. |
| `pvfs.mount.read_through_failed` | warning | system | A read-through fetch failed; a later open retries. |
| `pvfs.mount.rename_failed` | error | system | A rename or relabel through a mount failed (EIO). |
| `pvfs.mount.rename_refused` | warning | system | A rename through the view was refused. |
| `pvfs.mount.rename_unrolled` | error | system | Copies already renamed could not be put back. |
| `pvfs.mount.renamed` | info | system | A rename was done on the boxes that hold the copies. |
| `pvfs.mount.rmdir_failed` | error | system | An rmdir through the view failed. |
| `pvfs.mount.rmdir_refused` | warning | system | An rmdir was refused (not empty on a holder). |
| `pvfs.mount.status_unwritten` | warning | system | The mount's status file could not be written. |
| `pvfs.mount.stream_verified` | debug | system | A file read through in stream mode is whole and verified (one per file; the cache report counts them). |
| `pvfs.mount.streaming` | info | system | A file streams while its fetch verifies. |
| `pvfs.mount.unmount_failed` | error | system | Still mounted after `fusermount -uz`. |
| `pvfs.mount.verified` | info | system | A read-through file is whole, verified and kept (keep mode). |
| `pvfs.notify.failed` | warning | system | A fleet notification was not sent, or emit failed. |
| `pvfs.notify.sent` | info | system | A fleet notification was sent. |
| `pvfs.pairing.revoked` | notice | audit | A paired server was removed. |
| `pvfs.pairing.trusted` | notice | audit | A URL was pre-trusted for a pairing. |
| `pvfs.pairing.untrusted` | notice | audit | A trusted URL was forgotten. |
| `pvfs.priority.lower_failed` | warning | system | A thread or the hashing pool stays at the daemon's priority. |
| `pvfs.priority.nice_denied` | warning | system | A job holding the writer keeps its lowered CPU priority (needs LimitNICE=). |
| `pvfs.priority.policy` | notice | system | The background-priority policy at start. |
| `pvfs.projection.cache_discarded` | warning | system | The cached projection failed a fold or device check; a full replay follows. |
| `pvfs.projection.fold_busy` | warning | system | Another process holds the fold lock; waiting or retrying. |
| `pvfs.projection.fold_gave_up` | error | system | The fold lock was held too long; this open gives up. |
| `pvfs.projection.migrated` | notice | system | The projection's schema was migrated in place. |
| `pvfs.projection.rebuilding` | notice | system | Rebuilding the index from the log. |
| `pvfs.quality.probe_broken` | warning | system | ffprobe says a file's data is invalid. |
| `pvfs.quality.probe_error` | warning | system | A probe could not run; retried later. |
| `pvfs.quality.probe_timeout` | warning | system | A probe was killed at its timeout. |
| `pvfs.quality.prober_failed` | warning | system | The prober would not start this pass. |
| `pvfs.quality.prober_found` | notice | system | ffprobe was found; quality is measured. |
| `pvfs.quality.prober_missing` | notice | system | No ffprobe; quality falls back to size. |
| `pvfs.quality.recorded` | info | system | A quality was written through the view. |
| `pvfs.quality.remote_failed` | warning | system | The remote probe step failed. |
| `pvfs.quality.remote_no_prober` | warning | system | probe-remote names regions but there is no ffprobe. |
| `pvfs.quality.remote_refused` | warning | system | The holder refused a remote probe result. |
| `pvfs.quality.remote_skipped` | info | system | The remote probe skipped a region. |
| `pvfs.quality.report` | info | system | A region's probe summary. |
| `pvfs.quality.unmeasured` | info | system | Video files in a region not measured yet. |
| `pvfs.receive.failed` | warning | system | Receiving a file failed. |
| `pvfs.receive.folders_made` | info | system | Receive made folders only staging had. |
| `pvfs.receive.no_space` | warning | system | No space to receive a file. |
| `pvfs.receive.received` | info | system | A file was received into the library. |
| `pvfs.rename.renamed` | info | system | A rename through the view. |
| `pvfs.rename.rows_deferred` | warning | system | Renamed on disk; its rows wait for the next pass. |
| `pvfs.replica.fold_deferred` | warning | system | The follow job's fold failed; the next tick retries. |
| `pvfs.request.unknown_op` | warning | system | A client asked for an op this daemon does not know (once per op name per run). |
| `pvfs.resolve.folders_removed` | info | system | Emptied staging folders were removed. |
| `pvfs.resolve.trashed` | info | system | Staging copies the library holds were trashed (confirmed). |
| `pvfs.resolve.unconfirmed` | info | system | Staging copies kept: not confirmed yet. |
| `pvfs.rmdir.removed` | info | system | A folder was removed through the view. |
| `pvfs.scan.file_gone` | info | system | A file went away before it could be read. |
| `pvfs.scan.hash_failed` | warning | system | Hashing a file failed. |
| `pvfs.scan.hash_from_sidecar` | info | system | A file's hash was taken from its sidecar. |
| `pvfs.scan.hash_skipped` | info | system | Not hashing an unlinked duplicate. |
| `pvfs.scan.hashing` | info | system | Hashing a file. |
| `pvfs.scan.ingested` | info | system | A watch pass ingested changes. |
| `pvfs.scan.needs_attention` | warning | system | How many files need attention. |
| `pvfs.scan.node_model` | info | system | The watch scans node-model bindings with its own engine. |
| `pvfs.scan.owner_unreachable` | warning | system | No route to the owner; cataloguing locally. |
| `pvfs.scan.skipped` | warning | system | A watch pass skipped a file that needs a person. |
| `pvfs.scan.stopped` | info | system | A watch pass stopped mid-pass. |
| `pvfs.serve.fatal` | error | system | pvfsd exits with an error. |
| `pvfs.serve.listening` | notice | system | The TLS listener is up (with its transport pin). |
| `pvfs.serve.serving` | notice | system | Serving the mount on its socket. |
| `pvfs.serve.shutting_down` | notice | system | Shutting down; checkpointing. |
| `pvfs.supervise.save_failed` | warning | system | The supervise record was not saved. |
| `pvfs.supervise.start_sent` | notice | system | A start was sent to a down peer. |
| `pvfs.sync.attested` | info | system | The tier pass hashed a file into a successor node. |
| `pvfs.sync.fetch_failed` | warning | system | Streaming or committing from one holder failed; the next is tried. |
| `pvfs.sync.fetched` | info | system | A file was fetched and committed from a holder. |
| `pvfs.sync.quarantine_failed` | warning | system | Quarantining a stale location failed. |
| `pvfs.sync.quarantined` | warning | system | A stale location was quarantined after an id mismatch. |
| `pvfs.sync.replaced` | info | system | The tier pass replaces a copy in place with a better one. |
| `pvfs.sync.swarm_abandoned` | warning | system | A swarm gave up with chunks left; the partial file is kept. |
| `pvfs.sync.swarm_done` | info | system | A swarm finished: chunks per holder. |
| `pvfs.sync.swarm_fallback` | warning | system | A swarm fetch failed; falling back to one stream. |
| `pvfs.sync.swarm_resumed` | info | system | A swarm resumed chunks from an earlier attempt. |
| `pvfs.sync.tmp_sweep_failed` | warning | system | The start-up sync tmp sweep failed. |
| `pvfs.sync.tmp_swept` | info | system | Orphaned sync tmp files were removed at start. |
| `pvfs.tls.handshake_failed` | warning | security | A TLS handshake on the network listener failed (a client that connects and leaves is not logged). |
| `pvfs.tls.trust_failed` | warning | system | Keychain trust was not installed. |
| `pvfs.tls.trust_installed` | notice | audit | The web agent's certificate was added as a trusted root in the login keychain. |
| `pvfs.tls.trust_manual` | notice | system | Not macOS: the person is told to trust the certificate by hand. |
| `pvfs.tls.unavailable` | warning | system | Web-agent TLS failed; serving plain http. |
| `pvfs.trash.orphans_moved` | info | system | Orphaned manifests were moved to the trash. |
| `pvfs.trash.purge_failed` | warning | system | Receive's trash purge failed. |
| `pvfs.trash.purged` | info | system | Trash buckets past retention were purged. |
| `pvfs.trash.served` | info | system | A reader was served from the trash (once per file per hour). |
| `pvfs.trash.trashed` | info | system | A file was trashed through the view. |
| `pvfs.vault.forest_linked` | notice | system | A forest was recorded in a key's ledger. |
| `pvfs.vault.keychain_unavailable` | warning | system | The OS keychain failed; falling back to a passphrase. |
| `pvfs.vault.left_out` | warning | system | A non-default phrase could not be opened and is not served. |
| `pvfs.vault.locked` | notice | system | The running agent was told to drop its seed. |
| `pvfs.vault.sealed` | notice | audit | A phrase was sealed into a vault or tenant store. |
| `pvfs.writer.checkpoint_offload_failed` | warning | system | Checkpoints stay on the writer's commits. |
| `pvfs.writer.checkpoint_slow` | warning | system | An off-writer checkpoint passed the log threshold. |
| `pvfs.writer.held` | warning | system | The writer was held past the threshold. |
| `pvfs.writer.hourly` | info | system | The hourly report on the writer. |
| `pvfs.writer.index_sync_failed` | warning | system | index.db keeps an fsync per commit. |
| `pvfs.writer.panicked` | error | system | A step panicked while holding the writer. |
| `pvfs.writer.waited` | warning | system | A step waited past the threshold for the writer. |
