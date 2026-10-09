# Changelog

PVFS uses the layered version scheme in [VERSIONING.md](VERSIONING.md): this
file tracks Layer 0, the file-system engine.

## Unreleased

- **What kind of failure, slow requests, and a log level you change live
  (PVOS D229).**
  - Every record at warning or above carries `error_kind`
    (`network:refused`, `disk:no_space`, `auth:forbidden`, `slow:busy`, …):
    a fixed vocabulary, kept at every privacy level, so a log server can
    group failures even where the error's text is not shipped. It comes from
    the call site, the event name or the error's text (`pvfs_log::kind`);
    pvosd's records get it too. A test holds every PVFS warning and error
    call to it.
  - `pvfs.request.slow` (pvfsd took past `PVFS_SLOW_REQUEST_MS`, 5 s, to
    answer) and `pvfs.client.request_slow` (a daemon waited that long on a
    peer): the op, the peer, how long. Rate-limited per op.
  - `pvfs serve log-level`: a level for a while (1 minute to a day), applied
    by pvfsd and its mounts within 5 s, back on its own; `serve status`
    shows it. Proto 17 (`SetLogLevel`, additive).

- **Troubleshooting with the logs (PVOS D228).**
  - pvfsd logs `pvfs.daemon.config` at start: the forest, owner or replica,
    the enabled jobs, the regions by kind, and the listener.
  - `pvfs serve status` shows each log destination's health, and the owner
    turns a box's failing or recovered destination into a fleet event
    (`log_destination_failing` / `log_destination_recovered`); the wire
    field is optional both ways.
  - Elasticsearch destinations can send record ids as `_id` (`doc_ids`,
    opt-in), so a resend is not stored twice.
  - New tests for the companion's audit and refusal records.

- **The Mac companion: settings that are settings, a Logging section, and
  Touch ID for history (PVOS D226).**
  - Six tabs: Status, Keys, Sign-ins, Audit, Details, Settings. Settings
    holds only what can be set: Startup, Security (lock after idle,
    signatures per minute), Logging and SSH.
  - Key history, the audit log and Revoke ask for Touch ID (or the Mac's
    password).
  - The agent ships its records to this Mac's log destinations. Tokens are
    kept in the Keychain (`keychain:<name>`).
  - `pvfs-companion log list|add|test|remove` (prompts when run bare).
  - `pvfs log destinations add` and the companion ask the same questions
    (`pvfs_log::ship::ask_destination`).

- **Daemons say their build when they start, and a panic is a record
  (PVOS D225).** pvfsd, the mount and the companion log
  `pvfs.process.started` (`build`, `pid`) first. Every daemon
  (`init_daemon`, pvosd too) records a panic as `pvfs.thread.panicked` at
  critical, with the thread, where, and the
  message, to the journal and the destinations, before Rust's own report.

- **A Loki destination takes `labels` (PVOS D224).** Extra stream labels
  on every push, such as `{"env": "prod"}`, so records sent by a box with
  no Alloy (the NAS) match the same alert rules as the journal streams.
  Names may not be `job`, `host`, `service`, `level` or `category`; only
  `loki` destinations take them. `pvfs log destinations add` asks for
  them. An older daemon ignores the key.

- **Elasticsearch's default index is `logs-pvfs-default` (was `pvfs-logs`),
  and pvosd's web refusals are ECS `web` (PVOS D222e, found live).** Against
  a real Elasticsearch 9.5.2, `pvfs-logs` was a plain index; a name in
  Elastic's `logs-<dataset>-<namespace>` scheme becomes a data stream with
  ECS mappings. A destination that names its index is unchanged. Doc 33 no
  longer says `event.id` drops duplicates: a resent batch stores the ones
  already taken twice, with the same `event.id`.

- **The mount's per-file "whole and verified" line is `debug` in stream
  mode (PVOS D223).** It was about 9,300 of mediabox's 9,600 mount lines a
  day. It is now the event `pvfs.mount.stream_verified` (same text), and
  the cache report counts every verified file: `… N file(s) opened
  through, N verified, N kept whole, …` (field `verified`). Keep mode's
  `… whole, verified and kept` line stays `info`.

- **More log formats (PVOS D222e).** These are new destination types and
  formats, each built from the record already rendered at the
  destination's privacy level:
  - syslog `leef` (IBM QRadar) and `rfc3164`;
  - `gelf` (Graylog, over UDP, TCP or HTTP);
  - `elasticsearch` (`_bulk` of ECS documents; `errors:true` is a failure);
  - `otlp` (OpenTelemetry logs over HTTP JSON);
  - `https_json` with `format` `ecs` or `ocsf`.

  The token header defaults per type (`Bearer`, `ApiKey`) unless the token
  names its scheme. The prompts in `pvfs log destinations add` ask about
  them, and the ECS/OCSF mapping is in doc 33.

- **Log destinations: Loki, Splunk HEC, syslog (RFC 5424 as text, JSON or
  CEF, over TLS, TCP or UDP) and HTTPS JSON, built in (PVOS D222d).** A
  daemon sends its records to the destinations in
  `~/.config/pvfs/log-destinations.json` (or `/etc/pvfs/…`, or
  `$PVFS_LOG_DESTINATIONS`) and re-reads the file within 30 s of a change.
  - Each destination has a filter (categories, minimum severity,
    services) and a privacy level, `minimal` by default.
  - Delivery is at least once, through an on-disk spool (256 MB cap, the
    oldest dropped and counted) rendered at the destination's privacy level
    at send time.
  - TLS is always verified: public roots, a CA file, or a pinned SHA-256.
    There is no setting to skip it.
  - A destination failing for 15 min logs `pvfs.log.destination_failing`,
    and `…_recovered` when it is back.
  - `pvfs log destinations` lists, adds (asking each question), tests and
    removes destinations; `pvfs log whois a:…` turns a pseudonym back into
    a key.
  - Reference and recipes for Splunk UF, Elastic, Vector, rsyslog and Alloy:
    [docs/33-shipping-logs.md](docs/33-shipping-logs.md).
  - New feature `ship` in `pvfs-log`; pvfsd and the CLI turn it on.

- **Every refusal and every change of authority is logged, with who and
  from where (PVOS D222b).** These are category `security`, outcome
  `failure`, rate-limited to 10 a minute per peer, with the next one saying
  how many were dropped:
  - a request refused (`pvfs.access.denied`);
  - a revoked key used (`pvfs.access.revoked_key`);
  - a signature that does not verify;
  - a refused handshake (`pvfs.auth.refused`: challenge reused or expired,
    bad signature, malformed, protocol);
  - a TLS handshake that fails (`pvfs.tls.handshake_failed`; a client that
    connects and leaves is not logged).

  pvfsd catches them where the answer leaves (`err()`), so every gate is
  covered. Each line carries the op, the principal, and the client's
  `peer_addr`, or `local` for the Unix socket.

  Authority changes a daemon commits are logged once, category `audit`
  (`pvfs.authority.device_authorized`, `device_revoked`, `acl_set`,
  `member_tagged`, `root_rotated`, `recovery_key_registered`/`_revoked`,
  `certificates_bound`), with author, subject and log seq.

  The companion logs its web agent's refusals and each `audit.jsonl` entry
  (`pvfs.agent.audit`). New: `ClientMsg::op_name`, `Engine::is_revoked_key`,
  `Engine::known_keys`, `pvfs_log::limit`, thread context fields, and
  `testing::GlobalCapture`.

- **Every daemon line is a log record a log server can use (PVOS D222).**
  pvfsd, the `pvfs mount` view and the companion's `serve` log through a new
  crate, `pvfs-log` (PVOS uses it too): each line keeps its exact text and
  gains a severity (RFC 5424), a stable event name (`pvfs.job.failed`; the
  list is [docs/32-log-events.md](docs/32-log-events.md), checked by a test),
  a category (`system`/`audit`/`security`), an outcome, a UTC timestamp, an
  id and named fields, each with a privacy class (`meta`, `actor`, `net`,
  `content`, `identity`). Under systemd the record goes to the journal with
  its native protocol: `MESSAGE` is the old line, `PRIORITY` the severity,
  and `PV_EVENT`, `PV_CATEGORY`, `PV_<FIELD>` … beside it (`journalctl
  PV_EVENT=pvfs.job.failed` works; a send that fails falls back to `<N>line`
  on stderr). Anywhere else — the NAS's `pvfsd.log`, a terminal, a test — the
  output is the old line byte for byte. `PVFS_LOG_FORMAT`
  (`auto`/`text`/`journal`/`json`/`logfmt`), `PVFS_LOG_LEVEL`,
  `PVFS_LOG_PRIVACY` (`full`/`identified`/`minimal`: what a level takes out
  of the fields it also takes out of the sentence) and
  `PVFS_LOG_PSEUDONYM_KEY_FILE` (keyed BLAKE3 pseudonyms) set it. All 187
  daemon-side `eprintln!` moved; a test fails on a new one. The job
  failure/recovery lines are logged by `JobsState::failed`/`recovered`
  themselves. The CLIs print exactly what they did.

- **pvfs-core compiles on macOS again (fix to PVOS D216).** D216's
  `Engine::floor_for` multiplied a statvfs `blocks()` by its
  `fragment_size()` directly: both are `u64` on Linux, but on macOS
  `fsblkcnt_t` is 32-bit while `fragment_size()` is `c_ulong`, so the
  product did not type-check and `apps/macos-companion/build.sh` failed at
  `cargo build -p pvfs-companion`. Both are now cast to `u64`, as the other
  statvfs callers (`store_filesystems`, `sync`, `ingest::free_space_at`)
  already do, with `clippy::unnecessary_cast` allowed on that statement: on
  Linux the casts are no-ops, and clippy's type-alias exemption that keeps
  the other callers quiet does not reach a closure parameter. No behaviour
  change on Linux.

- **A file being read through the view keeps reading after its holder
  trashes it (PVOS D220).** A Plex stream of an episode Sonarr upgrades
  broke the moment the holder moved the old copy to its region's trash; a
  file open on a local disk stays readable after its unlink. A read-through
  that has already been served bytes now asks with `CatHash { trashed: true
  }`, and a holder whose live copy has gone serves the trashed one — found by
  its sidecar's hash at the sidecar's size, in a region this box catalogues
  from its own disk, under the same read check on that region — for as long
  as it is in the trash. A reader that opens the file after the delete still
  gets ENOENT (D219). The holder says so once an hour per file (`pvfsd:
  <hash> served from <region>'s trash …`). The trash is indexed by hash when
  first asked, reused for a minute, rebuilt on a miss once two seconds old.
  No protocol bump: the field is optional, and an older holder ignores it
  and says `not_found`, as before. `Client::cat_hash_range_from`,
  `sync::trashed_with_hash`, `Engine::trashed_bytes_for_hash`. And the
  view's `getattr` answers for a file open here whose path has left the view
  with its attributes at the open (`fstat` after an unlink): the kernel asks
  at a read that reaches the end, so a stream that outlived its path failed
  there with ENOENT (found on the lab).

- **A read through the view of a file its holder no longer has answers
  "no such file", and a box fetches a new catalogue head when it lands
  (PVOS D219).** When every box a read-through asks says it holds no such
  bytes — none unreachable, none refusing another way — the file was
  deleted or replaced since this box's catalogue last moved: the read
  answers `ENOENT` (it was `EIO`), the mount hides that copy of the path
  (D169's tombstone, at most 2 minutes, gone earlier when the catalogue
  catches up or the holder publishes again still listing it), another copy
  at the path with another hash shows at once, and the handle's later reads
  fail at once for 5 s instead of asking every box again (Bazarr's ffprobe
  of a file Sonarr had just upgraded was nine `read-through … failed` lines
  and an I/O error; it is now two lines and "No such file or directory").
  An unreachable box, a dial or stream failure, or no box at all stay `EIO`.
  `HashFetch::gone()`, `Engine::fetched_seqs()`. On the daemon: a
  `SubRegionHead` committed on the owner, and a replica's follow folding new
  events, nudge the catalogue job; a nudged pass is quick (the stale regions
  only, no claims from every box, the region's last holder asked first) and
  runs at most every 10 s without moving the minute's full pass —
  `catalogue::fetch_pass_db_with`. A holder's head reached mediabox 53–58 s
  after the holder published it; now ~a second (plus the floor).

- **Docs (PVOS D218, 2026-10-04).** A full review of the user docs against
  the code at `ea84559`; no code changed. `docs/INSTALL.md`: both
  walkthroughs run again (`ROOT=` came out empty; `pvfs recover` takes
  `--mnemonic` and does not prompt; `bind --recursive`, `scan <root> <dir>`
  and `serve --bind` never parsed), `libdbus-1-dev`, `fuse3` and ffprobe
  named, several phrases in one companion (`pvfs-companion keys`, repeated
  `--vault`), `PVFS_COMPANION_KEY` and `PVFS_FFPROBE`.
  `docs/USER-MANUAL.md`: `pvfs mount --view --writable` with its known
  problems, placement and `pvfs region floor`, `pvfs fleet announce`, the
  `stalled`/`overdue` rules since D207, a protocol bump rolls box by box,
  four reference rows that did not parse (`mv`, `relabel`, `reorder`,
  `quality`) and the rows that were missing. `VERSIONING.md`: protocol 16
  and the fleet's build. This file: the four entries below that were never
  written (D217, D216, D212, D201). `README.md`, docs 28, 30 and 31, and
  the companion's and the pipeline's READMEs corrected; docs 25 and 29,
  historical runbooks, carry dated notes.

- **Files can be created and edited through the view mount: `pvfs mount
  --view --writable` (PVOS D217).** Off by default, because it changes what
  Plex and the arrs may do to the library through that path. With it, a
  file whose bytes this box already holds opens for writing: `write`,
  `fsync`, `flush` and truncate work on the real file in its region, and the
  `watch` job hashes it again afterwards — no fetch, no copy, no new wire
  op. A file held only on another box still answers `EROFS`. `create` makes
  a new file on this box, in the catalogue region D216's rule picks among
  those it holds that do not drain (`Engine::writable_roots`), and the
  mount answers for it from memory (lookup, read, a second write-open,
  listings) until the catalogue lists it, for at most 10 minutes. A file
  created this way and deleted before it is catalogued is unlinked
  outright, since there is no catalogued copy to send to a trash (it
  answered `EIO`: found on the fleet minutes after the roll). On the fleet
  since `v1.4-549`, 2026-10-04; mediabox's library mount runs with it.
  **Known problems, all open** (PVOS D218 §2.1; user manual §7.13): an edit
  or a truncate lands on the first local file with the same content hash,
  not on the file opened; the free-space floor is not checked for a file at
  the view's root or when no holder of the folder has room; a created file
  drops out of the listing when it is not catalogued within 10 minutes;
  truncating or renaming a just-created file answers `EIO`; the mount
  checks no per-user permissions. Tests: `d217_view_write` (pvfs-fuse).
  Commits `790436c`, `9b314d1`, `ea84559`.

- **A new file goes where its folder already is, and each region keeps a
  free-space floor (PVOS D216).** `receive` took the receiving region with
  the most free space for every file, so an episode could land away from
  its season, and whatever was written through a union landed on the
  union's writable branch: on the fleet, 8,723 subtitles, `.nfo` files and
  artwork sat on a different disk from their media (counted 2026-10-03).
  `Engine::placement_for` prefers the region whose root already has the
  file's parent folder — the disk's own answer, no catalogue read per file
  — and, where a folder is split across regions, the one that holds a file
  with the same stem (`S01E02.en.srt` joins `S01E02.mkv`; the lab had put a
  subtitle away from its episode). With no holder the region with the most
  free space takes it. A region whose disk has less free space than its
  floor is passed over even when it holds the folder, so a show cannot fill
  the disk it started on and a filling disk hands new work to a roomier
  one. The floor is per region and local to the box: `pvfs region floor
  <region> [size]` (`500G`, `1T`, bytes; bare asks), kept as `floor <region>
  <bytes>` in the placement file. With nothing set it is 5 % of the disk,
  capped at 500 GB — a flat 500 GB had switched the folder rule off on
  every smaller disk without saying so. `receive` uses the rule, and so
  does a create through a writable view (D217). Open (PVOS D218 §2.1): the
  fallback — a file at the view's root, or one whose folder no region with
  room holds — takes the region with the most free space without checking
  that region's floor; bare `pvfs region floor` offers `[500G]`, so Enter
  writes an explicit 500 GB; and no command shows a floor or returns a
  region to the default. Tests: `d216_placement`. Commits `f78587b`,
  `59eb640`; the floor in `790436c` and `9b314d1`. On the fleet since
  `v1.4-549`, 2026-10-04.

- **A copy the arrs remove mid-pass no longer fails `resolve`, and a missing
  source stops reading as a broken trash.** `resolve` guards with `is_file`,
  but then reads the file's tail and asks the holder to confirm the bytes — a
  network round trip — before moving it to the trash, and the arrs delete and
  replace in these roots all day. A file that went inside that window aborted
  the whole pass, abandoning its remaining candidates and raising a job error;
  it is now the same nothing-to-do as a row that outlived its file. And
  `move_to_trash`'s copy+remove fallback, for a store on another mount, ran
  on EVERY rename error, so the vanished file came back as `copy to trash: No
  such file or directory` — as though writing to the trash had failed, when
  the trash was fine. The fallback is now `EXDEV` only; anything else says
  `move to trash`. Seen on feederbox 2026-10-03 11:09 AM ET, cleared by the
  next pass, while Sonarr upgraded five episodes of one show.

- **The companion's session grant lasts 7 days (PVOS D212).** It was 30. A
  sign-out cannot revoke the grant a session certificate gives in the
  person's own forest, so the grant now lasts no longer than a session's
  7-unused-days lapse (`SESSION_GRANT_MS`, `pvfs-companion`'s `agent.rs`).
  A session in use is renewed by signing the same certificate again: the
  repeated admission is a no-op, the grant's end moves, and nothing is
  asked. Test: `d193_structured_relays` pins the 7 days and the renewal.
  Commit `e294ddf`. It needs the companion rebuilt (the Mac app carries it
  since 2026-10-02); nothing changes on the fleet.

- **An unreadable copy loses to a readable one; mediabox measures the NAS's
  video over the LAN; view tests unmount (PVOS D211).** Chris's decisions of
  2026-10-01.
  - **The ladder.** A probe now tells "ffprobe said the data is invalid"
    (`ProbeOutcome::Broken`: `Invalid data found when processing input`,
    `moov atom not found`, `EBML header parsing failed`, and no I/O words)
    from "the probe could not run" (`ProbeOutcome::Error`: permission, I/O,
    a signal, a network fetch that failed — nothing recorded, the file rests
    6 h). A first `Broken` is a SUSPECT (`"probe":"suspect","probe_at":ms`);
    a second at least 30 minutes later CONFIRMS it (`"probe":"failed"`);
    `media::quality_after` is that rule, applied by every write of a
    quality. A confirmed-unreadable copy loses to a MEASURED copy (a new
    rung after decode); two unreadable copies, or unreadable vs unmeasured
    or suspect, change nothing. The drain: an unreadable draining winner no
    longer replaces a measured library copy (`receive-plan` says why).
  - **Probing for another box.** A box with ffprobe measures the regions
    named in its `probe-remote` file (`pvfs region probe-remote`), held by
    another box: the daemon runner's probe step (every 10 min, like the
    trash step — not a `serve.jobs` job, so a rollback is safe) checks the
    holder is on the LAN (a TCP connect under 10 ms), serves ffprobe the
    file's ranges from `127.0.0.1` (`probe::RangeServer`: `CatHash` from
    the holder as ffprobe asks, ≤64 MiB a probe; a fault is an error), and
    sends the result with the new `SetRegionQuality` (proto 16, `w` on the
    region; the holder checks its copy and writes its own row in one
    writer step). A measurement of the same hash elsewhere is sent without a
    read. With a real ffprobe a 150 MB film read 3–5 MB over HTTP.
  - **Tests**: `pvfs_fuse::MountGuard` unmounts a test's mount and waits
    before its directory goes (fuser 0.14's `AutoUnmount` drop does not);
    all seven mounting tests use it; the pipeline reports pvfs FUSE mounts
    the tests or smoke left and fails the run.
  Tests: `d211_unreadable_loses`, `d211_remote_probe`,
  `d211_probe_remote_cli`, the range server's unit tests,
  `d211_real_ffprobe` (ignored; run where ffprobe is).

- **A cold read through the view asks the region's holder first (PVOS
  D210).** The view mount's read-through asked the fleet's boxes in pin
  order, from the box that served last — a dial and a `not_found` per box
  asked in vain, and up to the 10 s dial timeout for one that is down. Now
  `view_open` takes the regions of the copies with the served hash, the
  catalogue's `Engine::region_holders()` (the box each region's manifest
  was fetched from, `region_fetched.source`, else the box that claimed its
  provisional head) and opens with `HashCache::open_preferring`: the fetch
  starts at the first holder the fleet announces, then goes round in
  today's order (a stale holder costs one `not_found`). No protocol change.
  Measured on the lab LAN (v1.4-518): a cold read whose holder sorted
  second took 0.23–0.28 s against 0.21–0.22 s holder-first. Tests:
  `d210_holder_first` (pvfs-fuse: a silent box listed before the holder is
  never dialed when the holder is known; an unknown holder keeps today's
  order), `start_at` unit test.

- **Each job's pass says how far it has got; stalls are judged by it (PVOS
  D207).** `pvfs_core::progress::JobProgress` — a pass's own account: when it
  began, when it last moved, files and bytes done, its phase, the files in
  hand. The daemon's stepped watch reports its walk, its hashing (8 MiB at a
  time, `sync::hash_with_manifest_progress`), files taken from rows or
  sidecars, and its steps (`CatalogueCtx.progress`); the receive reports
  each pulled file (`receive::receive_pass_progress`,
  `pull_into_partial_progress`). `serve status` carries it per job
  (`ServeJobWire.progress`, defaulted — no proto bump), the health record
  too (`JobHealth.progress`); `pvfs serve status` prints a line under a
  job with a pass in flight (and `--json` carries it), `pvfs fleet health`
  a note. The stall check: a pass that reports and advances is `running`
  however long it runs; one that has not advanced for 30 min is `stalled`,
  with where it stopped. Jobs that do not report are judged as before.
  Tests: `d207_quiet_pass` (every kind of change through the daemon's
  stepped pass writes exactly its rows — D199's skip-unchanged-rows — and a
  pass's progress while it hashes), `d207_measure` (ignored: the quiet-pass
  measurement), `d207_progress` (a pull's progress; `serve status` over the
  socket), jobs and wire tests.

- **Catalogue rows carry video quality (PVOS D208).** The daemon's `watch`
  measures each video file (`.mkv`, `.mp4`, … — not audio) that has no
  `quality` with ffprobe, on the box whose disk holds it: after the sweep
  and before the publish of the same pass, newest first, one file at a time
  with no lock held, at most 300 files or 60 s a pass (30 s a file, killed
  after), written in short steps that land only on a row still the file
  probed. The measurement travels in the manifest, so the copy ladder
  (served copy, drain, `receive`) compares resolution, HDR, bit depth and
  duration before size wherever both copies are measured. A file that
  changes loses its quality and is measured again. A probe that fails is
  recorded (`"probe":"failed"`), logged and listed by `pvfs region
  quality`, and not repeated until the file changes; the ladder does not
  use it. No ffprobe (PATH, or `PVFS_FFPROBE`): nothing is measured, the
  daemon says so once per region, and the ladder falls back to size as
  before. The CLI's `pvfs scan` does not probe. The ladder's HDR rung now
  needs both copies measured (an unmeasured copy is unknown, not SDR).
  New: `pvfs region quality [region]`.
- **One writer per daemon: jobs share the daemon's engine (PVOS D199).**
  A pvfsd process now writes `index.db` through ONE connection
  (`pvfs_core::Writer`). Serving and every region-model job take its lock
  for one database step at a time and hold it for nothing else: disk
  walks, hashing, network fetches and file moves run with no lock. The
  daemon's own threads no longer meet as "SQLite is busy/locked" or as
  "another pvfs process folding this forest".
  - **The jobs.** `watch` (`watch::run_shared`, `fs::scan_catalogues`): the
    walk, the rows read once at the pass's start, the hashing and the
    manifest outside the writer; each batch (≤250 rows, `fs::STEP_ROWS`),
    each sweep chunk and the snapshot row a step. `catalogue`
    (`catalogue::fetch_pass_db`): claims a step each; an install
    (`fs::install_region_snapshot_db`) computes its delta off the writer and
    writes it in steps of ≤250 rows — the upserts first, the removals
    after, `region_fetched` last — so a first install of 55,000 rows is
    ~220 short steps, not one hold of seconds; another process's commit
    meanwhile is put right in the last
    step (D194's rule). `follow` (`follow::run_shared`): an ingest step
    and a fold step per batch of at most 128 events (`Engine::ingest_log_rows`,
    `Engine::catch_up`; the fold lock is tried, not waited for). `receive`,
    `resolve` and `reclaim` read through a view and write only files. A
    replica's catch-up after routed writes: `advertise::catch_up_db`. None
    opens an engine, so none folds the log to open one. The node-model jobs
    (sync, export, tier, evict) and a node-model binding's scan keep their
    own engines; no fleet box runs them.
  - **Skip unchanged rows.** A catalogue pass writes a row only when its
    kind, size, mtime, changed time or hash differ from the row held
    (folders too). A quiet pass over a 29,500-row region wrote every row;
    now it writes none.
  - **Serving goes first.** A job about to take the writer lets a waiting
    served op go first, so a served write waits for the one step in
    progress at most — and a job thread lowered below serving (D191) is
    raised for each hold: out of the idle disk class always, and to the
    process's nice value where the unit's `LimitNICE=` allows
    (`priority::raise_for_hold`). A rename or folder removal through the view does its
    disk work outside the writer (in order, among themselves) and its rows
    in one step; the ingest publish-retry hashes before it takes the writer.
  - **The writer's commits stay short on a slow disk.** WAL checkpoints
    run on a thread of the daemon's own (`Writer::offload_checkpoints`,
    PASSIVE every 2 s, at the daemon's priority) instead of inside
    whichever step crosses SQLite's 1,000-page mark; and the daemon's
    writer commits `index.db` with `synchronous = NORMAL`
    (`Engine::set_index_sync_normal`) — everything in it is derived (an OS
    crash can cost its last commits; the startup check, the next pass or
    the next fetch puts them back) — and so does a replica's writer with
    its copy of the owner's log (fetched again if lost; a log that went
    back is behind its owner, never ahead). The owner's `log.db`, the
    forest's truth, keeps FULL. On presubuntu's disk (65–80 ms an fsync) these took a
    30,000-row first install from 19.8 s to 1.8 s, and a served write's
    wait behind it from p99 524 ms to 16 ms. The CLI and the mount keep
    SQLite's defaults.
  - **A replica's read pool.** `Engine::open_read_view` works on a replica
    (it needed the forest's device key, which a replica does not have), so
    feederbox's and the NAS's daemons have a read pool for the first time:
    `serve status`, listings and manifests stop waiting on the writer.
  - **Said in the journal.** A hold of the writer over 1 s: `pvfsd: the
    writer was held 2.4 s by catalogue: install c020473f`; a wait over 1 s,
    with who held it; hourly: `pvfsd: the writer, last hour: N hold(s), …
    in all (longest … by …); …; engine opens N, read views N, folds N (N
    events)`. A step that panics no longer takes the writer with it.
  - **The unit's `LimitNICE=+0`** (PVOS fleet template) lets the hold raise
    lower a job's nice value back to the daemon's (nothing above normal):
    under CPU load a fold at nice 10 held the writer 200 ms, 39 ms raised.
  - **The watch's startup pass schedules the settle recheck**, as every
    later pass does: files still being written when a daemon started
    waited for the next change, or the hourly reconcile.

  No wire, schema or protocol change.
- **Small fleet fixes (PVOS D206).**
  - **`pvfs serve enable|disable` bare asks which job.** At a terminal it
    lists the jobs (enabled here or not, and what each does) and takes a
    name or its number. Anywhere else (a script, `--json`, Ansible's pty
    with stderr redirected) it is refused at once, exit 2, naming every job:
    it never waits on stdin (D198). It was clap's "required arguments were
    not provided".
  - **Every notifier event names its forest** (`forest`: the owner's
    registry alias, else its mount directory's name; omitted when neither
    can be read). The chat formats say `PVFS media: …`, ntfy's title `PVFS
    media peer_down`; `summary` is unchanged. Lab and production events
    differed only by address (D142). `pvfs fleet notify --test` names it
    too.
  - **`pvfs region ls` shows a receiving region's tuning**: `receives 2×4`
    (files at once × ranges of each, D144), and `receive_parallel` /
    `receive_streams` in `--json` (`null` where the region does not
    receive here).
  - **A refused region claim reaches the fleet.** The catalogue job puts the
    refusal on its row as a note (`last_error`, D156's attention: the pass
    still completed, `last_ok` is stamped). The owner's health probe reads
    it, so the notifier says it as that box's `job_error` once it stands
    (D151) and clears it (D161), and the page lists it. It was a journal
    line once a minute (D183). `CatalogueReport.claims_refused`' reason now
    starts with the region's short id.

- **The pipeline reaps idle build slots first, and never a roll slot (PVOS
  D201).** The reap was the last stage, so it never ran for a run that
  failed earlier, and presubuntu reached 16 MB free (D182). It now runs
  before the sync (tag `reap`, and under `deploy`): a slot idle for two
  days goes — never this run's, `/opt/pvfs`, a roll slot (`/opt/pvfs-roll*`:
  the build the fleet runs, or rolls back to) or one holding a `.keep` file
  — and the run then stops, listing every slot with its size and last
  change, when `/` has less than `min_free_gb` (15) free. D121's entry
  below says "reaped at report time": that is how it was until this.
  Commit `0ccfd8a`.
- **Each box says its build; a routed write's failure is judged by its type
  (PVOS D200).**
  - **`serve status` carries `build`**, the build the daemon runs
    (`v1.4-495-gc17ae29`; defaulted, so an older daemon's reply still
    decodes). The owner's health job records it per peer in
    `fleet-health.json` — `last.build` for the probe, `build` beside
    `version` for the last one heard, kept while a box is down — and `pvfs
    serve status` and `pvfs fleet health` print it. What a box announces
    (crate version, proto, schema) could not tell two builds apart (D177).
  - **A routed write's failure is classified by type, not words.**
    `retry_routed` read the error's text for eleven words (busy, timeout,
    connection, …). A network failure without one — this client's own idle
    timeout (`Resource temporarily unavailable`, EAGAIN on Linux), an EOF
    inside a frame, a TLS alert, the owner's full disk — came back as a
    refusal, and a refusal that happened to contain one was retried (D182
    worded the fence's refusal around the list). Now: the owner's `busy` is
    waited out on the same connection; a failed connection (`Io`,
    `Protocol`) or the owner's own trouble (`internal`, `io`) fails the
    pass at once, and the next pass dials again — nothing is retried on a
    connection that may be dead or out of step; every other code is a
    refusal of this write, permanent as before, with the same text.
  - **The daemon sends `busy` for a busy database** (`PvfsError::Busy`),
    which went out as `internal`; D182 and D185 already sent `busy` for
    theirs. An older client finds its word in the text, as before.
- **`pvfs serve enable --help` names every job (PVOS D203).** It listed 7 of
  the 11 by hand (`follow|watch|sync|export|tier|evict|reclaim`), missing
  `resolve`, `catalogue`, `health` and `receive`. `serve enable` and `serve
  disable` now take the job from `JOB_NAMES` through clap's possible values:
  `-h` lists the names, `--help` each with one line on what it does
  (`serve::job_summary`, beside `JOB_NAMES`; a job without a line fails a
  test). An unknown name is refused before the command runs — exit 2 as
  before, now with clap's "did you mean" and, under `--json`, clap's plain
  text like every other restricted argument. `load_jobs` still refuses an
  unknown name in the file. Also: `pvfs --help` described `ingest` with
  `ssh`'s text (the paragraph sat above the wrong variant) and `ssh` by its
  examples run into one line; each has its own again, and `ssh`'s examples
  follow its options.
- **The CLI never waits on a question nobody can see, and `forest promote`
  signs for the forest it names (PVOS D198).**
  - **One rule for asking**: only when not `--json` and stdin **and** stderr
    are terminals. Ansible runs commands under a pseudo-terminal, so stdin
    alone passed for a person: D186's promotion hung ~9 minutes on
    `pvfs --json fleet notify 2>/dev/null`, which asked for a webhook URL on
    the redirected stderr. `prompt_line`, the confirmations, promote's and
    `fence`'s questions, the sidecar-upgrade check, the "use the companion's
    identity?" question and `identity replace`'s "Type yes" (which read stdin
    unchecked) all follow it; a person at a terminal is still asked.
    `read_phrase_stdin` still reads a piped phrase and refuses a terminal
    nobody watches.
  - **`pvfs --json fleet notify` with nothing configured prints `null`** — a
    query answers; it does not start a setup.
  - **`forest promote <dir> --via-companion` routes by `<dir>`'s root**, not
    by the directory it runs in: from a home directory over ssh it named no
    key, and a companion holding several phrases (D189) answered with its
    default one. `PVFS_COMPANION_KEY` still wins.
- **The companion keeps its runtime files (PVOS D197).** `serve` writes
  `<socket>.pid` and `<socket>.http` beside its socket in `/tmp`, and macOS's
  `tmp_cleaner` deletes regular files there that have gone three days
  untouched (sockets are left). On 2026-09-26 both were gone while the app
  ran, so a new companion could not take over by pid and pvosd could not
  find the web agent. A keeper thread now looks at both every hour: a file
  still holding what this companion wrote is touched, one that has gone is
  written again (0600, and said in the log), and one another instance has
  rewritten is left to it. Same names, same formats, same place — no reader
  changes (`pvfs_companion::runtime`; `WebAgent::port_file_json`).
- **Before the move: a hung follower says so, a failed pass reaches the log,
  a fenced owner is no route (PVOS D196).**
  - **A hung follower is news.** Since D146 `follow` stamps its row on every
    long-poll, so its `overdue` is a long-poll that never came back. The
    notifier no longer filters it (`notify::overdue_is_news`), and its row
    says *"no word from the source in N min — its long-poll never came back:
    the follower is hung"*. Every other job's `overdue` is still filtered.
  - **A periodic job's failed pass reaches the journal**, once per run of
    failures and when the text changes, and once when a pass completes again
    (`pvfsd: <job> pass failed: …` / `pvfsd: <job> recovered: …`; the same
    rule D157/D159 gave the watch and the follower). The periodic jobs used
    to write only to their status row, so D162's "database or disk is full"
    never reached the NAS's `pvfsd.log`.
  - **A fenced owner is no route.** `replica_route` asks the owner's `serve
    status` when it opens a route. A `fenced` answer (D182) is an error, as
    a failed dial is, so a replica whose bindings are all catalogue regions
    catalogues here with a pending head (D183), instead of failing every pass
    against the refusal. The pending head commits once the fence is lifted
    or the box is re-pointed. The watch's line is now `no route through the
    owner (…) — cataloguing here; …`.
  - **`follow` backs off**: 2 s doubling to 30 s, back to 2 s at the next
    contact that proves it current (it retried every 2 s forever).

  `watch::scan_once` (test hook). No wire, schema or protocol change.
- **Personal forests (PVOS D193; protocol 15).** `pvfs_core::personal`:
  a person's forest genesis, prepared from public keys and parameters the
  SIGNER chooses (a fresh random forest id — so no certificate in it can
  name another forest the phrase roots — the instance id, time and root
  nonce) and signed where the person's keys are: `ForestCreated` (root,
  born bound), the phrase's DEVICE key (`1'/0'`) as the owner device, the
  root folder and its link (owner), and the hosting box's key as a member
  with no grant. `init_signed_genesis` checks every signature in memory,
  then opens the forest — the fold is the full verifying replay — and keeps
  it only if it holds. `SessionCert` / `session_cert_events`: a session key
  admitted as a member of THIS forest and granted `rw` on its root until it
  expires, by the owner key. New daemon call **`CommitSigned`**: events
  their authors signed elsewhere, delivered by any authenticated connection
  and verified exactly as their author's own commit (it grants the
  deliverer nothing). An engine whose own device is a member now checks the
  member rules on its own writes (it could append what every follower would
  refuse).
- **The companion builds what it signs for PVOS (D193).** A relayed
  `sign_in` carries its login fields and the companion computes the digest
  itself — a sign-in digest it did not build is refused, so no server can
  pass off 32 bytes as a login (a PVOS server from before D193 cannot be
  signed into with this companion until it is updated). New relay kinds:
  `personal_genesis` (prompted in the companion's own words; it picks the
  forest id and signs with the root and device keys), `session_cert`
  (silent like a sign-in, and only for a forest this phrase's device key
  bound as its own on the very site asking), `confirm` (a delete or a
  grant, prompted in words written from the structured operation; an
  operation it does not know is refused). The device key is reached only
  from these — no `request_type` maps to it — so the companion's raw-digest
  identity paths can never touch a personal forest.
- **A catalogue head bump writes only what changed (PVOS D194).**
  `Engine::install_region_snapshot` used to delete a fetched region's rows
  and insert the manifest's in one transaction — ≈59,000 row writes on the
  NAS for a two-row bump of mediabox's 29,500-row catalogue, longer than the
  15 s the daemon's other jobs wait for the write lock, so a watch, follow
  or receive pass failed about once a day ("SQLite is busy/locked … (retried
  0x)"). It now reads the rows held without the lock (noting `PRAGMA
  data_version`), takes the lock with `BEGIN IMMEDIATE`, reads again under
  it only if another connection committed in between, and deletes and
  upserts the difference: the rows end exactly as before (a row it does not
  touch keeps its `seen_at`), and a two-row bump of 30,000 rows holds the
  lock 28–68 ms instead of 1.4 s on presubuntu's disk. A manifest listing a
  path twice is refused up front. New `install_region_snapshot_delta`
  returns `SnapshotInstall { rows, added, changed, removed }`; pvfsd logs
  `catalogue <region> at head N: M rows (+a changed c removed r)`, and `pvfs
  region fetch` prints the same (`--json`: `added`, `changed`, `removed`).
  No wire, schema or protocol change.
- **Root certificates bound to their forest (PVOS D192; protocol 14).**
  One phrase is one root key in every forest it roots, and the forest-
  authority events — `DeviceAuthorized`, `DeviceRevoked`, `RootRotated`,
  `RecoveryKeyRegistered`, `RecoveryKeyRevoked`, `MemberTagged` — were
  signed without the forest id: a certificate from one forest verified in
  another with the same root (a member with write access could append it
  and gain a device, a revocation, a rotation, a tag). v2 digests carry the
  forest id (same fields, `:v2:` domains). A forest is unbound (v1 valid, as
  before) or bound (an authority event must be signed for THIS forest; v1
  refused on replay and at commit, history kept). Forests made by this
  build are **born bound** (a v2 genesis, no extra signature); an existing
  forest binds with one new event, `CertificatesBound` (the current root or
  an admin device; the first counts), through `pvfs forest bind-certs` —
  which refuses unless every box the fleet knows announces protocol 14 (an
  older box could not read the forest after). Until a forest binds, this
  build still writes v1: fleet-neutral. `forest tip` and `fleet versions`
  report the binding; new write op `BindCertificates`.
- **One companion, several recovery phrases (PVOS D189; agent protocol
  v4).** `pvfs-companion serve --vault A --vault B …` serves every phrase
  from one process, one socket and one web port: one agent per vault (its
  own lock, prompts, audit log and pairings), behind a router that sends
  each request to the phrase holding the public key its optional top-level
  `key` field names — any of a phrase's root, identity or encryption keys;
  `role`/`request_type` still pick the key inside it. No `key` → the first
  (default) vault, so every client before v4 works unchanged; a key no
  phrase holds → `no_such_key`, never another phrase. `list_keys` lists the
  phrases' public keys. With several, every signing prompt names the phrase
  that would sign. An extra vault that will not open is left out (said), the
  default one must. `pvfs` names the CURRENT root of the forest a command
  runs on (`$PVFS_COMPANION_KEY` overrides, for a new forest) and routes a
  secure unwrap by the wrap's recipient. The macOS app launches its
  companion with every keychain-sealed vault in `~/.config/pvfs`
  (`companion.vault` first). Why: separate forests should not share a
  phrase — one phrase is one root key in every forest, and root
  certificates do not name the forest.
- **What each phrase is used for (PVOS D189).** A companion request may
  name its forest (top-level `forest`: id + label); once it succeeds, the
  answering phrase's ledger (`<vault>.forests.json`) records which of its
  keys that forest used and for what — never used to route or authorize.
  `link_forest` records an older forest by a key a phrase holds (public keys
  only: no unlock, no prompt). `pvfs` names the forest it runs on with every
  companion request. `pvfs-companion keys [--json]` reports each phrase: its
  public keys, the forests that used them, paired servers, web origins, and
  the approvals and root signatures in its audit log; `keys link` asks for
  what it needs. The macOS app's Settings show it, key by key.
- **Serving at the daemon's priority, background below it (PVOS D191).**
  mediabox's unit lowered the whole daemon (nice 10, best-effort 7): its
  serving threads too (writes through the view mount, other boxes' reads of
  files held there). And its disk half did nothing — mq-deadline, the media
  disks' scheduler, ignores the level inside best-effort. Now the job
  supervisor (`pvfsd-jobs`) lowers itself before it spawns anything, so
  every pass and the trash step start below serving, and the hashing pool
  is built at start with lowered workers (`pvfsd-hash-<n>`; a write's
  commit hashes there too): nice +10 and the idle disk class, which
  mq-deadline honours (its 10 s aging keeps an idle request from waiting
  forever). The listeners and their connection threads keep the unit's
  priority. Job threads are named `pvfsd-<job>`. `PVFSD_BACKGROUND` sets
  the step (1–19; the NAS takes 19, D88's level — its start script's
  `renice` had moved only the main thread) or `normal` for none.
- **Before an owner holds regions on a busy box (PVOS D188).** Found reading
  the code for mediabox's move to owner:
  - **A mount left on an older build no longer passes the roll's check.** A
    running mount reads the catalogue at its own schema; moving the
    catalogue in place still leaves it behind, because every fresh open it
    makes (each read it fetches from another box, each delete or rename it
    routes there) refuses the newer schema. `versions --json` now says such
    a mount does not survive, so a roll stops on a Plex box unless told to
    interrupt the mount (PVOS D181's rule) instead of leaving it unable to
    open anything held elsewhere until it restarts.
  - **A mount's endpoint lookup opens a read view and remembers it for a
    minute** (`hash_cache::announced_sources`). It opened the forest in full
    for every such read — the writer lock, the startup check, the
    clean-shutdown flip; on an owner, the writer path from a second process.
    A forest a read view can't open (a replica) still takes the full open.
  - **Read-only commands read through a read view while the daemon runs**:
    `info`, `view ls|conflicts`, `region ls`, `region entries`. A full open
    commits region heads on close on an owner that holds regions; a status
    page polling these every minute on the owner no longer writes to the
    log. `Engine::close` on a read view is a no-op (it used to fail).
  - **A retired box's endpoint is no longer dialed.** `catalog_endpoints`
    skips a record written by a device key the forest has revoked — a
    promotion revokes the old owner's — so no box dials it each pass and the
    owner stops paging "peer down" for it. A follower's record (written with
    its member key) is never hidden by this; a re-announce rewrites a hidden
    record under the box's current key. The owner's health record drops a
    peer that is no longer announced (it listed it "not answering" forever),
    and the health job reads through a read view (it only reads; its full
    open committed an owner's region heads on every poll).
  - `serve status --json` carries `mounts` and `backup`, as the daemon sends
    them.
- **Every request over the network cost about half a second (PVOS D187).**
  `write_msg` wrote a frame as two writes — its length, then its body — so
  over TLS each frame left as two records in two TCP segments, and Nagle held
  the second until the peer's delayed ACK: a stall on the request and
  another on the reply. On the lab a folder listing took 495 ms and a connect
  2.1 s, where the Unix socket answered at once. A frame (control and data)
  is now one write, and both ends set `TCP_NODELAY` (`pvfs_client`'s dial,
  the daemon's TLS accept): the same listing takes one round trip (138 ms
  over a 137 ms path; 316 ms with only the client fixed). On a LAN the stalls
  were the delayed-ACK timer, 40–200 ms each — every small request a view
  mount makes of a remote holder paid two. The bytes on the wire are
  unchanged.
- **The merged view over the socket (PVOS D187, protocol 13).** Three read
  ops, answered from the read pool: `ViewLs { dir }` (the merged view's
  children of a directory), `ViewEntry { rel_path }` and `CatalogueStatus`
  (`region ls`). Member-gated like `ServeStatus`, and every answer is judged
  only over the catalogue regions the caller may read (`r`): a path held only
  where it may not read is not listed, and a path held in several regions
  shows the copies it may read, re-judged by the view's admission rule. An
  application — PVOS's Media app — reads a forest through its daemon under
  the forest's ACLs instead of opening its store (which would need the
  owner's device key). Client: `view_ls`, `view_entry`, `catalogue_status`,
  `VIEW_PROTO`. Additive; compatible-with stays 3.
- **An owner that holds its own regions (PVOS D185).** A holder promoted to
  owner (D182) keeps its `bindings.local`, and it now keeps its library too:
  `bindings_for` marks those rows as this device's, as `bindings()` and
  `binding_for()` always did, so the owner-side checks that filter on
  `bound_by == me` see them. Before, a promoted holder served none of its own
  bytes (`CatHash` said "no bytes for that hash"; its own view could not read
  its disks), refused view trashes and renames there, left its disks out of
  `stores`, and `pvfs scan <region>` called its region "bound on another
  machine". Unbinding a root the log never held (a local one) on an owner
  edits `bindings.local` instead of logging an unbind that changed nothing.
  An owner that has just started opens its listener at once and serves
  reads; only **routed writes** wait for its first health pass (D182's fence,
  still bounded at 30 s), answered `busy` meanwhile — the whole listener used
  to wait. `forest tip` prints the forest's **current** root (the last
  `RootRotated`'s, else genesis's) — the key a companion must hold to
  promote.
- **Stream mode kept the readahead ahead only after reads it could serve at
  once (D181 fix).** The window was armed in one place — `poll_range`'s
  covered branch — so a read that had to WAIT left none behind it. Such a
  read carried its readahead as the `ahead` extension of its own fetch job,
  and `wait_range` drops its demand the moment its own pieces land: when a
  reader caught the prefetcher up, the demand was satisfied by a job already
  in flight, the worker came back to no demand and a window it had just
  filled, and it idled with the keep-ahead short. A playing file re-armed
  itself at the next read it could serve at once, so the cost was a stream
  running without its cushion, not a stall; nothing re-armed it after the
  last read. Both paths now arm it (`HashFetch::arm_readahead`). This is what
  failed the D181 stream-mode test intermittently — 8 runs in 20 on the build
  host, about one CI run in three, since D181 shipped; raising that test's
  budget to 60 s on 2026-09-22 treated a stall as slowness, and it is back
  to 10 s.

- **The owner out of the daily path (PVOS D183).** A catalogue region's head
  was already signed by the box that owns the region; it now also travels
  **box to box**, so an owner outage no longer freezes cataloguing, the heads
  between boxes, or anything downstream of them. A replica whose bindings are
  all catalogue regions scans with no route (`OwnerAway`): its rows are local
  and its head is **published here, pending** (`region ls` `pending`), then
  committed through the existing `CommitRegionHead` by the next routed watch
  pass or the `catalogue` job — the newest per region, so an outage costs the
  log one row per region. New read op **`RegionClaims`** (proto 12,
  member-gated): a replica's daemon answers with a fresh `SubRegionHead` for
  each region it binds and has published, signed by its client identity. The
  `catalogue` job asks every endpoint and takes each claim the fold's own rule
  accepts (signature; catalogue region; active, unrevoked author with admin
  on it; a seq past what is held) as a **provisional head**
  (`region_provisional`, schema v20, in place); a second hash at a held seq is
  refused. `catalogue_status`, the fetch pass and `install_region_snapshot`
  read max(committed, provisional); the fold of a committed head at or past a
  provisional one deletes it; `region ls` shows `provisional` and
  `committed`. A head the owner already holds settles instead of failing the
  pass, and a local head the log names differently at the same seq is
  published past. Client dials time out after 10 s (a powered-off host cost
  every dial the kernel's ~2 min of SYN retries). An outage still stops what
  is the owner's own: admin changes, revocations, NAS supervision, the health
  observer and the HA feed. Lab: `deploy/d183-heads-pair.sh`.

- **The owner can be lost (PVOS D182).** A follower only ever copies the
  owner, so a follower holding more of the log than the owner proves it
  stale — restored from an older copy, or replaced by a promotion. Such an
  owner now **fences itself** and writes nothing: every routed write carries
  the replica's tip (`PrepareWrite.tip`), the health job reads every peer's
  (`serve status` `log`), and an owner's daemon hears its peers (its first
  health pass, 30 s at most) before it listens. The fence is a file in the
  data dir, checked by `Engine::append_durable_with` (the one choke point),
  shown in `serve status` (`fenced`) and `pvfs forest fence` (which lifts
  it, asked), told once as `owner_fenced` (critical) — a fenced owner says
  nothing else but its check-in. Only a key holding admin on the forest
  root can fence the owner by its word (D182 §3.3a) — a routed write's
  author, or the key that announced a probed endpoint: such a key could
  revoke the owner's device outright, so believing it adds no authority; a
  longer log claimed by anyone else is refused, not believed (the write is
  not written; the health record says `ahead-unproven`). A follower on
  another branch is refused
  and told as `peer_diverged`; the owner keeps writing. `follow` calls a
  source BEHIND its replica an error instead of "up to date". Promotion is
  one append (`Engine::promote_with_root_signer`; D128's two could
  half-finish), by phrase or **`pvfs forest promote --via-companion`**
  (a device key made on the box, the root signatures from the companion,
  each approved at its prompt), with defaults that survive a second move
  (the next index never used; revoke every other live owner device). New:
  `pvfs forest tip` (read-only, beside a running daemon), `pvfs forest
  backup` (a dated copy by `VACUUM INTO`, verified by a full replay, pruned
  by `--keep`; `backup` in `serve status`) and `pvfs forest restore`.
  A second `pvfsd` for a forest whose socket already answers refuses to
  start instead of deleting it and taking its place (the socket is
  `<dir>/<forest_id>.sock`, so a standby beside a holder's replica on one box
  needs its own `PVFS_SOCKET_DIR`), and it refuses before sweeping sync tmp
  files. Notify labels resolve by `host:port` before host. `ServeJobs` boxes `jobs`
  and `capacity` (same JSON) to stay under clippy's 128 bytes. Wire: two
  defaulted fields and one optional request field — no proto bump. Lab:
  `deploy/d182-owner-pair.sh`; doc 28 rewritten around PVOS `promote.sh`.

- **The view's stream mode, and rolling under it (PVOS D181).** `pvfs mount
  --view --cache-mode stream` keeps nothing — Plex on the LAN reads the view
  and Chris wants no cache: no background completion, the readahead kept
  filled ahead of each sequential reader, pieces more than 64 MiB behind the
  rearmost reader punched out of the partial, the partial deleted at the last
  close; small files still verified before their last piece is served, and
  not kept. `keep` (D165) stays the default. For a box that leaves its mount
  on an older build across a roll (restarting a mount ends every stream open
  through it; restarting the daemon does not): `MOUNT_COMPAT` (bump for a
  change a running older mount cannot follow), `projection::projection_plan`
  (in place, rebuild, newer — the decision the open will make, the ladder and
  its gate now shared through `migration_step` / `rebuild_reason`), a status
  file per running view mount (`<data>/mounts/`), a once-a-minute check that
  says when the catalogue is newer than the mount reads, and `pvfs versions`
  reporting the build, the compat level, the plan and each running mount with
  `survives` / `why_not`. Lab: `deploy/d130-view-pair.sh` stage E2b (600 MiB
  in stream mode, at most 80 MiB on disk, gone at close) and
  `deploy/d181-backlog-pair.sh` (a daemon catches up 600 events and a
  3,004-row catalogue beside a streaming mount in 1.8 s). No wire change.
- **Doc 31, common issues and fixes (PVOS D168).** An operations page: what
  each issue looks like, why, and the fix, with the fleet as the worked
  example — first the duplicate cleanup (plan, the holds a folder-and-number
  key needs, canary, `trash put --from`, freeing the space, verified moves,
  the arrs' rescan), then a show misfiled in another's folder, two editions
  of a film (Plex's `{edition-…}`), the watch starved by writes under a
  region root, the arrs' recycle bin and download clients on the union.
- **`pvfs trash put`: one region's copy to its trash (PVOS D168).** The
  duplicate cleanup keeps the better of two copies, and where two regions
  hold different bytes at the same path a delete through the view — which
  asks every holder (D169) — would trash the one being kept. `pvfs trash put
  <PATH> --region <ID>` sends D169's `TrashPath` for that region's copy
  alone: here when this box catalogues the region from its own disk, else to
  the box that answers for it; write-gated, and only while the copy is still
  the file with the catalogue's hash (or `--hash`). Bare at a terminal it
  asks for the path and, if more than one region has a file there, which.
  `--from FILE|-` takes a list (`region<TAB>path<TAB>hash`, full ids): every
  line is checked before anything moves, each gets its own answer —
  `trashed`, `already gone`, `refused` and why — over one connection per
  box, the list goes on past a refusal, and the exit status is non-zero (2, the
  CLI's invalid-input code) if any was refused. `--json` too. `hash_cache::trash_each` is the list's client half;
  D169's `ask_holders` gained a per-item core (`ask_holder`) for it, its own
  behaviour unchanged. No wire or daemon change.
- **A stream of writes under a region root no longer holds the watch off
  (PVOS D180).** The watch started a pass only after 2 s with no inotify
  event, and every event under the root counted, including writes to a
  `.pvfs-` folder the walk never looks at. rclone copying into mediabox's
  `/mnt/local/Media/.pvfs-d168-incoming/` held every pass off from about
  10:50 to 11:25 AM EDT on 2026-09-21 (46 files placed and 13 trashed, none
  taken until 11:25); the NAS's
  `receive` writes its partials into `<library>/.pvfs-incoming/` for as long
  as a pull runs, so its catalogue could lag an hour, the reconcile. Now the
  handler drops an event whose every path is one the walk passes over
  (`is_own_name`, `is_litter_name` — which also ends the extra pass each
  pass's own sidecars set off), and the debounce has a ceiling: once the
  first unanswered event is 30 s old a pass starts, whatever keeps coming.
  `watch::run` takes `ceiling_ms`; pvfsd passes 30 s, `pvfs serve watch
  --ceiling-ms` defaults to it.
- **One free-space figure per disk when choosing where to receive (PVOS
  D179).** GitHub CI failed twice on `d133_receive_plan`'s tie test while our
  pipeline passed it: `receiving_roots()` measured free space once per region,
  and two regions on one disk measured a moment apart need not agree while
  anything writes there — the order of the two was decided by what was
  written in between. It now measures each filesystem once (by device), so
  regions sharing a disk tie by construction and the region id decides. The
  test gained a writer that grows and shrinks a file on the same disk while
  `receiving_roots()` runs 2,000 times: the old code put the wrong region
  first 12 times on disk and 207 on tmpfs; the new code never.
- **Every filesystem a box stores on (PVOS D178).** `serve status` — and so
  the health record a peer answers with — gains `stores`: the data dir's
  filesystem first, then each filesystem under the roots of the catalogue
  regions the box catalogues from its own disk, once per device, with the
  regions on it (`Engine::store_filesystems`). `capacity` (D131) measured the
  data dir's alone, and a holder's files are rarely there: the forest page
  said mediabox had 339 GB free while both its stores were 98 % full, and it
  gave the NAS one of its two volumes. Additive and defaulted (an older
  daemon answers without `stores`); `pvfs serve status` and `pvfs fleet
  health` print them. `ServeJobs`' `trash` and `stores` are boxed so
  `ServerMsg` stays under clippy's `result_large_err` size — the JSON is
  unchanged.
- **Every box purges its trash, whatever jobs it runs (PVOS D176).** A
  catalogue region's trash was purged by retention only inside the `receive`
  and `resolve` job bodies — also the only thing that filled `serve
  status`'s `trash` (D148). mediabox runs neither: its trash (9.7 GB on
  2026-09-18, from deletes through the view since D169 and D149's orphaned
  sidecars; both disks 98 % full) was never purged, and D148's page warning
  (*a bucket older than retention + 1 day: the purge is not running*) could
  never fire for a box that reported no trash. The job runner now has a
  trash step beside its heads tick: once at start and every five minutes it
  asks the daemon's read pool which catalogue regions this box holds
  (`Engine::trash_roots`, no engine opened, nothing folded) and purges each
  by its retention on its own thread (`sync::purge_region`), recording what
  each keeps. A region that fails is said once per run (D157) and does not
  cost the others theirs. `receive` and `resolve` purge exactly as before;
  a lock keeps their purge and the step's from overlapping (two purges race
  on `remove_dir_all`, and the loser would fail a `resolve` pass).
  `PVFS_TRASH_EVERY_MS` shortens the interval for tests. No wire change.
  `pvfsd/tests/d176_trash_everywhere.rs` runs a box with two catalogue
  regions and no jobs, under a held fold lock and writer.
- **The receive plan comes from the running daemon (PVOS D174).** The
  owner's dashboard collector (PVOS D143) asked the NAS for the mover's plan
  every minute by running `pvfs view receive --dry-run` inside the production
  replica: a second process opening the forest and folding its log under the
  fold lock, once a minute. On a replica that fold lands in the window
  between the follow job's append and its own fold, and the daemon's next
  open waits behind it — D173's standing candidate. New wire op
  `ReceivePlan` (**proto 10 → 11**, additive; compatible-with stays 3),
  answered from the daemon's read pool — no engine opened, nothing folded,
  the writer not waited on — and member-gated like `ServeStatus`. New CLI
  `pvfs serve receive-plan`: the dry run's JSON shape, each file with its
  `size` and `replaces`; with no daemon it fails as `serve status` does and
  never falls back to opening the forest. `view receive --dry-run` is
  unchanged. `pvfsd/tests/d174_receive_plan.rs` asks for the plan with the
  cache behind the log, the fold lock held and the writer held, and checks
  that nothing folded.
- **A projection replay must not cost a box its catalogue (D173).** Three
  hours after the v1.4-385 roll the NAS's watch job reported `head seq 1
  does not advance 0a16d644… (at 6)`. Another `pvfs` process had held its
  fold lock for longer than the five-second budget, and `startup_check`'s
  rule for a failed tail fold (D69: the cache is lying — replay) threw the
  projection away. Since D125 the projection also holds what the log cannot
  give back: `region_entries`, `region_snapshots`, `region_fetched`. The
  replay emptied them; library-ext was re-walked and then published from 1
  against an attested 6, the owner refused it, the watch backed off and the
  library never got its re-walk — 0 rows, so a file the NAS holds could not
  be found by hash, and every read-through of a library file not already
  cached failed. Three rules now, each enough on its own: a publish counts
  up from the head the LOG attests (and, with no record of its own, judges
  "unchanged" against the attested hash); a busy fold lock is retried for a
  minute and then fails the open — it is never a reason to replay; and a
  replay carries the three catalogue tables across
  (`CARRIED_ACROSS_A_REBUILD`).
- **The view's lookups come from an index (D171).** Krusader took 24–36 s to
  open `Movies` through feederbox's mount: the listing itself was 0.5 s, and
  then every one of its 2,452 `stat`s took 13 ms. `region_entries` is keyed
  `(region_id, rel_path)`, and the view asks by **path across every region**
  — `EXPLAIN QUERY PLAN` said `SCAN e`: all 72k rows on the box, per lookup;
  and again by **hash** on every `open` (`local_path_for_hash`). Every `stat`
  an arr or Plex makes paid it too, on fuser's one session thread. Two
  indexes — `idx_region_entries_path (rel_path, region_id)` and
  `idx_region_entries_hash (content_hash)` — and a listing that is a RANGE
  over the first (`"dir/" ≤ path < "dir0"`) instead of `substr(…) = ?` over
  every row. Schema v18 → v19, migrated **in place** (CREATE INDEX): the rows
  come from disks and fetched manifests, not the log, so a replay could not
  bring them back. `tests/d171_view_index.rs` holds the three queries to
  their indexes by their query plans, so a rewording that scans again fails
  there and not as a slow `ls` on a full library.
- **Renames and folders through the view (D170).** D169 closed the one hole
  that was failing in front of us; an arr does more to a library than delete.
  "Rename files" is a verified move — `rename`, then the target must exist
  with the source's size, within the second; a changed series path is one
  `rename` of a folder; a rename into a season folder the arr just made finds
  that folder on `/mnt/local` only, so mergerfs first clones the path onto
  our branch (`mkdir`); "delete empty folders" is `rmdir`. All of it was
  `EROFS`/`ENOSYS` in the view, though the node mount has had it since D71 W2
  because Chris asked for exactly this. Now the box that **holds** the files
  does it on its own disk: `Engine::rename_region_path` (a file only if it is
  still the one that was seen — hash and size; a folder with everything
  under it; nothing may be renamed to a name the catalogue passes over) and
  `Engine::remove_region_dir` (only when nothing of the operator's is left;
  PVFS's own names and litter go to the trash); `RenamePath` / `RemoveDir`
  on the wire (proto 9 → 10, additive, **write-gated** on the region). The
  holder's **rows follow the rename at once** — bytes are found by hash → row
  → path, so a row left at the old name was a file nobody could open until a
  pass had run — and a file's sidecar moves with it (one is written if it had
  none), so the next pass does not read a 40 GB film to learn a hash it knew.
  The mount **remembers** what it did until the catalogue agrees
  (`pvfs-fuse/src/overlay.rs`): rows a fetched snapshot still lists at the old
  path show at the new one, a folder made here exists here, a folder removed
  here is gone here; moves compose (A→B→C, a file inside a renamed folder),
  the inode table follows, and it all lapses when every region touched has
  published since and nothing is left at the old path — or after ten minutes.
  A file renamed **onto** another replaces it softly (the target goes to the
  trash first). `chmod`/`chown`/`touch` are accepted and ignored, as the
  rclone mount did; a truncate, a create and a write-open are still refused —
  new bytes arrive through `/mnt/local` and `receive`. D169's delete learned
  the same no-row rule (a file renamed a moment ago and then deleted answered
  "gone" and stayed on disk). A folder **made** through the mount remembers
  which regions' holders have it for real by now — a rename into it makes the
  holder create it — so an `rmdir` before the next head still reaches them
  (the lab fleet: a season folder made, filled, emptied and removed within
  the minute stayed on the store's disk).
- **`pvfs trash restore` brings back every identical copy (D170).** One
  delete through the view trashes the same file in every region that held
  it, so a restore brings every one of those back — matched by **hash** (the
  trashed sidecar's; else the bytes are read) — and leaves alone, and names,
  a region whose trashed file at that path is a *different* file
  (`sync::restore_identical`). D169's "which region?" prompt is gone:
  nothing about it was a question. `--region` still restores exactly one.
- **A delete through the view is a trip to the holder's trash (D169).** The
  view mount's namespace was read-only (D130), and an arr importing an
  upgrade removes the existing file first: Sonarr moves it to its recycle
  bin (another filesystem — a copy, then a delete of the original), Radarr
  deletes it. Ninety minutes after the arrs' union became `/mnt/local` + the
  view, Sonarr was logging "Unable to move … to the recycling bin" once a
  minute for three queued upgrades (`EROFS`). The node mount's own comment
  had called this "the gap that made the design a REGRESSION against the
  rclone mounts it replaces" (D71 W2); the view never got the fix. Now
  `unlink` in the view asks **the box that holds the file** to move its copy
  into that region's trash — soft, kept for the region's retention,
  restorable with `pvfs trash restore` (rclone's delete was for ever).
  `Engine::trash_region_path` (only a file, only in a region this box
  catalogues from its own disk, only when the row's hash and the file's
  size are what the caller saw); `ClientMsg::TrashPath` → `ServerMsg::
  Trashed` (**proto 8 → 9**, additive), write-gated on the region,
  `not_found` when the box does not hold the region (ask the next),
  `conflict` when the file changed; `hash_cache::trash_elsewhere` asks the
  fleet box by box, off the mount's session thread. Every copy the view
  shows at the path goes (a copy left on another disk would leave the path
  there and the arr would refuse to write over it). The path is tombstoned
  in the mount — hidden at once, by the hashes that were trashed, because
  the arr creates the new file at the same path within the second and the
  catalogue takes a pass and a fetch to agree; a new file there (another
  hash) shows; it lapses when the catalogue no longer lists the path, when
  the holder has published again and still lists it (it was restored), or
  after ten minutes. `rename` and `rmdir` stay `EROFS`. `pvfs trash restore`,
  when more than one region on the box has the path: asks at a terminal
  (an id prefix, or `all`), and tells a script to pass `--region` naming
  them — D167's prompt gave a script an unreadable error (the smoke suite
  found it).
  `pvfs-core/tests/d169_trash_region_path.rs`,
  `pvfsd/tests/d169_trash_path.rs`, `pvfs-fuse/tests/d169_view_unlink.rs`.

- **`pvfs trash ls` and `pvfs trash restore` (D167).** Every automated
  deletion moves the file aside (`<root>/.pvfs-trash/<day>/<its path>`,
  sidecar beside it) — "recoverable by moving it back", by hand, and
  browsable only because rclone showed the folder. Nothing listed it and
  nothing put a file back. `pvfs trash ls [PATH] [--json]`: per bound folder
  on this box, each trashed file with the day (as a date), the days until
  the purge takes it, its size and its path as it was. `pvfs trash restore
  <PATH> [--from DAY] [--region ID]`: a file, or every file under a folder,
  back where it was with its sidecar — never over a file that is there (it
  is reported and stays in the trash), the newest day unless `--from` names
  one; bare at a terminal it lists and asks. A restored file is catalogued
  at the region's next pass; in a draining region the command says it will
  be drained again. Core: `sync::list_trash`, `sync::restore_from_trash`,
  `Engine::region_trash_lists`. `pvfs-core/tests/d167_trash.rs`.

- **The operator's dotfiles are content (D166).** `walk_disk` skipped every
  name that starts with a dot. That was how PVFS's own bookkeeping stayed out
  of the catalogue (doc 24 §2: "make the sidecar a dotfile so no walker has
  to know anything") — and it took the operator's dot-names with it: 153
  `.plexmatch` files on the fleet, the file that tells Plex which show a
  folder holds, and a `.htaccess`. Found when the merged view was compared
  with the rclone union it replaces (PVOS D164 §6); harmless to Sonarr and
  Radarr, not to Plex once it reads through PVFS. Now a dot-name is content
  like any other, with two exceptions, both in `pvfs_core::sync`:
  `is_own_name` — a forest's `.pvfs`, anything `.pvfs-*` (the markers, the
  trash, `.pvfs-incoming`), a sidecar (`.X.manifest`, V1's `X.manifest`;
  files only), and a dot-named file still being written (`.<id>.tmp`,
  `.<id>.swarmpart`, `.<id>.progress`, `.X.partial`); and `is_litter_name` —
  what an OS or a NAS leaves in every folder it touches (`.DS_Store`, `._*`,
  `.AppleDouble`, `.Trash-*`, the QNAP indexer's `.@__thumb` — 346 folders and
  792 MB of thumbnails on one fleet disk — `.fuse_hidden*`, `.nfs*`, …).
  Litter is dot-names only, so nothing catalogued before stops being
  catalogued, and `skipped` counts what it counted. A dotfile's sidecar is
  `..plexmatch.manifest` — ours, so the D87 chain cannot start. The walker
  is now the ONE place that knows our names, the test holds every function
  that makes one to it, and **new bookkeeping takes the `.pvfs-` prefix**.
  `pvfs-core/tests/d166_operator_dotfiles.rs`.

- **The view mount reads through by the piece, keeps what is consumed, and
  is bounded (D165).** A file the mount did not hold got a whole-file,
  sequential fetch from byte 0 at `open`, one thread per file, that nothing
  stopped and nothing evicted; `read` waited up to 120 s for its range *on
  fuser's one session thread*, so one read waiting on the WAN froze `ls`,
  `stat` and every other read. A media scan reads 40 KB of each file —
  Sonarr's ffprobe, traced: 38.5 KB of head and the last 1.1 KB — so every
  probe cost a whole file, and the tail read ended in EIO. New
  `pvfs_client::hash_cache`: the file is a map of 1 MiB pieces over a
  sparse `.partial`; a read registers the pieces it covers and the worker
  asks a holder for exactly the missing run (`CatHash` was ranged all
  along). Readahead only once a reader is sequential (1 → 8 MiB). A reader
  that has consumed 64 MiB in a row is a consumer: the file is completed in
  the background in 32 MiB bursts, hashed as a stream (it used to be read
  whole into memory), and only a match is kept — a mismatch is refused, the
  box named and skipped, the next asked; files up to 64 MiB are verified
  before their last piece is served. The last handle closing ends a probe's
  fetch at once and a completing one after 60 s, unless it is three quarters
  through. At most 4 requests on the network, a waiting read before a
  background burst; connections pooled per holder. A read that must wait
  does so off the session thread. The store is bounded: `pvfs mount --view
  --cache-max 500G --cache-age 1d` (those are the defaults), least recently
  read first — an entry's mtime is its last open — never an open file or a
  live fetch; leftover partials are swept at mount start. A request no box
  will serve fails the reads that were waiting and keeps the pieces.
  `pvfs-client/src/hash_cache.rs` (unit tests), `pvfsd/tests/
  d165_hash_cache.rs`, `pvfs-fuse/tests/d165_view_read_through.rs`.

- **One box, one client identity, however many ask at once (D163).**
  `client_identity_mnemonic` made the phrase with a check, a `File::create`
  and a write. Two callers that found no file — the CLI beside a daemon job
  on a box's first start; two tests of one binary — each wrote a phrase, the
  second `create` truncated the first's, and a write could land on top of
  the other's (a 25-word file). The loser kept a phrase the file no longer
  held, so its next dial was a stranger's: "forbidden: log replication
  requires admin rights on the forest root" from a box that had authorized
  the file's phrase (GitHub CI, `serve_jobs`, twice on 2026-09-16; the
  tests were the two callers, not the fleet — every box made its phrase at
  enrollment). Now each writer fills a private file (0600, fsync) and links
  it into place; the link fails for the second, which reads the first's.
  Nobody reads a phrase mid-write and nobody keeps one the file does not
  hold. `pvfs-core/tests/d163_identity_race.rs`; `serve_jobs.rs` makes the
  identity inside its once. *Follow-up the same night:* the private file
  was named by pid and nanosecond, and on GitHub's runner two of the
  test's sixteen callers drew the same nanosecond, so one `create_new`
  failed "File exists". A process-wide counter names it now.

- **SQLite's scratch files go beside the database (D162).** A sort too big
  for the page cache spills to a temp file, which SQLite put in `/var/tmp` or
  `/tmp`. On the QNAP that is a 64 MB RAM disk with about 25 MB free, and on
  2026-09-16, once mediabox-local's first pass landed and the merged view
  grew from about 43,000 rows to 71,000, the NAS's receive job failed
  "database error during view conflicts: database or disk is full" on and
  off. The first engine a process opens (either `open_connection`) now sets
  SQLite's process-wide `temp_store_directory` to `<data_dir>/sqlite-tmp`, on
  the catalogue's own disk. An operator's `SQLITE_TMPDIR` is left alone, and
  a directory that cannot be made leaves SQLite's own choice.

- **An alert that reached the phone says when it has cleared (D161).** The
  owner's notifier had no event for a job error going away: `job_errors`
  dropped its memory on the first clean pass, silently, and the same text
  back a minute later was a new alert. A sent job error that is gone for
  `JOB_ERROR_AFTER_MS` (210 s, the wait an error has before it is said) now
  sends `job_error_cleared` (info), with `detail` = the text last sent,
  `since_ms` = the episode's first sighting and a new `until_ms` = its first
  clean pass, and the summary "On the NAS, the receive job's error has
  cleared, after 12 minutes. It had reported: …". Back inside the wait it is
  one episode: nothing is said either way. An error that cleared before it
  was sent is still never mentioned. `notify-state.json` gains
  `reported_since_ms` and `job_errors_gone` (both default, so an old file
  loads); `until_ms` is omitted from every other event's payload. Home
  Assistant's automation sends it, and `peer_up`, titled ✅ (PVOS D161).

- **A log region's deletions ask the disk whether a file is gone (D160).**
  The deletion step of a log-region pass (`scan_binding` step 3) retired
  each tracked location the walk had not listed if `Path::exists` was
  false. That is false on any stat error. A directory that stopped being
  searchable is skipped by the walk as `unreadable`, so the next complete
  pass retired every location beneath it. The pass after the directory
  became searchable again added them back, which cost a remove/add pair in
  the log for each file. Step 3 now asks D156's `gone_from_disk`, as the
  catalogue sweep does: only ENOENT and ENOTDIR mean gone. Any other stat
  error leaves the location, its node and its `scan_state` row alone. The
  root marker still covers an unmount.

- **Follow's failed sessions and a continuous job's exits reach the journal
  (D159).** D157 gave a failed watch pass a journal line. Two paths still
  reached only the status row, and now each logs too:
  - The follow job's `FollowEvent::Retrying` (a dial refused, a connection
    lost, a busy store), which the follower retries every 2 s, logs `pvfsd:
    follow failed: <reason>; retrying`. The first `CaughtUp` or `UpToDate`
    after a run logs `pvfsd: follow recovered: current with its source after
    N failed attempt(s) over <time>`.
  - A `follow` or `watch` thread that exits with an error (not a replica,
    `serve.lock` held, a watch it cannot register) logs `pvfsd: <job>
    exited: <error>; restarting it in 60 s`. The supervisor restarts it after
    60 s. Once a restarted thread is through its setup (watch: its watches
    registered; follow: its first event), it logs `pvfsd: <job> recovered:
    running again after N exit(s) over <time>`.

  Both follow D157's rule: a line when a run starts, and again only when the
  text changes. D157's memory is generalised to one run per fault (a watch
  pass, a follow session, an exit) rather than per job. A watch's startup
  pass completes before the setup that can fail, so a run per job would log
  `recovered` and `exited` at every restart. The status rows are unchanged.

- **One unreadable new file does not stop a log-region pass (D158).**
  `ingest_file` hashed a brand-new file with `?`. The read's error is `Io`,
  which `is_transient` calls transient, so one file's read error ended the
  pass. A file that failed every time stopped every pass at the same place,
  before the pass's deletions. D156's classifier, renamed `read_fault`, now
  judges that read and only that read:
  - A file gone since the walk (ENOENT, ENOTDIR) is skipped, with a journal
    line. The next pass's walk will not list it.
  - A fault of the file itself (EACCES, EIO, …) is quarantined the way D71
    W4 quarantines a file the catalog refuses. It is skipped, counted in
    `needs_attention` and named in `quarantined`. Nothing is written for it,
    so every pass tries it again. D156's reporting already carries it
    (`WatchEvent::NeedsAttention`, pvfsd's note, `pvfs scan`).
  - Anything else (ENOTCONN, ESTALE, EMFILE, any errno not named) fails the
    pass as before.

  `ingest_file`'s other errors come from the writes: this engine's database,
  or the owner's through a routed writer. `is_transient` judges them as
  before, whatever their errno. The root marker is verified again before the
  pass's deletions. A volume unmounted mid-pass now fails the pass, where it
  would have retired every tracked location the walk had held back. D156's
  seam, `Engine::on_catalogue_read`, is called before this read too.

- **A failed watch pass reaches the journal (D157).** pvfsd's watch job took
  a failed pass (`WatchEvent::ScanError`) into its status row (`backoff`,
  `last_error`) and wrote nothing to the journal. In D156's lab rehearsal a
  pass failed on every retry with an EIO, and `journalctl` showed nothing;
  only `pvfs serve status` did. It now logs `pvfsd: watch pass failed:
  <error>; retrying`, once when a run of failures starts and again only when
  the text changes, as D151's notifier does for job errors. So a pass
  retrying in backoff (5 s doubling to 300 s) does not flood the journal.
  The first completed pass after a run logs `pvfsd: watch recovered: a pass
  completed after N failed pass(es) over <time>`. A stopped pass (D154) ends
  nothing. The row, and so `serve status`, the HA page and the notifier, is
  unchanged.

- **One unreadable file does not stop a catalogue pass (D156).**
  `scan_region_catalogue` hashed each file with `?`, so one file's read error
  ended the pass. A file that failed every time stopped every pass at the
  same place. The sweep and the head wait for a complete pass (D154), so
  that region would never have published again. A failed read is now
  classified by its errno (`catalogue_read_fault`, `read_fault` since
  D158), because `is_transient` calls every I/O error transient:
  - A file gone since the walk (ENOENT, ENOTDIR) is left to the sweep. The
    NAS's old forest logged two renamed episodes that way.
  - A fault of the file itself (EACCES, EIO, ENODATA, EBADMSG, EUCLEAN, …)
    is quarantined. It is skipped, counted in `needs_attention` and named in
    `quarantined`, and its prior row stays as the last read left it. The pass
    carries on, sweeps and publishes: a quarantine does not hold back the
    head.
  - Anything else (ENOTCONN, ESTALE, EMFILE, any errno not named) fails the
    pass as before. The pass now commits the rows it holds first.

  Because a pass can now reach the sweep after meeting errors, two guards
  come with it. The root marker is verified again before the sweep, so a
  volume unmounted mid-pass fails the pass instead of sweeping every row the
  pass had not reached. And the sweep takes a row only when `metadata()` says
  NotFound, where `Path::exists` took it on any stat error. That also stops a
  directory that became unsearchable from having every row beneath it swept.

  `needs_attention` is now reported, for log regions too. It has been
  counted since D71 W4, and nothing reported it:
  - `WatchEvent::NeedsAttention` comes after the pass's verdict.
  - pvfsd logs `pvfsd: watch skipped <uri>: <reason>` and keeps a one-line
    note in the watch job's `last_error` until a clean pass clears it. From
    there it shows in `serve status` and among the HA page's problems, and
    reaches the notifier's `job_error` once (D151).
  - `pvfs serve watch` and `pvfs scan` print it, and `pvfs scan --json`
    carries `needs_attention`.

  Test seam: `Engine::on_catalogue_read`.

- **A catalogue pass keeps what it did (D154).** `scan_region_catalogue`
  hashed every file first and committed every row in one transaction at the
  end, so a stop (D86) during the hashing committed nothing. mediabox's two
  regions had no rows from their creation (D147, 2026-09-13) onward: a first
  pass there takes hours, and two daemon restarts each threw one away whole
  (its hashing survived as sidecars, its rows did not). Rows now commit in
  batches of `CATALOGUE_BATCH_ROWS` (1,000) or every `CATALOGUE_BATCH_MS`
  (30 s), whichever comes first. A stop commits what the pass holds, a kill
  loses one batch at most, and the next pass takes every committed file's
  hash from its row. The stale-row sweep and the head stay at the end of a
  COMPLETE pass: a stopped pass (also one stopped after its last file)
  sweeps nothing and publishes nothing, so a fetch never installs a partial
  catalogue, and this box's rows can run ahead of its head but never behind
  it. `region ls`'s `entries` therefore rises during a first pass; `head`
  > 0 is what says one has completed. The catalogue's hash now honours a stop
  mid-file (`hash_reusing_sidecar_until`, as D86 gave ingest), so a stop no
  longer waits out a film and the unit's stop timeout. The watch reports a
  stopped pass as `WatchEvent::Stopped`, not `Ingested`. It used to log
  `watch ingested … +8520` for a pass that had committed nothing, a second
  before shutdown. It sends no `Quiet` for a stopped pass, and the daemon
  gives it no verdict: `pvfsd: watch stopped mid-pass in <folder>: kept +A
  changed C`. Test seams: `Engine::set_catalogue_batch`,
  `Engine::interrupt_catalogue_at`.

- **A file dated in the future is judged by its ctime (D152).** The settle
  window defers a file while `max(mtime, ctime)` is under 15 s old (D71 W6,
  D112), so a file some other tool stamped 2038-01-18 (2³¹−1) was "still
  settling" on every pass until 2038: never hashed, never catalogued, and the
  watch re-ran every 20 s for it. mediabox holds 164 such files (337.8 GiB,
  stamped 2038 and 2097, their ctimes months old). `storage::changed_ms` now
  leaves out a stamp more than `FUTURE_SKEW_MS` (an hour) ahead of the clock,
  so such a file settles by its ctime (the `utimes` that set the stamp set it,
  after the last write), or at once when no sane stamp is left. A file being
  written carries the current time and is judged as before; D112's back-dated
  mtime is in the past and untouched. D149's orphan grace times a sidecar from
  its `changed_ms` when its mtime is from the far future (D150 dates such a
  file's sidecar to match it), so one whose 2038 file was renamed is not kept
  forever.

- **A job's error is reported after about four minutes, not after two
  records (D151).** The owner reported a peer job's error once the same text
  was in two consecutive health records — meant as four minutes, so a
  restart's transient never woke anyone. But every daemon start polls at
  once, so a few restarts in a row wrote records seconds apart: on
  2026-09-13 a play's four restarts in 21 s sent two `job_error`s for the
  peers' momentary "connection refused". `notify-state.json` now remembers
  when each job's error was first seen (`State.job_errors_seen`), and
  `job_errors` says it once it has been there `JOB_ERROR_AFTER_MS` (3½ min:
  the third two-minute pass) — still once, and again only when the text
  changes, after the new text's own wait. The clock survives restarts and
  is not advanced by them. A peer that misses a pass keeps its memory
  (unknown is not clear), so an error already said is no longer said again
  after a blip. `job_errors` no longer takes `prev`.

- **A manifest records its file's mtime, and is trusted only on an exact match
  (D150).** D91's exact-size check refused a sidecar when a replacement
  changed the size, which an arr upgrade nearly always does; a SAME-size
  replacement — an in-place tag edit (`mkvpropedit`), another encode matching
  to the byte — went through, and the scan recorded the old file's hash.
  Manifests are now **v3**: after the size they record the file's mtime (ms,
  the catalogue's unit), and `read_manifest_sidecar` — the one path every
  reader takes (the scan, receive's "already there", the backfill,
  `manifest_of`) — trusts a v3 manifest only when its recorded size AND mtime
  are the file's now. No clock is compared (the production NAS ran 142 s
  slow, and receive stamps a file with its source's mtime), and a replacement
  is caught even when it brings an OLDER mtime. Hash paths record the
  (size, mtime) seen BEFORE the read and write nothing if the file moved
  meanwhile (`write_manifest_sidecar_seen`). v2/v1 manifests keep an interim
  rule — not older than their file — until **`pvfs sidecar-upgrade`** brings
  them up: per box, against the local catalogue region rows, it STAMPS a v2
  manifest the row vouches for (same size, mtime and hash) without reading
  the file, and RE-READS the rest; a re-read that disagrees with the row is a
  stale hash caught, listed by path, and its row handed back to the scan. It
  looks first and asks (`--dry-run`, `--yes` for scripts). On the production
  NAS 33 of 26,182 manifests were older than their files — all the SAME size
  and carrying the catalogue's hash (1 by clock skew, 32 re-stamped in the
  migration); the upgrade re-reads exactly those. (An earlier draft of this
  entry said "all already refused by size" — a misread of the manifest's
  line order.)

- **A manifest whose file is gone goes to the trash (D149).** PVFS took a
  sidecar along only when it moved the file itself (a drain, a retraction);
  one whose file Sonarr renamed, or rclone's upload temp name that then became
  the real file, stayed forever — two of ~34,700 on the production fleet. The
  scan's walk already lists every directory, so it now notes a `.X.manifest`
  (or v1 `X.manifest`) with no `X` beside it, and `scan_binding` moves each
  one older than `ORPHAN_SIDECAR_GRACE_MS` (an hour) to the root's
  `.pvfs-trash`, where the retention purge (D148) removes it. Counted as
  `ScanStats.orphan_sidecars`; `pvfs scan` prints it and the watch logs it
  (`WatchEvent::Ingested` gains a sixth field).

- **Every trash is purged by its retention, and every box reports it
  (D148).** A replaced library copy goes to the library's `.pvfs-trash`, and
  nothing purged it: D133 purged only draining regions. On the production NAS
  an 18 GB bucket sat 19 days past a 7-day retention. `purge_region_trash`
  purges every catalogue region a box holds locally by that region's
  retention; `receive` now calls it after each pass (and `resolve`, as
  before). Each pass records, per region, the bytes kept, the buckets, the
  oldest bucket's day and what it freed; `serve status` carries it as
  `trash` (defaulted, no proto bump), the owner's health record keeps it per
  peer, and `pvfs serve status` / `pvfs fleet health` print it — so a purge
  that stops working shows up as an aging bucket instead of a full disk.

- **`follow` says it is current on a quiet log; dial errors say what failed
  (D146).** The follow job stamped its status row only when events landed, so
  on a quiet log `last_ok` froze at the last event and the stall detector
  reported a caught-up follower `overdue` indefinitely — on both production
  replicas, whose log tips matched the owner's. An empty long-poll whose
  returned source tip is not ahead of the replica's is now
  `FollowEvent::UpToDate`: the row is stamped and nothing is nudged, so
  `last_ok` on `follow` means *last confirmed current* and an `overdue`
  follow is a real signal. `dial_source` wrapped every failure as `invalid
  input for follow`, and the health probe and `receive` dial through it; an
  I/O failure is now `PvfsError::Io` naming the target (`I/O error during
  dial <target>: …`), a refusal `Forbidden`. Monitoring as a whole — what
  the fleet exposes and a worked Home Assistant build — is the new doc 30.

- **The drain asks before it discards, and never against the arr's choice
  (D145).** On the new model's first production day feederbox's `resolve`
  trashed Sonarr's upgrade of an episode: the NAS's catalogue still listed
  the copy Sonarr had just deleted through the union, and the ladder, with no
  quality measured, preferred it for being larger. A staging copy now goes
  only when a library region holds the same bytes AND the holder serves
  their last chunk back matching — read on this box, or over the wire by
  content hash; otherwise it is kept and asked about again next pass. A
  staging copy that differs from the library's is the arr's latest import and
  wins: the receiving side replaces the library copy (to the library's
  trash). The sidecar goes to the trash with its file; the receiving side
  makes the folders only staging has; a staging folder goes once it is empty
  and the library holds it, a region's top level excepted.
- **The merge no longer combines two boxes' DIFFERENT files (D119).** A
  duplicate group is CONTESTED when more than one member holds live bytes and
  those holders disagree about size — two versions of one path, an upgrade in
  flight — and `--merge` skips it. It had kept the node with more locations
  and unlinked the other, which cost `Lanterns s01e04` the catalogue entry for
  the holder's real copy. Two boxes at the SAME size still merge.
- **`resolve --rules` weighs a pending change on the D76 ladder (D120)** and
  prints the reason, instead of `--replace`/`--delete` chosen blind. The
  ladder's last rung is recency, so two comparable copies still get a decision
  — the newer one — while a truncated rewrite is refused before recency can
  fire. Also D120: `meta_set` retries a BUSY lock with the bounded backoff the
  durable append has had since a 28,000-file adoption died on one; the flake
  that surfaced it carried `retries: 0`.
- **The pipeline runs clippy and reaps idle build slots (D121).** Clippy was
  ad-hoc and got skipped: D114 reached production with a lint error, D120 was
  green on 512 tests while carrying five. `--all-targets`, because both misses
  were in test code. Slots idle for two days are reaped at report time, never
  this run's or `/opt/pvfs` — presubuntu hit 100% twice under the old
  delete-on-merge rule. The recap says NOT RUN when tags skipped clippy rather
  than claiming clean.
- **Docs (D118).** A full review: doc 24's "duplicates should NOT recur" (in a
  section headed CHECKED, not assumed) corrected; docs 01/04's pre-D105
  deletion contract updated; the settle window specified for the first time;
  eight undocumented commands added to the manual; doc 08 flagged as frozen at
  D29. Doc 25 §11 records the re-genesis rehearsal: 40 files, 152 GB, 26
  seconds, 40 of 40 sidecars reused.

- **Duplicates: the cause, the cleanup, and the check that was a no-op
  (D112–D117).** Two mechanisms were minting a node per file version, and
  production held 588 duplicate groups.

  **D112** — the settle window asked "has this stopped moving?" as
  `mtime + 15s > now`. rclone preserves the SOURCE mtime, so a file that landed
  seconds ago carried an mtime from days back, cleared the window on its first
  sighting, and was catalogued mid-copy at a partial size (measured: arrivals
  41.8h and 56.5h behind their ctime). Now `max(mtime, ctime)`; ctime cannot be
  back-dated from userspace. D112 also put a **24-hour grace** in front of
  D105's unlink — "no live location" is a routine transient state on a fleet
  whose mover works outside the catalogue, and unlinking on it removed files
  the NAS was holding. Recorded in `scan_unheld` (schema 15) and decided by a
  SWEEP at the end of a pass, not a branch in the removal arm, which sees a
  file only once.

  **D115/D117** — the scan matched on name AND size, so a file whose CONTENT
  changed was not a candidate and it concluded "new": an *arr upgrade grew a
  node per version. **A directory cannot hold two files with one name**, so
  same name + same parent + same root is now a CHANGE. Scoped to the root
  because D81 4c handles the same title upgraded on a different volume — and
  D117 taught that check the second spelling of a location, since a replica
  records `pvfs-host://<own pin>/path` and the bare-prefix test made D115 a
  no-op on every box that scans media.

  **D113/D114/D116** — `pvfs duplicates [--merge]` finds groups by parent and
  name (not size: the pairs exist BECAUSE their sizes disagree, so grouping by
  the identity rule found nothing) and merges them onto one node.
  `pvfs islands --drop <id>` unlinks a named detached subtree.

- **The daemon names its own build (D110), and so does the NAS binary.** D100
  stamped the CLI and stopped; `pvfsd --version` said a bare `1.4.0` on every
  arch, so after a roll the only way to identify the running daemon was to hash
  it — on the holder, the box where that is hardest.

- **The watch job reports what it took out of the tree (D111).** It is how the
  fleet actually scans and it reported its counts to nobody, so the one
  operation that changes the shape of the forest had no record.


- **A cache older than the current DDL opens again (D108):** `create_schema`
  ran with `?` at the top of the projection open path, so applying
  `INDEX_SCHEMA` to a pre-v10 cache failed on `idx_links_label` — a column
  `links` does not have until v10, indexed unconditionally since D72
  (2026-08-19) — and the error reached the caller. **`pvfsd` exited 1 and
  systemd restart-looped it** on `no such column: label`, which reads as a
  corrupt forest rather than as one wanting its migration. The DDL is now
  applied AFTER the migration ladder has added the columns it indexes, so the
  cheap door stays open for exactly the forest that needs it — old, large,
  where the alternative is replaying the whole log — and any remaining failure
  routes to `full_rebuild` like every other probe there. The test helper that
  should have caught this was relabelling a current cache `v7` rather than
  reshaping it; it now drops `links.label` too.
- **Detached subtrees are reported now (D106, doc 24 §18-19):** `pvfs
  islands` walks from every tree root and names every live-linked node the
  walk never reaches, **grouped by the folder whose link was cut** — one
  line, not 1,849. Nothing could see these before: `orphans` asks whether a
  node has a live link, `missing` whether a file is held, `reclaim` whether
  central bytes have a live node, and a detached subtree answers all three
  healthily because the only broken thing is one removed edge at its top,
  which no node inside is adjacent to. Production carried 1,849 such nodes
  (1,358 files, 491 folders) for a fortnight under a folder unlinked on
  2026-08-24, in no report at all, holding space `reclaim` can never sweep.
  The report dates the cut and sizes the loss. `pvfs unlink` now **counts
  the subtree first and says what it is about to strand** — the operator
  used to see one success and no number — and asks for confirmation at a
  terminal (`--yes` skips it; scripted runs warn and proceed, so no
  pipeline breaks). Unlink stays non-cascading: the semantics were never
  the bug, the silence after was.
- **The identity model, settled and frictionless (doc 18 §4, decided
  2026-08-13):** every outbound connection authenticates as the box's
  client identity — never the forest device key — and `pvfs forest init`
  now **self-enrolls the creating box's own client identity with read**
  (an explicit, logged, revocable grant), so a private forest's own mover
  and read-through work from birth. Other boxes enroll via `pvfs fleet
  enroll`, unchanged. Log compaction (doc 11) was reviewed and
  deliberately deferred with a written trigger metric.
- **Streaming-mount fix:** a background fetch that *failed* no longer
  sticks in the mount — re-opening the file retries instead of serving
  the cached error until remount.
- **Same-box fast path (P10.2, doc 23 §13, for the PVOS Torrents app):**
  `IngestBegin`/`IngestList` return each file's partial path over the Unix
  socket (additive `IngestFileWire.partial_path`; TCP callers get none),
  so a same-box downloader writes the partial directly — one home for the
  bytes, no spool — and still marks/commits through the unchanged gates.
  Session activation pre-creates the shard directories, so the writer's
  first `open(create)` just works.
- **In-flight streaming (P10.1, doc 23 §11):** everything an ingest session
  has verified serves **while the download runs**, through one seam —
  ranged `Cat` on the ingesting daemon. Marked chunks stream immediately;
  a request for unverified bytes *waits* server-side (60 s cap, lock-free)
  and registers as a **hot range** in `IngestList` — the demand signal the
  BT app maps to sequential piece priority, so hitting play reprioritizes
  the torrent. FUSE mounts (local or replica) proxy reads of in-flight
  files through the same op, gated by the early-serve license: the session
  opener must hold admin on the target, the attestation bar. Fleet phase K
  proved the arc across two machines: out-of-order ingest, mid-ingest
  chunk pulls, a blocked edge reader surfacing as demand and unblocking on
  verify, an in-flight consumer mount, and a bit-perfect post-commit read
  — **89/89**.
- **Replica-ingest race fixed (latent since P7.2b):** the follow job's
  sweep and a manual `replica sync` shipping the same tail concurrently
  could die on a PRIMARY KEY collision. Both ingest paths now take the
  write transaction first and verify-then-skip rows another writer already
  landed; a diverging row for an existing seq still refuses at its seq.
- **External-ingest sessions (P10.0, doc 23):** the seam a downloader app
  (first consumer: the PVOS BitTorrent app) uses to land bytes **as they
  arrive**. Six wire ops: `IngestBegin` catalogs the whole torrent up front
  (unhashed pointer nodes + a log-resident `pvos.download` origin record
  carrying the infohash) in one member-signed commit, with a free-space
  preflight (`allow_shortfall` overrides at the caller's risk);
  `IngestWrite` streams bytes sparse and out of order into a crash-safe
  partial (disk-full pauses, never poisons); `IngestVerified` turns the
  app's piece verification into marked 8 MiB chunks in an authoritative
  progress sidecar; `IngestCommit` runs the existing gates — hash-fill
  successor, `ChunkManifestRecorded` attestation, atomic publish — and the
  session's last commit (or `IngestAbort`) writes a `pvos.download.closed`
  record, so origin records never dangle. Sessions are deployment state
  (`ingest.sessions`) and survive kill -9; `pvfs ingest` drives it all from
  the CLI (bare form lists sessions). Live member commits may now batch
  nodes with intra-batch parentage (authority resolves at the nearest
  pre-existing ancestor — replay semantics unchanged), and `LinkSuperseded`
  joined the member-signable kinds (a latent gap the e2e test caught).
  Validated: 233 cargo tests + 366 smoke checks green on both hosts,
  clippy clean; USER-MANUAL §7.12.

## 1.4.0 — 2026-08-13

Validated end to end: the Ansible pipeline on two hosts (227 tests + 344
smoke checks, clippy clean), the chaos suite (20/20 — crash semantics
re-validated under the live-writer flock), and the two-machine fleet test
(`deploy/fleet-test.sh`, **75/75**: regions shipped to the edge hands-free,
attachment kinds draining and mirroring, a 1 GiB swarm split across two real
holders with kill -9 resume, and the streaming mount serving its first MiB
while the fetch ran).

- **Serve-while-fetching (P9.1, doc 22 §2):** the streaming mount delivers on
  punch J — opening an unfetched file whose chunk layout the owner attested
  starts a background chunked fetch, and each read waits only for the chunks
  covering its range (first MiB of a 1 GiB file in ~2 s on the fleet, fetch
  still in flight). The attestation (`ChunkManifestRecorded`, projection
  schema v7) is admin-gated on replay and binds the content hash; it is
  authored wherever a content hash is computed from bytes, in the same read.
  Unattested files keep the safe block-until-verified mount behavior and
  attest on their next re-hash.
- **The swarm data plane (P9.0, doc 22):** a fetch with two or more reachable
  holders pulls a hashed file as **parallel verified chunks from every holder
  at once** — 8 MiB BLAKE3 chunks, one worker per holder, bad chunks requeued
  to other seeds, dead holders dropped. Chunk manifests are computed at the
  sync sink (sidecar-cached) and served over two additive wire ops (ranged
  `Cat`, `ChunkManifest`); they are deliberately advisory — the catalog hash
  and the whole-file verify-then-rename gate remain the only trust anchor.
  Transfers are **resumable**: a kill at any point leaves a `.swarmpart` the
  next attempt re-verifies locally and completes (the long-standing chaos
  caveat, retired). Single-holder, small, and unhashed fetches keep the
  existing single-stream path byte-for-byte.
- **Attachment policies (P8, doc 21):** `pvfs bind <folder> <dir> --kind
  in-place|migrate|mirror [--to <store>]` — enrollment chooses the space's
  fate in one command. `migrate` = staging: the mover lands a verified copy
  in the store, retires the staged location (a new capability — the binding's
  own `file://` locations retire once a non-staged copy is live), and evict
  reclaims the bytes. `mirror` = the new `central-keep` placement mode: the
  mover maintains a verified second copy and never retires the source — a
  live backup that also seeds the future swarm (doc 20 §6). Placement file
  grows `central-keep` lines; `pvfs place <node> central-keep --to <dir>`
  exposes the mode directly.
- **Cross-region moves (P7.2c, doc 20 §2.5):** `mv` across a region boundary
  works — the paired protocol authors `NodeMovedOut` in the source region's
  log and `NodeMovedIn` in the destination's, one commit, one shared
  timestamp, each half carrying the other region's last committed head. Replay
  converges in either inter-log order; the moved subtree's sticky regions
  follow; orphan adoption across a boundary is the same protocol. New purge
  tombstones keep a purge that replays before its node's creation from
  resurrecting it (schema v6). Also fixes a latent pre-region bug: moving a
  node back under a former parent regenerates the same content-addressed link
  id, and recreation now reactivates the soft-removed row instead of being
  silently ignored.
- **The live-writer flock:** every open writer engine holds a shared `flock`
  on `writer.lock`; an engine opening a forest whose `clean_shutdown` flag is
  down now distinguishes "another writer is live" (catch up — no rebuild, no
  minutes-long lock holds under a running daemon) from "the last writer
  crashed" (full rebuild, exactly as before — chaos-suite re-validated). Ends
  the full-projection-rebuild-per-CLI-command era on daemon-served forests,
  and the SQLITE_BUSY races that came with it. Serve config verbs
  (`enable`/`disable`/`ls`/`status`) no longer open an engine at all.
- **Region logs over the wire (P7.2b, doc 20 §2.4):** `LogInfo`/`LogRead`/
  `LogWait` gain an additive **generation address** scope, gated on admin of
  the region's root; replicas discover generations by scanning shipped
  `RegionBaseline` rows and chain-verify each region log against its committed
  genesis before ingest. Whole-forest `replica add`/`sync`/`follow` ship every
  generation; `pvfs replica add --region <node>` scopes a replica to one
  region (absent siblings replay as attested-but-unfetched — replicas only;
  owners keep the strict check). Followers wake on any log's activity and
  sweep their generations, and the daemon attests dirty region heads on a
  60-second tick.
- **Physical region logs (P7.2a, doc 20 §2.3):** a marked region now owns its
  own signed, dense hash-chained log (`regions/<id>/g-*.db`). The mark commit
  carries a deterministic **baseline commitment** of the subtree's state (the
  doc 11 verifiable-snapshot subset), the region log's genesis binds it, and
  the enclosing log attests region heads (`SubRegionHead`, final one sealing
  the generation at unmark — files stay in place; a re-mark starts a fresh
  generation). Replay walks the tree of logs root-down, re-verifying every
  baseline and seal on every rebuild; membership checks became as-of-time to
  make parallel logs replay soundly. Legacy P7.0 marks split lazily at first
  writer open. New refusals guard causal isolation until P7.2c's paired-event
  protocol: cross-region orphan adoption, and purging a subtree that still
  contains a boundary. Projection schema v5 (one-time rebuild on first open).
- **Serve integration — the fleet runs itself (P5, doc 18):** `pvfsd` grows a job
  supervisor — `serve.jobs` deployment config (`pvfs serve enable|disable|ls|status|
  exports`, SIGHUP reload, corrupt-config-refuses-start), the F5.4 follower absorbed
  as the `follow` job, and `sync` / `export` / `tier` / `evict` as fold-nudged passes
  with 5-minute safety intervals and a catch-up pass at start. `pvfs export
  --keep-fresh` records a view the export job re-runs on change. **`pvfs fleet
  enroll`** admits a box's client identity (member + root rights) in one visible,
  logged, revocable step — the doc 17 §9 Q5 resolution (c): client identities dial,
  forest device keys never do. The fetch/tier/follow engines moved to `pvfs-client`
  (evict to core) so the CLI and daemon run one implementation.

## 1.3.0 — 2026-08-10

Validated end to end: the Ansible pipeline on two hosts (194 tests + 268
smoke checks, clippy clean) and the two-machine fleet test
(`deploy/fleet-test.sh`, 40/40, including a 3 GiB tier/evict/stream cycle
over the LAN) — see `docs/HANDOFF.md` §2 as it was then (this repo's
HANDOFF was retired on 2026-08-10, `c176336`, and is in its history; today's
handoff is PVOS's `docs/HANDOFF.md`).

- **Tail-subscribe (P4 F5.4, doc 17 §7.5):** the `LogWait` long-poll — the
  daemon holds a gated log read (up to a server-capped 60 s) until new
  events arrive — and **`pvfs replica follow <mount>`**, the follower loop
  that long-polls, chain-verifies, ingests, and folds, with reconnect
  backoff and tolerance for concurrent local commands. Events authored on
  the owner appear on following replicas (and through daemons serving
  them) within seconds. This completes the doc 17 §7 arc: the ingest-box →
  central-store pipeline is built end to end.
- **The mover — tiered storage (P4 F5.3, doc 17 §7.4):** `pvfs place
  <subtree> central --to <dir>` (owner-side) declares "every file here must
  hold a verified copy in this store"; **`pvfs tier`** enforces it — bytes
  already on the owner's disks satisfy it in place, everything else is
  reached (locally or by read-through), streamed through the verified read
  path into a node-id-addressed store, and logged as a new location; only
  THEN are foreign-instance locations retired. **`pvfs evict`** on the edge
  acts on the catalog's retired rows for its own pin and deletes local
  bytes only when another live location is recorded — a stale replica
  evicts less, never wrongly. End-to-end: an ingest box catalogs a file,
  consumers stream it, the owner migrates it home, the edge reclaims its
  space, and the file never stops being available.
- **Remote read-through (P4 F5.2, doc 17 §7.3):** fetching now resolves
  **per file**: candidates are every `pvfs-host://` location whose pin the
  instance registry knows (the holder), then the replica's recorded source
  — pooled connections, dead targets skipped. `pvfs sync` / `export
  --fetch` therefore work when bytes live on a third instance the source
  can't read, and **`pvfs cat` self-heals**: a read with no local bytes
  fetches on demand (blocking, hash-verified, into the sync store) and
  serves — a catalog entry alone is enough to reach the bytes. Owned
  forests fetch too: `pvfs sync` on the owner pulls edge bytes home (the
  F5.3 mover's core primitive). Write-through's read-your-writes now folds
  the pulled tail into the projection immediately, so a daemon serving the
  same replica sees the change live.
- **Instance-qualified locations (P4 F5.1, doc 17 §7.2):**
  `pvfs-host://<transport-pin>/<abs-path>` records **which instance** holds
  a file's bytes — the pin is the host's F1 transport pin, so the claim is
  verifiable and survives address changes. Resolution is local exactly when
  the pin is the data dir's own; a foreign pin degrades cleanly (`stat`
  unavailable, `cat` skips, `missing_bytes` counts it) and `pvfs sync`
  already fetches such files through the replica's source, which resolves
  its own pin. New `pvfs loc add <file> --here <path>` records a path on
  this instance under its pin (requires having served with `pvfsd --listen`
  once); composes with write-through, so an ingest box records its own pin
  into the owner's log.
- **Write-through replicas (P4 F5.0, doc 17 §7):** mutations on a replica
  mount now **route to its recorded source** instead of being refused —
  `pvfs add` and `pvfs loc add` explicitly, and every op that auto-routes
  through the daemon-client path (`acl`/`tag`/`device`, secure ops), because
  a replica's "daemon" is its source now. Writes are member-signed with the
  client identity over the same two-phase protocol as `pvfs remote`; after a
  write-through the CLI best-effort pulls the source's log tail so the
  change is locally visible at once (read-your-writes; silently skipped
  without replication rights). Temp nodes, `link`/`unlink`/`reorder`, and
  `loc rm` stay unrouted (the engine still refuses locally); writes need
  the source reachable — no offline queue, offline divergence stays
  app-level (doc 13 §A). The write model is unchanged: single writer per
  forest — a "writable replica" forwards, never merges. Doc 17 §7 specs the
  rest of the arc (instance-qualified `pvfs-host://` locations, remote
  read-through, the tiering mover with edge eviction, tail-subscribe) —
  the download-box → NAS media pipeline.
- **Placement & sync (P4 F3, doc 17 §6) — the pointer-vs-sync knob:**
  `pvfs place <target> sync` marks a subtree "keep its bytes local" (a plain
  per-instance deployment file — never log events; different replicas
  legitimately pin different subtrees). `pvfs sync` (and `pvfs export
  --fetch`) then streams every file that has **no readable local location**
  from the replica's recorded source over the raw data plane, hashing while
  the bytes arrive: a hashed node must match its content hash exactly, a
  lazy node its recorded size — wrong bytes never land, failures report per
  file. Fetched bytes live in a managed node-id-addressed store
  (`<data-dir>/synced/…`) and the read path synthesizes a
  `pvfs-sync:///<id>` location **from the store's existence** — no new
  projection state, so synced bytes survive rebuilds by construction and
  the whole mechanism works on read-only replicas. Verify-on-read and
  quarantine apply to the store like any location; a fresh verified sync
  lifts a stale quarantine. With F0–F2 this completes the cross-host media
  scenario: replicate the catalog, place the library `sync`, export, point
  the media server at it.
- **Forest replicas (P4 F2, doc 17 §5 — doc 03 Mode A):** `pvfs replica add
  <mount> --instance <name> | --connect <addr> --pin <hex> | --socket <path>`
  pulls a served forest's **full signed log** and builds a local, read-only
  replica; `pvfs replica sync` ships the tail from the recorded source. Log
  shipping (`LogInfo`/`LogRead`) is gated on **admin rights on the forest
  root** — replication is an owner/admin capability, not a member read.
  Ingest verifies chain linkage row-by-row (fail fast on a tampered tail);
  the open then runs the standard startup replay, verifying the entire log —
  chain from genesis, every event signature, replay-time authorization — so
  *a replica that opens is a proven copy*. Replicas are ordinary forest dirs
  with a `replica` marker: `Engine::open` routes them to a read-only open
  (every local write refused; the owner instance stays the only writer),
  `pvfsd` serves them with identical ACL answers (the grants are in the
  shipped log), and `pvfs export` materializes them like any forest — the
  cross-host media library composes today from F0 + F2.
- **Network transport (P4 F1, doc 17 §4):** `pvfsd --listen <addr>` serves the
  full daemon protocol (reads, member-signed writes, the raw data plane) over
  **TCP+TLS** alongside the Unix socket — same `serve_connection`, one generic
  body. No CA: the daemon generates a self-signed cert on first use
  (`<data-dir>/nettls/`, key 0600) and clients verify only its **transport
  pin** (BLAKE3 hex of the cert DER, printed at startup and written to
  `nettls/pin`). New `pvfs instance add|ls|rm` remembers `(address, pin)`
  pairs — adding the entry is the pinning step — and `pvfs remote` gains
  `--connect <host:port> --pin <hex>` / `--instance <name>`. Challenge
  **nonces are now single-use** (registered at issue, consumed on first
  auth; doc 08 §4 item 7 closed): a captured signature can never be
  replayed, on either transport. Principals still authenticate per
  connection by challenge-response — TLS is transport privacy + server
  identity, never authorization.
- **`pvfs export` — the native tree view (P4 F0, doc 17):** materialize any
  tree as a plain directory that non-PVFS apps (media servers, backup tools)
  read natively — files from every bound location appear as one hierarchy.
  Symlinks by default; `--mode hardlink` for apps that refuse symlinks;
  `--mode copy` streams through the verified read path (a corrupted location
  quarantines instead of landing bytes). A `.pvfs-export` manifest marks the
  directory export-owned (never adopts a foreign directory) and makes re-runs
  idempotent: unchanged entries counted, departed entries pruned (`--prune`)
  or reported stale. Files without local bytes, secure blobs, and folder refs
  are skipped with per-entry reasons. First slice of the federation & sync
  track (doc 17 phases F0–F4).
- **Companion: `POST /redeem-invite`** — join a PVOS server from the browser
  (PVOS D18 §2.7): one human prompt pairs the server and signs the invite
  acceptance with the identity key; redeem prompts show the signed email, and
  pairing names pin the install.
- **Tenant custody: provision and remove hosted users over the socket**
  (PVOS D32).
- **`pvfsd`: sd_notify READY when serving** (PVOS D57) — `Type=notify`
  systemd units gate dependents on the socket actually accepting.

## 1.2.0 — 07/22/2026

- **Daemon: concurrent metadata reads** (doc 07 §6 split): `ls`/`stat`/
  `payload`/`info` and the `cat`/secure-cat control phase now run over a pool
  of read-only WAL views (`Engine::open_read_view`); only mutations serialize
  behind the writer. No async runtime; if a view can't open, reads fall back
  to the writer lock.
- **CLI: `pvfs remote` takes paths and `pvfs://` URIs** everywhere a node id
  was required — resolved over the daemon by ACL-filtered `ls` (the owner's
  engine is never opened), so callers can only resolve what they could list.
- **CLI: `pvfs remote add-node` / `payload`** — operator surface for the 1.1
  log-resident typed records (payload from a literal, `@<file>`, or `@-`).
- **CLI: `pvfs audit` completeness**: now also reports direct `key:` grants
  to revoked device keys (never-authorized guest keys stay unreported — their
  grants are live by design) and grants past their `expires_at`, as two new
  appended sections (JSON keys `inert_key_grants`, `expired_grants`).
- **Companion: pairing trust binds to the server key, not pinned urls**
  (PVOS D27, doc 14 §6.1): the relay envelope verifies against the paired key
  first; a relay from a new url for a known key gets a one-time "trust this
  new address?" prompt, remembered as a per-`(key, url)` trust grant
  (`pvfs-companion pairings trust|untrust`). Pairing no longer requires
  origins (`Pair.origins` optional; `API_VERSION` 3, additive) — no re-pair
  when a server moves or adds an https origin.
- **Companion: auto sign-in over trusted pairs** (PVOS D29, doc 16 §2):
  `sign_in` relayed over a trusted `(key, url)` auto-approves — no tap per
  login; prompts remain for first contact and admin/sensitive request types
  (`user_action` unchanged). Rate limit, lock, and audit unchanged.
- **Companion: web agent serves https** (PVOS M3.6 §4a): the loopback agent
  generates a `localhost`/`127.0.0.1` cert next to the vault (key `0600`),
  offers it to the macOS login keychain once, and serves port 7421
  **dual-mode** — a one-byte peek distinguishes a TLS ClientHello from plain
  HTTP, so https pages and older http callers share the port through the
  transition. Closes the reliance on Chromium's loopback mixed-content
  exemption.
- **Companion: singleton per user + restart** (2026-07-21 request, PVOS M3.5):
  `serve` takes over an existing instance on launch — kill via `<socket>.pid`
  (SIGTERM → SIGKILL), rebind the socket, re-acquire the stable web port —
  and `pvfs-companion restart` / the menu-bar "Restart agent" item make it
  explicit. The dual-instance socket-orphaning failure can no longer happen.
- **Expiring ACL grants** (doc 13 Q-E1): `AclSet` gains an optional
  `expires_at` (ms epoch, 0 = never). An expired grant is inert on the read
  path — masked by `effective_rights` like a revoked-authority tag grant —
  while the row stays listed (`acl ls` flags `[expired]`) until compaction.
  Backward compatible: the expiry is a trailing wire field written only when
  set, so 1.0 events decode unchanged and no-expiry events stay byte-identical
  (expiring grants sign under a new `pvfs:aclset:v2:` digest domain). Replay
  judges expiry at the row's chain-protected `written_at`, so writes
  authorized by a then-valid grant rebuild deterministically. Surfaces:
  `pvfs acl set … --expires <45s|30m|12h|7d|2w|@unix-ms>`, engine/client
  `set_acl_expiring`, daemon `SetAcl.expires_at` (serde-defaulted; old
  clients unaffected). Projection schema v3 (self-heals by rebuild).

## 1.1.0 — 07/09/2026

Backward-compatible additions + fixes surfaced by the first PVOS milestone
(the M1 walking skeleton builds and tests against this engine).

### Added

- **`AddNode` / `Payload` daemon ops** (doc 13, PVOS-driven): create a
  custom-typed node with a small inline payload (≤64 KiB, lives in the signed
  event log — auditable + replayable) and read it back, both ACL-gated.
  Reserved types (`file`/`folder`/`secure`) keep their dedicated ops. Client:
  `add_node()` / `payload()`. Carries PVOS grant records (`/grants`).

### Fixed

- **Daemon error fidelity:** `pvfsd` now sends `already_exists` as a typed
  error code instead of the `internal` catch-all, and `pvfs remote …` maps it
  back to `AlreadyExists` (exit 4), matching the local-path semantics scripts
  already rely on. (Surfaced by PVOS's idempotent hand-install path.)

### Security

- **Revoked keys are contained on the read path** (doc 06 §5, doc 06 §9 rule
  table). `effective_rights` now distinguishes a key's standing: *revoked* keys
  have their direct `key:` ACL grants masked at access time (previously only
  `any`/tag grants and authorship died with `DeviceRevoked`; a lingering `key:`
  row still granted reads). *Never-authorized* guest keys are unchanged —
  their `key:` grants apply without membership (the doc 13 §E public-link
  path). Found by the PVOS M1 §0 default-deny smoke gate; regression test in
  `p2_access.rs` (`revoked_key_acl_grants_are_masked_but_guest_keys_keep_theirs`).

## 1.0.0 — 07/03/2026

The first complete release: a standalone, multi-user, signed file-system
engine, ready to host an application layer (sync/file server) above it.
Everything below was built across the `0.1` development line (P0 → P3 +
companion phases 1–7); `1.0.0` is the point where the committed scope closed.

### The engine (P0–P1.5)

- Append-only signed event log with hash chaining; content-addressed, signed
  nodes and links; a disposable SQLite projection rebuilt from the log.
- BIP39/BIP32 identity: one recovery phrase; per-machine device keys signed by
  the root; recovery is recovery-only (everyday admin never touches the phrase).
- Storage: bind real folders, scan/reconcile, verified reads, quarantine,
  a `serve` watcher, temp spool.
- Mounts & registry: portable `<mount>/.pvfs/` forests, `/etc/pvfs` host
  registry (`PVFS_REGISTRY_DIR` override), `pvfs://alias@local/tree/path` URIs
  and path shorthand.

### Multi-user (P2 A–G)

- Per-node ACLs (`public`/`any`/`tag:`/`key:`) with grant-only inheritance,
  admin-checked grants, and replay-time authorization (a crafted log cannot
  smuggle rights).
- Per-key tag authority: a tag is `(authority, name)`, so one forest hosts many
  apps' namespaces; revoking an authority masks its tags immediately;
  `pvfs audit` reports inert grants forest-wide.
- The `pvfsd` per-user daemon: challenge-response auth, ACL-filtered reads,
  member-signed two-phase writes, live admin over the socket, a raw binary
  data plane with concurrent transfers, graceful SIGTERM/SIGINT shutdown with
  WAL checkpointing, and a `pvfsd@.service` systemd `--user` unit.
- Seamless CLI: plain `acl`/`tag`/`device` commands auto-route to a running
  daemon (signing with the forest's admin device key) and fall back to the
  direct engine.

### Encryption at rest (P3)

- The secure node type (`m/43'/20566'/2'`): an opaque **mutable encrypted
  blob** plus a **content-free signed hash-state ledger**; envelope encryption
  with ECDH-wrapped per-blob content keys; companion-gated decryption — the
  server alone holds only inert ciphertext.
- Secure stores work over the daemon (`SecureCreate`/`SecurePut`/`SecureCat`):
  apps create and update encrypted stores on the fly, member-signed,
  ciphertext-only on the wire.

### Key replacement & rotation (doc 15, cases A/B/C)

- Replace a lost identity key (index bump + root-signed swap + authority
  re-issue), replace a member key (dual-signed handoff), and rotate the root
  itself (`RootRotated` lineage) with an optional offline **recovery key** —
  the forest survives full seed compromise with its id and history intact.

### The companion (doc 14, phases 1–7)

- A local key custodian: the seed sealed in an OS-keychain or passphrase vault
  (Argon2 + AEAD), never written unsealed.
- A tiered signer over an owner-only Unix socket: root events always prompt,
  the owner's local identity ops are friction-free, everything is rate-limited,
  audit-logged (append-only JSONL), and idle-locked with on-demand re-unlock.
- Approval UI: desktop dialog or terminal prompt, headless denies.
- Multi-tenant custody for servers: per-user sealed vaults, session tokens for
  trusted devices, root ops always require a fresh unlock.
- "Sign in with PVFS": a loopback identity agent with a per-launch token and
  wallet-style origin connects — proven end-to-end against a live `pvfsd`.
- The joint PVFS⇄PVOS agent API (doc 16): broker-built `ApprovalContext`
  rendered in prompts and recorded in the audit log, the `user_action` request
  type (prompt-by-default), and an explicit `api_version` handshake.

### Explicitly after 1.0

Federation & sub-forest replication (doc 03), log compaction & verifiable
snapshots (doc 11), single-use challenge nonces (needed only when the socket
is network-proxied), named groups / explicit deny, Touch ID unlock, and a
read-only metadata connection pool.
