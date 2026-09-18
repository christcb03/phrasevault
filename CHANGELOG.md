# Changelog

PVFS uses the layered version scheme in [VERSIONING.md](VERSIONING.md): this
file tracks Layer 0, the file-system engine.

## Unreleased

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
over the LAN) — see [HANDOFF.md](docs/HANDOFF.md) §2.

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
