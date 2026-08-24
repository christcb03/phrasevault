//! F5.2's fetch pass, shared (P5.2, doc 18 §5): per-file candidate
//! resolution (registry-pinned holders first, then the replica's source),
//! pooled connections, verified streaming into the sync store. One
//! implementation drives `pvfs sync` / `export --fetch` / self-healing `cat`
//! (the CLI) and pvfsd's `sync` job.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use pvfs_core::{identity, Engine, PvfsError, ReplicaSource};

use crate::follow::dial_source;
use crate::Client;

/// The instance registry file (`pvfs instance add`): `<config>/instances`,
/// one `name addr pin` triple per line. Reads live here so the daemon's jobs
/// resolve holders exactly like the CLI; the CLI still owns writes.
pub fn instances_path() -> Result<PathBuf, PvfsError> {
    Ok(identity::config_dir()?.join("instances"))
}

/// All registered instances as `(name, addr, pin)`.
pub fn load_instances() -> Result<Vec<(String, String, String)>, PvfsError> {
    let path = instances_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PvfsError::io("read instances", e)),
    };
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some(n), Some(a), Some(p)) => out.push((n.into(), a.into(), p.into())),
            _ => {
                return Err(PvfsError::BadInput {
                    field: "instances".into(),
                    reason: format!("corrupt registry line: {line:?}"),
                })
            }
        }
    }
    Ok(out)
}

/// Fetches missing bytes from wherever they can be reached (F5.2, doc 17
/// §7.3). Per file, candidates are tried in order: every `pvfs-host://`
/// location whose pin the instance registry knows (that host *definitely*
/// holds the bytes), then the replica's recorded source (which resolves its
/// own locations). Connections are pooled per target; dead targets are
/// remembered and not re-dialed.
pub struct Fetcher {
    pool: HashMap<String, Client>,
    dead: HashSet<String>,
    instances: Vec<(String, String, String)>,
    source: Option<ReplicaSource>,
    /// F5.7: catalog-published endpoints (pin → addr), lazily loaded once
    /// per pass — the registry always wins; these cover pins it lacks.
    endpoints: Option<std::collections::HashMap<String, String>>,
    /// D83 — set to abandon this pass. Checked between files AND between
    /// chunks, because a pass that can only stop between files still takes
    /// half an hour to notice when the file is a 20GB remux.
    ///
    /// Chris, 2026-08-24: *"having the daemon serving files and allowing reads
    /// to the library is the #1 top priority. Killing background transfers
    /// isn't a very big issue."* A half-pulled temp file costs one re-fetch;
    /// a daemon that will not answer costs the library.
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl Fetcher {
    pub fn new(data_dir: &std::path::Path) -> Fetcher {
        Fetcher {
            pool: HashMap::new(),
            dead: HashSet::new(),
            instances: load_instances().unwrap_or_default(),
            endpoints: None,
            source: ReplicaSource::load(data_dir).ok(),
            cancel: None,
        }
    }

    /// D83 — give this fetcher a cancellation flag. The daemon hands it the
    /// job's stop flag so a shutdown can abandon a transfer in progress.
    pub fn set_cancel(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.cancel = Some(flag);
    }

    /// Has this pass been told to stop?
    pub fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Whether ANY source could serve fetches: a recorded replica source or
    /// at least one registered instance. False means a pass cannot succeed.
    pub fn has_any_source(&self) -> bool {
        self.source.is_some() || !self.instances.is_empty()
    }

    /// Where `id`'s bytes might be fetched from, best candidate first.
    /// Where a file's bytes can be fetched from, in preference order:
    /// registry-resolved holders, catalog-taught holders (F5.7), then the
    /// replica's source. Public because tests and tooling reason about it.
    pub fn candidates(&mut self, engine: &Engine, id: &str) -> Vec<ReplicaSource> {
        let mut out: Vec<ReplicaSource> = Vec::new();
        for loc in engine.locations(&id.to_string()).unwrap_or_default() {
            if let Some((pin, _path)) = pvfs_core::storage::parse_host_uri(&loc) {
                // Registry first — the operator's word beats the log; the
                // catalog's endpoint directory (F5.7) covers unknown pins,
                // so one bootstrap entry self-teaches the rest. Either
                // way the connect still proves the pin.
                let addr = self
                    .instances
                    .iter()
                    .find(|(_, _, p)| p == pin)
                    .map(|(_, a, _)| a.clone())
                    .or_else(|| {
                        self.endpoints
                            .get_or_insert_with(|| catalog_endpoints(engine))
                            .get(pin)
                            .cloned()
                    });
                if let Some(addr) = addr {
                    out.push(ReplicaSource {
                        transport: "tcp".into(),
                        target: addr,
                        pin: pin.to_string(),
                        region: String::new(),
                    });
                }
            }
        }
        if let Some(src) = &self.source {
            out.push(src.clone());
        }
        out.dedup_by(|a, b| a.transport == b.transport && a.target == b.target);
        out
    }

    /// Fetch one file into the sync store, verified. `Err` is the last
    /// candidate's failure (or why there were none). P9 (doc 22): with two or
    /// more reachable holders and a hashed multi-chunk file, the bytes arrive
    /// as a parallel chunk swarm; anything else takes the single-stream path.
    pub fn fetch(&mut self, engine: &mut Engine, id: &str) -> Result<(), String> {
        let candidates = self.candidates(engine, id);
        if candidates.is_empty() {
            return Err("no reachable source holds this file (register the holding \
                        instance with `pvfs instance add`)"
                .into());
        }
        if candidates.len() >= 2 {
            match self.swarm_fetch(engine, id, &candidates) {
                Ok(true) => return Ok(()),
                Ok(false) => {} // not swarm-eligible — single-stream below
                Err(e) => {
                    // the partial (if any) stays for resume; a fresh attempt
                    // may still succeed single-stream from one good holder
                    eprintln!("swarm: falling back to single-stream ({e})");
                }
            }
        }
        let mut last_err = String::new();
        for cand in candidates {
            let key = format!("{}:{}", cand.transport, cand.target);
            if self.dead.contains(&key) {
                continue;
            }
            if !self.pool.contains_key(&key) {
                match dial_source(&cand) {
                    Ok(c) => {
                        self.pool.insert(key.clone(), c);
                    }
                    Err(e) => {
                        last_err = e.to_string();
                        self.dead.insert(key);
                        continue;
                    }
                }
            }
            let client = self.pool.get_mut(&key).expect("inserted above");
            let mut sink = match engine.sync_begin(&id.to_string()) {
                Ok(s) => s,
                Err(e) => return Err(e.to_string()),
            };
            match client.cat(id, &mut sink) {
                Ok(_) => match engine.sync_commit(sink) {
                    Ok(_) => return Ok(()),
                    Err(e) => {
                        // D83 — the bytes arrived and the COMMIT refused. A
                        // different failure entirely from a broken stream, and
                        // indistinguishable in `last_err` alone.
                        eprintln!("fetch: {id} streamed but commit failed from {key}: {e}");
                        last_err = e.to_string();
                    }
                },
                Err(e) => {
                    // D83 — say it HERE, not only if every candidate fails.
                    //
                    // This is the path production actually takes: the swarm
                    // needs two or more holders, and with one holder it is
                    // skipped entirely. So the swarm's diagnostics never fire,
                    // and a stream that dies mid-file left no trace at all —
                    // fetches were abandoned at multiple GB for hours with an
                    // empty log and nothing to read.
                    eprintln!("fetch: {id} stream failed from {key}: {e}");
                    // a failed stream may leave the connection out of step
                    last_err = e.to_string();
                    self.pool.remove(&key);
                }
            }
        }
        if last_err.contains("forbidden") {
            last_err.push_str(
                " — this box's identity may not be enrolled on the forest: \
                 on the owner, run `pvfs fleet enroll <this box's 'pvfs whoami' pubkey>`",
            );
        }
        Err(last_err)
    }

    /// The all-holder parallel pull (P9, doc 22 §3). `Ok(true)` = published;
    /// `Ok(false)` = not swarm-eligible (small/unhashed/one live holder) —
    /// caller takes the single-stream path; `Err` leaves any partial in place
    /// for a later resume.
    fn swarm_fetch(
        &mut self,
        engine: &mut Engine,
        id: &str,
        candidates: &[ReplicaSource],
    ) -> Result<bool, String> {
        self.swarm_fetch_opts(engine, id, candidates, 2, None)
    }

    fn swarm_fetch_opts(
        &mut self,
        engine: &mut Engine,
        id: &str,
        candidates: &[ReplicaSource],
        min_holders: usize,
        progress: Option<&SwarmProgress>,
    ) -> Result<bool, String> {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::sync::Mutex;

        const CHUNK: u64 = pvfs_core::sync::SWARM_CHUNK;
        let data_dir = engine.data_dir().to_path_buf();

        // Swarm only for HASHED files (doc 22 §2): without a catalog hash the
        // final gate would be size-only, and per-chunk hashes from an unsigned
        // manifest are not a substitute for the trust anchor.
        let hashed = engine
            .get_node(&id.to_string())
            .ok()
            .flatten()
            .and_then(|n| pvfs_core::FilePayload::decode(&n.payload).ok())
            .is_some_and(|p| !p.content_hash.is_empty());
        if !hashed {
            return Ok(false);
        }

        // Dial every candidate; each worker owns its connection.
        let mut holders: Vec<(String, Client)> = Vec::new();
        for cand in candidates {
            let key = format!("{}:{}", cand.transport, cand.target);
            if self.dead.contains(&key) || holders.iter().any(|(k, _)| *k == key) {
                continue;
            }
            match dial_source(cand) {
                Ok(c) => holders.push((key, c)),
                Err(_) => {
                    self.dead.insert(key);
                }
            }
        }
        if holders.len() < min_holders {
            return Ok(false);
        }

        // Manifest from the first holder that answers; advisory only (§2 of
        // doc 22) — the whole-file gate at commit is the trust boundary.
        let mut manifest: Option<(u64, Vec<[u8; 32]>)> = None;
        for (_, client) in holders.iter_mut() {
            if let Ok((size, chunk_size, hashes)) = client.chunk_manifest(id) {
                if chunk_size != CHUNK {
                    continue;
                }
                let mut decoded = Vec::with_capacity(hashes.len());
                for h in &hashes {
                    match hex::decode(h).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                        Some(a) => decoded.push(a),
                        None => break,
                    }
                }
                let expect = if size == 0 { 0 } else { size.div_ceil(CHUNK) } as usize;
                if decoded.len() == expect {
                    manifest = Some((size, decoded));
                    break;
                }
            }
        }
        let Some((size, manifest)) = manifest else {
            return Ok(false); // no swarm-capable holder — single-stream
        };
        // P9.1 (doc 22 §2): a progress consumer serves bytes EARLY, so the
        // manifest must verify against the OWNER-ATTESTED root — an unsigned
        // holder manifest is only ever advisory.
        if progress.is_some() {
            let attested = engine
                .attested_manifest_root(&id.to_string())
                .map_err(|e| e.to_string())?;
            match attested {
                Some((cs, root))
                    if cs == CHUNK
                        && pvfs_core::sync::manifest_root(&manifest) == root.as_slice() => {}
                _ => return Ok(false), // unattested/mismatched — blocking path
            }
        }
        if manifest.len() < 2 {
            return Ok(false); // one chunk: a plain stream is strictly better
        }

        // The resumable partial: verify what a previous attempt already
        // landed (a local read), fetch only the rest.
        let part = pvfs_core::sync::swarm_part_path(&data_dir, id).map_err(|e| e.to_string())?;
        if let Some(dir) = part.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&part)
            .map_err(|e| e.to_string())?;
        f.set_len(size).map_err(|e| e.to_string())?;
        if let Some(pr) = progress {
            pr.set_layout(size, CHUNK, manifest.len(), part.clone());
        }
        let mut have = vec![false; manifest.len()];
        let mut resumed = 0usize;
        {
            let mut f = &f;
            let mut buf = vec![0u8; CHUNK as usize];
            for (i, want) in manifest.iter().enumerate() {
                let off = i as u64 * CHUNK;
                let clen = (size - off).min(CHUNK) as usize;
                f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
                if f.read_exact(&mut buf[..clen]).is_ok()
                    && blake3::hash(&buf[..clen]).as_bytes() == want
                {
                    have[i] = true;
                    resumed += 1;
                    if let Some(pr) = progress {
                        pr.mark(i);
                    }
                }
            }
        }
        drop(f);
        if resumed > 0 {
            eprintln!("swarm: resumed {resumed}/{} chunks from a previous attempt", manifest.len());
        }

        let queue: Mutex<Vec<usize>> = Mutex::new(
            (0..manifest.len()).filter(|i| !have[*i]).rev().collect(),
        );
        let counts: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());
        let manifest_ref = &manifest;
        let queue_ref = &queue;
        let counts_ref = &counts;
        let part_ref = &part;
        let progress_ref = &progress;
        // D83 — cloned out of `self` before the scope so every worker can see
        // it. Cancellation is checked BETWEEN CHUNKS, not just between files:
        // a 20GB remux is half an hour of a daemon that has been told to stop.
        // Abandoning costs one re-fetch and not even that in practice — the
        // partial `.tmp` is resumed chunk-by-chunk on the next attempt (see
        // "resumed N/M chunks" above).
        // Owned once, then shared by REFERENCE like every other ref above:
        // `Option<Arc<_>>` is not Copy, so handing the value itself to a
        // `move` closure moves it on the first iteration and the second worker
        // will not compile. `&Option<Arc<_>>` is Copy, which is why
        // queue/counts/progress are all borrowed rather than cloned.
        let cancel_owned = self.cancel.clone();
        let cancel_ref = &cancel_owned;

        std::thread::scope(|scope| {
            for (key, mut client) in holders.drain(..) {
                scope.spawn(move || {
                    let Ok(mut out) = std::fs::OpenOptions::new().write(true).open(part_ref)
                    else {
                        return;
                    };
                    let mut pulled = 0u64;
                    let mut strikes = 0u32;
                    loop {
                        if cancel_ref
                            .as_ref()
                            .is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst))
                        {
                            break;
                        }
                        let idx = match queue_ref.lock().unwrap().pop() {
                            Some(i) => i,
                            None => break,
                        };
                        let off = idx as u64 * CHUNK;
                        let clen = (size - off).min(CHUNK);
                        let mut buf = Vec::with_capacity(clen as usize);
                        let ok = client.cat_range(id, off, clen, &mut buf).is_ok()
                            && buf.len() as u64 == clen
                            && blake3::hash(&buf).as_bytes() == &manifest_ref[idx];
                        if !ok {
                            // requeue; a transient (a holder mid-fold) must
                            // not retire a good seed — three strikes does
                            queue_ref.lock().unwrap().push(idx);
                            strikes += 1;
                            if strikes >= 3 {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(300));
                            continue;
                        }
                        if out.seek(SeekFrom::Start(off)).is_err()
                            || out.write_all(&buf).is_err()
                        {
                            queue_ref.lock().unwrap().push(idx);
                            break;
                        }
                        if let Some(pr) = progress_ref {
                            pr.mark(idx);
                        }
                        pulled += 1;
                    }
                    if pulled > 0 {
                        counts_ref.lock().unwrap().push((key, pulled));
                    }
                });
            }
        });

        let leftover = queue.lock().unwrap().len();
        if leftover > 0 {
            // D83 — say WHICH it was. "every holder failed" was the only
            // message either case produced, so hours of abandoned fetches gave
            // no way to tell a cancelled pass from a failing link, and the
            // failure was invisible until the pass ended — which, for a pass
            // that never ends, is never.
            let why = if cancel_owned
                .as_ref()
                .is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst))
            {
                "cancelled mid-fetch"
            } else {
                "every holder failed"
            };
            eprintln!(
                "swarm: giving up on {id} — {leftover}/{} chunk(s) unfetched ({why})",
                manifest.len()
            );
            return Err(format!(
                "{leftover} chunk(s) unfetched — {why}; partial kept for resume"
            ));
        }
        let stats = counts.into_inner().unwrap();
        engine
            .swarm_commit(&id.to_string(), &part, &manifest)
            .map_err(|e| e.to_string())?;
        let total: u64 = stats.iter().map(|(_, n)| n).sum();
        let desc: Vec<String> = stats.iter().map(|(k, n)| format!("{k}={n}")).collect();
        eprintln!(
            "swarm: {total} chunk(s) from {} holder(s) [{}]",
            stats.len(),
            desc.join(", ")
        );
        Ok(true)
    }
}

/// A logged location that resolves on THIS host (central-satisfying, F5.3):
/// a `file://` path that exists, or a `pvfs-host://` under our own pin whose
/// path exists. Synthesized sync-store entries never count — they aren't
/// catalog truth.
fn logged_local_location(uri: &str, own_pin: &Option<String>) -> bool {
    if let Ok(p) = pvfs_core::storage::uri_to_path(uri) {
        return p.is_file();
    }
    if let Some((pin, path)) = pvfs_core::storage::parse_host_uri(uri) {
        return own_pin.as_deref() == Some(pin) && std::path::Path::new(path).is_file();
    }
    false
}

/// What one mover pass did (F5.3). `failed` carries `(label, reason)` —
/// a failed migration never retires anything.
#[derive(Debug, Default)]
pub struct TierReport {
    pub migrated: u64,
    pub satisfied: u64,
    pub retired: u64,
    pub failed: Vec<(String, String)>,
    /// D83 — the pass was told to stop rather than reaching the end.
    ///
    /// This matters because cancelling mid-pass produces a burst of entries in
    /// `failed`: every in-flight fetch abandons, and each abandoned migration
    /// looks exactly like a migration that failed on its own merits. Reported
    /// as failures they are worse than noise — they become the job's
    /// `last_error`, so a clean shutdown leaves the mover looking broken.
    /// Observed for real: disabling `tier` produced "215 migrations failed"
    /// when the true count of real problems was 34.
    pub cancelled: bool,
    /// D76 — what a DRY RUN would have done, in order, one line per action.
    ///
    /// Empty on a real pass. This exists because two separate bugs in this
    /// milestone were only visible in what the mover DID afterwards — locations
    /// retired that should not have been, bytes written to a disk that was not
    /// the NAS. Being able to read the plan before it runs is the cheapest
    /// possible defence against the next one.
    pub planned: Vec<String>,
}

/// One mover pass, owner-side (F5.3, shared by `pvfs tier` and the daemon's
/// `tier` job): ensure a verified central copy for every file under a
/// `central`-placed subtree — satisfied in place by the owner's own disks,
/// else fetched (locally or by read-through) and streamed into the store —
/// then retire foreign-instance locations. `Ok(None)` = nothing placed
/// central (a clean no-op for the job; the CLI turns it into guidance).
/// Decide which of two live copies of one tree path survives (D76).
///
/// `None` = do not act. That is returned when the rules are OFF, when either
/// side has never been measured, or when the ladder cannot separate them — and
/// in every one of those cases the caller keeps the existing refusal. The rules
/// exist to replace "I will not guess" with "here is why", never to
/// manufacture a decision out of missing information.
///
/// `Some((true, _))` = the INCOMING copy wins and the occupant is trashed.
/// Retire the loser of a collision: its location, and its place in the tree.
///
/// D81, and Chris's call on the shape. When the ladder decides, the loser's
/// bytes go to trash — but leaving its NODE linked showed a phantom duplicate
/// of every upgraded title in a Plex-facing library, and leaving its LOCATION
/// pointing at a path that now holds the winner's bytes was worse than a
/// phantom: it was a lie the catalog would act on.
///
/// The trash is the recovery mechanism, not the node. Restoring from it is a
/// deliberate act either way.
fn retire_loser(
    engine: &mut pvfs_core::Engine,
    loser: &str,
    at: &std::path::Path,
) -> Result<(), PvfsError> {
    // The location that named the trashed bytes, in whichever form it was
    // recorded (a replica writes them pin-qualified — D81).
    let doomed: Vec<String> = engine
        .locations(&loser.to_string())?
        .into_iter()
        .filter(|u| pvfs_core::storage::any_path_of(u).is_some_and(|p| p == at))
        .collect();
    for u in doomed {
        let _ = engine.remove_location(&loser.to_string(), &u);
    }
    // …and out of the tree, so nobody browsing sees a title that is in trash.
    if let Some(parent) = engine.parent_of(&loser.to_string())? {
        let links: Vec<String> = engine
            .children(&parent)?
            .into_iter()
            .filter(|c| c.node.id == loser)
            .map(|c| c.link_id)
            .collect();
        for l in links {
            let _ = engine.remove_link(&l);
        }
    }
    Ok(())
}

fn decide_collision(
    engine: &Engine,
    incoming: &str,
    occupant: &str,
    rules: Option<pvfs_core::media::Rules>,
) -> Option<(bool, pvfs_core::media::Verdict)> {
    let rules = rules?;
    let cand = |id: &str| -> Option<pvfs_core::media::Candidate> {
        let node = engine.node(&id.to_string()).ok()??;
        let payload = pvfs_core::FilePayload::decode(&node.payload).ok()?;
        // NEVER MEASURED IS NOT NO OPINION — it is an empty rung, and the
        // ladder is built to fall through empty rungs to the next one.
        //
        // This used to bail here, which made the mover REFUSE every unmeasured
        // pair while `pvfs explain` — same ladder, same two files — decided
        // them on size and said so. Chris, on exactly that case: "I wanted the
        // size comparison for that exact case, I want the larger one to win."
        // His rule was that size ranks LAST, not that it never applies.
        //
        // It matters at production scale rather than in the abstract: all three
        // collisions pending on the real library are TV, and TV is the 5,868
        // files Sonarr never analysed. Bailing here refused precisely the cases
        // `--rules` exists to settle, while the comment below promised they
        // would reach size.
        let (quality, _src) = engine
            .media_quality(&id.to_string())
            .ok()
            .flatten()
            .unwrap_or_else(|| (Default::default(), "never measured".into()));
        Some(pvfs_core::media::Candidate {
            label: node.label.clone(),
            quality,
            size_bytes: payload.size_bytes,
            mtime_ms: node.created_at,
            // A recorded hash that disagrees is caught by the fetch itself;
            // what this flag carries is whether anything has DECODED the file.
            integrity_ok: true,
        })
    };
    let (a, b) = (cand(incoming)?, cand(occupant)?);
    // From the FILE TYPE, not from whether a measurement happens to exist —
    // an unmeasured episode is still an episode, and must climb the ladder
    // (and so reach SIZE) rather than being decided on date alone.
    let is_media = pvfs_core::media::is_media_file(&a.label, "")
        || pvfs_core::media::is_media_file(&b.label, "");
    let (a_wins, verdict) = if is_media {
        pvfs_core::media::choose(&a, &b, &rules)
    } else {
        pvfs_core::media::choose_non_media(&a, &b)
    };
    verdict.decided().then_some((a_wins, verdict))
}

pub fn tier_pass(
    engine: &mut Engine,
    fetcher: &mut Fetcher,
) -> Result<Option<TierReport>, PvfsError> {
    tier_pass_opts(engine, fetcher, false)
}

/// The mover with copy-selection rules enabled (D76). Rules are OPT-IN: with
/// `None` a collision is refused exactly as before.
pub fn tier_pass_ruled(
    engine: &mut Engine,
    fetcher: &mut Fetcher,
    dry_run: bool,
    rules: Option<pvfs_core::media::Rules>,
) -> Result<Option<TierReport>, PvfsError> {
    tier_pass_inner(engine, fetcher, dry_run, rules)
}

/// The mover, with `dry_run` — plan every action, take none of them.
pub fn tier_pass_opts(
    engine: &mut Engine,
    fetcher: &mut Fetcher,
    dry_run: bool,
) -> Result<Option<TierReport>, PvfsError> {
    tier_pass_inner(engine, fetcher, dry_run, None)
}

fn tier_pass_inner(
    engine: &mut Engine,
    fetcher: &mut Fetcher,
    dry_run: bool,
    rules: Option<pvfs_core::media::Rules>,
) -> Result<Option<TierReport>, PvfsError> {
    // D75 — a REPLICA may pull-and-place, but never retire.
    //
    // The mover does two separable things: it PLACES bytes at their tree path
    // in a central store, and it RETIRES other boxes' locations once that copy
    // exists. Placing is a local act — fetch from the swarm, write the file,
    // log where it went. Retiring is an authority decision about someone
    // else's copy, and belongs to the owner.
    //
    // Refusing a replica outright conflated the two, and forced the central
    // store to be a path the OWNER can write — which meant NFS, and an owner
    // sitting in the byte path for bytes it does not keep. A holder that pulls
    // for itself and advertises what it now has is the shape the fleet wants:
    // the holder does the I/O, the controller decides when the edge may
    // reclaim.
    let pull_only = engine.is_replica();
    // Opened once: a replica's catalog writes all go through the owner.
    let mut route = if pull_only {
        crate::advertise::replica_route(engine.data_dir(), true)?
    } else {
        None
    };
    let data_dir = engine.data_dir().to_path_buf();
    let central = pvfs_core::sync::load_central_all(&data_dir)?;
    if central.is_empty() {
        return Ok(None);
    }
    // D74 — the central store must PROVE it is the central store.
    //
    // A central directory is very often a mount (NFS/SMB to a NAS). When that
    // mount is not there, the mountpoint is still a perfectly good local
    // directory — so the mover writes to it, reports "migrated into the central
    // store", and the catalog records bytes as safely central that are actually
    // on the owner's own small disk. Demonstrated on the lab: 16MB written to a
    // VM's root filesystem while every message said success. With `evict`
    // downstream, that is a path to losing the only real copy.
    //
    // The marker costs one file and turns a silent wrong-disk write into a
    // refusal that names the mount. It is written when placement is set.
    for (_root, dir, _keep) in &central {
        pvfs_core::sync::verify_central_marker(dir).map_err(|e| PvfsError::BadInput {
            field: "tier".into(),
            reason: format!(
                "{} does not look like the central store: {e}. If this is a mount, it is                  probably not mounted — writing here would put the bytes on this box's own                  disk while the catalog recorded them as central.",
                dir.display()
            ),
        })?;
    }
    let own_pin = pvfs_core::storage::host_pin(&data_dir);
    // F5.5 (doc 17 §7.7): central subtrees with a serving instance log the
    // store copy as THAT instance's pvfs-host:// location too — resolved to
    // its pin from the registry once, up front (a vanished registry entry
    // fails the pass loudly rather than logging unattributable rows).
    let placement = pvfs_core::sync::load_placement_full(&data_dir)?;
    let served_by = placement.served_by;
    // D71 W5: roots whose destination is the file's TREE PATH, not a hex blob.
    let tree_roots: std::collections::HashSet<String> =
        placement.central_tree.iter().cloned().collect();
    let mut serve_as: std::collections::HashMap<String, (String, std::path::PathBuf)> =
        std::collections::HashMap::new();
    if !served_by.is_empty() {
        let registry = load_instances()?;
        for (root, inst, prefix) in served_by {
            let Some((_, _, pin)) = registry.iter().find(|(n, _, _)| n == &inst) else {
                return Err(PvfsError::BadInput {
                    field: "tier".into(),
                    reason: format!(
                        "placement names serving instance '{inst}' but the registry has no \
                         such entry — `pvfs instance add` it or re-place without --served-by"
                    ),
                });
            };
            serve_as.insert(root, (pin.clone(), prefix));
        }
    }
    let mut report = TierReport::default();
    // D71 W5 — the MOST SPECIFIC placement wins.
    //
    // Placements nest: a store placement on `Media` and a tree placement on
    // `Media/from-feeder` both cover the same files, and without an order the
    // outer one silently claims them. The lab caught exactly that — a file
    // configured for a human path landed as a hex blob in the store because
    // the broader root was processed first. Deepest root first, and a file
    // handled by an inner placement is not revisited by an outer one.
    let forest_root = engine.identity.root_node_id.clone();
    let mut central: Vec<_> = central;
    central.sort_by_key(|(root, _, _)| {
        std::cmp::Reverse(
            engine
                .tree_path_under(root, &forest_root)
                .ok()
                .flatten()
                .map(|segs| segs.len())
                .unwrap_or(0),
        )
    });
    let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (root, dest, keep) in central {
        // P8 (doc 21): a MIGRATE-kind binding's own staging dir drains too —
        // its file:// locations retire once the central copy is live, and the
        // evict pass then reclaims the staged bytes. Resolved per root from
        // the binding, so in-place binds elsewhere are never touched.
        // D81 — WHICH ROOTS DRAIN IS PER ROOT, not per folder.
        //
        // This used to be "every bound root, when the placement is migrate",
        // which made Chris's topology inexpressible: feederbox must drain while
        // Data_ext must not, and they are roots of the same folder. Under
        // migrate every root staged (so a hand-moved title was fetched back);
        // under mirror none did (so nothing was ever placed).
        //
        // A root is a LIBRARY root unless explicitly marked staging. That
        // default is the safe one: mis-marking a library root as staging
        // retires real locations, while the reverse merely leaves bytes where
        // they already are.
        // BACKWARD COMPATIBILITY, and it is not optional. A folder that has
        // never been marked keeps the OLD meaning — under `migrate`, every
        // bound root stages. Without this, upgrading a running fleet would make
        // every staging root look like a library root, so every pending file
        // would read as "already in the library" and the mover would quietly
        // stop placing anything. Silent, and exactly the failure mode this
        // milestone keeps finding.
        //
        // Marking ANY root of a folder opts that folder into the per-root
        // model, where unmarked means LIBRARY (Chris: default to keeps).
        let marked = pvfs_core::sync::staging_roots_of(&data_dir, &root)?;
        let declared = pvfs_core::sync::library_roots_of(&data_dir, &root)?;
        let opted_in = !marked.is_empty() || !declared.is_empty();
        // trailing slash: "file:///a/b" must not match "file:///a/bXX/…"
        //
        // DECLARED roots win over discovered ones, because the mover often
        // cannot discover them at all: it runs on the owner, and a replica's
        // binding is machine-local (D71 W1). On Chris's fleet the owner sees
        // `no bound spaces`, so deriving the topology from bindings alone gave
        // an empty set — quietly making everything below a no-op on the one
        // box it runs on.
        let visible: Vec<String> = engine
            .bindings_for(&root)?
            .iter()
            .map(|b| b.source_uri.clone())
            .collect();
        let as_prefix = |u: &str| format!("{}/", u.trim_end_matches('/'));
        let staging_prefixes: Vec<String> = if keep {
            Vec::new()
        } else if opted_in {
            marked.iter().map(|u| as_prefix(u)).collect()
        } else {
            visible.iter().map(|u| as_prefix(u)).collect()
        };
        // D81 4b — the library's roots, as directories. A file sitting at its
        // tree path under ANY of them is in the library; only the write target
        // is where new content is PUT.
        //
        // STAGING ROOTS ARE EXCLUDED, and the first draft of this got it wrong
        // by including them: an incoming file sits in staging, staging is a
        // bound root, so the file counted as "already in the library" and was
        // never placed at all. Ingest would have silently stopped. That is
        // exactly the line 4a-i draws — a file whose only live location is a
        // staging root is placement work, not a file that has arrived.
        let library_dirs: Vec<std::path::PathBuf> = declared
            .iter()
            .cloned()
            .chain(visible.iter().cloned())
            .filter(|u| !staging_prefixes.contains(&as_prefix(u)))
            .collect::<std::collections::BTreeSet<_>>()
            .iter()
            .filter_map(|u| pvfs_core::storage::uri_to_path(u).ok())
            .collect();
        for entry in engine.walk(&root)?.entries {
            // D83 — stop between files as well as between chunks. The pass
            // returns what it has done so far rather than erroring: a mover
            // that was told to stop has not failed, and reporting it as a
            // failure would put a permanent `last_error` on the job every
            // time the daemon restarts.
            if fetcher.cancelled() {
                report.cancelled = true;
                break;
            }
            if entry.node.node_type != pvfs_core::TYPE_FILE {
                continue;
            }
            let mut id = entry.node.id;
            // Claimed by a deeper (more specific) placement already.
            if !handled.insert(id.clone()) {
                continue;
            }
            let label = entry.label;
            let unhashed = pvfs_core::FilePayload::decode(&entry.node.payload)
                .map(|pl| pl.content_hash.is_empty())
                .unwrap_or(false);
            // What satisfies this root: for a MIRROR (keep) root the whole
            // point is a copy IN THE STORE — the source's own local location
            // never satisfies it. For migrate/central roots any local copy
            // does (the F5.3 owner-disk rule) — except a staged one, which is
            // exactly what's about to be retired; counting it would strand
            // the catalog entry with no live location.
            let dest_prefix = format!(
                "{}/",
                pvfs_core::storage::path_to_uri(&dest)?.trim_end_matches('/')
            );

            // D71 — under TREE layout, "already placed" means at the RIGHT
            // path, not merely somewhere under the root.
            //
            // A node-addressed store derives its path from the id, which never
            // changes, so "is there a copy under the root" was a sound test.
            // A tree path changes whenever the file — or ANY ancestor folder —
            // is renamed. The lab caught it: renaming a show left three
            // episodes sitting at their old paths while the catalog said
            // otherwise, and the mover reported success because a copy did
            // exist under the root.
            let tree_dest: Option<std::path::PathBuf> = if tree_roots.contains(&root) {
                match engine.tree_path_under(&id, &root)? {
                    Some(segs) if !segs.is_empty() => {
                        Some(segs.iter().fold(dest.clone(), |acc, s| acc.join(s)))
                    }
                    _ => None,
                }
            } else {
                None
            };

            // D81 — this file's tree path under every LIBRARY root. Used twice:
            // to decide it is already in the library (4b), and to find a copy
            // of it on another volume (4c).
            let tree_segs = engine.tree_path_under(&id, &root)?.unwrap_or_default();
            let at_a_root: Vec<std::path::PathBuf> = if tree_segs.is_empty() {
                Vec::new()
            } else {
                library_dirs
                    .iter()
                    .map(|d| tree_segs.iter().fold(d.clone(), |acc, s| acc.join(s)))
                    .collect()
            };

            let has_central = match &tree_dest {
                Some(want) => {
                    let want_uri = pvfs_core::storage::path_to_uri(want)?;
                    // D81 4b — SATISFIED AT ANY LIBRARY ROOT.
                    //
                    // This used to ask only "is there a copy at the write
                    // target". So a title Chris hand-moved from Data to
                    // Data_ext was recorded correctly by the scan and then
                    // FETCHED BACK by the very next mover pass, because it was
                    // no longer at the destination. The catalog knew where the
                    // file was; the mover simply was not asking.
                    //
                    // The write target is still the ONE place new content is
                    // put (Chris: "writing needs to be a single place"). Being
                    // already somewhere in the library is a different question,
                    // and this is it.

                    // D75: a REPLICA logs its store copy PIN-QUALIFIED, because a
                    // bare file:// path is host-implicit and that copy lives on a
                    // specific box. So the satisfied check must recognise both
                    // forms — otherwise the holder does not recognise the file it
                    // placed itself, re-places it every pass, and the occupied-path
                    // guard reports it as "the catalog has never seen it".
                    //
                    // (Found by the dry run, before it had written anything.)
                    let want_host = own_pin
                        .as_deref()
                        .map(|pin| format!("pvfs-host://{pin}{}", want.display()));
                    engine.locations(&id)?.iter().any(|u| {
                        if u == &want_uri || want_host.as_deref().is_some_and(|w| u == w) {
                            return true;
                        }
                        // Held by ANY box, at its tree path under ANY root.
                        pvfs_core::storage::any_path_of(u)
                            .is_some_and(|p| at_a_root.contains(&p))
                    })
                }
                None => engine.locations(&id)?.iter().any(|u| {
                    if keep {
                        u.starts_with(&dest_prefix)
                    } else {
                        logged_local_location(u, &own_pin)
                            && !staging_prefixes.iter().any(|p| u.starts_with(p))
                    }
                }),
            };
            if has_central {
                report.satisfied += 1;
            } else {
                // reach the bytes (locally or via read-through)…
                if engine.readable_path(&id)?.is_none() {
                    if dry_run {
                        report.planned.push(format!(
                            "WOULD FETCH  {label}  (no local copy — would pull from the swarm)"
                        ));
                        report.migrated += 1;
                        continue;
                    }
                    if let Err(e) = fetcher.fetch(engine, &id) {
                        report.failed.push((label, e));
                        continue; // never retire without a central copy
                    }
                }
                // F5.6 (doc 17 §7.7): the MOVER ATTESTS — but only what it
                // MIGRATES. An unhashed lazy pointer (the arr hook's
                // add + loc-here output), bytes in hand, gains its
                // hash-fill successor first — verified from the real
                // bytes, owner-signed — so the central copy lands under
                // the attested id and consumers stream + verify from now
                // on. Satisfied-in-place unhashed files (a no-hash scan of
                // a huge library) are deliberately NOT ground through
                // here: bulk attestation is an explicit operator act
                // (`pvfs loc hash`), never a silent tier side effect.
                // D75: attestation mints a SUCCESSOR NODE, which is a catalog
                // write and therefore the owner's. A replica places the bytes
                // and records where they are; the owner attests on its own
                // pass (or an operator does, with `pvfs loc hash`). Trying it
                // here fails the whole file for a reason that has nothing to
                // do with the copy having been made.
                if unhashed && !pull_only && dry_run {
                    report
                        .planned
                        .push(format!("WOULD ATTEST {label} (hash + successor node)"));
                } else if unhashed && !pull_only {
                    match engine.hash_node(&id) {
                        Ok(new_id) => {
                            eprintln!(
                                "tier: attested {label} ({} -> {})",
                                &id[..12],
                                &new_id[..12]
                            );
                            id = new_id;
                        }
                        Err(e) => {
                            report.failed.push((label, e.to_string()));
                            continue; // never migrate what we couldn't attest
                        }
                    }
                }
                // …then land a verified copy at its destination.
                //
                // D71 W5: for a tree-layout root that is the file's own path —
                // `…/Media/TV/Show/Season 03/ep.mkv` — so the NAS stays a
                // normal media library rather than a node-addressed store, and
                // PVFS is not required to read it.
                let cpath = if tree_roots.contains(&root) {
                    match &tree_dest {
                        Some(p) => p.clone(),
                        // Not under this root, or the root itself: never guess
                        // a path on a 130T NAS.
                        None => {
                            report.failed.push((
                                label,
                                "no tree path under the placement root — refusing to \
                                 guess a destination"
                                    .into(),
                            ));
                            continue;
                        }
                    }
                } else {
                    dest.join(&id[..2]).join(&id)
                };

                // D81 4c — THE OCCUPANT MAY BE ON ANOTHER VOLUME.
                //
                // Chris: "if something gets upgraded from data_ext it would get
                // written to Data, but then the system has to remove the extra
                // copy from data_ext. I'm not sure how to manage that just yet."
                //
                // Collision detection asked only whether the DESTINATION PATH
                // was occupied. Upgrade a title that lives on the cold volume
                // and the destination on the warm one is empty, so nothing was
                // detected: the new copy landed and the old one stayed, two
                // live copies of one tree path on two volumes, with nothing to
                // reconcile them. The fix is to ask the catalog rather than the
                // destination directory — same tree path, whichever root holds
                // it — which turns this from a special case into the ordinary
                // one the D76 ladder already decides.
                //
                // The loser is trashed ON ITS OWN VOLUME. `move_to_trash`
                // refuses a file outside the root it is given, which is what
                // stops a 20GB cold title being copied across filesystems to
                // reach the warm volume's trash.
                let mut superseded_elsewhere = false;
                if tree_roots.contains(&root) {
                    for (cand, cand_root) in at_a_root.iter().zip(library_dirs.iter()) {
                        if cand == &cpath || !cand.exists() {
                            continue;
                        }
                        let cand_uri = pvfs_core::storage::path_to_uri(cand)?;
                        let Some(occupant) = engine.location_owner(&cand_uri)? else {
                            continue;
                        };
                        if occupant == id {
                            continue;
                        }
                        match decide_collision(engine, &id, &occupant, rules) {
                            Some((incoming_wins, verdict)) if incoming_wins => {
                                if dry_run {
                                    report.planned.push(format!(
                                        "WOULD TRASH  {} (on another root; lost: {})",
                                        cand.display(),
                                        verdict.reason()
                                    ));
                                } else if let Err(e) =
                                    pvfs_core::sync::move_to_trash(cand_root, cand)
                                {
                                    report.failed.push((label.clone(), e.to_string()));
                                    superseded_elsewhere = true;
                                    break;
                                } else if let Err(e) = retire_loser(engine, &occupant, cand) {
                                    report.failed.push((label.clone(), e.to_string()));
                                }
                            }
                            Some((_, verdict)) => {
                                report.failed.push((
                                    label.clone(),
                                    format!(
                                        "the copy already at {} wins — {}",
                                        cand.display(),
                                        verdict.reason()
                                    ),
                                ));
                                superseded_elsewhere = true;
                                break;
                            }
                            None => {
                                report.failed.push((
                                    label.clone(),
                                    format!(
                                        "{} holds another live copy of this same tree path; {}",
                                        cand.display(),
                                        match rules {
                                            Some(_) => "the rules could not separate them, so a human decides which survives",
                                            None => "copy-selection rules are off (`--rules`), so a human decides which survives",
                                        }
                                    ),
                                ));
                                superseded_elsewhere = true;
                                break;
                            }
                        }
                    }
                }
                if superseded_elsewhere {
                    continue;
                }

                // An occupied destination is decided by the LIVE CATALOG, never
                // by overwriting on faith (D71 W5). Replacing IS the normal
                // upgrade — quality is not in the filename, so a 720p file and
                // its 1080p replacement share a name — but only when the bytes
                // there are not some OTHER live node's, and not a file the
                // catalog has never seen.
                if tree_roots.contains(&root) && cpath.exists() {
                    let occupant_uri = pvfs_core::storage::path_to_uri(&cpath)?;
                    match engine.location_owner(&occupant_uri)? {
                        // Our own older copy: this is the upgrade. The old
                        // bytes still go to the trash rather than under the
                        // rename — once evict has reclaimed the ingest copy
                        // this is the ONLY copy, and an automated overwrite
                        // that turns out to be wrong is unrecoverable
                        // (D71 W5, Chris: build in the safety).
                        Some(owner) if owner == id => {
                            if dry_run {
                                report.planned.push(format!(
                                    "WOULD TRASH  {} (replaced in place)",
                                    cpath.display()
                                ));
                            } else if let Err(e) = pvfs_core::sync::move_to_trash(&dest, &cpath) {
                                report.failed.push((label, e.to_string()));
                                continue;
                            }
                        }
                        Some(occupant) => {
                            // D76 — TWO LIVE COPIES CLAIM ONE PATH. This is the
                            // upgrade case: same name, different bytes, because
                            // quality is not in the filename.
                            //
                            // Refusing is still the DEFAULT and still the right
                            // answer when nothing can separate them. The rules
                            // only ever replace "I will not guess" with "here is
                            // why", and the loser goes to TRASH, never to
                            // unlink.
                            match decide_collision(engine, &id, &occupant, rules) {
                                Some((incoming_wins, verdict)) if incoming_wins => {
                                    if dry_run {
                                        report.planned.push(format!(
                                            "WOULD REPLACE {label}  ({})",
                                            verdict.reason()
                                        ));
                                        report.planned.push(format!(
                                            "WOULD TRASH  {} (lost: {})",
                                            cpath.display(),
                                            verdict.reason()
                                        ));
                                        continue;
                                    }
                                    eprintln!("tier: {label} replaces the copy in place — {}", verdict.reason());
                                    if let Err(e) = pvfs_core::sync::move_to_trash(&dest, &cpath) {
                                        report.failed.push((label, e.to_string()));
                                        continue;
                                    }
                                    // Without this the loser kept a location
                                    // naming `cpath` — which the winner is
                                    // about to be written to. Two nodes, one
                                    // path, and the stale one pointing at the
                                    // other's bytes.
                                    if let Err(e) = retire_loser(engine, &occupant, &cpath) {
                                        report.failed.push((label, e.to_string()));
                                        continue;
                                    }
                                }
                                Some((_, verdict)) => {
                                    // The copy already there wins. Not a
                                    // failure — a decision, and it must read
                                    // like one.
                                    report.failed.push((
                                        label,
                                        format!(
                                            "the copy already at {} wins — {}",
                                            cpath.display(),
                                            verdict.reason()
                                        ),
                                    ));
                                    continue;
                                }
                                None => {
                                    report.failed.push((
                                        label,
                                        format!(
                                            "{} is another live file's bytes — refusing to \
                                             overwrite; {}",
                                            cpath.display(),
                                            match rules {
                                                Some(_) => "the rules could not separate them",
                                                None => "copy-selection rules are off \
                                                         (`--rules`), so the old entry must be \
                                                         deleted first",
                                            }
                                        ),
                                    ));
                                    continue;
                                }
                            }
                        }
                        None => {
                            report.failed.push((
                                label,
                                format!(
                                    "{} exists but the catalog has never seen it — \
                                     refusing to overwrite an unknown file",
                                    cpath.display()
                                ),
                            ));
                            continue;
                        }
                    }
                }
                let mut planned_place: Option<String> = None;
                if let Err(e) = (|| -> Result<(), PvfsError> {
                    // DRY RUN STOPS HERE — first statement in the closure, on
                    // purpose.
                    //
                    // It used to sit further down, just before the atomic
                    // publish, which looked like "before anything is written".
                    // It was not: D71's same-filesystem MOVE optimisation runs
                    // above that point, so a dry run RENAMED the file into the
                    // store. Caught by the test that diffs the store rather
                    // than trusting the report — the plan said "would place"
                    // while the file had already moved.
                    if dry_run {
                        planned_place = Some(cpath.display().to_string());
                        return Ok(());
                    }
                    if let Some(dir) = cpath.parent() {
                        std::fs::create_dir_all(dir)
                            .map_err(|e| PvfsError::io("create central dir", e))?;
                    }

                    // D71 — MOVE, don't re-copy, when the bytes are already on
                    // this filesystem under a different name.
                    //
                    // A rename changes a file's tree path, and under tree
                    // layout that means its destination changes too. Streaming
                    // it through `cat` costs minutes for a 40 GB episode; a
                    // same-filesystem `rename` costs milliseconds. Renaming a
                    // SEASON folder moves every episode beneath it, so without
                    // this a folder rename is unusable.
                    //
                    // Only for `central` (migrate). A mirror keeps its source
                    // by definition, so moving it would be exactly wrong.
                    if !keep {
                        let here: Option<std::path::PathBuf> = engine
                            .locations(&id)?
                            .iter()
                            .filter_map(|u| pvfs_core::storage::uri_to_path(u).ok())
                            .find(|p| p != &cpath && p.is_file());
                        if let Some(old) = here {
                            if std::fs::rename(&old, &cpath).is_ok() {
                                engine
                                    .add_location(&id, &pvfs_core::storage::path_to_uri(&cpath)?)?;
                                let old_uri = pvfs_core::storage::path_to_uri(&old)?;
                                engine.remove_location(&id, &old_uri)?;
                                // Tidy the directories the move emptied. A
                                // renamed show otherwise leaves `Rename Show/
                                // Season 02/` standing beside
                                // `Rename Show (2019)/Season 02/`, and Plex
                                // shows an empty series. `remove_dir` only
                                // succeeds on an EMPTY directory, so this can
                                // never take anything with it — and it stops at
                                // the placement root.
                                let mut dir = old.parent().map(|p| p.to_path_buf());
                                while let Some(d) = dir {
                                    if d == dest || !d.starts_with(&dest) {
                                        break;
                                    }
                                    if std::fs::remove_dir(&d).is_err() {
                                        break; // not empty — leave it alone
                                    }
                                    dir = d.parent().map(|p| p.to_path_buf());
                                }
                                return Ok(());
                            }
                            // Different filesystem (EXDEV) or otherwise
                            // refused: fall through to the honest copy.
                        }
                    }
                    // Publish atomically: a 40 GB copy written under its final name would
                    // be visible to Plex half-transferred, and a failed transfer would
                    // leave a broken file under the real name. Same directory, so the
                    // rename is instant and the upgrade swap has no visible window.
                    let tmp = cpath.with_file_name(format!(".{id}.tmp"));
                    let mut f = std::fs::File::create(&tmp)
                        .map_err(|e| PvfsError::io("create central copy", e))?;
                    if let Err(e) = engine.cat(&id, None, &mut f) {
                        let _ = std::fs::remove_file(&tmp);
                        return Err(e);
                    }
                    std::fs::rename(&tmp, &cpath)
                        .map_err(|e| PvfsError::io("place central copy", e))?;
                    // D75: on a REPLICA the catalog is the owner's to write, so
                    // the row is ROUTED there — and pin-qualified, because a
                    // bare file:// path is host-implicit and this copy lives on
                    // a specific box. That is what makes the fleet able to dial
                    // the holder for these bytes, and what lets the controller
                    // see the copy exists before telling the edge to reclaim.
                    let cpath_uri = pvfs_core::storage::path_to_uri(&cpath)?;
                    if pull_only {
                        let (client, sign) = route.as_mut().ok_or_else(|| PvfsError::BadInput {
                            field: "tier".into(),
                            reason: "a replica must route its writes to the owner, but no \
                                     route is available — check the owner is reachable"
                                .into(),
                        })?;
                        let qualified = match &own_pin {
                            Some(pin) => format!("pvfs-host://{pin}{}", cpath.display()),
                            None => cpath_uri.clone(),
                        };
                        client
                            .add_location(&id, &qualified, |d| sign(d))
                            .map_err(|e| PvfsError::BadInput {
                                field: "tier".into(),
                                reason: e.to_string(),
                            })?;
                    } else {
                        engine.add_location(&id, &cpath_uri)?;
                    }
                    // F5.5: the attributed row — the serving instance's view
                    // of the same store file (same aa/<id> layout under its
                    // remote prefix), so consumers dial IT for these bytes.
                    if let Some((pin, prefix)) = serve_as.get(&root) {
                        let remote = prefix.join(&id[..2]).join(&id);
                        engine
                            .add_location(&id, &pvfs_core::storage::host_uri(pin, &remote)?)?;
                    }
                    Ok(())
                })() {
                    report.failed.push((label, e.to_string()));
                    continue;
                }
                report.migrated += 1;
                if let Some(dest_shown) = planned_place {
                    report
                        .planned
                        .push(format!("WOULD PLACE  {label}  ->  {dest_shown}"));
                    // Nothing was written, so nothing downstream applies.
                    continue;
                }
            }
            // MIRROR kind (central-keep, P8): the copy is the whole point —
            // nothing is ever retired, the source keeps serving, and the
            // logged store location doubles as a future swarm seed.
            // A replica places and advertises; retiring another box's location
            // is the owner's call, so it stops here.
            if keep || pull_only {
                continue;
            }
            // central copy live → retire foreign-instance locations, plus —
            // for a migrate-kind binding — the staging dir's own file:// ones
            for u in engine.locations(&id)? {
                // F5.5: the serving instance's attribution rows for THIS
                // subtree's store are ours, not edge copies — retiring
                // them would undo the row logged moments ago. Precise
                // exemption: that pin AND a path inside the remote store
                // prefix; the same instance's other paths retire as ever.
                let served_row = serve_as.get(&root).is_some_and(|(pin, prefix)| {
                    matches!(
                        pvfs_core::storage::parse_host_uri(&u),
                        Some((p, path)) if p == pin
                            && std::path::Path::new(path).starts_with(prefix)
                    )
                });
                let foreign = !served_row
                    && matches!(
                        pvfs_core::storage::parse_host_uri(&u),
                        Some((pin, _)) if own_pin.as_deref() != Some(pin)
                    );
                // A location that IS the central store is never "staged".
                //
                // Staging drains because a migrate binding stages bytes
                // LOCALLY and the mover then copies them to a SEPARATE central
                // store — once the central copy exists the staged one is
                // redundant. When the binding's source and the store are the
                // SAME directory, there is nowhere to drain to, and this
                // retired the very locations that made those files central:
                // the mover ate its own tail. 27,562 locations went in one
                // pass, leaving 26,729 files catalogued with no live location
                // while every byte sat untouched on disk.
                //
                // Adopting an existing store (D74) makes source == store the
                // NORMAL case, so this is a guard the drain logic always
                // needed and never had.
                let staged = staging_prefixes.iter().any(|p| u.starts_with(p))
                    && !u.starts_with(&dest_prefix);
                if foreign || staged {
                    if dry_run {
                        report
                            .planned
                            .push(format!("WOULD RETIRE {label}  ->  {u}"));
                        report.retired += 1;
                        continue;
                    }
                    match engine.remove_location(&id, &u) {
                        Ok(()) => report.retired += 1,
                        Err(e) => report.failed.push((id.clone(), e.to_string())),
                    }
                }
            }
        }
    }
    Ok(Some(report))
}

/// F5.7 (doc 17 §7.8): the well-known endpoint directory —
/// `<root>/.fleet/endpoints/<pin>` with a `host:port` payload.
pub const FLEET_DIR: &str = ".fleet";
pub const ENDPOINTS_DIR: &str = "endpoints";
/// `<root>/.fleet/versions/<pin>` — what each box RUNS, announced by that box.
///
/// D72 Part C: the fleet has to be able to answer "is every box on the same
/// format?" from the forest itself, not from a control host with SSH. A box
/// that can read the catalog can read the fleet's spread, which is what makes
/// a format flip safe to decide anywhere.
pub const VERSIONS_DIR: &str = "versions";

/// Read the catalog-published endpoint directory: pin → dial address.
/// Missing directory = empty map (the fleet simply hasn't announced).
pub fn catalog_endpoints(engine: &Engine) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let step = |parent: &str, label: &str| -> Option<String> {
        engine
            .children(&parent.to_string())
            .ok()?
            .into_iter()
            .find(|c| c.label == label)
            .map(|c| c.node.id)
    };
    let root = engine.identity.root_node_id.clone();
    let Some(fleet) = step(&root, FLEET_DIR) else { return out };
    let Some(eps) = step(&fleet, ENDPOINTS_DIR) else { return out };
    for c in engine.children(&eps).unwrap_or_default() {
        if let Ok(addr) = String::from_utf8(c.node.payload) {
            let addr = addr.trim().to_string();
            if !addr.is_empty() {
                out.insert(c.label, addr);
            }
        }
    }
    out
}

/// Fetch missing bytes under `roots`, streaming each file into the managed
/// sync store (hash-verified on commit). Returns `(fetched, failures)` —
/// per-file failures never abort the pass.
pub fn sync_pull(
    engine: &mut Engine,
    fetcher: &mut Fetcher,
    roots: &[String],
) -> Result<(u64, Vec<(String, String)>), PvfsError> {
    let mut fetched = 0u64;
    let mut failed = Vec::new();
    for root in roots {
        for (id, label) in engine.missing_bytes(root)? {
            match fetcher.fetch(engine, &id) {
                Ok(()) => fetched += 1,
                Err(e) => failed.push((label, e)),
            }
        }
    }
    Ok((fetched, failed))
}


/// P9.1 (doc 22 §2): shared progress of a chunked background fetch — which
/// chunks are verified-present in the partial, and how it ended. The mount's
/// read path waits on this to serve bytes the moment their chunks land.
pub struct SwarmProgress {
    state: std::sync::Mutex<ProgressState>,
    cv: std::sync::Condvar,
}

#[derive(Default)]
struct ProgressState {
    size: u64,
    chunk: u64,
    part: Option<PathBuf>,
    done: Vec<bool>,
    finished: Option<Result<PathBuf, String>>,
}

impl Default for SwarmProgress {
    fn default() -> Self {
        SwarmProgress {
            state: std::sync::Mutex::new(ProgressState::default()),
            cv: std::sync::Condvar::new(),
        }
    }
}

impl SwarmProgress {
    fn set_layout(&self, size: u64, chunk: u64, n: usize, part: PathBuf) {
        let mut st = self.state.lock().unwrap();
        st.size = size;
        st.chunk = chunk;
        st.part = Some(part);
        st.done = vec![false; n];
        self.cv.notify_all();
    }

    fn mark(&self, idx: usize) {
        let mut st = self.state.lock().unwrap();
        if let Some(d) = st.done.get_mut(idx) {
            *d = true;
        }
        self.cv.notify_all();
    }

    fn finish(&self, r: Result<PathBuf, String>) {
        let mut st = self.state.lock().unwrap();
        st.finished = Some(r);
        self.cv.notify_all();
    }

    /// Whether the fetch ended in failure. The mount consults this on
    /// open so a failed background fetch is retried instead of serving
    /// its cached error to every later reader until remount.
    pub fn failed(&self) -> bool {
        self.state
            .lock()
            .map(|st| st.finished.as_ref().is_some_and(|r| r.is_err()))
            .unwrap_or(false)
    }

    /// Wait until the chunks covering `[off, off+len)` are verified-present.
    /// `Ok(path)` names where to read: the published file once finished, else
    /// the partial. Errors when the fetch failed or `timeout` lapsed.
    pub fn wait_range(
        &self,
        off: u64,
        len: u64,
        timeout: std::time::Duration,
    ) -> Result<PathBuf, String> {
        let deadline = std::time::Instant::now() + timeout;
        let mut st = self.state.lock().unwrap();
        loop {
            if let Some(fin) = &st.finished {
                return fin.clone();
            }
            if st.chunk > 0 {
                let size = st.size;
                let chunk = st.chunk;
                let first = (off.min(size) / chunk) as usize;
                let last = (off.saturating_add(len).min(size).saturating_sub(1) / chunk) as usize;
                let covered = len == 0
                    || off >= size
                    || (first..=last).all(|i| st.done.get(i).copied().unwrap_or(false));
                if covered {
                    if let Some(p) = &st.part {
                        return Ok(p.clone());
                    }
                }
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err("timed out waiting for chunks".into());
            }
            let (g, _) = self.cv.wait_timeout(st, left).unwrap();
            st = g;
        }
    }
}

/// P9.1: the mount's background fetch — its OWN engine and fetcher (transient
/// opens are cheap since the live-writer flock), chunked even with one holder,
/// attested-manifest required; falls back to a blocking whole-file fetch for
/// anything ineligible. Marks `progress` throughout and finishes it with the
/// published path or the error.
pub fn fetch_streaming(data_dir: &std::path::Path, id: &str, progress: &SwarmProgress) {
    let result = (|| -> Result<PathBuf, String> {
        let mut engine = Engine::open(data_dir).map_err(|e| e.to_string())?;
        let mut fetcher = Fetcher::new(data_dir);
        let candidates = fetcher.candidates(&engine, id);
        if candidates.is_empty() {
            return Err("no reachable source holds this file".into());
        }
        match fetcher.swarm_fetch_opts(&mut engine, id, &candidates, 1, Some(progress)) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                // ineligible or failed mid-swarm: the blocking path (any
                // partial stays for a later resume)
                fetcher.fetch(&mut engine, id)?;
            }
        }
        engine
            .readable_path(&id.to_string())
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "fetched but not readable".into())
    })();
    progress.finish(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    // The mount's evict-on-failure check (doc 22 wart fix): only a fetch
    // that ended in error reads as failed — in-flight and successful ones
    // stay reusable.
    #[test]
    fn failed_reads_only_error_finishes() {
        let p = SwarmProgress::default();
        assert!(!p.failed(), "in-flight is not failed");
        p.finish(Ok(PathBuf::from("/tmp/x")));
        assert!(!p.failed(), "success is not failed");
        let q = SwarmProgress::default();
        q.finish(Err("no holders".into()));
        assert!(q.failed(), "an error finish is");
    }
}
