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
}

impl Fetcher {
    pub fn new(data_dir: &std::path::Path) -> Fetcher {
        Fetcher {
            pool: HashMap::new(),
            dead: HashSet::new(),
            instances: load_instances().unwrap_or_default(),
            source: ReplicaSource::load(data_dir).ok(),
        }
    }

    /// Whether ANY source could serve fetches: a recorded replica source or
    /// at least one registered instance. False means a pass cannot succeed.
    pub fn has_any_source(&self) -> bool {
        self.source.is_some() || !self.instances.is_empty()
    }

    /// Where `id`'s bytes might be fetched from, best candidate first.
    fn candidates(&self, engine: &Engine, id: &str) -> Vec<ReplicaSource> {
        let mut out: Vec<ReplicaSource> = Vec::new();
        for loc in engine.locations(&id.to_string()).unwrap_or_default() {
            if let Some((pin, _path)) = pvfs_core::storage::parse_host_uri(&loc) {
                if let Some((_, addr, _)) = self.instances.iter().find(|(_, _, p)| p == pin) {
                    out.push(ReplicaSource {
                        transport: "tcp".into(),
                        target: addr.clone(),
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
                    Err(e) => last_err = e.to_string(),
                },
                Err(e) => {
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
        if holders.len() < 2 {
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
            return Err(format!(
                "{leftover} chunk(s) unfetched — every holder failed; partial kept for resume"
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
}

/// One mover pass, owner-side (F5.3, shared by `pvfs tier` and the daemon's
/// `tier` job): ensure a verified central copy for every file under a
/// `central`-placed subtree — satisfied in place by the owner's own disks,
/// else fetched (locally or by read-through) and streamed into the store —
/// then retire foreign-instance locations. `Ok(None)` = nothing placed
/// central (a clean no-op for the job; the CLI turns it into guidance).
pub fn tier_pass(
    engine: &mut Engine,
    fetcher: &mut Fetcher,
) -> Result<Option<TierReport>, PvfsError> {
    if engine.is_replica() {
        return Err(PvfsError::BadInput {
            field: "tier".into(),
            reason: "the mover runs on the owner — edges reclaim space with `pvfs evict`".into(),
        });
    }
    let data_dir = engine.data_dir().to_path_buf();
    let central = pvfs_core::sync::load_central_all(&data_dir)?;
    if central.is_empty() {
        return Ok(None);
    }
    let own_pin = pvfs_core::storage::host_pin(&data_dir);
    let mut report = TierReport::default();
    for (root, dest, keep) in central {
        // P8 (doc 21): a MIGRATE-kind binding's own staging dir drains too —
        // its file:// locations retire once the central copy is live, and the
        // evict pass then reclaims the staged bytes. Resolved per root from
        // the binding, so in-place binds elsewhere are never touched.
        let staging_prefix: Option<String> = if keep {
            None
        } else {
            // trailing slash: "file:///a/b" must not match "file:///a/bXX/…"
            engine
                .binding_for(&root)?
                .map(|b| format!("{}/", b.source_uri.trim_end_matches('/')))
        };
        for entry in engine.walk(&root)?.entries {
            if entry.node.node_type != pvfs_core::TYPE_FILE {
                continue;
            }
            let id = entry.node.id;
            let label = entry.node.label;
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
            let has_central = engine.locations(&id)?.iter().any(|u| {
                if keep {
                    u.starts_with(&dest_prefix)
                } else {
                    logged_local_location(u, &own_pin)
                        && !staging_prefix.as_deref().is_some_and(|p| u.starts_with(p))
                }
            });
            if has_central {
                report.satisfied += 1;
            } else {
                // reach the bytes (locally or via read-through)…
                if engine.readable_path(&id)?.is_none() {
                    if let Err(e) = fetcher.fetch(engine, &id) {
                        report.failed.push((label, e));
                        continue; // never retire without a central copy
                    }
                }
                // …then land a verified copy in the central store
                let cpath = dest.join(&id[..2]).join(&id);
                if let Err(e) = (|| -> Result<(), PvfsError> {
                    if let Some(dir) = cpath.parent() {
                        std::fs::create_dir_all(dir)
                            .map_err(|e| PvfsError::io("create central dir", e))?;
                    }
                    let tmp = cpath.with_file_name(format!(".{id}.tmp"));
                    let mut f = std::fs::File::create(&tmp)
                        .map_err(|e| PvfsError::io("create central copy", e))?;
                    if let Err(e) = engine.cat(&id, None, &mut f) {
                        let _ = std::fs::remove_file(&tmp);
                        return Err(e);
                    }
                    std::fs::rename(&tmp, &cpath)
                        .map_err(|e| PvfsError::io("place central copy", e))?;
                    engine.add_location(&id, &pvfs_core::storage::path_to_uri(&cpath)?)
                })() {
                    report.failed.push((label, e.to_string()));
                    continue;
                }
                report.migrated += 1;
            }
            // MIRROR kind (central-keep, P8): the copy is the whole point —
            // nothing is ever retired, the source keeps serving, and the
            // logged store location doubles as a future swarm seed.
            if keep {
                continue;
            }
            // central copy live → retire foreign-instance locations, plus —
            // for a migrate-kind binding — the staging dir's own file:// ones
            for u in engine.locations(&id)? {
                let foreign = matches!(
                    pvfs_core::storage::parse_host_uri(&u),
                    Some((pin, _)) if own_pin.as_deref() != Some(pin)
                );
                let staged = staging_prefix
                    .as_deref()
                    .is_some_and(|p| u.starts_with(p));
                if foreign || staged {
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
