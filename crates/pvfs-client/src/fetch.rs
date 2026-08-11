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
    /// candidate's failure (or why there were none).
    pub fn fetch(&mut self, engine: &mut Engine, id: &str) -> Result<(), String> {
        let candidates = self.candidates(engine, id);
        if candidates.is_empty() {
            return Err("no reachable source holds this file (register the holding \
                        instance with `pvfs instance add`)"
                .into());
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
        Err(last_err)
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
    let central = pvfs_core::sync::load_central(&data_dir)?;
    if central.is_empty() {
        return Ok(None);
    }
    let own_pin = pvfs_core::storage::host_pin(&data_dir);
    let mut report = TierReport::default();
    for (root, dest) in central {
        for entry in engine.walk(&root)?.entries {
            if entry.node.node_type != pvfs_core::TYPE_FILE {
                continue;
            }
            let id = entry.node.id;
            let label = entry.node.label;
            let has_central = engine
                .locations(&id)?
                .iter()
                .any(|u| logged_local_location(u, &own_pin));
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
            // central copy live → retire foreign-instance locations
            for u in engine.locations(&id)? {
                if let Some((pin, _)) = pvfs_core::storage::parse_host_uri(&u) {
                    if own_pin.as_deref() != Some(pin) {
                        match engine.remove_location(&id, &u) {
                            Ok(()) => report.retired += 1,
                            Err(e) => report.failed.push((id.clone(), e.to_string())),
                        }
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
