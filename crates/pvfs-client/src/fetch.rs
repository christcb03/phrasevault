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
