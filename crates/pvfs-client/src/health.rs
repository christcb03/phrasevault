//! D131 (doc 26 phase 7; D83 §4 piece 1) — observation. One box asks every
//! announced peer for its health, records what it saw, and the record says
//! "down since" instead of a human noticing ten hours later. Read-only: a
//! probe is `info` + `serve status` over the existing member-gated dial.
//! Notification and restart (D83 §4.2, §4.3) are not here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use pvfs_core::{Engine, PvfsError, ReplicaSource};

use crate::follow::dial_source;

/// Consecutive missed polls before a peer is called DOWN (D83 §4.2: a
/// daemon restarting — a minute, with its drain — must not read as an
/// outage). The first miss dates `unreachable_since`, so the duration is
/// honest once it is called.
pub const DOWN_AFTER: u32 = 2;

const FILE: &str = "fleet-health.json";

/// One serve job as the peer reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHealth {
    pub name: String,
    pub state: String,
    pub last_ok_ms: Option<u64>,
    pub last_error: Option<String>,
}

/// What one probe saw — or why it saw nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHealth {
    /// The dial and the auth succeeded.
    pub reachable: bool,
    /// It serves OUR forest (a re-used address is not a peer).
    pub forest_ok: bool,
    pub runner: String,
    pub jobs: Vec<JobHealth>,
    /// D127: conflicting view paths there.
    pub conflicts: u64,
    /// D129: catalogue regions it holds a superseded snapshot of.
    pub stale: u64,
    /// D131: `(free, total)` bytes of the filesystem under its sync store.
    pub capacity: Option<(u64, u64)>,
    /// D148: each region's trash on that box, as its last purge pass left it.
    #[serde(default)]
    pub trash: Vec<pvfs_proto::TrashWire>,
    /// PVOS D178: every filesystem that box stores on (empty from an older daemon).
    #[serde(default)]
    pub stores: Vec<pvfs_proto::StoreWire>,
    /// PVOS D181: the view mounts running on that box, each with the build it
    /// is on and whether that is older than its daemon's — what tells the
    /// fleet a mount has not yet moved to a new build (it moves when nothing
    /// is open through it: Plex streams through mediabox's).
    #[serde(default)]
    pub mounts: Vec<pvfs_proto::MountWire>,
    /// PVOS D182: that box's top-log tip (absent from an older daemon).
    #[serde(default)]
    pub log: Option<pvfs_proto::LogTipWire>,
    /// PVOS D182: what THIS box concluded from `log` against its own log —
    /// `consistent`, `ahead` (this box is stale: it fences itself) or
    /// `diverged` (that box is on another branch). Absent without a tip.
    #[serde(default)]
    pub log_verdict: Option<String>,
    /// PVOS D182: that box says it is a fenced owner.
    #[serde(default)]
    pub fenced: Option<pvfs_proto::FenceWire>,
    /// PVOS D182: that box's last dated copy of the log, when it makes them.
    #[serde(default)]
    pub backup: Option<pvfs_proto::BackupWire>,
    pub error: Option<String>,
}

impl PeerHealth {
    pub fn ok(&self) -> bool {
        self.reachable && self.forest_ok
    }
}

/// What the record holds per announced peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub addr: String,
    /// From `.fleet/versions/<pin>`, when announced.
    pub version: Option<String>,
    pub last_attempt_ms: u64,
    pub last_ok_ms: Option<u64>,
    /// The first miss of the current streak.
    pub unreachable_since_ms: Option<u64>,
    /// Consecutive misses.
    pub misses: u32,
    pub last: PeerHealth,
    /// D135 — what the owner did about a silence (`start` over the
    /// supervise channel), newest last; absent on records written before.
    #[serde(default)]
    pub actions: Vec<crate::supervise::Action>,
    /// D135 — starts sent during the current outage (the backoff's input);
    /// reset when the peer answers.
    #[serde(default)]
    pub attempts: u32,
}

impl PeerRecord {
    /// "Its daemon is not answering" — which D83 §2 shows is not the same
    /// as "its process is gone"; the CLI words it that way.
    pub fn is_down(&self) -> bool {
        self.misses >= DOWN_AFTER
    }
}

/// The fleet as last observed from this box: `<data>/fleet-health.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHealth {
    pub polled_at_ms: u64,
    /// By transport pin (the endpoint directory's key), sorted.
    pub peers: BTreeMap<String, PeerRecord>,
    /// PVOS D182: THIS box's own fence at the end of the poll — what the
    /// notifier compares to say `owner_fenced` / `owner_unfenced` once.
    #[serde(default)]
    pub fenced: Option<pvfs_proto::FenceWire>,
    /// PVOS D182: this box's own announced address (from the catalogue), so a
    /// notification about this box can name it.
    #[serde(default)]
    pub self_addr: Option<String>,
    /// PVOS D182: this box's own top-log tip seq at the end of the poll — the
    /// page reads each follower's lag against it.
    #[serde(default)]
    pub self_log_seq: Option<u64>,
}

impl FleetHealth {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(FILE)
    }

    /// The record, or `None` when this box has never polled.
    pub fn load(data_dir: &Path) -> Result<Option<FleetHealth>, PvfsError> {
        let p = Self::path(data_dir);
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(PvfsError::io("read fleet health", e)),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| PvfsError::BadInput {
                field: "fleet-health".into(),
                reason: format!("unreadable record ({e}) — delete {} to start over", p.display()),
            })
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), PvfsError> {
        let p = Self::path(data_dir);
        let tmp = p.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self).map_err(|e| PvfsError::BadInput {
            field: "fleet-health".into(),
            reason: e.to_string(),
        })?;
        std::fs::write(&tmp, text).map_err(|e| PvfsError::io("write fleet health", e))?;
        std::fs::rename(&tmp, &p).map_err(|e| PvfsError::io("write fleet health", e))
    }

    /// Fold one probe into the record (the `DOWN_AFTER` rule).
    pub fn observe(&mut self, pin: &str, addr: &str, version: Option<String>, now_ms: u64, health: PeerHealth) {
        let rec = self.peers.entry(pin.to_string()).or_default();
        rec.addr = addr.to_string();
        if version.is_some() {
            rec.version = version;
        }
        rec.last_attempt_ms = now_ms;
        if health.ok() {
            rec.last_ok_ms = Some(now_ms);
            rec.misses = 0;
            rec.unreachable_since_ms = None;
            rec.attempts = 0;
        } else {
            if rec.misses == 0 {
                rec.unreachable_since_ms = Some(now_ms);
            }
            rec.misses = rec.misses.saturating_add(1);
        }
        rec.last = health;
        self.polled_at_ms = now_ms;
    }

    /// Peers currently called down.
    pub fn down(&self) -> Vec<(&String, &PeerRecord)> {
        self.peers.iter().filter(|(_, r)| r.is_down()).collect()
    }
}

/// Probe one peer: dial with the client identity, `info`, `serve status`.
/// Never errors — what went wrong is in `error`, and a dial is bounded by
/// the socket timeout.
pub fn probe_peer(src: &ReplicaSource, want_forest: &str) -> PeerHealth {
    let mut h = PeerHealth::default();
    let mut client = match dial_source(src) {
        Ok(c) => c,
        Err(e) => {
            h.error = Some(e.to_string());
            return h;
        }
    };
    h.reachable = true;
    match client.info() {
        Ok(info) if info.forest_id == want_forest => h.forest_ok = true,
        Ok(info) => {
            h.error = Some(format!("serves forest {} — not ours", info.forest_id));
            return h;
        }
        Err(e) => {
            h.error = Some(format!("info: {e}"));
            return h;
        }
    }
    match client.serve_status_full() {
        Ok(s) => {
            h.runner = s.runner;
            h.jobs = s
                .jobs
                .into_iter()
                .map(|j| JobHealth {
                    name: j.name,
                    state: j.state,
                    last_ok_ms: j.last_ok_ms,
                    last_error: j.last_error,
                })
                .collect();
            h.conflicts = s.conflicts;
            h.stale = s.stale;
            h.capacity = s.capacity.map(|c| (c.free_bytes, c.total_bytes));
            h.trash = s.trash;
            h.stores = s.stores;
            h.mounts = s.mounts;
            h.log = s.log;
            h.fenced = s.fenced;
            h.backup = s.backup;
        }
        Err(e) => h.error = Some(format!("serve status: {e}")),
    }
    h
}

/// `.fleet/versions/<pin>` → what that box announced it runs.
pub fn catalog_versions(engine: &Engine) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let step = |parent: &str, label: &str| -> Option<String> {
        engine
            .children(&parent.to_string())
            .ok()?
            .into_iter()
            .find(|c| c.label == label)
            .map(|c| c.node.id)
    };
    let root = engine.identity.root_node_id.clone();
    let Some(fleet) = step(&root, crate::fetch::FLEET_DIR) else { return out };
    let Some(vers) = step(&fleet, crate::fetch::VERSIONS_DIR) else { return out };
    for c in engine.children(&vers).unwrap_or_default() {
        out.insert(c.label, String::from_utf8_lossy(&c.node.payload).trim().to_string());
    }
    out
}

/// PVOS D182 §3.3a — the announced endpoints (pins) whose word may fence
/// this owner: those announced by a key holding admin on the forest root.
pub fn trusted_announcers(engine: &Engine) -> std::collections::HashSet<String> {
    crate::fetch::catalog_endpoint_authors(engine)
        .into_iter()
        .filter(|(_, author)| engine.may_fence_owner(author).unwrap_or(false))
        .map(|(pin, _)| pin)
        .collect()
}

/// One poll of every announced peer (minus this box), folded into the
/// record on disk. Honours `cancel` between peers (D123).
pub fn poll_fleet(data_dir: &Path, cancel: &AtomicBool) -> Result<FleetHealth, PvfsError> {
    let engine = Engine::open(data_dir)?;
    let forest = engine.identity.forest_id.clone();
    let own = pvfs_core::storage::host_pin(data_dir);
    let all = crate::fetch::catalog_endpoints(&engine);
    let self_addr = own.as_deref().and_then(|p| all.get(p).cloned());
    let endpoints: BTreeMap<String, String> = all
        .into_iter()
        .filter(|(pin, _)| own.as_deref() != Some(pin.as_str()))
        .collect();
    let versions = catalog_versions(&engine);
    // §3.3a: a peer's longer log fences this owner only when the key that
    // announced it holds admin on the forest root.
    let trusted = trusted_announcers(&engine);
    engine.close()?;
    let mut record = FleetHealth::load(data_dir)?.unwrap_or_default();
    for (pin, addr) in endpoints {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        let src = ReplicaSource {
            transport: "tcp".into(),
            target: addr.clone(),
            pin: pin.clone(),
            region: String::new(),
        };
        let mut health = probe_peer(&src, &forest);
        judge_tip(data_dir, &addr, trusted.contains(&pin), &mut health);
        record.observe(&pin, &addr, versions.get(&pin).cloned(), now_ms(), health);
    }
    record.fenced = pvfs_core::fence::load(data_dir).map(|f| pvfs_proto::FenceWire {
        reason: f.reason,
        peer: f.peer,
        peer_seq: f.peer_seq,
        own_seq: f.own_seq,
        at_ms: f.at_ms,
    });
    record.self_addr = self_addr;
    record.self_log_seq = pvfs_core::mount::peek_tip(data_dir).ok().map(|(seq, _)| seq);
    record.save(data_dir)?;
    Ok(record)
}

/// PVOS D182 — the fence rule for one probed peer: its tip against this
/// box's log. A peer AHEAD of this owner proves it stale and fences it
/// (`pvfs_core::fence::check_peer`) — when `trusted` (§3.3a: announced by a
/// key with admin on the root); an untrusted one is only marked
/// `ahead-unproven`. One on another branch is only marked (the notifier says
/// so; the owner refuses its writes as they come).
fn judge_tip(data_dir: &Path, addr: &str, trusted: bool, health: &mut PeerHealth) {
    let Some(t) = health.log.as_ref().filter(|_| health.ok()) else { return };
    let Ok(hash) = hex::decode(&t.hash) else { return };
    match pvfs_core::fence::check_peer(data_dir, addr, t.seq, &hash, trusted) {
        Ok((v, _)) => {
            health.log_verdict = Some(
                match v {
                    pvfs_core::fence::TipVerdict::Consistent => "consistent",
                    pvfs_core::fence::TipVerdict::Ahead if trusted => "ahead",
                    pvfs_core::fence::TipVerdict::Ahead => "ahead-unproven",
                    pvfs_core::fence::TipVerdict::Diverged => "diverged",
                }
                .into(),
            )
        }
        Err(e) => eprintln!("pvfs: health: could not judge {addr}'s log tip: {e}"),
    }
}

/// PVOS D182 — the record `pvfs forest backup` leaves in the data dir: the
/// last dated copy of the log, whether it verified, and why not.
pub const BACKUP_STATE_FILE: &str = "backup-state.json";

/// PVOS D182 — that record, if this box has ever made a copy.
pub fn load_backup_state(data_dir: &Path) -> Option<pvfs_proto::BackupWire> {
    let text = std::fs::read_to_string(data_dir.join(BACKUP_STATE_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
