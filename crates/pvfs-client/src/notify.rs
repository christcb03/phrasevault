//! D142 — the fleet tells a person when something changes (PVOS D83 §4.2,
//! piece 2).
//!
//! Everything is already observed (D131) and acted on (D135) in the owner's
//! `fleet-health.json`; this is the last metre. The owner POSTs a small JSON
//! event to a webhook — Home Assistant first — on TRANSITIONS only: a peer
//! going down, coming back, a `start` sent, a job's error appearing, and a
//! daily heartbeat so a silent owner is noticed by its absence. Transitions
//! only is the hysteresis D83 asked for; the two-miss rule supplies it.
//!
//! Transport is `curl` (the owner is a Linux box that has it), body on stdin,
//! ten-second timeout. A failure to notify is logged and never fails the
//! health pass. `PVFS_NOTIFY_CMD` replaces the command for tests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use pvfs_core::PvfsError;

use crate::health::FleetHealth;

const FILE: &str = "notify";
const STATE_FILE: &str = "notify-state.json";
/// One heartbeat a day: enough for "the owner has gone quiet" to mean
/// something, not enough to be noise.
pub const HEARTBEAT_EVERY_MS: u64 = 24 * 3600 * 1000;
/// How long a job's error must have been there, with the same text, before
/// it is said (D151). Health passes are two minutes apart, so this is the
/// third pass, about four minutes after the first sighting; the second pass
/// never reports. 3½ rather than 4 because `now` is stamped after the
/// probes finish, so the third pass can land a few seconds under 240 s.
pub const JOB_ERROR_AFTER_MS: u64 = 210_000;
pub const FORMATS: [&str; 5] = ["ha", "json", "slack", "discord", "ntfy"];

/// PVOS D196 — whose stall-detector `overdue` is a real fault. `follow` is a
/// tail that stamps its row on every long-poll (D146), so for it "overdue"
/// means the source stopped answering mid-poll: the follower is hung. Every
/// other job's overdue only says no pass has finished lately (D100), which a
/// healthy long pass also says.
pub fn overdue_is_news(job: &str) -> bool {
    job == "follow"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notify {
    pub url: String,
    pub format: String,
    /// Names for the boxes, by host (the address without the port): the
    /// person reads "the NAS", not a pin and a port. `pvfs fleet notify
    /// --label 192.168.1.237=NAS`.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl Notify {
    /// The name a person knows a peer by, or its address when unnamed.
    /// PVOS D182: a label for the full address (`host:port`) wins over one for
    /// the host — two daemons on one box (mediabox's holder and the standby
    /// owner) are two boxes to a person.
    pub fn name_for(&self, addr: &str) -> String {
        let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
        self.labels
            .get(addr)
            .or_else(|| self.labels.get(host))
            .cloned()
            .unwrap_or_else(|| addr.to_string())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub last_heartbeat_ms: u64,
    /// Job errors already reported, `pin/job` → the error text, so a
    /// persisting error is said once and a changed one again.
    #[serde(default)]
    pub reported_job_errors: BTreeMap<String, String>,
    /// D151 — every job error present now, `pin/job` → its text and when that
    /// text was first seen: the clock `job_errors` waits on. Persisted, so a
    /// restart neither resets it nor advances it.
    #[serde(default)]
    pub job_errors_seen: BTreeMap<String, Seen>,
    /// D161 — when each SENT error was first seen, `pin/job` → ms: the "after
    /// N minutes" of its clear. Set at the first send of an episode; a
    /// changed text does not move it.
    #[serde(default)]
    pub reported_since_ms: BTreeMap<String, u64>,
    /// D161 — a sent error its job no longer reports, `pin/job` → the first
    /// pass it was gone. Said cleared once gone for `JOB_ERROR_AFTER_MS`;
    /// forgotten if the error comes back first (one episode, not two).
    #[serde(default)]
    pub job_errors_gone: BTreeMap<String, u64>,
    /// PVOS D231 — stuck trash buckets already said, `<pin8 or self>/<region>/<day>`
    /// → the detail sent, so each is said once and its clear once.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reported_stuck: BTreeMap<String, String>,
}

/// A job's error and when this text of it was first seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub error: String,
    pub first_seen_ms: u64,
}

/// One thing worth saying. `event` is one of `peer_down`, `peer_up`,
/// `supervise`, `job_error`, `job_error_cleared`, `heartbeat`, `test`, and
/// since PVOS D182 `owner_fenced`, `owner_unfenced`, `peer_diverged`,
/// `peer_diverged_cleared`, since PVOS D228 `log_destination_failing`,
/// `log_destination_recovered`, and since PVOS D231 `trash_stuck`,
/// `trash_stuck_cleared`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub event: String,
    pub at_ms: u64,
    pub peer: Option<String>,
    pub addr: Option<String>,
    pub since_ms: Option<u64>,
    pub detail: Option<String>,
    pub up: u32,
    pub down: u32,
    /// D161 — `job_error_cleared` only: the first pass the error was gone, so
    /// "after N minutes" is how long it lasted, not how long the clear waited.
    /// Absent from every other event's payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    /// PVOS D206 — the forest the event is about: its registry alias, else
    /// its mount directory's name (`forest_name`). Lab and production events
    /// differed only by address, so the lab notifier stayed off (D142).
    /// Stamped by `emit` and the test; absent from the payload when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forest: Option<String>,
}

/// PVOS D206 — the name a person knows this forest by: the alias it is
/// registered under (`pvfs forest register --alias`, the system registry),
/// else the name of its mount directory. `data_dir` is the forest's
/// `.pvfs` state directory.
pub fn forest_name(data_dir: &Path) -> Option<String> {
    forest_name_in(&pvfs_core::mount::Registry::system(), data_dir)
}

/// [`forest_name`] against a given registry (tests use a scratch one).
pub fn forest_name_in(registry: &pvfs_core::mount::Registry, data_dir: &Path) -> Option<String> {
    let mount = data_dir.parent()?;
    let mount = std::fs::canonicalize(mount).unwrap_or_else(|_| mount.to_path_buf());
    let alias = registry
        .find(&mount.to_string_lossy())
        .ok()
        .flatten()
        .and_then(|f| f.alias);
    alias.or_else(|| mount.file_name().map(|n| n.to_string_lossy().into_owned())).filter(|n| !n.is_empty())
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

pub fn load(data_dir: &Path) -> Result<Option<Notify>, PvfsError> {
    let p = path(data_dir);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PvfsError::io("read notify", e)),
    };
    serde_json::from_str(&text).map(Some).map_err(|e| PvfsError::BadInput {
        field: "notify".into(),
        reason: format!("unreadable ({e}) — `pvfs fleet notify --off` and set it again"),
    })
}

pub fn set(data_dir: &Path, url: &str, format: &str) -> Result<Notify, PvfsError> {
    let labels = load(data_dir)?.map(|n| n.labels).unwrap_or_default();
    set_with_labels(data_dir, url, format, labels)
}

/// Add or replace names (`host=name`); the URL and format stay.
pub fn label(data_dir: &Path, pairs: &[(String, String)]) -> Result<Notify, PvfsError> {
    let Some(mut n) = load(data_dir)? else {
        return Err(PvfsError::BadInput { field: "notify".into(), reason: "set the webhook first: pvfs fleet notify <url>".into() });
    };
    for (host, name) in pairs {
        n.labels.insert(host.clone(), name.clone());
    }
    let labels = n.labels.clone();
    set_with_labels(data_dir, &n.url, &n.format, labels)
}

fn set_with_labels(data_dir: &Path, url: &str, format: &str, labels: BTreeMap<String, String>) -> Result<Notify, PvfsError> {
    if !FORMATS.contains(&format) {
        return Err(PvfsError::BadInput {
            field: "format".into(),
            reason: format!("{format} is not one of {}", FORMATS.join(", ")),
        });
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(PvfsError::BadInput { field: "url".into(), reason: "a webhook is an http(s) URL".into() });
    }
    let n = Notify { url: url.to_string(), format: format.to_string(), labels };
    let text = serde_json::to_string_pretty(&n).map_err(|e| PvfsError::BadInput { field: "notify".into(), reason: e.to_string() })?;
    std::fs::write(path(data_dir), text).map_err(|e| PvfsError::io("write notify", e))?;
    Ok(n)
}

/// Returns whether anything was configured.
pub fn clear(data_dir: &Path) -> Result<bool, PvfsError> {
    match std::fs::remove_file(path(data_dir)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(PvfsError::io("remove notify", e)),
    }
}

fn load_state(data_dir: &Path) -> State {
    std::fs::read_to_string(data_dir.join(STATE_FILE))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(data_dir: &Path, st: &State) {
    if let Ok(text) = serde_json::to_string(st) {
        let _ = std::fs::write(data_dir.join(STATE_FILE), text);
    }
}

fn short(pin: &str) -> String {
    pin.chars().take(8).collect()
}

fn counts(rec: &FleetHealth) -> (u32, u32) {
    let down = rec.peers.values().filter(|r| r.is_down()).count() as u32;
    (rec.peers.len() as u32 - down, down)
}

/// What changed between the last record and this one — each thing once.
///
/// `prev` is `None` on the very first poll: nothing is a transition then,
/// except a peer that is ALREADY down (that is worth one message).
pub fn transitions(prev: Option<&FleetHealth>, next: &FleetHealth, now_ms: u64) -> Vec<Event> {
    let (up, down) = counts(next);
    let mut out = Vec::new();
    let base = |event: &str, pin: &str, r: &crate::health::PeerRecord| Event {
        event: event.into(),
        at_ms: now_ms,
        peer: Some(short(pin)),
        addr: Some(r.addr.clone()),
        since_ms: None,
        detail: None,
        up,
        down,
        until_ms: None,
        forest: None,
    };
    for (pin, r) in &next.peers {
        let p = prev.and_then(|p| p.peers.get(pin));
        let was_down = p.is_some_and(|p| p.is_down());
        if r.is_down() && !was_down {
            let mut e = base("peer_down", pin, r);
            e.since_ms = r.unreachable_since_ms;
            e.detail = r.last.error.clone();
            out.push(e);
        }
        if !r.is_down() && r.misses == 0 && was_down {
            let mut e = base("peer_up", pin, r);
            let since = p.and_then(|p| p.unreachable_since_ms);
            e.since_ms = since;
            e.detail = since.map(|s| format!("was down {} min", now_ms.saturating_sub(s) / 60_000));
            out.push(e);
        }
        let seen = p.map_or(0, |p| p.actions.len());
        for a in r.actions.iter().skip(seen) {
            let mut e = base("supervise", pin, r);
            e.since_ms = Some(a.at_ms);
            e.detail = Some(format!("{} → rc {}: {}", a.verb, a.rc, a.output.trim()));
            out.push(e);
        }
        // Job errors are handled by `job_errors` (they need memory across
        // passes and restarts: a restart's "connection refused" clears itself
        // in a minute and must not wake anyone).
        //
        // PVOS D182 — a peer whose copy of the log is on another branch: said
        // once when it is first seen, and cleared once when it agrees again
        // (re-seeded). Only answering peers count: a peer that did not answer
        // keeps its verdict unknown, not cleared.
        let diverged = r.last.log_verdict.as_deref() == Some("diverged");
        let was_diverged = p.is_some_and(|p| p.last.log_verdict.as_deref() == Some("diverged"));
        if diverged && !was_diverged {
            let mut e = base("peer_diverged", pin, r);
            e.detail = r.last.log.as_ref().map(|t| format!("seq {}", t.seq));
            out.push(e);
        }
        if was_diverged && r.last.log_verdict.as_deref() == Some("consistent") {
            out.push(base("peer_diverged_cleared", pin, r));
        }
        // PVOS D228 — a peer's log destination that has stopped delivering
        // (its shipper already waited 15 minutes before calling it failing),
        // said once, and once more when it delivers again. Only answering
        // peers count: one that did not answer says nothing either way.
        if r.last.ok() {
            let before = |name: &str| p.and_then(|p| p.last.log_destinations.iter().find(|d| d.name == name));
            for d in &r.last.log_destinations {
                let was_failing = before(&d.name).is_some_and(|b| b.failing);
                if d.failing && !was_failing {
                    let mut e = base("log_destination_failing", pin, r);
                    e.detail = Some(format!("{} ({}): {}", d.name, d.kind, d.last_error.as_deref().unwrap_or("no delivery")));
                    out.push(e);
                } else if !d.failing && was_failing {
                    let mut e = base("log_destination_recovered", pin, r);
                    e.detail = Some(format!("{} ({})", d.name, d.kind));
                    out.push(e);
                }
            }
        }
    }
    // PVOS D182 — this box's own fence, said once when it appears (on the
    // very first poll too: worth one message, like a peer already down) and
    // once when a person lifts it.
    let was_fenced = prev.is_some_and(|p| p.fenced.is_some());
    let own = |event: &str| Event {
        event: event.into(),
        at_ms: now_ms,
        peer: None,
        addr: next.self_addr.clone(),
        since_ms: None,
        detail: None,
        up,
        down,
        until_ms: None,
        forest: None,
    };
    match (&next.fenced, was_fenced) {
        (Some(f), false) => {
            let mut e = own("owner_fenced");
            e.since_ms = Some(f.at_ms);
            e.detail = Some(f.reason.clone());
            out.push(e);
        }
        (None, true) => {
            let mut e = own("owner_unfenced");
            e.since_ms = prev.and_then(|p| p.fenced.as_ref()).map(|f| f.at_ms);
            out.push(e);
        }
        _ => {}
    }
    out
}

/// PVOS D231 — a trash bucket a box's purge could not wholly remove, or a
/// region whose purge failed as a whole (`purge_error`), said once when first
/// seen (`trash_stuck`) and once when that region's latest purge no longer
/// lists it (`trash_stuck_cleared`). The trash step's failure was a journal
/// line only (never a job's `last_error`), so `job_errors` never saw it. Remembered in `state`,
/// not compared with the last record: a daemon that has just started reports
/// no trash until its first purge, and a peer that missed a probe reports
/// nothing, and neither is a clear — nor, when the bucket shows again, news.
/// The owner's own trash (`self_trash`; it never polls itself) is held to
/// the same rule. A peer no longer polled at all is forgotten silently.
pub fn trash_stuck(state: &mut State, next: &FleetHealth, now_ms: u64) -> Vec<Event> {
    let (up, down) = counts(next);
    let event = |name: &str, peer: Option<String>, addr: Option<String>, detail: String| Event {
        event: name.into(),
        at_ms: now_ms,
        peer,
        addr,
        since_ms: None,
        detail: Some(detail),
        up,
        down,
        until_ms: None,
        forest: None,
    };
    // every box that answered, and this one
    let mut boxes: Vec<TrashSource> = next
        .peers
        .iter()
        .filter(|(_, r)| r.last.ok())
        .map(|(pin, r)| TrashSource { who: short(pin), peer: Some(short(pin)), addr: Some(r.addr.clone()), trash: &r.last.trash })
        .collect();
    boxes.push(TrashSource { who: "self".into(), peer: None, addr: next.self_addr.clone(), trash: &next.self_trash });
    let mut out = Vec::new();
    for TrashSource { who, peer, addr, trash } in &boxes {
        for t in trash.iter() {
            // the region's purge failed as a whole (its trash unreadable)
            if let Some(err) = &t.purge_error {
                let key = format!("{who}/{}/error", t.region);
                if let std::collections::btree_map::Entry::Vacant(slot) = state.reported_stuck.entry(key) {
                    let detail = format!("region {}: cannot purge its trash: {err}", short(&t.region));
                    out.push(event("trash_stuck", peer.clone(), addr.clone(), detail.clone()));
                    slot.insert(detail);
                }
            }
            for b in &t.stuck {
                let key = format!("{who}/{}/{}", t.region, b.day);
                if let std::collections::btree_map::Entry::Vacant(slot) = state.reported_stuck.entry(key) {
                    let detail = stuck_detail(&t.region, b);
                    out.push(event("trash_stuck", peer.clone(), addr.clone(), detail.clone()));
                    slot.insert(detail);
                }
            }
        }
        let mine = format!("{who}/");
        let gone: Vec<String> = state
            .reported_stuck
            .keys()
            .filter(|k| k.starts_with(&mine))
            .filter(|k| {
                let Some((region, what)) = k[mine.len()..].rsplit_once('/') else { return false };
                let Some(t) = trash.iter().find(|t| t.region == region) else { return false };
                if what == "error" {
                    return t.purge_error.is_none(); // a purge ran since
                }
                // its region purged again, and the bucket no longer stuck there
                let day: Option<u64> = what.parse().ok();
                t.purge_error.is_none() && !t.stuck.iter().any(|b| Some(b.day) == day)
            })
            .cloned()
            .collect();
        for key in gone {
            let was = state.reported_stuck.remove(&key).unwrap_or_default();
            let what = was
                .split_once(": cannot remove")
                .or_else(|| was.split_once(": cannot purge"))
                .map_or(was.as_str(), |(w, _)| w)
                .to_string();
            out.push(event("trash_stuck_cleared", peer.clone(), addr.clone(), what));
        }
    }
    // a peer no longer polled (retired, retracted): forget it, say nothing
    let polled: BTreeSet<String> = next.peers.keys().map(|p| short(p)).chain(["self".to_string()]).collect();
    state.reported_stuck.retain(|k, _| k.split_once('/').is_some_and(|(w, _)| polled.contains(w)));
    out
}

/// One box's trash as [`trash_stuck`] reads it: its key in the memory
/// (`pin8`, or `self`), how an event names it, and its regions.
struct TrashSource<'a> {
    who: String,
    peer: Option<String>,
    addr: Option<String>,
    trash: &'a [pvfs_proto::TrashWire],
}

/// `bucket 20729 (/mnt/…/.pvfs-trash/20729) in region c020473f: cannot remove
/// …: Permission denied (os error 13); its folder belongs to root (uid 0),
/// the daemon runs as chris (uid 1000)`.
fn stuck_detail(region: &str, b: &pvfs_proto::StuckBucketWire) -> String {
    let whose = match (&b.folder_owner, &b.daemon_user) {
        (Some(f), Some(d)) if f != d => format!("; its folder belongs to {f}, the daemon runs as {d}"),
        _ => String::new(),
    };
    format!("bucket {} ({}) in region {}: cannot remove {}: {}{whose}", b.day, b.bucket, short(region), b.path, b.error)
}

/// A job's error is reported once it has been there, with the same text,
/// for `JOB_ERROR_AFTER_MS` — timed from when it was first seen, not by
/// counting records: every daemon start polls at once, so a burst of
/// restarts writes several records seconds apart, and on 2026-09-13 that
/// reported the peers' momentary "connection refused" (D151). Said once,
/// and again only when the text changes, after that text's own wait. A
/// peer that did not answer this pass keeps its memory: its jobs are
/// unknown, not clear.
///
/// D161 — a SENT error that goes away is said cleared once it has been gone
/// for the same `JOB_ERROR_AFTER_MS`, and only then forgotten. Back before
/// that, it is one episode: nothing is said either way. An error that goes
/// away before it was ever sent is forgotten at once, silently, as before.
pub fn job_errors(state: &mut State, next: &FleetHealth, now_ms: u64) -> Vec<Event> {
    let (up, down) = counts(next);
    let mut out = Vec::new();
    let mut live: BTreeSet<String> = BTreeSet::new();
    for (pin, r) in &next.peers {
        let mine = format!("{}/", short(pin));
        if !r.last.reachable {
            live.extend(
                state.job_errors_seen.keys().chain(state.reported_job_errors.keys()).filter(|k| k.starts_with(&mine)).cloned(),
            );
            continue;
        }
        let mut present: BTreeSet<String> = BTreeSet::new();
        for j in r.last.jobs.iter().filter(|j| j.last_error.is_some()) {
            let err = j.last_error.clone().unwrap_or_default();
            // The stall detector's "overdue … not the same as stuck" is a
            // notice, not an error: a long pass that is working says it too,
            // and nobody can act on it. Except on `follow` (PVOS D196): since
            // D146 a follower stamps its row every few seconds, so its overdue
            // is a long-poll that never came back — a hung follower, and the
            // box stops hearing the forest.
            if err.contains("overdue") && !overdue_is_news(&j.name) {
                continue;
            }
            let key = format!("{}/{}", short(pin), j.name);
            live.insert(key.clone());
            present.insert(key.clone());
            // back before its clear was said: the same episode
            state.job_errors_gone.remove(&key);
            let seen = state.job_errors_seen.entry(key.clone()).or_insert_with(|| Seen { error: err.clone(), first_seen_ms: now_ms });
            if seen.error != err {
                // a different error: it waits its own time
                *seen = Seen { error: err.clone(), first_seen_ms: now_ms };
            }
            if now_ms.saturating_sub(seen.first_seen_ms) < JOB_ERROR_AFTER_MS {
                continue; // not there long enough yet
            }
            if state.reported_job_errors.get(&key) == Some(&err) {
                continue; // already said
            }
            out.push(Event {
                event: "job_error".into(),
                at_ms: now_ms,
                peer: Some(short(pin)),
                addr: Some(r.addr.clone()),
                since_ms: None,
                detail: Some(format!("{}: {err}", j.name)),
                up,
                down,
                until_ms: None,
                forest: None,
            });
            let first_seen_ms = seen.first_seen_ms;
            state.reported_since_ms.entry(key.clone()).or_insert(first_seen_ms);
            state.reported_job_errors.insert(key, err);
        }
        // D161 — the sent errors this peer no longer reports.
        let sent: Vec<String> =
            state.reported_job_errors.keys().filter(|k| k.starts_with(&mine) && !present.contains(*k)).cloned().collect();
        for key in sent {
            let gone_ms = *state.job_errors_gone.entry(key.clone()).or_insert(now_ms);
            if now_ms.saturating_sub(gone_ms) < JOB_ERROR_AFTER_MS {
                live.insert(key); // not gone long enough to say so
                continue;
            }
            let err = state.reported_job_errors.get(&key).cloned().unwrap_or_default();
            let job = key.split_once('/').map_or("a job", |(_, j)| j);
            out.push(Event {
                event: "job_error_cleared".into(),
                at_ms: now_ms,
                peer: Some(short(pin)),
                addr: Some(r.addr.clone()),
                since_ms: state.reported_since_ms.get(&key).copied(),
                detail: Some(format!("{job}: {err}")),
                up,
                down,
                until_ms: Some(gone_ms),
                forest: None,
            });
            // not in `live`: every memory of this episode goes below
        }
    }
    state.job_errors_seen.retain(|k, _| live.contains(k));
    state.reported_job_errors.retain(|k, _| live.contains(k));
    state.reported_since_ms.retain(|k, _| live.contains(k));
    state.job_errors_gone.retain(|k, _| live.contains(k));
    out
}

/// The daily heartbeat, if it is due.
pub fn heartbeat(state: &mut State, next: &FleetHealth, now_ms: u64) -> Option<Event> {
    // Never sent one (a fresh configuration): say hello on this poll, so the
    // person sees the channel work without waiting a day.
    let due = state.last_heartbeat_ms == 0 || now_ms.saturating_sub(state.last_heartbeat_ms) >= HEARTBEAT_EVERY_MS;
    if !due {
        return None;
    }
    state.last_heartbeat_ms = now_ms;
    let (up, down) = counts(next);
    let peers: Vec<String> = next
        .peers
        .iter()
        .map(|(pin, r)| format!("{} {} {}", short(pin), r.addr, if r.is_down() { "DOWN" } else { "up" }))
        .collect();
    // PVOS D182 — a fenced owner's check-in says that, not "all good".
    let detail = match &next.fenced {
        Some(f) => format!("FENCED: {}", f.reason),
        None => peers.join("; "),
    };
    Some(Event {
        event: "heartbeat".into(),
        at_ms: now_ms,
        peer: None,
        addr: next.self_addr.clone().filter(|_| next.fenced.is_some()),
        since_ms: None,
        detail: Some(detail),
        up,
        down,
        until_ms: None,
        forest: None,
    })
}

pub fn test_event(now_ms: u64) -> Event {
    Event {
        event: "test".into(),
        at_ms: now_ms,
        peer: None,
        addr: None,
        since_ms: None,
        detail: Some("pvfs fleet notify --test".into()),
        up: 0,
        down: 0,
        until_ms: None,
        forest: None,
    }
}

fn minutes(ms: u64) -> String {
    let m = ms / 60_000;
    if m < 1 { "under a minute".into() } else if m == 1 { "1 minute".into() } else if m < 120 { format!("{m} minutes") } else { format!("{} hours", m / 60) }
}

/// `critical` wakes a person, `warning` is worth a look, `info` is news.
pub fn severity(ev: &Event) -> &'static str {
    let restart_worked = ev.detail.as_deref().is_some_and(|d| d.contains("rc 0"));
    match ev.event.as_str() {
        "peer_down" => "critical",
        // a restart that worked needs nobody; one that failed needs a hand
        "supervise" if restart_worked => "info",
        "supervise" => "critical",
        "job_error" => "warning",
        // PVOS D182 — an owner that has stopped writing is the forest stopped.
        "owner_fenced" => "critical",
        "peer_diverged" => "warning",
        "log_destination_failing" => "warning",
        // PVOS D231 — needs a hand (an ownership fix), wakes nobody
        "trash_stuck" => "warning",
        "heartbeat" if ev.detail.as_deref().is_some_and(|d| d.starts_with("FENCED")) => "warning",
        "heartbeat" if ev.down > 0 => "warning",
        _ => "info",
    }
}

/// The sentence a person reads. Names the box (by label when there is
/// one), says what happened, and what was done or is expected.
pub fn summary(n: &Notify, ev: &Event) -> String {
    let who = ev.addr.as_deref().map(|a| n.name_for(a)).unwrap_or_else(|| "a peer".into());
    // PVOS D182 — events about THIS box (its fence) name it by its own
    // announced address; without one, it is "the owner".
    let me = ev.addr.as_deref().map(|a| n.name_for(a)).unwrap_or_else(|| "the owner".into());
    let me_cap = format!("{}{}", me.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default(), me.chars().skip(1).collect::<String>());
    match ev.event.as_str() {
        "peer_down" => {
            let since = ev.since_ms.map(|s| format!(" It has not answered for {}.", minutes(ev.at_ms.saturating_sub(s)))).unwrap_or_default();
            let why = ev.detail.as_deref().map(|d| format!(" Last error: {d}.")).unwrap_or_default();
            format!("{who} is down.{since}{why} The owner will try to restart it if it supervises that box.")
        }
        "supervise" => {
            let d = ev.detail.as_deref().unwrap_or("");
            if d.contains("rc 0") {
                format!("The owner restarted PVFS on {who} ({}).", d.split(": ").last().unwrap_or(d).trim())
            } else {
                format!("The owner tried to restart PVFS on {who} and it FAILED ({d}). It needs a hand.")
            }
        }
        "peer_up" => {
            let how_long = ev.since_ms.map(|s| format!(" after {} down", minutes(ev.at_ms.saturating_sub(s)))).unwrap_or_default();
            format!("{who} is back{how_long}.")
        }
        "job_error" => {
            let (job, err) = ev.detail.as_deref().and_then(|d| d.split_once(": ")).unwrap_or(("a job", ""));
            format!("On {who}, the {job} job reports an error: {err}")
        }
        "job_error_cleared" => {
            let (job, err) = ev.detail.as_deref().and_then(|d| d.split_once(": ")).unwrap_or(("a job", ""));
            let lasted = match (ev.since_ms, ev.until_ms) {
                (Some(s), Some(u)) => format!(", after {}", minutes(u.saturating_sub(s))),
                _ => String::new(),
            };
            format!("On {who}, the {job} job's error has cleared{lasted}. It had reported: {err}")
        }
        "owner_fenced" => format!(
            "{me_cap} has stopped writing to the forest: {}. It writes nothing until a person looks \
             (pvfs forest fence on that box).",
            ev.detail.as_deref().unwrap_or("a follower holds more of the log than it does")
        ),
        "owner_unfenced" => {
            let how_long = ev.since_ms.map(|s| format!(" after {}", minutes(ev.at_ms.saturating_sub(s)))).unwrap_or_default();
            format!("{me_cap}'s fence has been lifted{how_long}; it writes to the forest again.")
        }
        "peer_diverged" => format!(
            "{who}'s copy of the forest's log differs from the owner's{}: it followed a writer that is \
             not the owner, or was restored from the wrong copy. The owner takes no writes from it until it \
             is re-seeded (pvfs replica add into a fresh directory).",
            ev.detail.as_deref().map(|d| format!(" at {d}")).unwrap_or_default()
        ),
        "peer_diverged_cleared" => format!("{who}'s copy of the forest's log agrees with the owner's again."),
        "log_destination_failing" => format!(
            "On {who}, the log destination {} has delivered nothing for 15 minutes. Its records wait in the \
             spool (up to its cap). pvfs serve status there shows it; pvfs log destinations test <name> checks it.",
            ev.detail.as_deref().unwrap_or("?")
        ),
        "trash_stuck" if ev.detail.as_deref().is_some_and(|d| d.contains(": cannot purge its trash")) => format!(
            "On {who}, the trash purge failed: {}. Nothing in that region's trash is purged until it is fixed; \
             its other regions still are. To fix it: sudo pvfs trash unstick on {who} (it shows what it \
             changes and asks).",
            ev.detail.as_deref().unwrap_or("?")
        ),
        "trash_stuck" => format!(
            "On {who}, the trash purge could not remove a bucket: {}. The rest of the trash is still purged. \
             The usual cause is a folder made by `sudo pvfs`. To clear it: sudo pvfs trash unstick on {who} \
             (it shows the bucket and asks before removing it).",
            ev.detail.as_deref().unwrap_or("?")
        ),
        "trash_stuck_cleared" if ev.detail.as_deref().is_some_and(|d| !d.starts_with("bucket ")) => format!(
            "On {who}, the trash purge runs again in {}.",
            ev.detail.as_deref().unwrap_or("that region")
        ),
        "trash_stuck_cleared" => format!(
            "On {who}, the trash purge has removed {}, which it could not before.",
            ev.detail.as_deref().unwrap_or("the stuck bucket")
        ),
        "log_destination_recovered" => format!(
            "On {who}, the log destination {} delivers again; what it queued is being sent.",
            ev.detail.as_deref().unwrap_or("?")
        ),
        "heartbeat" if ev.detail.as_deref().is_some_and(|d| d.starts_with("FENCED")) => format!(
            "Daily check-in: {me} is still fenced and writes nothing — {}. Run pvfs forest fence on it.",
            ev.detail.as_deref().unwrap_or("").trim_start_matches("FENCED: ")
        ),
        "heartbeat" => {
            // "peers", not "boxes": the count is the announced endpoints this
            // box polls, which never includes the box sending the message
            // (`poll_fleet` filters its own pin). Calling them boxes made a
            // four-box fleet report three and read like a box was missing.
            let peers = if ev.up == 1 { "peer" } else { "peers" };
            if ev.down == 0 {
                format!("All good: {} {peers} reporting, nothing to do.", ev.up)
            } else {
                format!(
                    "Daily check-in: {} {peers} reporting, {} DOWN — {}",
                    ev.up,
                    ev.down,
                    ev.detail.as_deref().unwrap_or("")
                )
            }
        }
        "test" => "PVFS can reach this webhook — notifications are working.".into(),
        other => format!("{other} on {who}"),
    }
}

/// One line a person can read, for the chat-shaped formats.
/// PVOS D206 — with the forest's name when the event carries one.
pub fn line(n: &Notify, ev: &Event) -> String {
    format!("{}: {}", title(ev), summary(n, ev))
}

/// PVOS D206 — "PVFS", or "PVFS <forest>" when the event names its forest.
fn title(ev: &Event) -> String {
    match ev.forest.as_deref() {
        Some(f) => format!("PVFS {f}"),
        None => "PVFS".into(),
    }
}

/// The request body and its headers for the configured format. The JSON
/// shapes carry the event's fields plus `summary` and `severity`, and the
/// peer's `name` when it has a label.
pub fn payload(n: &Notify, ev: &Event) -> (String, Vec<(String, String)>) {
    let json = |v: serde_json::Value| (v.to_string(), vec![("Content-Type".to_string(), "application/json".to_string())]);
    match n.format.as_str() {
        "slack" => json(serde_json::json!({ "text": line(n, ev) })),
        "discord" => json(serde_json::json!({ "content": line(n, ev) })),
        "ntfy" => (
            summary(n, ev),
            vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Title".to_string(), format!("{} {}", title(ev), ev.event)),
            ],
        ),
        _ => {
            let mut v = serde_json::to_value(ev).unwrap_or(serde_json::Value::Null);
            if let serde_json::Value::Object(m) = &mut v {
                m.insert("summary".into(), serde_json::Value::String(summary(n, ev)));
                m.insert("severity".into(), serde_json::Value::String(severity(ev).into()));
                m.insert("name".into(), serde_json::Value::String(ev.addr.as_deref().map(|a| n.name_for(a)).unwrap_or_default()));
            }
            json(v)
        }
    }
}

/// POST one event. `PVFS_NOTIFY_CMD` names the program (default `curl`);
/// it gets curl's arguments and the body on stdin.
pub fn send(n: &Notify, ev: &Event) -> Result<(), PvfsError> {
    use std::io::Write;
    let (body, headers) = payload(n, ev);
    let cmd = std::env::var("PVFS_NOTIFY_CMD").unwrap_or_else(|_| "curl".into());
    let mut c = std::process::Command::new(&cmd);
    c.args(["-fsS", "--max-time", "10", "-X", "POST"]);
    for (k, v) in &headers {
        c.arg("-H").arg(format!("{k}: {v}"));
    }
    c.args(["--data-binary", "@-"]).arg(&n.url);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().map_err(|e| PvfsError::io(&format!("run {cmd}"), e))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(body.as_bytes()).map_err(|e| PvfsError::io("notify body", e))?;
    }
    let out = child.wait_with_output().map_err(|e| PvfsError::io("notify wait", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(PvfsError::BadInput {
            field: "notify".into(),
            reason: format!(
                "{cmd} exited {}: {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        })
    }
}

/// The health job's call: everything that changed since `prev`, plus the
/// heartbeat if due, each sent once. Returns one line per event for the
/// daemon's log — sent or failed — and never fails the pass itself.
pub fn emit(data_dir: &Path, prev: Option<&FleetHealth>, next: &FleetHealth, now_ms: u64) -> Result<Vec<String>, PvfsError> {
    let Some(n) = load(data_dir)? else { return Ok(Vec::new()) };
    let mut state = load_state(data_dir);
    let mut events = transitions(prev, next, now_ms);
    events.extend(job_errors(&mut state, next, now_ms));
    events.extend(trash_stuck(&mut state, next, now_ms));
    // PVOS D182 — a fenced owner's view of the fleet is not the fleet's (after
    // a promotion it is a zombie, and the new owner reports the fleet): it
    // says its own fence, its clear and the check-in, nothing else.
    if next.fenced.is_some() {
        events.retain(|e| matches!(e.event.as_str(), "owner_fenced" | "owner_unfenced"));
    }
    if let Some(h) = heartbeat(&mut state, next, now_ms) {
        events.push(h);
    }
    // PVOS D206 — every event names its forest.
    let forest = forest_name(data_dir);
    for ev in &mut events {
        ev.forest = forest.clone();
    }
    let mut lines = Vec::new();
    for ev in &events {
        let what = format!("{}{}", ev.event, ev.peer.as_deref().map(|p| format!(" {p}")).unwrap_or_default());
        match send(&n, ev) {
            Ok(()) => lines.push(format!("{what} → sent")),
            Err(e) => lines.push(format!("{what} → NOT sent: {e}")),
        }
    }
    save_state(data_dir, &state);
    Ok(lines)
}
