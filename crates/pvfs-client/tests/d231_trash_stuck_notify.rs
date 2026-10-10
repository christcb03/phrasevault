//! PVOS D231 — a trash bucket a box's purge cannot remove reaches a person:
//! said once (`trash_stuck`, naming the bucket, the path and whose folder),
//! once more when it goes (`trash_stuck_cleared`), and not again because a
//! daemon restarted or a probe was missed.
//!
//! 2026-10-09 the only sign was a journal line, which Grafana paged as "Disk
//! errors on mediabox".
use pvfs_client::health::{FleetHealth, PeerHealth};
use pvfs_client::notify::{self, Event, Notify, State};
use pvfs_proto::{StuckBucketWire, TrashWire};

const REGION: &str = "c020473f9a4e";

fn pin() -> String {
    "42".repeat(32)
}

fn kinds(ev: &[Event]) -> Vec<&str> {
    ev.iter().map(|e| e.event.as_str()).collect()
}

fn stuck(day: u64) -> StuckBucketWire {
    StuckBucketWire {
        day,
        bucket: format!("/mnt/local/Media/.pvfs-trash/{day}"),
        path: format!("/mnt/local/Media/.pvfs-trash/{day}/TV/Show/ep.mkv"),
        error: "Permission denied (os error 13)".into(),
        folder_owner: Some("root (uid 0)".into()),
        daemon_user: Some("chris (uid 1000)".into()),
        left_entries: 4,
        left_bytes: 64_000_000_000,
    }
}

fn trash(days: &[u64]) -> Vec<TrashWire> {
    vec![TrashWire {
        region: REGION.into(),
        bytes: 1,
        buckets: days.len() as u32,
        retention_days: 7,
        stuck: days.iter().map(|d| stuck(*d)).collect(),
        ..Default::default()
    }]
}

fn answering(trash: Vec<TrashWire>) -> PeerHealth {
    PeerHealth { reachable: true, forest_ok: true, trash, ..Default::default() }
}

fn record(t: u64, peer: PeerHealth) -> FleetHealth {
    let mut h = FleetHealth { self_addr: Some("192.168.1.142:7434".into()), ..Default::default() };
    h.observe(&pin(), "192.168.1.142:7436", None, t, peer);
    h
}

fn labels() -> Notify {
    let mut n = Notify { url: "http://ha:8123/api/webhook/pvfs-fleet".into(), format: "ha".into(), labels: Default::default() };
    n.labels.insert("192.168.1.142:7436".into(), "mediabox's holder".into());
    n
}

#[test]
fn a_stuck_bucket_is_said_once_with_its_path_and_owner_then_cleared_once() {
    let t = 1_791_000_000_000;
    let mut st = State::default();

    let ev = notify::trash_stuck(&mut st, &record(t, answering(trash(&[20729]))), t);
    assert_eq!(kinds(&ev), ["trash_stuck"]);
    assert_eq!(notify::severity(&ev[0]), "warning", "worth a look; wakes nobody");
    let d = ev[0].detail.as_deref().unwrap();
    assert!(d.contains("bucket 20729 (/mnt/local/Media/.pvfs-trash/20729) in region c020473f"), "{d}");
    assert!(d.contains("cannot remove /mnt/local/Media/.pvfs-trash/20729/TV/Show/ep.mkv: Permission denied"), "{d}");
    assert!(d.contains("its folder belongs to root (uid 0), the daemon runs as chris (uid 1000)"), "{d}");
    let said = notify::summary(&labels(), &ev[0]);
    assert!(said.starts_with("On mediabox's holder, the trash purge could not remove a bucket"), "{said}");
    assert!(said.contains("The rest of the trash is still purged"), "{said}");
    assert!(said.contains("chown -R"), "it says what to do: {said}");

    // the next steps: still stuck — said already
    assert!(notify::trash_stuck(&mut st, &record(t + 120_000, answering(trash(&[20729]))), t + 120_000).is_empty());
    // a second bucket sticks: only it is news
    let ev = notify::trash_stuck(&mut st, &record(t + 240_000, answering(trash(&[20729, 20730]))), t + 240_000);
    assert_eq!(kinds(&ev), ["trash_stuck"]);
    assert!(ev[0].detail.as_deref().unwrap().contains("bucket 20730"), "{ev:?}");

    // fixed by hand (chown): the region's next purge lists neither
    let ev = notify::trash_stuck(&mut st, &record(t + 360_000, answering(trash(&[]))), t + 360_000);
    assert_eq!(kinds(&ev), ["trash_stuck_cleared", "trash_stuck_cleared"]);
    assert_eq!(notify::severity(&ev[0]), "info");
    let said = notify::summary(&labels(), &ev[0]);
    assert!(said.contains("has removed bucket 20729 (/mnt/local/Media/.pvfs-trash/20729) in region c020473f"), "{said}");
    assert!(notify::trash_stuck(&mut st, &record(t + 480_000, answering(trash(&[]))), t + 480_000).is_empty());
    assert!(st.reported_stuck.is_empty(), "{st:?}");
}

/// A restart empties a daemon's trash record until its first purge, and a
/// missed probe reports nothing: neither is a clear, and the bucket that
/// shows again is not news.
#[test]
fn a_restart_or_a_missed_probe_is_neither_a_clear_nor_news() {
    let t = 1_791_000_000_000;
    let mut st = State::default();
    assert_eq!(kinds(&notify::trash_stuck(&mut st, &record(t, answering(trash(&[20729]))), t)), ["trash_stuck"]);

    // the daemon restarted: no trash measured yet
    assert!(notify::trash_stuck(&mut st, &record(t + 1, answering(Vec::new())), t + 1).is_empty());
    // the probe failed
    let down = PeerHealth { reachable: false, error: Some("connection refused".into()), ..Default::default() };
    assert!(notify::trash_stuck(&mut st, &record(t + 2, down), t + 2).is_empty());
    // its first purge since: still stuck, already said
    assert!(notify::trash_stuck(&mut st, &record(t + 3, answering(trash(&[20729]))), t + 3).is_empty());
    assert_eq!(st.reported_stuck.len(), 1, "{st:?}");
}

/// The owner never polls itself: its own trash is said from `self_trash`.
#[test]
fn the_owners_own_stuck_bucket_is_said_too() {
    let t = 1_791_000_000_000;
    let mut st = State::default();
    let mut h = FleetHealth { self_addr: Some("192.168.1.142:7434".into()), ..Default::default() };
    h.self_trash = trash(&[20729]);
    let ev = notify::trash_stuck(&mut st, &h, t);
    assert_eq!(kinds(&ev), ["trash_stuck"]);
    assert_eq!(ev[0].peer, None);
    assert_eq!(ev[0].addr.as_deref(), Some("192.168.1.142:7434"));
    h.self_trash = trash(&[]);
    assert_eq!(kinds(&notify::trash_stuck(&mut st, &h, t + 1)), ["trash_stuck_cleared"]);
}

/// A peer no longer announced (retired) is forgotten without a word.
#[test]
fn a_retired_peer_is_forgotten_silently() {
    let t = 1_791_000_000_000;
    let mut st = State::default();
    notify::trash_stuck(&mut st, &record(t, answering(trash(&[20729]))), t);
    let gone = FleetHealth { self_addr: Some("192.168.1.142:7434".into()), ..Default::default() };
    assert!(notify::trash_stuck(&mut st, &gone, t + 1).is_empty());
    assert!(st.reported_stuck.is_empty(), "{st:?}");
}

/// The memory survives the notifier's state file (`reported_stuck`), and a
/// state file from before D231 reads with none.
#[test]
fn the_memory_round_trips_and_an_older_state_reads() {
    let mut st = State::default();
    notify::trash_stuck(&mut st, &record(1, answering(trash(&[20729]))), 1);
    let text = serde_json::to_string(&st).unwrap();
    assert_eq!(serde_json::from_str::<State>(&text).unwrap(), st);
    let old: State = serde_json::from_str(r#"{"last_heartbeat_ms":5}"#).unwrap();
    assert!(old.reported_stuck.is_empty());
}

/// A region whose purge failed as a whole (its trash unreadable) is said
/// too, once, and cleared when a purge runs there again.
#[test]
fn a_region_whose_purge_fails_as_a_whole_is_said_and_cleared() {
    let t = 1_791_000_000_000;
    let mut st = State::default();
    let mut failing = trash(&[]);
    failing[0].purge_error = Some("I/O error during read trash: Permission denied (os error 13)".into());
    let ev = notify::trash_stuck(&mut st, &record(t, answering(failing.clone())), t);
    assert_eq!(kinds(&ev), ["trash_stuck"]);
    let d = ev[0].detail.as_deref().unwrap();
    assert_eq!(d, "region c020473f: cannot purge its trash: I/O error during read trash: Permission denied (os error 13)");
    let said = notify::summary(&labels(), &ev[0]);
    assert!(said.starts_with("On mediabox's holder, the trash purge failed: region c020473f"), "{said}");
    assert!(notify::trash_stuck(&mut st, &record(t + 1, answering(failing)), t + 1).is_empty(), "said once");
    let ev = notify::trash_stuck(&mut st, &record(t + 2, answering(trash(&[]))), t + 2);
    assert_eq!(kinds(&ev), ["trash_stuck_cleared"]);
    assert_eq!(notify::summary(&labels(), &ev[0]), "On mediabox's holder, the trash purge runs again in region c020473f.");
}

/// While a region's purge fails, its stuck buckets are unknown, not cleared.
#[test]
fn a_failing_region_does_not_clear_its_stuck_buckets() {
    let t = 1_791_000_000_000;
    let mut st = State::default();
    notify::trash_stuck(&mut st, &record(t, answering(trash(&[20729]))), t);
    let mut failing = trash(&[]);
    failing[0].purge_error = Some("unreadable".into());
    let ev = notify::trash_stuck(&mut st, &record(t + 1, answering(failing)), t + 1);
    assert_eq!(kinds(&ev), ["trash_stuck"], "only the region's failure is news: {ev:?}");
    assert!(st.reported_stuck.keys().any(|k| k.ends_with("/20729")), "{st:?}");
}
