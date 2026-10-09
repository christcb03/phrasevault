//! PVOS D182 — what a person is told about a fence and a diverged follower,
//! and what a fenced owner stops saying.
use pvfs_client::health::{FleetHealth, PeerHealth};
use pvfs_client::notify::{self, Event, Notify};

fn pin() -> String {
    "93".repeat(32)
}

fn kinds(ev: &[Event]) -> Vec<&str> {
    ev.iter().map(|e| e.event.as_str()).collect()
}

fn peer(verdict: Option<&str>, seq: u64) -> PeerHealth {
    PeerHealth {
        reachable: true,
        forest_ok: true,
        log: Some(pvfs_proto::LogTipWire { seq, hash: "ab".repeat(32) }),
        log_verdict: verdict.map(str::to_string),
        ..Default::default()
    }
}

fn labels() -> Notify {
    let mut n = Notify { url: "http://ha:8123/api/webhook/pvfs-fleet".into(), format: "ha".into(), labels: Default::default() };
    n.labels.insert("192.168.1.120".into(), "the owner".into());
    n.labels.insert("192.168.1.142".into(), "mediabox".into());
    n.labels.insert("192.168.1.142:7435".into(), "mediabox's standby".into());
    n
}

fn fence() -> pvfs_proto::FenceWire {
    pvfs_proto::FenceWire {
        reason: "192.168.1.142:7435 holds the forest's log to seq 3480, this box only to seq 3472".into(),
        peer: "192.168.1.142:7435".into(),
        peer_seq: 3480,
        own_seq: 3472,
        at_ms: 1_000,
    }
}

#[test]
fn a_label_for_the_full_address_wins_over_the_host() {
    let n = labels();
    assert_eq!(n.name_for("192.168.1.142:7435"), "mediabox's standby");
    assert_eq!(n.name_for("192.168.1.142:7434"), "mediabox");
    assert_eq!(n.name_for("10.0.0.9:1"), "10.0.0.9:1");
}

#[test]
fn a_fence_is_said_once_when_it_appears_and_once_when_it_is_lifted() {
    let t = 1_790_000_000_000;
    let mut prev = FleetHealth { self_addr: Some("192.168.1.120:7431".into()), ..Default::default() };
    prev.observe(&pin(), "192.168.1.142:7435", None, t, peer(Some("consistent"), 3472));
    let mut next = prev.clone();
    next.observe(&pin(), "192.168.1.142:7435", None, t + 120_000, peer(Some("ahead"), 3480));
    next.fenced = Some(fence());
    let ev = notify::transitions(Some(&prev), &next, t + 120_000);
    assert_eq!(kinds(&ev), ["owner_fenced"]);
    assert_eq!(notify::severity(&ev[0]), "critical");
    let said = notify::summary(&labels(), &ev[0]);
    assert!(said.starts_with("The owner has stopped writing to the forest"), "{said}");
    assert!(said.contains("seq 3480"), "{said}");

    // Still fenced on the next pass: nothing new.
    let again = next.clone();
    assert!(notify::transitions(Some(&next), &again, t + 240_000).is_empty());
    // Lifted: said once.
    let mut lifted = again.clone();
    lifted.fenced = None;
    let ev = notify::transitions(Some(&again), &lifted, t + 360_000);
    assert_eq!(kinds(&ev), ["owner_unfenced"]);
    assert_eq!(notify::severity(&ev[0]), "info");
    // On the very first poll, a fence already there is worth one message.
    assert_eq!(kinds(&notify::transitions(None, &next, t)), ["owner_fenced"]);
}

#[test]
fn a_diverged_follower_is_said_once_and_cleared_when_it_agrees_again() {
    let t = 1_790_000_000_000;
    let mut a = FleetHealth::default();
    a.observe(&pin(), "192.168.1.142:7434", None, t, peer(Some("consistent"), 10));
    let mut b = a.clone();
    b.observe(&pin(), "192.168.1.142:7434", None, t + 1, peer(Some("diverged"), 9));
    let ev = notify::transitions(Some(&a), &b, t + 1);
    assert_eq!(kinds(&ev), ["peer_diverged"]);
    assert_eq!(notify::severity(&ev[0]), "warning");
    let said = notify::summary(&labels(), &ev[0]);
    assert!(said.starts_with("mediabox's copy of the forest's log differs from the owner's at seq 9"), "{said}");
    let mut c = b.clone();
    c.observe(&pin(), "192.168.1.142:7434", None, t + 2, peer(Some("diverged"), 9));
    assert!(notify::transitions(Some(&b), &c, t + 2).is_empty(), "said once");
    let mut d = c.clone();
    d.observe(&pin(), "192.168.1.142:7434", None, t + 3, peer(Some("consistent"), 11));
    assert_eq!(kinds(&notify::transitions(Some(&c), &d, t + 3)), ["peer_diverged_cleared"]);
}

#[test]
fn a_fenced_owners_check_in_says_so() {
    let mut st = notify::State::default();
    let mut rec = FleetHealth { self_addr: Some("192.168.1.120:7431".into()), fenced: Some(fence()), ..Default::default() };
    rec.observe(&pin(), "192.168.1.142:7435", None, 5, peer(Some("ahead"), 3480));
    let hb = notify::heartbeat(&mut st, &rec, 10).expect("a first heartbeat is due");
    assert_eq!(notify::severity(&hb), "warning");
    let said = notify::summary(&labels(), &hb);
    assert!(said.starts_with("Daily check-in: the owner is still fenced"), "{said}");
}

fn with_dest(failing: bool) -> PeerHealth {
    let mut p = peer(Some("consistent"), 3472);
    p.log_destinations = vec![pvfs_proto::LogDestHealthWire {
        name: "loki".into(),
        kind: "loki".into(),
        sent: 10,
        queued_bytes: if failing { 8192 } else { 0 },
        dropped: 0,
        last_ok_ms: 1,
        last_error: failing.then(|| "192.168.1.83:3100: Connection refused".into()),
        failing,
    }];
    p
}

/// PVOS D228 — a peer's log destination that stops delivering is said once
/// (the shipper already waited its 15 minutes), not again while it stays
/// down, and once more when it delivers again. A peer that did not answer
/// says nothing either way.
#[test]
fn a_failing_log_destination_is_said_once_and_its_recovery_once() {
    let t = 1_790_000_000_000;
    let addr = "192.168.1.142:7434";
    let mut prev = FleetHealth { self_addr: Some("192.168.1.120:7431".into()), ..Default::default() };
    prev.observe(&pin(), addr, None, t, with_dest(false));
    let mut next = prev.clone();
    next.observe(&pin(), addr, None, t + 120_000, with_dest(true));
    let ev = notify::transitions(Some(&prev), &next, t + 120_000);
    assert_eq!(kinds(&ev), ["log_destination_failing"]);
    assert_eq!(notify::severity(&ev[0]), "warning");
    let said = notify::summary(&labels(), &ev[0]);
    assert!(said.starts_with("On mediabox, the log destination loki (loki): 192.168.1.83:3100: Connection refused"), "{said}");
    // Still failing: nothing new.
    let mut again = next.clone();
    again.observe(&pin(), addr, None, t + 240_000, with_dest(true));
    assert!(notify::transitions(Some(&next), &again, t + 240_000).is_empty());
    // Not answering: nothing either way.
    let mut silent = again.clone();
    silent.observe(&pin(), addr, None, t + 360_000, PeerHealth { error: Some("refused".into()), ..Default::default() });
    assert!(!kinds(&notify::transitions(Some(&again), &silent, t + 360_000)).iter().any(|k| k.starts_with("log_destination")));
    // Delivering again.
    let mut back = again.clone();
    back.observe(&pin(), addr, None, t + 480_000, with_dest(false));
    let ev = notify::transitions(Some(&again), &back, t + 480_000);
    assert_eq!(kinds(&ev), ["log_destination_recovered"]);
    assert_eq!(notify::severity(&ev[0]), "info");
}

