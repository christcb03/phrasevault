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
