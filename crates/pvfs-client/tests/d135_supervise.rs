//! D135 item 1 — the owner's one action on silence: `start` over the
//! supervise channel, only when down AND supervised AND due, recorded,
//! backed off, and reset when the peer answers.

use pvfs_client::health::{FleetHealth, PeerHealth};
use pvfs_client::supervise::{self, backoff_secs, Action};

fn fake_ssh(dir: &std::path::Path, reply: &str) -> std::path::PathBuf {
    let p = dir.join("ssh");
    std::fs::write(
        &p,
        format!("#!/bin/sh\necho \"$@\" >> \"{}\"\necho \"{reply}\"\n", dir.join("argv.log").display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[test]
fn start_is_sent_only_when_down_supervised_and_due() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let ssh = fake_ssh(tmp.path(), "started 4242");
    std::env::set_var("PVFS_SSH", &ssh);
    let key = tmp.path().join("k");
    std::fs::write(&key, "not a real key").unwrap();
    let pin = "ab".repeat(32);
    let other = "cd".repeat(32);
    supervise::set(&data, &pin, "chris@nas", &key).unwrap();
    assert_eq!(supervise::load(&data).unwrap().len(), 1);

    let up = PeerHealth { reachable: true, forest_ok: true, ..Default::default() };
    let gone = PeerHealth { error: Some("refused".into()), ..Default::default() };
    let mut rec = FleetHealth::default();
    rec.observe(&pin, "10.0.0.9:7423", None, 1_000, up.clone());
    rec.observe(&other, "10.0.0.8:7421", None, 1_000, up.clone());

    // One miss: not down, nothing sent.
    rec.observe(&pin, "10.0.0.9:7423", None, 2_000, gone.clone());
    assert!(supervise::act_on_down(&data, &mut rec, 2_000).unwrap().is_empty());
    // Two misses on an UNSUPERVISED peer: nothing.
    rec.observe(&other, "10.0.0.8:7421", None, 2_000, gone.clone());
    rec.observe(&other, "10.0.0.8:7421", None, 3_000, gone.clone());
    // Two misses on the supervised peer: start, once.
    rec.observe(&pin, "10.0.0.9:7423", None, 3_000, gone.clone());
    let done = supervise::act_on_down(&data, &mut rec, 3_000).unwrap();
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(done[0].0, pin);
    assert_eq!((done[0].1.rc, done[0].1.output.as_str()), (0, "started 4242"));
    let argv = std::fs::read_to_string(tmp.path().join("argv.log")).unwrap();
    assert!(argv.contains(&format!("-i {}", key.display())) && argv.contains("chris@nas start") && argv.contains("BatchMode=yes"), "{argv}");
    assert_eq!(rec.peers[&pin].attempts, 1);
    assert_eq!(rec.peers[&pin].actions.len(), 1);
    assert!(rec.peers[&other].actions.is_empty(), "the unsupervised peer got nothing");

    // Still down a minute later: within the backoff, nothing.
    rec.observe(&pin, "10.0.0.9:7423", None, 63_000, gone.clone());
    assert!(supervise::act_on_down(&data, &mut rec, 63_000).unwrap().is_empty());
    // Past the first backoff: a second start; the backoff doubles.
    let t2 = 3_000 + backoff_secs(1) * 1000 + 1;
    rec.observe(&pin, "10.0.0.9:7423", None, t2, gone.clone());
    assert_eq!(supervise::act_on_down(&data, &mut rec, t2).unwrap().len(), 1);
    assert_eq!(rec.peers[&pin].attempts, 2);
    assert_eq!(backoff_secs(2), 2 * backoff_secs(1));
    assert_eq!(backoff_secs(9), supervise::BACKOFF_MAX_SECS, "capped");
    // The peer answers: the streak and the attempts reset; the actions stay as history.
    rec.observe(&pin, "10.0.0.9:7423", None, t2 + 1_000, up.clone());
    assert_eq!(rec.peers[&pin].attempts, 0);
    assert_eq!(rec.peers[&pin].actions.len(), 2);
    assert!(supervise::act_on_down(&data, &mut rec, t2 + 1_000).unwrap().is_empty());

    // The record round-trips with its actions; a pre-D135 record loads (defaults).
    rec.save(&data).unwrap();
    let back = FleetHealth::load(&data).unwrap().unwrap();
    assert_eq!(back.peers[&pin].actions, rec.peers[&pin].actions);
    let _ = Action { at_ms: 0, verb: "start".into(), rc: 0, output: String::new() };

    // Unset: no channel, no action however down.
    assert!(supervise::unset(&data, &pin).unwrap());
    rec.observe(&pin, "10.0.0.9:7423", None, t2 + 2_000, gone.clone());
    rec.observe(&pin, "10.0.0.9:7423", None, t2 + 3_000, gone.clone());
    assert!(supervise::act_on_down(&data, &mut rec, t2 + 900_000).unwrap().is_empty());
}
