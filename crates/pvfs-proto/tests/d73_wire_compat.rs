//! D73 — forward compatibility for the WIRE.
//!
//! D72 Part A made the LOG tolerant: a box replaying a log survives an event it
//! cannot read. The wire got nothing, so a newer peer sending an op an older
//! daemon had never heard of simply lost its connection — indistinguishable
//! from a network fault, and the reason no additive wire change could roll.
//!
//! What makes refusing safe is the FRAMING: frames are length-prefixed, so a
//! frame we cannot interpret has still been consumed exactly and the stream
//! stays aligned.

use pvfs_proto::{read_frame, ClientMsg, Frame, WriteOp, PROTO_COMPATIBLE_WITH};

fn framed(json: &str) -> Vec<u8> {
    let mut out = (json.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(json.as_bytes());
    out
}

/// The core claim: an unknown op is a REFUSAL, and the stream survives it.
#[test]
fn an_unknown_op_is_refusable_and_the_stream_stays_aligned() {
    let mut buf = Vec::new();
    buf.extend(framed(r#"{"t":"something_from_the_future","wat":1}"#));
    buf.extend(framed(r#"{"t":"info"}"#));
    let mut cur = std::io::Cursor::new(buf);

    match read_frame::<_, ClientMsg>(&mut cur).unwrap() {
        Some(Frame::Unknown { tag }) => assert_eq!(tag, "something_from_the_future"),
        other => panic!("expected Unknown, got {other:?}"),
    }
    // ...and the NEXT frame still reads. This is the whole point: one
    // unreadable request must not cost the connection.
    match read_frame::<_, ClientMsg>(&mut cur).unwrap() {
        Some(Frame::Msg(ClientMsg::Info)) => {}
        other => panic!("the stream must stay aligned, got {other:?}"),
    }
}

/// A write op is named by `op`, not `t` — the refusal must say which one, or a
/// client cannot tell which of its requests was too new to fall back on.
#[test]
fn an_unknown_write_op_is_named() {
    let mut cur = std::io::Cursor::new(framed(r#"{"op":"teleport","link_id":"x"}"#));
    match read_frame::<_, WriteOp>(&mut cur).unwrap() {
        Some(Frame::Unknown { tag }) => assert_eq!(tag, "teleport"),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

/// Tolerance is NOT unconditional. Bytes that are not a JSON object mean the
/// peer is not speaking this protocol, and reading on would be guessing.
#[test]
fn garbage_is_still_fatal() {
    let mut cur = std::io::Cursor::new(framed("not json at all"));
    assert!(
        read_frame::<_, ClientMsg>(&mut cur).is_err(),
        "a frame that is not even JSON must not be treated as a polite unknown"
    );
}

/// Relabel is the op D73 adds, and it must round-trip on the wire.
#[test]
fn the_relabel_op_round_trips() {
    let op = WriteOp::Relabel {
        link_id: "abc".into(),
        label: "Show Name (2019)".into(),
    };
    let json = serde_json::to_string(&op).unwrap();
    assert!(json.contains(r#""op":"relabel""#), "tagged as relabel: {json}");
    assert_eq!(serde_json::from_str::<WriteOp>(&json).unwrap(), op);
}

/// The two numbers that let a playbook tell an additive bump from a breaking
/// one. `PROTO_VERSION` is what we speak; `PROTO_COMPATIBLE_WITH` is how far
/// back we degrade. Moving the FLOOR is the fleet-wide event — moving the
/// version alone is not.
#[test]
fn the_compatibility_floor_is_not_above_what_we_speak() {
    // (`COMPATIBLE_WITH <= VERSION` is a compile-time assertion in the crate —
    // it cannot be violated, so there is nothing for a runtime test to catch.)
    assert_eq!(
        PROTO_COMPATIBLE_WITH, 3,
        "D73 is additive: proto 4 still talks to 3. Changing this is a \
         fleet-wide event and should be a deliberate edit, not a surprise."
    );
}

/// D148 — an older daemon's `serve status` reply has no `trash`; it still
/// decodes (empty), and a new reply round-trips.
#[test]
fn an_older_serve_jobs_reply_without_trash_decodes() {
    let old = r#"{"t":"serve_jobs","runner":"on","jobs":[],"conflicts":0,"stale":0}"#;
    match serde_json::from_str::<pvfs_proto::ServerMsg>(old).unwrap() {
        pvfs_proto::ServerMsg::ServeJobs { trash, capacity, .. } => {
            assert!(trash.is_empty());
            assert!(capacity.is_none());
        }
        other => panic!("{other:?}"),
    }
    let new = pvfs_proto::ServerMsg::ServeJobs {
        runner: Box::new("on".into()),
        jobs: Box::default(),
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::new(vec![pvfs_proto::TrashWire {
            region: "fe38175f".into(),
            bytes: 5,
            buckets: 1,
            oldest_day: Some(20691),
            retention_days: 7,
            freed_bytes: 0,
            measured_ms: 1,
        }]),
        log_destinations: Box::default(),
        stores: Box::default(),
        mounts: Box::default(),
        log: None,
        fenced: None,
        backup: None,
        build: None,
        log_level: None,
    };
    let s = serde_json::to_string(&new).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&s).unwrap(), new);
}

/// PVOS D178 — an older daemon's reply has no `stores`: it decodes (empty),
/// and a new reply round-trips with them.
#[test]
fn an_older_serve_jobs_reply_without_stores_decodes() {
    let old = r#"{"t":"serve_jobs","runner":"on","jobs":[],"conflicts":0,"stale":0,"capacity":{"free_bytes":1,"total_bytes":2},"trash":[]}"#;
    match serde_json::from_str::<pvfs_proto::ServerMsg>(old).unwrap() {
        pvfs_proto::ServerMsg::ServeJobs { stores, capacity, .. } => {
            assert!(stores.is_empty());
            assert!(capacity.is_some());
        }
        other => panic!("{other:?}"),
    }
    let new = pvfs_proto::ServerMsg::ServeJobs {
        runner: Box::new("on".into()),
        jobs: Box::default(),
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::default(),
        log_destinations: Box::default(),
        stores: Box::new(vec![
            pvfs_proto::StoreWire { path: "/srv/pvfs/x/.pvfs/sync".into(), regions: vec![], free_bytes: 3, total_bytes: 4 },
            pvfs_proto::StoreWire { path: "/mnt/local".into(), regions: vec!["c020473f".into()], free_bytes: 5, total_bytes: 6 },
        ]),
        mounts: Box::default(),
        log: None,
        fenced: None,
        backup: None,
        build: None,
        log_level: None,
    };
    let s = serde_json::to_string(&new).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&s).unwrap(), new);
}

/// PVOS D181 — an older daemon's reply has no `mounts`: it decodes (empty),
/// and a new reply round-trips with them. A box keeps its view mount running
/// across a roll, so the fleet has to be able to read "which build is that
/// mount on" from a daemon that has just been rolled and one that has not.
#[test]
fn an_older_serve_jobs_reply_without_mounts_decodes() {
    let old = r#"{"t":"serve_jobs","runner":"on","jobs":[],"conflicts":0,"stale":0,"trash":[],"stores":[]}"#;
    match serde_json::from_str::<pvfs_proto::ServerMsg>(old).unwrap() {
        pvfs_proto::ServerMsg::ServeJobs { mounts, .. } => assert!(mounts.is_empty()),
        other => panic!("{other:?}"),
    }
    let new = pvfs_proto::ServerMsg::ServeJobs {
        runner: Box::new("on".into()),
        jobs: Box::default(),
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::default(),
        log_destinations: Box::default(),
        stores: Box::default(),
        mounts: Box::new(vec![pvfs_proto::MountWire {
            mountpoint: "/mnt/pvfs/Media".into(),
            build: "v1.4-416-gf085fdb".into(),
            behind: true,
            stale: None,
            started_ms: 7,
        }]),
        log: None,
        fenced: None,
        backup: None,
        build: None,
        log_level: None,
    };
    let s = serde_json::to_string(&new).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&s).unwrap(), new);
}

/// PVOS D182 — `serve status` gains the box's log tip and, on a fenced owner,
/// the fence. An older reply decodes without them; a new one round-trips.
#[test]
fn an_older_serve_jobs_reply_without_log_or_fence_decodes() {
    let old = r#"{"t":"serve_jobs","runner":"on","jobs":[],"conflicts":0,"stale":0,"trash":[],"stores":[],"mounts":[]}"#;
    match serde_json::from_str::<pvfs_proto::ServerMsg>(old).unwrap() {
        pvfs_proto::ServerMsg::ServeJobs { log, fenced, .. } => {
            assert!(log.is_none());
            assert!(fenced.is_none());
        }
        other => panic!("{other:?}"),
    }
    let new = pvfs_proto::ServerMsg::ServeJobs {
        runner: Box::new("on".into()),
        jobs: Box::default(),
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::default(),
        log_destinations: Box::default(),
        stores: Box::default(),
        mounts: Box::default(),
        log: Some(Box::new(pvfs_proto::LogTipWire { seq: 3472, hash: "ab".repeat(32) })),
        fenced: Some(Box::new(pvfs_proto::FenceWire {
            reason: "x holds the forest's log to seq 3480".into(),
            peer: "192.168.1.142:7435".into(),
            peer_seq: 3480,
            own_seq: 3472,
            at_ms: 9,
        })),
        backup: Some(Box::new(pvfs_proto::BackupWire { at_ms: 7, ok: true, seq: Some(3472), error: None })),
        build: None,
        log_level: None,
    };
    let s = serde_json::to_string(&new).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&s).unwrap(), new);
}

/// PVOS D200 — `serve status` gains the daemon's build. A reply from a daemon
/// before it (every field up to D182's, no `build`) decodes with none; a new
/// one round-trips, and says the build on the wire under that name (the page
/// and the health record read it).
#[test]
fn an_older_serve_jobs_reply_without_build_decodes() {
    let old = r#"{"t":"serve_jobs","runner":"on","jobs":[],"conflicts":0,"stale":0,"trash":[],"stores":[],"mounts":[],"log":{"seq":3,"hash":"ab"}}"#;
    match serde_json::from_str::<pvfs_proto::ServerMsg>(old).unwrap() {
        pvfs_proto::ServerMsg::ServeJobs { build, log, .. } => {
            assert!(build.is_none());
            assert!(log.is_some());
        }
        other => panic!("{other:?}"),
    }
    let new = pvfs_proto::ServerMsg::ServeJobs {
        runner: Box::new("on".into()),
        jobs: Box::default(),
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::default(),
        log_destinations: Box::default(),
        stores: Box::default(),
        mounts: Box::default(),
        log: None,
        fenced: None,
        backup: None,
        build: Some(Box::new("v1.4-495-gc17ae29".into())),
        log_level: None,
    };
    let s = serde_json::to_string(&new).unwrap();
    assert!(s.contains(r#""build":"v1.4-495-gc17ae29""#), "{s}");
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&s).unwrap(), new);
}

/// PVOS D182 — a routed write carries the replica's tip. An older replica's
/// request (no tip) decodes on a new owner; a new request decodes as the same
/// write on an older owner, which simply ignores the field (serde's default:
/// unknown fields are not an error). And no tip, no field on the wire.
#[test]
fn a_prepare_write_tip_is_optional_both_ways() {
    let op = pvfs_proto::WriteOp::CommitRegionHead { region: "r".into(), seq: 2, hash: "h".into() };
    let old = r#"{"t":"prepare_write","op":{"op":"commit_region_head","region":"r","seq":2,"hash":"h"}}"#;
    match serde_json::from_str::<pvfs_proto::ClientMsg>(old).unwrap() {
        pvfs_proto::ClientMsg::PrepareWrite { op: got, tip } => {
            assert_eq!(got, op);
            assert!(tip.is_none());
        }
        other => panic!("{other:?}"),
    }
    let bare = serde_json::to_string(&pvfs_proto::ClientMsg::PrepareWrite { op: op.clone(), tip: None }).unwrap();
    assert!(!bare.contains("tip"), "no tip, no field: {bare}");
    let with = pvfs_proto::ClientMsg::PrepareWrite {
        op: op.clone(),
        tip: Some(Box::new(pvfs_proto::LogTipWire { seq: 3472, hash: "cd".repeat(32) })),
    };
    let s = serde_json::to_string(&with).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ClientMsg>(&s).unwrap(), with);
    // What an older owner does with it: the same struct minus the field.
    #[derive(serde::Deserialize)]
    #[serde(tag = "t", rename_all = "snake_case")]
    enum OldClientMsg {
        PrepareWrite { op: pvfs_proto::WriteOp },
    }
    match serde_json::from_str::<OldClientMsg>(&s).unwrap() {
        OldClientMsg::PrepareWrite { op: got } => assert_eq!(got, op),
    }
}

/// PVOS D207 — a job row from an older daemon (no `progress`) decodes; a
/// row with a pass in flight carries it, and one without leaves it out.
#[test]
fn a_job_row_with_and_without_progress() {
    let old = r#"{"name":"watch","enabled":true,"state":"running","last_ok_ms":1,"last_error":null}"#;
    let row: pvfs_proto::ServeJobWire = serde_json::from_str(old).unwrap();
    assert_eq!(row.progress, None);
    assert!(!serde_json::to_string(&row).unwrap().contains("progress"), "absent when no pass is in flight");
    let with = pvfs_proto::ServeJobWire {
        progress: Some(pvfs_proto::PassProgressWire {
            started_ms: 1,
            advanced_ms: 2,
            files_done: 3,
            bytes_done: 4,
            phase: Some("pulling".into()),
            current: vec![pvfs_proto::FileProgressWire {
                path: "Shows/e01.mkv".into(),
                hash: Some("ab".into()),
                bytes: 5,
                size: Some(6),
                advanced_ms: 2,
            }],
        }),
        ..row
    };
    let json = serde_json::to_string(&with).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ServeJobWire>(&json).unwrap(), with);
}

/// PVOS D228 — `serve status` carries each log destination's health; an
/// older daemon's reply (none) still parses, and a box with none sends no
/// field.
#[test]
fn serve_status_log_destinations_are_optional_both_ways() {
    let old = r#"{"t":"serve_jobs","runner":"on","jobs":[]}"#;
    match serde_json::from_str::<pvfs_proto::ServerMsg>(old).unwrap() {
        pvfs_proto::ServerMsg::ServeJobs { log_destinations, .. } => assert!(log_destinations.is_empty()),
        other => panic!("{other:?}"),
    }
    let mut new = pvfs_proto::ServerMsg::ServeJobs {
        runner: Box::new("on".into()),
        jobs: Box::default(),
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::default(),
        log_destinations: Box::default(),
        stores: Box::default(),
        mounts: Box::default(),
        log: None,
        fenced: None,
        backup: None,
        build: None,
        log_level: None,
    };
    assert!(!serde_json::to_string(&new).unwrap().contains("log_destinations"));
    if let pvfs_proto::ServerMsg::ServeJobs { log_destinations, .. } = &mut new {
        log_destinations.push(pvfs_proto::LogDestHealthWire {
            name: "loki".into(),
            kind: "loki".into(),
            sent: 12,
            queued_bytes: 4096,
            dropped: 0,
            last_ok_ms: 1_791_000_000_000,
            last_error: Some("connection refused".into()),
            failing: true,
        });
    }
    let s = serde_json::to_string(&new).unwrap();
    assert!(s.contains(r#""log_destinations":[{"name":"loki","type":"loki""#), "{s}");
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&s).unwrap(), new);
}


/// PVOS D229 — `serve status` from an older daemon has no log level; a new
/// one round-trips, and `SetLogLevel` (proto 17) round-trips with and
/// without its minutes.
#[test]
fn serve_status_log_level_is_optional_and_set_log_level_round_trips() {
    let old = r#"{"t":"serve_jobs","runner":"on","jobs":[]}"#;
    match serde_json::from_str::<pvfs_proto::ServerMsg>(old).unwrap() {
        pvfs_proto::ServerMsg::ServeJobs { log_level, .. } => assert!(log_level.is_none()),
        other => panic!("{other:?}"),
    }
    let lvl = pvfs_proto::LogLevelWire {
        configured: "info".into(),
        current: "debug".into(),
        until_ms: 1_791_000_000_000,
        by: "key:4f1c".into(),
    };
    let reply = pvfs_proto::ServerMsg::LogLevel(Box::new(lvl.clone()));
    let back: pvfs_proto::ServerMsg = serde_json::from_str(&serde_json::to_string(&reply).unwrap()).unwrap();
    assert_eq!(back, reply);
    let quiet = pvfs_proto::LogLevelWire { configured: "info".into(), current: "info".into(), ..Default::default() };
    let j = serde_json::to_string(&pvfs_proto::ServerMsg::LogLevel(Box::new(quiet))).unwrap();
    assert!(!j.contains("until_ms") && !j.contains("\"by\""), "{j}");

    let set = pvfs_proto::ClientMsg::SetLogLevel { level: "debug".into(), minutes: 30 };
    assert_eq!(set.op_name(), "set_log_level");
    let j = serde_json::to_string(&set).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ClientMsg>(&j).unwrap(), set);
    let bare: pvfs_proto::ClientMsg = serde_json::from_str(r#"{"t":"set_log_level","level":"default"}"#).unwrap();
    assert_eq!(bare, pvfs_proto::ClientMsg::SetLogLevel { level: "default".into(), minutes: 0 });
}

/// PVOS D230 — `Diagnose` (proto 18) and its answer round-trip; the answer
/// from a box without a problems file says why, and an empty list is fine.
#[test]
fn diagnose_round_trips() {
    let ask = pvfs_proto::ClientMsg::Diagnose { since_ms: 1_791_000_000_000 };
    assert_eq!(ask.op_name(), "diagnose");
    assert_eq!(serde_json::from_str::<pvfs_proto::ClientMsg>(&serde_json::to_string(&ask).unwrap()).unwrap(), ask);
    let bare: pvfs_proto::ClientMsg = serde_json::from_str(r#"{"t":"diagnose"}"#).unwrap();
    assert_eq!(bare, pvfs_proto::ClientMsg::Diagnose { since_ms: 0 });
    let d = pvfs_proto::DiagnoseWire {
        now_ms: 1_791_000_000_500,
        started_ms: 1_790_990_000_000,
        host: "qnap".into(),
        build: "v1.4-620".into(),
        forest: "ae60b1db".into(),
        role: "replica".into(),
        jobs: "follow".into(),
        regions: "1 catalogue".into(),
        listen: "0.0.0.0:7434".into(),
        privacy: "full".into(),
        problems: vec![pvfs_proto::ProblemWire {
            ts_ms: 1_791_000_000_000,
            severity: "warning".into(),
            event: "pvfs.writer.held".into(),
            error_kind: "slow:held".into(),
            service: "pvfsd".into(),
            line: "pvfsd: the writer was held 2.4 s by scan".into(),
        }],
        problems_left_out: 4,
        problems_note: String::new(),
    };
    let reply = pvfs_proto::ServerMsg::Diagnose(Box::new(d));
    let j = serde_json::to_string(&reply).unwrap();
    assert!(!j.contains("problems_note"), "{j}");
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&j).unwrap(), reply);
}
