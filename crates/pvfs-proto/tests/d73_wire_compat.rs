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
        runner: "on".into(),
        jobs: vec![],
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
        stores: Box::default(),
        mounts: Box::default(),
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
        runner: "on".into(),
        jobs: vec![],
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::default(),
        stores: Box::new(vec![
            pvfs_proto::StoreWire { path: "/srv/pvfs/x/.pvfs/sync".into(), regions: vec![], free_bytes: 3, total_bytes: 4 },
            pvfs_proto::StoreWire { path: "/mnt/local".into(), regions: vec!["c020473f".into()], free_bytes: 5, total_bytes: 6 },
        ]),
        mounts: Box::default(),
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
        runner: "on".into(),
        jobs: vec![],
        conflicts: 0,
        stale: 0,
        capacity: None,
        trash: Box::default(),
        stores: Box::default(),
        mounts: Box::new(vec![pvfs_proto::MountWire {
            mountpoint: "/mnt/pvfs/Media".into(),
            build: "v1.4-416-gf085fdb".into(),
            behind: true,
            stale: None,
            started_ms: 7,
        }]),
    };
    let s = serde_json::to_string(&new).unwrap();
    assert_eq!(serde_json::from_str::<pvfs_proto::ServerMsg>(&s).unwrap(), new);
}
