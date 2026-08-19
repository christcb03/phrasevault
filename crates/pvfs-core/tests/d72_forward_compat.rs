//! D72 Part A — a box must survive a forest newer than itself.
//!
//! Two things used to make every format change fleet-wide:
//! `Event::decode` hard-errored on an unknown kind, and `Dec::finish()`
//! hard-errored on trailing bytes. So neither a new event type nor an added
//! field could pass an older binary, and no wire change could ever roll.
//!
//! What makes tolerance safe is that the chain hash covers `(seq, kind, body,
//! written_at)` — the RAW bytes — so a box can verify the log's integrity
//! without understanding what every event MEANS.
//!
//! What tolerance must never become is silence: a box that skipped an event is
//! missing whatever that event said, and reporting itself healthy would be a
//! lie. These tests pin both halves.

use pvfs_core::event::Event;

#[test]
fn an_unknown_kind_is_kept_not_rejected() {
    let body = b"a payload written by a newer binary".to_vec();
    let ev = Event::decode("SomethingFromTheFuture", &body)
        .expect("an unknown kind must not stop a replay");

    match &ev {
        Event::Unknown { kind, body: got } => {
            assert_eq!(kind, "SomethingFromTheFuture");
            assert_eq!(got, &body);
        }
        other => panic!("expected Unknown, got {:?}", other.kind()),
    }
}

/// It must re-encode byte-for-byte: any re-encoding would change the chain
/// hash and break the log for every box that DOES understand the event.
#[test]
fn an_unknown_event_round_trips_exactly() {
    let body = vec![0x00, 0xff, 0x10, 0x42, 0x99];
    let ev = Event::decode("FutureKind", &body).unwrap();
    assert_eq!(ev.encode_body(), body);
    assert_eq!(ev.kind(), "FutureKind");
}

/// An unknown event authorizes nothing. We cannot name an author we cannot
/// parse, and replay must not grant authority it cannot verify.
#[test]
fn an_unknown_event_carries_no_authority() {
    let ev = Event::decode("FutureKind", b"x").unwrap();
    assert!(ev.author().is_empty(), "no parse ⇒ no author ⇒ no authority");
}

/// And it must never claim to have verified. Returning Ok here would be a
/// silent "this is fine" for bytes we cannot even read.
#[test]
fn an_unknown_event_refuses_signature_verification() {
    let ev = Event::decode("FutureKind", b"x").unwrap();
    let err = ev.verify_sig().unwrap_err().to_string();
    assert!(
        err.contains("does not know the kind"),
        "the refusal must explain itself, got: {err}"
    );
}

/// Trailing bytes on a KNOWN event are tolerated — that is what lets a future
/// version append an optional field without breaking older readers, which is
/// the single change that turns a fleet-wide upgrade into a rolling one.
#[test]
fn a_known_event_tolerates_a_field_it_does_not_know_about() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = pvfs_core::Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = engine
        .add_node(
            &root,
            pvfs_core::NodeSpec {
                node_type: pvfs_core::TYPE_FOLDER.into(),
                label: "shelf".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine.close().unwrap();

    // Take a real event and append bytes, as a newer writer would.
    let log = rusqlite::Connection::open(dir.path().join("log.db")).unwrap();
    let (kind, mut body): (String, Vec<u8>) = log
        .query_row(
            "SELECT kind, body FROM events WHERE kind = 'NodeCreated'
              ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    body.extend_from_slice(b"a field from a later version");

    let ev = Event::decode(&kind, &body)
        .expect("an appended field must not break an older reader");
    match ev {
        Event::NodeCreated(n) => assert_eq!(n.label, "shelf", "the known fields still decode"),
        other => panic!("expected NodeCreated, got {:?}", other.kind()),
    }
    assert!(!f.is_empty());
}
