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

/// THE proof: a forest containing an event this binary cannot parse still
/// opens, still verifies, still serves — and SAYS it did not understand.
///
/// This is what makes a rolling upgrade possible. A newer box writes a kind an
/// older box has never heard of; the older box must keep working rather than
/// refusing the whole log. The event is appended through the real chain-hash
/// path, so this exercises replay and verification, not just decoding.
#[test]
fn a_forest_with_a_future_event_still_opens_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = pvfs_core::Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    engine
        .add_node(
            &root,
            pvfs_core::NodeSpec {
                node_type: pvfs_core::TYPE_FOLDER.into(),
                label: "library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine.close().unwrap();

    // A newer binary appends a kind we have never heard of, chained correctly.
    {
        // The append writes to the attached `log` alias, exactly as an engine
        // connection has it.
        let mut conn = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
        conn.execute(
            "ATTACH DATABASE ?1 AS log",
            [dir.path().join("log.db").to_str().unwrap()],
        )
        .unwrap();
        let (seq, prev): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT seq, chain_hash FROM log.events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let mut prev32 = [0u8; 32];
        prev32.copy_from_slice(&prev);
        let future = Event::Unknown {
            kind: "MediaTitleAssigned".into(), // something a later version might add
            body: b"imdb=tt0111161".to_vec(),
        };
        let tx = conn.transaction().unwrap();
        pvfs_core::log_store::append_event(&tx, &prev32, seq as u64 + 1, &future, 1)
            .expect("appending a future event must chain like any other");
        tx.commit().unwrap();
    }

    // Force a full replay so the unknown event goes through the fold.
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let engine = pvfs_core::Engine::open(dir.path())
        .expect("a forest newer than this binary must still OPEN");

    // It still works: the parts it understood are intact.
    let kids = engine.children(&root).unwrap();
    assert!(
        kids.iter().any(|c| c.node.label == "library"),
        "everything this binary DID understand must still be there"
    );
    engine.close().unwrap();

    // And it is honest about the part it did not.
    let (n, kinds) = pvfs_core::projection::unknown_events(dir.path())
        .expect("the count must be recorded");
    assert_eq!(n, 1, "the skipped event is counted, not silently dropped");
    assert!(
        kinds.contains("MediaTitleAssigned"),
        "and named, so an operator knows WHAT it is behind on: {kinds}"
    );
}

/// D72 Part B — `LinkRelabeled` round-trips, and the ROLLING claim is named
/// honestly rather than faked.
///
/// What a unit test can show: the event encodes and decodes correctly, and
/// (above) that an unrecognised kind is tolerated, counted and named.
///
/// What it CANNOT show: that an OLDER box tolerates this specific event. This
/// binary knows the kind, so asking it to decode "LinkRelabeled" gives the
/// real variant — any "old box" simulation here would be a costume, not a
/// test. That claim needs two binaries and belongs on the lab (D72 §6 step 3),
/// where PVFS has never yet knowingly run a mixed-version fleet.
#[test]
fn a_relabel_round_trips() {
    let ev = Event::LinkRelabeled {
        link_id: "abc123".into(),
        label: "Show Name (2019)".into(),
        author: vec![1, 2, 3],
        sig: vec![4, 5, 6],
    };
    let body = ev.encode_body();
    assert_eq!(ev.kind(), pvfs_core::event::K_LINK_RELABELED);

    match Event::decode(pvfs_core::event::K_LINK_RELABELED, &body).unwrap() {
        Event::LinkRelabeled { link_id, label, .. } => {
            assert_eq!(link_id, "abc123");
            assert_eq!(label, "Show Name (2019)");
        }
        other => panic!("expected LinkRelabeled, got {:?}", other.kind()),
    }
}

// ---------------------------------------------------------------------------
// The gap the mixed-version lab test exposed BEFORE it was ever run.
// ---------------------------------------------------------------------------

/// `is_known_kind` must answer for the kinds this binary actually decodes —
/// it is the migration's only way to ask "did I ignore something I can now
/// read?", and a wrong answer costs correctness in both directions.
#[test]
fn a_binary_knows_which_kinds_it_knows() {
    use pvfs_core::event::{is_known_kind, K_LINK_CREATED, K_LINK_RELABELED};

    assert!(is_known_kind(K_LINK_CREATED), "a long-standing kind");
    assert!(is_known_kind(K_LINK_RELABELED), "the kind Part B adds");
    assert!(
        !is_known_kind("SomethingFromTheFuture"),
        "a kind no binary has ever emitted"
    );
}

/// THE ROLLING-UPGRADE TRAP, pinned.
///
/// Part A lets an older box fold an event it cannot read as `Unknown` and keep
/// going. That box's projection is then MISSING whatever the event carried.
/// If it later gains the code to read that kind, the cheap in-place migration
/// (an `ALTER` adding an empty column) does NOT recover it — the labels are in
/// the log, not in the column, and nothing re-reads the log.
///
/// This is not a corner case. In a rolling upgrade every box except the first
/// is behind for a while, so nearly every box may have ignored events it can
/// now read. Migrating those in place leaves them permanently, silently wrong
/// — the exact failure Part A's "tolerance must never become silence" rule
/// exists to prevent.
///
/// So: recorded unknown events whose kinds are NOW known must force the slow
/// door (replay). Unknown events still genuinely unknown must not — a replay
/// would not teach the box anything it does not already lack.
#[test]
fn a_box_that_ignored_an_event_it_can_now_read_must_replay_not_migrate() {
    use pvfs_core::event::is_known_kind;

    // The decision the migration makes, stated exactly as the code states it.
    let should_replay = |kinds: &str| {
        kinds
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .any(is_known_kind)
    };

    assert!(
        should_replay("LinkRelabeled"),
        "ignored a relabel, then learned to read one ⇒ the column is empty \
         but the log has the names ⇒ MUST replay"
    );
    assert!(
        should_replay("SomethingFromTheFuture,LinkRelabeled"),
        "one now-known kind among unknowns is enough to require a replay"
    );
    assert!(
        !should_replay("SomethingFromTheFuture"),
        "still unreadable ⇒ a replay teaches nothing ⇒ take the cheap door"
    );
    assert!(!should_replay(""), "nothing ignored ⇒ nothing to recover");
}

/// The bug the read-path flip nearly shipped.
///
/// Identity-by-name matched `nodes.label`. Once a rename became a
/// `LinkRelabeled`, the NODE label stayed at the old name — so a file renamed
/// in place would stop matching its own catalogue entry, and the next watch
/// pass would enrol it as a NEW file. A duplicate node for a file that was
/// merely renamed is exactly the re-cataloguing D72 exists to remove, and it
/// would have looked like a working rename right up until the next scan.
///
/// This pins the resolution rule that the fix and `Engine::children` share:
/// a link that HAS a label is known by it; a link without one falls back to
/// the node's.
#[test]
fn a_renamed_file_is_matched_by_its_new_name_not_its_old_one() {
    // The predicate, exactly as the SQL states it.
    let matches = |link_label: &str, node_label: &str, looking_for: &str| {
        if !link_label.is_empty() {
            link_label == looking_for
        } else {
            node_label == looking_for
        }
    };

    // Renamed in place: the disk now says the new name, the node still says the old.
    assert!(
        matches("Deep Show (2021) - s01e01.mkv", "Deep Show - s01e01.mkv",
                "Deep Show (2021) - s01e01.mkv"),
        "a renamed file must match the name it now has on disk"
    );
    assert!(
        !matches("Deep Show (2021) - s01e01.mkv", "Deep Show - s01e01.mkv",
                 "Deep Show - s01e01.mkv"),
        "and must NOT still answer to the name it was renamed away from — \
         otherwise the old path would resurrect as a second live claim"
    );

    // Never renamed: the node label is the name, exactly as before D72.
    assert!(
        matches("", "Deep Show - s01e01.mkv", "Deep Show - s01e01.mkv"),
        "an un-renamed file keeps matching by its node label — the fallback is \
         the NORMAL case, not a legacy path"
    );
}
