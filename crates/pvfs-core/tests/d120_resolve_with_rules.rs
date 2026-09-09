//! D120 — a pending change can be weighed on the D76 ladder instead of blind.
//!
//! A pending change says "the file at this path is not the file I catalogued".
//! Deciding which is better was entirely manual: `resolve --replace` or
//! `--delete`, chosen without evidence, with `pvfs explain` available only as a
//! separate thing you had to know to run. The ladder `collide` and the mover
//! already use is `media::choose`; this points it at the change.
//!
//! The incoming copy has a size and no measured quality. That is NOT "no
//! opinion" — the ladder falls through empty rungs to the next one and reaches
//! size, which on this library is the case that matters: the unmeasured files
//! are the ones nobody analysed.

use pvfs_core::media::Rules;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn rig(first: usize, second: usize) -> (tempfile::TempDir, Engine, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("ep01.mkv"), vec![1u8; first]).unwrap();

    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let folder = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Season 01".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    e.bind_folder(
        &folder,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&folder), None, 0).unwrap();
    let id = e
        .children(&folder)
        .unwrap()
        .into_iter()
        .find(|c| c.node.node_type == TYPE_FILE)
        .unwrap()
        .node
        .id;

    // The file is replaced at the same path — the *arr-upgrade shape.
    std::fs::write(lib.join("ep01.mkv"), vec![2u8; second]).unwrap();
    let rep = e.scan_routed(Some(&folder), None, 0).unwrap();
    assert_eq!(rep[0].stats.changed, 1, "the replacement must be FLAGGED");
    (dir, e, folder, id)
}

/// A significantly larger incoming copy wins on the size rung, and says so.
#[test]
fn a_bigger_incoming_copy_wins_and_explains_itself() {
    let (_d, e, _f, id) = rig(1_000_000, 2_000_000);
    let (incoming_wins, verdict) = e.weigh_pending_change(&id, &Rules::default()).unwrap();
    assert!(incoming_wins, "twice the size should win: {}", verdict.reason());
    assert!(verdict.decided(), "and it must be a DECISION, not a shrug");
    assert!(
        !verdict.reason().is_empty(),
        "the reason is the point — a verdict nobody can read is no better than guessing"
    );
    e.close().unwrap();
}

/// A smaller incoming copy does NOT win. The flag stays: the file on disk is
/// still the wrong one, and something has to keep saying so.
#[test]
fn a_smaller_incoming_copy_does_not_win() {
    let (_d, e, _f, id) = rig(2_000_000, 1_000_000);
    let (incoming_wins, verdict) = e.weigh_pending_change(&id, &Rules::default()).unwrap();
    assert!(
        !incoming_wins,
        "half the size must not replace the catalogued copy: {}",
        verdict.reason()
    );
    e.close().unwrap();
}

/// Inside the size margin the ladder does NOT stop — it falls through to
/// recency and takes the newer copy.
///
/// I expected a refusal here and was wrong, which is worth recording: the
/// ladder's last rung is "newer wins", so two comparable copies still get a
/// decision. For a pending change that is the right answer — the file was
/// replaced at that path deliberately, and the replacement is the newer one.
/// A genuinely truncated rewrite is caught earlier, by `truncation_pct`.
#[test]
fn a_comparable_size_falls_through_to_recency() {
    let (_d, e, _f, id) = rig(1_000_000, 1_020_000); // 2%, inside the 10% margin
    let (incoming_wins, verdict) = e.weigh_pending_change(&id, &Rules::default()).unwrap();
    assert!(
        verdict.reason().contains("newer"),
        "expected the recency rung, got: {}",
        verdict.reason()
    );
    assert!(
        incoming_wins,
        "the file just written at that path is the newer one: {}",
        verdict.reason()
    );
    e.close().unwrap();
}

/// A truncated rewrite is NOT an upgrade, however new it is — the truncation
/// rung fires before recency can.
#[test]
fn a_truncated_rewrite_does_not_win_on_being_newer() {
    let (_d, e, _f, id) = rig(2_000_000, 1_000_000); // half the size
    let (incoming_wins, verdict) = e.weigh_pending_change(&id, &Rules::default()).unwrap();
    assert!(
        !incoming_wins,
        "newer must not beat half-the-bytes: {}",
        verdict.reason()
    );
    e.close().unwrap();
}

/// No pending change is an error, not a silent "keep" — asking about a change
/// that does not exist is a mistake worth hearing about.
#[test]
fn weighing_a_file_with_no_pending_change_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let err = e.weigh_pending_change(&root, &Rules::default());
    assert!(err.is_err(), "expected NotFound, got {err:?}");
    e.close().unwrap();
}
