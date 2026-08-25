//! D84 — two live nodes at one tree path are the same episode.
//!
//! The identity this library actually has is the PATH. The arrs write
//! `Show - s16e10 - Title.mkv` with no quality tag, so an upgrade lands at the
//! same path — which is why it replaces in place. Content identity answers
//! "are these the same bytes?"; the question here is "are these the same
//! episode?", and only the path answers that without hashing 67 TB.
//!
//! Chris: "we don't need to use hash to tell what the file is when we have the
//! path... that is the identifier for that episode."
//!
//! The governing asymmetry, and why refusal is everywhere in these tests:
//! **leaving a duplicate costs a refusal; deciding wrongly costs a file.**

use pvfs_core::{Engine, FilePayload, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn forest(dir: &std::path::Path) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(dir).unwrap();
    let root = e.identity.root_node_id.clone();
    let media = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Media".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    (e, media)
}

/// A file node at `label` under `parent`, optionally holding bytes.
fn file_at(e: &mut Engine, parent: &str, label: &str, size: u64, bytes: Option<&std::path::Path>) -> String {
    let id = e
        .add_node(
            &parent.to_string(),
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: label.into(),
                payload: FilePayload {
                    content_hash: String::new(),
                    size_bytes: size,
                    mime_type: "video/x-matroska".into(),
                    original_name: label.into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    if let Some(p) = bytes {
        e.add_location(&id, &pvfs_core::storage::path_to_uri(p).unwrap())
            .unwrap();
    }
    id
}

fn live(e: &Engine, id: &str) -> bool {
    e.walk(&e.identity.root_node_id.clone())
        .unwrap()
        .entries
        .iter()
        .any(|x| x.node.id == id)
}

/// A node holding nothing loses to one that does, and no ladder is needed to
/// say so. 91 of the production 184 are exactly this shape — the residue of an
/// in-place replacement that catalogued the new content and never retired the
/// old node.
#[test]
fn a_ghost_loses_to_a_node_that_holds_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = dir.path().join("ep.mkv");
    std::fs::write(&bytes, vec![b'a'; 2048]).unwrap();
    let (mut e, media) = forest(&dir.path().join("forest"));

    let real = file_at(&mut e, &media, "ep.mkv", 2048, Some(&bytes));
    let ghost = file_at(&mut e, &media, "ep.mkv", 2048, None);

    // No rules: a ghost needs none. It cannot be the better copy.
    let r = pvfs_client::fetch::collide_pass(&mut e, &media, None, false).unwrap();
    assert_eq!(r.examined, 1);
    assert_eq!(r.resolved, 1, "the ghost is not a judgement call");
    assert!(r.refused.is_empty());

    assert!(live(&e, &real), "the node holding bytes survives");
    assert!(!live(&e, &ghost), "the ghost is out of the tree");
    e.close().unwrap();
}

/// THE ONE THAT MUST NOT BE CLEVER: where NO node at a path holds bytes, all
/// are kept. Those are the 98 episodes a drive failure took, which Chris chose
/// deliberately to keep as a record. "Tidying" them erases the only trace they
/// ever existed.
#[test]
fn a_path_where_nothing_holds_bytes_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, media) = forest(&dir.path().join("forest"));
    let a = file_at(&mut e, &media, "lost.mkv", 2048, None);
    let b = file_at(&mut e, &media, "lost.mkv", 4096, None);

    let r = pvfs_client::fetch::collide_pass(&mut e, &media, None, false).unwrap();
    assert_eq!(r.resolved, 0);
    assert_eq!(r.refused.len(), 1);
    assert!(
        r.refused[0].1.contains("none holding bytes"),
        "and it must say why: {:?}",
        r.refused[0]
    );
    assert!(live(&e, &a) && live(&e, &b), "a record of a loss is not a duplicate");
    e.close().unwrap();
}

/// Two REAL copies are a judgement call, and the ladder is opt-in exactly as it
/// is for the mover. Without `--rules` a human decides.
#[test]
fn two_real_copies_are_refused_without_rules() {
    let dir = tempfile::tempdir().unwrap();
    let (p, q) = (dir.path().join("a.mkv"), dir.path().join("b.mkv"));
    std::fs::write(&p, vec![b'a'; 2048]).unwrap();
    std::fs::write(&q, vec![b'b'; 9000]).unwrap();
    let (mut e, media) = forest(&dir.path().join("forest"));
    let a = file_at(&mut e, &media, "ep.mkv", 2048, Some(&p));
    let b = file_at(&mut e, &media, "ep.mkv", 9000, Some(&q));

    let r = pvfs_client::fetch::collide_pass(&mut e, &media, None, false).unwrap();
    assert_eq!(r.resolved, 0);
    assert_eq!(r.refused.len(), 1);
    assert!(live(&e, &a) && live(&e, &b), "nothing is touched without rules");
    e.close().unwrap();
}

/// With the rules on, the ladder decides — and on unmeasured TV it reaches
/// SIZE, which is the rung Chris asked for: "I want the larger one to win."
#[test]
fn with_rules_the_larger_copy_wins() {
    let dir = tempfile::tempdir().unwrap();
    let (p, q) = (dir.path().join("a.mkv"), dir.path().join("b.mkv"));
    std::fs::write(&p, vec![b'a'; 2048]).unwrap();
    std::fs::write(&q, vec![b'b'; 9000]).unwrap();
    let (mut e, media) = forest(&dir.path().join("forest"));
    let small = file_at(&mut e, &media, "ep.mkv", 2048, Some(&p));
    let large = file_at(&mut e, &media, "ep.mkv", 9000, Some(&q));

    let rules = pvfs_core::media::Rules::default();
    let r = pvfs_client::fetch::collide_pass(&mut e, &media, Some(rules), false).unwrap();
    assert_eq!(r.resolved, 1, "refused: {:?}", r.refused);
    assert!(live(&e, &large), "the larger copy survives");
    assert!(!live(&e, &small));
    e.close().unwrap();
}

/// A dry run must be worth trusting before it is pointed at 184 real paths.
#[test]
fn a_dry_run_reports_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = dir.path().join("ep.mkv");
    std::fs::write(&bytes, vec![b'a'; 2048]).unwrap();
    let (mut e, media) = forest(&dir.path().join("forest"));
    let real = file_at(&mut e, &media, "ep.mkv", 2048, Some(&bytes));
    let ghost = file_at(&mut e, &media, "ep.mkv", 2048, None);

    let r = pvfs_client::fetch::collide_pass(&mut e, &media, None, true).unwrap();
    assert_eq!(r.examined, 1);
    assert!(!r.planned.is_empty(), "a dry run must SAY what it would do");
    assert!(live(&e, &real) && live(&e, &ghost), "and change nothing");
    e.close().unwrap();
}
