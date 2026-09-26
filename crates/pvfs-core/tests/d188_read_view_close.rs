//! PVOS D188 — a read view closes without writing.
//!
//! The CLI's read-only commands (`region ls`, `region entries`, `view ls`,
//! `info`) now read through a read view while the forest's daemon runs — the
//! Home Assistant page runs them every minute on the owner, and a full open
//! there commits region heads on close from a second process. Their code
//! paths end in `Engine::close`, which on a read view used to try to commit
//! heads and flip the clean-shutdown flag on a read-only connection (and
//! fail). A read view is born closed: closing it is dropping it.

use pvfs_core::{Engine, NodeSpec, TYPE_FOLDER};

#[test]
fn a_read_view_closes_cleanly_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut writer, _mn) = Engine::init(dir.path()).unwrap();
    let root = writer.identity.root_node_id.clone();
    let folder = |label: &str| NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    };
    writer.add_node(&root, folder("Media")).unwrap();
    let tip = writer.log_tip().unwrap();

    // The writer stays open, as the daemon keeps it.
    let view = Engine::open_read_view(dir.path()).unwrap();
    assert_eq!(view.log_tip().unwrap(), tip, "the view reads the writer's log");
    assert!(view.children(&root).unwrap().iter().any(|c| c.label == "Media"));
    view.close().expect("closing a read view is dropping it, never an error");

    assert_eq!(writer.log_tip().unwrap(), tip, "a read view's close appends nothing");
    writer.add_node(&root, folder("After")).expect("the writer is untouched");
    assert!(writer.log_tip().unwrap() > tip);
}
