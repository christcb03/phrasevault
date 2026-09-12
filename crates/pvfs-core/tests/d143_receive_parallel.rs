//! D143 — the receiving region's parallel setting lives in the placement.
use pvfs_core::sync;
use pvfs_core::Engine;

#[test]
fn parallel_is_stored_per_region_and_defaults_to_four() {
    let tmp = tempfile::tempdir().unwrap();
    let (e, _) = Engine::init(tmp.path()).unwrap();
    let r = "ab".repeat(32);
    sync::set_region_receive(e.data_dir(), &r, true).unwrap();
    assert_eq!(sync::region_receive_parallel(e.data_dir(), &r).unwrap(), sync::RECEIVE_PARALLEL_DEFAULT);
    sync::set_region_receive_parallel(e.data_dir(), &r, 3).unwrap();
    assert_eq!(sync::region_receive_parallel(e.data_dir(), &r).unwrap(), 3);
    assert_eq!(sync::receiving_regions(e.data_dir()).unwrap(), vec![r.clone()], "still receiving");
    sync::set_region_receive_parallel(e.data_dir(), &r, 0).unwrap();
    assert_eq!(sync::region_receive_parallel(e.data_dir(), &r).unwrap(), 1, "never zero");
    sync::set_region_receive(e.data_dir(), &r, false).unwrap();
    sync::set_region_receive(e.data_dir(), &r, true).unwrap();
    assert_eq!(sync::region_receive_parallel(e.data_dir(), &r).unwrap(), 1, "off and on keeps it");
    sync::set_region_receive_streams(e.data_dir(), &r, 6).unwrap();
    assert_eq!(sync::region_receive_streams(e.data_dir(), &r).unwrap(), 6);
    let text = std::fs::read_to_string(e.data_dir().join("placement")).unwrap();
    assert!(text.contains(&format!("receive {r} 1 6")), "{text}");
    assert_eq!(sync::region_receive_parallel(e.data_dir(), &r).unwrap(), 1, "both survive a re-read");
}
