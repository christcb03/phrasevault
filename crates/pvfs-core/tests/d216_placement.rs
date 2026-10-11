//! D216 — a file goes where its folder already is.
//!
//! The mover used to take the emptiest receiving region for everything, so an
//! episode of a show that lives on one disk could land on another, and every
//! subtitle written through the union piled up on whichever branch was
//! writable (8,723 of them had, by 2026-10-03). The rule now prefers the
//! region that already holds the file's folder — unless that region is nearly
//! full, because a show must not fill the disk it started on.

use std::fs;

use pvfs_core::{Engine, NodeId};

fn roots(tmp: &std::path::Path, names: &[&str]) -> Vec<(NodeId, std::path::PathBuf)> {
    names
        .iter()
        .map(|n| {
            let p = tmp.join(n);
            fs::create_dir_all(&p).unwrap();
            (n.to_string(), p)
        })
        .collect()
}

fn engine(tmp: &std::path::Path) -> Engine {
    let (e, _mn) = Engine::init(&tmp.join("forest")).unwrap();
    e
}

#[test]
fn a_file_joins_the_region_that_already_holds_its_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    // `dests` arrives most-free-first; here "empty" would win on space alone.
    let dests = roots(tmp.path(), &["empty", "has_the_show"]);
    fs::create_dir_all(dests[1].1.join("TV/Foundation (2021)/Season 02")).unwrap();

    let (region, root) = e.placement_for_with_floor("TV/Foundation (2021)/Season 02/s02e05.mkv", &dests, 0).expect("a destination with room");
    assert_eq!(region, "has_the_show", "the disk that already has the season takes it");
    assert_eq!(root, dests[1].1);
    e.close().unwrap();
}

#[test]
fn with_no_region_holding_the_folder_the_emptiest_takes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["emptiest", "other"]);

    let (region, _) = e.placement_for_with_floor("TV/Brand New Show (2026)/Season 01/s01e01.mkv", &dests, 0).expect("a destination with room");
    assert_eq!(region, "emptiest", "nobody has the folder: the order from receiving_roots stands");
    e.close().unwrap();
}

#[test]
fn the_season_decides_not_the_series() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["has_season_one", "has_season_two"]);
    fs::create_dir_all(dests[0].1.join("TV/Show/Season 01")).unwrap();
    fs::create_dir_all(dests[1].1.join("TV/Show/Season 02")).unwrap();

    let (a, _) = e.placement_for_with_floor("TV/Show/Season 01/e01.mkv", &dests, 0).expect("a destination with room");
    let (b, _) = e.placement_for_with_floor("TV/Show/Season 02/e01.mkv", &dests, 0).expect("a destination with room");
    assert_eq!((a.as_str(), b.as_str()), ("has_season_one", "has_season_two"),
               "a show split by season keeps each season together");
    e.close().unwrap();
}

#[test]
fn a_supplemental_file_follows_its_episode() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["scratch", "library"]);
    let season = dests[1].1.join("TV/Show/Season 01");
    fs::create_dir_all(&season).unwrap();
    fs::write(season.join("Show - s01e01.mkv"), b"x").unwrap();

    let (region, _) = e.placement_for_with_floor("TV/Show/Season 01/Show - s01e01.en.srt", &dests, 0).expect("a destination with room");
    assert_eq!(region, "library", "the subtitle lands beside its episode, not on the writable branch");
    e.close().unwrap();
}

#[test]
fn a_file_at_the_root_has_no_folder_to_follow() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["first", "second"]);
    let (region, _) = e.placement_for_with_floor("loose.mkv", &dests, 0).expect("a destination with room");
    assert_eq!(region, "first");
    e.close().unwrap();
}

#[test]
fn a_region_under_the_floor_stops_attracting_files() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["roomy", "nearly_full"]);
    fs::create_dir_all(dests[1].1.join("TV/Show/Season 01")).unwrap();

    // A floor of 0 lets the folder win...
    let (with_room, _) = e.placement_for_with_floor("TV/Show/Season 01/e02.mkv", &dests, 0).expect("a destination with room");
    assert_eq!(with_room, "nearly_full", "the folder wins while there is room");

    // ...and the folder holder under its floor falls through to the emptiest
    // with room, which is what hands new work to library-ext as library fills
    // (Chris, D216 §6a).
    let (no_room, _) = e
        .placement_for_with_floors("TV/Show/Season 01/e02.mkv", &dests, &[0, u64::MAX])
        .expect("the roomy region takes it");
    assert_eq!(no_room, "roomy", "under the floor, the default pool takes it");
    e.close().unwrap();
}

/// PVOS D233 — the floor is a floor: with every region under it, nothing is
/// placed. It used to fall through to `dests[0]` regardless (D218 §2.1 item
/// 2), so a full disk took the file anyway.
#[test]
fn with_every_region_under_its_floor_nothing_is_placed() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["full_a", "full_b"]);
    fs::create_dir_all(dests[1].1.join("TV/Show/Season 01")).unwrap();
    assert_eq!(e.placement_for_with_floor("TV/Show/Season 01/e02.mkv", &dests, u64::MAX), None, "the folder holder is full too");
    assert_eq!(e.placement_for_with_floor("TV/New/Season 01/e01.mkv", &dests, u64::MAX), None, "no holder, nobody with room");
    e.close().unwrap();
}

/// PVOS D233 — a file at the root is held to the floor like any other (it
/// was handed to `dests[0]` with no test at all).
#[test]
fn a_file_at_the_root_honours_the_floor() {
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["first_but_full", "second"]);
    let (region, _) = e
        .placement_for_with_floors("loose.mkv", &dests, &[u64::MAX, 0])
        .expect("the second has room");
    assert_eq!(region, "second", "the emptiest WITH room, not the emptiest");
    assert_eq!(e.placement_for_with_floor("loose.mkv", &dests, u64::MAX), None);
    e.close().unwrap();
}

#[test]
fn an_unset_floor_is_a_share_of_the_disk_capped() {
    use pvfs_core::sync::default_floor_for;
    // A small disk keeps a little, so the folder rule still works there — a
    // flat 500 GB default made it silently never fire on the 58 GB lab box.
    assert_eq!(default_floor_for(58_000_000_000), 2_900_000_000);
    // A big one keeps the cap, not 5% of 80 TB.
    assert_eq!(default_floor_for(80_000_000_000_000), 500_000_000_000);
    // And an unmeasurable disk asks for nothing rather than blocking writes.
    assert_eq!(default_floor_for(0), 0);
}

#[test]
fn a_split_folder_sends_a_file_to_its_own_sibling() {
    // A season with one episode on each disk: the folder alone cannot say
    // which disk a new subtitle belongs on, and free space picked the wrong
    // one on the lab (2026-10-04). The file it belongs to decides.
    let tmp = tempfile::tempdir().unwrap();
    let e = engine(tmp.path());
    let dests = roots(tmp.path(), &["disk_a", "disk_b"]);
    for (i, ep) in [(0usize, "e01"), (1usize, "e02")] {
        let season = dests[i].1.join("TV/Show/Season 01");
        fs::create_dir_all(&season).unwrap();
        fs::write(season.join(format!("Show - s01{ep}.mkv")), b"x").unwrap();
    }
    let (a, _) = e.placement_for_with_floor("TV/Show/Season 01/Show - s01e01.en.srt", &dests, 0).expect("a destination with room");
    let (b, _) = e.placement_for_with_floor("TV/Show/Season 01/Show - s01e02.en.srt", &dests, 0).expect("a destination with room");
    assert_eq!((a.as_str(), b.as_str()), ("disk_a", "disk_b"),
               "each subtitle lands with its own episode, not with the roomier disk");
    e.close().unwrap();
}
