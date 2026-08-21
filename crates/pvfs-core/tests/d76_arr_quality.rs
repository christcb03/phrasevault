//! D76 — turning what the *arrs know into what the ladder needs.
//!
//! Every shape here is one MEASURED off Chris's live Sonarr v4.0.19 / Radarr
//! v6.3.0, not invented: v4 reports `resolution` as a string (not
//! `width`/`height`), Sonarr with analysis off reports `videoBitrate: 0` for
//! every single file, and `runTime` looks like `"22:22"`.

use pvfs_core::arr::{parse_runtime, tree_path_of, ArrFile};

/// The exact record sampled from Chris's Sonarr: 1080p, 8-bit, no HDR flag,
/// and — the thing that matters — NO BITRATE.
fn measured_sonarr_file() -> ArrFile {
    ArrFile {
        path: "/mnt/unionfs/Media/TV/Show Name/Season 01/ep.mkv".into(),
        size_bytes: 790_503_828,
        resolution: "1920x1080".into(),
        bit_depth: 8,
        dynamic_range: String::new(),
        bitrate: 0, // measured: 0 in 2,373/2,373 with analysis off
        codec: "x264".into(),
        run_time: "22:22".into(),
        file_id: 4242,
    }
}

#[test]
fn a_real_sonarr_record_becomes_a_usable_measurement() {
    let q = measured_sonarr_file().to_quality().unwrap();
    assert_eq!((q.width, q.height), (1920, 1080), "v4 gives `resolution`");
    assert_eq!(q.pixels(), 1920 * 1080);
    assert_eq!(q.bit_depth, 8);
    assert_eq!(q.duration_s, 1342, "22:22");
    assert!(q.hdr.is_empty(), "SDR is an empty flag, not a missing field");
}

/// The gap that would otherwise sink rung 3 of the ladder: Sonarr reports no
/// bitrate, but size and runTime are present in 100% of sampled files.
#[test]
fn bitrate_is_derived_when_the_arr_does_not_measure_it() {
    let q = measured_sonarr_file().to_quality().unwrap();
    let mbps = q.bitrate as f64 / 1_000_000.0;
    assert!(
        (4.0..5.5).contains(&mbps),
        "790MB over 22:22 is about 4.7 Mbps, got {mbps:.2}"
    );
}

/// ...but a bitrate the arr DID measure is kept — Radarr, with analysis on,
/// reports one for about half its files, and a real figure beats a derived one.
#[test]
fn a_measured_bitrate_is_not_overwritten_by_the_derived_one() {
    let mut f = measured_sonarr_file();
    f.bitrate = 8_000_000;
    assert_eq!(f.to_quality().unwrap().bitrate, 8_000_000);
}

/// Resolutions are NOT clean buckets in the real library — `1440x1080`,
/// `1916x1076`, `1920x804` all appear, and Sonarr labels several of them
/// "1080p". Pixel count is what separates them.
#[test]
fn odd_real_world_resolutions_are_ordered_by_pixels() {
    let mk = |res: &str| {
        let mut f = measured_sonarr_file();
        f.resolution = res.into();
        f.to_quality().unwrap()
    };
    assert!(
        mk("1920x1080").pixels() > mk("1440x1080").pixels(),
        "both are '1080p' to Sonarr; they are not the same picture"
    );
    assert!(mk("1920x1080").pixels() > mk("1920x804").pixels());
    assert!(mk("1280x720").pixels() < mk("1916x1076").pixels());
}

/// A malformed resolution must not poison the import — leave it unknown and
/// let the later rungs decide, rather than failing the whole file.
#[test]
fn a_bad_resolution_leaves_the_rest_intact() {
    let mut f = measured_sonarr_file();
    f.resolution = "not-a-resolution".into();
    let q = f.to_quality().unwrap();
    assert_eq!(q.pixels(), 0, "unknown, not wrong");
    assert_eq!(q.duration_s, 1342, "and everything else still landed");
    assert!(q.bitrate > 0, "including the derived bitrate");
}

#[test]
fn runtimes_parse_in_both_shapes() {
    assert_eq!(parse_runtime("22:22"), 1342, "mm:ss");
    assert_eq!(parse_runtime("1:34:05"), 5645, "h:mm:ss — a film");
    assert_eq!(parse_runtime(""), 0, "unknown ⇒ 0, meaning 'cannot compare'");
    assert_eq!(parse_runtime("garbage"), 0);
}

/// The arr describes an absolute path on ITS filesystem; the catalog knows a
/// tree path under the library node. Matching on the tail is what lets one arr
/// describe files PVFS reaches by an entirely different route — feederbox sees
/// /mnt/unionfs, the owner sees an NFS mount, the store sees local disk.
#[test]
fn an_arr_path_maps_to_a_tree_path() {
    assert_eq!(
        tree_path_of("/mnt/unionfs/Media/TV/Show/Season 01/ep.mkv", "Media").as_deref(),
        Some("TV/Show/Season 01/ep.mkv")
    );
    assert_eq!(
        tree_path_of("/share/Data/Media/Movies/Film (2020)/film.mkv", "Media").as_deref(),
        Some("Movies/Film (2020)/film.mkv"),
        "the same file seen from the NAS maps to the SAME tree path"
    );
    assert_eq!(
        tree_path_of("/mnt/local/Downloads/thing.mkv", "Media"),
        None,
        "a path outside the library matches nothing rather than guessing"
    );
}
