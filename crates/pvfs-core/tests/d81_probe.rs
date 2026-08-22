//! D81 — mapping a prober's output onto the ladder's rungs.
//!
//! Tested on the PARSE rather than on ffprobe, so it runs on a box with no
//! prober installed — and because the output's shape is the thing most likely
//! to drift under us, not the subprocess call.

use pvfs_core::probe::parse_ffprobe;

/// A real 1080p SDR episode, verbatim from `ffprobe` on Chris's library.
#[test]
fn a_real_sdr_episode_maps_onto_every_rung_it_can_fill() {
    let q = parse_ffprobe(
        "codec_name=h264\nwidth=1920\nheight=1080\ncolor_transfer=bt709\n\
         bits_per_raw_sample=8\nduration=1282.949000\nsize=544014616\n",
    );
    assert_eq!((q.width, q.height), (1920, 1080));
    assert_eq!(q.bit_depth, 8);
    assert_eq!(q.video_codec, "h264");
    assert_eq!(q.duration_s, 1282);
    assert_eq!(q.hdr, "", "bt709 is SDR");
    assert!(q.bitrate > 3_000_000, "derived from size and duration: {}", q.bitrate);
    assert_eq!(
        q.decoded_ok, None,
        "reading headers proves the container parses and NOTHING about whether \
         every frame decodes — that is the corruption Chris actually worries \
         about, and claiming it here would be a lie the ladder would act on"
    );
}

/// HDR arrives as a TRANSFER FUNCTION, not a flag.
#[test]
fn hdr_flavours_are_recognised_from_the_transfer_function() {
    for (transfer, want) in [
        ("smpte2084", "PQ"),
        ("bt2020-10", "PQ"),
        ("arib-std-b67", "HLG"),
        ("bt709", ""),
        ("", ""),
    ] {
        let q = parse_ffprobe(&format!(
            "codec_name=hevc\nwidth=3840\nheight=2160\ncolor_transfer={transfer}\n"
        ));
        assert_eq!(q.hdr, want, "transfer {transfer:?}");
    }
}

/// Missing fields mean UNKNOWN, and the ladder falls through unknown rungs.
///
/// The dangerous misreading is treating an absent `bits_per_raw_sample` as
/// 0-bit video, which would make every unmeasured file lose a comparison it
/// should merely have skipped.
#[test]
fn absent_fields_are_unknown_not_zero_valued_facts() {
    let q = parse_ffprobe("codec_name=h264\nwidth=1280\nheight=720\n");
    assert_eq!((q.width, q.height), (1280, 720));
    assert_eq!(q.bit_depth, 0, "unknown");
    assert_eq!(q.duration_s, 0);
    assert_eq!(q.bitrate, 0, "no duration means no honest derivation");
    assert_eq!(q.hdr, "");
}

/// Garbage in is empty out, not a panic — a prober can fail mid-library and
/// the pass has 27,000 more files to get through.
#[test]
fn unparseable_output_yields_nothing_rather_than_panicking() {
    let q = parse_ffprobe("this is not ffprobe output at all\n\n=\n=x\ny=\n");
    assert_eq!((q.width, q.height), (0, 0));
    assert_eq!(q.video_codec, "");
    assert_eq!(q.decoded_ok, None);
}

/// The probe must not out-rank a real measurement by accident: a probed file
/// and an arr-reported one must produce comparable numbers for the same file.
#[test]
fn a_probed_file_compares_like_for_like_with_an_arr_reported_one() {
    let probed = parse_ffprobe(
        "codec_name=h264\nwidth=1920\nheight=1080\ncolor_transfer=bt709\n\
         bits_per_raw_sample=8\nduration=1200\nsize=600000000\n",
    );
    let arr = pvfs_core::arr::ArrFile {
        path: "/x/ep.mkv".into(),
        size_bytes: 600_000_000,
        resolution: "1920x1080".into(),
        bit_depth: 8,
        dynamic_range: String::new(),
        bitrate: 0,
        codec: "h264".into(),
        run_time: "20:00".into(),
        file_id: 1,
    }
    .to_quality()
    .unwrap();
    assert_eq!((probed.width, probed.height), (arr.width, arr.height));
    assert_eq!(probed.bit_depth, arr.bit_depth);
    assert_eq!(
        probed.duration_s, arr.duration_s,
        "same file, same seconds, whichever tool looked"
    );
    assert_eq!(
        probed.bitrate, arr.bitrate,
        "both DERIVE from size and duration, so the ladder's size rung compares \
         like with like across sources"
    );
}
