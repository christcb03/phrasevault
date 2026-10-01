//! PVOS D208 — catalogue rows carry the video quality the watch measured.
//!
//! The probe step runs a stand-in for ffprobe (a shell script that answers
//! as ffprobe does, fails on a name with `bad` in it, hangs on `slow`, and
//! logs every file it was asked about), so the tests need no ffprobe — the
//! test server has none.
//!
//! 1. A changed file loses its measured quality; a ctime-only change keeps it.
//! 2. New video files are measured and the head carries it; other files not.
//! 3. The budget: newest first, the rest left for the next pass.
//! 4. A failed probe is recorded and not repeated until the file changes.
//! 5. A probe that hangs is killed at the timeout and not recorded.
//! 6. No prober: the pass is today's; rows stay unmeasured.
//! 7. A measurement never lands on a row that changed since it was read.
//! 8. A stop during a probe lands at once.
//! 9. The ladder: HDR decides only between two measured copies.
//! 10. `probe_failed` round-trips; an old encoding is byte-identical.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pvfs_core::fs::{scan_catalogues, CatalogueCtx, ProbeCtx, ProbeSetting};
use pvfs_core::media::{choose, Candidate, MediaQuality, Observed, Rules};
use pvfs_core::probe::Prober;
use pvfs_core::writer::OwnDb;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

const FAKE: &str = r#"#!/bin/sh
for a; do f="$a"; done
echo "$f" >> "$(dirname "$0")/probed.log"
case "$f" in
  *bad*) echo "$f: Invalid data found when processing input" >&2; exit 1 ;;
  *slow*) sleep 10 ;;
esac
echo "codec_name=hevc"
echo "width=1920"
echo "height=1080"
echo "bits_per_raw_sample=10"
echo "color_transfer=smpte2084"
echo "duration=1342.5"
echo "size=1000000"
"#;

struct Rig {
    _tmp: tempfile::TempDir,
    e: Engine,
    media: PathBuf,
    region: String,
    script: PathBuf,
}

fn rig(files: &[&str]) -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let media = tmp.path().join("media");
    for f in files {
        let p = media.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("bytes of {f}")).unwrap();
    }
    std::fs::create_dir_all(&media).unwrap();
    let root = e.identity.root_node_id.clone();
    let region = e
        .add_node(
            &root,
            NodeSpec { node_type: TYPE_FOLDER.into(), label: "Local".into(), payload: Vec::new(), is_temp: false, creation_nonce: None },
        )
        .unwrap();
    e.region_mark_as(&region, "catalogue", None).unwrap();
    e.bind_folder(
        &region,
        BindSpec {
            source_uri: format!("file://{}", media.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = bin.join("fake-ffprobe");
    std::fs::write(&script, FAKE).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    Rig { _tmp: tmp, e, media, region, script }
}

impl Rig {
    fn probing(&self, max_files: usize, timeout: Duration) -> ProbeSetting {
        ProbeSetting::On(ProbeCtx {
            prober: Prober { program: self.script.clone() },
            max_files,
            max_time: Duration::from_secs(60),
            timeout,
            now_ms: None,
            errored: Default::default(),
        })
    }

    fn pass(&mut self, probe: ProbeSetting) -> pvfs_core::ScanStats {
        let mut ctx = CatalogueCtx::new(None);
        ctx.probe = probe;
        let db = OwnDb::new(&mut self.e);
        let mut r = scan_catalogues(&db, &mut ctx, None, 0).unwrap();
        r.remove(0).stats
    }

    fn quality(&self, rel: &str) -> Option<String> {
        self.e
            .region_entries(&self.region)
            .unwrap()
            .into_iter()
            .find(|r| r.rel_path == rel)
            .unwrap_or_else(|| panic!("no row for {rel}"))
            .quality
    }

    fn probed(&self) -> Vec<String> {
        let log = self.script.parent().unwrap().join("probed.log");
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(|l| Path::new(l).strip_prefix(&self.media).unwrap().display().to_string())
            .collect()
    }

    fn set_mtime(&self, rel: &str, secs_ago: u64) {
        let f = std::fs::File::options().write(true).open(self.media.join(rel)).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(secs_ago)).unwrap();
    }
}

fn measured() -> MediaQuality {
    MediaQuality {
        width: 1920,
        height: 1080,
        bit_depth: 10,
        hdr: "PQ".into(),
        bitrate: MediaQuality::derive_bitrate(1_000_000, 1342),
        video_codec: "hevc".into(),
        duration_s: 1342,
        decoded_ok: None,
        probe_failed: false,
        probe_suspect_ms: 0,
    }
}

#[test]
fn new_video_files_are_measured_and_the_head_carries_it() {
    let mut r = rig(&["Show/e01.mkv", "Show/e01.nfo", "Show/e01.en.srt", "Film/f.mp4", "Music/a.flac"]);
    let s = r.pass(r.probing(300, Duration::from_secs(10)));
    assert_eq!((s.probed, s.probe_failed, s.probe_pending), (2, 0, 0));
    let want = measured().encode();
    assert_eq!(r.quality("Show/e01.mkv").as_deref(), Some(want.as_str()));
    assert_eq!(r.quality("Film/f.mp4").as_deref(), Some(want.as_str()));
    for other in ["Show/e01.nfo", "Show/e01.en.srt", "Music/a.flac"] {
        assert_eq!(r.quality(other), None, "{other} is not video; never probed");
    }
    let mut asked = r.probed();
    asked.sort();
    assert_eq!(asked, vec!["Film/f.mp4", "Show/e01.mkv"]);
    // The head the pass published carries the measurement.
    let head = r.e.region_snapshots(&r.region).unwrap().pop().expect("a head");
    let rows = r.e.region_entries(&r.region).unwrap();
    let bytes = Engine::region_manifest_bytes(&r.region, head.seq, &rows);
    assert_eq!(blake3::hash(&bytes).to_hex().to_string(), head.manifest_hash, "published after the probe step");
    assert!(String::from_utf8(bytes).unwrap().contains(&want));
    // A second pass probes nothing and publishes nothing.
    let heads = r.e.region_snapshots(&r.region).unwrap().len();
    let s = r.pass(r.probing(300, Duration::from_secs(10)));
    assert_eq!((s.probed, s.probe_failed, s.probe_pending), (0, 0, 0));
    assert_eq!(r.probed().len(), 2, "a measured file is not probed again");
    assert_eq!(r.e.region_snapshots(&r.region).unwrap().len(), heads);
}

#[test]
fn a_changed_file_loses_its_quality_and_a_ctime_change_keeps_it() {
    let mut r = rig(&["a.mkv", "b.mkv"]);
    r.pass(r.probing(300, Duration::from_secs(10)));
    assert!(r.quality("a.mkv").is_some() && r.quality("b.mkv").is_some());
    // b: other bytes at the same path (an upgrade). a: a chmod (ctime only).
    std::fs::write(r.media.join("b.mkv"), "a better copy of b, longer").unwrap();
    std::fs::set_permissions(r.media.join("a.mkv"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let s = r.pass(ProbeSetting::Off);
    assert_eq!(s.changed, 1);
    assert_eq!(r.quality("b.mkv"), None, "the old file's quality is not the new file's");
    assert!(r.quality("a.mkv").is_some(), "same bytes, same quality");
    // The next probing pass measures the new b, and only it.
    let s = r.pass(r.probing(300, Duration::from_secs(10)));
    assert_eq!(s.probed, 1);
    assert_eq!(r.probed().iter().filter(|p| *p == "b.mkv").count(), 2);
    assert_eq!(r.probed().iter().filter(|p| *p == "a.mkv").count(), 1);
}

#[test]
fn the_budget_takes_the_newest_and_leaves_the_rest_for_later() {
    let names = ["v1.mkv", "v2.mkv", "v3.mkv", "v4.mkv", "v5.mkv"];
    let mut r = rig(&names);
    for (i, n) in names.iter().enumerate() {
        r.set_mtime(n, 1000 * (i as u64 + 1)); // v1 newest
    }
    let s = r.pass(r.probing(2, Duration::from_secs(10)));
    assert_eq!((s.probed, s.probe_pending), (2, 3));
    assert_eq!(r.probed(), vec!["v1.mkv", "v2.mkv"]);
    let s = r.pass(r.probing(2, Duration::from_secs(10)));
    assert_eq!((s.probed, s.probe_pending), (2, 1));
    let s = r.pass(r.probing(2, Duration::from_secs(10)));
    assert_eq!((s.probed, s.probe_pending), (1, 0));
    assert_eq!(r.probed(), names.to_vec());
    let sum = r.e.region_quality_summary(&r.region).unwrap();
    assert_eq!((sum.video_files, sum.measured, sum.unmeasured, sum.failed), (5, 5, 0, 0));
}

#[test]
fn a_failed_probe_is_recorded_reported_and_not_repeated() {
    let mut r = rig(&["good.mkv", "bad.mkv"]);
    let s = r.pass(r.probing(300, Duration::from_secs(10)));
    assert_eq!((s.probed, s.probe_failed, s.probe_pending), (1, 1, 0));
    // PVOS D211 — the first "invalid data" is a SUSPECT, not yet a failure
    // (`d211_unreadable_loses.rs` has the second probe that confirms it).
    let q = MediaQuality::decode(&r.quality("bad.mkv").unwrap()).unwrap();
    assert!(q.suspect() && !q.unreadable() && !q.measured());
    let sum = r.e.region_quality_summary(&r.region).unwrap();
    assert_eq!((sum.measured, sum.failed, sum.suspect, sum.unmeasured), (1, 0, 1, 0));
    assert_eq!(sum.suspect_paths, vec!["bad.mkv"]);
    r.pass(r.probing(300, Duration::from_secs(10)));
    assert_eq!(r.probed().iter().filter(|p| *p == "bad.mkv").count(), 1, "not probed every pass");
    // The file changes: probed again.
    std::fs::write(r.media.join("bad.mkv"), "a replacement").unwrap();
    r.pass(r.probing(300, Duration::from_secs(10)));
    assert_eq!(r.probed().iter().filter(|p| *p == "bad.mkv").count(), 2);
}

#[test]
fn a_probe_that_hangs_is_killed_and_not_recorded() {
    let mut r = rig(&["slow.mkv", "ok.mkv"]);
    r.set_mtime("slow.mkv", 10); // newest: probed first
    r.set_mtime("ok.mkv", 1000);
    let t = std::time::Instant::now();
    let s = r.pass(r.probing(300, Duration::from_millis(300)));
    assert!(t.elapsed() < Duration::from_secs(5), "killed at the timeout, not after its 10 s");
    assert_eq!((s.probed, s.probe_failed, s.probe_pending), (1, 0, 1));
    assert_eq!(r.quality("slow.mkv"), None, "a timeout is not a measurement");
    assert!(r.quality("ok.mkv").is_some(), "and the step went on to the next file");
}

#[test]
fn with_no_prober_the_pass_is_todays() {
    let mut r = rig(&["a.mkv"]);
    let s = r.pass(ProbeSetting::On(ProbeCtx::with(Prober { program: "/nonexistent/ffprobe".into() })));
    assert_eq!((s.added, s.probed, s.probe_failed), (1, 0, 0));
    assert_eq!(r.quality("a.mkv"), None);
    let s = r.pass(ProbeSetting::Missing(Default::default()));
    assert_eq!((s.probed, s.probe_pending), (0, 0));
    assert_eq!(r.quality("a.mkv"), None);
    let sum = r.e.region_quality_summary(&r.region).unwrap();
    assert_eq!((sum.video_files, sum.unmeasured), (1, 1));
    assert!(!Prober { program: "/nonexistent/ffprobe".into() }.available());
}

#[test]
fn a_measurement_never_lands_on_a_row_that_changed() {
    let mut r = rig(&["a.mkv"]);
    r.pass(ProbeSetting::Off);
    let cands = r.e.quality_candidates(&r.region).unwrap();
    assert_eq!(cands.len(), 1);
    let (rel, size, mtime) = cands[0].clone();
    // The file changes and a pass rewrites its row before the write lands.
    std::fs::write(r.media.join("a.mkv"), "other, longer bytes").unwrap();
    r.pass(ProbeSetting::Off);
    let n = r.e.write_region_quality(&r.region, &[(rel.clone(), size, mtime, Observed::Measured(measured()))]).unwrap();
    assert_eq!(n, 0, "the probed file is no longer the row's");
    assert_eq!(r.quality("a.mkv"), None);
    // Against the row as it is now, it lands — once.
    let (rel, size, mtime) = r.e.quality_candidates(&r.region).unwrap()[0].clone();
    assert_eq!(r.e.write_region_quality(&r.region, &[(rel.clone(), size, mtime, Observed::Measured(measured()))]).unwrap(), 1);
    let other = MediaQuality { width: 640, height: 480, ..Default::default() };
    assert_eq!(r.e.write_region_quality(&r.region, &[(rel.clone(), size, mtime, Observed::Measured(other))]).unwrap(), 0, "never over a measurement");
    assert_eq!(r.e.write_region_quality(&r.region, &[(rel, size, mtime, Observed::Broken)]).unwrap(), 0, "nor a failure over one");
}

#[test]
fn a_stop_during_a_probe_lands_at_once() {
    let mut r = rig(&["slow.mkv"]);
    let stop = Arc::new(AtomicBool::new(false));
    let raise = Arc::clone(&stop);
    let raiser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        raise.store(true, Ordering::SeqCst);
    });
    let mut ctx = CatalogueCtx::new(Some(Arc::clone(&stop)));
    ctx.probe = r.probing(300, Duration::from_secs(30));
    let heads = r.e.region_snapshots(&r.region).unwrap().len();
    let t = std::time::Instant::now();
    let rep = {
        let db = OwnDb::new(&mut r.e);
        scan_catalogues(&db, &mut ctx, None, 0).unwrap()
    };
    raiser.join().unwrap();
    assert!(t.elapsed() < Duration::from_secs(5), "the probe was killed by the stop");
    assert!(rep[0].stats.cancelled, "a stopped pass");
    assert_eq!(r.e.region_snapshots(&r.region).unwrap().len(), heads, "and publishes nothing");
    assert_eq!(r.quality("slow.mkv"), None);
}

fn cand(label: &str, q: MediaQuality, size: u64) -> Candidate {
    Candidate { label: label.into(), quality: q, size_bytes: size, mtime_ms: 1, integrity_ok: true }
}

#[test]
fn hdr_decides_only_between_two_measured_copies() {
    let rules = Rules::default();
    let hdr = measured();
    // Unmeasured and 50% larger: unknown is not SDR, so size decides.
    let (a_wins, v) = choose(&cand("hdr", hdr.clone(), 1_000), &cand("unmeasured", MediaQuality::default(), 1_500), &rules);
    assert!(!a_wins, "{v:?}");
    assert!(v.reason().contains("bytes"), "{v:?}");
    // Both measured, same resolution: HDR decides before size.
    let sdr = MediaQuality { hdr: String::new(), ..measured() };
    let (a_wins, v) = choose(&cand("hdr", hdr.clone(), 1_000), &cand("sdr", sdr, 1_500), &rules);
    assert!(a_wins, "{v:?}");
    assert!(v.reason().starts_with("HDR"), "{v:?}");
    // A failed probe carries no numbers. PVOS D211 (Chris: "Yes"): a
    // confirmed failure loses to a measured copy, whatever the sizes.
    let (a_wins, v) = choose(&cand("hdr", hdr, 1_000), &cand("failed", MediaQuality::probe_failure(), 1_500), &rules);
    assert!(a_wins, "an unreadable copy loses to a measured one (D211): {v:?}");
}

#[test]
fn probe_failed_round_trips_and_old_encodings_are_unchanged() {
    let q = measured();
    assert_eq!(
        q.encode(),
        r#"{"w":1920,"h":1080,"depth":10,"hdr":"PQ","bitrate":5961,"codec":"hevc","dur":1342,"decoded":""}"#,
        "no probe field unless it failed"
    );
    let f = MediaQuality::probe_failure();
    assert!(f.encode().ends_with(r#","probe":"failed"}"#));
    assert_eq!(MediaQuality::decode(&f.encode()).unwrap(), f);
    assert_eq!(MediaQuality::decode(&q.encode()).unwrap(), q);
}
