//! PVOS D211 — a copy ffprobe cannot read loses to a readable copy (Chris,
//! 2026-10-01: "Yes"), but only once it is CONFIRMED (two "invalid data"
//! probes 30+ minutes apart) and only against a copy that was MEASURED.
//!
//! 1. The rung: unreadable vs measured, either side; silent for two
//!    unreadable copies, unreadable vs unmeasured, unreadable vs suspect.
//! 2. Encodings: a suspect round-trips; old encodings are unchanged; the
//!    wire takes only a canonical measurement or a bare failure.
//! 3. `quality_after`: the holder's rule, case by case.
//! 4. `classify_failure`: "invalid data" is broken; I/O, signals and
//!    unknown words are not.
//! 5. The probe step: a broken file is a suspect, re-probed only after
//!    30 minutes, then confirmed; a probe that could not run records
//!    nothing and rests; a suspect that reads the second time is measured.
//! 6. The region model: the served copy and the drain prefer a measured
//!    copy over an unreadable one; two unreadable copies keep today's
//!    answers; a measured library copy keeps an unreadable upgrade out.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pvfs_core::fs::{scan_catalogues, CatalogueCtx, ProbeCtx, ProbeSetting};
use pvfs_core::media::{choose, quality_after, Candidate, MediaQuality, Observed, Rules, SUSPECT_RECHECK_MS};
use pvfs_core::probe::{classify_failure, Prober};
use pvfs_core::writer::OwnDb;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, ViewCopy, ViewEntry, ViewState, TYPE_FOLDER};

fn hd() -> MediaQuality {
    MediaQuality { width: 1920, height: 1080, video_codec: "h264".into(), duration_s: 1300, ..Default::default() }
}

fn suspect(at: u64) -> MediaQuality {
    MediaQuality { probe_suspect_ms: at, ..Default::default() }
}

fn cand(label: &str, q: MediaQuality, size: u64) -> Candidate {
    Candidate { label: label.into(), quality: q, size_bytes: size, mtime_ms: 1, integrity_ok: true }
}

#[test]
fn an_unreadable_copy_loses_only_to_a_measured_one() {
    let rules = Rules::default();
    let bad = MediaQuality::probe_failure();
    // Unreadable and twice the size: the measured copy wins, either side.
    let (a_wins, v) = choose(&cand("good", hd(), 1_000), &cand("bad", bad.clone(), 2_000), &rules);
    assert!(a_wins, "{v:?}");
    assert!(v.reason().contains("bad could not be read by ffprobe"), "{v:?}");
    let (a_wins, v) = choose(&cand("bad", bad.clone(), 2_000), &cand("good", hd(), 1_000), &rules);
    assert!(!a_wins, "{v:?}");
    // Two unreadable copies: the rung is silent, size decides as before.
    let (a_wins, v) = choose(&cand("bad1", bad.clone(), 1_000), &cand("bad2", bad.clone(), 2_000), &rules);
    assert!(!a_wins && v.reason().contains("bytes"), "today's answer: {v:?}");
    // Unreadable vs never measured: no readable copy is known — size decides.
    let (a_wins, v) = choose(&cand("bad", bad.clone(), 2_000), &cand("unmeasured", MediaQuality::default(), 1_000), &rules);
    assert!(a_wins && v.reason().contains("bytes"), "{v:?}");
    // Unreadable vs a suspect: the suspect is unknown too.
    let (a_wins, v) = choose(&cand("bad", bad, 2_000), &cand("suspect", suspect(5), 1_000), &rules);
    assert!(a_wins && v.reason().contains("bytes"), "{v:?}");
    // A suspect is not unreadable: against a measured copy, size decides.
    let (a_wins, v) = choose(&cand("suspect", suspect(5), 2_000), &cand("good", hd(), 1_000), &rules);
    assert!(a_wins && v.reason().contains("bytes"), "a first failure decides nothing: {v:?}");
    // A measured copy with no picture (no video stream) is not "readable".
    let audio = MediaQuality { duration_s: 100, ..Default::default() };
    let (a_wins, v) = choose(&cand("bad", MediaQuality::probe_failure(), 2_000), &cand("audio", audio, 1_000), &rules);
    assert!(a_wins && v.reason().contains("bytes"), "{v:?}");
}

#[test]
fn encodings_and_what_the_wire_takes() {
    let s = suspect(1_700_000_000_000);
    let enc = s.encode();
    assert!(enc.ends_with(r#","probe":"suspect","probe_at":1700000000000}"#), "{enc}");
    assert_eq!(MediaQuality::decode(&enc).unwrap(), s);
    assert!(s.suspect() && !s.unreadable() && !s.measured());
    let f = MediaQuality::probe_failure();
    assert!(f.unreadable() && !f.suspect());
    assert_eq!(MediaQuality::decode(&f.encode()).unwrap(), f);
    assert_eq!(
        hd().encode(),
        r#"{"w":1920,"h":1080,"depth":0,"hdr":"","bitrate":0,"codec":"h264","dur":1300,"decoded":""}"#,
        "a measurement encodes as it always did"
    );
    // The wire: a measurement or a bare failure, canonical, nothing else.
    assert_eq!(Observed::decode_wire(&hd().encode()), Some(Observed::Measured(hd())));
    assert_eq!(Observed::decode_wire(&f.encode()), Some(Observed::Broken));
    assert_eq!(Observed::Broken.encode(), f.encode());
    assert_eq!(Observed::decode_wire(&enc), None, "a caller cannot write a suspect");
    let decoded = MediaQuality { decoded_ok: Some(false), ..hd() };
    assert_eq!(Observed::decode_wire(&decoded.encode()), None, "nor a decode verdict");
    let failed_with_numbers = MediaQuality { width: 1, height: 1, probe_failed: true, ..Default::default() };
    assert_eq!(Observed::decode_wire(&failed_with_numbers.encode()), None);
    assert_eq!(Observed::decode_wire(r#"{"w":1920}"#), None, "not canonical");
    assert_eq!(Observed::decode_wire("garbage"), None);
}

#[test]
fn the_holders_rule_for_what_lands() {
    let t0 = 1_000_000_000_000u64;
    let m = Observed::Measured(hd());
    // Nothing yet.
    assert_eq!(quality_after(None, &m, t0), Some(hd().encode()));
    assert_eq!(quality_after(None, &Observed::Broken, t0), Some(suspect(t0).encode()));
    // A suspect: confirmed only 30 minutes on; a reading clears it.
    let s = suspect(t0).encode();
    assert_eq!(quality_after(Some(&s), &Observed::Broken, t0 + SUSPECT_RECHECK_MS - 1), None, "too soon");
    assert_eq!(
        quality_after(Some(&s), &Observed::Broken, t0 + SUSPECT_RECHECK_MS),
        Some(MediaQuality::probe_failure().encode())
    );
    assert_eq!(quality_after(Some(&s), &m, t0 + 1), Some(hd().encode()), "it read this time");
    // A measurement or a failure is never overwritten.
    assert_eq!(quality_after(Some(&hd().encode()), &Observed::Broken, t0 + SUSPECT_RECHECK_MS * 10), None);
    let f = MediaQuality::probe_failure().encode();
    assert_eq!(quality_after(Some(&f), &m, t0), None);
    assert_eq!(quality_after(Some(&f), &Observed::Broken, t0), None);
    // An unreadable current value is left alone.
    assert_eq!(quality_after(Some("junk"), &m, t0), None);
}

#[test]
fn what_counts_as_broken() {
    let yes = [
        "/m/a.mkv: Invalid data found when processing input",
        "[mov,mp4,m4a,3gp,3g2,mj2 @ 0x55] moov atom not found\n/m/a.mp4: Invalid data found when processing input",
        "[matroska,webm @ 0x1] EBML header parsing failed\n/m/a.mkv: Invalid data found when processing input",
    ];
    for e in yes {
        assert!(classify_failure(e, true), "{e}");
        assert!(!classify_failure(e, false), "a signal is never broken: {e}");
    }
    let no = [
        "/m/a.mkv: Permission denied",
        "/m/a.mkv: Input/output error",
        "/m/a.mkv: No such file or directory",
        "http://127.0.0.1:1/x/probe.mkv: Connection refused",
        "[http @ 0x1] Server returned 404 Not Found",
        "/m/a.mkv: End of file",
        // a short read can look like invalid data: any I/O word wins
        "[matroska @ 0x1] Read error at pos. 1234 (0x4d2)\n/m/a.mkv: Input/output error\nInvalid data found when processing input",
        "something else entirely",
        "",
    ];
    for e in no {
        assert!(!classify_failure(e, true), "{e}");
    }
}

// ---- the probe step ---------------------------------------------------------

/// A stand-in for ffprobe: `bad` files are invalid data, `ioerr` files a
/// read error, `heals` files invalid data until a marker file exists.
const FAKE: &str = r#"#!/bin/sh
for a; do f="$a"; done
d="$(dirname "$0")"
echo "$f" >> "$d/probed.log"
case "$f" in
  *heals*) [ -e "$d/healed" ] || { echo "$f: Invalid data found when processing input" >&2; exit 1; } ;;
  *bad*) echo "$f: Invalid data found when processing input" >&2; exit 1 ;;
  *ioerr*) echo "$f: Input/output error" >&2; exit 1 ;;
esac
echo "codec_name=h264"
echo "width=1920"
echo "height=1080"
echo "duration=1300.0"
echo "size=1000"
"#;

struct Rig {
    _tmp: tempfile::TempDir,
    e: Engine,
    media: PathBuf,
    region: String,
    script: PathBuf,
    errored: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<(String, String), std::time::Instant>>>,
}

fn rig(files: &[&str]) -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let (mut e, _) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let media = tmp.path().join("media");
    std::fs::create_dir_all(&media).unwrap();
    for f in files {
        std::fs::write(media.join(f), format!("bytes of {f}")).unwrap();
    }
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
    Rig { _tmp: tmp, e, media, region, script, errored: Default::default() }
}

impl Rig {
    fn pass_at(&mut self, now_ms: u64) -> pvfs_core::ScanStats {
        let mut ctx = CatalogueCtx::new(None);
        ctx.probe = ProbeSetting::On(ProbeCtx {
            prober: Prober { program: self.script.clone() },
            max_files: 300,
            max_time: Duration::from_secs(60),
            timeout: Duration::from_secs(10),
            now_ms: Some(now_ms),
            errored: self.errored.clone(),
        });
        let db = OwnDb::new(&mut self.e);
        scan_catalogues(&db, &mut ctx, None, 0).unwrap().remove(0).stats
    }

    fn quality(&self, rel: &str) -> Option<MediaQuality> {
        self.e
            .region_entries(&self.region)
            .unwrap()
            .into_iter()
            .find(|r| r.rel_path == rel)
            .unwrap()
            .quality
            .map(|q| MediaQuality::decode(&q).unwrap())
    }

    fn probes_of(&self, name: &str) -> usize {
        std::fs::read_to_string(self.script.parent().unwrap().join("probed.log"))
            .unwrap_or_default()
            .lines()
            .filter(|l| Path::new(l).file_name().is_some_and(|f| f == name))
            .count()
    }
}

#[test]
fn a_broken_file_is_suspected_then_confirmed_and_an_error_records_nothing() {
    let mut r = rig(&["good.mkv", "bad.mkv", "ioerr.mkv", "heals.mkv"]);
    let t0 = 1_900_000_000_000u64;
    let s = r.pass_at(t0);
    assert_eq!((s.probed, s.probe_failed, s.probe_errors, s.probe_pending), (1, 2, 1, 0));
    assert!(r.quality("good.mkv").unwrap().measured());
    assert_eq!(r.quality("bad.mkv").unwrap(), suspect(t0), "a first failure is only a suspect");
    assert_eq!(r.quality("heals.mkv").unwrap(), suspect(t0));
    assert_eq!(r.quality("ioerr.mkv"), None, "a probe that could not read records nothing");

    // Too soon: nothing is probed again (and the errored file rests).
    let s = r.pass_at(t0 + SUSPECT_RECHECK_MS - 1);
    assert_eq!((s.probed, s.probe_failed, s.probe_errors), (0, 0, 0));
    assert_eq!((r.probes_of("bad.mkv"), r.probes_of("ioerr.mkv")), (1, 1));

    // 30 minutes on: the second probe confirms bad.mkv; heals.mkv reads now.
    std::fs::write(r.script.parent().unwrap().join("healed"), "").unwrap();
    let s = r.pass_at(t0 + SUSPECT_RECHECK_MS);
    assert_eq!((s.probed, s.probe_failed), (1, 1));
    assert!(r.quality("bad.mkv").unwrap().unreadable(), "confirmed");
    assert!(r.quality("heals.mkv").unwrap().measured(), "a suspect that reads is measured");
    assert_eq!(r.probes_of("ioerr.mkv"), 1, "the errored file still rests");
    let sum = r.e.region_quality_summary(&r.region).unwrap();
    assert_eq!((sum.measured, sum.failed, sum.suspect, sum.unmeasured), (2, 1, 0, 1));
    assert_eq!(sum.failed_paths, vec!["bad.mkv"]);

    // Confirmed is final until the file changes.
    r.pass_at(t0 + 10 * SUSPECT_RECHECK_MS);
    assert_eq!(r.probes_of("bad.mkv"), 2);
    std::fs::write(r.media.join("bad.mkv"), "a replacement, longer").unwrap();
    r.pass_at(t0 + 11 * SUSPECT_RECHECK_MS);
    assert_eq!(r.probes_of("bad.mkv"), 3, "a changed file is probed again");
    assert!(r.quality("bad.mkv").unwrap().suspect(), "and starts over");
}

// ---- the region model ------------------------------------------------------

fn copy(region: &str, size: u64, hash: &str, q: Option<MediaQuality>) -> ViewCopy {
    ViewCopy {
        region: region.into(),
        kind: "file".into(),
        size_bytes: size,
        mtime_ms: 1,
        content_hash: Some(hash.into()),
        quality: q.map(|q| q.encode()),
        stale: false,
    }
}

fn entry(sources: Vec<ViewCopy>) -> ViewEntry {
    let hashes = sources.iter().filter_map(|c| c.content_hash.clone()).collect();
    ViewEntry {
        rel_path: "TV/Show/e01.mkv".into(),
        kind: "file".into(),
        size_bytes: 0,
        mtime_ms: 0,
        content_hash: None,
        quality: None,
        state: ViewState::ConflictHashes(hashes),
        copies: 0,
        sources,
    }
}

#[test]
fn the_served_copy_and_the_drain_prefer_the_readable_copy() {
    let rules = Rules::default();
    let bad = || Some(MediaQuality::probe_failure());
    // Served: two library copies, the larger unreadable.
    let e = entry(vec![copy("lib1", 2_000, "h1", bad()), copy("lib2", 1_000, "h2", Some(hd()))]);
    assert_eq!(Engine::served_copy(&e, &rules).unwrap().region, "lib2");
    // Two unreadable copies: today's answer (the larger).
    let e = entry(vec![copy("lib1", 2_000, "h1", bad()), copy("lib2", 1_000, "h2", bad())]);
    assert_eq!(Engine::served_copy(&e, &rules).unwrap().region, "lib1");

    let draining = |r: &str| r.starts_with("stage");
    // D145: a draining copy beats the library copy outright…
    let e = entry(vec![copy("lib", 2_000, "h1", Some(hd())), copy("stage", 1_000, "h2", None)]);
    assert_eq!(Engine::drain_winner(&e, &rules, &draining).unwrap().region, "stage");
    assert!(!Engine::drain_kept_readable(&e, &rules, &draining));
    // …unless it could not be read and the library copy was measured.
    let e = entry(vec![copy("lib", 1_000, "h1", Some(hd())), copy("stage", 2_000, "h2", bad())]);
    assert_eq!(Engine::drain_winner(&e, &rules, &draining).unwrap().region, "lib");
    assert!(Engine::drain_kept_readable(&e, &rules, &draining));
    // An unreadable upgrade against an unmeasured library copy: D145 stands
    // (no readable copy is known).
    let e = entry(vec![copy("lib", 1_000, "h1", None), copy("stage", 2_000, "h2", bad())]);
    assert_eq!(Engine::drain_winner(&e, &rules, &draining).unwrap().region, "stage");
    // An unreadable library copy and a readable upgrade: as before, the upgrade.
    let e = entry(vec![copy("lib", 2_000, "h1", bad()), copy("stage", 1_000, "h2", Some(hd()))]);
    assert_eq!(Engine::drain_winner(&e, &rules, &draining).unwrap().region, "stage");
    // Among draining copies, the readable one.
    let e = entry(vec![
        copy("lib", 500, "h0", None),
        copy("stage1", 2_000, "h1", bad()),
        copy("stage2", 1_000, "h2", Some(hd())),
    ]);
    assert_eq!(Engine::drain_winner(&e, &rules, &draining).unwrap().region, "stage2");
}
