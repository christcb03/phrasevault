// D110 — the DAEMON carries its build identity too.
//
// D100 stamped the CLI and stopped there, so `pvfsd --version` reported a bare
// `pvfsd 1.4.0` on every arch. The daemon is the process that actually runs:
// after a roll, "which build is this box serving?" could only be answered by
// hashing the binary — on the holder, the box that is hardest to reach and
// where a half-swap has already happened once (ETXTBSY, 2026-08-23). The
// question the CLI could answer was never the question that mattered.
//
// Deliberately a COPY of crates/pvfs-cli/build.rs rather than a shared crate.
// Cargo runs a build script per package, so sharing would mean a new
// build-dependency crate existing only to hold forty lines that never change —
// and a build script that cannot itself fail to build is worth more here than
// the de-duplication. Keep the two in step.

use std::process::Command;

fn main() {
    // The pipeline rsyncs the repo WITHOUT .git, so `git describe` cannot work
    // on the build host — and the build host is where every deployed binary
    // comes from. An env var supplied by the caller takes precedence, and the
    // playbook computes it on the control machine where the repo really is.
    // Without this the stamp reads "unknown" on exactly the builds that matter.
    println!("cargo:rerun-if-env-changed=PVFS_BUILD");
    if let Ok(v) = std::env::var("PVFS_BUILD") {
        let v = v.trim();
        if !v.is_empty() {
            println!("cargo:rustc-env=PVFS_BUILD={v}");
            return;
        }
    }

    let describe = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    match describe {
        Some(d) => println!("cargo:rustc-env=PVFS_BUILD={d}"),
        None => println!("cargo:rustc-env=PVFS_BUILD=unknown"),
    }

    // Rerun when HEAD moves, so a rebuild after a commit restamps rather than
    // reusing a cached value that now names the wrong build.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}
