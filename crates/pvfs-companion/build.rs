// D100 — bake the BUILD identity into the binary, not just the release number.
//
// `1.4.0` once meant two materially different binaries at once: `main` sat 80
// commits behind the branch the fleet actually ran, both reported `pvfs 1.4.0`,
// and a fix was written, tested and clippy-cleaned against the stale tree
// before anyone noticed. The only reliable tell was grepping the binary for a
// string that only the intended build contained. VERSIONING.md turned that
// incident into a RULE; this is the rule being kept.
//
// Falls back to the crate version alone when git is unavailable (a source
// tarball, a sandbox with no `git`), because a build must not fail for want of
// a version string.
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
    // D124 item 3 — a new tag touches refs/tags or packed-refs, not HEAD or
    // the index; without these two a tag-only change kept the stale stamp.
    println!("cargo:rerun-if-changed=../../.git/refs/tags");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
}
