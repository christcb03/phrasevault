#!/usr/bin/env python3
"""PVOS D261 — what a pipeline run did, and what a retest may rerun.

The pipeline calls this on the Mac (the record lives beside the fetched
artifacts); `selftest` runs on presubuntu in the test stage. Standard library
only. D261b: the SAME file is in PVOS and PVFS (deploy/ansible/files/) —
change both. The stages are whatever the run reports; `--self` names the
repo whose test files map to cargo targets.

  fingerprint OUT DIR=PREFIX ...   every tracked or untracked, not-ignored file
                                   of each checkout, with its git blob hash
  record RUN --tree T --results F --stages JSON [--describe D]
                                   a full run: its tree, stages, test binaries
  plan RUN --tree T --repo DIR [--self PREFIX] [--tests SPECS]
                                   may this tree be retested, and what reruns
  merge RUN --results F --stages JSON [--drop KEYS]
                                   fold a retest into the record
  show RUN                         the record, for retest.sh's questions
  selftest
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

# Display order only; a run may report any subset, and an unknown stage
# sorts last. "build" passed if a run is recorded at all; "test" is special
# (it reruns by binary); every other stage reruns whole.
ORDER = ["build", "web", "test", "fuse_leaks_test", "lint", "smoke", "fuse_leaks_smoke",
         "cli_smoke", "install", "daemon"]


def ordered(stages):
    return sorted(stages, key=lambda s: (ORDER.index(s) if s in ORDER else len(ORDER), s))

# Files whose change may be checked by a retest instead of a full run: a test
# or a doc. A test inside a src/ file is code.
TEST_ONLY = [
    re.compile(r"^crates/[^/]+/tests/"),
    re.compile(r"^web/e2e/"),
    re.compile(r"^web/[^/]+\.test\.mjs$"),
    re.compile(r"^docs/"),
    re.compile(r"(^|/)[^/]+\.md$"),
]

# What the pipeline's rsync leaves out, so a change there is not a change to
# what was built (most of these are gitignored as well).
NOT_SYNCED = re.compile(
    r"^(\.claude/|web/node_modules/|web/dist/|deploy/ansible/artifacts/|artifacts/|"
    r"\.pvfs/|old/|v0\.0-concept/|target/)|(^|/)(device\.key|\.DS_Store)$"
)

RUNNING = re.compile(r"^\s+Running (\S+(?: \S+)?) \(([^)]+)\)\s*$")
DOCTESTS = re.compile(r"^\s+Doc-tests (\S+)\s*$")
RESULT = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;")
RERUN = re.compile(r"to rerun pass `([^`]+)`")
FAILED_LIST = re.compile(r"^\s+`(-p [^`]+)`\s*$")

PKG = r"[a-z0-9][a-z0-9_-]*"
NAME = r"[A-Za-z0-9_][A-Za-z0-9_-]*"
FILTER = r"(?: [A-Za-z0-9_:]+)?"
SPEC = re.compile(
    rf"^(?:--workspace|-p {PKG}(?: --(?:lib|doc|bins|tests)| --(?:test|bin) {NAME})?){FILTER}$"
)
BARE = re.compile(rf"^({NAME})({FILTER})$")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- the tree -----------------------------------------------------------------


def fingerprint(trees):
    """{prefix:path: blob} for each (dir, prefix)."""
    out = {}
    for d, prefix in trees:
        listed = subprocess.run(
            ["git", "-C", d, "ls-files", "-co", "--exclude-standard", "-z"],
            check=True, capture_output=True,
        ).stdout.decode().split("\0")
        paths = sorted({p for p in listed if p and not NOT_SYNCED.search(p)
                        and os.path.isfile(os.path.join(d, p))})
        if not paths:
            continue
        blobs = subprocess.run(
            ["git", "-C", d, "hash-object", "--stdin-paths"],
            input="\n".join(paths).encode(), check=True, capture_output=True,
        ).stdout.decode().split()
        for p, b in zip(paths, blobs):
            out[f"{prefix}:{p}"] = b
    return out


def changed_paths(then, now):
    keys = set(then) | set(now)
    return sorted(k for k in keys if then.get(k) != now.get(k))


def test_only(key):
    path = key.split(":", 1)[1]
    return any(r.search(path) for r in TEST_ONLY)


# ---- cargo's output -----------------------------------------------------------


SECTION = re.compile(r"^== cargo test --no-fail-fast (.+?)\s*$")


def parse_cargo(text):
    """{key: {passed, failed, ignored, rerun, base, exe, spec}}, plus whether
    a failure named no binary (a test that did not compile).

    A key is the binary's source and name (`tests/m2_services.rs
    m2_services`); two packages with the same test file name (D261b: both
    pvfs-cli and pvfsd have `tests/sigpipe.rs`) get `#2`. `exe` is the built
    file (`sigpipe-<hash>`), and `spec` the retest section it ran in."""
    targets, base, exe, key, unnamed_failure = {}, None, None, None, False
    spec = None
    failed_list = []
    in_failed_list = False
    for line in text.splitlines():
        m = SECTION.match(line)
        if m:
            spec = m.group(1)
            continue
        m = RUNNING.match(line)
        if m:
            exe = os.path.basename(m.group(2))
            base = f"{m.group(1)} {exe.rsplit('-', 1)[0]}"
            in_failed_list = False
            continue
        m = DOCTESTS.match(line)
        if m:
            base, exe = f"doc {m.group(1)}", None
            continue
        m = RESULT.match(line)
        if m and base:
            key, n = base, 2
            while key in targets:
                key, n = f"{base}#{n}", n + 1
            targets[key] = {
                "passed": int(m.group(1)), "failed": int(m.group(2)),
                "ignored": int(m.group(3)), "rerun": None,
                "base": base, "exe": exe, "spec": spec,
            }
            continue
        m = RERUN.search(line)
        if m:
            if key in targets and targets[key]["failed"]:
                targets[key]["rerun"] = m.group(1)
            else:
                failed_list.append(m.group(1))
            continue
        if re.match(r"^error: \d+ targets? failed:", line):
            in_failed_list = True
            continue
        if in_failed_list:
            m = FAILED_LIST.match(line)
            if m:
                failed_list.append(m.group(1))
                continue
            in_failed_list = False
        if line.startswith("error: could not compile") or line.startswith("error[E"):
            unnamed_failure = True
    named = {t["rerun"] for t in targets.values() if t["rerun"]}
    stray = [a for a in failed_list if a not in named]
    return targets, unnamed_failure or bool(stray)


def totals(targets):
    p = sum(t["passed"] for t in targets.values())
    f = sum(t["failed"] for t in targets.values())
    i = sum(t["ignored"] for t in targets.values())
    return p, f, i, len(targets)


def totals_line(targets):
    p, f, i, n = totals(targets)
    s = f"{p} passed, {f} failed, {i} ignored ({n} suites)"
    return s + ("; an ignored test is not allowed (D221)" if i else "")


def test_status(targets, unnamed_failure):
    _, f, i, n = totals(targets)
    return "failed" if (f or i or unnamed_failure or n == 0) else "passed"


def unnamed_of(rc, targets, unnamed):
    """A red test stage that names no failing binary (it did not compile, or
    cargo listed a target it never ran) can only be checked by the whole
    suite."""
    return rc != 0 and (unnamed or not any(t["failed"] for t in targets.values()))


def status_of(rc):
    """None: the stage did not run (a retest runs it). "skipped": the run
    left it out on purpose (PVFS's `--skip-tags install`; a retest leaves it
    out too). Else its exit code."""
    if rc is None:
        return "not_run"
    if rc == "skipped":
        return "skipped"
    return "passed" if rc == 0 else "failed"


DONE = ("passed", "skipped")


# ---- record / plan / merge ------------------------------------------------------


def load(path):
    with open(path) as f:
        return json.load(f)


def save(path, rec):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def record(run, tree_file, results, stages, describe=""):
    rcs = json.loads(stages)
    rec = {
        "version": 1, "at": now_iso(), "describe": describe,
        "tree": load(tree_file), "stages": {"build": "passed"},
        "targets": {}, "unnamed_failure": False, "retests": [],
    }
    for s, rc in rcs.items():
        if s != "whole_suite":
            rec["stages"][s] = status_of(rc)
    if rcs.get("test") is not None:
        with open(results, errors="replace") as f:
            targets, unnamed = parse_cargo(f.read())
        rec["targets"] = targets
        rec["unnamed_failure"] = unnamed_of(rcs["test"], targets, unnamed)
        rec["stages"]["test"] = test_status(targets, rec["unnamed_failure"])
    save(run, rec)
    return rec


def package_of(repo, crate_dir):
    try:
        with open(os.path.join(repo, crate_dir, "Cargo.toml")) as f:
            text = f.read()
    except OSError:
        return None
    m = re.search(r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', text, re.M | re.S)
    return m.group(1) if m else None


def resolve_spec(spec, repo):
    """A test the user named → cargo's form, or None if it is not one."""
    spec = " ".join(spec.split())
    if SPEC.match(spec):
        return spec
    m = BARE.match(spec)
    if not m:
        return None
    crates = os.path.join(repo, "crates")
    for c in sorted(os.listdir(crates)) if os.path.isdir(crates) else []:
        if os.path.isfile(os.path.join(crates, c, "tests", m.group(1) + ".rs")):
            pkg = package_of(repo, os.path.join("crates", c))
            return f"-p {pkg} --test {m.group(1)}{m.group(2)}" if pkg else None
    return None


def specs_for_changes(changed, repo, self_prefix="pvos"):
    """What a changed test file obliges the retest to run."""
    specs, stages, drop, notes = [], set(), [], []
    for key in changed:
        prefix, path = key.split(":", 1)
        if prefix != self_prefix:
            continue
        m = re.match(r"^crates/([^/]+)/tests/(.+)$", path)
        if m:
            pkg = package_of(repo, f"crates/{m.group(1)}")
            if not pkg:
                continue
            stages.add("lint")
            sub = m.group(2)
            if "/" not in sub and sub.endswith(".rs"):
                name = sub[:-3]
                if os.path.isfile(os.path.join(repo, path)):
                    specs.append(f"-p {pkg} --test {name}")
                else:
                    drop.append(f"tests/{name}.rs {name}")
            else:
                specs.append(f"-p {pkg} --tests")
            continue
        if re.match(r"^web/[^/]+\.test\.mjs$", path):
            stages.add("web")
            continue
        if path.startswith("web/e2e/"):
            base = os.path.basename(path)
            found = False
            for c in sorted(os.listdir(os.path.join(repo, "crates")) if os.path.isdir(os.path.join(repo, "crates")) else []):
                tdir = os.path.join(repo, "crates", c, "tests")
                if not os.path.isdir(tdir):
                    continue
                for t in sorted(os.listdir(tdir)):
                    if t.endswith(".rs"):
                        with open(os.path.join(tdir, t), errors="replace") as f:
                            if base in f.read():
                                pkg = package_of(repo, f"crates/{c}")
                                specs.append(f"-p {pkg} --test {t[:-3]}")
                                found = True
            if not found:
                notes.append(f"no test drives {path}")
    return specs, stages, drop, notes


def plan(run, tree_file, repo, tests="", self_prefix="pvos"):
    if not os.path.isfile(run):
        return {"ok": False, "why": f"no recorded run ({run}) — run the full pipeline first"}
    rec = load(run)
    if rec["stages"].get("build") != "passed":
        return {"ok": False, "why": "the recorded run's build did not pass — run the full pipeline"}
    changed = changed_paths(rec["tree"], load(tree_file))
    code = [k for k in changed if not test_only(k)]
    if code:
        return {"ok": False, "changed": changed, "code": code,
                "why": "these are not tests or docs, so they need the full pipeline: "
                       + ", ".join(code[:20]) + (" …" if len(code) > 20 else "")}
    specs, stages, drop, notes = specs_for_changes(changed, repo, self_prefix)
    for raw in [t for t in (tests or "").split(";") if t.strip()]:
        r = resolve_spec(raw, repo)
        if r is None:
            return {"ok": False, "why": f"not a test this can run: {raw.strip()!r}"}
        specs.append(r)
    t = rec["stages"].get("test")
    # A leaked mount (PVFS D211's check) names no binary, so only the whole
    # suite can show it gone; the smoke's leak check reruns the smoke.
    leaked = rec["stages"].get("fuse_leaks_test", "passed") not in DONE
    if t == "not_run" or rec.get("unnamed_failure") or leaked:
        specs = ["--workspace"]
    elif t == "failed":
        specs += [v["rerun"] for k, v in rec["targets"].items()
                  if v.get("rerun") and v.get("base", k.split("#")[0]) not in drop]
    for s, st in rec["stages"].items():
        if s not in ("build", "test") and st not in DONE:
            stages.add(s)
    if "fuse_leaks_smoke" in stages:
        stages.add("smoke")
    seen, uniq = set(), []
    for s in specs:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    if uniq:
        stages.add("test")
    return {"ok": True, "changed": changed, "stages": ordered(stages),
            "tests": uniq, "drop": drop, "notes": notes}


def filtered(spec):
    """A spec with a test-name filter after its target runs part of a binary."""
    t = (spec or "").split()
    if not t or t[0] == "--workspace":
        return len(t) > 1
    flags = [x for x in t[2:] if x.startswith("--")]
    takes_name = any(f in ("--test", "--bin") for f in flags)
    return len(t) > 2 + len(flags) + (1 if takes_name else 0)


def match_target(have, t):
    """The record's key a rerun binary replaces, or None if it is new, or
    "?" if it could be either of two (same file name, two packages)."""
    if t.get("exe"):
        hit = [k for k, v in have.items() if v.get("exe") == t["exe"]]
        if len(hit) == 1:
            return hit[0]
    if t.get("spec"):
        hit = [k for k, v in have.items() if v.get("rerun") and t["spec"].startswith(v["rerun"])]
        if len(hit) == 1:
            return hit[0]
    base = t.get("base")
    hit = [k for k, v in have.items() if v.get("base", k.split("#")[0]) == base]
    if len(hit) == 1:
        return hit[0]
    return "?" if hit else None


def merge(run, results, stages, drop="", quiet=False):
    rec = load(run)
    rcs = json.loads(stages)
    notes = []
    for d in [d for d in (drop or "").split(";") if d]:
        hit = [k for k, v in rec["targets"].items() if v.get("base", k.split("#")[0]) == d]
        if len(hit) == 1:
            rec["targets"].pop(hit[0])
        elif hit:
            notes.append(f"{d} is in two packages; its removed file's totals were left in")
    ran = {}
    if rcs.get("test") is not None:
        with open(results, errors="replace") as f:
            targets, unnamed = parse_cargo(f.read())
        if rcs.get("whole_suite"):
            rec["targets"] = {}
        for t in targets.values():
            if filtered(t.get("spec")):
                notes.append(f"{t['spec']}: {t['passed']} passed, {t['failed']} failed — a filtered run, "
                             "so the binary's totals stand until it is rerun whole")
                continue
            k = match_target(rec["targets"], t)
            if k == "?":
                notes.append(f"{t['base']} ({t.get('spec')}) matches two recorded binaries; counted as its own")
                k = None
            if k is None:
                k, n = t["base"], 2
                while k in rec["targets"]:
                    k, n = f"{t['base']}#{n}", n + 1
            rec["targets"][k] = t
        rec["unnamed_failure"] = unnamed_of(rcs["test"], targets, unnamed)
        rec["stages"]["test"] = test_status(rec["targets"], rec["unnamed_failure"])
        ran["test"] = sorted(targets)
    for s, rc in rcs.items():
        if s not in ("test", "whole_suite") and rc is not None:
            rec["stages"][s] = status_of(rc)
            ran[s] = rec["stages"][s]
    if not quiet:
        rec["retests"].append({"at": now_iso(), "ran": ran})
    save(run, rec)
    green = all(v in DONE for v in rec["stages"].values())
    pending = [k for k in ordered(rec["stages"]) if rec["stages"][k] not in DONE]
    return {"green": green, "pending": pending, "totals": totals_line(rec["targets"]),
            "stages": {k: rec["stages"][k] for k in ordered(rec["stages"])}, "notes": notes}


def show(run):
    if not os.path.isfile(run):
        return {"exists": False}
    rec = load(run)
    return {
        "exists": True, "at": rec["at"], "describe": rec.get("describe", ""),
        "stages": {k: rec["stages"][k] for k in ordered(rec["stages"])}, "totals": totals_line(rec["targets"]),
        "failed_tests": [v["rerun"] for v in rec["targets"].values() if v.get("rerun")],
        "retests": len(rec["retests"]),
    }


# ---- the self-test --------------------------------------------------------------

CARGO_RED = """\
   Compiling pvosd v0.0.0
     Running unittests src/lib.rs (target/debug/deps/pvos_core-0f1e2d3c4b5a6978)

running 54 tests
test result: ok. 54 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

     Running tests/m2_services.rs (target/debug/deps/m2_services-abc123)

running 1 test
test m2_behavior_plane ... FAILED

failures:
    m2_behavior_plane

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 40.47s

error: test failed, to rerun pass `-p pvosd --test m2_services`
     Running tests/d259_member_app_actions.rs (target/debug/deps/d259_member_app_actions-9f9f)

running 1 test
test d259_member_app_actions ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.21s

   Doc-tests pvos_core

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

error: 1 target failed:
    `-p pvosd --test m2_services`
"""

CARGO_RETEST = """\
     Running tests/m2_services.rs (target/debug/deps/m2_services-def456)

running 1 test
test m2_behavior_plane ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.0s
"""


def selftest():
    checks = 0

    def ok(cond, what):
        nonlocal checks
        checks += 1
        if not cond:
            raise SystemExit(f"selftest FAILED: {what}")

    targets, unnamed = parse_cargo(CARGO_RED)
    ok(len(targets) == 4, f"four suites, got {sorted(targets)}")
    twice = ("     Running tests/sigpipe.rs (target/debug/deps/sigpipe-aaa)\n"
             "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
             "     Running tests/sigpipe.rs (target/debug/deps/sigpipe-bbb)\n"
             "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n")
    dup, _ = parse_cargo(twice)
    ok(sorted(dup) == ["tests/sigpipe.rs sigpipe", "tests/sigpipe.rs sigpipe#2"], f"two packages, one file name: {sorted(dup)}")
    ok(match_target(dup, {"exe": "sigpipe-bbb", "base": "tests/sigpipe.rs sigpipe"}) == "tests/sigpipe.rs sigpipe#2", "by the built file")
    ok(match_target(dup, {"exe": "sigpipe-ccc", "base": "tests/sigpipe.rs sigpipe"}) == "?", "ambiguous without it")
    ok(filtered("-p pvosd --test m2_services m2_behavior_plane") and not filtered("-p pvosd --test m2_services")
       and filtered("-p pvos-core --lib pairing") and not filtered("-p pvos-core --lib")
       and not filtered("--workspace") and filtered("-p pvosd x") and not filtered("-p pvosd"), "which specs filter")
    ok(targets["tests/m2_services.rs m2_services"]["rerun"] == "-p pvosd --test m2_services", "cargo's rerun line")
    ok(not unnamed, "the failure has a name")
    ok(totals_line(targets).startswith("55 passed, 1 failed, 0 ignored (4 suites)"), totals_line(targets))
    _, unnamed = parse_cargo("error[E0425]: cannot find value `x`\nerror: could not compile `pvosd` (test \"t\")\n")
    ok(unnamed, "a compile failure names no binary")

    for good, want in [("--workspace", "--workspace"), ("-p pvosd --test m2_services", None),
                       ("-p pvos-core --lib", None), ("-p pvos-core --lib pairing::role_tests", None),
                       ("-p pvosd --tests", None)]:
        ok(resolve_spec(good, "/nonexistent") == (want or good), f"spec {good!r}")
    for bad in ["-p pvosd --test x; rm -rf /", "$(id)", "-p pvosd --test `x`", "--release", "-p PVOSD --lib"]:
        ok(resolve_spec(bad, "/nonexistent") is None, f"refuses {bad!r}")

    with tempfile.TemporaryDirectory() as d:
        repo = os.path.join(d, "pvos")
        os.makedirs(os.path.join(repo, "crates/pvosd/tests"))
        os.makedirs(os.path.join(repo, "crates/pvosd/src"))
        os.makedirs(os.path.join(repo, "docs"))

        def write(p, s):
            with open(os.path.join(repo, p), "w") as f:
                f.write(s)

        write("crates/pvosd/Cargo.toml", '[package]\nname = "pvosd"\nversion = "0.0.0"\n\n[dependencies]\n')
        write("crates/pvosd/src/lib.rs", "pub fn a() {}\n")
        write("crates/pvosd/tests/m2_services.rs", "#[test] fn t() {}\n")
        write("crates/pvosd/tests/d260_gone.rs", "#[test] fn t() {}\n")
        write("docs/a.md", "a\n")
        write(".gitignore", "target/\n")
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "add", "-A"], check=True)
        os.makedirs(os.path.join(repo, "target"))
        write("target/junk", "x")

        def tree():
            p = os.path.join(d, "tree.json")
            with open(p, "w") as f:
                json.dump(fingerprint([(repo, "pvos")]), f)
            return p

        t0 = tree()
        ok("pvos:target/junk" not in load(t0), "ignored files are not the tree")
        ok("pvos:crates/pvosd/tests/m2_services.rs" in load(t0), "tracked files are")
        ok(resolve_spec("m2_services", repo) == "-p pvosd --test m2_services", "a bare binary name")
        ok(resolve_spec("m2_services m2_behavior_plane", repo)
           == "-p pvosd --test m2_services m2_behavior_plane", "with a filter")
        ok(resolve_spec("nonesuch", repo) is None, "an unknown binary")

        results = os.path.join(d, "red.txt")
        with open(results, "w") as f:
            f.write(CARGO_RED)
        run = os.path.join(d, "runs", "pvos-x.json")
        rcs = {"web": 0, "lint": 0, "test": 101, "smoke": None, "cli_smoke": None}
        rec = record(run, t0, results, json.dumps(rcs), "v1-test")
        ok(rec["stages"]["test"] == "failed" and rec["stages"]["smoke"] == "not_run", rec["stages"])

        p = plan(run, tree(), repo)
        ok(p["ok"] and p["tests"] == ["-p pvosd --test m2_services"], p)
        ok(p["stages"] == ["test", "smoke", "cli_smoke"], f"the stages that did not run, got {p['stages']}")

        write("crates/pvosd/tests/m2_services.rs", "#[test] fn t() { /* fixed */ }\n")
        write("docs/a.md", "a, edited\n")
        p = plan(run, tree(), repo)
        ok(p["ok"] and "lint" in p["stages"], f"a test-file change reruns clippy too: {p}")
        ok(p["tests"] == ["-p pvosd --test m2_services"], f"no duplicate: {p['tests']}")
        write("crates/pvosd/tests/new_one.rs", "#[test] fn t() {}\n")
        os.remove(os.path.join(repo, "crates/pvosd/tests/d260_gone.rs"))
        p = plan(run, tree(), repo, "d259_member_app_actions_absent;-p pvosd --lib")
        ok(not p["ok"] and "not a test" in p["why"], f"an unknown name refuses: {p}")
        p = plan(run, tree(), repo, "-p pvosd --lib")
        ok(p["ok"] and "-p pvosd --test new_one" in p["tests"] and "-p pvosd --lib" in p["tests"], p)
        ok(p["drop"] == ["tests/d260_gone.rs d260_gone"], f"a deleted test is dropped: {p['drop']}")
        write("crates/pvosd/src/lib.rs", "pub fn a() { /* code */ }\n")
        p = plan(run, tree(), repo)
        ok(not p["ok"] and p["code"] == ["pvos:crates/pvosd/src/lib.rs"], f"a src change refuses: {p}")

        retest = os.path.join(d, "retest.txt")
        with open(retest, "w") as f:
            f.write(CARGO_RETEST)
        with open(retest, "w") as f:
            f.write("== cargo test --no-fail-fast -p pvosd --test m2_services\n" + CARGO_RETEST)
        m = merge(run, retest, json.dumps({"test": 0, "smoke": 0, "cli_smoke": 0}), "tests/d260_gone.rs d260_gone")
        ok(m["green"], f"green after the retest: {m}")
        ok(m["totals"].startswith("56 passed, 0 failed, 0 ignored (4 suites)"), m["totals"])
        ok(show(run)["retests"] == 1 and show(run)["failed_tests"] == [], show(run))
        m = merge(run, retest, json.dumps({"test": None, "lint": 1}))
        ok(not m["green"] and m["stages"]["lint"] == "failed", f"a failed rerun is red: {m}")

        # D261b — PVFS's stages: install and daemon did not run (a red
        # build is not installed), so a retest that goes green runs them.
        prun = os.path.join(d, "runs", "pvfs-x.json")
        prcs = {"test": 101, "fuse_leaks_test": 0, "lint": 0, "smoke": 0, "fuse_leaks_smoke": 0,
                "install": "skipped", "daemon": None}
        rec = record(prun, tree(), results, json.dumps(prcs))
        ok(list(show(prun)["stages"]) == ["build", "test", "fuse_leaks_test", "lint", "smoke",
                                          "fuse_leaks_smoke", "install", "daemon"], show(prun)["stages"])
        p = plan(prun, tree(), repo, "", "pvfs")
        ok(p["ok"] and p["stages"] == ["test", "daemon"], f"PVFS stages (install left out on purpose): {p}")
        ok(p["tests"] == ["-p pvosd --test m2_services"], f"PVFS: only the failed binary, {p['tests']}")
        lrun = os.path.join(d, "runs", "pvfs-leak.json")
        record(lrun, tree(), results, json.dumps({"test": 0, "fuse_leaks_test": 1, "lint": 0,
                                                  "smoke": 0, "fuse_leaks_smoke": 1}))
        p = plan(lrun, tree(), repo, "", "pvfs")
        ok(p["tests"] == ["--workspace"] and "smoke" in p["stages"], f"a leak reruns the suite and the smoke: {p}")
        m = merge(prun, retest, json.dumps({"test": 0}))
        ok(not m["green"] and m["pending"] == ["daemon"], f"only the daemon is left: {m}")
        m = merge(prun, retest, json.dumps({"daemon": 0}), quiet=True)
        ok(m["green"] and show(prun)["retests"] == 1, f"PVFS green after the retest: {m}")

    print(f"pipeline_record selftest: {checks} checks passed")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, args = argv[1], argv[2:]

    def opt(name, default=None):
        if name in args:
            i = args.index(name)
            return args[i + 1]
        return default

    if cmd == "selftest":
        selftest()
    elif cmd == "fingerprint":
        trees = [tuple(a.rsplit("=", 1)) for a in args[1:]]
        tree = fingerprint(trees)
        save(args[0], tree)
        print(f"{len(tree)} files")
    elif cmd == "record":
        rec = record(args[0], opt("--tree"), opt("--results"), opt("--stages"), opt("--describe", ""))
        print(json.dumps({"stages": rec["stages"], "totals": totals_line(rec["targets"])}))
    elif cmd == "plan":
        print(json.dumps(plan(args[0], opt("--tree"), opt("--repo"), opt("--tests", ""), opt("--self", "pvos"))))
    elif cmd == "merge":
        print(json.dumps(merge(args[0], opt("--results"), opt("--stages"), opt("--drop", ""), "--quiet" in args)))
    elif cmd == "show":
        print(json.dumps(show(args[0])))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
