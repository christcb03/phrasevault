#!/usr/bin/env bash
# PVOS D261b — after a change to tests or docs only, rerun just what failed.
#
#   deploy/retest.sh                              asks: session, host, tests
#   deploy/retest.sh <session> [test ...]         for scripts: no questions
#
# It reruns the recorded run's failed test binaries, the binaries of any test
# file changed since, the tests you name, and every stage that failed or did
# not run (the leak checks, clippy, the smoke; install and daemon when a red
# check held them back). It refuses if anything but tests and docs changed
# since that run — then run the full pipeline. A test is a binary name
# (d219_gone_reads), or cargo's form (-p pvfs-fuse --test x, -p pvfs-core
# --lib), either with a test-name filter after it.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
interactive() { [ -t 0 ] && [ -t 2 ]; }

# The session is the worktree's name (phrasevault-<session>); the main
# checkout has none.
base="$(basename "$root")"
default_session=""
if [ "$base" != "phrasevault-repo" ]; then default_session="${base#phrasevault-}"; fi
session="${1-}"
if [ $# -gt 0 ]; then shift; fi
if [ -z "$session" ]; then
  if interactive; then
    read -r -p "Session [${default_session:-main checkout}]: " session
  fi
  session="${session:-$default_session}"
fi
case "$session" in
  *[!a-zA-Z0-9._-]*) echo "a session name is letters, digits, dot, dash, underscore" >&2; exit 1 ;;
esac
host="${RETEST_HOST:-presubuntu}"
if interactive && [ -z "${RETEST_HOST-}" ]; then
  read -r -p "The host that runs the suite [$host]: " answer
  host="${answer:-$host}"
fi

record="$root/deploy/ansible/artifacts/runs/pvfs${session:+-$session}.json"
if [ ! -f "$record" ]; then
  echo "no recorded run for '${session:-main checkout}' ($record)." >&2
  echo "Run the full pipeline first:" >&2
  echo "  cd deploy/ansible && ansible-playbook -i inventory.ini pipeline.yml${session:+ -e session=$session} --skip-tags install" >&2
  exit 1
fi
python3 - "$record" <<'PY' >&2
import json, sys
r = json.load(open(sys.argv[1]))
print(f"last run: {r['at']} ({r.get('describe') or 'no describe'})")
print("stages  : " + ", ".join(f"{k} {v}" for k, v in r["stages"].items()))
failed = [v["rerun"] for v in r["targets"].values() if v.get("rerun")]
print("failed  : " + ("; ".join(failed) if failed else "no test binary"))
PY

tests=("$@")
if [ ${#tests[@]} -eq 0 ] && interactive; then
  read -r -p "Also rerun (tests, ';'-separated; Enter = just what failed and what changed): " answer
  if [ -n "$answer" ]; then tests=("$answer"); fi
fi
joined="$(IFS=';'; echo "${tests[*]-}")"
extra="$(python3 -c 'import json,sys; print(json.dumps({"retest_tests": sys.argv[1]}))' "$joined")"

cd "$root/deploy/ansible"
exec ansible-playbook -i inventory.ini pipeline.yml --limit "$host" ${session:+-e "session=$session"} -e "$extra" --tags retest
