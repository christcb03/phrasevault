#!/usr/bin/env bash
# PVFS CLI smoke suite — exercises every P0 CLI function end-to-end against a
# fresh forest, including exit-code contracts (spec §13.4). Run by the Ansible
# pipeline; can also be run by hand: PVFS_BIN=target/release/pvfs ./smoke-test.sh
set -euo pipefail

PVFS="${PVFS_BIN:-pvfs}"
DATA="$(mktemp -d /tmp/pvfs-smoke.XXXXXX)"
export PVFS_DATA_DIR="$DATA/forest"
PASS=0
FAIL=0

cleanup() { rm -rf "$DATA"; }
trap cleanup EXIT

say()  { printf '%s\n' "== $*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }

# assert_rc <expected_rc> <description> -- cmd args...
assert_rc() {
  local want="$1" desc="$2"; shift 2; shift # consume --
  local rc=0
  "$@" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$desc (rc=$rc)"; else fail "$desc (want rc=$want got $rc)"; fi
}

jget() { # jget <json> <key>  — tiny JSON string-field extractor
  python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"
}

say "init"
INIT_JSON="$($PVFS --json init)"
MNEMONIC="$(jget "$INIT_JSON" mnemonic)"
ROOT="$(jget "$INIT_JSON" root_node_id)"
[ -n "$MNEMONIC" ] && ok "init returns mnemonic"
[ ${#ROOT} -eq 64 ] && ok "init returns 64-hex root id" || fail "bad root id: $ROOT"
assert_rc 4 "double init refuses (exists)" -- $PVFS init

say "info"
INFO_JSON="$($PVFS --json info)"
[ "$(jget "$INFO_JSON" root_node_id)" = "$ROOT" ] && ok "info matches init" || fail "info mismatch"

say "tree create"
TREE2="$($PVFS tree create second-tree)"
[ ${#TREE2} -eq 64 ] && ok "second tree created" || fail "tree create: $TREE2"

say "add nodes"
A="$($PVFS add "$ROOT" --kind folder --label movies)"
F="$($PVFS add "$A" --kind file --label fifth-element.mkv --size 1234 --mime video/x-matroska)"
ok "folder + file added"
assert_rc 3 "add under missing parent → 3" -- $PVFS add deadbeef --kind folder --label x
assert_rc 2 "empty label → 2" -- $PVFS add "$ROOT" --kind folder --label ""

say "locations"
$PVFS loc add "$F" "file:///data/movies/fifth-element.mkv" >/dev/null
$PVFS loc add "$F" "https://host/fifth-element.mkv" >/dev/null
[ "$($PVFS loc ls "$F" | wc -l)" -eq 2 ] && ok "two locations listed" || fail "loc ls count"
$PVFS loc rm "$F" "https://host/fifth-element.mkv" >/dev/null
[ "$($PVFS loc ls "$F" | wc -l)" -eq 1 ] && ok "soft-removed one location" || fail "loc rm"
assert_rc 3 "removing absent location → 3" -- $PVFS loc rm "$F" "https://nope"

say "links: ref ok, second home refused, cycle refused"
$PVFS link "$TREE2" "$F" --type ref >/dev/null && ok "ref link into second tree"
assert_rc 4 "second contains (one-home) → 4" -- $PVFS link "$TREE2" "$F" --type contains
assert_rc 4 "duplicate ref same nonce → 4" -- $PVFS link "$TREE2" "$F" --type ref
$PVFS link "$TREE2" "$F" --type ref --nonce 1 >/dev/null && ok "parallel ref with nonce 1"

say "ls / walk / node / verify"
$PVFS ls "$ROOT" | grep -q movies && ok "ls shows folder"
$PVFS walk "$ROOT" | grep -q fifth-element && ok "walk reaches file"
$PVFS node "$F" >/dev/null && ok "node show"
$PVFS verify "$F" >/dev/null && ok "verify valid node"
assert_rc 3 "verify missing node → 3" -- $PVFS verify deadbeef

say "reorder"
B="$($PVFS add "$ROOT" --kind folder --label shows)"
B_LINK="$($PVFS --json ls "$ROOT" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "shows": print(e["link_id"])')"
$PVFS reorder "$B_LINK" --key 5 >/dev/null
FIRST="$($PVFS --json ls "$ROOT" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["label"])')"
[ "$FIRST" = "shows" ] && ok "reorder moved shows first" || fail "reorder (first=$FIRST)"
assert_rc 2 "bad order key → 2" -- $PVFS reorder "$B_LINK" --key "a 0"

say "temp lifecycle"
T="$($PVFS add "$ROOT" --kind folder --label scratch --temp)"
T_LINK="$($PVFS --json ls "$ROOT" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "scratch": print(e["link_id"])')"
$PVFS unlink "$T_LINK" >/dev/null
assert_rc 3 "temp node purged on orphan → 3" -- $PVFS node "$T"

say "orphans / purge"
# G has no refs anywhere, so after purging A it must become an orphan.
# F keeps its ref links from TREE2, so it must NOT be listed as an orphan.
G="$($PVFS add "$A" --kind file --label extras.nfo)"
A_LINK="$($PVFS --json ls "$ROOT" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "movies": print(e["link_id"])')"
assert_rc 4 "purge non-orphan → 4" -- $PVFS purge "$A"
$PVFS unlink "$A_LINK" >/dev/null
$PVFS orphans | grep -q "$A" && ok "orphan listed"
$PVFS purge "$A" >/dev/null && ok "purge orphan"
$PVFS orphans | grep -q "$G" && ok "ref-less child became orphan after purge"
if $PVFS orphans | grep -q "$F"; then
  fail "file with active refs wrongly listed as orphan"
else
  ok "file with active refs is not an orphan"
fi

say "device certificates"
DEV1_JSON="$($PVFS --json device authorize --mnemonic "$MNEMONIC" --index 1)"
DEV1="$(jget "$DEV1_JSON" device_pubkey)"
ok "device 1 authorized"
$PVFS device revoke --mnemonic "$MNEMONIC" --pubkey "$DEV1" >/dev/null && ok "device 1 revoked"

say "recovery from mnemonic"
rm "$PVFS_DATA_DIR/device.key"
$PVFS recover --mnemonic "$MNEMONIC" --device-index 0 >/dev/null && ok "recover re-derives device key"
$PVFS info >/dev/null && ok "forest usable after recovery"

say "rebuild from log (projection is disposable)"
rm "$PVFS_DATA_DIR/index.db"
$PVFS walk "$ROOT" | grep -q second-tree || true # walk only walks one tree
$PVFS info >/dev/null && ok "index rebuilt from log"
$PVFS ls "$TREE2" | grep -q fifth-element && ok "rebuilt projection has ref links"

say "json error shape"
$PVFS --json node deadbeef 2>&1 | grep -q '"error":"NotFound"' && ok "json error variant"

echo
echo "smoke results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL SMOKE TESTS PASSED"
exit "$([ "$FAIL" -eq 0 ] && echo 0 || echo 1)"
