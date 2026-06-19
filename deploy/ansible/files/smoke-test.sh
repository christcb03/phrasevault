#!/usr/bin/env bash
# PVFS CLI smoke suite — exercises every P0 CLI function end-to-end against a
# fresh forest, including exit-code contracts (spec §13.4). Run by the Ansible
# pipeline; can also be run by hand: PVFS_BIN=target/release/pvfs ./smoke-test.sh
set -euo pipefail

PVFS="${PVFS_BIN:-pvfs}"
PVFSD="${PVFSD_BIN:-$(dirname "$PVFS")/pvfsd}"
DATA="$(mktemp -d /tmp/pvfs-smoke.XXXXXX)"
export PVFS_DATA_DIR="$DATA/forest"
export PVFS_REGISTRY_DIR="$DATA/registry"   # user-writable registry for the P1.5 section
export XDG_CONFIG_HOME="$DATA/config"       # keep the client identity out of $HOME
PASS=0
FAIL=0
DPID=""

cleanup() { [ -n "$DPID" ] && kill "$DPID" 2>/dev/null; rm -rf "$DATA"; }
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

say "P1: bind / scan / stat / cat"
LIB="$DATA/library"
mkdir -p "$LIB/movies"
printf 'alpha-bytes' > "$LIB/movies/alpha.mkv"
printf 'hello notes' > "$LIB/notes.txt"
LFOLDER="$($PVFS add "$ROOT" --kind folder --label library)"
$PVFS bind "$LFOLDER" "$LIB" --hash-policy on_add >/dev/null && ok "bind"
$PVFS --json scan "$LFOLDER" | grep -q '"added":2' && ok "scan indexed 2 files"
$PVFS --json scan "$LFOLDER" | grep -q '"unchanged":2' && ok "rescan no-op"
MOVIES="$($PVFS --json ls "$LFOLDER" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "movies": print(e["id"])')"
ALPHA="$($PVFS --json ls "$MOVIES" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "alpha.mkv": print(e["id"])')"
[ "$($PVFS cat "$ALPHA")" = "alpha-bytes" ] && ok "cat verified read"
$PVFS stat "$ALPHA" | grep -q "file://" && ok "stat shows location"

say "P1: changed file -> flag -> resolve"
printf 'alpha-bytes-changed-longer' > "$LIB/movies/alpha.mkv"
$PVFS --json scan "$LFOLDER" | grep -q '"changed":1' && ok "change flagged"
$PVFS changes | grep -q "$ALPHA" && ok "changes lists flagged node"
assert_rc 3 "flagged location not served → 3" -- $PVFS cat "$ALPHA"
NEW_ALPHA="$($PVFS resolve "$ALPHA" --replace)"
[ ${#NEW_ALPHA} -eq 64 ] && ok "resolve --replace returns successor"
[ "$($PVFS cat "$NEW_ALPHA")" = "alpha-bytes-changed-longer" ] && ok "successor serves new bytes"
$PVFS orphans | grep -q "$ALPHA" && ok "old node kept as orphan"

say "P1: disk deletion is soft"
rm "$LIB/notes.txt"
$PVFS --json scan "$LFOLDER" | grep -q '"removed":1' && ok "deletion soft-removed location"
NOTES="$($PVFS --json ls "$LFOLDER" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "notes.txt": print(e["id"])')"
$PVFS stat "$NOTES" | grep -q UNAVAILABLE && ok "node kept, marked unavailable"

say "P1: lazy hash fill"
printf 'lazy-content' > "$LIB/movies/lazy.bin"
$PVFS scan "$LFOLDER" >/dev/null
LAZY="$($PVFS --json ls "$MOVIES" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "lazy.bin": print(e["id"])')"
HASHED="$($PVFS hash "$LAZY" 2>/dev/null)"
[ ${#HASHED} -eq 64 ] && [ "$HASHED" != "$LAZY" ] && ok "hash created successor node"
[ "$($PVFS cat "$HASHED")" = "lazy-content" ] && ok "hashed node serves verified"

say "P1: serve daemon (watcher)"
$PVFS serve --debounce-ms 300 >/dev/null 2>&1 &
SERVE_PID=$!
sleep 2
printf 'watched-file' > "$LIB/movies/watched.mkv"
sleep 3
kill "$SERVE_PID" 2>/dev/null; wait "$SERVE_PID" 2>/dev/null || true
rm -f "$PVFS_DATA_DIR/serve.lock"
$PVFS ls "$MOVIES" | grep -q watched.mkv && ok "watcher ingested new file"

say "P1.5: forest init / registry / mount URIs"
MOUNT="$DATA/workspace"
mkdir -p "$MOUNT/docs"
printf 'mount notes' > "$MOUNT/docs/readme.txt"
FINIT="$($PVFS --json forest init --mount "$MOUNT")"
echo "$FINIT" | grep -q '"imported":true' && ok "forest init imported mount tree"
[ -f "$MOUNT/.pvfs/log.db" ] && ok "state lives under .pvfs/"
$PVFS forest register "$MOUNT" --alias smokehome >/dev/null && ok "forest register"
$PVFS ls | grep -q smokehome && ok "pvfs ls lists registered forest"
$PVFS ls "pvfs://smokehome@local/docs" | grep -q readme.txt && ok "ls by alias URI"
$PVFS ls "$MOUNT/docs" | grep -q readme.txt && ok "ls by absolute path shorthand"
$PVFS cat "pvfs://smokehome/docs/readme.txt" | grep -q "mount notes" && ok "cat by tree path"
$PVFS forest info "pvfs://smokehome@local/" | grep -q instance_id && ok "forest info by URI"
if $PVFS ls "$MOUNT" | grep -q "\.pvfs"; then
  fail ".pvfs leaked into the indexed tree"
else
  ok ".pvfs not indexed into the tree"
fi

say "P1.5: portable forest (no registry)"
PORT="$DATA/usb-project"
cp -r "$MOUNT" "$PORT"
$PVFS ls "$PORT/docs" | grep -q readme.txt && ok "portable mount opens by path"
$PVFS forest unregister smokehome >/dev/null && ok "unregister"
[ -f "$MOUNT/.pvfs/log.db" ] && ok "unregister keeps .pvfs/"
assert_rc 3 "unknown alias → 3" -- $PVFS ls "pvfs://smokehome/docs"
$PVFS ls "$MOUNT/docs" | grep -q readme.txt && ok "unregistered mount still opens by path"

say "P2: daemon + remote client (doc 07)"
DMOUNT="$DATA/served"
mkdir -p "$DMOUNT/albums"
printf 'hi' > "$DMOUNT/albums/a.txt"
DINIT="$($PVFS --json forest init --mount "$DMOUNT")"
DROOT="$(jget "$DINIT" root_node_id)"
DFID="$(jget "$DINIT" forest_id)"
DMN="$(jget "$DINIT" mnemonic)"
CLIENTKEY="$(jget "$($PVFS --json whoami)" pubkey)"
[ -n "$CLIENTKEY" ] && ok "whoami prints client identity"

# Owner setup happens BEFORE serving (the daemon opens a snapshot of the log).
$PVFS --data-dir "$DMOUNT/.pvfs" acl set "$DROOT" public r >/dev/null \
  && ok "acl set public r on root"
$PVFS --data-dir "$DMOUNT/.pvfs" device authorize-member --pubkey "$CLIENTKEY" \
  >/dev/null && ok "authorize member (admin device, no recovery phrase)"
$PVFS --data-dir "$DMOUNT/.pvfs" acl set "$DROOT" "key:$CLIENTKEY" rw >/dev/null \
  && ok "grant member rw on root"
# tags (doc 09): CLI wiring — tag a member, list it, share a node to a tag
$PVFS --data-dir "$DMOUNT/.pvfs" tag add "$CLIENTKEY" testers >/dev/null && ok "tag add"
$PVFS --data-dir "$DMOUNT/.pvfs" tag ls "$CLIENTKEY" | grep -q testers && ok "tag ls"
$PVFS --data-dir "$DMOUNT/.pvfs" acl set "$DROOT" tag:testers r >/dev/null && ok "acl set tag principal"

SOCK="$DATA/served.sock"
"$PVFSD" --mount "$DMOUNT" --socket "$SOCK" >/dev/null 2>&1 &
DPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] && ok "pvfsd listening on socket" || fail "pvfsd socket missing"

$PVFS --json remote --socket "$SOCK" --anon info | grep -q "\"forest_id\":\"$DFID\"" \
  && ok "remote info (anonymous)"
$PVFS remote --socket "$SOCK" --anon ls "$DROOT" | grep -q albums \
  && ok "remote ls root (anon via public grant)"
$PVFS --json remote --socket "$SOCK" info | grep -q '"principal":"key:' \
  && ok "remote info (signed client identity)"

# member write: create a folder through the daemon, signed by the client identity
NEWID="$(jget "$($PVFS --json remote --socket "$SOCK" mkdir "$DROOT" uploaded)" created)"
[ ${#NEWID} -eq 64 ] && ok "member created a folder via the daemon" || fail "member mkdir: $NEWID"
$PVFS remote --socket "$SOCK" ls "$DROOT" | grep -q uploaded && ok "member's folder is visible"
# member adds a file then removes it via the daemon
FILEID="$(jget "$($PVFS --json remote --socket "$SOCK" add-file "$DROOT" clip.mkv --size 99 --mime video/x-matroska)" created)"
[ ${#FILEID} -eq 64 ] && ok "member added a file via the daemon" || fail "add-file: $FILEID"
$PVFS remote --socket "$SOCK" rm "$FILEID" >/dev/null && ok "member removed a node via the daemon"
if $PVFS remote --socket "$SOCK" ls "$DROOT" | grep -q clip.mkv; then
  fail "removed file still listed"
else
  ok "removed file is gone"
fi
# member reads a file's bytes over the daemon (the imported albums/a.txt = "hi")
pick_id() { python3 -c 'import json,sys; print(next((c["id"] for c in json.loads(sys.argv[1]) if c["label"]==sys.argv[2]),""))' "$1" "$2"; }
ALBUMS_ID="$(pick_id "$($PVFS --json remote --socket "$SOCK" ls "$DROOT")" albums)"
ATXT_ID="$(pick_id "$($PVFS --json remote --socket "$SOCK" ls "$ALBUMS_ID")" a.txt)"
[ "$($PVFS remote --socket "$SOCK" cat "$ATXT_ID")" = "hi" ] \
  && ok "member reads file bytes via daemon (cat)" || fail "cat mismatch"
# member adds its own file + a location, then reads the bytes back
printf 'member-bytes' > "$DMOUNT/uploaded-blob"
MFILE="$(jget "$($PVFS --json remote --socket "$SOCK" add-file "$DROOT" blob.bin --size 12)" created)"
$PVFS remote --socket "$SOCK" add-location "$MFILE" "file://$DMOUNT/uploaded-blob" >/dev/null \
  && ok "member added a file location"
[ "$($PVFS remote --socket "$SOCK" cat "$MFILE")" = "member-bytes" ] \
  && ok "member reads back its own file content" || fail "member cat mismatch"
# member moves the "uploaded" folder under a new "archive" folder
DEST="$(jget "$($PVFS --json remote --socket "$SOCK" mkdir "$DROOT" archive)" created)"
UPLOADED_ID="$(pick_id "$($PVFS --json remote --socket "$SOCK" ls "$DROOT")" uploaded)"
$PVFS remote --socket "$SOCK" mv "$UPLOADED_ID" "$DEST" >/dev/null && ok "member moved a node"
[ -n "$(pick_id "$($PVFS --json remote --socket "$SOCK" ls "$DEST")" uploaded)" ] \
  && ok "moved node is under its new parent" || fail "mv target missing"
# an anonymous client cannot write (no identity to sign with) → bad input (2)
assert_rc 2 "anon write refused (needs identity)" -- \
  $PVFS remote --socket "$SOCK" --anon mkdir "$DROOT" sneaky

kill "$DPID" 2>/dev/null || true
DPID=""

say "json error shape"
$PVFS --json node deadbeef 2>&1 | grep -q '"error":"NotFound"' && ok "json error variant"

echo
echo "smoke results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL SMOKE TESTS PASSED"
exit "$([ "$FAIL" -eq 0 ] && echo 0 || echo 1)"
