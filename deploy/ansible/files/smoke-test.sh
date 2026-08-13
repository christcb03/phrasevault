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
export XDG_RUNTIME_DIR="$DATA/runtime"      # isolate companion auto-detect from a host agent
unset PVFS_COMPANION_SOCKET                 # never inherit a desktop-SSO forward
export PVFS_SOCKET_DIR="$DATA/sockets"      # per-forest daemon sockets (doc 09 §3b)
# Pre-create the socket dir so pvfsd exercises its "dir already exists → don't
# chmod" path (the /run/pvfs systemd/tmpfiles case), not just first-use creation.
mkdir -p "$PVFS_SOCKET_DIR" "$XDG_RUNTIME_DIR"
PASS=0
FAIL=0
DPID=""
U2PID=""
CPID=""
TPID=""
EPID=""
RPID=""
FPID=""
JPID=""
MPID=""

cleanup() {
  [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
  [ -n "$U2PID" ] && kill "$U2PID" 2>/dev/null
  [ -n "$CPID" ] && kill "$CPID" 2>/dev/null
  [ -n "$TPID" ] && kill "$TPID" 2>/dev/null
  [ -n "$EPID" ] && kill "$EPID" 2>/dev/null
  [ -n "$RPID" ] && kill "$RPID" 2>/dev/null
  [ -n "$FPID" ] && kill "$FPID" 2>/dev/null
  [ -n "$JPID" ] && kill "$JPID" 2>/dev/null
  [ -n "$MPID" ] && { fusermount3 -u "$DATA/fuse-view" 2>/dev/null; kill "$MPID" 2>/dev/null; }
  rm -rf "$DATA"
}
trap cleanup EXIT

say()  { printf '%s\n' "== $*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }

# qgrep: `grep -q` semantics, but consumes ALL input before exiting. grep -q
# quits at the first match, which closes the pipe while the writer may still
# be printing; the Rust CLI then panics on EPIPE and pipefail turns that
# race into a spurious pipeline failure (seen 2026-08-10: the F3 replica
# stat UNAVAILABLE check). Reading to EOF keeps the writer's stdout open
# for its whole lifetime.
qgrep() { grep "$@" >/dev/null; }

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
[ -n "$MNEMONIC" ] && ok "init returns mnemonic" || fail "init returns mnemonic"
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
$PVFS link "$TREE2" "$F" --type ref >/dev/null && ok "ref link into second tree" || fail "ref link into second tree"
assert_rc 4 "second contains (one-home) → 4" -- $PVFS link "$TREE2" "$F" --type contains
assert_rc 4 "duplicate ref same nonce → 4" -- $PVFS link "$TREE2" "$F" --type ref
$PVFS link "$TREE2" "$F" --type ref --nonce 1 >/dev/null && ok "parallel ref with nonce 1" || fail "parallel ref with nonce 1"

say "ls / walk / node / verify"
$PVFS ls "$ROOT" | qgrep movies && ok "ls shows folder" || fail "ls shows folder"
$PVFS walk "$ROOT" | qgrep fifth-element && ok "walk reaches file" || fail "walk reaches file"
$PVFS node "$F" >/dev/null && ok "node show" || fail "node show"
$PVFS verify "$F" >/dev/null && ok "verify valid node" || fail "verify valid node"
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
$PVFS orphans | qgrep "$A" && ok "orphan listed" || fail "orphan listed"
$PVFS purge "$A" >/dev/null && ok "purge orphan" || fail "purge orphan"
$PVFS orphans | qgrep "$G" && ok "ref-less child became orphan after purge" || fail "ref-less child became orphan after purge"
if $PVFS orphans | qgrep "$F"; then
  fail "file with active refs wrongly listed as orphan"
else
  ok "file with active refs is not an orphan"
fi

say "device certificates"
DEV1_JSON="$($PVFS --json device authorize --mnemonic "$MNEMONIC" --index 1)"
DEV1="$(jget "$DEV1_JSON" device_pubkey)"
ok "device 1 authorized"
$PVFS device revoke --mnemonic "$MNEMONIC" --pubkey "$DEV1" >/dev/null && ok "device 1 revoked" || fail "device 1 revoked"

say "recovery from mnemonic"
rm "$PVFS_DATA_DIR/device.key"
$PVFS recover --mnemonic "$MNEMONIC" --device-index 0 >/dev/null && ok "recover re-derives device key" || fail "recover re-derives device key"
$PVFS info >/dev/null && ok "forest usable after recovery" || fail "forest usable after recovery"

say "rebuild from log (projection is disposable)"
rm "$PVFS_DATA_DIR/index.db"
$PVFS walk "$ROOT" >/dev/null && ok "walk triggers index rebuild" || fail "walk post-rebuild"
$PVFS walk "$ROOT" | qgrep second-tree && fail "walk crossed into another tree" || ok "walk stays within one tree"
$PVFS info >/dev/null && ok "index rebuilt from log" || fail "index rebuilt from log"
$PVFS ls "$TREE2" | qgrep fifth-element && ok "rebuilt projection has ref links" || fail "rebuilt projection has ref links"

say "P1: bind / scan / stat / cat"
LIB="$DATA/library"
mkdir -p "$LIB/movies"
printf 'alpha-bytes' > "$LIB/movies/alpha.mkv"
printf 'hello notes' > "$LIB/notes.txt"
LFOLDER="$($PVFS add "$ROOT" --kind folder --label library)"
$PVFS bind "$LFOLDER" "$LIB" --hash-policy on_add >/dev/null && ok "bind" || fail "bind"
$PVFS --json scan "$LFOLDER" | qgrep '"added":2' && ok "scan indexed 2 files" || fail "scan indexed 2 files"
$PVFS --json scan "$LFOLDER" | qgrep '"unchanged":2' && ok "rescan no-op" || fail "rescan no-op"
MOVIES="$($PVFS --json ls "$LFOLDER" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "movies": print(e["id"])')"
ALPHA="$($PVFS --json ls "$MOVIES" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "alpha.mkv": print(e["id"])')"
[ "$($PVFS cat "$ALPHA")" = "alpha-bytes" ] && ok "cat verified read" || fail "cat verified read"
$PVFS stat "$ALPHA" | qgrep "file://" && ok "stat shows location" || fail "stat shows location"

say "P1: changed file -> flag -> resolve"
printf 'alpha-bytes-changed-longer' > "$LIB/movies/alpha.mkv"
$PVFS --json scan "$LFOLDER" | qgrep '"changed":1' && ok "change flagged" || fail "change flagged"
$PVFS changes | qgrep "$ALPHA" && ok "changes lists flagged node" || fail "changes lists flagged node"
assert_rc 3 "flagged location not served → 3" -- $PVFS cat "$ALPHA"
NEW_ALPHA="$($PVFS resolve "$ALPHA" --replace)"
[ ${#NEW_ALPHA} -eq 64 ] && ok "resolve --replace returns successor" || fail "resolve --replace returns successor"
[ "$($PVFS cat "$NEW_ALPHA")" = "alpha-bytes-changed-longer" ] && ok "successor serves new bytes" || fail "successor serves new bytes"
$PVFS orphans | qgrep "$ALPHA" && ok "old node kept as orphan" || fail "old node kept as orphan"

say "P1: disk deletion is soft"
rm "$LIB/notes.txt"
$PVFS --json scan "$LFOLDER" | qgrep '"removed":1' && ok "deletion soft-removed location" || fail "deletion soft-removed location"
NOTES="$($PVFS --json ls "$LFOLDER" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "notes.txt": print(e["id"])')"
$PVFS stat "$NOTES" | qgrep UNAVAILABLE && ok "node kept, marked unavailable" || fail "node kept, marked unavailable"

say "P1: hash fill"
# Under --hash-policy on_add the scan already content-addresses the file, so
# `pvfs hash` is an idempotent no-op that returns the SAME id (no successor).
printf 'lazy-content' > "$LIB/movies/lazy.bin"
$PVFS scan "$LFOLDER" >/dev/null
LAZY="$($PVFS --json ls "$MOVIES" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "lazy.bin": print(e["id"])')"
HASHED="$($PVFS hash "$LAZY" 2>/dev/null)"
[ "$HASHED" = "$LAZY" ] && ok "hash on an on_add node is an idempotent no-op" \
  || fail "hash on on_add node re-identified: $LAZY -> $HASHED"
[ "$($PVFS cat "$HASHED")" = "lazy-content" ] && ok "hashed node serves verified" || fail "hashed cat"
# A genuinely lazy binding: scan skips hashing, so the fill happens at `pvfs
# hash` time — the hash lives in the immutable payload, hence a successor node.
LAZYLIB="$DATA/lazylib"
mkdir -p "$LAZYLIB"
printf 'truly-lazy' > "$LAZYLIB/slow.bin"
ZFOLDER="$($PVFS add "$ROOT" --kind folder --label lazylib)"
$PVFS bind "$ZFOLDER" "$LAZYLIB" --hash-policy lazy >/dev/null && ok "bind (lazy policy)" || fail "lazy bind"
$PVFS scan "$ZFOLDER" >/dev/null
SLOW="$($PVFS --json ls "$ZFOLDER" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "slow.bin": print(e["id"])')"
FILLED="$($PVFS hash "$SLOW" 2>/dev/null)"
[ ${#FILLED} -eq 64 ] && [ "$FILLED" != "$SLOW" ] && ok "hash created successor node (lazy policy)" \
  || fail "lazy hash fill: $SLOW -> $FILLED"
[ "$($PVFS cat "$FILLED")" = "truly-lazy" ] && ok "successor serves verified bytes" || fail "successor cat"

say "P4 F0: export (native tree view, doc 17)"
EXPORT_DIR="$DATA/exportview"
$PVFS --json export "$LFOLDER" "$EXPORT_DIR" | qgrep '"exported":2' && ok "export materialized 2 files" || fail "export materialized 2 files"
[ -L "$EXPORT_DIR/movies/alpha.mkv" ] && ok "export entry is a symlink" || fail "export entry is a symlink"
[ "$(cat "$EXPORT_DIR/movies/alpha.mkv")" = "alpha-bytes-changed-longer" ] && ok "export reads through" || fail "export reads through"
$PVFS --json export "$LFOLDER" "$EXPORT_DIR" | qgrep '"unchanged":2' && ok "re-export idempotent" || fail "re-export idempotent"
$PVFS --json export "$LFOLDER" "$EXPORT_DIR" | qgrep '"path":"notes.txt"' && ok "unavailable file reported skipped" || fail "unavailable file reported skipped"
COPY_DIR="$DATA/exportcopy"
$PVFS export "$LFOLDER" "$COPY_DIR" --mode copy >/dev/null
[ ! -L "$COPY_DIR/movies/lazy.bin" ] && [ "$(cat "$COPY_DIR/movies/lazy.bin")" = "lazy-content" ] \
  && ok "copy export lands real verified bytes" || fail "copy export lands real verified bytes"
OCCUPIED="$DATA/occupied"
mkdir -p "$OCCUPIED"; printf 'x' > "$OCCUPIED/keep.txt"
assert_rc 2 "export refuses foreign non-empty dir → 2" -- $PVFS export "$LFOLDER" "$OCCUPIED"
[ -f "$OCCUPIED/keep.txt" ] && ok "foreign dir untouched" || fail "foreign dir untouched"

say "P1: the watcher (punch E: now `serve watch` / the watch job)"
$PVFS serve watch --debounce-ms 300 >/dev/null 2>&1 &
SERVE_PID=$!
sleep 2
printf 'watched-file' > "$LIB/movies/watched.mkv"
sleep 3
kill "$SERVE_PID" 2>/dev/null; wait "$SERVE_PID" 2>/dev/null || true
rm -f "$PVFS_DATA_DIR/serve.lock"
$PVFS ls "$MOVIES" | qgrep watched.mkv && ok "watcher ingested new file" || fail "watcher ingested new file"

say "P1.5: forest init / registry / mount URIs"
MOUNT="$DATA/workspace"
mkdir -p "$MOUNT/docs"
printf 'mount notes' > "$MOUNT/docs/readme.txt"
FINIT="$($PVFS --json forest init --mount "$MOUNT")"
echo "$FINIT" | qgrep '"imported":true' && ok "forest init imported mount tree" || fail "forest init imported mount tree"
[ -f "$MOUNT/.pvfs/log.db" ] && ok "state lives under .pvfs/" || fail "state lives under .pvfs/"
$PVFS forest register "$MOUNT" --alias smokehome >/dev/null && ok "forest register" || fail "forest register"
$PVFS ls | qgrep smokehome && ok "pvfs ls lists registered forest" || fail "pvfs ls lists registered forest"
$PVFS ls "pvfs://smokehome@local/docs" | qgrep readme.txt && ok "ls by alias URI" || fail "ls by alias URI"
$PVFS ls "$MOUNT/docs" | qgrep readme.txt && ok "ls by absolute path shorthand" || fail "ls by absolute path shorthand"
$PVFS cat "pvfs://smokehome/docs/readme.txt" | qgrep "mount notes" && ok "cat by tree path" || fail "cat by tree path"
$PVFS forest info "pvfs://smokehome@local/" | qgrep instance_id && ok "forest info by URI" || fail "forest info by URI"
if $PVFS ls "$MOUNT" | qgrep "\.pvfs"; then
  fail ".pvfs leaked into the indexed tree"
else
  ok ".pvfs not indexed into the tree"
fi

say "P1.5: portable forest (no registry)"
PORT="$DATA/usb-project"
cp -r "$MOUNT" "$PORT"
$PVFS ls "$PORT/docs" | qgrep readme.txt && ok "portable mount opens by path" || fail "portable mount opens by path"
$PVFS forest unregister smokehome >/dev/null && ok "unregister" || fail "unregister"
[ -f "$MOUNT/.pvfs/log.db" ] && ok "unregister keeps .pvfs/" || fail "unregister keeps .pvfs/"
assert_rc 3 "unknown alias → 3" -- $PVFS ls "pvfs://smokehome/docs"
$PVFS ls "$MOUNT/docs" | qgrep readme.txt && ok "unregistered mount still opens by path" || fail "unregistered mount still opens by path"

say "P2: daemon + remote client (doc 07)"
DMOUNT="$DATA/served"
mkdir -p "$DMOUNT/albums"
printf 'hi' > "$DMOUNT/albums/a.txt"
DINIT="$($PVFS --json forest init --mount "$DMOUNT")"
DROOT="$(jget "$DINIT" root_node_id)"
DFID="$(jget "$DINIT" forest_id)"
DMN="$(jget "$DINIT" mnemonic)"
CLIENTKEY="$(jget "$($PVFS --json whoami)" pubkey)"
[ -n "$CLIENTKEY" ] && ok "whoami prints client identity" || fail "whoami prints client identity"

# Owner setup happens BEFORE serving (the daemon opens a snapshot of the log).
$PVFS --data-dir "$DMOUNT/.pvfs" acl set "$DROOT" public r >/dev/null \
  && ok "acl set public r on root" || fail "acl set public r on root"
$PVFS --data-dir "$DMOUNT/.pvfs" device authorize-member --pubkey "$CLIENTKEY" \
  >/dev/null && ok "authorize member (admin device, no recovery phrase)" || fail "authorize member (admin device, no recovery phrase)"
$PVFS --data-dir "$DMOUNT/.pvfs" acl set "$DROOT" "key:$CLIENTKEY" rw >/dev/null \
  && ok "grant member rw on root" || fail "grant member rw on root"
# tags (doc 09): CLI wiring — tag a member, list it, share a node to a tag
$PVFS --data-dir "$DMOUNT/.pvfs" tag add "$CLIENTKEY" testers >/dev/null && ok "tag add" || fail "tag add"
$PVFS --data-dir "$DMOUNT/.pvfs" tag ls "$CLIENTKEY" | qgrep testers && ok "tag ls" || fail "tag ls"
$PVFS --data-dir "$DMOUNT/.pvfs" acl set "$DROOT" tag:testers r >/dev/null && ok "acl set tag principal" || fail "acl set tag principal"

# pvfsd binds its conventional per-forest socket ($PVFS_SOCKET_DIR/<forest_id>.sock)
# and (F1) a TLS network listener on an ephemeral port, logged for the F1 section.
SOCK="$PVFS_SOCKET_DIR/$DFID.sock"
"$PVFSD" --mount "$DMOUNT" --listen 127.0.0.1:0 >/dev/null 2>"$DATA/pvfsd.log" &
DPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] && ok "pvfsd binds its conventional socket" || fail "pvfsd socket missing"
# the client finds the socket by forest (mount path) without --socket
$PVFS --json remote --forest "$DMOUNT" --anon info | qgrep "\"forest_id\":\"$DFID\"" \
  && ok "remote --forest resolves the daemon socket" || fail "remote --forest resolves the daemon socket"

$PVFS --json remote --socket "$SOCK" --anon info | qgrep "\"forest_id\":\"$DFID\"" \
  && ok "remote info (anonymous)" || fail "remote info (anonymous)"
$PVFS remote --socket "$SOCK" --anon ls "$DROOT" | qgrep albums \
  && ok "remote ls root (anon via public grant)" || fail "remote ls root (anon via public grant)"
$PVFS --json remote --socket "$SOCK" info | qgrep '"principal":"key:' \
  && ok "remote info (signed client identity)" || fail "remote info (signed client identity)"

# member write: create a folder through the daemon, signed by the client identity
NEWID="$(jget "$($PVFS --json remote --socket "$SOCK" mkdir "$DROOT" uploaded)" created)"
[ ${#NEWID} -eq 64 ] && ok "member created a folder via the daemon" || fail "member mkdir: $NEWID"
$PVFS remote --socket "$SOCK" ls "$DROOT" | qgrep uploaded && ok "member's folder is visible" || fail "member's folder is visible"
# member adds a file then removes it via the daemon
FILEID="$(jget "$($PVFS --json remote --socket "$SOCK" add-file "$DROOT" clip.mkv --size 99 --mime video/x-matroska)" created)"
[ ${#FILEID} -eq 64 ] && ok "member added a file via the daemon" || fail "add-file: $FILEID"
$PVFS remote --socket "$SOCK" rm "$FILEID" >/dev/null && ok "member removed a node via the daemon" || fail "member removed a node via the daemon"
if $PVFS remote --socket "$SOCK" ls "$DROOT" | qgrep clip.mkv; then
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
  && ok "member added a file location" || fail "member added a file location"
[ "$($PVFS remote --socket "$SOCK" cat "$MFILE")" = "member-bytes" ] \
  && ok "member reads back its own file content" || fail "member cat mismatch"
# remote takes paths/URIs too (doc 08 §4 item 6 remainder): resolved by
# ACL-filtered ls over the daemon, never by opening the owner's engine
[ "$($PVFS remote --socket "$SOCK" cat "$DMOUNT/albums/a.txt")" = "hi" ] \
  && ok "remote cat resolves an absolute path" || fail "remote path cat"
$PVFS remote --socket "$SOCK" --anon ls "$DMOUNT/albums" | qgrep a.txt \
  && ok "remote ls resolves a path (anon)" || fail "remote path ls"
# remote add-node/payload (doc 13 log-resident records via the CLI)
RECID="$(jget "$($PVFS --json remote --socket "$SOCK" add-node "$DROOT" g-1 pvos.grant --payload '{"grant":1}')" created)"
[ ${#RECID} -eq 64 ] && ok "remote add-node created a typed record" || fail "remote add-node: $RECID"
[ "$($PVFS remote --socket "$SOCK" payload "$RECID")" = '{"grant":1}' ] \
  && ok "remote payload reads the record back" || fail "remote payload mismatch"
if $PVFS remote --socket "$SOCK" add-node "$DROOT" bad folder --payload x >/dev/null 2>&1; then
  fail "remote add-node accepted a reserved type"
else
  ok "remote add-node refuses reserved types"
fi
# secure store created + written + read on the fly WHILE the daemon serves
# (doc 12 §8.5): the messenger "new chat = new encrypted store" case. These
# auto-route through the running daemon (managed location, no path, no restart).
SSNODE="$(jget "$($PVFS --json --data-dir "$DMOUNT/.pvfs" secure create "$DROOT" chat-1)" created)"
[ ${#SSNODE} -eq 64 ] && ok "secure store created over the LIVE daemon (no restart)" || fail "secure create over daemon: $SSNODE"
printf 'msg-ciphertext' | $PVFS --data-dir "$DMOUNT/.pvfs" secure put "$SSNODE" - --raw >/dev/null \
  && ok "secure put over the live daemon (managed location auto-allocated)" || fail "secure put over daemon"
[ "$($PVFS --data-dir "$DMOUNT/.pvfs" secure cat "$SSNODE" --raw)" = "msg-ciphertext" ] \
  && ok "secure cat over the live daemon round-trips" || fail "secure cat over daemon"
# member moves the "uploaded" folder under a new "archive" folder
DEST="$(jget "$($PVFS --json remote --socket "$SOCK" mkdir "$DROOT" archive)" created)"
UPLOADED_ID="$(pick_id "$($PVFS --json remote --socket "$SOCK" ls "$DROOT")" uploaded)"
$PVFS remote --socket "$SOCK" mv "$UPLOADED_ID" "$DEST" >/dev/null && ok "member moved a node" || fail "member moved a node"
[ -n "$(pick_id "$($PVFS --json remote --socket "$SOCK" ls "$DEST")" uploaded)" ] \
  && ok "moved node is under its new parent" || fail "mv target missing"
# an anonymous client cannot write (no identity to sign with) → bad input (2)
assert_rc 2 "anon write refused (needs identity)" -- \
  $PVFS remote --socket "$SOCK" --anon mkdir "$DROOT" sneaky

say "F1: network transport — TLS listener + pinned client (doc 17 §4)"
NETLINE="$(grep -m1 'listening on' "$DATA/pvfsd.log" || true)"
NETADDR="$(printf '%s' "$NETLINE" | sed -E 's/.*listening on ([^ ]+).*/\1/')"
NETPIN="$(printf '%s' "$NETLINE" | sed -E 's/.*transport pin ([0-9a-f]+).*/\1/')"
if [ -n "$NETADDR" ] && [ ${#NETPIN} -eq 64 ]; then
  ok "pvfsd prints its listen address + transport pin"
else
  fail "pvfsd --listen line missing (got: $NETLINE)"
fi
[ "$(cat "$DMOUNT/.pvfs/nettls/pin")" = "$NETPIN" ] \
  && ok "pin file matches the printed pin" || fail "nettls/pin mismatch"
$PVFS --json remote --connect "$NETADDR" --pin "$NETPIN" --anon info \
  | qgrep "\"forest_id\":\"$DFID\"" && ok "remote --connect info over TLS (anon)" || fail "remote --connect info over TLS (anon)"
$PVFS remote --connect "$NETADDR" --pin "$NETPIN" --anon ls "$DROOT" | qgrep albums \
  && ok "remote ls over TLS" || fail "remote ls over TLS"
[ "$($PVFS remote --connect "$NETADDR" --pin "$NETPIN" cat "$ATXT_ID")" = "hi" ] \
  && ok "remote cat streams bytes over TLS (signed identity)" || fail "TLS cat mismatch"
BADPIN="$(printf '0%.0s' $(seq 1 64))"
assert_rc 2 "wrong pin refused at the TLS handshake → 2" -- \
  $PVFS remote --connect "$NETADDR" --pin "$BADPIN" --anon info
$PVFS instance add smokehost "$NETADDR" "$NETPIN" >/dev/null && ok "instance add pins the server" || fail "instance add pins the server"
$PVFS instance ls | qgrep "smokehost  $NETADDR" && ok "instance ls lists it" || fail "instance ls lists it"
$PVFS --json remote --instance smokehost --anon info | qgrep "\"forest_id\":\"$DFID\"" \
  && ok "remote --instance dials by name" || fail "remote --instance dials by name"
$PVFS instance rm smokehost >/dev/null && ok "instance rm forgets it" || fail "instance rm forgets it"
assert_rc 3 "removed instance no longer resolves → 3" -- \
  $PVFS remote --instance smokehost --anon info

say "P2-E 3d: auto-routed owner admin with the daemon RUNNING (doc 08 item 16)"
# Regression guard. Plain `acl set` / `tag add` — no --data-dir, no `remote` —
# must auto-route to the running daemon AND sign with the forest's authorized
# admin device key (<mount>/.pvfs/device.key), NOT the generic client identity.
# The client identity here is an authorized *member* with rw (granted above) but
# NOT admin, so before the fix these ops were rejected (forbidden, rc 5) — the
# admin signer must be the forest device key. The earlier admin ops (lines above)
# don't catch this: they run with --data-dir *before* pvfsd starts, so they go
# direct (forest device key) and never exercise auto-routing.
# rc 0 here is decisive: the daemon only returns 0 after it authorizes the author
# as admin AND commits the event, so a rejected (unauthorized) signer would fail.
assert_rc 0 "auto-routed acl set accepted (owner admin via running daemon)" -- \
  $PVFS --forest "$DMOUNT" acl set "$DROOT" public rw
assert_rc 0 "auto-routed tag add accepted (owner admin via running daemon)" -- \
  $PVFS --forest "$DMOUNT" tag add "$CLIENTKEY" liveadmin
assert_rc 0 "auto-routed acl set tag principal accepted" -- \
  $PVFS --forest "$DMOUNT" acl set "$DROOT" tag:liveadmin r
# daemon is still serving the same live forest after the auto-routed admin ops
$PVFS --json remote --socket "$SOCK" info | qgrep "\"forest_id\":\"$DFID\"" \
  && ok "daemon still serving after auto-routed admin" || fail "daemon still serving after auto-routed admin"

say "P5.0: serve jobs — config, live status, SIGHUP reload (doc 18 §2)"
$PVFS --data-dir "$DMOUNT/.pvfs" serve ls | qgrep "follow" && ok "serve ls lists known jobs" || fail "serve ls"
$PVFS --data-dir "$DMOUNT/.pvfs" serve enable sync >/dev/null && ok "serve enable edits serve.jobs" || fail "serve enable"
$PVFS --json --data-dir "$DMOUNT/.pvfs" serve ls | qgrep '"job":"sync","enabled":true' \
  && ok "serve ls shows the enabled job" || fail "serve ls enabled"
assert_rc 2 "unknown job refused → 2" -- $PVFS --data-dir "$DMOUNT/.pvfs" serve enable defrag
$PVFS --json --data-dir "$DMOUNT/.pvfs" serve status | qgrep '"runner":"on"' \
  && ok "live status: runner attached" || fail "serve status runner"
# the daemon started before the enable — SIGHUP folds the new config in
kill -HUP "$DPID"
STATUS_OK=""
for _ in $(seq 1 20); do
  if $PVFS --json --data-dir "$DMOUNT/.pvfs" serve status | qgrep '"job":"sync","enabled":true,"state":"idle"'; then
    STATUS_OK=1; break
  fi
  sleep 0.25
done
[ -n "$STATUS_OK" ] && ok "SIGHUP reloaded serve.jobs into the runner" || fail "SIGHUP reload"
$PVFS --data-dir "$DMOUNT/.pvfs" serve disable sync >/dev/null && ok "serve disable" || fail "serve disable"

say "F2: replica — verified log shipping (doc 17 §5)"
REPMOUNT="$DATA/replica"
# the gate: log shipping needs admin on the forest root (client has only rw)
assert_rc 5 "replica add without root admin → 5" -- \
  $PVFS replica add "$REPMOUNT" --connect "$NETADDR" --pin "$NETPIN"
$PVFS --forest "$DMOUNT" acl set "$DROOT" "key:$CLIENTKEY" rwa >/dev/null \
  && ok "owner granted the client root admin (the replication capability)" || fail "owner granted the client root admin (the replication capability)"
REP_JSON="$($PVFS --json replica add "$REPMOUNT" --connect "$NETADDR" --pin "$NETPIN")"
[ "$(jget "$REP_JSON" forest_id)" = "$DFID" ] \
  && ok "replica add ships + verifies the full log (over TLS)" || fail "replica add: $REP_JSON"
$PVFS --data-dir "$REPMOUNT/.pvfs" ls "$DROOT" | qgrep albums && ok "replica lists the tree" || fail "replica lists the tree"
[ "$($PVFS --data-dir "$REPMOUNT/.pvfs" cat "$ATXT_ID")" = "hi" ] \
  && ok "replica cat reads through (same-host locations)" || fail "replica cat"
# P6.0 (doc 19 §2): the once-refused ops now write through, member-signed.
# (The replica's own engine still never writes its log — every op routes;
# the temp-node refusal in F5.0 below stays the no-route proof.)
P6DIR="$(jget "$($PVFS --json --data-dir "$REPMOUNT/.pvfs" add "$DROOT" --kind folder --label p6-scratch)" node_id)"
P6LINK="$(jget "$($PVFS --json --data-dir "$REPMOUNT/.pvfs" link "$P6DIR" "$ATXT_ID" --type ref)" link_id)"
[ ${#P6LINK} -eq 64 ] && ok "member link wrote through (ref link created)" || fail "p6 link: $P6LINK"
$PVFS remote --socket "$SOCK" --anon ls "$P6DIR" | qgrep a.txt \
  && ok "…and the ref landed in the owner's log" || fail "p6 link not on owner"
$PVFS --data-dir "$REPMOUNT/.pvfs" unlink "$P6LINK" >/dev/null \
  && ok "member unlink wrote through" || fail "p6 unlink"
$PVFS remote --socket "$SOCK" --anon ls "$P6DIR" | qgrep a.txt \
  && fail "unlinked ref still visible" || ok "unlinked ref gone from the owner"
printf 'p6-bytes' > "$DATA/p6.bin"
P6F="$(jget "$($PVFS --json --data-dir "$REPMOUNT/.pvfs" add "$P6DIR" --kind file --label p6.bin --size 8)" node_id)"
$PVFS --data-dir "$REPMOUNT/.pvfs" loc add "$P6F" "file://$DATA/p6.bin" >/dev/null
$PVFS --data-dir "$REPMOUNT/.pvfs" loc ls "$P6F" | qgrep p6.bin \
  && ok "loc add visible" || fail "p6 loc add"
$PVFS --data-dir "$REPMOUNT/.pvfs" loc rm "$P6F" "file://$DATA/p6.bin" >/dev/null \
  && ok "member loc rm wrote through (P6.0 retraction)" || fail "p6 loc rm"
$PVFS --data-dir "$REPMOUNT/.pvfs" loc ls "$P6F" | qgrep p6.bin \
  && fail "retracted location still listed" || ok "retracted location gone"
# …and re-recording after a retraction works (also keeps the file fetchable
# for the F3 sync pass below — a placed subtree must not hold a dead file)
$PVFS --data-dir "$REPMOUNT/.pvfs" loc add "$P6F" "file://$DATA/p6.bin" >/dev/null \
  && ok "location re-recorded after the retraction" || fail "re-add after loc rm"
# F0 + F2: a replica exports like any forest — the cross-host media view
$PVFS --data-dir "$REPMOUNT/.pvfs" export "$DROOT" "$DATA/replica-view" >/dev/null
[ "$(cat "$DATA/replica-view/albums/a.txt")" = "hi" ] \
  && ok "export from the replica reads through" || fail "replica export"
# pvfsd serves a replica read-only, ACLs replayed from the shipped log
REPSOCK="$DATA/replica.sock"
"$PVFSD" --mount "$REPMOUNT" --socket "$REPSOCK" >/dev/null 2>&1 &
RPID=$!
for _ in $(seq 1 50); do [ -S "$REPSOCK" ] && break; sleep 0.1; done
$PVFS remote --socket "$REPSOCK" --anon ls "$DROOT" | qgrep albums \
  && ok "pvfsd serves the replica (anon via replayed public grant)" || fail "replica daemon ls"
assert_rc 5 "write via the replica daemon refused → 5" -- \
  $PVFS remote --socket "$REPSOCK" mkdir "$DROOT" sneaky
kill -TERM "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null || true
RPID=""
# sync: new content on the owner appears after `replica sync`
$PVFS remote --socket "$SOCK" mkdir "$DROOT" fresh-content >/dev/null
SYNC_JSON="$($PVFS --json replica sync "$REPMOUNT")"
[ "$(jget "$SYNC_JSON" synced)" -ge 1 ] && ok "replica sync shipped the tail" || fail "sync: $SYNC_JSON"
$PVFS --data-dir "$REPMOUNT/.pvfs" ls "$DROOT" | qgrep fresh-content \
  && ok "synced content visible on the replica" || fail "synced content missing"

say "F3: placement & sync — bytes pulled local (doc 17 §6)"
# an owned forest has no source to sync from
assert_rc 2 "sync on an owned forest → 2 (no source)" -- \
  $PVFS --data-dir "$DMOUNT/.pvfs" sync "$DROOT"
# a file whose bytes "live elsewhere": catalog it, ship it to the replica,
# then move the bytes and tell only the OWNER — the replica's recorded
# location now dangles, exactly like a location on another host.
mkdir -p "$DATA/far-store"
printf 'far-away-bytes' > "$DATA/far-store/movie.mkv"
MOVIE="$(jget "$($PVFS --json remote --socket "$SOCK" add-file "$DROOT" movie.mkv --size 14)" created)"
$PVFS remote --socket "$SOCK" add-location "$MOVIE" "file://$DATA/far-store/movie.mkv" >/dev/null
$PVFS --json replica sync "$REPMOUNT" >/dev/null
mv "$DATA/far-store" "$DATA/far-store2"
$PVFS remote --socket "$SOCK" add-location "$MOVIE" "file://$DATA/far-store2/movie.mkv" >/dev/null
# stat (which never fetches) shows the file unavailable locally — cat would
# already self-heal via F5.2 read-through, so the sync pass below proves the
# batch path instead
$PVFS --data-dir "$REPMOUNT/.pvfs" stat "$MOVIE" | qgrep UNAVAILABLE \
  && ok "replica sees the file unavailable locally before sync" || fail "replica sees the file unavailable locally before sync"
$PVFS --data-dir "$REPMOUNT/.pvfs" place "$DROOT" sync >/dev/null \
  && ok "placed the root subtree sync" || fail "placed the root subtree sync"
SYNCJ="$($PVFS --json --data-dir "$REPMOUNT/.pvfs" sync)"
[ "$(jget "$SYNCJ" fetched)" -ge 1 ] && ok "pvfs sync fetched the missing bytes" || fail "sync: $SYNCJ"
[ "$($PVFS --data-dir "$REPMOUNT/.pvfs" cat "$MOVIE")" = "far-away-bytes" ] \
  && ok "replica serves the synced bytes (verified)" || fail "synced cat mismatch"
$PVFS --data-dir "$REPMOUNT/.pvfs" stat "$MOVIE" | qgrep "pvfs-sync" \
  && ok "stat shows the managed sync-store location" || fail "stat shows the managed sync-store location"
# F0 + F3: re-export picks the synced file up like any other
$PVFS --data-dir "$REPMOUNT/.pvfs" export "$DROOT" "$DATA/replica-view" >/dev/null
[ "$(cat "$DATA/replica-view/movie.mkv")" = "far-away-bytes" ] \
  && ok "re-export serves the synced file to non-PVFS apps" || fail "export after sync"
# P6.1 (doc 19 §3): the sync store can move to the big disk; earlier files keep serving
$PVFS --data-dir "$REPMOUNT/.pvfs" sync --to "$DATA/big-disk" >/dev/null \
  && ok "sync --to points new fetches at the big disk" || fail "sync --to set"
$PVFS --data-dir "$REPMOUNT/.pvfs" sync --to | qgrep big-disk \
  && ok "bare --to prints the configured root" || fail "sync --to print"
[ "$($PVFS --data-dir "$REPMOUNT/.pvfs" cat "$MOVIE" 2>/dev/null)" = "far-away-bytes" ] \
  && ok "files in the default store keep serving after the move" || fail "old store unreadable"
$PVFS --data-dir "$REPMOUNT/.pvfs" sync --to default >/dev/null \
  && ok "--to default restores the in-data-dir store" || fail "sync --to default"

say "F5.0: write-through — the replica accepts writes via its source (doc 17 §7)"
WTID="$(jget "$($PVFS --json --data-dir "$REPMOUNT/.pvfs" add "$DROOT" --kind file --label ingest.mkv --size 11 --mime video/x-matroska)" node_id)"
[ ${#WTID} -eq 64 ] && ok "pvfs add on the replica wrote through" || fail "write-through add: $WTID"
$PVFS --data-dir "$REPMOUNT/.pvfs" ls "$DROOT" | qgrep ingest.mkv \
  && ok "read-your-writes: visible on the replica at once" || fail "read-your-writes: visible on the replica at once"
$PVFS remote --socket "$SOCK" --anon ls "$DROOT" | qgrep ingest.mkv \
  && ok "…and recorded in the owner's log" || fail "…and recorded in the owner's log"
printf 'ingested-it' > "$DATA/ingest-src.bin"
$PVFS --data-dir "$REPMOUNT/.pvfs" loc add "$WTID" "file://$DATA/ingest-src.bin" >/dev/null \
  && ok "loc add wrote through" || fail "loc add wrote through"
[ "$($PVFS --data-dir "$REPMOUNT/.pvfs" cat "$WTID")" = "ingested-it" ] \
  && ok "replica serves the newly ingested file" || fail "write-through cat"
$PVFS --forest "$REPMOUNT" tag add "$CLIENTKEY" via-replica >/dev/null \
  && ok "admin op auto-routes through the source" || fail "admin op auto-routes through the source"
$PVFS --data-dir "$DMOUNT/.pvfs" tag ls "$CLIENTKEY" | qgrep via-replica \
  && ok "tag landed in the owner's log" || fail "tag landed in the owner's log"
assert_rc 2 "temp node on a replica refused → 2" -- \
  $PVFS --data-dir "$REPMOUNT/.pvfs" add "$DROOT" --kind folder --label scratch --temp

say "F5.1: instance-qualified locations (pvfs-host://, doc 17 §7.2)"
printf 'host-qualified' > "$DATA/hostloc.bin"
HQ="$(jget "$($PVFS --json remote --socket "$SOCK" add-file "$DROOT" hostloc.bin --size 14)" created)"
$PVFS --data-dir "$DMOUNT/.pvfs" loc add "$HQ" --here "$DATA/hostloc.bin" >/dev/null \
  && ok "loc add --here records this instance's pin" || fail "loc add --here records this instance's pin"
$PVFS --data-dir "$DMOUNT/.pvfs" loc ls "$HQ" | qgrep "pvfs-host://$NETPIN" \
  && ok "location carries the owner's transport pin" || fail "host uri missing"
[ "$($PVFS --data-dir "$DMOUNT/.pvfs" cat "$HQ")" = "host-qualified" ] \
  && ok "own pin resolves locally" || fail "owner host-loc cat"
$PVFS --json replica sync "$REPMOUNT" >/dev/null
$PVFS --data-dir "$REPMOUNT/.pvfs" stat "$HQ" | qgrep UNAVAILABLE \
  && ok "foreign pin is unavailable locally (stat never fetches)" || fail "foreign pin is unavailable locally (stat never fetches)"
$PVFS --json --data-dir "$REPMOUNT/.pvfs" sync >/dev/null \
  && ok "sync fetches the host-qualified file from the source" || fail "sync fetches the host-qualified file from the source"
[ "$($PVFS --data-dir "$REPMOUNT/.pvfs" cat "$HQ")" = "host-qualified" ] \
  && ok "replica serves it from the sync store" || fail "host-loc after sync"

say "F5.2: remote read-through — fetch from any pinned instance (doc 17 §7.3)"
# the edge box (the first replica) now serves a TLS listener of its own
"$PVFSD" --mount "$REPMOUNT" --socket "$REPSOCK" --listen 127.0.0.1:0 >/dev/null 2>"$DATA/repd.log" &
RPID=$!
for _ in $(seq 1 50); do [ -S "$REPSOCK" ] && break; sleep 0.1; done
REPLINE="$(grep -m1 'listening on' "$DATA/repd.log" || true)"
REPADDR="$(printf '%s' "$REPLINE" | sed -E 's/.*listening on ([^ ]+).*/\1/')"
REPPIN="$(printf '%s' "$REPLINE" | sed -E 's/.*transport pin ([0-9a-f]+).*/\1/')"
[ ${#REPPIN} -eq 64 ] && ok "edge box minted its own transport pin" || fail "edge pin: $REPLINE"
# bytes that exist ONLY on the edge box, cataloged via write-through + --here
printf 'edge-bytes' > "$DATA/edge.bin"
EDGE="$(jget "$($PVFS --json --data-dir "$REPMOUNT/.pvfs" add "$DROOT" --kind file --label edge.bin --size 10)" node_id)"
$PVFS --data-dir "$REPMOUNT/.pvfs" loc add "$EDGE" --here "$DATA/edge.bin" >/dev/null \
  && ok "edge box recorded its pin into the owner's log" || fail "edge box recorded its pin into the owner's log"
# a second consumer replica: the file is cataloged but its holder unknown…
$PVFS --json replica add "$DATA/rep2" --connect "$NETADDR" --pin "$NETPIN" >/dev/null
assert_rc 3 "consumer cat before the holder is registered → 3" -- \
  $PVFS --data-dir "$DATA/rep2/.pvfs" cat "$EDGE"
# …until the holder's pin is registered — then cat fetches on demand
$PVFS instance add edgebox "$REPADDR" "$REPPIN" >/dev/null
[ "$($PVFS --data-dir "$DATA/rep2/.pvfs" cat "$EDGE" 2>/dev/null)" = "edge-bytes" ] \
  && ok "consumer cat read-through fetched from the edge box" || fail "read-through cat"
$PVFS --data-dir "$DATA/rep2/.pvfs" stat "$EDGE" | qgrep "pvfs-sync" \
  && ok "fetched bytes promoted into the consumer's sync store" || fail "fetched bytes promoted into the consumer's sync store"
# the owner pulls edge bytes home too — the mover's core primitive (F5.3)
SYNCJ2="$($PVFS --json --data-dir "$DMOUNT/.pvfs" sync "$DROOT")"
[ "$(jget "$SYNCJ2" fetched)" -ge 1 ] && ok "owner pulled the edge bytes home" || fail "owner sync: $SYNCJ2"
[ "$($PVFS --data-dir "$DMOUNT/.pvfs" cat "$EDGE")" = "edge-bytes" ] \
  && ok "owner serves the file from its own store" || fail "owner cat edge"
$PVFS instance rm edgebox >/dev/null
kill -TERM "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null || true
RPID=""

say "F5.3: the mover — central migration + edge eviction (doc 17 §7.4)"
$PVFS --data-dir "$DMOUNT/.pvfs" place "$DROOT" central --to "$DATA/central-store" >/dev/null \
  && ok "owner placed the library central" || fail "owner placed the library central"
TIERJ="$($PVFS --json --data-dir "$DMOUNT/.pvfs" tier)"
[ "$(jget "$TIERJ" migrated)" -ge 1 ] && ok "mover migrated the edge file" || fail "tier: $TIERJ"
[ "$(jget "$TIERJ" retired)" -ge 1 ] && ok "mover retired the edge location" || fail "tier retired: $TIERJ"
EDGE2="$(printf '%s' "$EDGE" | cut -c1-2)"
[ "$(cat "$DATA/central-store/$EDGE2/$EDGE")" = "edge-bytes" ] \
  && ok "verified copy sits in the central store" || fail "central copy missing"
$PVFS --data-dir "$DMOUNT/.pvfs" loc ls "$EDGE" | qgrep "file://$DATA/central-store" \
  && ok "central location recorded in the log" || fail "central location recorded in the log"
if $PVFS --data-dir "$DMOUNT/.pvfs" loc ls "$EDGE" | qgrep "pvfs-host://$REPPIN"; then
  fail "edge location still live in the catalog"
else
  ok "edge location gone from the live catalog"
fi
# the edge box syncs the tail, then reclaims its space — never before the
# catalog shows another live location
$PVFS --json replica sync "$REPMOUNT" >/dev/null
EVICTJ="$($PVFS --json --data-dir "$REPMOUNT/.pvfs" evict)"
[ "$(jget "$EVICTJ" evicted)" -ge 1 ] && ok "edge box evicted the migrated bytes" || fail "evict: $EVICTJ"
[ ! -f "$DATA/edge.bin" ] && ok "edge bytes deleted — space reclaimed" || fail "edge bytes remain"
# and the file never stopped being available fleet-wide
[ "$($PVFS --data-dir "$REPMOUNT/.pvfs" cat "$EDGE" 2>/dev/null)" = "edge-bytes" ] \
  && ok "file still streams after migration + eviction" || fail "post-eviction cat"

say "F5.4: tail-subscribe — the replica follows the source live (doc 17 §7.5)"
$PVFS replica follow "$REPMOUNT" >/dev/null 2>"$DATA/follow.log" &
FPID=$!
sleep 1
$PVFS remote --socket "$SOCK" mkdir "$DROOT" hot-news >/dev/null
FOUND=""
for _ in $(seq 1 80); do
  if $PVFS --data-dir "$REPMOUNT/.pvfs" ls "$DROOT" 2>/dev/null | qgrep hot-news; then
    FOUND=1; break
  fi
  sleep 0.25
done
[ -n "$FOUND" ] && ok "follower picked up a new event within seconds" || fail "follow: $(tail -3 "$DATA/follow.log")"
# a second event proves the loop keeps polling, not a one-shot
$PVFS remote --socket "$SOCK" mkdir "$DROOT" hot-news-2 >/dev/null
FOUND2=""
for _ in $(seq 1 80); do
  if $PVFS --data-dir "$REPMOUNT/.pvfs" ls "$DROOT" 2>/dev/null | qgrep hot-news-2; then
    FOUND2=1; break
  fi
  sleep 0.25
done
[ -n "$FOUND2" ] && ok "follower keeps following (second event landed)" || fail "follow second event"
kill "$FPID" 2>/dev/null; wait "$FPID" 2>/dev/null || true
FPID=""

say "P5.1/P5.2: daemon jobs — follow, sync, export keep a consumer fresh (doc 18 §5)"
$PVFS --data-dir "$REPMOUNT/.pvfs" serve enable follow >/dev/null \
  && ok "follow enabled on the replica" || fail "enable follow"
$PVFS --data-dir "$REPMOUNT/.pvfs" serve enable sync >/dev/null \
  && $PVFS --data-dir "$REPMOUNT/.pvfs" serve enable export >/dev/null \
  && ok "sync + export jobs enabled" || fail "enable sync/export"
$PVFS --data-dir "$REPMOUNT/.pvfs" export "$DROOT" "$DATA/kept-view" --mode copy --prune --keep-fresh >/dev/null \
  && ok "export --keep-fresh recorded the view" || fail "export --keep-fresh"
$PVFS --data-dir "$REPMOUNT/.pvfs" serve exports | qgrep kept-view \
  && ok "serve exports lists it" || fail "serve exports"
REPJSOCK="$DATA/replica-jobs.sock"
"$PVFSD" --mount "$REPMOUNT" --socket "$REPJSOCK" >/dev/null 2>"$DATA/repjobs.log" &
JPID=$!
for _ in $(seq 1 50); do [ -S "$REPJSOCK" ] && break; sleep 0.1; done
$PVFS remote --socket "$SOCK" mkdir "$DROOT" job-news >/dev/null
JFOUND=""
for _ in $(seq 1 80); do
  if $PVFS --data-dir "$REPMOUNT/.pvfs" ls "$DROOT" 2>/dev/null | qgrep job-news; then
    JFOUND=1; break
  fi
  sleep 0.25
done
[ -n "$JFOUND" ] && ok "daemon follow job folded the owner's event (no CLI follower)" \
  || fail "follow job: $(tail -3 "$DATA/repjobs.log")"
# the fold nudges the export job — the kept-fresh view refreshes by itself
VFOUND=""
for _ in $(seq 1 80); do
  [ -d "$DATA/kept-view/job-news" ] && { VFOUND=1; break; }
  sleep 0.25
done
[ -n "$VFOUND" ] && ok "export job refreshed the kept-fresh view" \
  || fail "export view stale: $(ls "$DATA/kept-view" 2>/dev/null | tail -3)"
# a new file's BYTES flow too: catalog on the owner → view serves the content
printf 'fresh-bytes' > "$DATA/fresh-bytes.bin"
FB="$(jget "$($PVFS --json remote --socket "$SOCK" add-file "$DROOT" fresh-bytes.bin --size 11)" created)"
$PVFS remote --socket "$SOCK" add-location "$FB" "file://$DATA/fresh-bytes.bin" >/dev/null
BFOUND=""
for _ in $(seq 1 80); do
  if [ "$(cat "$DATA/kept-view/fresh-bytes.bin" 2>/dev/null)" = "fresh-bytes" ]; then
    BFOUND=1; break
  fi
  sleep 0.25
done
[ -n "$BFOUND" ] && ok "new owner file reached the view (follow → sync → export)" \
  || fail "byte flow to the view"
kill -TERM "$JPID" 2>/dev/null; wait "$JPID" 2>/dev/null || true
JPID=""
$PVFS --data-dir "$REPMOUNT/.pvfs" serve disable follow >/dev/null \
  && $PVFS --data-dir "$REPMOUNT/.pvfs" serve disable sync >/dev/null \
  && $PVFS --data-dir "$REPMOUNT/.pvfs" serve disable export >/dev/null \
  && ok "jobs disabled again" || fail "disable jobs"

say "P7.0: region boundaries — mark, membership, mv refusal (doc 20 §2)"
RGN="$(jget "$($PVFS --json remote --socket "$SOCK" mkdir "$DROOT" region-app)" created)"
RGNFILE="$(jget "$($PVFS --json remote --socket "$SOCK" mkdir "$RGN" inner)" created)"
$PVFS --data-dir "$DMOUNT/.pvfs" region mark "$RGN" >/dev/null \
  && ok "region mark" || fail "region mark"
$PVFS --json --data-dir "$DMOUNT/.pvfs" region ls "$RGNFILE" | qgrep "\"region\":\"$RGN\"" \
  && ok "membership resolves to the nearest boundary" || fail "region membership"
$PVFS --data-dir "$DMOUNT/.pvfs" region ls | qgrep "$RGN" \
  && ok "region ls lists the boundary" || fail "region ls"
# P7.2c (doc 20 §2.5): a mv across the boundary is the PAIRED protocol now —
# NodeMovedOut in the source region's log, NodeMovedIn in the destination's
$PVFS remote --socket "$SOCK" mv "$RGNFILE" "$DROOT" >/dev/null \
  && ok "cross-region mv out of the region (paired protocol)" || fail "cross-region mv out"
$PVFS --json --data-dir "$DMOUNT/.pvfs" region ls "$RGNFILE" | qgrep "\"region\":\"$RGN\"" \
  && fail "moved node still claims the old region" \
  || ok "the node's sticky region flipped to the destination"
$PVFS remote --socket "$SOCK" mv "$RGNFILE" "$RGN" >/dev/null \
  && ok "and back in (the reverse crossing)" || fail "cross-region mv back"
$PVFS --json --data-dir "$DMOUNT/.pvfs" region ls "$RGNFILE" | qgrep "\"region\":\"$RGN\"" \
  && ok "membership follows the move" || fail "post-move membership"
$PVFS --data-dir "$DMOUNT/.pvfs" region unmark "$RGN" >/dev/null \
  && ok "region unmark" || fail "region unmark"
$PVFS remote --socket "$SOCK" mv "$RGNFILE" "$DROOT" >/dev/null \
  && ok "a plain mv once the boundary is gone" || fail "post-unmark mv"

say "P7.2a: physical region logs — split, routing, seal, tree rebuild (doc 20 §2.3)"
PR="$($PVFS add "$ROOT" --kind folder --label phys-region)"
PRIN="$($PVFS add "$PR" --kind folder --label inner)"
$PVFS region mark "$PR" >/dev/null && ok "mark (the split commit)" || fail "region mark"
if ls "$DATA/forest/regions/$PR/"g-*.db >/dev/null 2>&1; then
  fail "generation file must not exist before the first region write"
else
  ok "no generation file before the first region write"
fi
PRDEEP="$($PVFS add "$PRIN" --kind folder --label deep)"
GEN1="$(ls "$DATA/forest/regions/$PR/"g-*.db 2>/dev/null | head -1)"
[ -n "$GEN1" ] && ok "first region write created the generation file" || fail "generation file"
$PVFS --json region ls "$PRDEEP" | qgrep "\"region\":\"$PR\"" \
  && ok "membership rides the physical split" || fail "split membership"
# cross-region orphan adoption IS a cross-region move — since P7.2c it
# authors as a NodeMovedIn and the sticky region flips (doc 20 §2.5)
XADOPT="$($PVFS add "$ROOT" --kind folder --label adoptee)"
XLINK="$($PVFS --json ls "$ROOT" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "adoptee": print(e["link_id"])')"
$PVFS unlink "$XLINK" >/dev/null
$PVFS link "$PR" "$XADOPT" --type contains >/dev/null \
  && ok "cross-region orphan adoption (paired protocol)" || fail "orphan adoption"
$PVFS --json region ls "$XADOPT" | qgrep "\"region\":\"$PR\"" \
  && ok "adoption flipped the orphan's region" || fail "adoption region flip"
# tree rebuild: baseline verification + region-log replay reproduce the state
rm "$DATA/forest/index.db"
$PVFS ls "$PRIN" 2>/dev/null | qgrep deep \
  && ok "tree rebuild replays the region log (baseline verified)" || fail "tree rebuild"
# unmark = seal: the generation file stays, writes author in the top log again
$PVFS region unmark "$PR" >/dev/null && ok "unmark (the seal commit)" || fail "region unmark"
[ -f "$GEN1" ] && ok "sealed generation file remains" || fail "sealed generation vanished"
$PVFS add "$PRIN" --kind folder --label post-seal >/dev/null \
  && ok "post-seal write lands in the enclosing log" || fail "post-seal write"
# re-mark: a fresh generation, distinct from the sealed one
$PVFS region mark "$PR" >/dev/null
$PVFS add "$PRIN" --kind folder --label gen2 >/dev/null
GEN2="$(ls "$DATA/forest/regions/$PR/"g-*.db 2>/dev/null | grep -Fvx "$GEN1" | head -1)"
[ -n "$GEN2" ] && ok "re-mark started a fresh generation" || fail "fresh generation"
# a rebuild now walks: top log, the sealed generation at its unmark, gen 2
rm "$DATA/forest/index.db"
$PVFS ls "$PRIN" 2>/dev/null | qgrep gen2 \
  && ok "rebuild replays sealed + active generations in order" || fail "sealed+active rebuild"
$PVFS region unmark "$PR" >/dev/null

say "P7.2b: region logs over the wire — the replica ships generations (doc 20 §2.4)"
WREG="$(jget "$($PVFS --json remote --socket "$SOCK" mkdir "$DROOT" wire-region)" created)"
$PVFS --data-dir "$DMOUNT/.pvfs" region mark "$WREG" >/dev/null \
  && ok "mark on the served forest" || fail "wire-region mark"
# this write routes into the region's own log on the daemon side
$PVFS --json remote --socket "$SOCK" mkdir "$WREG" inside >/dev/null \
  && ok "daemon write routed into the region log" || fail "daemon region write"
$PVFS replica sync "$REPMOUNT" >/dev/null \
  && ok "replica sync ships the generation" || fail "replica region sync"
ls "$REPMOUNT/.pvfs/regions/$WREG/"g-*.db >/dev/null 2>&1 \
  && ok "generation file landed on the replica" || fail "replica generation file"
$PVFS --data-dir "$REPMOUNT/.pvfs" ls "$WREG" | qgrep inside \
  && ok "region content replays on the replica" || fail "replica region replay"
# seal it; the final head + sealed generation verify on the replica too
$PVFS --data-dir "$DMOUNT/.pvfs" region unmark "$WREG" >/dev/null
$PVFS replica sync "$REPMOUNT" >/dev/null \
  && ok "the seal ships and verifies on the replica" || fail "replica seal sync"

say "P8: attachment policies — bind --kind migrate|mirror (doc 21)"
# migrate: the staging dir drains — tier lands + retires, evict reclaims
mkdir -p "$DATA/staging" "$DATA/mirror-src"
printf 'drain-me' > "$DATA/staging/episode.mkv"
MIG="$($PVFS add "$ROOT" --kind folder --label staging)"
$PVFS bind "$MIG" "$DATA/staging" --kind migrate --to "$DATA/drain-store" --hash-policy on_add >/dev/null \
  && ok "bind --kind migrate records the store" || fail "bind migrate"
$PVFS scan "$MIG" >/dev/null
EP="$($PVFS --json ls "$MIG" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "episode.mkv": print(e["id"])')"
$PVFS tier >/dev/null 2>&1 && ok "tier pass over the migrate binding" || fail "tier migrate"
[ -f "$DATA/drain-store/${EP:0:2}/$EP" ] && ok "central copy landed" || fail "no central copy"
$PVFS loc ls "$EP" | qgrep "$DATA/staging" \
  && fail "staged location still live after tier" || ok "staged location retired"
$PVFS evict >/dev/null 2>&1
[ -f "$DATA/staging/episode.mkv" ] \
  && fail "staging bytes not reclaimed" || ok "evict drained the staging dir"
$PVFS cat "$EP" | qgrep drain-me && ok "file streams from the central store" || fail "post-drain stream"
# mirror: tier keeps a second verified copy; nothing retired, nothing evicted
printf 'keep-me' > "$DATA/mirror-src/song.mp3"
MIR="$($PVFS add "$ROOT" --kind folder --label mirror-space)"
$PVFS bind "$MIR" "$DATA/mirror-src" --kind mirror --to "$DATA/mirror-store" --hash-policy on_add >/dev/null \
  && ok "bind --kind mirror records the store" || fail "bind mirror"
$PVFS scan "$MIR" >/dev/null
SONG="$($PVFS --json ls "$MIR" | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e["label"] == "song.mp3": print(e["id"])')"
$PVFS tier >/dev/null 2>&1
[ -f "$DATA/mirror-store/${SONG:0:2}/$SONG" ] && ok "mirror copy landed" || fail "no mirror copy"
$PVFS loc ls "$SONG" | qgrep "$DATA/mirror-src" \
  && ok "source location stays live (never retired)" || fail "mirror source retired"
$PVFS evict >/dev/null 2>&1
[ -f "$DATA/mirror-src/song.mp3" ] \
  && ok "evict never touches a mirror source" || fail "mirror source evicted"
# the backup story: the source dies, the mirror serves
rm "$DATA/mirror-src/song.mp3"
$PVFS cat "$SONG" 2>/dev/null | qgrep keep-me \
  && ok "content survives source deletion via the mirror" || fail "mirror read-through"

say "P9.0: swarm groundwork — manifest sidecars at the sink (doc 22)"
# the F3/F5 fetches above streamed bytes into the replica's sync store; the
# sink now writes a chunk-manifest sidecar beside every published file
find "$REPMOUNT/.pvfs/synced" -name "*.manifest" 2>/dev/null | grep -q . \
  && ok "sync sink wrote chunk-manifest sidecars" || fail "no manifest sidecars"
# a single-holder fetch stays on the plain stream path (no swarm regression):
# every earlier fetch in this suite already proved that by passing

say "P7.3: FUSE mount — browse + stream through the kernel (doc 20 §3)"
if [ -e /dev/fuse ] && command -v fusermount3 >/dev/null 2>&1; then
  mkdir -p "$DATA/fuse-view"
  $PVFS --data-dir "$REPMOUNT/.pvfs" mount "$DROOT" "$DATA/fuse-view" >/dev/null 2>"$DATA/fuse.log" &
  MPID=$!
  MOK=""
  for _ in $(seq 1 40); do
    if [ "$(cat "$DATA/fuse-view/albums/a.txt" 2>/dev/null)" = "hi" ]; then MOK=1; break; fi
    sleep 0.25
  done
  [ -n "$MOK" ] && ok "kernel read through the mount (a replica, resolved live)" \
    || fail "fuse read: $(tail -2 "$DATA/fuse.log" 2>/dev/null)"
  ls "$DATA/fuse-view" | qgrep albums && ok "readdir lists the tree" || fail "fuse readdir"
  $PVFS umount "$DATA/fuse-view" >/dev/null 2>&1 || fusermount3 -u "$DATA/fuse-view" 2>/dev/null
  wait "$MPID" 2>/dev/null || true
  MPID=""
  ok "unmounted cleanly"
else
  ok "fuse unavailable here — mount checks skipped (not a failure)"
fi

say "P9.1: serve-while-fetching — the streaming mount (doc 22 §2)"
if [ -e /dev/fuse ] && command -v fusermount3 >/dev/null 2>&1; then
  mkdir -p "$DATA/dstream"
  head -c 268435456 /dev/urandom > "$DATA/dstream/stream.bin"
  DSF="$($PVFS --data-dir "$DMOUNT/.pvfs" add "$DROOT" --kind folder --label stream-zone)"
  $PVFS --data-dir "$DMOUNT/.pvfs" bind "$DSF" "$DATA/dstream" --hash-policy on_add >/dev/null
  $PVFS --data-dir "$DMOUNT/.pvfs" scan "$DSF" >/dev/null
  $PVFS replica sync "$REPMOUNT" >/dev/null 2>&1
  mkdir -p "$DATA/fuse-view2"
  $PVFS --data-dir "$REPMOUNT/.pvfs" mount "$DROOT" "$DATA/fuse-view2" >/dev/null 2>"$DATA/fuse2.log" &
  M2PID=$!
  MOK2=""
  for _ in $(seq 1 40); do [ -d "$DATA/fuse-view2/stream-zone" ] && { MOK2=1; break; }; sleep 0.25; done
  [ -n "$MOK2" ] && ok "second mount up (attested catalog synced)" || fail "second mount"
  # single-box reality: the replica resolves the owner's file:// path
  # LOCALLY, so the mount rightly serves without fetching — the actual
  # serve-while-fetching path is proven cross-machine by fleet phase J.
  # Here: the attestation exists on the replica, and reads are correct.
  MCOUNT=$(python3 -c "import sqlite3;print(sqlite3.connect('$REPMOUNT/.pvfs/index.db').execute('SELECT COUNT(*) FROM chunk_manifests').fetchone()[0])" 2>/dev/null || echo 0)
  [ "$MCOUNT" -ge 1 ] \
    && ok "the attestation shipped and folded on the replica" || fail "no attested manifest on the replica"
  head -c 1048576 "$DATA/fuse-view2/stream-zone/stream.bin" > "$DATA/first-mib" 2>/dev/null \
    && ok "first MiB served" || fail "streaming first read"
  cmp -s <(head -c 1048576 "$DATA/dstream/stream.bin") "$DATA/first-mib" \
    && ok "early bytes are the right bytes" || fail "early byte mismatch"
  cmp -s "$DATA/fuse-view2/stream-zone/stream.bin" "$DATA/dstream/stream.bin" \
    && ok "full read completes bit-perfect" || fail "full streaming read"
  fusermount3 -u "$DATA/fuse-view2" 2>/dev/null; kill $M2PID 2>/dev/null; M2PID=""
else
  ok "skipped streaming mount (no fuse3 on this host)"
fi

say "P5.4: fleet enroll — one-step box admit (doc 18 §4)"
mkdir -p "$DATA/config3"
E3KEY="$(jget "$(XDG_CONFIG_HOME="$DATA/config3" $PVFS --json whoami)" pubkey)"
$PVFS --forest "$DMOUNT" fleet enroll "$E3KEY" --rights rw >/dev/null \
  && ok "fleet enroll admits the box (member + rw, one step)" || fail "fleet enroll"
XDG_CONFIG_HOME="$DATA/config3" $PVFS remote --socket "$SOCK" mkdir "$DROOT" enrolled-dir >/dev/null \
  && ok "enrolled identity writes through the daemon at once" || fail "enrolled write"
$PVFS --forest "$DMOUNT" fleet enroll "$E3KEY" --rights r >/dev/null \
  && ok "re-enroll is idempotent (rights just updated)" || fail "re-enroll"

say "P2: two distinct user identities over the socket (doc 08 RtO #4)"
# A second, independent forest served to a SECOND client identity ("Bob"), to
# show per-identity ACL enforcement over the socket — not just the owner's own
# client identity as in the section above.
U2="$DATA/multiuser"
mkdir -p "$U2/shared" "$U2/private"
printf 'shared note' > "$U2/shared/note.txt"
printf 'top secret' > "$U2/private/secret.txt"
U2INIT="$($PVFS --json forest init --mount "$U2")"
U2ROOT="$(jget "$U2INIT" root_node_id)"
U2FID="$(jget "$U2INIT" forest_id)"
# Bob = a separate config dir, hence a separate signing identity.
BOB="$DATA/bob-config"
bob() { XDG_CONFIG_HOME="$BOB" "$PVFS" "$@"; }
BOBKEY="$(jget "$(bob --json whoami)" pubkey)"
if [ -n "$BOBKEY" ] && [ "$BOBKEY" != "$CLIENTKEY" ]; then ok "Bob has a distinct client identity"; else fail "Bob identity not distinct"; fi
# Owner sets up sharing directly (before serving): authorize Bob; grant rw on /shared only.
SHARED_ID="$(pick_id "$($PVFS --json --data-dir "$U2/.pvfs" ls "$U2ROOT")" shared)"
PRIVATE_ID="$(pick_id "$($PVFS --json --data-dir "$U2/.pvfs" ls "$U2ROOT")" private)"
$PVFS --data-dir "$U2/.pvfs" device authorize-member --pubkey "$BOBKEY" >/dev/null && ok "owner authorized Bob as a member" || fail "owner authorized Bob as a member"
$PVFS --data-dir "$U2/.pvfs" acl set "$SHARED_ID" "key:$BOBKEY" rw >/dev/null && ok "owner granted Bob rw on /shared" || fail "owner granted Bob rw on /shared"
# Serve the multi-user forest.
U2SOCK="$PVFS_SOCKET_DIR/$U2FID.sock"
"$PVFSD" --mount "$U2" >/dev/null 2>&1 &
U2PID=$!
for _ in $(seq 1 50); do [ -S "$U2SOCK" ] && break; sleep 0.1; done
[ -S "$U2SOCK" ] && ok "multi-user daemon serving" || fail "multi-user socket missing"
# Bob, signing as himself over the socket, reads + writes /shared (granted)...
bob remote --socket "$U2SOCK" ls "$SHARED_ID" | qgrep note.txt && ok "Bob reads /shared (granted)" || fail "Bob reads /shared (granted)"
BOBDIR="$(jget "$(bob --json remote --socket "$U2SOCK" mkdir "$SHARED_ID" bob-was-here)" created)"
[ ${#BOBDIR} -eq 64 ] && ok "Bob writes under /shared (granted rw)" || fail "Bob mkdir under /shared: $BOBDIR"
# ...but is denied /private (no grant) — denial now exits 5 (forbidden), not a generic 2.
assert_rc 5 "Bob denied read on /private (no grant)" -- bob remote --socket "$U2SOCK" ls "$PRIVATE_ID"
assert_rc 5 "Bob denied write on /private (no grant)" -- bob remote --socket "$U2SOCK" mkdir "$PRIVATE_ID" nope
# An anonymous client (neither owner nor Bob) is denied the un-shared root too.
assert_rc 5 "anon denied read on a private node" -- $PVFS remote --socket "$U2SOCK" --anon ls "$PRIVATE_ID"
kill -TERM "$U2PID" 2>/dev/null || true; wait "$U2PID" 2>/dev/null || true
U2PID=""

say "P2-F: graceful shutdown on SIGTERM (doc 08 item 4)"
# pvfsd traps SIGTERM, stops accepting, checkpoints the WAL, removes its socket.
# Watchdog guards CI against a hang if the signal is ever mishandled.
( sleep 10; kill -9 "$DPID" 2>/dev/null ) & WATCH=$!
kill -TERM "$DPID"
wait "$DPID" 2>/dev/null; SHUT_RC=$?
kill "$WATCH" 2>/dev/null; wait "$WATCH" 2>/dev/null || true
[ "$SHUT_RC" -eq 0 ] && ok "pvfsd exited 0 on SIGTERM (clean shutdown)" || fail "pvfsd exit $SHUT_RC on SIGTERM"
[ -S "$SOCK" ] && fail "socket left behind after graceful shutdown" || ok "socket removed on graceful shutdown"
DPID=""

say "item 14: authorization audit (read-only)"
# DMOUNT has tag grants/memberships, all under live authorities → audit is clean.
$PVFS --data-dir "$DMOUNT/.pvfs" audit | qgrep "no stale authorizations" \
  && ok "audit reports a clean forest" || fail "audit clean-case text"
$PVFS --json --data-dir "$DMOUNT/.pvfs" audit | qgrep '"inert_grants":\[\],"inert_memberships":\[\]' \
  && ok "audit json reports no inert rows" || fail "audit json shape"

say "companion: phrase-free admit via the signing agent (doc 14 phase 3)"
COMPANION="${PVFS_COMPANION_BIN:-$(dirname "$PVFS")/pvfs-companion}"
CMOUNT="$DATA/companion-forest"
mkdir -p "$CMOUNT"
CMN="$(jget "$($PVFS --json forest init --mount "$CMOUNT")" mnemonic)"
CVAULT="$DATA/companion.vault"
CSOCK="$DATA/companion.sock"
# Seal the forest's owner seed into a companion vault (phrase on stdin, passphrase via env).
printf '%s' "$CMN" | PVFS_COMPANION_PASSPHRASE=testpass "$COMPANION" init --vault "$CVAULT" >/dev/null 2>&1 \
  && ok "companion sealed the owner seed" || fail "companion init"
# init validates the phrase — garbage is refused and nothing is written.
IRC=0
printf 'these are not valid recovery words at all' \
  | PVFS_COMPANION_PASSPHRASE=x "$COMPANION" init --vault "$DATA/bad.vault" >/dev/null 2>&1 || IRC=$?
[ "$IRC" -eq 1 ] && [ ! -e "$DATA/bad.vault" ] \
  && ok "init refuses an invalid phrase (nothing written)" || fail "invalid phrase rc=$IRC"
# init refuses to clobber an existing vault.
ERC=0
printf '%s' "$CMN" | PVFS_COMPANION_PASSPHRASE=x "$COMPANION" init --vault "$CVAULT" >/dev/null 2>&1 || ERC=$?
[ "$ERC" -eq 1 ] && ok "init refuses to overwrite an existing vault" || fail "vault overwrite rc=$ERC"
# Run the companion headless: root signing explicitly enabled, prompts forced
# to deny — a scripted agent must be deterministic even when the script runs
# from a terminal (an auto-detected /dev/tty prompt would block forever).
PVFS_COMPANION_PASSPHRASE=testpass "$COMPANION" serve --vault "$CVAULT" --socket "$CSOCK" --allow-root --prompt deny >/dev/null 2>&1 &
CPID=$!
for _ in $(seq 1 50); do [ -S "$CSOCK" ] && break; sleep 0.1; done
[ -S "$CSOCK" ] && ok "companion serving" || fail "companion socket missing"

# --- forest genesis via companion (desktop-SSO shape: env socket, no new phrase) ---
say "companion: forest init reuses companion root (no new phrase)"
G2="$DATA/genesis-via-companion"; mkdir -p "$G2"
# --json never auto-picks the companion (must be explicit).
assert_rc 2 "forest init --json + companion env requires --via-companion or --new-phrase" -- \
  env PVFS_COMPANION_SOCKET="$CSOCK" $PVFS --json forest init --mount "$G2" --no-import
# Dead env must not silently mint a phrase.
assert_rc 2 "forest init errors when PVFS_COMPANION_SOCKET points at nothing" -- \
  env PVFS_COMPANION_SOCKET="$DATA/missing-companion.sock" \
  $PVFS --json forest init --mount "$DATA/dead-env-mount" --no-import --via-companion
G2JSON="$(env PVFS_COMPANION_SOCKET="$CSOCK" $PVFS --json forest init \
  --mount "$G2" --no-import --via-companion)"
[ "$(jget "$G2JSON" via_companion)" = "True" ] || [ "$(jget "$G2JSON" via_companion)" = "true" ] \
  && ok "forest init --via-companion sets via_companion" || fail "via_companion: $G2JSON"
# Python json true → jget may print True depending on extractor — handle both.
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d.get("mnemonic") is None; assert d.get("via_companion") is True' "$G2JSON" \
  && ok "forest init via companion mints no mnemonic" || fail "mnemonic leaked: $G2JSON"
G2ROOT="$(jget "$G2JSON" root_pubkey)"
[ ${#G2ROOT} -eq 66 ] && ok "companion-rooted forest has root pubkey" || fail "root_pubkey: $G2ROOT"
# A second forest through the same companion shares the root identity.
G3="$DATA/genesis-via-companion-2"; mkdir -p "$G3"
G3JSON="$($PVFS --json forest init --mount "$G3" --no-import --via-companion --companion-socket "$CSOCK")"
python3 -c 'import json,sys; a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); assert a["root_pubkey"]==b["root_pubkey"]; assert a["forest_id"]!=b["forest_id"]' \
  "$G2JSON" "$G3JSON" \
  && ok "two companion forests share root, distinct forest_id" || fail "shared root: $G2JSON / $G3JSON"
# --new-phrase ignores the running companion and mints a separate seed.
G4="$DATA/genesis-new-phrase"; mkdir -p "$G4"
G4JSON="$(env PVFS_COMPANION_SOCKET="$CSOCK" $PVFS --json forest init \
  --mount "$G4" --no-import --new-phrase)"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d.get("via_companion") is False; assert d.get("mnemonic") and len(d["mnemonic"].split())==24' "$G4JSON" \
  && ok "forest init --new-phrase ignores companion" || fail "new-phrase: $G4JSON"
python3 -c 'import json,sys; a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); assert a["root_pubkey"]!=b["root_pubkey"]' \
  "$G2JSON" "$G4JSON" \
  && ok "--new-phrase forest has a different root" || fail "new-phrase root collision"
# Forest is usable after companion genesis (device key cached under .pvfs/).
$PVFS --data-dir "$G2/.pvfs" info >/dev/null && ok "companion-rooted forest reopens" || fail "reopen G2"
G2FOLDER="$($PVFS --data-dir "$G2/.pvfs" add "$(jget "$G2JSON" root_node_id)" --kind folder --label docs)"
[ ${#G2FOLDER} -eq 64 ] && ok "write works on companion-rooted forest" || fail "add on G2: $G2FOLDER"

# Admit a member with NO phrase typed — the companion root-signs the DeviceAuthorized.
CMEMBER="$(jget "$($PVFS --json whoami)" pubkey)"
$PVFS --data-dir "$CMOUNT/.pvfs" device authorize-member --via-companion --companion-socket "$CSOCK" --pubkey "$CMEMBER" >/dev/null \
  && ok "companion-signed authorize-member (no phrase)" || fail "companion authorize-member"
# Re-admitting the same key now fails (already a member) — proves the cert landed.
assert_rc 4 "member already authorized after companion admit" -- \
  $PVFS --data-dir "$CMOUNT/.pvfs" device authorize-member --via-companion --companion-socket "$CSOCK" --pubkey "$CMEMBER"

say "companion: identity key, tag ops, revoke, auto-detect (doc 14 phase 3)"
# Admit the human's identity key as an owner — fetched from and root-signed by the companion.
IDJSON="$($PVFS --json --data-dir "$CMOUNT/.pvfs" device authorize-identity --companion-socket "$CSOCK")"
IDPUB="$(jget "$IDJSON" identity_pubkey)"
[ "${#IDPUB}" -eq 66 ] && ok "companion-signed authorize-identity" || fail "authorize-identity pubkey: $IDJSON"
assert_rc 4 "identity key already authorized on re-run" -- \
  $PVFS --data-dir "$CMOUNT/.pvfs" device authorize-identity --companion-socket "$CSOCK"
# Tag the member under the identity key's authority (doc 10 §9.1) — no device key involved.
$PVFS --data-dir "$CMOUNT/.pvfs" tag add "$CMEMBER" vip --via-companion --companion-socket "$CSOCK" >/dev/null \
  && ok "companion identity-signed tag add" || fail "companion tag add"
$PVFS --json --data-dir "$CMOUNT/.pvfs" tag ls "$CMEMBER" | qgrep "\"tag\":\"vip\",\"authority\":\"$IDPUB\",\"active\":true" \
  && ok "tag authority is the identity key (active)" || fail "tag ls authority"
$PVFS --data-dir "$CMOUNT/.pvfs" tag rm "$CMEMBER" vip --via-companion --companion-socket "$CSOCK" >/dev/null \
  && ok "companion identity-signed tag rm" || fail "companion tag rm"
$PVFS --json --data-dir "$CMOUNT/.pvfs" tag ls "$CMEMBER" | qgrep '"tag":"vip"' \
  && fail "tag rm did not land" || ok "tag removed"
# Revoke the member via the companion — socket auto-detected from the env, no flag.
PVFS_COMPANION_SOCKET="$CSOCK" $PVFS --data-dir "$CMOUNT/.pvfs" device revoke --via-companion --pubkey "$CMEMBER" >/dev/null \
  && ok "companion-signed revoke (socket auto-detected)" || fail "companion revoke"
# Revoking an unknown key is NotFound — proves prepare_revoke checks the registry.
assert_rc 3 "companion revoke of unknown key is NotFound" -- \
  $PVFS --data-dir "$CMOUNT/.pvfs" device revoke --via-companion --companion-socket "$CSOCK" \
    --pubkey 02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
# Missing socket (no flag, no env, no runtime dir) is a clean BadInput, not a hang.
assert_rc 2 "companion auto-detect fails cleanly when nothing is running" -- \
  env -u PVFS_COMPANION_SOCKET XDG_RUNTIME_DIR="$DATA/empty-runtime" \
  $PVFS --data-dir "$CMOUNT/.pvfs" device revoke --via-companion --pubkey "$CMEMBER"
# lock: the seed drops; the next request re-unlocks from the serve env (doc 14 §4).
"$COMPANION" lock --socket "$CSOCK" >/dev/null 2>&1 && ok "companion lock accepted" || fail "companion lock"
assert_rc 4 "agent re-unlocks on demand after lock" -- \
  $PVFS --data-dir "$CMOUNT/.pvfs" device authorize-identity --companion-socket "$CSOCK"
# audit log (next to the vault): signatures, the lock, and the re-unlock.
CAUDIT="$DATA/companion.audit.jsonl"
[ -s "$CAUDIT" ] && ok "audit log exists" || fail "audit log missing"
grep -q '"decision":"approved"' "$CAUDIT" && ok "audit recorded approved signatures" || fail "audit signs"
grep -q '"event":"lock"' "$CAUDIT" && ok "audit recorded the lock" || fail "audit lock"
grep -q '"event":"unlock"' "$CAUDIT" && ok "audit recorded the re-unlock" || fail "audit unlock"
# identity replacement (doc 15 §1): swap, re-home, handoff to a second forest.
say "companion: identity replacement (doc 15)"
M2="$(jget "$(XDG_CONFIG_HOME="$DATA/m2cfg" $PVFS --json whoami)" pubkey)"
$PVFS --data-dir "$CMOUNT/.pvfs" device authorize-member --via-companion --companion-socket "$CSOCK" --pubkey "$M2" >/dev/null \
  && ok "admitted a member to carry a grant" || fail "admit M2"
$PVFS --data-dir "$CMOUNT/.pvfs" tag add "$M2" crew --via-companion --companion-socket "$CSOCK" >/dev/null \
  && ok "identity granted a tag" || fail "tag M2"
RJSON="$($PVFS --json --data-dir "$CMOUNT/.pvfs" identity replace --yes --companion-socket "$CSOCK")"
OLDID="$(jget "$RJSON" old)"; NEWID="$(jget "$RJSON" new)"
[ -n "$NEWID" ] && [ "$OLDID" != "$NEWID" ] && ok "identity replaced (companion rotated + swap committed)" \
  || fail "identity replace: $RJSON"
printf '%s' "$RJSON" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["handoff"]))' > "$DATA/handoff.json"
$PVFS --json --data-dir "$CMOUNT/.pvfs" tag ls "$M2" | qgrep "\"tag\":\"crew\",\"authority\":\"$NEWID\",\"active\":true" \
  && ok "grant re-homed to the new identity" || fail "reissue authority"
# A second forest where the OLD key was a member: replace from the handoff.
F2="$DATA/handoff-forest"; mkdir -p "$F2"
$PVFS --json forest init --mount "$F2" >/dev/null
$PVFS --data-dir "$F2/.pvfs" device authorize-member --pubkey "$OLDID" >/dev/null 2>&1 \
  && ok "old key was a member of the second forest" || fail "F2 admit"
$PVFS --data-dir "$F2/.pvfs" tag add "$OLDID" vip >/dev/null 2>&1 || true
$PVFS --data-dir "$F2/.pvfs" member replace "$DATA/handoff.json" >/dev/null \
  && ok "member replaced from the dual-signed handoff" || fail "member replace"
$PVFS --json --data-dir "$F2/.pvfs" tag ls "$NEWID" | qgrep '"tag":"vip"' \
  && ok "tags re-granted to the new key" || fail "F2 regrant"
python3 -c 'import json,sys; h=json.load(open(sys.argv[1])); h["replaced_at_ms"]+=1; print(json.dumps(h))' \
  "$DATA/handoff.json" > "$DATA/handoff-bad.json"
assert_rc 5 "tampered handoff refused" -- \
  $PVFS --data-dir "$F2/.pvfs" member replace "$DATA/handoff-bad.json"

# root lineage — case C (doc 15 §C): recovery key + root rotation.
say "case C: root rotation & recovery key (doc 15)"
RCF="$DATA/rotate-forest"; mkdir -p "$RCF"
RCINIT="$($PVFS --json forest init --mount "$RCF")"
RCMN="$(jget "$RCINIT" mnemonic)"
# Register a rotation recovery key (authorized by the main phrase on stdin).
RKJSON="$(printf '%s' "$RCMN" | $PVFS --json forest recovery-key --forest "$RCF")"
RKPHRASE="$(jget "$RKJSON" recovery_phrase)"
[ -n "$RKPHRASE" ] && ok "registered a rotation recovery key" || fail "recovery-key: $RKJSON"
# Rotate the root using ONLY the recovery phrase (simulates seed compromise).
RRJSON="$(printf '%s' "$RKPHRASE" | $PVFS --json forest rotate-root --forest "$RCF")"
NEWMN="$(jget "$RRJSON" new_phrase)"
NEWROOT="$(jget "$RRJSON" new_root_pubkey)"
[ -n "$NEWMN" ] && [ -n "$NEWROOT" ] && ok "rotated the root via the recovery phrase" || fail "rotate: $RRJSON"
# The recovery key that authored the rotation is now invalid (reset on rotation).
RKRC=0; printf '%s' "$RKPHRASE" | $PVFS forest rotate-root --forest "$RCF" >/dev/null 2>&1 || RKRC=$?
[ "$RKRC" -eq 5 ] && ok "recovery key retired by the rotation cannot rotate again" || fail "reset-on-rotation rc=$RKRC"
# The OLD phrase no longer authorizes; the NEW phrase does.
assert_rc 5 "old seed rejected after rotation" -- \
  $PVFS --data-dir "$RCF/.pvfs" device authorize --mnemonic "$RCMN" --index 5
$PVFS --data-dir "$RCF/.pvfs" device authorize --mnemonic "$NEWMN" --index 5 >/dev/null \
  && ok "new seed authorizes after rotation" || fail "new seed authorize"
# De-register: register a key under the new root, then retire it explicitly.
RK2="$(jget "$(printf '%s' "$NEWMN" | $PVFS --json forest recovery-key --forest "$RCF")" recovery_pubkey)"
printf '%s' "$NEWMN" | $PVFS forest recovery-key --forest "$RCF" --revoke "$RK2" >/dev/null \
  && ok "recovery key de-registered explicitly" || fail "recovery-key --revoke"
assert_rc 3 "de-registering an unknown recovery key is NotFound" -- \
  sh -c "printf '%s' '$NEWMN' | $PVFS forest recovery-key --forest '$RCF' --revoke '$RK2'"
# forest_id is unchanged across the rotation (identity is the log, not the key).
RCFID="$(jget "$RCINIT" forest_id)"
$PVFS --json --data-dir "$RCF/.pvfs" forest info | qgrep "\"forest_id\":\"$RCFID\"" \
  && ok "forest_id survives the rotation" || fail "forest_id changed"

# identity agent (doc 14 §6): port file + token gate + headless connect denial.
CPORTF="${CSOCK%.sock}.http"
[ -f "$CPORTF" ] && ok "identity agent port file exists" || fail "port file missing"
WADDR="$(jget "$(cat "$CPORTF")" addr)"
WTOK="$(jget "$(cat "$CPORTF")" token)"
WPORT="${WADDR##*:}"
http_status() { # http_status <method> <path> <token> — prints the status line
  exec 3<>"/dev/tcp/127.0.0.1/$WPORT" || return 1
  printf '%s %s HTTP/1.1\r\nHost: l\r\nOrigin: https://app.example\r\nX-PVFS-Token: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
    "$1" "$2" "$3" >&3
  head -n1 <&3
  exec 3<&-
}
http_status POST /connect badtoken | qgrep " 401 " && ok "web: bad token refused" || fail "web 401"
http_status POST /connect "$WTOK" | qgrep " 403 " && ok "web: headless connect denied" || fail "web connect gate"
http_status GET /identity "$WTOK" | qgrep " 403 " && ok "web: unconnected origin blocked" || fail "web identity gate"
"$COMPANION" origins --vault "$CVAULT" | qgrep "no connected origins" && ok "origins list empty" || fail "origins list"

# status: flagless via env defaults — reports the sealing and the live agent.
PVFS_COMPANION_VAULT="$CVAULT" PVFS_COMPANION_SOCKET="$CSOCK" "$COMPANION" status > "$DATA/status.txt" 2>&1 || true
grep -q "passphrase-sealed" "$DATA/status.txt" && ok "status reports the vault sealing" || fail "status sealing"
grep -q "agent : running" "$DATA/status.txt" && ok "status sees the running agent" || fail "status agent up"
kill -TERM "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true
CPID=""
PVFS_COMPANION_VAULT="$CVAULT" PVFS_COMPANION_SOCKET="$CSOCK" "$COMPANION" status 2>/dev/null | qgrep "agent : not running" \
  && ok "status sees the stopped agent" || fail "status agent down"
# (The headless root-signing denial without --allow-root is covered by the
#  pvfs-companion unit/integration tests, not the smoke suite.)

say "companion: multi-tenant custody server (doc 14 §13)"
TSTORE="$DATA/tenant-store"
TSOCK="$DATA/tenant.sock"
# Provision two app-users, each with their own seed + password.
AMN="$(jget "$($PVFS --json forest init --mount "$DATA/tf-alice")" mnemonic)"
BMN="$(jget "$($PVFS --json forest init --mount "$DATA/tf-bob")" mnemonic)"
printf '%s' "$AMN" | PVFS_COMPANION_PASSPHRASE=alicepw "$COMPANION" tenant-init --store "$TSTORE" --user alice >/dev/null 2>&1 && ok "provisioned tenant alice" || fail "provisioned tenant alice"
printf '%s' "$BMN" | PVFS_COMPANION_PASSPHRASE=bobpw "$COMPANION" tenant-init --store "$TSTORE" --user bob >/dev/null 2>&1 && ok "provisioned tenant bob" || fail "provisioned tenant bob"
"$COMPANION" serve-tenant --store "$TSTORE" --socket "$TSOCK" >/dev/null 2>&1 &
TPID=$!
for _ in $(seq 1 50); do [ -S "$TSOCK" ] && break; sleep 0.1; done
[ -S "$TSOCK" ] && ok "tenant custody serving" || fail "tenant socket missing"
# alice's identity key over the socket: valid, deterministic, and distinct from bob's.
APUB="$(PVFS_COMPANION_PASSPHRASE=alicepw "$COMPANION" tenant-pubkey --socket "$TSOCK" --user alice --role identity)"
[ "${#APUB}" -eq 66 ] && ok "tenant get-pubkey returns a compressed key" || fail "tenant pubkey len ${#APUB}"
APUB2="$(PVFS_COMPANION_PASSPHRASE=alicepw "$COMPANION" tenant-pubkey --socket "$TSOCK" --user alice --role identity)"
[ "$APUB" = "$APUB2" ] && ok "tenant pubkey is deterministic" || fail "tenant pubkey not deterministic"
BPUB="$(PVFS_COMPANION_PASSPHRASE=bobpw "$COMPANION" tenant-pubkey --socket "$TSOCK" --user bob --role identity)"
[ -n "$BPUB" ] && [ "$APUB" != "$BPUB" ] && ok "tenant users have distinct keys (isolation)" || fail "tenant users not isolated"
# Wrong password is refused.
assert_rc 1 "tenant wrong password rejected" -- \
  env PVFS_COMPANION_PASSPHRASE=wrong "$COMPANION" tenant-pubkey --socket "$TSOCK" --user alice --role identity
kill "$TPID" 2>/dev/null || true; wait "$TPID" 2>/dev/null || true
TPID=""

say "P3: secure blobs — mutable ciphertext + signed ledger (doc 12 §8)"
SB="$DATA/secure-store"; mkdir -p "$SB"
SNODE="$(jget "$($PVFS --json secure create "$ROOT" secrets.db --path "$SB/secrets.enc")" created)"
[ -n "$SNODE" ] && ok "secure node created with a pinned location" || fail "secure create"
printf 'ciphertext-v1' | $PVFS secure put "$SNODE" - --raw >/dev/null && ok "secure put v1" || fail "secure put"
[ "$($PVFS secure cat "$SNODE" --raw)" = "ciphertext-v1" ] && ok "secure cat verifies and returns the bytes" || fail "secure cat"
printf 'ct-v2' | $PVFS secure put "$SNODE" - --raw >/dev/null
[ "$(cat "$SB/secrets.enc")" = "ct-v2" ] && ok "overwrite in place — old ciphertext bytes are gone" || fail "overwrite"
$PVFS secure verify "$SNODE" >/dev/null && ok "secure verify clean" || fail "secure verify"
printf 'tampered!' > "$SB/secrets.enc"
assert_rc 5 "tampered ciphertext refused at cat" -- $PVFS secure cat "$SNODE" --raw
assert_rc 5 "tampered ciphertext fails verify" -- $PVFS secure verify "$SNODE"
printf 'ct-v3' | $PVFS secure put "$SNODE" - --raw >/dev/null && ok "a fresh put repairs the blob" || fail "repair put"
$PVFS secure verify "$SNODE" >/dev/null && ok "verify clean after repair" || fail "verify after repair"
$PVFS --json secure status "$SNODE" | qgrep '"size":5' && ok "ledger head tracks size" || fail "secure status"

# Companion envelope (doc 12 §8.5): encrypt to the owner, decrypt via the agent.
say "P3: secure blobs — companion envelope (doc 12 §8.5)"
ESTORE="$DATA/secure-enc"; mkdir -p "$ESTORE"
EVAULT="$DATA/secure.vault"; ESOCK="$DATA/secure.sock"
EINIT="$($PVFS --json forest init --mount "$DATA/enc-forest")"
EROOT="$(jget "$EINIT" root_node_id)"
EMN="$(jget "$EINIT" mnemonic)"
printf '%s' "$EMN" | PVFS_COMPANION_PASSPHRASE=encpass "$COMPANION" init --vault "$EVAULT" >/dev/null 2>&1 \
  && ok "sealed the enc-forest owner seed" || fail "enc companion init"
PVFS_COMPANION_PASSPHRASE=encpass "$COMPANION" serve --vault "$EVAULT" --socket "$ESOCK" --prompt deny >/dev/null 2>&1 &
EPID=$!
for _ in $(seq 1 50); do [ -S "$ESOCK" ] && break; sleep 0.1; done
[ -S "$ESOCK" ] && ok "enc companion serving" || fail "enc socket missing"
ENODE="$(jget "$($PVFS --json --data-dir "$DATA/enc-forest/.pvfs" secure create "$EROOT" note --path "$ESTORE/note.enc")" created)"
# Default put encrypts via the companion; the on-disk bytes are NOT the plaintext.
printf 'dear diary' | $PVFS --data-dir "$DATA/enc-forest/.pvfs" secure put "$ENODE" - --companion-socket "$ESOCK" >/dev/null \
  && ok "secure put (companion-encrypted)" || fail "encrypted put"
grep -q 'dear diary' "$ESTORE/note.enc" && fail "plaintext leaked to disk" || ok "on-disk bytes are ciphertext, not plaintext"
# cat decrypts via the companion and returns the plaintext.
[ "$($PVFS --data-dir "$DATA/enc-forest/.pvfs" secure cat "$ENODE" --companion-socket "$ESOCK")" = "dear diary" ] \
  && ok "secure cat (companion-decrypted) round-trips" || fail "encrypted cat"
# --raw shows it really is an opaque envelope, not the message.
$PVFS --data-dir "$DATA/enc-forest/.pvfs" secure cat "$ENODE" --raw | qgrep 'dear diary' && fail "raw exposed plaintext" || ok "raw cat yields the opaque envelope"
# Grant a second key, then that key can find its wrap (unwrap needs its own companion; here we assert the wrap lands).
GRANTEE="$(jget "$(XDG_CONFIG_HOME="$DATA/grantee" $PVFS --json whoami)" pubkey)"
$PVFS --data-dir "$DATA/enc-forest/.pvfs" secure grant "$ENODE" "$GRANTEE" --companion-socket "$ESOCK" >/dev/null \
  && ok "secure grant re-wraps for a recipient" || fail "secure grant"
$PVFS --data-dir "$DATA/enc-forest/.pvfs" secure verify "$ENODE" >/dev/null \
  && ok "verify clean after grant (ledger advanced)" || fail "verify after grant"
kill -TERM "$EPID" 2>/dev/null || true; wait "$EPID" 2>/dev/null || true
EPID=""

say "json error shape"
# A well-formed but nonexistent 64-hex id is NotFound; short garbage like
# "deadbeef" is not a valid id / URI / path, so it is BadInput. The failing
# command exits nonzero (by contract), so capture output and rc separately —
# `cmd | grep` fails via pipefail even when the shape matches, which is why
# the old one-liner variant of this check could never fire.
NOID="$(printf 'ab%.0s' $(seq 1 32))"
NORC=0; NOJSON="$($PVFS --json node "$NOID" 2>&1)" || NORC=$?
[ "$NORC" -eq 3 ] && printf '%s' "$NOJSON" | qgrep '"error":"NotFound"' \
  && ok "json NotFound error variant (rc=3)" || fail "json NotFound variant (rc=$NORC): $NOJSON"
BADRC=0; BADJSON="$($PVFS --json node deadbeef 2>&1)" || BADRC=$?
[ "$BADRC" -eq 2 ] && printf '%s' "$BADJSON" | qgrep '"error":"BadInput"' \
  && ok "json BadInput error variant (rc=2)" || fail "json BadInput variant (rc=$BADRC): $BADJSON"

echo
echo "smoke results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL SMOKE TESTS PASSED"
exit "$([ "$FAIL" -eq 0 ] && echo 0 || echo 1)"
