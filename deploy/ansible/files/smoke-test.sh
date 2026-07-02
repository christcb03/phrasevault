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
export PVFS_SOCKET_DIR="$DATA/sockets"      # per-forest daemon sockets (doc 09 §3b)
# Pre-create the socket dir so pvfsd exercises its "dir already exists → don't
# chmod" path (the /run/pvfs systemd/tmpfiles case), not just first-use creation.
mkdir -p "$PVFS_SOCKET_DIR"
PASS=0
FAIL=0
DPID=""
U2PID=""
CPID=""
TPID=""
EPID=""

cleanup() {
  [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
  [ -n "$U2PID" ] && kill "$U2PID" 2>/dev/null
  [ -n "$CPID" ] && kill "$CPID" 2>/dev/null
  [ -n "$TPID" ] && kill "$TPID" 2>/dev/null
  [ -n "$EPID" ] && kill "$EPID" 2>/dev/null
  rm -rf "$DATA"
}
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

# pvfsd binds its conventional per-forest socket ($PVFS_SOCKET_DIR/<forest_id>.sock)
SOCK="$PVFS_SOCKET_DIR/$DFID.sock"
"$PVFSD" --mount "$DMOUNT" >/dev/null 2>&1 &
DPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] && ok "pvfsd binds its conventional socket" || fail "pvfsd socket missing"
# the client finds the socket by forest (mount path) without --socket
$PVFS --json remote --forest "$DMOUNT" --anon info | grep -q "\"forest_id\":\"$DFID\"" \
  && ok "remote --forest resolves the daemon socket"

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
$PVFS remote --socket "$SOCK" mv "$UPLOADED_ID" "$DEST" >/dev/null && ok "member moved a node"
[ -n "$(pick_id "$($PVFS --json remote --socket "$SOCK" ls "$DEST")" uploaded)" ] \
  && ok "moved node is under its new parent" || fail "mv target missing"
# an anonymous client cannot write (no identity to sign with) → bad input (2)
assert_rc 2 "anon write refused (needs identity)" -- \
  $PVFS remote --socket "$SOCK" --anon mkdir "$DROOT" sneaky

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
$PVFS --json remote --socket "$SOCK" info | grep -q "\"forest_id\":\"$DFID\"" \
  && ok "daemon still serving after auto-routed admin"

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
$PVFS --data-dir "$U2/.pvfs" device authorize-member --pubkey "$BOBKEY" >/dev/null && ok "owner authorized Bob as a member"
$PVFS --data-dir "$U2/.pvfs" acl set "$SHARED_ID" "key:$BOBKEY" rw >/dev/null && ok "owner granted Bob rw on /shared"
# Serve the multi-user forest.
U2SOCK="$PVFS_SOCKET_DIR/$U2FID.sock"
"$PVFSD" --mount "$U2" >/dev/null 2>&1 &
U2PID=$!
for _ in $(seq 1 50); do [ -S "$U2SOCK" ] && break; sleep 0.1; done
[ -S "$U2SOCK" ] && ok "multi-user daemon serving" || fail "multi-user socket missing"
# Bob, signing as himself over the socket, reads + writes /shared (granted)...
bob remote --socket "$U2SOCK" ls "$SHARED_ID" | grep -q note.txt && ok "Bob reads /shared (granted)"
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
$PVFS --data-dir "$DMOUNT/.pvfs" audit | grep -q "no stale authorizations" \
  && ok "audit reports a clean forest" || fail "audit clean-case text"
$PVFS --json --data-dir "$DMOUNT/.pvfs" audit | grep -q '"inert_grants":\[\],"inert_memberships":\[\]' \
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
$PVFS --json --data-dir "$CMOUNT/.pvfs" tag ls "$CMEMBER" | grep -q "\"tag\":\"vip\",\"authority\":\"$IDPUB\",\"active\":true" \
  && ok "tag authority is the identity key (active)" || fail "tag ls authority"
$PVFS --data-dir "$CMOUNT/.pvfs" tag rm "$CMEMBER" vip --via-companion --companion-socket "$CSOCK" >/dev/null \
  && ok "companion identity-signed tag rm" || fail "companion tag rm"
$PVFS --json --data-dir "$CMOUNT/.pvfs" tag ls "$CMEMBER" | grep -q '"tag":"vip"' \
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
$PVFS --json --data-dir "$CMOUNT/.pvfs" tag ls "$M2" | grep -q "\"tag\":\"crew\",\"authority\":\"$NEWID\",\"active\":true" \
  && ok "grant re-homed to the new identity" || fail "reissue authority"
# A second forest where the OLD key was a member: replace from the handoff.
F2="$DATA/handoff-forest"; mkdir -p "$F2"
$PVFS --json forest init --mount "$F2" >/dev/null
$PVFS --data-dir "$F2/.pvfs" device authorize-member --pubkey "$OLDID" >/dev/null 2>&1 \
  && ok "old key was a member of the second forest" || fail "F2 admit"
$PVFS --data-dir "$F2/.pvfs" tag add "$OLDID" vip >/dev/null 2>&1 || true
$PVFS --data-dir "$F2/.pvfs" member replace "$DATA/handoff.json" >/dev/null \
  && ok "member replaced from the dual-signed handoff" || fail "member replace"
$PVFS --json --data-dir "$F2/.pvfs" tag ls "$NEWID" | grep -q '"tag":"vip"' \
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
# The OLD phrase no longer authorizes; the NEW phrase does.
assert_rc 5 "old seed rejected after rotation" -- \
  $PVFS --data-dir "$RCF/.pvfs" device authorize --mnemonic "$RCMN" --index 5
$PVFS --data-dir "$RCF/.pvfs" device authorize --mnemonic "$NEWMN" --index 5 >/dev/null \
  && ok "new seed authorizes after rotation" || fail "new seed authorize"
# forest_id is unchanged across the rotation (identity is the log, not the key).
RCFID="$(jget "$RCINIT" forest_id)"
$PVFS --json --data-dir "$RCF/.pvfs" forest info | grep -q "\"forest_id\":\"$RCFID\"" \
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
http_status POST /connect badtoken | grep -q " 401 " && ok "web: bad token refused" || fail "web 401"
http_status POST /connect "$WTOK" | grep -q " 403 " && ok "web: headless connect denied" || fail "web connect gate"
http_status GET /identity "$WTOK" | grep -q " 403 " && ok "web: unconnected origin blocked" || fail "web identity gate"
"$COMPANION" origins --vault "$CVAULT" | grep -q "no connected origins" && ok "origins list empty" || fail "origins list"

# status: flagless via env defaults — reports the sealing and the live agent.
PVFS_COMPANION_VAULT="$CVAULT" PVFS_COMPANION_SOCKET="$CSOCK" "$COMPANION" status > "$DATA/status.txt" 2>&1 || true
grep -q "passphrase-sealed" "$DATA/status.txt" && ok "status reports the vault sealing" || fail "status sealing"
grep -q "agent : running" "$DATA/status.txt" && ok "status sees the running agent" || fail "status agent up"
kill -TERM "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true
CPID=""
PVFS_COMPANION_VAULT="$CVAULT" PVFS_COMPANION_SOCKET="$CSOCK" "$COMPANION" status 2>/dev/null | grep -q "agent : not running" \
  && ok "status sees the stopped agent" || fail "status agent down"
# (The headless root-signing denial without --allow-root is covered by the
#  pvfs-companion unit/integration tests, not the smoke suite.)

say "companion: multi-tenant custody server (doc 14 §13)"
TSTORE="$DATA/tenant-store"
TSOCK="$DATA/tenant.sock"
# Provision two app-users, each with their own seed + password.
AMN="$(jget "$($PVFS --json forest init --mount "$DATA/tf-alice")" mnemonic)"
BMN="$(jget "$($PVFS --json forest init --mount "$DATA/tf-bob")" mnemonic)"
printf '%s' "$AMN" | PVFS_COMPANION_PASSPHRASE=alicepw "$COMPANION" tenant-init --store "$TSTORE" --user alice >/dev/null 2>&1 && ok "provisioned tenant alice"
printf '%s' "$BMN" | PVFS_COMPANION_PASSPHRASE=bobpw "$COMPANION" tenant-init --store "$TSTORE" --user bob >/dev/null 2>&1 && ok "provisioned tenant bob"
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
$PVFS --json secure status "$SNODE" | grep -q '"size":5' && ok "ledger head tracks size" || fail "secure status"

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
$PVFS --data-dir "$DATA/enc-forest/.pvfs" secure cat "$ENODE" --raw | grep -q 'dear diary' && fail "raw exposed plaintext" || ok "raw cat yields the opaque envelope"
# Grant a second key, then that key can find its wrap (unwrap needs its own companion; here we assert the wrap lands).
GRANTEE="$(jget "$(XDG_CONFIG_HOME="$DATA/grantee" $PVFS --json whoami)" pubkey)"
$PVFS --data-dir "$DATA/enc-forest/.pvfs" secure grant "$ENODE" "$GRANTEE" --companion-socket "$ESOCK" >/dev/null \
  && ok "secure grant re-wraps for a recipient" || fail "secure grant"
$PVFS --data-dir "$DATA/enc-forest/.pvfs" secure verify "$ENODE" >/dev/null \
  && ok "verify clean after grant (ledger advanced)" || fail "verify after grant"
kill -TERM "$EPID" 2>/dev/null || true; wait "$EPID" 2>/dev/null || true
EPID=""

say "json error shape"
$PVFS --json node deadbeef 2>&1 | grep -q '"error":"NotFound"' && ok "json error variant"

echo
echo "smoke results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL SMOKE TESTS PASSED"
exit "$([ "$FAIL" -eq 0 ] && echo 0 || echo 1)"
