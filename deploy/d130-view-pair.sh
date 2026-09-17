#!/bin/bash
# D130 item 6 — the VIEW MOUNT on the two-machine lab: the D129 pair (both boxes
# hold the union) plus `pvfs mount --view` on the owner: its own bytes read from
# disk, the edge's read through by content hash, kept, and served on when the
# edge is gone.
# D165 — the read-through by the piece: a 600 MiB file on the edge; what a
# media analysis reads of it (38.5 KB of head, the last 1.1 KB) returns at
# once and costs two pieces, not the file; a full read lands it verified in
# the store; a remount with a small --cache-max evicts it.
#   owner : presubuntu (192.168.0.184) — forest, `own-shelf` catalogued here
#   edge  : pvos-test  (192.168.0.138) — replica, `edge-shelf` catalogued there
# Binaries: ~/.local/bin on both boxes, installed by the pipeline — or a
# session's own build, without touching that machine-global install:
#   PVFS_LAB_BIN=/opt/pvfs-<session>/src/target/release deploy/d130-view-pair.sh
# Run from
# the Mac; nothing here touches production.
OWNER=chris@192.168.0.184; EDGE=chris@192.168.0.138; OWNER_IP=192.168.0.184; EDGE_IP=192.168.0.138
LABBIN=${PVFS_LAB_BIN:-'$HOME/.local/bin'}   # expanded on the lab box, not here
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
RH='B='"$LABBIN"'; FT=$HOME/fleet-test; O=$FT/d130-owner; R=$FT/d130-replica; D=$O/.pvfs; RD=$R/.pvfs
jget(){ python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
stopd(){ p=$(cat "$1" 2>/dev/null) || return 0; kill "$p" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done; echo "STILL_RUNNING $p"; }
# region ls as "held/head/stale" for one region
rstat(){ "$B/pvfs" --json --data-dir "$1" region ls 2>/dev/null | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r[\"region\"]==sys.argv[1]: print(\"%s/%s/%s\" % (r.get(\"held\"), r.get(\"head\"), r.get(\"stale\")))" "$2"; }
# wait until rstat matches, up to N seconds
waitr(){ for _ in $(seq 1 "$3"); do [ "$(rstat "$1" "$2")" = "$4" ] && return 0; sleep 2; done; echo "TIMEOUT rstat=$(rstat "$1" "$2")"; return 1; }
vpaths(){ "$B/pvfs" --json --data-dir "$1" view ls "$2" 2>/dev/null | python3 -c "import json,sys; print(\",\".join(e[\"path\"] for e in json.load(sys.stdin)))"; }
'

say "0: preflight — the D130 build on both boxes, a clean slate"
VA=$(ssh "$OWNER" "\"$LABBIN/pvfs\" --version" 2>&1); VB=$(ssh "$EDGE" "\"$LABBIN/pvfs\" --version" 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" "\"$LABBIN/pvfs\" mount --help >/dev/null 2>&1" && ok "$h has pvfs mount" || fail "$h: not a D130 build"
  # an aborted run leaves its mounts up (the gate exits before the teardown): a view mount
  # that outlives its data dir goes on listing the LAST run's files to this one
  ssh "$h" 'for m in d130-union d130-view; do fusermount3 -uz "$HOME/fleet-test/$m" 2>/dev/null; done; pkill -f "mount --view $HOME/fleet-test/d130" 2>/dev/null; pkill -f "pvfsd --mount $HOME/fleet-test/d130" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d130-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
AKEY=$(ssh "$OWNER" "\"$LABBIN/pvfs\" --json whoami" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" "\"$LABBIN/pvfs\" --json whoami" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
ssh "$EDGE" 'L=$HOME/fleet-test/d130-edge-lib; mkdir -p "$L/season" "$L/unused"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"; head -c 629145600 /dev/urandom > "$L/big.mkv"; md5sum < "$L/big.mkv" | cut -d" " -f1 > "$HOME/fleet-test/d130-big.md5"' \
  && ok "edge library staged (x.mkv, season/y.mkv, unused/, and a 600 MiB big.mkv)" || fail "edge library"
gate preflight

say "A: owner — forest, two catalogue regions, its shelf catalogued, announced, listener up with the catalogue job"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d130-owner-lib; mkdir -p "\$L/sub" "\$L/empty"; printf aaa > "\$L/a.mkv"; printf bbbbb > "\$L/sub/b.mkv"
"\$B/pvfs" forest init --mount "\$O" >/dev/null 2>&1 || { echo INIT_FAILED; exit 0; }
INFO=\$("\$B/pvfs" --json --data-dir "\$D" info)
ROOT=\$(printf '%s' "\$INFO" | jget root_node_id); FID=\$(printf '%s' "\$INFO" | jget forest_id)
"\$B/pvfs" --forest "\$O" fleet enroll $EDGEKEY --rights rwa >/dev/null 2>&1 && echo A0=ok
"\$B/pvfs" --forest "\$O" fleet enroll $AKEY --rights rwa >/dev/null 2>&1 && echo A1=ok
OWN=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label own-shelf)
EDGESHELF=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label edge-shelf)
"\$B/pvfs" --json --data-dir "\$D" region mark "\$OWN" --catalogue | grep -q '"kind":"catalogue"' && echo A2=ok
"\$B/pvfs" --json --data-dir "\$D" region mark "\$EDGESHELF" --catalogue --owner key:$EDGEKEY | grep -q '"owner":"key:' && echo A3=ok
"\$B/pvfs" --data-dir "\$D" bind "\$OWN" "\$L" --hash-policy on_add >/dev/null && echo A4=ok
"\$B/pvfs" --data-dir "\$D" scan "\$OWN" >/dev/null && echo A5=ok
# mint the pin with a brief start, then announce with the daemon down (the lease rule)
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7446 >/dev/null 2>"\$FT/d130-owner.log" &
echo \$! > "\$FT/d130-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
stopd "\$FT/d130-owner.pid"
"\$B/pvfs" --data-dir "\$D" fleet announce $OWNER_IP:7446 >/dev/null 2>&1 && echo A6=ok
"\$B/pvfs" --data-dir "\$D" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable catalogue >/dev/null 2>&1 && echo A7=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7446 >/dev/null 2>>"\$FT/d130-owner.log" &
echo \$! > "\$FT/d130-owner.pid"
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7446 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$got" = "\$FID" ] && { echo A8=ok; break; }; sleep 0.5
done
echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "OWN=\$OWN"; echo "EDGESHELF=\$EDGESHELF"; echo "PIN=\$PIN"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
has "$A_OUT" A0=ok && ok "edge enrolled (rwa)" || fail "enroll edge"
has "$A_OUT" A1=ok && ok "owner's own client key enrolled (serve status is member-gated)" || fail "enroll A"
has "$A_OUT" A2=ok && ok "own-shelf marked catalogue" || fail "own-shelf mark"
has "$A_OUT" A3=ok && ok "edge-shelf marked catalogue, owned by the edge's key" || fail "edge-shelf mark"
has "$A_OUT" A4=ok && ok "owner bound its shelf" || fail "owner bind"
has "$A_OUT" A5=ok && ok "owner scanned its shelf" || fail "owner scan"
has "$A_OUT" A6=ok && ok "owner announced its endpoint" || fail "owner announce"
has "$A_OUT" A7=ok && ok "owner enabled watch + catalogue jobs" || fail "owner serve enable"
has "$A_OUT" A8=ok && ok "owner daemon up on :7446" || fail "owner daemon: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d130-owner.log')"
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); OWN=$(val "$A_OUT" OWN); EDGESHELF=$(val "$A_OUT" EDGESHELF); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "owner transport pin minted" || fail "pin: $PIN"
gate owner

say "B: edge — replica, binds its shelf, announces, publishes its head through the owner"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d130owner >/dev/null 2>&1; "\$B/pvfs" instance add d130owner $OWNER_IP:7446 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d130owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --data-dir "\$RD" bind "$EDGESHELF" "\$FT/d130-edge-lib" --hash-policy on_add >/dev/null 2>&1 && echo B3=ok
age=\$(( \$(date +%s) - \$(stat -c %Z "\$FT/d130-edge-lib/x.mkv") )); [ "\$age" -lt 17 ] && sleep \$(( 17 - age ))
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7447 >/dev/null 2>"\$FT/d130-edge.log" &
echo \$! > "\$FT/d130-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" fleet announce $EDGE_IP:7447 >/dev/null 2>&1 && echo B4=ok
"\$B/pvfs" --data-dir "\$RD" serve enable follow >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable catalogue >/dev/null 2>&1 && echo B5=ok
for _ in \$(seq 1 90); do
  seq=\$("\$B/pvfs" --json --data-dir "\$RD" region entries "$EDGESHELF" 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["head"]["seq"] if d["head"] else 0)' 2>/dev/null || echo 0)
  [ "\$seq" = "1" ] && { echo B6=ok; break; }; sleep 2
done
EOS
)
has "$B_OUT" B1=ok && ok "edge pinned the owner" || fail "instance add: $B_OUT"
has "$B_OUT" B2=ok && ok "replica shipped the owner's log" || fail "replica add"
has "$B_OUT" B3=ok && ok "edge bound its shelf locally" || fail "edge bind"
has "$B_OUT" B4=ok && ok "edge announced its endpoint (written through the owner)" || fail "edge announce"
has "$B_OUT" B5=ok && ok "edge daemon up with follow + watch + catalogue" || fail "edge serve jobs"
has "$B_OUT" B6=ok && ok "edge published edge-shelf head 1 through the owner" || fail "no edge head within 180s: $(ssh "$EDGE" 'tail -3 $HOME/fleet-test/d130-edge.log')"
gate edge

say "C: each box fetches the other's catalogue; the merged view is the whole library on both"
C_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitr "\$D" "$EDGESHELF" 75 "1/1/False" && echo C1=ok
echo "OWNER_TOP=\$(vpaths "\$D" "")"
echo "OWNER_SEASON=\$(vpaths "\$D" season)"
"\$B/pvfs" --json --data-dir "\$D" region ls | python3 -c '
import json,sys
rows={r["region"]:r for r in json.load(sys.stdin)}
e=rows[sys.argv[1]]; assert e["local"] is False and e["fetched_at"] and e["entries"]==5, e
o=rows[sys.argv[2]]; assert o["local"] is True and o["stale"] is False, o' "$EDGESHELF" "$OWN" && echo C2=ok
"\$B/pvfs" --json --data-dir "\$D" serve status 2>/dev/null | grep -q '"stale":0' && echo C3=ok
EOS
)
has "$C_OUT" C1=ok && ok "owner fetched edge-shelf at head 1 (the catalogue job)" || fail "owner never fetched: $C_OUT"
[ "$(val "$C_OUT" OWNER_TOP)" = "a.mkv,big.mkv,empty,season,sub,unused,x.mkv" ] && ok "owner's view is the union of both shelves" || fail "owner top: $(val "$C_OUT" OWNER_TOP)"
[ "$(val "$C_OUT" OWNER_SEASON)" = "season/y.mkv" ] && ok "owner sees the edge's season/y.mkv" || fail "owner season: $(val "$C_OUT" OWNER_SEASON)"
has "$C_OUT" C2=ok && ok "region ls: edge-shelf fetched (5 rows), own-shelf live" || fail "owner region ls: $C_OUT"
has "$C_OUT" C3=ok && ok "owner's serve status: stale 0" || fail "serve status stale: $C_OUT"
D_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitr "\$RD" "$OWN" 75 "1/1/False" && echo D1=ok
echo "EDGE_TOP=\$(vpaths "\$RD" "")"
echo "EDGE_SUB=\$(vpaths "\$RD" sub)"
EOS
)
has "$D_OUT" D1=ok && ok "edge fetched own-shelf at head 1" || fail "edge never fetched: $D_OUT"
[ "$(val "$D_OUT" EDGE_TOP)" = "a.mkv,big.mkv,empty,season,sub,unused,x.mkv" ] && ok "edge's view is the same union" || fail "edge top: $(val "$D_OUT" EDGE_TOP)"
[ "$(val "$D_OUT" EDGE_SUB)" = "sub/b.mkv" ] && ok "edge sees the owner's sub/b.mkv" || fail "edge sub: $(val "$D_OUT" EDGE_SUB)"
gate fetch

say "D: the edge's shelf changes — a new head, the owner goes stale, then catches up"
ssh "$EDGE" 'printf zzz > "$HOME/fleet-test/d130-edge-lib/z.mkv"' && ok "z.mkv added on the edge"
E_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
for _ in \$(seq 1 90); do [ "\$(rstat "\$D" "$EDGESHELF" | cut -d/ -f2)" = "2" ] && { echo E1=ok; break; }; sleep 2; done
waitr "\$D" "$EDGESHELF" 75 "2/2/False" && echo E2=ok
echo "OWNER_TOP2=\$(vpaths "\$D" "")"
EOS
)
has "$E_OUT" E1=ok && ok "the log attests edge-shelf head 2 on the owner" || fail "no head 2: $E_OUT"
has "$E_OUT" E2=ok && ok "owner caught up to head 2" || fail "owner stuck: $E_OUT"
[ "$(val "$E_OUT" OWNER_TOP2)" = "a.mkv,big.mkv,empty,season,sub,unused,x.mkv,z.mkv" ] && ok "owner's view shows z.mkv" || fail "owner top2: $(val "$E_OUT" OWNER_TOP2)"
gate change

say "E: the view mount on the owner — the union as a filesystem; the edge's bytes read through by hash"
E_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view; mkdir -p "\$V"
nohup "\$B/pvfs" --data-dir "\$D" mount --view "\$V" >/dev/null 2>"\$FT/d130-view.log" &
echo \$! > "\$FT/d130-view.pid"
for _ in \$(seq 1 40); do mountpoint -q "\$V" && break; sleep 0.25; done
mountpoint -q "\$V" && echo E1=ok
echo "TOP=\$(ls "\$V" | tr '\n' ' ')"
[ "\$(cat "\$V/a.mkv")" = "aaa" ] && echo E2=ok
[ "\$(cat "\$V/sub/b.mkv")" = "bbbbb" ] && echo E3=ok
t0=\$(date +%s.%N); got=\$(cat "\$V/x.mkv" 2>/dev/null); t1=\$(date +%s.%N)
[ "\$got" = "xx" ] && echo E4=ok
echo "READTHROUGH_S=\$(python3 -c "print(round(\$t1-\$t0,2))")"
H=\$(python3 -c "import hashlib,sys; print(__import__('blake3').blake3(b'xx').hexdigest())" 2>/dev/null || echo "")
find "\$D" -path '*/by-hash/*' -type f ! -name '*.partial' 2>/dev/null | head -3 | sed 's/^/STORE=/'
sleep 1; grep -c "is whole, verified and kept" "\$FT/d130-view.log" | sed 's/^/LOGGED=/'
[ "\$(cat "\$V/z.mkv")" = "zzz" ] && echo E5=ok
EOS
)
has "$E_OUT" E1=ok && ok "the view is mounted on the owner" || fail "view mount: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d130-view.log')"
[ "$(val "$E_OUT" TOP)" = "a.mkv big.mkv empty season sub unused x.mkv z.mkv " ] && ok "ls shows the union of both shelves" || fail "ls: $(val "$E_OUT" TOP)"
has "$E_OUT" E2=ok && ok "a.mkv (the owner's own bytes) reads from disk" || fail "a.mkv"
has "$E_OUT" E3=ok && ok "sub/b.mkv reads from disk" || fail "sub/b.mkv"
has "$E_OUT" E4=ok && ok "x.mkv (only the edge holds it) read through by hash in $(val "$E_OUT" READTHROUGH_S)s" || fail "x.mkv read-through: $E_OUT $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d130-view.log')"
has "$E_OUT" STORE= && ok "the bytes landed in the hash store" || fail "hash store empty: $E_OUT"
[ "$(val "$E_OUT" LOGGED)" = "1" ] && ok "the mount logged x.mkv whole, verified and kept (a small file is verified before it is served)" || fail "kept log: $(val "$E_OUT" LOGGED)"
has "$E_OUT" E5=ok && ok "z.mkv (added later on the edge) reads through too" || fail "z.mkv"
gate mount

say "E2 (D165): what a media analysis reads of a 600 MiB file costs two pieces; a full read lands it verified"
BIGMD5=$(ssh "$EDGE" 'cat $HOME/fleet-test/d130-big.md5')
P_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
python3 - "\$V/big.mkv" <<'PY'
import os, sys, time
p = sys.argv[1]; size = os.path.getsize(p); print("SIZE=%d" % size)
f = open(p, "rb", buffering=0)
t = time.time(); f.seek(size - 1101); tail = f.read(1101); print("TAIL_S=%.3f" % (time.time() - t)); print("TAIL_N=%d" % len(tail))
t = time.time(); f.seek(0); head = f.read(38550); print("HEAD_S=%.3f" % (time.time() - t)); print("HEAD_N=%d" % len(head))
f.close()
PY
sleep 1
PART=\$(find "\$D" -path '*/by-hash/*' -name '*.partial' | head -1)
[ -n "\$PART" ] && echo "PART_LEN=\$(stat -c %s "\$PART")" && echo "PART_KB=\$(du -k "\$PART" | cut -f1)"
echo "WHOLE_BEFORE=\$(find "\$D" -path '*/by-hash/*' -type f -size +100M ! -name '*.partial' | wc -l)"
t0=\$(date +%s.%N); GOT=\$(md5sum < "\$V/big.mkv" | cut -d' ' -f1); t1=\$(date +%s.%N)
echo "FULL_MD5=\$GOT"; echo "FULL_S=\$(python3 -c "print(round(\$t1-\$t0,1))")"
for _ in \$(seq 1 60); do [ "\$(find "\$D" -path '*/by-hash/*' -type f -size +100M ! -name '*.partial' | wc -l)" = "1" ] && { echo KEPT=ok; break; }; sleep 1; done
echo "PART_AFTER=\$(find "\$D" -path '*/by-hash/*' -name '*.partial' | wc -l)"
t0=\$(date +%s.%N); AGAIN=\$(md5sum < "\$V/big.mkv" | cut -d' ' -f1); t1=\$(date +%s.%N)
echo "AGAIN_MD5=\$AGAIN"; echo "AGAIN_S=\$(python3 -c "print(round(\$t1-\$t0,1))")"
EOS
)
[ "$(val "$P_OUT" SIZE)" = "629145600" ] && ok "big.mkv is listed at its size" || fail "big.mkv size: $(val "$P_OUT" SIZE)"
[ "$(val "$P_OUT" TAIL_N)" = "1101" ] && python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 2 else 1)" "$(val "$P_OUT" TAIL_S)" && ok "the last 1,101 bytes read in $(val "$P_OUT" TAIL_S)s" || fail "tail: $P_OUT"
[ "$(val "$P_OUT" HEAD_N)" = "38550" ] && python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 2 else 1)" "$(val "$P_OUT" HEAD_S)" && ok "the first 38,550 bytes read in $(val "$P_OUT" HEAD_S)s" || fail "head: $P_OUT"
[ "$(val "$P_OUT" PART_LEN)" = "629145600" ] && [ "$(val "$P_OUT" PART_KB)" -lt 30720 ] && ok "the probe left a sparse partial holding $(val "$P_OUT" PART_KB) KB of the 614,400" || fail "partial: len=$(val "$P_OUT" PART_LEN) kb=$(val "$P_OUT" PART_KB)"
[ "$(val "$P_OUT" WHOLE_BEFORE)" = "0" ] && ok "and no whole file: a probe is not a consumer" || fail "a probe kept a whole file"
[ "$(val "$P_OUT" FULL_MD5)" = "$BIGMD5" ] && ok "a full read through the mount matches the edge's md5 ($(val "$P_OUT" FULL_S)s)" || fail "md5: got $(val "$P_OUT" FULL_MD5) want $BIGMD5"
has "$P_OUT" KEPT=ok && [ "$(val "$P_OUT" PART_AFTER)" = "0" ] && ok "the file is whole in the hash store, verified, and its partial is gone" || fail "not kept: $P_OUT $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d130-view.log')"
[ "$(val "$P_OUT" AGAIN_MD5)" = "$BIGMD5" ] && ok "a second full read comes from the store ($(val "$P_OUT" AGAIN_S)s)" || fail "second read md5"
gate pieces

say "E3 (D169): a delete through the owner's mount is a trip to the EDGE's trash; restored there, it comes back"
ZHEAD=$(ssh "$OWNER" "bash -s" <<EOS
$RH
rstat "\$D" "$EDGESHELF" | cut -d/ -f2
EOS
)
X_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
rm "\$V/z.mkv" 2>"\$FT/d169-rm.err" && echo X1=ok
[ -e "\$V/z.mkv" ] || echo X2=ok
echo "TOP3=\$(ls "\$V" | tr '\n' ' ')"
( : > "\$V/new.mkv" ) 2>/dev/null || echo X3=ok
[ "\$(cat "\$V/a.mkv")" = "aaa" ] && echo X4=ok
EOS
)
has "$X_OUT" X1=ok && ok "rm of z.mkv (only the edge holds it) through the owner's mount succeeded" || fail "rm through the mount: $X_OUT $(ssh "$OWNER" 'cat $HOME/fleet-test/d169-rm.err; tail -2 $HOME/fleet-test/d130-view.log')"
has "$X_OUT" X2=ok && [ "$(val "$X_OUT" TOP3)" = "a.mkv big.mkv empty season sub unused x.mkv " ] && ok "and it is gone from the mount at once" || fail "still listed: $(val "$X_OUT" TOP3)"
has "$X_OUT" X3=ok && has "$X_OUT" X4=ok && ok "a write is still refused; a.mkv reads" || fail "write: $X_OUT"
Y_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
L=\$FT/d130-edge-lib
[ -e "\$L/z.mkv" ] || echo Y1=ok
"\$B/pvfs" --data-dir "\$RD" trash ls 2>/dev/null | grep -q "z.mkv" && echo Y2=ok
"\$B/pvfs" --data-dir "\$RD" trash ls 2>/dev/null | sed -n '1,3p' | sed 's/^/LS=/'
grep -c "trashed z.mkv" "\$FT/d130-edge.log" | sed 's/^/LOGGED=/'
EOS
)
has "$Y_OUT" Y1=ok && has "$Y_OUT" Y2=ok && ok "the edge moved ITS z.mkv into its trash, and \`pvfs trash ls\` there shows it" || fail "edge trash: $Y_OUT"
[ "$(val "$Y_OUT" LOGGED)" = "1" ] && ok "the edge's daemon logged who asked" || fail "edge log: $(val "$Y_OUT" LOGGED)"
W_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
for _ in \$(seq 1 90); do h=\$(rstat "\$D" "$EDGESHELF" | cut -d/ -f1); [ "\$h" -gt "$ZHEAD" ] 2>/dev/null && { echo W1=ok; break; }; ls "\$V" >/dev/null; sleep 2; done
echo "TOP4=\$(vpaths "\$D" "")"
ls "\$V" >/dev/null
EOS
)
has "$W_OUT" W1=ok && ok "the edge published a head without z.mkv and the owner fetched it" || fail "no new head: $W_OUT"
[ "$(val "$W_OUT" TOP4)" = "a.mkv,big.mkv,empty,season,sub,unused,x.mkv" ] && ok "the owner's catalogue agrees: z.mkv is gone" || fail "owner top4: $(val "$W_OUT" TOP4)"
R_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" --data-dir "\$RD" trash restore z.mkv 2>&1 | head -1 | sed 's/^/RESTORE=/'
[ "\$(cat "\$FT/d130-edge-lib/z.mkv")" = "zzz" ] && echo R1=ok
EOS
)
has "$R_OUT" R1=ok && ok "restored on the edge: $(val "$R_OUT" RESTORE)" || fail "restore: $R_OUT"
B_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
for _ in \$(seq 1 120); do [ "\$(cat "\$V/z.mkv" 2>/dev/null)" = "zzz" ] && { echo B1=ok; break; }; sleep 2; done
EOS
)
has "$B_OUT" B1=ok && ok "and z.mkv is back in the owner's mount, readable — the delete's tombstone did not outlive it" || fail "z.mkv never came back: $B_OUT"
gate delete

say "E4 (D170): renames and folders through the owner's mount, done on the EDGE's disk — seen at once, and still right after the head"
ssh "$EDGE" 'L=$HOME/fleet-test/d130-edge-lib; mkdir -p "$L/show/s1"; printf e1e1 > "$L/show/s1/e1.mkv"' && ok "show/s1/e1.mkv added on the edge"
N_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
for _ in \$(seq 1 120); do [ "\$(vpaths "\$D" show/s1)" = "show/s1/e1.mkv" ] && { echo N1=ok; break; }; ls "\$V" >/dev/null; sleep 2; done
echo "HEAD=\$(rstat "\$D" "$EDGESHELF" | cut -d/ -f2)"
EOS
)
has "$N_OUT" N1=ok && ok "the owner's catalogue lists it (never read: its bytes are only on the edge)" || fail "show never arrived: $N_OUT"
MHEAD=$(val "$N_OUT" HEAD)
M_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
mv "\$V/z.mkv" "\$V/Z - renamed.mkv" 2>"\$FT/d170.err" && echo M1=ok
[ "\$(stat -c %s "\$V/Z - renamed.mkv" 2>/dev/null)" = "3" ] && [ ! -e "\$V/z.mkv" ] && echo M2=ok
[ "\$(cat "\$V/Z - renamed.mkv")" = "zzz" ] && echo M3=ok
mv "\$V/show" "\$V/Show (2020)" 2>>"\$FT/d170.err" && echo M4=ok
[ "\$(ls "\$V/Show (2020)/s1" | tr '\n' ' ')" = "e1.mkv " ] && [ ! -e "\$V/show" ] && echo M5=ok
[ "\$(cat "\$V/Show (2020)/s1/e1.mkv")" = "e1e1" ] && echo M6=ok
mkdir "\$V/Show (2020)/s2" 2>>"\$FT/d170.err" && mv "\$V/Show (2020)/s1/e1.mkv" "\$V/Show (2020)/s2/E01.mkv" 2>>"\$FT/d170.err" && echo M7=ok
[ "\$(stat -c %s "\$V/Show (2020)/s2/E01.mkv" 2>/dev/null)" = "4" ] && [ ! -e "\$V/Show (2020)/s1/e1.mkv" ] && echo M8=ok
# a folder MADE here becomes real on the edge when a file is renamed into it; emptied and removed
# within the minute — before any head says the edge has it — the rmdir must still reach the edge
mkdir "\$V/Show (2020)/s9" 2>>"\$FT/d170.err" && mv "\$V/Show (2020)/s2/E01.mkv" "\$V/Show (2020)/s9/E01.mkv" 2>>"\$FT/d170.err" \
  && mv "\$V/Show (2020)/s9/E01.mkv" "\$V/Show (2020)/s2/E01.mkv" 2>>"\$FT/d170.err" && rmdir "\$V/Show (2020)/s9" 2>>"\$FT/d170.err" && echo M8B=ok
rmdir "\$V/Show (2020)/s1" 2>>"\$FT/d170.err" && echo M9=ok
rmdir "\$V/unused" 2>>"\$FT/d170.err" && echo M10=ok
rmdir "\$V/sub" 2>/dev/null || echo M11=ok
chmod 664 "\$V/Z - renamed.mkv" 2>>"\$FT/d170.err" && echo M12=ok
echo "TOP5=\$(LC_ALL=C ls "\$V" | tr '\n' ',')"
echo "SHOW5=\$(LC_ALL=C ls "\$V/Show (2020)" | tr '\n' ',')"
EOS
)
merr() { ssh "$OWNER" 'cat $HOME/fleet-test/d170.err; tail -3 $HOME/fleet-test/d130-view.log'; }
has "$M_OUT" M1=ok && has "$M_OUT" M2=ok && has "$M_OUT" M3=ok && ok "a verified move of z.mkv (the edge's): the new name is there with its size AT ONCE, reads, and the old one is gone" || fail "file rename: $M_OUT $(merr)"
has "$M_OUT" M4=ok && has "$M_OUT" M5=ok && ok "a folder renamed with what is under it, listed at the new path at once" || fail "folder rename: $M_OUT $(merr)"
has "$M_OUT" M6=ok && ok "a never-read file reads through at its NEW path (the edge finds its bytes: its rows followed the rename)" || fail "read after rename: $M_OUT $(merr)"
has "$M_OUT" M7=ok && has "$M_OUT" M8=ok && ok "mkdir, then a verified move into the new folder (mergerfs's path clone)" || fail "mkdir+rename: $M_OUT $(merr)"
has "$M_OUT" M8B=ok && ok "a folder made here, filled, emptied and removed within the minute" || fail "made/filled/emptied/removed: $M_OUT $(merr)"
has "$M_OUT" M9=ok && has "$M_OUT" M10=ok && has "$M_OUT" M11=ok && ok "emptied folders are removed; one with a file in it stays" || fail "rmdir: $M_OUT $(merr)"
has "$M_OUT" M12=ok && ok "chmod is accepted" || fail "chmod: $M_OUT $(merr)"
[ "$(val "$M_OUT" TOP5)" = "Show (2020),Z - renamed.mkv,a.mkv,big.mkv,empty,season,sub,x.mkv," ] && [ "$(val "$M_OUT" SHOW5)" = "s2," ] && ok "the mount lists exactly what was done" || fail "listing: $(val "$M_OUT" TOP5) / $(val "$M_OUT" SHOW5)"
G_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
L=\$FT/d130-edge-lib
[ "\$(cat "\$L/Z - renamed.mkv")" = "zzz" ] && [ ! -e "\$L/z.mkv" ] && echo G1=ok
[ "\$(cat "\$L/Show (2020)/s2/E01.mkv")" = "e1e1" ] && echo G2=ok
[ ! -e "\$L/show" ] && [ ! -e "\$L/Show (2020)/s1" ] && [ ! -e "\$L/unused" ] && echo G3=ok
[ ! -e "\$L/Show (2020)/s9" ] && echo G4=ok
grep -c "pvfsd: renamed " "\$FT/d130-edge.log" | sed 's/^/RENAMED=/'
grep -c "pvfsd: removed folder " "\$FT/d130-edge.log" | sed 's/^/REMOVED=/'
EOS
)
has "$G_OUT" G1=ok && has "$G_OUT" G2=ok && has "$G_OUT" G3=ok && ok "the edge's disk agrees, file for file" || fail "edge disk: $G_OUT"
has "$G_OUT" G4=ok && ok "and the folder that was made, filled, emptied and removed is gone from the edge's disk — the rmdir reached it" || fail "s9 is still on the edge's disk: $G_OUT"
[ "$(val "$G_OUT" RENAMED)" = "5" ] && [ "$(val "$G_OUT" REMOVED)" = "3" ] && ok "and its daemon logged who asked: 5 renames, 3 folders" || fail "edge log: $G_OUT"
H_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
for _ in \$(seq 1 120); do
  [ "\$(vpaths "\$D" "")" = "Show (2020),Z - renamed.mkv,a.mkv,big.mkv,empty,season,sub,x.mkv" ] && [ "\$(vpaths "\$D" "Show (2020)/s2")" = "Show (2020)/s2/E01.mkv" ] && { echo H1=ok; break; }
  ls "\$V" >/dev/null; sleep 2
done
echo "HEAD=\$(rstat "\$D" "$EDGESHELF" | cut -d/ -f2)"
sleep 6
echo "TOP6=\$(LC_ALL=C ls "\$V" | tr '\n' ',')"
[ "\$(cat "\$V/Show (2020)/s2/E01.mkv")" = "e1e1" ] && [ "\$(cat "\$V/Z - renamed.mkv")" = "zzz" ] && echo H2=ok
EOS
)
has "$H_OUT" H1=ok && [ "$(val "$H_OUT" HEAD)" -gt "$MHEAD" ] && ok "the edge published what it did (head $MHEAD → $(val "$H_OUT" HEAD)) and the owner's catalogue says the same" || fail "catalogue never agreed: $H_OUT"
[ "$(val "$H_OUT" TOP6)" = "Show (2020),Z - renamed.mkv,a.mkv,big.mkv,empty,season,sub,x.mkv," ] && has "$H_OUT" H2=ok && ok "and the mount shows the same thing it showed from memory — and reads it" || fail "after the head: $H_OUT"
gate rename

say "E5 (D170): the same through a REAL mergerfs union — feederbox's options, <local>=RW : <the view>=NC"
U_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view; U=\$FT/d130-union; LB=\$FT/d130-union-local
command -v mergerfs >/dev/null || { echo NO_MERGERFS=1; exit 0; }
# the arr's union: the show's folder exists on the local branch too (an import landed there once)
mkdir -p "\$U" "\$LB/Show (2020)"
mergerfs -o category.create=ff,async_read=true,cache.files=partial -o category.action=epall,category.search=ff \
  -o dropcacheonclose=true,minfreespace=0,fsname=d130union -o xattr=nosys,statfs=base,statfs_ignore=nc,noatime \
  -o func.readdir=seq "\$LB=RW:\$V=NC" "\$U" 2>"\$FT/d170-union.err" && echo U0=ok
echo "MERGERFS=\$(mergerfs --version | head -1)"
S="\$U/Show (2020)"
# 1. "Rename files": a verified move of a file that is on the view's branch only
mv "\$S/s2/E01.mkv" "\$S/s2/Show - S02E01.mkv" 2>>"\$FT/d170-union.err" && [ "\$(stat -c %s "\$S/s2/Show - S02E01.mkv")" = "4" ] && [ ! -e "\$S/s2/E01.mkv" ] && echo U1=ok
[ "\$(cat "\$S/s2/Show - S02E01.mkv")" = "e1e1" ] && echo U2=ok
# 2. into a season folder the arr just made: it lands on the LOCAL branch, so mergerfs clones the path onto ours first
mkdir "\$S/s3" 2>>"\$FT/d170-union.err" && [ -d "\$LB/Show (2020)/s3" ] && echo U3=ok
mv "\$S/s2/Show - S02E01.mkv" "\$S/s3/Show - S03E01.mkv" 2>>"\$FT/d170-union.err" && [ "\$(stat -c %s "\$S/s3/Show - S03E01.mkv")" = "4" ] && echo U4=ok
[ -e "\$LB/Show (2020)/s3/Show - S03E01.mkv" ] && echo U4_ON_LOCAL=1   # it must NOT have been copied to local
# 3. "delete empty folders"
rmdir "\$S/s2" 2>>"\$FT/d170-union.err" && [ ! -e "\$S/s2" ] && echo U5=ok
# 4. the series folder renamed: it exists on BOTH branches, mergerfs renames on each
mv "\$S" "\$U/Show Renamed (2020)" 2>>"\$FT/d170-union.err" && [ -d "\$LB/Show Renamed (2020)" ] && [ ! -e "\$S" ] && echo U6=ok
[ "\$(cat "\$U/Show Renamed (2020)/s3/Show - S03E01.mkv")" = "e1e1" ] && echo U7=ok
# 5. an upgrade: the old file deleted (D169), the new one created at the same path — on the local branch
rm "\$U/Z - renamed.mkv" 2>>"\$FT/d170-union.err" && [ ! -e "\$U/Z - renamed.mkv" ] && echo U8=ok
printf 'upgraded' > "\$U/Z - renamed.mkv" 2>>"\$FT/d170-union.err" && [ "\$(cat "\$U/Z - renamed.mkv")" = "upgraded" ] && [ -f "\$LB/Z - renamed.mkv" ] && echo U9=ok
# 6. "set permissions" on a library file
chmod 664 "\$U/x.mkv" 2>>"\$FT/d170-union.err" && echo U10=ok
echo "UTOP=\$(LC_ALL=C ls "\$U" | tr '\n' ',')"
fusermount3 -u "\$U" 2>/dev/null || fusermount -u "\$U" 2>/dev/null; echo U11=ok
EOS
)
if has "$U_OUT" NO_MERGERFS=1; then
  ok "mergerfs is not on the owner — the union rehearsal is skipped (not a failure)"
else
  uerr() { ssh "$OWNER" 'cat $HOME/fleet-test/d170-union.err; tail -4 $HOME/fleet-test/d130-view.log'; }
  has "$U_OUT" U0=ok && ok "a union of a local folder (RW) and the view (NC), with feederbox's options ($(val "$U_OUT" MERGERFS))" || fail "mergerfs mount: $(uerr)"
  has "$U_OUT" U1=ok && has "$U_OUT" U2=ok && ok "through the union: a verified move in place, and it reads" || fail "union rename: $U_OUT $(uerr)"
  has "$U_OUT" U3=ok && has "$U_OUT" U4=ok && ! has "$U_OUT" U4_ON_LOCAL=1 && ok "a new season folder lands on local; the rename into it stays on the view's branch (the path clone → our mkdir)" || fail "union rename into a new folder: $U_OUT $(uerr)"
  has "$U_OUT" U5=ok && ok "the emptied season folder is removed" || fail "union rmdir: $U_OUT $(uerr)"
  has "$U_OUT" U6=ok && has "$U_OUT" U7=ok && ok "the series folder, present on BOTH branches, renames on both — and the episode reads under the new name" || fail "union folder rename: $U_OUT $(uerr)"
  has "$U_OUT" U8=ok && has "$U_OUT" U9=ok && ok "an upgrade: the old file deleted through the union, the new one created at the same path (on local)" || fail "union upgrade: $U_OUT $(uerr)"
  has "$U_OUT" U10=ok && ok "chmod of a library file through the union" || fail "union chmod: $U_OUT $(uerr)"
  [ "$(val "$U_OUT" UTOP)" = "Show Renamed (2020),Z - renamed.mkv,a.mkv,big.mkv,empty,season,sub,x.mkv," ] && ok "the union lists exactly what was done" || fail "union listing: $(val "$U_OUT" UTOP)"
  J_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
L=\$FT/d130-edge-lib
[ "\$(cat "\$L/Show Renamed (2020)/s3/Show - S03E01.mkv")" = "e1e1" ] && [ ! -e "\$L/Show (2020)" ] && [ ! -e "\$L/Show Renamed (2020)/s2" ] && echo J1=ok
[ ! -e "\$L/Z - renamed.mkv" ] && "\$B/pvfs" --data-dir "\$RD" trash ls 2>/dev/null | grep -q "Z - renamed.mkv" && echo J2=ok
EOS
)
  has "$J_OUT" J1=ok && ok "the edge's disk: the episode is at Show Renamed (2020)/s3, the old folders are gone" || fail "edge disk after the union: $J_OUT"
  has "$J_OUT" J2=ok && ok "and the upgraded-away file is in the edge's trash" || fail "edge trash after the union: $J_OUT"
fi
gate union

say "F: the edge goes down — the fetched copy still reads, an unfetched one fails within the bound, ls stays instant"
STOP=$(ssh "$EDGE" "bash -s" <<EOS
$RH
stopd "\$FT/d130-edge.pid"
pgrep -f "pvfsd --mount \$R" >/dev/null && echo EDGE_STILL_UP || echo EDGE_DOWN
EOS
)
has "$STOP" EDGE_DOWN && ok "edge daemon stopped (verified: no pvfsd on its replica)" || fail "edge daemon still up: $STOP"
gate edge-down
F_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
[ "\$(cat "\$V/x.mkv")" = "xx" ] && echo F1=ok
# season/y.mkv was never read: no holder answers now. Time it, and time ls meanwhile.
( cat "\$V/season/y.mkv" >/dev/null 2>&1; echo "CAT_RC=\$?" ) > "\$FT/d130-cat.out" &
CATPID=\$!
sleep 2
t0=\$(date +%s.%N); ls "\$V" >/dev/null; t1=\$(date +%s.%N)
echo "LS_S=\$(python3 -c "print(round(\$t1-\$t0,3))")"
t0=\$(date +%s)
wait \$CATPID; t1=\$(date +%s)
cat "\$FT/d130-cat.out"
echo "FAIL_S=\$((t1-t0+2))"
EOS
)
has "$F_OUT" F1=ok && ok "x.mkv still reads from the hash store with the edge down" || fail "cached read: $F_OUT"
[ "$(val "$F_OUT" CAT_RC)" != "0" ] && ok "an unfetched edge file fails to read (no holder answers)" || fail "y.mkv read succeeded with the edge down?"
python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 0.5 else 1)" "$(val "$F_OUT" LS_S)" && ok "ls answered in $(val "$F_OUT" LS_S)s while the read waited" || fail "ls took $(val "$F_OUT" LS_S)s"
[ "$(val "$F_OUT" FAIL_S)" -lt 150 ] && ok "the failed read returned within the bound ($(val "$F_OUT" FAIL_S)s)" || fail "read hung: $(val "$F_OUT" FAIL_S)s"

say "F2 (D165): the bound — a remount with --cache-max 100M evicts the 600 MiB file at start"
B_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
V=\$FT/d130-view
"\$B/pvfs" umount "\$V" >/dev/null 2>&1 || fusermount3 -u "\$V" 2>/dev/null
for _ in \$(seq 1 40); do mountpoint -q "\$V" || break; sleep 0.25; done
nohup "\$B/pvfs" --data-dir "\$D" mount --view "\$V" --cache-max 100M --cache-age 1d >/dev/null 2>>"\$FT/d130-view.log" &
echo \$! > "\$FT/d130-view.pid"
for _ in \$(seq 1 40); do mountpoint -q "\$V" && break; sleep 0.25; done
mountpoint -q "\$V" && echo B1=ok
echo "BIG_LEFT=\$(find "\$D" -path '*/by-hash/*' -type f -size +100M | wc -l)"
echo "STORE_KB=\$(du -sk "\$(find "\$D" -type d -name by-hash | head -1)" | cut -f1)"
[ "\$(cat "\$V/a.mkv")" = "aaa" ] && echo B2=ok
EOS
)
has "$B_OUT" B1=ok && ok "remounted with --cache-max 100M" || fail "remount: $B_OUT"
[ "$(val "$B_OUT" BIG_LEFT)" = "0" ] && [ "$(val "$B_OUT" STORE_KB)" -lt 102400 ] && ok "the bound was applied at start: the store holds $(val "$B_OUT" STORE_KB) KB" || fail "bound: $B_OUT"
has "$B_OUT" B2=ok && ok "the mount serves on" || fail "a.mkv after remount"

say "G: stop the lab daemons and the mount (dirs kept under ~/fleet-test/d130-* for inspection)"
ssh "$OWNER" 'B='"$LABBIN"'; V=$HOME/fleet-test/d130-view; "$B/pvfs" umount "$V" >/dev/null 2>&1 || fusermount3 -u "$V" 2>/dev/null; kill "$(cat $HOME/fleet-test/d130-view.pid)" 2>/dev/null; kill "$(cat $HOME/fleet-test/d130-owner.pid)" 2>/dev/null; true' && ok "owner's mount and daemon stopped"
echo; echo "view pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
