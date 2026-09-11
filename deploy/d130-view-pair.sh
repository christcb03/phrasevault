#!/bin/bash
# D130 item 6 — the VIEW MOUNT on the two-machine lab: the D129 pair (both boxes
# hold the union) plus `pvfs mount --view` on the owner: its own bytes read from
# disk, the edge's read through by content hash, kept, and served on when the
# edge is gone.
#   owner : presubuntu (192.168.0.184) — forest, `own-shelf` catalogued here
#   edge  : pvos-test  (192.168.0.138) — replica, `edge-shelf` catalogued there
# Binaries: ~/.local/bin on both boxes, installed by the pipeline. Run from
# the Mac; nothing here touches production.
OWNER=chris@192.168.0.184; EDGE=chris@192.168.0.138; OWNER_IP=192.168.0.184; EDGE_IP=192.168.0.138
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
RH='B=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d130-owner; R=$FT/d130-replica; D=$O/.pvfs; RD=$R/.pvfs
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
VA=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --version' 2>&1); VB=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --version' 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" '"$HOME/.local/bin/pvfs" mount --help >/dev/null 2>&1' && ok "$h has pvfs mount" || fail "$h: not a D130 build"
  ssh "$h" 'pkill -f "pvfsd --mount $HOME/fleet-test/d130" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d130-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
AKEY=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
ssh "$EDGE" 'L=$HOME/fleet-test/d130-edge-lib; mkdir -p "$L/season" "$L/unused"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"' \
  && ok "edge library staged (x.mkv, season/y.mkv, unused/)" || fail "edge library"
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
e=rows[sys.argv[1]]; assert e["local"] is False and e["fetched_at"] and e["entries"]==4, e
o=rows[sys.argv[2]]; assert o["local"] is True and o["stale"] is False, o' "$EDGESHELF" "$OWN" && echo C2=ok
"\$B/pvfs" --json --data-dir "\$D" serve status 2>/dev/null | grep -q '"stale":0' && echo C3=ok
EOS
)
has "$C_OUT" C1=ok && ok "owner fetched edge-shelf at head 1 (the catalogue job)" || fail "owner never fetched: $C_OUT"
[ "$(val "$C_OUT" OWNER_TOP)" = "a.mkv,empty,season,sub,unused,x.mkv" ] && ok "owner's view is the union of both shelves" || fail "owner top: $(val "$C_OUT" OWNER_TOP)"
[ "$(val "$C_OUT" OWNER_SEASON)" = "season/y.mkv" ] && ok "owner sees the edge's season/y.mkv" || fail "owner season: $(val "$C_OUT" OWNER_SEASON)"
has "$C_OUT" C2=ok && ok "region ls: edge-shelf fetched (4 rows), own-shelf live" || fail "owner region ls: $C_OUT"
has "$C_OUT" C3=ok && ok "owner's serve status: stale 0" || fail "serve status stale: $C_OUT"
D_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitr "\$RD" "$OWN" 75 "1/1/False" && echo D1=ok
echo "EDGE_TOP=\$(vpaths "\$RD" "")"
echo "EDGE_SUB=\$(vpaths "\$RD" sub)"
EOS
)
has "$D_OUT" D1=ok && ok "edge fetched own-shelf at head 1" || fail "edge never fetched: $D_OUT"
[ "$(val "$D_OUT" EDGE_TOP)" = "a.mkv,empty,season,sub,unused,x.mkv" ] && ok "edge's view is the same union" || fail "edge top: $(val "$D_OUT" EDGE_TOP)"
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
[ "$(val "$E_OUT" OWNER_TOP2)" = "a.mkv,empty,season,sub,unused,x.mkv,z.mkv" ] && ok "owner's view shows z.mkv" || fail "owner top2: $(val "$E_OUT" OWNER_TOP2)"
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
grep -c "reading x.mkv through by hash" "\$FT/d130-view.log" | sed 's/^/LOGGED=/'
[ "\$(cat "\$V/z.mkv")" = "zzz" ] && echo E5=ok
EOS
)
has "$E_OUT" E1=ok && ok "the view is mounted on the owner" || fail "view mount: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d130-view.log')"
[ "$(val "$E_OUT" TOP)" = "a.mkv empty season sub unused x.mkv z.mkv " ] && ok "ls shows the union of both shelves" || fail "ls: $(val "$E_OUT" TOP)"
has "$E_OUT" E2=ok && ok "a.mkv (the owner's own bytes) reads from disk" || fail "a.mkv"
has "$E_OUT" E3=ok && ok "sub/b.mkv reads from disk" || fail "sub/b.mkv"
has "$E_OUT" E4=ok && ok "x.mkv (only the edge holds it) read through by hash in $(val "$E_OUT" READTHROUGH_S)s" || fail "x.mkv read-through: $E_OUT $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d130-view.log')"
has "$E_OUT" STORE= && ok "the bytes landed in the hash store" || fail "hash store empty: $E_OUT"
[ "$(val "$E_OUT" LOGGED)" = "1" ] && ok "the mount logged one read-through" || fail "read-through log: $(val "$E_OUT" LOGGED)"
has "$E_OUT" E5=ok && ok "z.mkv (added later on the edge) reads through too" || fail "z.mkv"
gate mount

say "F: the edge goes down — the fetched copy still reads, an unfetched one fails within the bound, ls stays instant"
ssh "$EDGE" "bash -s" <<EOS
$RH
stopd "\$FT/d130-replica.pid"
EOS
ok "edge daemon stopped"
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

say "G: stop the lab daemons and the mount (dirs kept under ~/fleet-test/d130-* for inspection)"
ssh "$OWNER" 'B=$HOME/.local/bin; V=$HOME/fleet-test/d130-view; "$B/pvfs" umount "$V" >/dev/null 2>&1 || fusermount3 -u "$V" 2>/dev/null; kill "$(cat $HOME/fleet-test/d130-view.pid)" 2>/dev/null; kill "$(cat $HOME/fleet-test/d130-owner.pid)" 2>/dev/null; true' && ok "owner's mount and daemon stopped"
echo; echo "view pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
