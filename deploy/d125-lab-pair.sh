#!/bin/bash
# D125 item 9 — the milestone's exit criterion, on the two-machine lab
# fleet-test.sh already uses: two boxes, two catalogue regions, each
# cataloguing ITS OWN disk. The shared log learns two heads — and not one
# file event.
#   owner : presubuntu (192.168.0.184) — a fresh forest, `own-shelf` is its region
#   edge  : pvos-test  (192.168.0.138) — a replica, `edge-shelf` is its region,
#           owned through `region mark --catalogue --owner key:<edge>`
# Binaries: ~/.local/bin on both boxes, installed by the pipeline. Run from
# the Mac; nothing here touches production.
OWNER=chris@192.168.0.184; EDGE=chris@192.168.0.138; OWNER_IP=192.168.0.184
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
# every remote block gets these helpers prepended
RH='B=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d125-owner; R=$FT/d125-replica; D=$O/.pvfs; RD=$R/.pvfs
jget(){ python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
'

say "0: preflight — the D125 build on both boxes, a clean slate"
for h in "$OWNER" "$EDGE"; do
  v=$(ssh "$h" '"$HOME/.local/bin/pvfs" --version' 2>&1)
  has "$v" "ga67ad92" && ok "$h runs the D125 build ($v)" || fail "$h runs $v, not the D125 build"
  ssh "$h" 'pkill -f "pvfsd --mount $HOME/fleet-test/d125" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d125-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
EDGEKEY=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#EDGEKEY}" -eq 66 ] && ok "edge client identity $EDGEKEY" || fail "edge identity: $EDGEKEY"
# The edge's library exists BEFORE anything else so it is older than the
# settle window (15s) by the time the watch job first sees it.
ssh "$EDGE" 'L=$HOME/fleet-test/d125-edge-lib; mkdir -p "$L/season" "$L/unused"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"' \
  && ok "edge library staged (x.mkv, season/y.mkv, unused/)" || fail "edge library"
gate preflight

say "A: owner — forest, two catalogue regions, its own shelf catalogued, listener up"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d125-owner-lib; mkdir -p "\$L/sub" "\$L/empty"; printf aaa > "\$L/a.mkv"; printf bbbbb > "\$L/sub/b.mkv"
"\$B/pvfs" forest init --mount "\$O" >/dev/null 2>&1 || { echo INIT_FAILED; exit 0; }
INFO=\$("\$B/pvfs" --json --data-dir "\$D" info)
ROOT=\$(printf '%s' "\$INFO" | jget root_node_id); FID=\$(printf '%s' "\$INFO" | jget forest_id)
"\$B/pvfs" --forest "\$O" fleet enroll $EDGEKEY --rights rwa >/dev/null 2>&1 && echo A0=ok
OWN=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label own-shelf)
EDGESHELF=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label edge-shelf)
"\$B/pvfs" --json --data-dir "\$D" region mark "\$OWN" --catalogue | grep -q '"kind":"catalogue"' && echo A1=ok
"\$B/pvfs" --json --data-dir "\$D" region mark "\$EDGESHELF" --catalogue --owner key:$EDGEKEY | grep -q '"owner":"key:' && echo A2=ok
"\$B/pvfs" --data-dir "\$D" bind "\$OWN" "\$L" --hash-policy on_add >/dev/null && echo A3=ok
"\$B/pvfs" --data-dir "\$D" scan "\$OWN" >/dev/null && echo A4=ok
"\$B/pvfs" --json --data-dir "\$D" region entries "\$OWN" | python3 -c '
import json,sys; d=json.load(sys.stdin)
assert [(e["path"],e["kind"]) for e in d["entries"]]==[("a.mkv","file"),("empty","dir"),("sub","dir"),("sub/b.mkv","file")], d["entries"]
assert d["head"]["seq"]==1, d["head"]' && echo A5=ok
TIP0=\$(python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('select ifnull(max(seq),0) from events').fetchone()[0])" "\$D/log.db")
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7440 >/dev/null 2>"\$FT/d125-owner.log" &
echo \$! > "\$FT/d125-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7440 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$got" = "\$FID" ] && { echo A6=ok; break; }; sleep 0.5
done
echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "OWN=\$OWN"; echo "EDGESHELF=\$EDGESHELF"; echo "PIN=\$PIN"; echo "TIP0=\$TIP0"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
has "$A_OUT" A0=ok && ok "edge enrolled as a replicator (rwa at the root — replication needs admin; the REGION grant comes with the mark)" || fail "fleet enroll edge"
has "$A_OUT" A1=ok && ok "own-shelf marked catalogue" || fail "own-shelf mark"
has "$A_OUT" A2=ok && ok "edge-shelf marked catalogue, owned by the edge's key" || fail "edge-shelf mark --owner"
has "$A_OUT" A3=ok && ok "owner bound its shelf" || fail "owner bind"
has "$A_OUT" A4=ok && ok "owner scanned its shelf" || fail "owner scan"
has "$A_OUT" A5=ok && ok "owner's rows: two files, two folders (one empty), head seq 1" || fail "owner entries: $A_OUT"
has "$A_OUT" A6=ok && ok "owner daemon up on :7440" || fail "owner daemon"
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); OWN=$(val "$A_OUT" OWN); EDGESHELF=$(val "$A_OUT" EDGESHELF); PIN=$(val "$A_OUT" PIN); TIP0=$(val "$A_OUT" TIP0)
[ "${#PIN}" -eq 64 ] && ok "owner transport pin minted" || fail "pin: $PIN"
gate owner

say "B: edge — replica, sees both marks, binds its shelf LOCALLY, the watch job catalogues and publishes through the owner"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d125owner >/dev/null 2>&1; "\$B/pvfs" instance add d125owner $OWNER_IP:7440 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d125owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --json --data-dir "\$RD" region ls | grep -q "\"region\":\"$EDGESHELF\",\"marked_at\":[0-9]*,\"kind\":\"catalogue\"" && echo B3=ok
"\$B/pvfs" --data-dir "\$RD" bind "$EDGESHELF" "\$FT/d125-edge-lib" --hash-policy on_add >/dev/null 2>&1 && echo B4=ok
# The settle window (D112, 15s on max(mtime, ctime)) is real: a file younger
# than that gets no row on the pass that sees it. Let the staged library age
# past it before the first watch pass, so seq 1 is the whole shelf.
age=\$(( \$(date +%s) - \$(stat -c %Z "\$FT/d125-edge-lib/x.mkv") )); [ "\$age" -lt 17 ] && sleep \$(( 17 - age ))
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7441 >/dev/null 2>"\$FT/d125-edge.log" &
echo \$! > "\$FT/d125-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" serve enable follow >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable watch >/dev/null 2>&1 && echo B5=ok
for _ in \$(seq 1 90); do
  seq=\$("\$B/pvfs" --json --data-dir "\$RD" region entries "$EDGESHELF" 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["head"]["seq"] if d["head"] else 0)' 2>/dev/null || echo 0)
  [ "\$seq" = "1" ] && { echo B6=ok; break; }; sleep 2
done
"\$B/pvfs" --json --data-dir "\$RD" region entries "$EDGESHELF" | python3 -c '
import json,sys; d=json.load(sys.stdin)
assert [(e["path"],e["kind"]) for e in d["entries"]]==[("season","dir"),("season/y.mkv","file"),("unused","dir"),("x.mkv","file")], d["entries"]
print("EDGEHASH=" + d["head"]["hash"])' && echo B7=ok
echo "--- edge daemon log (tail) ---"; tail -5 "\$FT/d125-edge.log"
EOS
)
has "$B_OUT" B1=ok && ok "edge pinned the owner" || fail "instance add: $B_OUT"
has "$B_OUT" B2=ok && ok "replica shipped the owner's log" || fail "replica add"
has "$B_OUT" B3=ok && ok "the replica sees edge-shelf as a catalogue region" || fail "replica region ls"
has "$B_OUT" B4=ok && ok "edge bound its shelf locally (no write-through for a binding, D71 W4)" || fail "edge bind"
has "$B_OUT" B5=ok && ok "edge daemon up with follow + watch" || fail "edge serve jobs"
has "$B_OUT" B6=ok && ok "the watch job catalogued the shelf and published head seq 1 THROUGH the owner" || fail "no head within 180s: $B_OUT"
has "$B_OUT" B7=ok && ok "edge rows: two files, two folders (one empty)" || fail "edge entries"
EDGEHASH=$(val "$B_OUT" EDGEHASH)
gate edge

say "C: the log — two heads, zero file events; the owner attests the edge's manifest"
C_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
python3 - "\$D" $TIP0 "$EDGESHELF" "$OWN" <<'PY'
import sqlite3, sys, collections
d, tip0, edge, own = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
log = sqlite3.connect(f"file:{d}/log.db?mode=ro", uri=True)
kinds = collections.Counter(k for (k,) in log.execute("select kind from events where seq > ?", (tip0,)))
print("KINDS=" + ",".join(f"{k}:{n}" for k, n in sorted(kinds.items())))
files = sum(kinds[k] for k in ("NodeCreated","LinkCreated","FileLocationAdded","FolderBound","AddNode"))
print("FILE_EVENTS=%d" % files)
print("HEADS=%d" % kinds.get("SubRegionHead", 0))
idx = sqlite3.connect(f"file:{d}/index.db?mode=ro", uri=True)
for node, name in ((edge, "EDGE"), (own, "OWN")):
    seq, head, kind = idx.execute("select committed_seq, committed_head, kind from regions where node_id=?", (node,)).fetchone()
    print(f"{name}_HEAD={seq}:{head}:{kind}")
PY
EOS
)
echo "$C_OUT" | grep -E '^KINDS=' 
FE=$(val "$C_OUT" FILE_EVENTS); HEADS=$(val "$C_OUT" HEADS)
[ "$FE" = "0" ] && ok "zero file events after the marks (the exit criterion)" || fail "file events in the log: $FE ($C_OUT)"
[ "$HEADS" = "1" ] && ok "exactly one event since the owner's own head: the edge's SubRegionHead" || fail "heads since TIP0: $HEADS"
EH=$(val "$C_OUT" EDGE_HEAD)
[ "$EH" = "1:$EDGEHASH:catalogue" ] && ok "the owner attests the edge's manifest hash as edge-shelf's head" || fail "owner's view of edge-shelf: $EH vs $EDGEHASH"
has "$C_OUT" "OWN_HEAD=1:" && ok "own-shelf's head stands at seq 1" || fail "own-shelf head: $(val "$C_OUT" OWN_HEAD)"

say "D: stop the lab daemons (dirs kept under ~/fleet-test/d125-* for inspection)"
ssh "$OWNER" 'kill "$(cat $HOME/fleet-test/d125-owner.pid)" 2>/dev/null' && ok "owner daemon stopped"
ssh "$EDGE"  'kill "$(cat $HOME/fleet-test/d125-edge.pid)" 2>/dev/null' && ok "edge daemon stopped"
echo; echo "lab pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
