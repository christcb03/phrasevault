#!/bin/bash
# D131 item 4 — fleet health on the two-machine lab: the D129 pair (owner +
# edge, both announced) plus the `health` job on the owner: the edge is seen
# up with its jobs and free space; it stops — one miss is not an outage, two
# are, dated from the first; it returns — up again.
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
RH='B=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d131-owner; R=$FT/d131-replica; D=$O/.pvfs; RD=$R/.pvfs
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

say "0: preflight — the D131 build on both boxes, a clean slate"
VA=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --version' 2>&1); VB=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --version' 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" '"$HOME/.local/bin/pvfs" fleet health --help >/dev/null 2>&1' && ok "$h has fleet health" || fail "$h: not a D131 build"
  ssh "$h" 'pkill -f "pvfsd --mount $HOME/fleet-test/d131" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d131-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
AKEY=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
ssh "$EDGE" 'L=$HOME/fleet-test/d131-edge-lib; mkdir -p "$L/season" "$L/unused"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"' \
  && ok "edge library staged (x.mkv, season/y.mkv, unused/)" || fail "edge library"
gate preflight

say "A: owner — forest, two catalogue regions, its shelf catalogued, announced, listener up with the catalogue job"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d131-owner-lib; mkdir -p "\$L/sub" "\$L/empty"; printf aaa > "\$L/a.mkv"; printf bbbbb > "\$L/sub/b.mkv"
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
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7448 >/dev/null 2>"\$FT/d131-owner.log" &
echo \$! > "\$FT/d131-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
stopd "\$FT/d131-owner.pid"
"\$B/pvfs" --data-dir "\$D" fleet announce $OWNER_IP:7448 >/dev/null 2>&1 && echo A6=ok
"\$B/pvfs" --data-dir "\$D" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable catalogue >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable health >/dev/null 2>&1 && echo A7=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7448 >/dev/null 2>>"\$FT/d131-owner.log" &
echo \$! > "\$FT/d131-owner.pid"
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7448 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
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
has "$A_OUT" A7=ok && ok "owner enabled watch + catalogue + health jobs" || fail "owner serve enable"
has "$A_OUT" A8=ok && ok "owner daemon up on :7448" || fail "owner daemon: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d131-owner.log')"
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); OWN=$(val "$A_OUT" OWN); EDGESHELF=$(val "$A_OUT" EDGESHELF); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "owner transport pin minted" || fail "pin: $PIN"
gate owner

say "B: edge — replica, binds its shelf, announces, publishes its head through the owner"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d131owner >/dev/null 2>&1; "\$B/pvfs" instance add d131owner $OWNER_IP:7448 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d131owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --data-dir "\$RD" bind "$EDGESHELF" "\$FT/d131-edge-lib" --hash-policy on_add >/dev/null 2>&1 && echo B3=ok
age=\$(( \$(date +%s) - \$(stat -c %Z "\$FT/d131-edge-lib/x.mkv") )); [ "\$age" -lt 17 ] && sleep \$(( 17 - age ))
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7449 >/dev/null 2>"\$FT/d131-edge.log" &
echo \$! > "\$FT/d131-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" fleet announce $EDGE_IP:7449 >/dev/null 2>&1 && echo B4=ok
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
has "$B_OUT" B6=ok && ok "edge published edge-shelf head 1 through the owner" || fail "no edge head within 180s: $(ssh "$EDGE" 'tail -3 $HOME/fleet-test/d131-edge.log')"
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

say "D: the owner observes the edge — up, jobs, free space"
D_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" --json --data-dir "\$D" fleet health --now > "\$FT/d131-h1.json" 2>"\$FT/d131-h1.err" && echo D1=ok
python3 - "\$FT/d131-h1.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1])); peers=r["peers"]
assert len(peers)==1, peers
p=list(peers.values())[0]
assert p["last"]["reachable"] and p["last"]["forest_ok"] and p["misses"]==0, p
jobs={j["name"]:j for j in p["last"]["jobs"]}
assert "follow" in jobs and "watch" in jobs, jobs
assert p["last"]["conflicts"]==0 and p["last"]["stale"]==0, p["last"]
assert p["last"]["capacity"] and p["last"]["capacity"][1]>0, p["last"]["capacity"]
assert p["version"], p
print("EDGE_ADDR=%s" % p["addr"])
PY
"\$B/pvfs" --data-dir "\$D" fleet health | grep -q "  up" && echo D2=ok
"\$B/pvfs" --data-dir "\$D" fleet health | grep -q "free of" && echo D3=ok
EOS
)
has "$D_OUT" D1=ok && ok "fleet health --now polled the edge" || fail "poll: $D_OUT $(ssh "$OWNER" 'cat $HOME/fleet-test/d131-h1.err')"
[ "$(val "$D_OUT" EDGE_ADDR)" = "$EDGE_IP:7449" ] && ok "the edge is seen up at its announced address, with follow + watch, 0 conflicts, 0 stale, a measured disk, a version" || fail "edge record: $D_OUT"
has "$D_OUT" D2=ok && ok "the table says up" || fail "table"
has "$D_OUT" D3=ok && ok "the table shows free space" || fail "free space line"
gate observe

say "E: the edge stops — one miss is a restart, two are an outage dated from the first; then it returns"
STOP=$(ssh "$EDGE" "bash -s" <<EOS
$RH
stopd "\$FT/d131-edge.pid"
pgrep -f "pvfsd --mount \$R" >/dev/null && echo EDGE_STILL_UP || echo EDGE_DOWN
EOS
)
has "$STOP" EDGE_DOWN && ok "edge daemon stopped (verified)" || fail "edge still up: $STOP"
E_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" --json --data-dir "\$D" fleet health --now | python3 -c '
import json,sys
p=list(json.load(sys.stdin)["peers"].values())[0]
assert not p["last"]["reachable"] and p["misses"]==1 and p["unreachable_since_ms"], p
print("FIRST_MISS=%d" % p["unreachable_since_ms"])' && echo E1=ok
"\$B/pvfs" --data-dir "\$D" fleet health | grep -q "missed once" && echo E2=ok
"\$B/pvfs" --json --data-dir "\$D" fleet health --now | python3 -c '
import json,sys
p=list(json.load(sys.stdin)["peers"].values())[0]
assert p["misses"]==2 and p["unreachable_since_ms"], p
print("SECOND=%d" % p["unreachable_since_ms"])' && echo E3=ok
"\$B/pvfs" --data-dir "\$D" fleet health | grep -q "DOWN — not answering since" && echo E4=ok
EOS
)
has "$E_OUT" E1=ok && ok "first poll after the stop: missed once, dated" || fail "first miss: $E_OUT"
has "$E_OUT" E2=ok && ok "the table says 'missed once, not yet called down'" || fail "table after one miss"
has "$E_OUT" E3=ok && [ "$(val "$E_OUT" FIRST_MISS)" = "$(val "$E_OUT" SECOND)" ] && ok "second poll: DOWN, dated from the FIRST miss" || fail "second miss: $E_OUT"
has "$E_OUT" E4=ok && ok "the table says DOWN — not answering since" || fail "table after two misses"
ssh "$EDGE" "bash -s" <<EOS >/dev/null 2>&1
$RH
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7449 >/dev/null 2>>"\$FT/d131-edge.log" &
echo \$! > "\$FT/d131-edge.pid"
for _ in \$(seq 1 40); do "\$B/pvfs" --json --data-dir "\$RD" serve status >/dev/null 2>&1 && break; sleep 0.5; done
EOS
ok "edge daemon started again"
F_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" --json --data-dir "\$D" fleet health --now | python3 -c '
import json,sys
p=list(json.load(sys.stdin)["peers"].values())[0]
assert p["last"]["reachable"] and p["misses"]==0 and p["unreachable_since_ms"] is None, p' && echo F1=ok
"\$B/pvfs" --data-dir "\$D" fleet health | grep -q "  up" && echo F2=ok
"\$B/pvfs" --json --data-dir "\$D" serve status | python3 -c '
import json,sys
j={x["job"]:x for x in json.load(sys.stdin)["jobs"]}
assert j["health"]["enabled"] and j["health"]["last_error"] is None, j["health"]' && echo F3=ok
EOS
)
has "$F_OUT" F1=ok && ok "next poll: up again, streak cleared" || fail "recovery: $F_OUT"
has "$F_OUT" F2=ok && ok "the table says up" || fail "table after recovery"
has "$F_OUT" F3=ok && ok "the owner's health job runs clean" || fail "health job: $F_OUT"

say "G: stop the lab daemons (dirs kept under ~/fleet-test/d131-* for inspection)"
ssh "$EDGE" 'kill "$(cat $HOME/fleet-test/d131-edge.pid)" 2>/dev/null; true' && ok "edge daemon stopped"
ssh "$OWNER" 'kill "$(cat $HOME/fleet-test/d131-owner.pid)" 2>/dev/null; true' && ok "owner daemon stopped"
echo; echo "health pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
