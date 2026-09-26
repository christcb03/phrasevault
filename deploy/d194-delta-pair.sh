#!/bin/bash
# PVOS D194 — a catalogue head bump writes only what changed, on the
# two-machine pair D129 uses: each box catalogues its own shelf and fetches
# the other's; the edge's shelf then changes (a file added; a file changed
# and another removed), and the owner's catalogue job logs each install's
# delta — `(+a changed c removed r)` — while its rows and view follow.
#   owner : presubuntu (192.168.0.184:7494) — forest, `own-shelf` catalogued here
#   edge  : pvos-test  (192.168.0.138:7495) — replica, `edge-shelf` catalogued there
# Binaries: ~/.local/bin on both boxes, installed by the pipeline. Run from
# the Mac; nothing here touches production or the lab.
OWNER=chris@192.168.0.184; EDGE=chris@192.168.0.138; OWNER_IP=192.168.0.184; EDGE_IP=192.168.0.138
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
RH='B=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d194-owner; R=$FT/d194-replica; D=$O/.pvfs; RD=$R/.pvfs
jget(){ python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
stopd(){ p=$(cat "$1" 2>/dev/null) || return 0; kill "$p" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done; echo "STILL_RUNNING $p"; }
# region ls as "held/head/stale" for one region
rstat(){ "$B/pvfs" --json --data-dir "$1" region ls 2>/dev/null | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r[\"region\"]==sys.argv[1]: print(\"%s/%s/%s\" % (r.get(\"held\"), r.get(\"head\"), r.get(\"stale\")))" "$2"; }
# wait until rstat matches, up to N×2 seconds
waitr(){ for _ in $(seq 1 "$3"); do [ "$(rstat "$1" "$2")" = "$4" ] && return 0; sleep 2; done; echo "TIMEOUT rstat=$(rstat "$1" "$2")"; return 1; }
# the rows held here for a region, as path:size,…
rrows(){ "$B/pvfs" --json --data-dir "$1" region entries "$2" 2>/dev/null | python3 -c "import json,sys; print(\",\".join(\"%s:%s\" % (e[\"path\"], e[\"size\"]) for e in json.load(sys.stdin)[\"entries\"]))"; }
# the install lines of a daemon log for a region: "seq rows added changed removed", one per line
installs(){ python3 -c "
import re,sys
for l in open(sys.argv[1]):
    m = re.match(r\"pvfsd: catalogue (\w{8}) at head (\d+): (\d+) rows \(\+(\d+) changed (\d+) removed (\d+)\)\", l)
    if m and m.group(1) == sys.argv[2][:8]: print(*m.groups()[1:])" "$1" "$2"; }
'

say "0: preflight — the same build on both boxes, free ports, a clean slate"
VA=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --version' 2>&1); VB=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --version' 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" 'pkill -f "[p]vfsd --mount $HOME/fleet-test/d194" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d194-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
  busy=$(ssh "$h" 'ss -ltn | grep -Eo ":749[45] " | tr -d " " | tr "\n" " "')
  [ -z "$busy" ] && ok "$h: ports 7494–7495 free" || fail "$h: ports in use: $busy"
done
AKEY=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
ssh "$EDGE" 'L=$HOME/fleet-test/d194-edge-lib; mkdir -p "$L/season" "$L/unused"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"' \
  && ok "edge library staged (x.mkv, season/y.mkv, unused/)" || fail "edge library"
gate preflight

say "A: owner — forest, two catalogue regions, its shelf catalogued, announced, listener up with the catalogue job"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d194-owner-lib; mkdir -p "\$L/sub" "\$L/empty"; printf aaa > "\$L/a.mkv"; printf bbbbb > "\$L/sub/b.mkv"
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
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7494 >/dev/null 2>"\$FT/d194-owner.log" &
echo \$! > "\$FT/d194-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
stopd "\$FT/d194-owner.pid"
"\$B/pvfs" --data-dir "\$D" fleet announce $OWNER_IP:7494 >/dev/null 2>&1 && echo A6=ok
"\$B/pvfs" --data-dir "\$D" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable catalogue >/dev/null 2>&1 && echo A7=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7494 >/dev/null 2>>"\$FT/d194-owner.log" &
echo \$! > "\$FT/d194-owner.pid"
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7494 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$got" = "\$FID" ] && { echo A8=ok; break; }; sleep 0.5
done
echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "OWN=\$OWN"; echo "EDGESHELF=\$EDGESHELF"; echo "PIN=\$PIN"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
has "$A_OUT" A0=ok && ok "edge enrolled (rwa)" || fail "enroll edge"
has "$A_OUT" A1=ok && ok "owner's own client key enrolled" || fail "enroll A"
has "$A_OUT" A2=ok && ok "own-shelf marked catalogue" || fail "own-shelf mark"
has "$A_OUT" A3=ok && ok "edge-shelf marked catalogue, owned by the edge's key" || fail "edge-shelf mark"
has "$A_OUT" A4=ok && ok "owner bound its shelf" || fail "owner bind"
has "$A_OUT" A5=ok && ok "owner scanned its shelf" || fail "owner scan"
has "$A_OUT" A6=ok && ok "owner announced its endpoint" || fail "owner announce"
has "$A_OUT" A7=ok && ok "owner enabled watch + catalogue jobs" || fail "owner serve enable"
has "$A_OUT" A8=ok && ok "owner daemon up on :7494" || fail "owner daemon: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d194-owner.log')"
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); OWN=$(val "$A_OUT" OWN); EDGESHELF=$(val "$A_OUT" EDGESHELF); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "owner transport pin minted" || fail "pin: $PIN"
gate owner

say "B: edge — replica, binds its shelf, announces, publishes its head through the owner"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d194owner >/dev/null 2>&1; "\$B/pvfs" instance add d194owner $OWNER_IP:7494 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d194owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --data-dir "\$RD" bind "$EDGESHELF" "\$FT/d194-edge-lib" --hash-policy on_add >/dev/null 2>&1 && echo B3=ok
age=\$(( \$(date +%s) - \$(stat -c %Z "\$FT/d194-edge-lib/x.mkv") )); [ "\$age" -lt 17 ] && sleep \$(( 17 - age ))
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7495 >/dev/null 2>"\$FT/d194-edge.log" &
echo \$! > "\$FT/d194-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" fleet announce $EDGE_IP:7495 >/dev/null 2>&1 && echo B4=ok
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
has "$B_OUT" B4=ok && ok "edge announced its endpoint" || fail "edge announce"
has "$B_OUT" B5=ok && ok "edge daemon up with follow + watch + catalogue" || fail "edge serve jobs"
has "$B_OUT" B6=ok && ok "edge published edge-shelf head 1" || fail "no edge head within 180s: $(ssh "$EDGE" 'tail -3 $HOME/fleet-test/d194-edge.log')"
gate edge

say "C: each box fetches the other's shelf — a first install is all additions"
C_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitr "\$D" "$EDGESHELF" 75 "1/1/False" && echo C1=ok
echo "INSTALLS=\$(installs "\$FT/d194-owner.log" "$EDGESHELF" | tr "\n" ";")"
echo "ROWS=\$(rrows "\$D" "$EDGESHELF")"
EOS
)
has "$C_OUT" C1=ok && ok "owner fetched edge-shelf at head 1" || fail "owner never fetched: $C_OUT"
[ "$(val "$C_OUT" INSTALLS)" = "1 4 4 0 0;" ] && ok "owner logged head 1: 4 rows (+4 changed 0 removed 0)" || fail "owner installs: $(val "$C_OUT" INSTALLS)"
[ "$(val "$C_OUT" ROWS)" = "season:0,season/y.mkv:4,unused:0,x.mkv:2" ] && ok "owner holds the edge's 4 rows" || fail "owner rows: $(val "$C_OUT" ROWS)"
D_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitr "\$RD" "$OWN" 75 "1/1/False" && echo D1=ok
echo "INSTALLS=\$(installs "\$FT/d194-edge.log" "$OWN" | tr "\n" ";")"
EOS
)
has "$D_OUT" D1=ok && ok "edge fetched own-shelf at head 1" || fail "edge never fetched: $D_OUT"
[ "$(val "$D_OUT" INSTALLS)" = "1 4 4 0 0;" ] && ok "edge logged head 1: 4 rows (+4 changed 0 removed 0)" || fail "edge installs: $(val "$D_OUT" INSTALLS)"
gate fetch

say "D: a file added on the edge — the owner's install writes one row"
ssh "$EDGE" 'printf zzz > "$HOME/fleet-test/d194-edge-lib/z.mkv"' && ok "z.mkv added on the edge"
E_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
for _ in \$(seq 1 90); do [ "\$(rstat "\$D" "$EDGESHELF" | cut -d/ -f2)" = "2" ] && break; sleep 2; done
waitr "\$D" "$EDGESHELF" 75 "2/2/False" && echo E1=ok
echo "INSTALLS=\$(installs "\$FT/d194-owner.log" "$EDGESHELF" | tr "\n" ";")"
echo "ROWS=\$(rrows "\$D" "$EDGESHELF")"
EOS
)
has "$E_OUT" E1=ok && ok "owner caught up to head 2" || fail "owner stuck: $E_OUT"
[ "$(val "$E_OUT" INSTALLS)" = "1 4 4 0 0;2 5 1 0 0;" ] && ok "owner logged head 2: 5 rows (+1 changed 0 removed 0)" || fail "owner installs: $(val "$E_OUT" INSTALLS)"
[ "$(val "$E_OUT" ROWS)" = "season:0,season/y.mkv:4,unused:0,x.mkv:2,z.mkv:3" ] && ok "owner holds z.mkv" || fail "owner rows: $(val "$E_OUT" ROWS)"
gate add

say "E: a file changed and another removed on the edge — one row changed, one removed, whatever heads carry them"
ssh "$EDGE" 'L=$HOME/fleet-test/d194-edge-lib; printf xxxxxxx > "$L/x.mkv"; rm "$L/season/y.mkv"' && ok "x.mkv rewritten (2 → 7 bytes), season/y.mkv removed"
F_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
want="season:0,unused:0,x.mkv:7,z.mkv:3"
for _ in \$(seq 1 120); do
  s=\$(rstat "\$D" "$EDGESHELF"); h=\$(printf '%s' "\$s" | cut -d/ -f1)
  [ "\$(rrows "\$D" "$EDGESHELF")" = "\$want" ] && [ "\${s##*/}" = "False" ] && { echo F1=ok; echo "HELD=\$h"; break; }
  sleep 2
done
echo "INSTALLS=\$(installs "\$FT/d194-owner.log" "$EDGESHELF" | tr "\n" ";")"
echo "ROWS=\$(rrows "\$D" "$EDGESHELF")"
EOS
)
has "$F_OUT" F1=ok && ok "owner holds x.mkv at 7 bytes and no season/y.mkv, not stale (head $(val "$F_OUT" HELD))" || fail "owner rows: $(val "$F_OUT" ROWS)"
LATER=$(val "$F_OUT" INSTALLS | tr ';' '\n' | awk '$1 > 2 { a += $3; c += $4; r += $5; n = $2 } END { printf "%d %d %d %d", a, c, r, n }')
[ "$LATER" = "0 1 1 4" ] && ok "owner's installs after head 2 wrote +0 changed 1 removed 1, ending at 4 rows ($(val "$F_OUT" INSTALLS))" || fail "owner installs after head 2: $LATER ($(val "$F_OUT" INSTALLS))"
gate change

say "F: stop the pair's daemons (dirs kept under ~/fleet-test/d194-* for inspection)"
ssh "$EDGE" 'kill "$(cat $HOME/fleet-test/d194-edge.pid)" 2>/dev/null' && ok "edge daemon stopped"
ssh "$OWNER" 'kill "$(cat $HOME/fleet-test/d194-owner.pid)" 2>/dev/null' && ok "owner daemon stopped"
echo; echo "delta pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
