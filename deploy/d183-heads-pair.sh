#!/bin/bash
# PVOS D183 — the owner out of the daily path, on the two-machine lab the D129
# pair uses, with a THIRD instance so two replicas can trade heads:
#   owner : presubuntu (192.168.0.184:7471) — the forest; binds nothing
#   edge  : pvos-test  (192.168.0.138:7472) — replica, catalogues edge-shelf
#   near  : presubuntu (192.168.0.184:7473) — replica with its OWN client
#           identity (XDG_CONFIG_HOME) and socket dir, catalogues near-shelf
# The owner stops. Both replicas keep cataloguing: each publishes its head
# locally (pending), the other takes it as a signed claim and fetches the
# manifest from it, and its view shows the new files — with the owner down the
# whole time. The owner comes back: each region's pending head commits as ONE
# row (the newest), and the provisional heads give way to the committed ones.
# Binaries: ~/.local/bin on both boxes, installed by the pipeline. Run from the
# Mac; nothing here touches production.
OWNER=chris@192.168.0.184; EDGE=chris@192.168.0.138; OWNER_IP=192.168.0.184; EDGE_IP=192.168.0.138
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
RH='B=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d183-owner; R=$FT/d183-edge; N=$FT/d183-near; D=$O/.pvfs; RD=$R/.pvfs; ND=$N/.pvfs
# near is a second daemon of the SAME forest on the owner box: its own client
# identity, and its own socket dir. The socket is <dir>/<forest_id>.sock, so
# sharing /tmp/pvfs would replace the socket of the owner with that of near.
NX="env XDG_CONFIG_HOME=$FT/d183-near-xdg PVFS_SOCKET_DIR=$FT/d183-near-sock"
envfor(){ [ "$1" = "$ND" ] && printf "%s" "$NX"; }
jget(){ python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
stopd(){ p=$(cat "$1" 2>/dev/null) || return 0; kill "$p" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done; echo "STILL_RUNNING $p"; }
# region ls for one region as held/head/committed/provisional/pending/stale
rq(){ $(envfor "$1") "$B/pvfs" --json --data-dir "$1" region ls 2>/dev/null | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r[\"region\"]==sys.argv[1]: print(\"%s/%s/%s/%s/%s/%s\" % (r.get(\"held\"), r.get(\"head\"), r.get(\"committed\"), r.get(\"provisional\"), r.get(\"pending\"), r.get(\"stale\")))" "$2"; }
# wait until rq matches, up to N×2 seconds
waitq(){ for _ in $(seq 1 "$3"); do [ "$(rq "$1" "$2")" = "$4" ] && return 0; sleep 2; done; echo "TIMEOUT rq=$(rq "$1" "$2") want=$4"; return 1; }
vpaths(){ $(envfor "$1") "$B/pvfs" --json --data-dir "$1" view ls "$2" 2>/dev/null | python3 -c "import json,sys; print(\",\".join(e[\"path\"] for e in json.load(sys.stdin)))"; }
heads(){ python3 -c "import sqlite3,sys; c=sqlite3.connect(\"file:\"+sys.argv[1]+\"?mode=ro\", uri=True); print(c.execute(\"SELECT COUNT(*) FROM events WHERE kind = ?\", (\"SubRegionHead\",)).fetchone()[0])" "$D/log.db"; }
# the settle rule: a file younger than 15 s is not catalogued yet
settle(){ age=$(( $(date +%s) - $(stat -c %Z "$1") )); [ "$age" -lt 17 ] && sleep $(( 17 - age )); return 0; }
'

say "0: preflight — the same build on both boxes, free ports, a clean slate"
VA=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --version' 2>&1); VB=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --version' 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" 'pkill -f "[p]vfsd --mount $HOME/fleet-test/d183" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d183-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
  busy=$(ssh "$h" 'ss -ltn | grep -Eo ":747[123] " | tr -d " " | tr "\n" " "')
  [ -z "$busy" ] && ok "$h: ports 7471–7473 free" || fail "$h: ports in use: $busy"
done
AKEY=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
NEARKEY=$(ssh "$OWNER" 'XDG_CONFIG_HOME=$HOME/fleet-test/d183-near-xdg "$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && [ "${#NEARKEY}" -eq 66 ] && ok "client identities (near has its own)" || fail "identities: A=$AKEY E=$EDGEKEY N=$NEARKEY"
[ "$NEARKEY" != "$AKEY" ] && ok "near's key is not the owner box's" || fail "near shares the owner box's key"
ssh "$EDGE" 'L=$HOME/fleet-test/d183-edge-lib; mkdir -p "$L/season"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"' \
  && ok "edge library staged (x.mkv, season/y.mkv)" || fail "edge library"
ssh "$OWNER" 'L=$HOME/fleet-test/d183-near-lib; mkdir -p "$L"; printf nnn > "$L/n.mkv"' \
  && ok "near library staged (n.mkv)" || fail "near library"
gate preflight

say "A: owner — forest, both replicas enrolled, two catalogue regions each owned by one of them"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" forest init --mount "\$O" >/dev/null 2>&1 || { echo INIT_FAILED; exit 0; }
INFO=\$("\$B/pvfs" --json --data-dir "\$D" info)
ROOT=\$(printf '%s' "\$INFO" | jget root_node_id); FID=\$(printf '%s' "\$INFO" | jget forest_id)
"\$B/pvfs" --forest "\$O" fleet enroll $EDGEKEY --rights rwa >/dev/null 2>&1 && echo A0=ok
"\$B/pvfs" --forest "\$O" fleet enroll $NEARKEY --rights rwa >/dev/null 2>&1 && echo A1=ok
"\$B/pvfs" --forest "\$O" fleet enroll $AKEY --rights rwa >/dev/null 2>&1
EDGESHELF=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label edge-shelf)
NEARSHELF=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label near-shelf)
"\$B/pvfs" --json --data-dir "\$D" region mark "\$EDGESHELF" --catalogue --owner key:$EDGEKEY | grep -q '"owner":"key:' && echo A2=ok
"\$B/pvfs" --json --data-dir "\$D" region mark "\$NEARSHELF" --catalogue --owner key:$NEARKEY | grep -q '"owner":"key:' && echo A3=ok
"\$B/pvfs" --json --data-dir "\$D" region ls | grep -q '"pending":' && echo A4=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7471 >/dev/null 2>"\$FT/d183-owner.log" &
echo \$! > "\$FT/d183-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "EDGESHELF=\$EDGESHELF"; echo "NEARSHELF=\$NEARSHELF"; echo "PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
has "$A_OUT" A0=ok && ok "edge enrolled (rwa)" || fail "enroll edge"
has "$A_OUT" A1=ok && ok "near enrolled (rwa)" || fail "enroll near"
has "$A_OUT" A2=ok && ok "edge-shelf: catalogue, owned by the edge's key" || fail "edge-shelf mark"
has "$A_OUT" A3=ok && ok "near-shelf: catalogue, owned by near's key" || fail "near-shelf mark"
has "$A_OUT" A4=ok && ok "a D183 build (region ls reports pending heads)" || fail "not a D183 build: region ls has no pending"
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); EDGESHELF=$(val "$A_OUT" EDGESHELF); NEARSHELF=$(val "$A_OUT" NEARSHELF); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "owner listening on :7471" || fail "pin: $PIN"
gate owner

say "B: edge — replica on pvos-test, binds edge-shelf, announces, publishes head 1 through the owner"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d183owner >/dev/null 2>&1; "\$B/pvfs" instance add d183owner $OWNER_IP:7471 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d183owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --data-dir "\$RD" bind "$EDGESHELF" "\$FT/d183-edge-lib" --hash-policy on_add >/dev/null 2>&1 && echo B3=ok
settle "\$FT/d183-edge-lib/x.mkv"
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7472 >/dev/null 2>"\$FT/d183-edge.log" &
echo \$! > "\$FT/d183-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" fleet announce $EDGE_IP:7472 >/dev/null 2>&1 && echo B4=ok
"\$B/pvfs" --data-dir "\$RD" serve enable follow >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable catalogue >/dev/null 2>&1 && echo B5=ok
waitq "\$RD" "$EDGESHELF" 90 "1/1/1/False/None/False" && echo B6=ok
EOS
)
has "$B_OUT" B1=ok && ok "edge pinned the owner" || fail "instance add: $B_OUT"
has "$B_OUT" B2=ok && ok "edge shipped the owner's log" || fail "replica add"
has "$B_OUT" B3=ok && ok "edge bound edge-shelf" || fail "edge bind"
has "$B_OUT" B4=ok && ok "edge announced $EDGE_IP:7472 (through the owner)" || fail "edge announce"
has "$B_OUT" B5=ok && ok "edge daemon up: follow + watch + catalogue" || fail "edge serve jobs"
has "$B_OUT" B6=ok && ok "edge-shelf head 1 committed (live, nothing pending)" || fail "no edge head: $B_OUT $(ssh "$EDGE" 'tail -3 $HOME/fleet-test/d183-edge.log')"
gate edge

say "C: near — a second replica on presubuntu with its own identity, binds near-shelf"
C_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
\$NX "\$B/pvfs" instance rm d183owner >/dev/null 2>&1; \$NX "\$B/pvfs" instance add d183owner $OWNER_IP:7471 $PIN >/dev/null 2>&1 && echo C1=ok
got=\$(\$NX "\$B/pvfs" --json replica add "\$N" --instance d183owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo C2=ok
\$NX "\$B/pvfs" --data-dir "\$ND" bind "$NEARSHELF" "\$FT/d183-near-lib" --hash-policy on_add >/dev/null 2>&1 && echo C3=ok
settle "\$FT/d183-near-lib/n.mkv"
nohup \$NX "\$B/pvfsd" --mount "\$N" --listen 0.0.0.0:7473 >/dev/null 2>"\$FT/d183-near.log" &
echo \$! > "\$FT/d183-near.pid"
for _ in \$(seq 1 50); do [ -s "\$ND/nettls/pin" ] && break; sleep 0.2; done
\$NX "\$B/pvfs" --data-dir "\$ND" fleet announce $OWNER_IP:7473 >/dev/null 2>&1 && echo C4=ok
\$NX "\$B/pvfs" --data-dir "\$ND" serve enable follow >/dev/null 2>&1
\$NX "\$B/pvfs" --data-dir "\$ND" serve enable watch >/dev/null 2>&1
\$NX "\$B/pvfs" --data-dir "\$ND" serve enable catalogue >/dev/null 2>&1 && echo C5=ok
waitq "\$ND" "$NEARSHELF" 90 "1/1/1/False/None/False" && echo C6=ok
EOS
)
has "$C_OUT" C1=ok && ok "near pinned the owner" || fail "near instance add: $C_OUT"
has "$C_OUT" C2=ok && ok "near shipped the owner's log" || fail "near replica add"
has "$C_OUT" C3=ok && ok "near bound near-shelf" || fail "near bind"
has "$C_OUT" C4=ok && ok "near announced $OWNER_IP:7473" || fail "near announce"
has "$C_OUT" C5=ok && ok "near daemon up: follow + watch + catalogue" || fail "near serve jobs"
has "$C_OUT" C6=ok && ok "near-shelf head 1 committed" || fail "no near head: $C_OUT $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d183-near.log')"
gate near

say "D: baseline, owner up — each replica holds the other's shelf; both views are the whole library"
D1=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitq "\$ND" "$EDGESHELF" 75 "1/1/1/False/None/False" && echo D1=ok
echo "NEAR_TOP=\$(vpaths "\$ND" "")"
EOS
)
D2=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitq "\$RD" "$NEARSHELF" 75 "1/1/1/False/None/False" && echo D2=ok
echo "EDGE_TOP=\$(vpaths "\$RD" "")"
EOS
)
has "$D1" D1=ok && ok "near holds edge-shelf at head 1" || fail "near never fetched edge-shelf: $D1"
has "$D2" D2=ok && ok "edge holds near-shelf at head 1" || fail "edge never fetched near-shelf: $D2"
[ "$(val "$D1" NEAR_TOP)" = "n.mkv,season,x.mkv" ] && ok "near's view: n.mkv, season, x.mkv" || fail "near top: $(val "$D1" NEAR_TOP)"
[ "$(val "$D2" EDGE_TOP)" = "n.mkv,season,x.mkv" ] && ok "edge's view: the same" || fail "edge top: $(val "$D2" EDGE_TOP)"
gate baseline

say "E: the OWNER GOES DOWN"
E_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
stopd "\$FT/d183-owner.pid"
echo "H0=\$(heads)"
EOS
)
has "$E_OUT" STILL_RUNNING && fail "owner daemon would not stop" || ok "owner daemon stopped"
H0=$(val "$E_OUT" H0); [ -n "$H0" ] && ok "owner log holds $H0 SubRegionHead rows" || fail "head count: $E_OUT"
gate down

say "F: the edge catalogues a new file with no owner — head 2 published there, pending"
ssh "$EDGE" 'printf aaaa1 > "$HOME/fleet-test/d183-edge-lib/season/away1.mkv"' && ok "season/away1.mkv written on the edge"
F_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitq "\$RD" "$EDGESHELF" 90 "1/1/1/False/2/False" && echo F1=ok
grep -q "the owner is unreachable" "\$FT/d183-edge.log" && echo F2=ok
EOS
)
has "$F_OUT" F1=ok && ok "edge-shelf: log head 1, head 2 published on the edge, pending" || fail "edge pending: $F_OUT"
has "$F_OUT" F2=ok && ok "the edge's watch said the owner is unreachable and catalogued anyway" || fail "watch message: $(ssh "$EDGE" 'tail -5 $HOME/fleet-test/d183-edge.log')"
gate edge-away

say "G: near takes the edge's claim, fetches head 2 from the edge — owner still down"
G_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitq "\$ND" "$EDGESHELF" 90 "2/2/1/True/None/False" && echo G1=ok
echo "NEAR_SEASON=\$(vpaths "\$ND" season)"
grep -q "head 2 taken from $EDGE_IP:7472" "\$FT/d183-near.log" && echo G2=ok
EOS
)
has "$G_OUT" G1=ok && ok "near: edge-shelf held 2 at provisional head 2 (log 1), not stale" || fail "near provisional: $G_OUT"
[ "$(val "$G_OUT" NEAR_SEASON)" = "season/away1.mkv,season/y.mkv" ] && ok "near's view shows season/away1.mkv" || fail "near season: $(val "$G_OUT" NEAR_SEASON)"
has "$G_OUT" G2=ok && ok "near's log: head 2 taken from $EDGE_IP:7472" || fail "near log: $(ssh "$OWNER" 'grep catalogue $HOME/fleet-test/d183-near.log | tail -5')"
gate claim

say "H: a second change on the edge, still no owner — head 3; near follows it"
ssh "$EDGE" 'printf aaaa22 > "$HOME/fleet-test/d183-edge-lib/season/away2.mkv"' && ok "season/away2.mkv written on the edge"
H_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitq "\$RD" "$EDGESHELF" 90 "1/1/1/False/3/False" && echo H1=ok
EOS
)
has "$H_OUT" H1=ok && ok "edge-shelf: head 3 published on the edge, pending (log still 1)" || fail "edge head 3: $H_OUT"
H2_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitq "\$ND" "$EDGESHELF" 90 "3/3/1/True/None/False" && echo H2=ok
echo "NEAR_SEASON=\$(vpaths "\$ND" season)"
EOS
)
has "$H2_OUT" H2=ok && ok "near: edge-shelf held 3 at provisional head 3" || fail "near head 3: $H2_OUT"
[ "$(val "$H2_OUT" NEAR_SEASON)" = "season/away1.mkv,season/away2.mkv,season/y.mkv" ] && ok "near's view shows away2.mkv" || fail "near season: $(val "$H2_OUT" NEAR_SEASON)"
gate second

say "I: the other direction — near (on the owner's own box) changes; the edge takes it"
ssh "$OWNER" 'printf nn2 > "$HOME/fleet-test/d183-near-lib/near-away.mkv"' && ok "near-away.mkv written on near"
I_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitq "\$ND" "$NEARSHELF" 90 "1/1/1/False/2/False" && echo I1=ok
EOS
)
has "$I_OUT" I1=ok && ok "near-shelf: head 2 published on near, pending" || fail "near pending: $I_OUT"
I2_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitq "\$RD" "$NEARSHELF" 90 "2/2/1/True/None/False" && echo I2=ok
echo "EDGE_TOP=\$(vpaths "\$RD" "")"
EOS
)
has "$I2_OUT" I2=ok && ok "edge: near-shelf held 2 at provisional head 2" || fail "edge provisional: $I2_OUT"
[ "$(val "$I2_OUT" EDGE_TOP)" = "n.mkv,near-away.mkv,season,x.mkv" ] && ok "edge's view shows near-away.mkv" || fail "edge top: $(val "$I2_OUT" EDGE_TOP)"
gate other-way

say "J: the OWNER COMES BACK — pending heads commit, provisional heads give way"
ssh "$OWNER" "bash -s" <<EOS >/dev/null
$RH
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7471 >/dev/null 2>>"\$FT/d183-owner.log" &
echo \$! > "\$FT/d183-owner.pid"
EOS
ok "owner daemon restarted on its own log"
J1=$(ssh "$EDGE" "bash -s" <<EOS
$RH
waitq "\$RD" "$EDGESHELF" 90 "3/3/3/False/None/False" && echo J1=ok
waitq "\$RD" "$NEARSHELF" 90 "2/2/2/False/None/False" && echo J2=ok
EOS
)
J2=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitq "\$ND" "$NEARSHELF" 90 "2/2/2/False/None/False" && echo J3=ok
waitq "\$ND" "$EDGESHELF" 90 "3/3/3/False/None/False" && echo J4=ok
echo "NEAR_SEASON=\$(vpaths "\$ND" season)"
EOS
)
has "$J1" J1=ok && ok "edge: edge-shelf head 3 committed, nothing pending" || fail "edge commit: $J1"
has "$J1" J2=ok && ok "edge: near-shelf committed 2 — its provisional head gave way" || fail "edge near-shelf: $J1"
has "$J2" J3=ok && ok "near: near-shelf head 2 committed, nothing pending" || fail "near commit: $J2"
has "$J2" J4=ok && ok "near: edge-shelf committed 3 — its provisional head gave way" || fail "near edge-shelf: $J2"
[ "$(val "$J2" NEAR_SEASON)" = "season/away1.mkv,season/away2.mkv,season/y.mkv" ] && ok "near's view unchanged by the commit" || fail "near season: $(val "$J2" NEAR_SEASON)"
gate back

say "K: the owner's log — one head per region for the whole outage, the newest"
K_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
stopd "\$FT/d183-owner.pid"
echo "H1=\$(heads)"
echo "OE=\$(rq "\$D" "$EDGESHELF")"; echo "ON=\$(rq "\$D" "$NEARSHELF")"
EOS
)
H1=$(val "$K_OUT" H1)
[ -n "$H1" ] && [ "$((H1 - H0))" -eq 2 ] && ok "two SubRegionHead rows in all ($H0 → $H1): edge-shelf's head 2 never needed one" || fail "heads $H0 → $H1"
case "$(val "$K_OUT" OE)" in */3/3/False/*) ok "owner: edge-shelf at 3";; *) fail "owner edge-shelf: $(val "$K_OUT" OE)";; esac
case "$(val "$K_OUT" ON)" in */2/2/False/*) ok "owner: near-shelf at 2";; *) fail "owner near-shelf: $(val "$K_OUT" ON)";; esac

say "L: stop the lab daemons (dirs kept under ~/fleet-test/d183-* for inspection)"
ssh "$EDGE" 'kill "$(cat $HOME/fleet-test/d183-edge.pid)" 2>/dev/null' && ok "edge daemon stopped"
ssh "$OWNER" 'kill "$(cat $HOME/fleet-test/d183-near.pid)" 2>/dev/null' && ok "near daemon stopped"
echo; echo "heads pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
