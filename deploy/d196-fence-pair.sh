#!/bin/bash
# PVOS D196 — a replica pointed at a FENCED owner catalogues here, on the
# two-machine pair D129 uses. The owner is fenced by hand (its `fenced` file,
# in D182's format): a file added on the edge is catalogued there with a
# pending head, the edge's watch says it has no route through the owner, and
# no pass fails. The fence is lifted (`pvfs forest fence --clear`): the
# edge's catalogue job commits the pending head through the owner, and the
# owner holds and fetches it. Run on the build before D196 to see the edge's
# passes fail instead.
#   owner : presubuntu (192.168.0.184:7496) — forest, `own-shelf` catalogued here
#   edge  : pvos-test  (192.168.0.138:7497) — replica, `edge-shelf` catalogued there
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
RH='B=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d196-owner; R=$FT/d196-replica; D=$O/.pvfs; RD=$R/.pvfs
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
  ssh "$h" 'pkill -f "[p]vfsd --mount $HOME/fleet-test/d196" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d196-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
  busy=$(ssh "$h" 'ss -ltn | grep -Eo ":749[67] " | tr -d " " | tr "\n" " "')
  [ -z "$busy" ] && ok "$h: ports 7496–7497 free" || fail "$h: ports in use: $busy"
done
AKEY=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
ssh "$EDGE" 'L=$HOME/fleet-test/d196-edge-lib; mkdir -p "$L/season" "$L/unused"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"' \
  && ok "edge library staged (x.mkv, season/y.mkv, unused/)" || fail "edge library"
gate preflight

say "A: owner — forest, two catalogue regions, its shelf catalogued, announced, listener up with the catalogue job"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d196-owner-lib; mkdir -p "\$L/sub" "\$L/empty"; printf aaa > "\$L/a.mkv"; printf bbbbb > "\$L/sub/b.mkv"
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
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7496 >/dev/null 2>"\$FT/d196-owner.log" &
echo \$! > "\$FT/d196-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
stopd "\$FT/d196-owner.pid"
"\$B/pvfs" --data-dir "\$D" fleet announce $OWNER_IP:7496 >/dev/null 2>&1 && echo A6=ok
"\$B/pvfs" --data-dir "\$D" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable catalogue >/dev/null 2>&1 && echo A7=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7496 >/dev/null 2>>"\$FT/d196-owner.log" &
echo \$! > "\$FT/d196-owner.pid"
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7496 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
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
has "$A_OUT" A8=ok && ok "owner daemon up on :7496" || fail "owner daemon: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d196-owner.log')"
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); OWN=$(val "$A_OUT" OWN); EDGESHELF=$(val "$A_OUT" EDGESHELF); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "owner transport pin minted" || fail "pin: $PIN"
gate owner

say "B: edge — replica, binds its shelf, announces, publishes its head through the owner"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d196owner >/dev/null 2>&1; "\$B/pvfs" instance add d196owner $OWNER_IP:7496 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d196owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --data-dir "\$RD" bind "$EDGESHELF" "\$FT/d196-edge-lib" --hash-policy on_add >/dev/null 2>&1 && echo B3=ok
age=\$(( \$(date +%s) - \$(stat -c %Z "\$FT/d196-edge-lib/x.mkv") )); [ "\$age" -lt 17 ] && sleep \$(( 17 - age ))
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7497 >/dev/null 2>"\$FT/d196-edge.log" &
echo \$! > "\$FT/d196-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" fleet announce $EDGE_IP:7497 >/dev/null 2>&1 && echo B4=ok
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
has "$B_OUT" B6=ok && ok "edge published edge-shelf head 1" || fail "no edge head within 180s: $(ssh "$EDGE" 'tail -3 $HOME/fleet-test/d196-edge.log')"
gate edge

say "C: the owner fetches the edge's head 1 (the pair works)"
C_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
waitr "\$D" "$EDGESHELF" 75 "1/1/False" && echo C1=ok
EOS
)
has "$C_OUT" C1=ok && ok "owner fetched edge-shelf at head 1" || fail "owner never fetched: $C_OUT"
gate fetch

say "D: the owner is fenced — the edge catalogues here, with a pending head, and no pass fails"
D_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
printf 'pvfs-fence 1\nat_ms %s000\npeer 10.0.0.8:7431\npeer_seq 99\npeer_hash %s\nown_seq 7\nown_hash %s\nreason 10.0.0.8:7431 holds the forest log to seq 99, this box only to seq 7 (D196 rehearsal)\n' \
  "\$(date +%s)" "\$(printf 'ab%.0s' \$(seq 1 32))" "\$(printf 'cd%.0s' \$(seq 1 32))" > "\$D/fenced"
"\$B/pvfs" --json forest fence "\$O" | grep -q '"fenced":true' && echo D1=ok
EOS
)
has "$D_OUT" D1=ok && ok "the owner reads as fenced (pvfs forest fence)" || fail "fence not set: $D_OUT"
ssh "$EDGE" 'printf zzz > "$HOME/fleet-test/d196-edge-lib/z.mkv"; wc -l < "$HOME/fleet-test/d196-edge.log" > "$HOME/fleet-test/d196-edge.mark"' && ok "z.mkv added on the edge"
E_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
pend(){ "\$B/pvfs" --json --data-dir "\$RD" region ls 2>/dev/null | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r[\"region\"]==sys.argv[1]: print(r.get(\"pending\"))" "$EDGESHELF"; }
for _ in \$(seq 1 60); do [ "\$(pend)" = "2" ] && { echo E1=ok; break; }; sleep 2; done
echo "PENDING=\$(pend)"
since=\$(cat "\$FT/d196-edge.mark")
tail -n +\$((since + 1)) "\$FT/d196-edge.log" > "\$FT/d196-edge.after"
grep -q "no route through the owner" "\$FT/d196-edge.after" && grep -q "the owner is fenced" "\$FT/d196-edge.after" && echo E2=ok
echo "FAILED_PASSES=\$(grep -c 'watch pass failed' "\$FT/d196-edge.after")"
echo "LINE=\$(grep -m1 'no route through the owner' "\$FT/d196-edge.after" | cut -c1-220)"
EOS
)
has "$E_OUT" E1=ok && ok "the edge catalogued z.mkv here: edge-shelf head 2 pending" || fail "no pending head: $(val "$E_OUT" PENDING) $(ssh "$EDGE" 'tail -4 $HOME/fleet-test/d196-edge.log')"
has "$E_OUT" E2=ok && ok "the edge's watch said it had no route through the owner, which is fenced" || fail "no route line: $(ssh "$EDGE" 'tail -4 $HOME/fleet-test/d196-edge.after')"
[ "$(val "$E_OUT" FAILED_PASSES)" = "0" ] && ok "no watch pass failed while the owner was fenced" || fail "watch passes failed: $(val "$E_OUT" FAILED_PASSES)"
echo "     $(val "$E_OUT" LINE)"
F_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
echo "OWNER=\$(rstat "\$D" "$EDGESHELF")"
EOS
)
has "$F_OUT" "OWNER=1/1/False" && ok "the owner still holds head 1: nothing was written through the fence" || fail "owner: $F_OUT"
gate fenced

say "E: the fence is lifted — the pending head commits, and the owner holds head 2"
G_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" forest fence "\$O" --clear >/dev/null 2>&1; [ ! -f "\$D/fenced" ] && echo G1=ok
waitr "\$D" "$EDGESHELF" 90 "2/2/False" && echo G2=ok
EOS
)
has "$G_OUT" G1=ok && ok "fence lifted" || fail "fence clear: $G_OUT"
has "$G_OUT" G2=ok && ok "the owner holds edge-shelf head 2 (committed and fetched)" || fail "no head 2 on the owner: $G_OUT"
H_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
for _ in \$(seq 1 45); do p=\$("\$B/pvfs" --json --data-dir "\$RD" region ls 2>/dev/null | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r[\"region\"]==sys.argv[1]: print(r.get(\"pending\"))" "$EDGESHELF"); [ "\$p" = "None" ] && { echo H1=ok; break; }; sleep 2; done
EOS
)
has "$H_OUT" H1=ok && ok "nothing pending on the edge once the owner holds it" || fail "still pending: $H_OUT"

say "F: stop the pair's daemons (dirs kept under ~/fleet-test/d196-* for inspection)"
ssh "$EDGE" 'kill "$(cat $HOME/fleet-test/d196-edge.pid)" 2>/dev/null' && ok "edge daemon stopped"
ssh "$OWNER" 'kill "$(cat $HOME/fleet-test/d196-owner.pid)" 2>/dev/null' && ok "owner daemon stopped"
echo; echo "fence pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
