#!/bin/bash
# D181 (PVOS §8, guardrail 4) — a daemon catches up on a BACKLOG beside a
# running view mount, and the mount's stream does not notice.
#
# Why: the fleet's mount unit is `PartOf=` the daemon because a long-running
# mount once starved a restarting daemon of the fold lock for over an hour.
# mediabox is to drop that tie, so Plex streams survive a roll. test-plex
# showed a daemon restart is invisible to a stream, but its daemon came back
# to nothing new. Here it comes back to thousands of events: new catalogue
# rows (a region snapshot replacing its rows in the edge's projection) and
# new top-log events, while a steady reader streams through the edge's view.
#
#   owner : presubuntu (192.168.0.184) — forest, `own-shelf` catalogued here,
#           holding a 1 GiB big.mkv
#   edge  : pvos-test  (192.168.0.138) — replica (follow + catalogue), NOT
#           announced (like test-plex), view mount in stream mode
# Binaries: ~/.local/bin on both boxes, or a session's own build:
#   PVFS_LAB_BIN=/opt/pvfs-<session>/src/target/release deploy/d181-backlog-pair.sh
# Run from the Mac; nothing here touches production.
OWNER=chris@192.168.0.184; EDGE=chris@192.168.0.138; OWNER_IP=192.168.0.184
LABBIN=${PVFS_LAB_BIN:-'$HOME/.local/bin'}   # expanded on the lab box, not here
FILES=${D181_FILES:-3000}; EVENTS=${D181_EVENTS:-600}
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
RH='B='"$LABBIN"'; FT=$HOME/fleet-test; O=$FT/d181-owner; R=$FT/d181-replica; D=$O/.pvfs; RD=$R/.pvfs; V=$FT/d181-view
jget(){ python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
stopd(){ p=$(cat "$1" 2>/dev/null) || return 0; kill "$p" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done; echo "STILL_RUNNING $p"; }
# region head as seen from a data dir
rhead(){ "$B/pvfs" --json --data-dir "$1" region ls 2>/dev/null | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r[\"region\"]==sys.argv[1]: print(r.get(\"head\") or 0)" "$2"; }
# top-log events caught up, counted as the e<N> folders this run adds under the root
enodes(){ "$B/pvfs" --json --data-dir "$1" ls "$2" 2>/dev/null | python3 -c "import json,sys; print(sum(1 for c in json.load(sys.stdin) if c[\"label\"].startswith(\"e\") and c[\"label\"][1:].isdigit()))"; }
'

say "0: preflight — one build on both boxes, a clean slate"
VA=$(ssh "$OWNER" "\"$LABBIN/pvfs\" --version" 2>&1); VB=$(ssh "$EDGE" "\"$LABBIN/pvfs\" --version" 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" 'fusermount3 -uz "$HOME/fleet-test/d181-view" 2>/dev/null; pkill -f "mount --view $HOME/fleet-test/d181" 2>/dev/null; pkill -f "pvfsd --mount $HOME/fleet-test/d181" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d181-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
AKEY=$(ssh "$OWNER" "\"$LABBIN/pvfs\" --json whoami" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" "\"$LABBIN/pvfs\" --json whoami" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
gate preflight

say "A: owner — forest, own-shelf catalogued with a 1 GiB big.mkv, announced, daemon up"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d181-owner-lib; mkdir -p "\$L/backlog"; head -c 1073741824 /dev/urandom > "\$L/big.mkv"; printf aaa > "\$L/a.mkv"
md5sum < "\$L/big.mkv" | cut -d' ' -f1 | sed 's/^/BIGMD5=/'
"\$B/pvfs" forest init --mount "\$O" >/dev/null 2>&1 || { echo INIT_FAILED; exit 0; }
INFO=\$("\$B/pvfs" --json --data-dir "\$D" info)
ROOT=\$(printf '%s' "\$INFO" | jget root_node_id); FID=\$(printf '%s' "\$INFO" | jget forest_id)
"\$B/pvfs" --forest "\$O" fleet enroll $EDGEKEY --rights rwa >/dev/null 2>&1 && echo A0=ok
"\$B/pvfs" --forest "\$O" fleet enroll $AKEY --rights rwa >/dev/null 2>&1 && echo A1=ok
OWN=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label own-shelf)
"\$B/pvfs" --json --data-dir "\$D" region mark "\$OWN" --catalogue | grep -q '"kind":"catalogue"' && echo A2=ok
"\$B/pvfs" --data-dir "\$D" bind "\$OWN" "\$L" --hash-policy on_add >/dev/null && echo A3=ok
"\$B/pvfs" --data-dir "\$D" scan "\$OWN" >/dev/null && echo A4=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7456 >/dev/null 2>"\$FT/d181-owner.log" &
echo \$! > "\$FT/d181-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
stopd "\$FT/d181-owner.pid"
"\$B/pvfs" --data-dir "\$D" fleet announce $OWNER_IP:7456 >/dev/null 2>&1 && echo A5=ok
"\$B/pvfs" --data-dir "\$D" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable catalogue >/dev/null 2>&1 && echo A6=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7456 >/dev/null 2>>"\$FT/d181-owner.log" &
echo \$! > "\$FT/d181-owner.pid"
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7456 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$got" = "\$FID" ] && { echo A7=ok; break; }; sleep 0.5
done
for _ in \$(seq 1 60); do [ "\$(rhead "\$D" "\$OWN")" -ge 1 ] 2>/dev/null && { echo A8=ok; break; }; sleep 1; done
echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "OWN=\$OWN"; echo "PIN=\$PIN"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
for k in A0 A1 A2 A3 A4 A5 A6 A7 A8; do has "$A_OUT" "$k=ok" || fail "owner step $k: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d181-owner.log')"; done
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); OWN=$(val "$A_OUT" OWN); PIN=$(val "$A_OUT" PIN); BIGMD5=$(val "$A_OUT" BIGMD5)
[ "$FAIL" -eq 0 ] && ok "owner up: forest, own-shelf catalogued (head ≥ 1), announced, daemon on :7456"
gate owner

say "B: edge — replica (follow + catalogue, not announced), the view mounted in stream mode"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d181owner >/dev/null 2>&1; "\$B/pvfs" instance add d181owner $OWNER_IP:7456 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d181owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --data-dir "\$RD" serve enable follow >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable catalogue >/dev/null 2>&1 && echo B3=ok
nohup "\$B/pvfsd" --mount "\$R" --listen 127.0.0.1:7457 >/dev/null 2>"\$FT/d181-edge.log" &
echo \$! > "\$FT/d181-edge.pid"
for _ in \$(seq 1 60); do [ "\$(rhead "\$RD" "$OWN")" -ge 1 ] 2>/dev/null && { echo B4=ok; break; }; sleep 1; done
mkdir -p "\$V"
nohup "\$B/pvfs" --data-dir "\$RD" mount --view "\$V" --cache-mode stream >/dev/null 2>"\$FT/d181-view.log" &
echo \$! > "\$FT/d181-view.pid"
for _ in \$(seq 1 40); do mountpoint -q "\$V" && break; sleep 0.25; done
mountpoint -q "\$V" && echo B5=ok
[ "\$(stat -c %s "\$V/big.mkv" 2>/dev/null)" = "1073741824" ] && echo B6=ok
echo "EDGE_E0=\$(enodes "\$RD" "$ROOT")"
EOS
)
for k in B1 B2 B3 B4 B5 B6; do has "$B_OUT" "$k=ok" || fail "edge step $k: $B_OUT $(ssh "$EDGE" 'tail -3 $HOME/fleet-test/d181-edge.log; tail -3 $HOME/fleet-test/d181-view.log')"; done
[ "$FAIL" -eq 0 ] && ok "edge up: replica, own-shelf fetched, the view mounted in stream mode, big.mkv listed at 1 GiB"
gate edge

say "C: the backlog — the edge's daemon stops; the owner catalogues $FILES files and logs $EVENTS events"
ssh "$EDGE" "bash -s" <<EOS >/dev/null
$RH
stopd "\$FT/d181-edge.pid"
EOS
ok "edge daemon stopped (the mount stays up)"
C_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d181-owner-lib
H0=\$(rhead "\$D" "$OWN")
# staged outside the root, then moved in (a write storm in the root starves the watch — D180)
S=\$FT/d181-stage/backlog; mkdir -p "\$S"
for i in \$(seq 1 $FILES); do printf "%08d" \$i > "\$S/f\$i.nfo"; done
mv "\$S" "\$L/backlog/batch"
# top-log events, with the owner's daemon down for the CLI writes (the lease rule)
stopd "\$FT/d181-owner.pid"
t=\$(date +%s)
for i in \$(seq 1 $EVENTS); do "\$B/pvfs" --data-dir "\$D" add "$ROOT" --kind folder --label "e\$i" >/dev/null 2>&1 || break; done
echo "ADD_S=\$(( \$(date +%s) - t ))"
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7456 >/dev/null 2>>"\$FT/d181-owner.log" &
echo \$! > "\$FT/d181-owner.pid"
for _ in \$(seq 1 180); do n=\$("\$B/pvfs" --json --data-dir "\$D" region entries "$OWN" 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["entries"]))' 2>/dev/null || echo 0); [ "\$n" -ge $FILES ] && break; sleep 2; done
echo "OWNER_ROWS=\$n"; echo "H0=\$H0"; echo "H1=\$(rhead "\$D" "$OWN")"; echo "OWNER_E=\$(enodes "\$D" "$ROOT")"
EOS
)
[ "$(val "$C_OUT" OWNER_ROWS)" -ge "$FILES" ] 2>/dev/null && ok "owner catalogued the batch: $(val "$C_OUT" OWNER_ROWS) rows, own-shelf head $(val "$C_OUT" H0) → $(val "$C_OUT" H1)" || fail "owner catalogue: $C_OUT"
[ "$(val "$C_OUT" OWNER_E)" = "$EVENTS" ] && ok "owner logged $EVENTS top-log events in $(val "$C_OUT" ADD_S)s (the edge, stopped, has $(val "$B_OUT" EDGE_E0) of them)" || fail "owner events: $C_OUT"
H1=$(val "$C_OUT" H1)
gate backlog

say "D: a steady 10 MB/s reader through the edge's view; the edge's daemon starts 10 s in and catches up"
D_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
python3 - "\$V/big.mkv" 10 90 > "\$FT/d181-read.out" 2>&1 <<'PY' &
import sys, time
p, rate, secs = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
f = open(p, "rb", buffering=0); t0 = time.time(); done = 0; err = 0; worst = 0.0
while time.time() - t0 < secs:
    due = t0 + done / (rate * 1e6)
    if due > time.time(): time.sleep(due - time.time())
    a = time.time()
    try: n = len(f.read(262144))
    except OSError as e:
        err += 1; print("ERROR %.1fs %s" % (a - t0, e), flush=True); time.sleep(1); continue
    worst = max(worst, time.time() - a)
    if n == 0: f.seek(0); continue
    done += n
print("READ bytes=%d worst=%.2f errors=%d" % (done, worst, err), flush=True)
PY
READER=\$!
# the view, probed twice a second throughout: the top listing and big.mkv's size
( while kill -0 \$READER 2>/dev/null; do
    top=\$(ls "\$V" 2>&1 | tr '\n' ',')
    sz=\$(stat -c %s "\$V/big.mkv" 2>&1)
    echo "\$(date +%s.%N) \$top \$sz"; sleep 0.5; done ) > "\$FT/d181-probe.out" &
sleep 10
t0=\$(date +%s.%N)
nohup "\$B/pvfsd" --mount "\$R" --listen 127.0.0.1:7457 >/dev/null 2>>"\$FT/d181-edge.log" &
echo \$! > "\$FT/d181-edge.pid"
for _ in \$(seq 1 150); do [ "\$(rhead "\$RD" "$OWN")" = "$H1" ] && [ "\$(enodes "\$RD" "$ROOT")" = "$EVENTS" ] && { echo "CAUGHT_UP_S=\$(python3 -c "import time; print(round(time.time()-\$t0,1))")"; break; }; sleep 0.5; done
echo "EDGE_E1=\$(enodes "\$RD" "$ROOT")"
wait \$READER
cat "\$FT/d181-read.out"
echo "BATCH_IN_VIEW=\$(ls "\$V/backlog/batch" 2>/dev/null | wc -l)"
echo "PROBES=\$(wc -l < "\$FT/d181-probe.out")"
echo "PROBES_BAD=\$(grep -cvE ' a.mkv,backlog,big.mkv, 1073741824$' "\$FT/d181-probe.out")"
grep -vE ' a.mkv,backlog,big.mkv, 1073741824$' "\$FT/d181-probe.out" | head -3 | sed 's/^/BADPROBE /'
grep -c "waiting for another pvfs process folding" "\$FT/d181-edge.log" "\$FT/d181-view.log" | sed 's/^/FOLDWAIT /'
tail -2 "\$FT/d181-edge.log" | sed 's/^/EDGELOG /'
EOS
)
has "$D_OUT" CAUGHT_UP_S= && ok "the edge's daemon caught up — own-shelf head $H1 and all $EVENTS top-log events — in $(val "$D_OUT" CAUGHT_UP_S)s beside the running mount" || fail "no catch-up: $D_OUT"
echo "$D_OUT" | grep -q "^FOLDWAIT .*:0$" && ! echo "$D_OUT" | grep -qE "^FOLDWAIT .*:[1-9]" && ok "nobody waited on the fold lock (daemon log and mount log)" || fail "fold-lock waits: $(echo "$D_OUT" | grep FOLDWAIT)"
READ=$(echo "$D_OUT" | grep '^READ ')
echo "$READ" | grep -q "errors=0" && ok "the stream carried on through the catch-up: $READ" || fail "the stream: $READ $(echo "$D_OUT" | grep ERROR | head -3)"
[ "$(val "$D_OUT" PROBES_BAD)" = "0" ] && ok "the view never flickered: $(val "$D_OUT" PROBES) probes of the listing and big.mkv's size, all right" || fail "the view flickered: $(val "$D_OUT" PROBES_BAD) bad probes — $(echo "$D_OUT" | grep BADPROBE)"
[ "$(val "$D_OUT" BATCH_IN_VIEW)" = "$FILES" ] && ok "the running mount shows the new $FILES files without a restart" || fail "batch in view: $(val "$D_OUT" BATCH_IN_VIEW)"
echo "edge log tail:"; echo "$D_OUT" | grep EDGELOG

say "E: stop the lab mount and daemons (dirs kept under ~/fleet-test/d181-* for inspection)"
ssh "$EDGE" 'B='"$LABBIN"'; V=$HOME/fleet-test/d181-view; fusermount3 -u "$V" 2>/dev/null; kill "$(cat $HOME/fleet-test/d181-view.pid)" "$(cat $HOME/fleet-test/d181-edge.pid)" 2>/dev/null; true' && ok "edge's mount and daemon stopped"
ssh "$OWNER" 'kill "$(cat $HOME/fleet-test/d181-owner.pid)" 2>/dev/null; true' && ok "owner's daemon stopped"
echo; echo "backlog pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
