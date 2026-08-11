#!/bin/bash
# Chaos test — what actually happens when things die mid-transfer.
#   owner : presubuntu (192.168.0.184)   edge : pvos-test (192.168.0.138)
# Tests: client killed -9 mid-fetch; source killed -9 mid-stream; the edge
# REBOOTED mid-fetch; a live follower surviving source death. pvos-test only
# is rebooted (presubuntu hosts pvosd).
set -u

OWNER=chris@192.168.0.184
EDGE=chris@192.168.0.138
OWNER_IP=192.168.0.184
PORT=7440

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "ok   $*"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL $*"; }
say()  { echo; echo "== $*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
jkey() { python3 -c 'import json,sys;print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"; }
RHELPERS='
jget(){ python3 -c "import json,sys;print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
pick(){ python3 -c "import json,sys
for e in json.load(sys.stdin):
    if e[\"label\"]==sys.argv[1]: print(e[\"id\"])" "$1"; }
'

say "0: setup — owner forest with a 2 GiB file, both identities enrolled"
for H in "$OWNER" "$EDGE"; do
  ssh "$H" 'pkill -9 -f "pvfsd --mount $HOME/chaos-test" 2>/dev/null; rm -rf "$HOME/chaos-test"; true'
done
A_OUT=$(ssh "$OWNER" "PORT=$PORT bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; CT=\$HOME/chaos-test
mkdir -p "\$CT/library"
head -c 2147483648 /dev/urandom > "\$CT/library/big1.bin"
"\$B/pvfs" forest init --mount "\$CT/owner" >/dev/null 2>&1
D="\$CT/owner/.pvfs"
INFO=\$("\$B/pvfs" --json --data-dir "\$D" info)
ROOT=\$(printf '%s' "\$INFO" | jget root_node_id)
FID=\$(printf '%s' "\$INFO" | jget forest_id)
LIB=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label library)
"\$B/pvfs" --data-dir "\$D" bind "\$LIB" "\$CT/library" --hash-policy on_add >/dev/null
"\$B/pvfs" --data-dir "\$D" scan "\$LIB" >/dev/null
BIG1=\$("\$B/pvfs" --json --data-dir "\$D" ls "\$LIB" | pick big1.bin)
nohup "\$B/pvfsd" --mount "\$CT/owner" --listen 0.0.0.0:\$PORT >/dev/null 2>"\$CT/pvfsd.log" &
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "LIB=\$LIB"; echo "BIG1=\$BIG1"
echo "PIN=\$(cat "\$D/nettls/pin")"
echo "SHA1=\$(sha256sum "\$CT/library/big1.bin" | cut -d' ' -f1)"
EOS
)
eval "$(echo "$A_OUT" | grep -E '^(ROOT|FID|LIB|BIG1|PIN|SHA1)=')"
[ "${#BIG1}" -eq 64 ] && ok "owner serves a 2 GiB hashed file (node $BIG1)" || fail "setup: $A_OUT"
EDGEKEY=$(jkey "$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami')" pubkey)
OWNERKEY=$(jkey "$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami')" pubkey)
ssh "$OWNER" 'B=$HOME/.local/bin; F=$HOME/chaos-test/owner
"$B/pvfs" --forest "$F" fleet enroll '"$EDGEKEY"' --rights rwa >/dev/null && "$B/pvfs" --forest "$F" fleet enroll '"$OWNERKEY"' --rights r >/dev/null' \
  && ok "both identities enrolled" || fail "enroll"
B_OUT=$(ssh "$EDGE" "OWNER_IP=$OWNER_IP PORT=$PORT PIN=$PIN FID=$FID LIB=$LIB bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; CT=\$HOME/chaos-test; mkdir -p "\$CT"
"\$B/pvfs" instance rm chaos-owner >/dev/null 2>&1 || true
"\$B/pvfs" instance add chaos-owner "\$OWNER_IP:\$PORT" "\$PIN" >/dev/null
RF=\$("\$B/pvfs" --json replica add "\$CT/replica" --instance chaos-owner | jget forest_id)
[ "\$RF" = "\$FID" ] && echo "B1=ok" || echo "B1=no"
"\$B/pvfs" --data-dir "\$CT/replica/.pvfs" place "\$LIB" sync >/dev/null && echo "B2=ok" || echo "B2=no"
EOS
)
echo "$B_OUT" | grep -q "B1=ok" && ok "edge replicated over the LAN" || fail "replica: $B_OUT"
gate setup

say "1: client killed -9 mid-fetch — partial must never become the file"
T1=$(ssh "$EDGE" "BIG1=$BIG1 SHA1=$SHA1 bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; R="\$HOME/chaos-test/replica/.pvfs"
STORE="\$R/synced/\${BIG1:0:2}/\$BIG1"
TMP="\$R/synced/\${BIG1:0:2}/.\$BIG1.tmp"
nohup "\$B/pvfs" --data-dir "\$R" sync >/dev/null 2>&1 &
SPID=\$!
for _ in \$(seq 1 60); do [ -f "\$TMP" ] && [ "\$(stat -c%s "\$TMP" 2>/dev/null || echo 0)" -gt 100000000 ] && break; sleep 0.5; done
kill -9 "\$SPID" 2>/dev/null
sleep 1
[ -f "\$STORE" ] && echo "T1a=no(committed-partial)" || echo "T1a=ok"
[ -f "\$TMP" ] && echo "T1b=tmp-left(\$(stat -c%s "\$TMP"))" || echo "T1b=tmp-gone"
# recovery: plain rerun
"\$B/pvfs" --data-dir "\$R" sync >/dev/null 2>&1
GOT=\$("\$B/pvfs" --data-dir "\$R" cat "\$BIG1" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "\$GOT" = "\$SHA1" ] && echo "T1c=ok" || echo "T1c=no(\$GOT)"
[ -f "\$TMP" ] && echo "T1d=tmp-still-there" || echo "T1d=tmp-cleaned"
EOS
)
echo "$T1" | grep -q "T1a=ok" && ok "no partial ever committed (atomic publish holds under kill -9)" || fail "$T1"
echo "$T1" | grep -o "T1b=[^ ]*" | sed 's/T1b=/note: after kill -9, /'
echo "$T1" | grep -q "T1c=ok" && ok "plain re-run recovered — 2 GiB bit-perfect" || fail "post-kill recovery: $T1"
echo "$T1" | grep -o "T1d=[^ ]*" | sed 's/T1d=/note: recovery pass left tmp: /'

say "2: SOURCE killed -9 mid-stream — client fails clean, resumes after restart"
ssh "$OWNER" 'head -c 2147483648 /dev/urandom > "$HOME/chaos-test/library/big2.bin"
"$HOME/.local/bin/pvfs" --data-dir "$HOME/chaos-test/owner/.pvfs" scan '"$LIB"' >/dev/null'
SHA2=$(ssh "$OWNER" 'sha256sum "$HOME/chaos-test/library/big2.bin" | cut -d" " -f1')
BIG2=$(ssh "$EDGE" 'B=$HOME/.local/bin; R="$HOME/chaos-test/replica/.pvfs"
"$B/pvfs" replica sync "$HOME/chaos-test/replica" >/dev/null 2>&1
"$B/pvfs" --json --data-dir "$R" ls '"$LIB"' | python3 -c "import json,sys
for e in json.load(sys.stdin):
  if e[\"label\"]==\"big2.bin\": print(e[\"id\"])"')
[ "${#BIG2}" -eq 64 ] && ok "owner grew big2.bin; edge sees it (node $BIG2)" || fail "big2 setup: $BIG2"
ssh "$EDGE" 'nohup "$HOME/.local/bin/pvfs" --data-dir "$HOME/chaos-test/replica/.pvfs" sync >/dev/null 2>&1 & echo started' >/dev/null
sleep 8
ssh "$OWNER" 'pkill -9 -f "pvfsd --mount $HOME/chaos-test/owner"' && ok "source daemon killed -9 mid-stream" || fail "kill owner daemon"
sleep 3
T2=$(ssh "$EDGE" "BIG2=$BIG2 bash -s" <<'EOS'
R="$HOME/chaos-test/replica/.pvfs"
STORE="$R/synced/${BIG2:0:2}/$BIG2"
[ -f "$STORE" ] && echo "T2a=no(committed-partial)" || echo "T2a=ok"
EOS
)
echo "$T2" | grep -q "T2a=ok" && ok "no partial committed when the source died" || fail "$T2"
ssh "$OWNER" 'B=$HOME/.local/bin; CT=$HOME/chaos-test
nohup "$B/pvfsd" --mount "$CT/owner" --listen 0.0.0.0:'"$PORT"' >/dev/null 2>>"$CT/pvfsd.log" &
sleep 2' && ok "source daemon restarted" || fail "owner restart"
T2R=$(ssh "$EDGE" "BIG2=$BIG2 SHA2=$SHA2 bash -s" <<'EOS'
B=$HOME/.local/bin; R="$HOME/chaos-test/replica/.pvfs"
for i in 1 2 3; do "$B/pvfs" --data-dir "$R" sync >/dev/null 2>&1 && break; sleep 3; done
GOT=$("$B/pvfs" --data-dir "$R" cat "$BIG2" 2>/dev/null | sha256sum | cut -d" " -f1)
[ "$GOT" = "$SHA2" ] && echo "T2c=ok" || echo "T2c=no($GOT)"
EOS
)
echo "$T2R" | grep -q "T2c=ok" && ok "sync resumed against the restarted source — bit-perfect" || fail "resume: $T2R"

say "3: the EDGE REBOOTS mid-fetch — forest intact, services return, transfer completes"
ssh "$OWNER" 'head -c 2147483648 /dev/urandom > "$HOME/chaos-test/library/big3.bin"
"$HOME/.local/bin/pvfs" --data-dir "$HOME/chaos-test/owner/.pvfs" scan '"$LIB"' >/dev/null'
SHA3=$(ssh "$OWNER" 'sha256sum "$HOME/chaos-test/library/big3.bin" | cut -d" " -f1')
BIG3=$(ssh "$EDGE" 'B=$HOME/.local/bin; R="$HOME/chaos-test/replica/.pvfs"
"$B/pvfs" replica sync "$HOME/chaos-test/replica" >/dev/null 2>&1
"$B/pvfs" --json --data-dir "$R" ls '"$LIB"' | python3 -c "import json,sys
for e in json.load(sys.stdin):
  if e[\"label\"]==\"big3.bin\": print(e[\"id\"])"')
ssh "$EDGE" 'nohup "$HOME/.local/bin/pvfs" --data-dir "$HOME/chaos-test/replica/.pvfs" sync >/dev/null 2>&1 & echo started' >/dev/null
sleep 8
ssh -o ConnectTimeout=5 "$EDGE" 'sudo reboot' 2>/dev/null
ok "reboot issued to pvos-test mid-transfer"
BACK=""
for _ in $(seq 1 60); do
  sleep 5
  ssh -o ConnectTimeout=3 -o BatchMode=yes "$EDGE" true 2>/dev/null && { BACK=1; break; }
done
[ -n "$BACK" ] && ok "pvos-test is back" || fail "pvos-test never came back — check it manually"
gate reboot-return
T3=$(ssh "$EDGE" "BIG3=$BIG3 SHA3=$SHA3 ROOT=$ROOT bash -s" <<'EOS'
B=$HOME/.local/bin; R="$HOME/chaos-test/replica/.pvfs"
STORE="$R/synced/${BIG3:0:2}/$BIG3"
[ -f "$STORE" ] && echo "T3a=no(committed-partial-survived-reboot)" || echo "T3a=ok"
"$B/pvfs" --data-dir "$R" ls "$ROOT" >/dev/null 2>&1 && echo "T3b=ok" || echo "T3b=no"
export XDG_RUNTIME_DIR=/run/user/$(id -u); export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
systemctl --user is-active pvfsd@smoke >/dev/null 2>&1 && echo "T3c=ok" || echo "T3c=no($(systemctl --user is-active pvfsd@smoke 2>&1))"
"$B/pvfs" --data-dir "$R" sync >/dev/null 2>&1
GOT=$("$B/pvfs" --data-dir "$R" cat "$BIG3" 2>/dev/null | sha256sum | cut -d" " -f1)
[ "$GOT" = "$SHA3" ] && echo "T3d=ok" || echo "T3d=no($GOT)"
EOS
)
echo "$T3" | grep -q "T3a=ok" && ok "no partial survived the reboot as a real file" || fail "$T3"
echo "$T3" | grep -q "T3b=ok" && ok "replica forest opens clean after the reboot" || fail "forest damaged: $T3"
echo "$T3" | grep -q "T3c=ok" && ok "systemd brought pvfsd@smoke back at boot (linger + Restart)" || fail "service not back: $T3"
echo "$T3" | grep -q "T3d=ok" && ok "interrupted 2 GiB transfer re-ran to bit-perfect after reboot" || fail "post-reboot sync: $T3"

say "4: live follower survives source death (kill -9, restart, catch up)"
T4=$(ssh "$EDGE" 'B=$HOME/.local/bin; R="$HOME/chaos-test/replica/.pvfs"
"$B/pvfs" --data-dir "$R" serve enable follow >/dev/null
nohup "$B/pvfsd" --mount "$HOME/chaos-test/replica" --socket "$HOME/chaos-test/jobs.sock" >/dev/null 2>&1 &
sleep 2; echo jobs-daemon-up')
[ -n "$T4" ] && ok "edge jobs daemon running with follow enabled" || fail "jobs daemon"
ssh "$OWNER" 'pkill -9 -f "pvfsd --mount $HOME/chaos-test/owner"; sleep 3
B=$HOME/.local/bin; CT=$HOME/chaos-test
nohup "$B/pvfsd" --mount "$CT/owner" --listen 0.0.0.0:'"$PORT"' >/dev/null 2>>"$CT/pvfsd.log" &
sleep 2
"$B/pvfs" --forest "$CT/owner" add '"$ROOT"' --kind folder --label chaos-survivor >/dev/null' \
  && ok "source killed -9 and restarted; new event authored" || fail "source cycle"
FOK=""
for _ in $(seq 1 60); do
  ssh "$EDGE" '"$HOME/.local/bin/pvfs" --data-dir "$HOME/chaos-test/replica/.pvfs" ls '"$ROOT"' 2>/dev/null' | grep -q chaos-survivor && { FOK=1; break; }
  sleep 2
done
[ -n "$FOK" ] && ok "follower reconnected by itself and folded the event" || fail "follower never caught up"

say "cleanup"
ssh "$OWNER" 'pkill -f "pvfsd --mount $HOME/chaos-test" 2>/dev/null; rm -rf "$HOME/chaos-test"; true'
ssh "$EDGE" 'pkill -f "pvfsd --mount $HOME/chaos-test" 2>/dev/null; rm -rf "$HOME/chaos-test"; true'
ok "daemons stopped, chaos dirs removed"

echo
echo "chaos results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL CHAOS TESTS PASSED" || exit 1
