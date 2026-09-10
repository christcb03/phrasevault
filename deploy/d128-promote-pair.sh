#!/bin/bash
# D128 item 4 — the owner MOVES, on the two-machine lab the D125 pair uses:
#   A : presubuntu (192.168.0.184) — the forest's first owner, then a replica of B
#   B : pvos-test  (192.168.0.138) — a replica, promoted to owner with the phrase
# A file written through A reaches B; A stops; B is promoted (refused while A
# still answers); B accepts a write; A's device is revoked; A rejoins as a
# replica of B and sees the write; the log is one unbroken chain.
# Binaries: ~/.local/bin on both boxes, installed by the pipeline. Run from
# the Mac; nothing here touches production.
A=chris@192.168.0.184; B=chris@192.168.0.138; A_IP=192.168.0.184; B_IP=192.168.0.138
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
# every remote block gets these helpers prepended
RH='BIN=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d128-owner; R=$FT/d128-replica; A2=$FT/d128-rejoin; D=$O/.pvfs; RD=$R/.pvfs; AD=$A2/.pvfs
jget(){ python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
tip(){ python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute(\"select ifnull(max(seq),0) from events\").fetchone()[0])" "$1"; }
stopd(){ p=$(cat "$1" 2>/dev/null) || return 0; kill "$p" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done; echo "STILL_RUNNING $p"; }
'

say "0: preflight — the D128 build on both boxes, a clean slate"
VA=$(ssh "$A" '"$HOME/.local/bin/pvfs" --version' 2>&1); VB=$(ssh "$B" '"$HOME/.local/bin/pvfs" --version' 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$A" "$B"; do
  ssh "$h" '"$HOME/.local/bin/pvfs" forest promote --help >/dev/null 2>&1 && "$HOME/.local/bin/pvfs" replica repoint --help >/dev/null 2>&1' \
    && ok "$h has forest promote + replica repoint" || fail "$h: not a D128 build"
  ssh "$h" 'pkill -f "pvfsd --mount $HOME/fleet-test/d128" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d128-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
AKEY=$(ssh "$A" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
BKEY=$(ssh "$B" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#BKEY}" -eq 66 ] && ok "client identities A=$AKEY B=$BKEY" || fail "identities: A=$AKEY B=$BKEY"
gate preflight

say "A: the first owner — forest, both boxes enrolled as replicators, a folder, listener up"
A_OUT=$(ssh "$A" "bash -s" <<EOS
$RH
INIT=\$("\$BIN/pvfs" --json forest init --mount "\$O" --no-import --new-phrase 2>/dev/null) || { echo INIT_FAILED; exit 0; }
MN=\$(printf '%s' "\$INIT" | jget mnemonic); ROOT=\$(printf '%s' "\$INIT" | jget root_node_id); FID=\$(printf '%s' "\$INIT" | jget forest_id)
"\$BIN/pvfs" --forest "\$O" fleet enroll $BKEY --rights rwa >/dev/null 2>&1 && echo A0=ok
"\$BIN/pvfs" --forest "\$O" fleet enroll $AKEY --rights rwa >/dev/null 2>&1 && echo A1=ok
"\$BIN/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label Before >/dev/null && echo A2=ok
DEV0=\$(python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('select hex(device_pubkey) from device_keys where device_index=0').fetchone()[0].lower())" "\$D/index.db")
nohup "\$BIN/pvfsd" --mount "\$O" --listen 0.0.0.0:7442 >/dev/null 2>"\$FT/d128-owner.log" &
echo \$! > "\$FT/d128-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
for _ in \$(seq 1 40); do
  got=\$("\$BIN/pvfs" --json remote --connect 127.0.0.1:7442 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$got" = "\$FID" ] && { echo A3=ok; break; }; sleep 0.5
done
echo "MN=\$MN"; echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "PIN=\$PIN"; echo "DEV0=\$DEV0"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
has "$A_OUT" A0=ok && ok "B enrolled (rwa — replication needs admin)" || fail "enroll B"
has "$A_OUT" A1=ok && ok "A's own client key enrolled (it rejoins as a replica later)" || fail "enroll A"
has "$A_OUT" A2=ok && ok "folder Before written through A" || fail "add Before"
has "$A_OUT" A3=ok && ok "A's daemon up on :7442" || fail "A daemon"
MN=$(val "$A_OUT" MN); ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); PIN=$(val "$A_OUT" PIN); DEV0=$(val "$A_OUT" DEV0)
[ "$(printf '%s' "$MN" | wc -w)" -ge 12 ] && ok "recovery phrase captured" || fail "phrase: '$MN'"
[ "${#PIN}" -eq 64 ] && ok "A's transport pin minted" || fail "pin: $PIN"
[ "${#DEV0}" -eq 64 ] && ok "A's device 0 is $DEV0" || fail "device 0: $DEV0"
gate owner

say "B: the replica — ships A's log, follows it, sees a folder written later through A"
B_OUT=$(ssh "$B" "bash -s" <<EOS
$RH
"\$BIN/pvfs" instance rm d128owner >/dev/null 2>&1; "\$BIN/pvfs" instance add d128owner $A_IP:7442 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$BIN/pvfs" --json replica add "\$R" --instance d128owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$BIN/pvfs" --data-dir "\$RD" ls "$ROOT" 2>/dev/null | grep -q Before && echo B3=ok
nohup "\$BIN/pvfsd" --mount "\$R" --listen 0.0.0.0:7443 >/dev/null 2>"\$FT/d128-replica.log" &
echo \$! > "\$FT/d128-replica.pid"
sleep 1; "\$BIN/pvfs" --data-dir "\$RD" serve enable follow >/dev/null 2>&1 && echo B4=ok
EOS
)
has "$B_OUT" B1=ok && ok "B pinned A" || fail "instance add: $B_OUT"
has "$B_OUT" B2=ok && ok "B shipped A's log (same forest id)" || fail "replica add: $B_OUT"
has "$B_OUT" B3=ok && ok "B sees Before" || fail "B ls: $B_OUT"
has "$B_OUT" B4=ok && ok "B's daemon up, following" || fail "B daemon"
ssh "$A" "bash -s" <<EOS >/dev/null 2>&1
$RH
"\$BIN/pvfs" --data-dir "\$D" add "$ROOT" --kind folder --label Live
EOS
ok "folder Live written through A while B follows"
LIVE=$(ssh "$B" "bash -s" <<EOS
$RH
for _ in \$(seq 1 60); do "\$BIN/pvfs" --data-dir "\$RD" ls "$ROOT" 2>/dev/null | grep -q Live && { echo SEEN; break; }; sleep 1; done
EOS
)
has "$LIVE" SEEN && ok "B saw Live within 60s (follow)" || fail "B never saw Live: $(ssh "$B" 'tail -3 $HOME/fleet-test/d128-replica.log')"
gate replica

say "C: promotion — refused while A answers; A stops; B becomes the owner, A's device revoked"
C_OUT=$(ssh "$B" "bash -s" <<EOS
$RH
stopd "\$FT/d128-replica.pid"
TIP_BEFORE=\$(tip "\$RD/log.db")
printf '%s\n' "$MN" | "\$BIN/pvfs" forest promote "\$R" --device-index 1 >"\$FT/d128-refused.txt" 2>&1 && echo C0=PROMOTED_WHILE_A_UP
grep -q "still answers" "\$FT/d128-refused.txt" && [ -f "\$RD/replica" ] && echo C0=ok
echo "TIP_BEFORE=\$TIP_BEFORE"
EOS
)
has "$C_OUT" C0=ok && ok "refused while A still answers (marker untouched)" || fail "no refusal: $C_OUT"
gate refusal
ssh "$A" "bash -s" <<EOS
$RH
stopd "\$FT/d128-owner.pid"
EOS
ok "A's daemon stopped (the old owner is down)"
TIP_BEFORE=$(val "$C_OUT" TIP_BEFORE)
P_OUT=$(ssh "$B" "bash -s" <<EOS
$RH
printf '%s\n' "wrong words that are not the phrase" | "\$BIN/pvfs" forest promote "\$R" --device-index 1 >/dev/null 2>&1 && echo P0=WRONG_PHRASE_PROMOTED
[ -f "\$RD/replica" ] && [ ! -f "\$RD/promoted-from" ] && echo P0=ok
printf '%s\n' "$MN" | "\$BIN/pvfs" forest promote "\$R" --device-index 0 >/dev/null 2>&1 && echo P1=INDEX0_ACCEPTED
[ -f "\$RD/replica" ] && echo P1=ok
J=\$(printf '%s\n' "$MN" | "\$BIN/pvfs" --json forest promote "\$R" --device-index 1 2>"\$FT/d128-promote.err") || { echo "PROMOTE_FAILED: \$(cat "\$FT/d128-promote.err")"; exit 0; }
printf '%s' "\$J" | grep -q '"promoted":true' && echo P2=ok
printf '%s' "\$J" | grep -q "\"revoked\":\"$DEV0\"" && echo P3=ok
[ -f "\$RD/promoted-from" ] && [ ! -f "\$RD/replica" ] && echo P4=ok
grep -q "$A_IP:7442" "\$RD/promoted-from" && echo P5=ok
echo "TIP_PROMOTED=\$(tip "\$RD/log.db")"
"\$BIN/pvfs" --data-dir "\$RD" add "$ROOT" --kind folder --label After >/dev/null 2>&1 && echo P6=ok
python3 - "\$RD/index.db" <<'PY'
import sqlite3, sys
rows = sqlite3.connect(sys.argv[1]).execute("select device_index, revoked_at is not null from device_keys order by device_index").fetchall()
print("DEVICES=" + ";".join(f"{i}:{'revoked' if r else 'live'}" for i, r in rows))
PY
printf '%s\n' "$MN" | "\$BIN/pvfs" forest promote "\$R" --device-index 2 >"\$FT/d128-again.txt" 2>&1 && echo P7=PROMOTED_TWICE
grep -q "not a replica" "\$FT/d128-again.txt" && echo P7=ok
echo "TIP_AFTER=\$(tip "\$RD/log.db")"
nohup "\$BIN/pvfsd" --mount "\$R" --listen 0.0.0.0:7443 >/dev/null 2>"\$FT/d128-newowner.log" &
echo \$! > "\$FT/d128-replica.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
NEWPIN=\$(cat "\$RD/nettls/pin" 2>/dev/null || echo MISSING)
for _ in \$(seq 1 40); do
  got=\$("\$BIN/pvfs" --json remote --connect 127.0.0.1:7443 --pin "\$NEWPIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$got" = "$FID" ] && { echo P8=ok; break; }; sleep 0.5
done
echo "NEWPIN=\$NEWPIN"
EOS
)
has "$P_OUT" PROMOTE_FAILED && fail "$(printf '%s' "$P_OUT" | grep PROMOTE_FAILED)"
has "$P_OUT" P0=ok && ok "a wrong phrase is refused and leaves a replica" || fail "wrong phrase: $P_OUT"
has "$P_OUT" P1=ok && ok "device index 0 (the old owner's) is refused" || fail "index 0: $P_OUT"
has "$P_OUT" P2=ok && ok "B promoted with the phrase" || fail "promote"
has "$P_OUT" P3=ok && ok "A's device 0 named as revoked" || fail "revoked field: $P_OUT"
has "$P_OUT" P4=ok && ok "marker kept as promoted-from, replica marker gone" || fail "markers"
has "$P_OUT" P5=ok && ok "promoted-from records A's address" || fail "promoted-from content"
has "$P_OUT" P6=ok && ok "B accepts a write (folder After)" || fail "B add After"
DEVS=$(val "$P_OUT" DEVICES)
[ "$DEVS" = "0:revoked;1:live" ] && ok "devices: 0 revoked, 1 live" || fail "devices: $DEVS"
has "$P_OUT" P7=ok && ok "a second promotion is refused (not a replica any more)" || fail "second promote: $P_OUT"
TIP_PROMOTED=$(val "$P_OUT" TIP_PROMOTED); TIP_AFTER=$(val "$P_OUT" TIP_AFTER)
[ "$TIP_PROMOTED" = "$((TIP_BEFORE + 2))" ] && ok "promotion appended exactly 2 events: DeviceAuthorized, DeviceRevoked" || fail "tip $TIP_BEFORE -> $TIP_PROMOTED"
[ "$TIP_AFTER" -gt "$TIP_PROMOTED" ] && ok "After's events sit past them ($TIP_AFTER)" || fail "tip after add: $TIP_AFTER"
has "$P_OUT" P8=ok && ok "B's daemon up as the owner on :7443" || fail "B owner daemon"
NEWPIN=$(val "$P_OUT" NEWPIN)
[ "${#NEWPIN}" -eq 64 ] && ok "B's transport pin minted" || fail "new pin: $NEWPIN"
gate promotion

say "D: A rejoins as a replica of B — one unbroken chain; repoint exercised"
D_OUT=$(ssh "$A" "bash -s" <<EOS
$RH
"\$BIN/pvfs" instance rm d128new >/dev/null 2>&1; "\$BIN/pvfs" instance add d128new $B_IP:7443 $NEWPIN >/dev/null 2>&1 && echo D1=ok
got=\$("\$BIN/pvfs" --json replica add "\$A2" --instance d128new 2>"\$FT/d128-rejoin.err" | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo D2=ok || cat "\$FT/d128-rejoin.err"
L=\$("\$BIN/pvfs" --data-dir "\$AD" ls "$ROOT" 2>/dev/null)
printf '%s' "\$L" | grep -q Before && printf '%s' "\$L" | grep -q Live && printf '%s' "\$L" | grep -q After && echo D3=ok
echo "REJOIN_TIP=\$(tip "\$AD/log.db")"
python3 - "\$AD/log.db" <<'PY'
import sqlite3, sys
kinds = [k for (k,) in sqlite3.connect(sys.argv[1]).execute("select kind from events order by seq")]
print("HAS_AUTH=%s" % ("DeviceAuthorized" in kinds[-6:]))
print("HAS_REVOKE=%s" % ("DeviceRevoked" in kinds[-6:]))
PY
"\$BIN/pvfs" instance rm d128again >/dev/null 2>&1; "\$BIN/pvfs" instance add d128again $B_IP:7443 $NEWPIN >/dev/null 2>&1
"\$BIN/pvfs" --json replica repoint "\$A2" --instance d128again 2>/dev/null | grep -q '"repointed":true' && echo D4=ok
grep -q "$B_IP:7443" "\$AD/replica" && echo D5=ok
"\$BIN/pvfs" replica repoint "\$A2" --connect 127.0.0.1:1 --pin $NEWPIN >/dev/null 2>&1 && echo D6=REPOINTED_TO_NOTHING
grep -q "$B_IP:7443" "\$AD/replica" && echo D6=ok
"\$BIN/pvfs" replica sync "\$A2" >/dev/null 2>&1 && echo D7=ok
EOS
)
has "$D_OUT" D1=ok && ok "A pinned B" || fail "instance add on A"
has "$D_OUT" D2=ok && ok "A shipped B's log as a fresh replica (chain verified from genesis)" || fail "rejoin: $D_OUT"
has "$D_OUT" D3=ok && ok "A sees Before, Live and After" || fail "A's listing: $D_OUT"
[ "$(val "$D_OUT" REJOIN_TIP)" = "$TIP_AFTER" ] && ok "A's tip equals B's ($TIP_AFTER)" || fail "tips: A=$(val "$D_OUT" REJOIN_TIP) B=$TIP_AFTER"
has "$D_OUT" HAS_AUTH=True && has "$D_OUT" HAS_REVOKE=True && ok "the chain carries B's DeviceAuthorized and A's DeviceRevoked" || fail "chain kinds: $D_OUT"
has "$D_OUT" D4=ok && ok "replica repoint to another instance of the same forest" || fail "repoint: $D_OUT"
has "$D_OUT" D5=ok && ok "the marker names B" || fail "marker after repoint"
has "$D_OUT" D6=ok && ok "repoint to a dead address is refused, marker untouched" || fail "dead repoint: $D_OUT"
has "$D_OUT" D7=ok && ok "replica sync from B works after the repoint" || fail "sync after repoint"

say "E: stop the lab daemons (dirs kept under ~/fleet-test/d128-* for inspection)"
ssh "$B" 'kill "$(cat $HOME/fleet-test/d128-replica.pid)" 2>/dev/null' && ok "B's daemon stopped"
echo; echo "promote pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
