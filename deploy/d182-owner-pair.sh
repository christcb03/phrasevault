#!/bin/bash
# PVOS D182 — the owner can be lost, on the two-machine lab the D128 pair uses:
#   A : presubuntu (192.168.0.184) — the forest's first owner; later the ZOMBIE
#   B : pvos-test  (192.168.0.138) — a replica, promoted THROUGH A COMPANION
# A and B agree on the tip; A goes down; B is promoted with a headless
# companion holding the lab forest's phrase (no phrase typed); A comes back
# with its unit's old log — and fences itself before it listens, because B's
# log is longer. A write on the zombie is refused. B makes a dated copy of the
# log; the copy restores into a replica that opens at the same tip; the old A
# rejoins as a replica of B.
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
RH='BIN=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d182-owner; R=$FT/d182-replica; A2=$FT/d182-rejoin; X=$FT/d182-restored; D=$O/.pvfs; RD=$R/.pvfs
jget(){ python3 -c "import json,sys; v=json.load(sys.stdin); [v:=v[k] for k in sys.argv[1].split(\".\")]; print(v)" "$1"; }
stopd(){ p=$(cat "$1" 2>/dev/null) || return 0; kill "$p" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done; echo "STILL_RUNNING $p"; }
'

say "0: preflight — the D182 build on both boxes, a clean slate"
VA=$(ssh "$A" '"$HOME/.local/bin/pvfs" --version' 2>&1); VB=$(ssh "$B" '"$HOME/.local/bin/pvfs" --version' 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$A" "$B"; do
  ssh "$h" 'for c in tip fence backup restore; do "$HOME/.local/bin/pvfs" forest $c --help >/dev/null 2>&1 || exit 1; done' \
    && ok "$h has forest tip/fence/backup/restore" || fail "$h: not a D182 build"
  ssh "$h" 'pkill -f "pvfsd --mount $HOME/fleet-test/d182" 2>/dev/null; pkill -f "[d]182-companion" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d182-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
AKEY=$(ssh "$A" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
BKEY=$(ssh "$B" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
gate preflight

say "A: the owner — forest, both boxes enrolled, health on, listening on :7452"
A_OUT=$(ssh "$A" "bash -s" <<EOS
$RH
INIT=\$("\$BIN/pvfs" --json forest init --mount "\$O" --no-import --new-phrase 2>/dev/null) || { echo INIT_FAILED; exit 0; }
MN=\$(printf '%s' "\$INIT" | jget mnemonic); ROOT=\$(printf '%s' "\$INIT" | jget root_node_id); FID=\$(printf '%s' "\$INIT" | jget forest_id)
"\$BIN/pvfs" --forest "\$O" fleet enroll $BKEY --rights rwa >/dev/null 2>&1 && echo A0=ok
"\$BIN/pvfs" --forest "\$O" fleet enroll $AKEY --rights rwa >/dev/null 2>&1 && echo A1=ok
"\$BIN/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label Before >/dev/null && echo A2=ok
"\$BIN/pvfs" --data-dir "\$D" serve enable health >/dev/null 2>&1 && echo A3=ok
nohup "\$BIN/pvfsd" --mount "\$O" --listen 0.0.0.0:7452 >/dev/null 2>"\$FT/d182-owner.log" &
echo \$! > "\$FT/d182-owner.pid"
for _ in \$(seq 1 150); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
echo "MN=\$MN"; echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
has "$A_OUT" A0=ok && ok "B enrolled (rwa)" || fail "enroll B"
has "$A_OUT" A1=ok && ok "A's client key enrolled (its health probe dials B)" || fail "enroll A"
has "$A_OUT" A2=ok && ok "folder Before written on A" || fail "add Before"
has "$A_OUT" A3=ok && ok "health job on (the owner's peer probe — and its fence)" || fail "serve enable health"
MN=$(val "$A_OUT" MN); ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "A listening, pin minted" || fail "pin: $PIN"
gate owner

say "B: the replica — follows A, announced to the fleet"
B_OUT=$(ssh "$B" "bash -s" <<EOS
$RH
"\$BIN/pvfs" instance rm d182owner >/dev/null 2>&1; "\$BIN/pvfs" instance add d182owner $A_IP:7452 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$BIN/pvfs" --json replica add "\$R" --instance d182owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$BIN/pvfs" --data-dir "\$RD" serve enable follow >/dev/null 2>&1
nohup "\$BIN/pvfsd" --mount "\$R" --listen 0.0.0.0:7453 >/dev/null 2>"\$FT/d182-replica.log" &
echo \$! > "\$FT/d182-replica.pid"
for _ in \$(seq 1 150); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
cd "\$R" && "\$BIN/pvfs" fleet announce $B_IP:7453 >/dev/null 2>&1 && echo B3=ok
EOS
)
has "$B_OUT" B1=ok && ok "B pinned A" || fail "instance add: $B_OUT"
has "$B_OUT" B2=ok && ok "B shipped A's log" || fail "replica add: $B_OUT"
has "$B_OUT" B3=ok && ok "B announced itself (written through A)" || fail "announce: $B_OUT"
gate replica

say "C: the tips agree — pvfs forest tip on both"
sleep 6
TA=$(ssh "$A" "bash -s" <<EOS
$RH
"\$BIN/pvfs" --json forest tip "\$O"
EOS
)
TB=$(ssh "$B" "bash -s" <<EOS
$RH
"\$BIN/pvfs" --json forest tip "\$R"
EOS
)
SA=$(printf '%s' "$TA" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j["seq"], j["hash"], j["replica"])' 2>/dev/null)
SB=$(printf '%s' "$TB" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j["seq"], j["hash"], j["replica"])' 2>/dev/null)
[ "${SA% *}" = "${SB% *}" ] && [ -n "${SA% *}" ] && ok "same seq and hash on both (${SA%% *})" || fail "tips: A=$SA B=$SB"
[ "${SA##* }" = "False" ] && [ "${SB##* }" = "True" ] && ok "A says owner, B says replica" || fail "roles: A=$SA B=$SB"
TIP_BEFORE=${SA%% *}
gate tips

say "D: A goes down; B is promoted through a headless companion (no phrase typed)"
ssh "$A" "bash -s" <<EOS >/dev/null
$RH
stopd "\$FT/d182-owner.pid"
EOS
ok "A's daemon stopped (the owner is down)"
P_OUT=$(ssh "$B" "bash -s" <<EOS
$RH
export PVFS_COMPANION_PASSPHRASE=d182-lab-only-passphrase
printf '%s\n' "$MN" | "\$BIN/pvfs-companion" init --vault "\$FT/d182-companion.vault" --passphrase >/dev/null 2>&1 && echo P0=ok
nohup "\$BIN/pvfs-companion" serve --vault "\$FT/d182-companion.vault" --socket "\$FT/d182-companion.sock" \
  --allow-root --prompt deny --web-port 0 --idle-lock-secs 0 >"\$FT/d182-companion.log" 2>&1 &
echo \$! > "\$FT/d182-companion.pid"
for _ in \$(seq 1 50); do [ -S "\$FT/d182-companion.sock" ] && break; sleep 0.2; done
stopd "\$FT/d182-replica.pid"
J=\$("\$BIN/pvfs" --json forest promote "\$R" --via-companion --companion-socket "\$FT/d182-companion.sock" --yes 2>"\$FT/d182-promote.err") \
  || { echo "PROMOTE_FAILED: \$(tail -3 "\$FT/d182-promote.err")"; exit 0; }
printf '%s' "\$J" | grep -q '"signed_by":"companion"' && echo P1=ok
printf '%s' "\$J" | grep -q '"revoked":\["' && echo P2=ok
echo "PROMOTED_TIP=\$(printf '%s' "\$J" | jget tip)"
"\$BIN/pvfs" --data-dir "\$RD" serve disable follow >/dev/null 2>&1
"\$BIN/pvfs" --data-dir "\$RD" add "$ROOT" --kind folder --label After >/dev/null 2>&1 && echo P3=ok
nohup "\$BIN/pvfsd" --mount "\$R" --listen 0.0.0.0:7453 >/dev/null 2>"\$FT/d182-newowner.log" &
echo \$! > "\$FT/d182-replica.pid"
for _ in \$(seq 1 50); do "\$BIN/pvfs" --data-dir "\$RD" serve status >/dev/null 2>&1 && break; sleep 0.2; done
"\$BIN/pvfs" --json forest tip "\$R" | python3 -c 'import json,sys; j=json.load(sys.stdin); print("NEW_OWNER=%s %s" % (not j["replica"], j["seq"]))'
echo "NEWPIN=\$(cat "\$RD/nettls/pin")"
EOS
)
has "$P_OUT" PROMOTE_FAILED && fail "$(printf '%s' "$P_OUT" | grep PROMOTE_FAILED)"
has "$P_OUT" P0=ok && ok "a headless companion holds the lab phrase (its vault, --allow-root)" || fail "companion init"
has "$P_OUT" P1=ok && ok "B promoted, signed by the companion" || fail "promote: $P_OUT"
has "$P_OUT" P2=ok && ok "the old owner's device named as revoked (default: every other live owner device)" || fail "revoked: $P_OUT"
[ "$(val "$P_OUT" PROMOTED_TIP)" = "$((TIP_BEFORE + 2))" ] && ok "one append: DeviceAuthorized + DeviceRevoked at $((TIP_BEFORE + 1))–$((TIP_BEFORE + 2))" || fail "promoted tip $(val "$P_OUT" PROMOTED_TIP) vs $TIP_BEFORE"
has "$P_OUT" P3=ok && ok "B writes (folder After) with its companion-made device key" || fail "B write"
has "$P_OUT" "NEW_OWNER=True" && ok "B is the owner now ($(val "$P_OUT" NEW_OWNER))" || fail "B role: $P_OUT"
NEWPIN=$(val "$P_OUT" NEWPIN)
gate promotion

say "E: the ZOMBIE — A comes back on its old log, hears B first, and fences itself"
E_OUT=$(ssh "$A" "bash -s" <<EOS
$RH
nohup "\$BIN/pvfsd" --mount "\$O" --listen 0.0.0.0:7452 >/dev/null 2>"\$FT/d182-zombie.log" &
echo \$! > "\$FT/d182-owner.pid"
for _ in \$(seq 1 150); do [ -f "\$D/fenced" ] && break; sleep 0.2; done
[ -f "\$D/fenced" ] && echo E1=ok
grep -q "hearing the fleet before listening" "\$FT/d182-zombie.log" && echo E2=ok
"\$BIN/pvfs" --json forest tip "\$O" | python3 -c 'import json,sys; j=json.load(sys.stdin); print("FENCE=%s" % (j["fenced"] or {}).get("peer",""))'
"\$BIN/pvfs" --json forest fence "\$O" | grep -q '"fenced":true' && echo E3=ok
TIP_ZOMBIE=\$("\$BIN/pvfs" --json forest tip "\$O" | jget seq)
"\$BIN/pvfs" --data-dir "\$D" add "$ROOT" --kind folder --label Ghost >"\$FT/d182-ghost.txt" 2>&1 && echo E4=GHOST_WRITTEN
grep -q "fenced" "\$FT/d182-ghost.txt" && echo E4=ok
[ "\$("\$BIN/pvfs" --json forest tip "\$O" | jget seq)" = "\$TIP_ZOMBIE" ] && echo E5=ok
"\$BIN/pvfs" --data-dir "\$D" serve status 2>/dev/null | head -1 | grep -q "^FENCED" && echo E6=ok
echo "TIP_ZOMBIE=\$TIP_ZOMBIE"
EOS
)
has "$E_OUT" E1=ok && ok "the zombie fenced itself" || fail "no fence: $E_OUT $(ssh "$A" 'tail -5 $HOME/fleet-test/d182-zombie.log')"
has "$E_OUT" E2=ok && ok "…before it listened (it heard the fleet first)" || fail "no startup gate line"
has "$E_OUT" "FENCE=$B_IP:7453" && ok "the fence names B ($B_IP:7453) as the longer log" || fail "fence peer: $E_OUT"
has "$E_OUT" E3=ok && ok "pvfs forest fence shows it" || fail "forest fence"
has "$E_OUT" E4=ok && ok "a write on the zombie is refused, and says fenced" || fail "ghost write: $E_OUT"
has "$E_OUT" E5=ok && ok "the zombie's log did not move" || fail "zombie tip moved"
has "$E_OUT" E6=ok && ok "serve status leads with FENCED" || fail "serve status"
[ "$(val "$E_OUT" TIP_ZOMBIE)" = "$TIP_BEFORE" ] && ok "the zombie still holds the old tip ($TIP_BEFORE)" || fail "zombie tip $(val "$E_OUT" TIP_ZOMBIE)"
gate zombie

say "F: a dated copy on B — verified by a full replay; restored on A as a replica at the same tip"
F_OUT=$(ssh "$B" "bash -s" <<EOS
$RH
J=\$("\$BIN/pvfs" --json --forest "\$R" forest backup --to "\$FT/d182-backups" --keep 30 2>"\$FT/d182-backup.err") || { echo "BACKUP_FAILED: \$(tail -2 "\$FT/d182-backup.err")"; exit 0; }
C=\$(printf '%s' "\$J" | jget copy); echo "COPY=\$C"; echo "COPY_SEQ=\$(printf '%s' "\$J" | jget seq)"
[ -f "\$C/manifest.json" ] && grep -q '"verified": true' "\$C/manifest.json" && echo F1=ok
python3 -c "import json,sys; print('OK' if json.load(open(sys.argv[1]))['ok'] else 'BAD')" "\$RD/backup-state.json" | grep -q OK && echo F2=ok
"\$BIN/pvfs" --json --data-dir "\$RD" serve status 2>/dev/null | python3 -c 'import json,sys; b=json.load(sys.stdin).get("log") or {}; print("STATUS_LOG=%s" % b.get("seq"))'
EOS
)
has "$F_OUT" BACKUP_FAILED && fail "$(printf '%s' "$F_OUT" | grep BACKUP_FAILED)"
has "$F_OUT" F1=ok && ok "the copy has a verified manifest" || fail "copy: $F_OUT"
has "$F_OUT" F2=ok && ok "backup-state.json records it (serve status reports it)" || fail "backup state"
COPY=$(val "$F_OUT" COPY); COPY_SEQ=$(val "$F_OUT" COPY_SEQ)
[ -n "$(val "$F_OUT" STATUS_LOG)" ] && ok "serve status carries the log tip (seq $(val "$F_OUT" STATUS_LOG))" || fail "status log: $F_OUT"
scp -q -r "$B:$COPY" "$A:fleet-test/d182-copy" && ok "the copy moved to A (scp)" || fail "scp copy"
X_OUT=$(ssh "$A" "bash -s" <<EOS
$RH
"\$BIN/pvfs" --json forest restore "\$FT/d182-copy" "\$X" 2>&1 | tail -1
"\$BIN/pvfs" --json forest tip "\$X" 2>/dev/null | python3 -c 'import json,sys; j=json.load(sys.stdin); print("RESTORED=%s %s" % (j["replica"], j["seq"]))'
EOS
)
has "$X_OUT" "RESTORED=True $COPY_SEQ" && ok "the copy restored into a replica at seq $COPY_SEQ" || fail "restore: $X_OUT"
gate copies

say "G: the old A rejoins as a replica of B, in a fresh directory — one chain"
G_OUT=$(ssh "$A" "bash -s" <<EOS
$RH
stopd "\$FT/d182-owner.pid"
"\$BIN/pvfs" instance rm d182new >/dev/null 2>&1; "\$BIN/pvfs" instance add d182new $B_IP:7453 $NEWPIN >/dev/null 2>&1
"\$BIN/pvfs" --json replica add "\$A2" --instance d182new 2>/dev/null | jget forest_id | grep -q "$FID" && echo G1=ok
"\$BIN/pvfs" --data-dir "\$A2/.pvfs" ls "$ROOT" 2>/dev/null | grep -q After && echo G2=ok
"\$BIN/pvfs" --data-dir "\$A2/.pvfs" ls "$ROOT" 2>/dev/null | grep -q Ghost || echo G3=ok
EOS
)
has "$G_OUT" G1=ok && ok "A shipped B's log as a fresh replica (chain verified from genesis)" || fail "rejoin: $G_OUT"
has "$G_OUT" G2=ok && ok "it sees After" || fail "no After on the rejoined A"
has "$G_OUT" G3=ok && ok "and no Ghost — the zombie's refused write exists nowhere" || fail "Ghost found"

say "H: stop the lab daemons and the companion (dirs kept under ~/fleet-test/d182-*)"
ssh "$B" 'kill "$(cat $HOME/fleet-test/d182-replica.pid)" "$(cat $HOME/fleet-test/d182-companion.pid)" 2>/dev/null' && ok "B's daemon and companion stopped"
echo; echo "owner pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
