#!/bin/bash
# PVOS D200 — each box says its build, on the two-machine pair D196 uses.
#   owner : presubuntu (192.168.0.184:7494) — a throwaway forest
#   edge  : pvos-test  (192.168.0.138:7495) — its replica, announced
# The edge's `serve status` says its daemon's build; the owner's health poll
# records it per peer (`build`, and `last.build` for the probe) and `pvfs fleet
# health` prints it; with the edge stopped, the record keeps the build while
# the box is down. With COLLECTOR set (the PVOS collector, pvfs-ha-status.py),
# a scratch copy runs `--print` on the owner against this forest — nothing
# sent — and the page's `version` is the build for both boxes.
#
#   deploy/d200-build-pair.sh [<dir with pvfs and pvfsd on both boxes>]
#
# With no argument it asks (at a terminal), else uses ~/.local/bin. Run from
# the Mac; nothing here touches production or the lab.
OWNER=chris@192.168.0.184; EDGE=chris@192.168.0.138; OWNER_IP=192.168.0.184; EDGE_IP=192.168.0.138
BIN=${1:-}
if [ -z "$BIN" ] && [ -t 0 ]; then
  read -r -p "Directory holding pvfs and pvfsd on both boxes [~/.local/bin]: " BIN
fi
BIN=${BIN:-'$HOME/.local/bin'}
PASS=0; FAIL=0
say()  { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf 'ok   %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
has()  { printf '%s' "$1" | grep -q "$2"; }
val()  { printf '%s' "$1" | sed -n "s/^$2=//p" | tail -1; }
RH="B=$BIN"'; FT=$HOME/fleet-test; O=$FT/d200a-owner; R=$FT/d200a-replica; D=$O/.pvfs; RD=$R/.pvfs
jget(){ python3 -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
stopd(){ p=$(cat "$1" 2>/dev/null) || return 0; kill "$p" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || return 0; sleep 0.2; done; echo "STILL_RUNNING $p"; }
build_of(){ "$B/pvfsd" --version 2>&1 | sed -n "s/.*(\(.*\)).*/\1/p"; }
'

say "0: preflight — the same build on both boxes, free ports, a clean slate"
VA=$(ssh "$OWNER" "$RH"'build_of' </dev/null 2>&1); VB=$(ssh "$EDGE" "$RH"'build_of' </dev/null 2>&1)
[ -n "$VA" ] && [ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ or none: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" 'pkill -f "[p]vfsd --mount $HOME/fleet-test/d200a" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d200a-*; mkdir -p "$HOME/fleet-test"' </dev/null \
    && ok "$h: clean slate" || fail "$h: clean slate"
  busy=$(ssh "$h" 'ss -ltn | grep -Eo ":749[45] " | tr -d " " | tr "\n" " "' </dev/null)
  [ -z "$busy" ] && ok "$h: ports 7494–7495 free" || fail "$h: ports in use: $busy"
done
AKEY=$(ssh "$OWNER" "$RH"'"$B/pvfs" --json whoami' </dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" "$RH"'"$B/pvfs" --json whoami' </dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
gate preflight

say "A: owner — a forest, both keys enrolled, announced, listener up"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" forest init --mount "\$O" </dev/null >/dev/null 2>&1 || { echo INIT_FAILED; exit 0; }
FID=\$("\$B/pvfs" --json --data-dir "\$D" info </dev/null | jget forest_id)
"\$B/pvfs" --forest "\$O" fleet enroll $EDGEKEY --rights rwa </dev/null >/dev/null 2>&1 && echo A1=ok
"\$B/pvfs" --forest "\$O" fleet enroll $AKEY --rights rwa </dev/null >/dev/null 2>&1 && echo A2=ok
# mint the pin with a brief start, then announce with the daemon down (the lease rule)
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7494 </dev/null >/dev/null 2>"\$FT/d200a-owner.log" &
echo \$! > "\$FT/d200a-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
stopd "\$FT/d200a-owner.pid"
"\$B/pvfs" --data-dir "\$D" fleet announce $OWNER_IP:7494 </dev/null >/dev/null 2>&1 && echo A3=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7494 </dev/null >/dev/null 2>>"\$FT/d200a-owner.log" &
echo \$! > "\$FT/d200a-owner.pid"
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7494 --pin "\$PIN" --anon info </dev/null 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$got" = "\$FID" ] && { echo A4=ok; break; }; sleep 0.5
done
echo "FID=\$FID"; echo "PIN=\$PIN"
EOS
)
has "$A_OUT" INIT_FAILED && fail "owner forest init"
has "$A_OUT" A1=ok && ok "edge enrolled (rwa)" || fail "enroll edge"
has "$A_OUT" A2=ok && ok "the owner's own client key enrolled" || fail "enroll owner key"
has "$A_OUT" A3=ok && ok "owner announced its endpoint" || fail "owner announce"
has "$A_OUT" A4=ok && ok "owner daemon up on :7494" || fail "owner daemon: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d200a-owner.log' </dev/null)"
FID=$(val "$A_OUT" FID); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "owner transport pin minted" || fail "pin: $PIN"
gate owner

say "B: edge — a replica of it, announced, daemon up; its serve status says its build"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d200aowner </dev/null >/dev/null 2>&1; "\$B/pvfs" instance add d200aowner $OWNER_IP:7494 $PIN </dev/null >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d200aowner </dev/null 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7495 </dev/null >/dev/null 2>"\$FT/d200a-edge.log" &
echo \$! > "\$FT/d200a-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" fleet announce $EDGE_IP:7495 </dev/null >/dev/null 2>&1 && echo B3=ok
for _ in \$(seq 1 20); do "\$B/pvfs" --json --data-dir "\$RD" serve status </dev/null >/dev/null 2>&1 && break; sleep 0.5; done
echo "EDGEPIN=\$(cat "\$RD/nettls/pin")"
echo "STATUS_BUILD=\$("\$B/pvfs" --json --data-dir "\$RD" serve status </dev/null 2>/dev/null | jget build 2>/dev/null)"
echo "TEXT=\$("\$B/pvfs" --data-dir "\$RD" serve status </dev/null 2>/dev/null | grep '^build: ')"
EOS
)
has "$B_OUT" B1=ok && ok "edge pinned the owner" || fail "instance add: $B_OUT"
has "$B_OUT" B2=ok && ok "replica shipped the owner's log" || fail "replica add: $B_OUT"
has "$B_OUT" B3=ok && ok "edge announced its endpoint (through the owner)" || fail "edge announce"
EDGEPIN=$(val "$B_OUT" EDGEPIN)
[ "$(val "$B_OUT" STATUS_BUILD)" = "$VB" ] && ok "the edge's serve status --json says build $VB" || fail "serve status build: $(val "$B_OUT" STATUS_BUILD)"
has "$B_OUT" "TEXT=build: $VB" && ok "…and its text says it" || fail "serve status text: $(val "$B_OUT" TEXT)"
gate edge

say "C: the owner's health poll records the edge's build; fleet health prints it"
C_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" --json --data-dir "\$D" fleet health --now </dev/null 2>/dev/null > "\$FT/d200a-health.json"
python3 - "\$FT/d200a-health.json" "$EDGEPIN" <<'PY'
import json,sys
h=json.load(open(sys.argv[1])); p=h["peers"].get(sys.argv[2]) or {}
print("REC_BUILD=%s" % p.get("build")); print("LAST_BUILD=%s" % (p.get("last") or {}).get("build"))
print("UP=%s" % (p.get("last") or {}).get("reachable"))
PY
echo "LINE=\$("\$B/pvfs" --data-dir "\$D" fleet health </dev/null 2>/dev/null | grep "$EDGE_IP:7495")"
echo "OWN_BUILD=\$("\$B/pvfs" --json --data-dir "\$D" serve status </dev/null 2>/dev/null | jget build 2>/dev/null)"
EOS
)
[ "$(val "$C_OUT" UP)" = True ] && ok "the owner reached the edge" || fail "probe: $C_OUT"
[ "$(val "$C_OUT" REC_BUILD)" = "$VB" ] && ok "fleet-health.json: the edge's build is $VB" || fail "record build: $(val "$C_OUT" REC_BUILD)"
[ "$(val "$C_OUT" LAST_BUILD)" = "$VB" ] && ok "…and the probe's (last.build)" || fail "last.build: $(val "$C_OUT" LAST_BUILD)"
has "$(val "$C_OUT" LINE)" "$VB" && ok "pvfs fleet health prints it: $(val "$C_OUT" LINE | sed 's/^ *//')" || fail "fleet health line: $(val "$C_OUT" LINE)"
[ "$(val "$C_OUT" OWN_BUILD)" = "$VA" ] && ok "the owner's own serve status says $VA" || fail "owner build: $(val "$C_OUT" OWN_BUILD)"

collect() {  # the PVOS collector, --print, a scratch config and HOME, this forest
  ssh "$OWNER" "bash -s" <<EOS
$RH
S=\$FT/d200a-collector; mkdir -p "\$S/home"
sed "s#^PVFS = .*#PVFS = \"\$B/pvfs\"#" "\$S/pvfs-ha-status.py.src" > "\$S/pvfs-ha-status.py"
printf 'PVFS_MOUNT=%s\nPVFS_ANNOUNCE=$OWNER_IP:7494\n' "\$O" > "\$S/conf"
HOME="\$S/home" PVFS_HA_STATUS_CONF="\$S/conf" python3 "\$S/pvfs-ha-status.py" --print </dev/null 2>"\$S/err" > "\$S/snap.json"
python3 - "\$S/snap.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1])); b=s["boxes"]; e=[v for k,v in b.items() if k!="owner"]
print("OWNER_V=%s" % b["owner"].get("version")); print("EDGE_V=%s" % (e[0].get("version") if e else None))
print("EDGE_UP=%s" % (e[0].get("up") if e else None)); print("PROBLEMS=%s" % s["problems"])
PY
EOS
}
if [ -n "${COLLECTOR:-}" ]; then
  say "D: the page — the collector's --print shows each daemon's build as its version"
  ssh "$OWNER" 'mkdir -p $HOME/fleet-test/d200a-collector' </dev/null
  scp -q "$COLLECTOR" "$OWNER:fleet-test/d200a-collector/pvfs-ha-status.py.src"
  D_OUT=$(collect)
  [ "$(val "$D_OUT" OWNER_V)" = "$VA" ] && ok "the owner's row: $VA (its daemon's)" || fail "owner row: $D_OUT"
  [ "$(val "$D_OUT" EDGE_V)" = "$VB" ] && ok "the edge's row: $VB" || fail "edge row: $D_OUT"
else
  say "D: skipped — set COLLECTOR to the PVOS collector (pvfs-ha-status.py) to check the page"
fi

say "E: the edge stopped — down after two polls, and the record keeps its build"
ssh "$EDGE" "$RH"'stopd "$FT/d200a-edge.pid"' </dev/null && ok "edge daemon stopped"
E_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" --json --data-dir "\$D" fleet health --now </dev/null >/dev/null 2>&1
"\$B/pvfs" --json --data-dir "\$D" fleet health --now </dev/null 2>/dev/null > "\$FT/d200a-health.json"
python3 - "\$FT/d200a-health.json" "$EDGEPIN" <<'PY'
import json,sys
h=json.load(open(sys.argv[1])); p=h["peers"].get(sys.argv[2]) or {}
print("MISSES=%s" % p.get("misses")); print("REC_BUILD=%s" % p.get("build"))
print("LAST_BUILD=%s" % (p.get("last") or {}).get("build"))
PY
EOS
)
[ "$(val "$E_OUT" MISSES)" -ge 2 ] 2>/dev/null && ok "the edge is down (misses $(val "$E_OUT" MISSES))" || fail "misses: $E_OUT"
[ "$(val "$E_OUT" REC_BUILD)" = "$VB" ] && ok "…and its record still says build $VB" || fail "record build: $(val "$E_OUT" REC_BUILD)"
[ "$(val "$E_OUT" LAST_BUILD)" = None ] && ok "…while the probe's own says nothing (it heard nothing)" || fail "last.build: $(val "$E_OUT" LAST_BUILD)"
if [ -n "${COLLECTOR:-}" ]; then
  D_OUT=$(collect)
  [ "$(val "$D_OUT" EDGE_V)" = "$VB" ] && [ "$(val "$D_OUT" EDGE_UP)" = False ] \
    && ok "the page: the edge down, still showing $VB" || fail "edge row when down: $D_OUT"
fi

say "F: stop the owner (dirs kept under ~/fleet-test/d200a-* for inspection)"
ssh "$OWNER" "$RH"'stopd "$FT/d200a-owner.pid"' </dev/null && ok "owner daemon stopped"
ssh "$EDGE" "$RH"'"$B/pvfs" instance rm d200aowner' </dev/null >/dev/null 2>&1
echo; echo "build pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
