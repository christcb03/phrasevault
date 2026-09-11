#!/bin/bash
# D133 item 6 — the mover on the new model, on the D129 pair: the edge's
# shelf DRAINS (staging), the owner's shelf RECEIVES (library). A file that
# appears on the edge is pulled by hash into the owner's shelf, the edge's
# resolve trashes its copy once the library has it, retention 0 purges it;
# an upgrade on the edge replaces the owner's older copy.
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
RH='B=$HOME/.local/bin; FT=$HOME/fleet-test; O=$FT/d133-owner; R=$FT/d133-replica; D=$O/.pvfs; RD=$R/.pvfs
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

say "0: preflight — the D133 build on both boxes, a clean slate"
VA=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --version' 2>&1); VB=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --version' 2>&1)
[ "$VA" = "$VB" ] && ok "both boxes run the same build ($VA)" || fail "builds differ: A=$VA B=$VB"
for h in "$OWNER" "$EDGE"; do
  ssh "$h" '"$HOME/.local/bin/pvfs" view receive --help >/dev/null 2>&1' && ok "$h has view receive" || fail "$h: not a D133 build"
  ssh "$h" 'pkill -f "pvfsd --mount $HOME/fleet-test/d129" 2>/dev/null; sleep 1; rm -rf "$HOME/fleet-test"/d133-*; mkdir -p "$HOME/fleet-test"' \
    && ok "$h: clean slate" || fail "$h: clean slate"
done
AKEY=$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
EDGEKEY=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami' | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])')
[ "${#AKEY}" -eq 66 ] && [ "${#EDGEKEY}" -eq 66 ] && ok "client identities" || fail "identities: A=$AKEY B=$EDGEKEY"
ssh "$EDGE" 'L=$HOME/fleet-test/d133-edge-lib; mkdir -p "$L/season" "$L/unused"; printf xx > "$L/x.mkv"; printf yyyy > "$L/season/y.mkv"' \
  && ok "edge library staged (x.mkv, season/y.mkv, unused/)" || fail "edge library"
gate preflight

say "A: owner — forest, two catalogue regions, its shelf catalogued, announced, listener up with the catalogue job"
A_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
L=\$FT/d133-owner-lib; mkdir -p "\$L/sub" "\$L/empty"; printf aaa > "\$L/a.mkv"; printf bbbbb > "\$L/sub/b.mkv"
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
"\$B/pvfs" --json --data-dir "\$D" region receive "\$OWN" on | grep -q '"receives":true' && echo A5b=ok
"\$B/pvfs" --json --data-dir "\$D" region drain "\$EDGESHELF" on | grep -q '"drains":true' && echo A5c=ok
# mint the pin with a brief start, then announce with the daemon down (the lease rule)
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7450 >/dev/null 2>"\$FT/d133-owner.log" &
echo \$! > "\$FT/d133-owner.pid"
for _ in \$(seq 1 50); do [ -s "\$D/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$D/nettls/pin" 2>/dev/null || echo MISSING)
stopd "\$FT/d133-owner.pid"
"\$B/pvfs" --data-dir "\$D" fleet announce $OWNER_IP:7450 >/dev/null 2>&1 && echo A6=ok
"\$B/pvfs" --data-dir "\$D" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable catalogue >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" serve enable receive >/dev/null 2>&1 && echo A7=ok
nohup "\$B/pvfsd" --mount "\$O" --listen 0.0.0.0:7450 >/dev/null 2>>"\$FT/d133-owner.log" &
echo \$! > "\$FT/d133-owner.pid"
for _ in \$(seq 1 40); do
  got=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7450 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
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
has "$A_OUT" A5b=ok && ok "own-shelf receives (the library)" || fail "region receive"
has "$A_OUT" A5c=ok && ok "edge-shelf drains (staging) — fleet-visible" || fail "region drain"
has "$A_OUT" A6=ok && ok "owner announced its endpoint" || fail "owner announce"
has "$A_OUT" A7=ok && ok "owner enabled watch + catalogue + receive jobs" || fail "owner serve enable"
has "$A_OUT" A8=ok && ok "owner daemon up on :7450" || fail "owner daemon: $(ssh "$OWNER" 'tail -3 $HOME/fleet-test/d133-owner.log')"
ROOT=$(val "$A_OUT" ROOT); FID=$(val "$A_OUT" FID); OWN=$(val "$A_OUT" OWN); EDGESHELF=$(val "$A_OUT" EDGESHELF); PIN=$(val "$A_OUT" PIN)
[ "${#PIN}" -eq 64 ] && ok "owner transport pin minted" || fail "pin: $PIN"
gate owner

say "B: edge — replica, binds its shelf, announces, publishes its head through the owner"
B_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
"\$B/pvfs" instance rm d133owner >/dev/null 2>&1; "\$B/pvfs" instance add d133owner $OWNER_IP:7450 $PIN >/dev/null 2>&1 && echo B1=ok
got=\$("\$B/pvfs" --json replica add "\$R" --instance d133owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$got" = "$FID" ] && echo B2=ok
"\$B/pvfs" --data-dir "\$RD" bind "$EDGESHELF" "\$FT/d133-edge-lib" --hash-policy on_add >/dev/null 2>&1 && echo B3=ok
age=\$(( \$(date +%s) - \$(stat -c %Z "\$FT/d133-edge-lib/x.mkv") )); [ "\$age" -lt 17 ] && sleep \$(( 17 - age ))
nohup "\$B/pvfsd" --mount "\$R" --listen 0.0.0.0:7451 >/dev/null 2>"\$FT/d133-edge.log" &
echo \$! > "\$FT/d133-edge.pid"
for _ in \$(seq 1 50); do [ -s "\$RD/nettls/pin" ] && break; sleep 0.2; done
"\$B/pvfs" --data-dir "\$RD" fleet announce $EDGE_IP:7451 >/dev/null 2>&1 && echo B4=ok
"\$B/pvfs" --data-dir "\$RD" serve enable follow >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable watch >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable catalogue >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" region retention "$EDGESHELF" 0 >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$RD" serve enable resolve >/dev/null 2>&1 && echo B5=ok
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
has "$B_OUT" B5=ok && ok "edge daemon up with follow + watch + catalogue + resolve, retention 0" || fail "edge serve jobs"
has "$B_OUT" B6=ok && ok "edge published edge-shelf head 1 through the owner" || fail "no edge head within 180s: $(ssh "$EDGE" 'tail -3 $HOME/fleet-test/d133-edge.log')"
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

say "D: the edge's x.mkv and season/y.mkv exist only on staging — the owner receives them"
D_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
"\$B/pvfs" --json --data-dir "\$D" view receive --dry-run | python3 -c '
import json,sys
r=json.load(sys.stdin); print("PLANNED=" + ",".join(sorted(x["path"] for x in r["received"])))'
"\$B/pvfs" --json --data-dir "\$D" view receive > "\$FT/d133-recv.json" 2>"\$FT/d133-recv.err" && echo D1=ok
python3 - "\$FT/d133-recv.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert sorted(x["path"] for x in r["received"])==["season/y.mkv","x.mkv"], r
assert r["failed"]==[] and r["skipped_no_space"]==[], r
PY
[ "\$(cat "\$FT/d133-owner-lib/x.mkv")" = "xx" ] && [ "\$(cat "\$FT/d133-owner-lib/season/y.mkv")" = "yyyy" ] && echo D2=ok
ls "\$FT/d133-owner-lib/.x.mkv.manifest" "\$FT/d133-owner-lib/season/.y.mkv.manifest" >/dev/null 2>&1 && echo D3=ok
[ "\$(stat -c %Y "\$FT/d133-owner-lib/x.mkv")" = "\$(python3 -c 'import json,sys; d=json.load(sys.stdin); print([e for e in d["entries"] if e["path"]=="x.mkv"][0]["mtime_ms"]//1000)' < <("\$B/pvfs" --json --data-dir "\$D" region entries "$EDGESHELF"))" ] && echo D4=ok
grep -q "received x.mkv" "\$FT/d133-owner.log" && echo D5=job || echo D5=cli
EOS
)
[ "$(val "$D_OUT" PLANNED)" = "season/y.mkv,x.mkv" ] && ok "dry run plans the edge's two files" || fail "plan: $(val "$D_OUT" PLANNED)"
has "$D_OUT" D1=ok && ok "view receive pulled both by hash over the wire from the edge" || fail "receive: $D_OUT $(ssh "$OWNER" 'cat $HOME/fleet-test/d133-recv.err')"
has "$D_OUT" D2=ok && ok "the bytes landed at the same relative paths in own-shelf" || fail "bytes"
has "$D_OUT" D3=ok && ok "sidecars written beside them" || fail "sidecars"
has "$D_OUT" D4=ok && ok "mtime copied from the staging row" || fail "mtime"
gate receive

say "E: the owner's watch catalogues them; the edge sees two copies; its resolve drains its own; retention 0 purges"
E_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
for _ in \$(seq 1 90); do
  n=\$("\$B/pvfs" --json --data-dir "\$D" region entries "$OWN" 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for e in d["entries"] if e["path"] in ("x.mkv","season/y.mkv")))' 2>/dev/null || echo 0)
  [ "\$n" = "2" ] && { echo E1=ok; break; }; sleep 2
done
echo "OWNER_HEAD=\$(rstat "\$D" "$OWN" | cut -d/ -f2)"
EOS
)
has "$E_OUT" E1=ok && ok "the owner's watch catalogued the received files (head $(val "$E_OUT" OWNER_HEAD))" || fail "owner watch: $E_OUT"
F_OUT=$(ssh "$EDGE" "bash -s" <<EOS
$RH
for _ in \$(seq 1 90); do
  c=\$("\$B/pvfs" --json --data-dir "\$RD" view ls 2>/dev/null | python3 -c 'import json,sys; v={e["path"]:e for e in json.load(sys.stdin)}; print(v.get("x.mkv",{}).get("copies",0))' 2>/dev/null || echo 0)
  [ "\$c" = "2" ] && { echo F1=ok; break; }; sleep 2
done
"\$B/pvfs" --json --data-dir "\$RD" view resolve | python3 -c '
import json,sys
r=json.load(sys.stdin); assert sorted(t["path"] for t in r["trashed"])==["season/y.mkv","x.mkv"], r
print("PURGED=%d" % r["purged"])' && echo F2=ok
[ ! -e "\$FT/d133-edge-lib/x.mkv" ] && [ ! -e "\$FT/d133-edge-lib/season/y.mkv" ] && echo F3=ok
[ -z "\$(ls -A "\$FT/d133-edge-lib/.pvfs-trash" 2>/dev/null)" ] && echo F4=ok
EOS
)
has "$F_OUT" F1=ok && ok "the edge's view shows two agreeing copies (its catalogue fetch)" || fail "edge view: $F_OUT"
has "$F_OUT" F2=ok && ok "the edge's resolve trashed its staging copies" || fail "edge resolve: $F_OUT"
has "$F_OUT" F3=ok && ok "the staging files are gone from the edge's disk" || fail "edge disk"
[ "$(val "$F_OUT" PURGED)" -ge 1 ] && has "$F_OUT" F4=ok && ok "retention 0: the trash was purged in the same pass — the disk is free" || fail "purge: $F_OUT"
gate drain

say "F: an upgrade on the edge — a bigger x.mkv wins the ladder and replaces the owner's copy"
ssh "$EDGE" 'printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx > "$HOME/fleet-test/d133-edge-lib/x.mkv"' && ok "the edge wrote a bigger x.mkv"
G_OUT=$(ssh "$OWNER" "bash -s" <<EOS
$RH
for _ in \$(seq 1 120); do
  st=\$("\$B/pvfs" --json --data-dir "\$D" view ls 2>/dev/null | python3 -c 'import json,sys; v={e["path"]:e for e in json.load(sys.stdin)}; print(v.get("x.mkv",{}).get("state",""))' 2>/dev/null)
  [ "\$st" = "conflict:hashes:2" ] && { echo G1=ok; break; }; sleep 2
done
"\$B/pvfs" --json --data-dir "\$D" view receive | python3 -c '
import json,sys
r=json.load(sys.stdin); assert [x["path"] for x in r["received"]]==["x.mkv"] and r["replaced"]==["x.mkv"], r' && echo G2=ok
[ "\$(wc -c < "\$FT/d133-owner-lib/x.mkv")" = "47" ] && echo G3=ok
ls "\$FT/d133-owner-lib"/.pvfs-trash/*/x.mkv >/dev/null 2>&1 && echo G4=ok
EOS
)
has "$G_OUT" G1=ok && ok "the owner's view shows the conflict (edge's head, fetched)" || fail "conflict never seen: $G_OUT"
has "$G_OUT" G2=ok && ok "view receive replaced the owner's copy with the staging winner" || fail "replace: $G_OUT"
has "$G_OUT" G3=ok && ok "the bigger bytes are in place" || fail "replaced bytes"
has "$G_OUT" G4=ok && ok "the old library copy is in the owner's trash (retained)" || fail "old copy not in trash"

say "G: stop the lab daemons (dirs kept under ~/fleet-test/d133-* for inspection)"
ssh "$EDGE" 'kill "$(cat $HOME/fleet-test/d133-edge.pid)" 2>/dev/null; true' && ok "edge daemon stopped"
ssh "$OWNER" 'kill "$(cat $HOME/fleet-test/d133-owner.pid)" 2>/dev/null; true' && ok "owner daemon stopped"
echo; echo "receive pair: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
