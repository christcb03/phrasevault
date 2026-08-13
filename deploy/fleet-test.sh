#!/bin/bash
# Two-machine fleet test — HANDOFF.md items 2+3 (USER-MANUAL §7.7–§7.10)
#   owner/NAS : presubuntu (192.168.0.184) — owns the forest, runs the mover
#   edge      : pvos-test  (192.168.0.138) — replica, ingest box, consumer
# Orchestrated from the Mac over ssh; binaries installed by the ansible pipeline.
set -u

OWNER=chris@192.168.0.184
EDGE=chris@192.168.0.138
OWNER_IP=192.168.0.184
EDGE_IP=192.168.0.138
B='$HOME/.local/bin'          # expanded remotely
FT='$HOME/fleet-test'

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "ok   $*"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL $*"; }
say()  { echo; echo "== $*"; }
gate() { if [ "$FAIL" -gt 0 ]; then echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; fi; }
# tiny JSON extractors (run on the Mac)
jkey() { python3 -c 'import json,sys;print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"; }

# every remote block gets these helpers prepended
RHELPERS='
jget(){ python3 -c "import json,sys;print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
pick(){ python3 -c "import json,sys
for e in json.load(sys.stdin):
    if e[\"label\"]==sys.argv[1]: print(e[\"id\"])" "$1"; }
'

say "0: preflight — binaries, space, clean slate"
for H in "$OWNER" "$EDGE"; do
  ssh "$H" 'test -x "$HOME/.local/bin/pvfs" && test -x "$HOME/.local/bin/pvfsd"' \
    && ok "binaries present on $H" || fail "binaries missing on $H"
  FREE=$(ssh "$H" 'df --output=avail -BG "$HOME" | tail -1 | tr -dc 0-9')
  [ "$FREE" -ge 10 ] && ok "$H has ${FREE}G free (need 10G)" || fail "$H low on space: ${FREE}G"
  ssh "$H" 'pkill -f "pvfsd --mount $HOME/fleet-test" 2>/dev/null; rm -rf "$HOME/fleet-test"; true' \
    && ok "clean slate on $H" || fail "cleanup on $H"
done
gate preflight

say "A: owner setup — forest, library, TLS listener (presubuntu)"
OWNER_OUT=$(ssh "$OWNER" "bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test
mkdir -p "\$FT/library/movies"
head -c 1048576 /dev/urandom > "\$FT/library/movies/alpha.mkv"
printf 'fleet-notes' > "\$FT/library/notes.txt"
"\$B/pvfs" forest init --mount "\$FT/owner" >/dev/null 2>&1 || { echo INIT_FAILED; exit 0; }
D="\$FT/owner/.pvfs"
INFO=\$("\$B/pvfs" --json --data-dir "\$D" info)
ROOT=\$(printf '%s' "\$INFO" | jget root_node_id)
FID=\$(printf '%s' "\$INFO" | jget forest_id)
LIB=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label library)
"\$B/pvfs" --data-dir "\$D" bind "\$LIB" "\$FT/library" --hash-policy on_add >/dev/null
"\$B/pvfs" --data-dir "\$D" scan "\$LIB" >/dev/null
MOVIES=\$("\$B/pvfs" --json --data-dir "\$D" ls "\$LIB" | pick movies)
ALPHA=\$("\$B/pvfs" --json --data-dir "\$D" ls "\$MOVIES" | pick alpha.mkv)
NOTES=\$("\$B/pvfs" --json --data-dir "\$D" ls "\$LIB" | pick notes.txt)
nohup "\$B/pvfsd" --mount "\$FT/owner" --listen 0.0.0.0:7430 >/dev/null 2>"\$FT/pvfsd.log" &
for _ in \$(seq 1 50); do [ -s "\$FT/owner/.pvfs/nettls/pin" ] && break; sleep 0.2; done
PIN=\$(cat "\$FT/owner/.pvfs/nettls/pin" 2>/dev/null || echo MISSING)
# daemon answers locally before we go cross-machine (listener may lag the pin)
OKINFO=NO
for _ in \$(seq 1 20); do
  OKINFO=\$("\$B/pvfs" --json remote --connect 127.0.0.1:7430 --pin "\$PIN" --anon info 2>/dev/null | jget forest_id 2>/dev/null || echo NO)
  [ "\$OKINFO" = "\$FID" ] && break; sleep 0.5
done
echo "ROOT=\$ROOT"; echo "FID=\$FID"; echo "LIB=\$LIB"; echo "ALPHA=\$ALPHA"; echo "NOTES=\$NOTES"
echo "PIN=\$PIN"; echo "LOCALINFO=\$OKINFO"
echo "ALPHA_SHA=\$(sha256sum "\$FT/library/movies/alpha.mkv" | cut -d' ' -f1)"
EOS
)
echo "$OWNER_OUT" | grep -q INIT_FAILED && fail "owner forest init"
eval "$(echo "$OWNER_OUT" | grep -E '^(ROOT|FID|LIB|ALPHA|NOTES|PIN|LOCALINFO|ALPHA_SHA)=')"
[ "${#ROOT}" -eq 64 ] && ok "owner forest initialized (root $ROOT)" || fail "bad root: $ROOT"
[ "${#PIN}" -eq 64 ] && ok "owner daemon minted transport pin" || fail "no pin: $PIN"
[ "$LOCALINFO" = "$FID" ] && ok "owner daemon answers over TLS locally" || fail "owner TLS self-check: $LOCALINFO"
gate "owner setup"

say "B: edge identity + owner grant"
EDGEKEY=$(jkey "$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --json whoami')" pubkey)
printf '%s' "$EDGEKEY" | grep -qE '^[0-9a-f]{64,66}$' && ok "edge client identity: $EDGEKEY" || fail "edge whoami: $EDGEKEY"
# P5.4: fleet enroll — membership + rights in one logged step (doc 18 §4)
ssh "$OWNER" '"$HOME/.local/bin/pvfs" --forest "$HOME/fleet-test/owner" fleet enroll '"$EDGEKEY"' --rights rwa' >/dev/null \
  && ok "fleet enroll admitted the edge box (member + rwa, one step)" \
  || fail "fleet enroll edge"
# the owner box's own outbound fetches (mover, read-through) authenticate as its
# CLIENT identity, not the forest device key — enroll it like any other box
OWNERKEY=$(jkey "$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami')" pubkey)
ssh "$OWNER" '"$HOME/.local/bin/pvfs" --forest "$HOME/fleet-test/owner" fleet enroll '"$OWNERKEY"' --rights r' >/dev/null \
  && ok "fleet enroll admitted the owner's own client identity (read)" \
  || fail "fleet enroll owner"
gate grant

say "C: §7.7 replicate over the LAN (pvos-test)"
C_OUT=$(ssh "$EDGE" "ROOT=$ROOT FID=$FID LIB=$LIB ALPHA=$ALPHA NOTES=$NOTES PIN=$PIN OWNER_IP=$OWNER_IP ALPHA_SHA=$ALPHA_SHA bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; mkdir -p "\$FT"
"\$B/pvfs" instance add owner "\$OWNER_IP:7430" "\$PIN" >/dev/null && echo "C1=ok" || echo "C1=no"
REPFID=\$("\$B/pvfs" --json replica add "\$FT/replica" --instance owner 2>&1 | jget forest_id 2>/dev/null || echo NO)
[ "\$REPFID" = "\$FID" ] && echo "C2=ok" || echo "C2=no(\$REPFID)"
R="\$FT/replica/.pvfs"
"\$B/pvfs" --data-dir "\$R" ls "\$ROOT" | grep -q library && echo "C3=ok" || echo "C3=no"
"\$B/pvfs" --data-dir "\$R" stat "\$ALPHA" | grep UNAVAILABLE >/dev/null && echo "C4=ok" || echo "C4=no"
FSHA=\$("\$B/pvfs" --data-dir "\$R" cat "\$ALPHA" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "\$FSHA" = "\$ALPHA_SHA" ] && echo "C5=ok" || echo "C5=no(\$FSHA)"
"\$B/pvfs" --data-dir "\$R" stat "\$ALPHA" | grep pvfs-sync >/dev/null && echo "C6=ok" || echo "C6=no"
"\$B/pvfs" --data-dir "\$R" place "\$LIB" sync >/dev/null && echo "C7=ok" || echo "C7=no"
FETCHED=\$("\$B/pvfs" --json --data-dir "\$R" sync | jget fetched 2>/dev/null || echo 0)
[ "\$FETCHED" -ge 1 ] && echo "C8=ok" || echo "C8=no(\$FETCHED)"
"\$B/pvfs" --data-dir "\$R" export "\$LIB" "\$FT/plex-view" >/dev/null 2>&1
[ "\$(cat "\$FT/plex-view/notes.txt" 2>/dev/null)" = "fleet-notes" ] && echo "C9=ok" || echo "C9=no"
EOS
)
echo "$C_OUT" | grep -q "C1=ok" && ok "instance add pins the owner" || fail "instance add: $C_OUT"
echo "$C_OUT" | grep -q "C2=ok" && ok "replica add ships + verifies the full log over the LAN" || fail "replica add"
echo "$C_OUT" | grep -q "C3=ok" && ok "replica lists the tree" || fail "replica ls"
echo "$C_OUT" | grep -q "C4=ok" && ok "HONEST CHECK: owner's file:// location is UNAVAILABLE cross-machine" || fail "stat should be UNAVAILABLE"
echo "$C_OUT" | grep -q "C5=ok" && ok "cat self-heals: fetched 1 MiB from owner over TLS, hash-verified" || fail "read-through cat"
echo "$C_OUT" | grep -q "C6=ok" && ok "fetched bytes promoted to the sync store" || fail "no pvfs-sync location"
echo "$C_OUT" | grep -q "C7=ok" && ok "placed library subtree sync" || fail "place sync"
echo "$C_OUT" | grep -q "C8=ok" && ok "pvfs sync fetched the remaining bytes" || fail "batch sync"
echo "$C_OUT" | grep -q "C9=ok" && ok "export serves the library to non-PVFS apps" || fail "export"
gate replicate

say "D: §7.9 ingest box — write-through + loc add --here (pvos-test)"
D_OUT=$(ssh "$EDGE" "ROOT=$ROOT LIB=$LIB bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; R="\$FT/replica/.pvfs"
nohup "\$B/pvfsd" --mount "\$FT/replica" --listen 0.0.0.0:7431 >/dev/null 2>"\$FT/repd.log" &
for _ in \$(seq 1 50); do [ -s "\$R/nettls/pin" ] && break; sleep 0.2; done
for _ in \$(seq 1 50); do ss -tln | grep -q ':7431 ' && break; sleep 0.2; done
EDGEPIN=\$(cat "\$R/nettls/pin" 2>/dev/null || echo MISSING)
echo "EDGEPIN=\$EDGEPIN"
mkdir -p "\$FT/downloads"
head -c 4194304 /dev/urandom > "\$FT/downloads/new-episode.mkv"
head -c 65536   /dev/urandom > "\$FT/downloads/cache-warm.bin"
echo "EP_SHA=\$(sha256sum "\$FT/downloads/new-episode.mkv" | cut -d' ' -f1)"
echo "CW_SHA=\$(sha256sum "\$FT/downloads/cache-warm.bin" | cut -d' ' -f1)"
T0=\$(date +%s)
EP=\$("\$B/pvfs" --json --data-dir "\$R" add "\$LIB" --kind file --label new-episode.mkv --size 4194304 --mime video/x-matroska | jget node_id)
"\$B/pvfs" --data-dir "\$R" loc add "\$EP" --here "\$FT/downloads/new-episode.mkv" >/dev/null && echo "D2=ok" || echo "D2=no"
CW=\$("\$B/pvfs" --json --data-dir "\$R" add "\$LIB" --kind file --label cache-warm.bin --size 65536 | jget node_id)
"\$B/pvfs" --data-dir "\$R" loc add "\$CW" --here "\$FT/downloads/cache-warm.bin" >/dev/null
echo "CATALOG_SECS=\$(( \$(date +%s) - T0 ))"
echo "EP=\$EP"; echo "CW=\$CW"
"\$B/pvfs" --data-dir "\$R" loc ls "\$EP" | grep "pvfs-host://\$EDGEPIN" >/dev/null && echo "D3=ok" || echo "D3=no"
"\$B/pvfs" --data-dir "\$R" ls "\$LIB" | grep -q new-episode.mkv && echo "D4=ok" || echo "D4=no"
EOS
)
eval "$(echo "$D_OUT" | grep -E '^(EDGEPIN|EP|CW|EP_SHA|CW_SHA|CATALOG_SECS)=')"
[ "${#EDGEPIN}" -eq 64 ] && ok "edge box minted its own transport pin" || fail "edge pin: $EDGEPIN"
[ "${#EP}" -eq 64 ] && ok "pvfs add wrote through to the owner (node $EP)" || fail "write-through add: $EP"
echo "$D_OUT" | grep -q "D2=ok" && ok "loc add --here recorded the edge's pin ($CATALOG_SECS s to catalog)" || fail "loc add --here"
echo "$D_OUT" | grep -q "D3=ok" && ok "location is instance-qualified (pvfs-host://<edge-pin>)" || fail "host uri missing"
echo "$D_OUT" | grep -q "D4=ok" && ok "read-your-writes: visible on the replica at once" || fail "read-your-writes"
E_OUT=$(ssh "$OWNER" "EP=$EP CW=$CW CW_SHA=$CW_SHA EDGEPIN=$EDGEPIN EDGE_IP=$EDGE_IP LIB=$LIB bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; D=\$HOME/fleet-test/owner/.pvfs
"\$B/pvfs" --data-dir "\$D" ls "\$LIB" | grep -q new-episode.mkv && echo "E1=ok" || echo "E1=no"
"\$B/pvfs" instance add edgebox "\$EDGE_IP:7431" "\$EDGEPIN" >/dev/null && echo "E2=ok" || echo "E2=no"
OSHA=\$("\$B/pvfs" --data-dir "\$D" cat "\$CW" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "\$OSHA" = "\$CW_SHA" ] && echo "E3=ok" || echo "E3=no(\$OSHA)"
EOS
)
echo "$E_OUT" | grep -q "E1=ok" && ok "ingested file landed in the owner's log" || fail "owner ls missing ingest"
echo "$E_OUT" | grep -q "E2=ok" && ok "owner registered the edge box" || fail "owner instance add"
echo "$E_OUT" | grep -q "E3=ok" && ok "owner-side read-through: pulled edge-held bytes over the LAN" || fail "owner read-through"
gate ingest

say "E: §7.10 tier to central + evict the edge (small files)"
T_OUT=$(ssh "$OWNER" "LIB=$LIB bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; D="\$FT/owner/.pvfs"
"\$B/pvfs" --data-dir "\$D" place "\$LIB" central --to "\$FT/central-store" >/dev/null && echo "T1=ok" || echo "T1=no"
TIERJ=\$("\$B/pvfs" --json --data-dir "\$D" tier)
echo "TIERJSON=\$TIERJ"
N=\$(find "\$FT/central-store" -type f | wc -l)
[ "\$N" -ge 1 ] && echo "T2=ok(\$N files)" || echo "T2=no"
EOS
)
echo "$T_OUT" | grep -q "T1=ok" && ok "owner placed library central" || fail "place central"
echo "$T_OUT" | grep -q "T2=ok" && ok "tier migrated verified copies into the central store" || fail "central store empty"
echo "$T_OUT" | grep -o 'TIERJSON=.*' | head -1
V_OUT=$(ssh "$EDGE" "EP=$EP EP_SHA=$EP_SHA bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; R="\$FT/replica/.pvfs"
"\$B/pvfs" --json replica sync "\$FT/replica" >/dev/null && echo "V1=ok" || echo "V1=no"
EVICTJ=\$("\$B/pvfs" --json --data-dir "\$R" evict)
echo "EVICTJSON=\$EVICTJ"
EV=\$(printf '%s' "\$EVICTJ" | jget evicted 2>/dev/null || echo 0)
[ "\$EV" -ge 1 ] && echo "V2=ok" || echo "V2=no(\$EV)"
[ -f "\$FT/downloads/new-episode.mkv" ] && echo "V3=kept" || echo "V3=deleted"
SSHA=\$("\$B/pvfs" --data-dir "\$R" cat "\$EP" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "\$SSHA" = "\$EP_SHA" ] && echo "V4=ok" || echo "V4=no(\$SSHA)"
EOS
)
echo "$V_OUT" | grep -q "V1=ok" && ok "edge learned the retirements (replica sync)" || fail "replica sync"
echo "$V_OUT" | grep -q "V2=ok" && ok "edge evicted migrated bytes" || fail "evict"
echo "$V_OUT" | grep -o 'V3=.*' | sed 's/V3=/note: original download file after evict: /'
echo "$V_OUT" | grep -q "V4=ok" && ok "file still streams after migration + eviction (via central)" || fail "post-eviction stream"
echo "$V_OUT" | grep -o 'EVICTJSON=.*' | head -1
gate tier-evict

say "F: scale spot-check — 3 GiB through ingest → tier → evict → stream"
S1=$(ssh "$EDGE" "LIB=$LIB bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; R="\$FT/replica/.pvfs"
T0=\$(date +%s)
head -c 3221225472 /dev/urandom > "\$FT/downloads/big-movie.mkv"
echo "GEN_SECS=\$(( \$(date +%s) - T0 ))"
T0=\$(date +%s)
echo "BIG_SHA=\$(sha256sum "\$FT/downloads/big-movie.mkv" | cut -d' ' -f1)"
echo "SHA_SECS=\$(( \$(date +%s) - T0 ))"
T0=\$(date +%s)
BIG=\$("\$B/pvfs" --json --data-dir "\$R" add "\$LIB" --kind file --label big-movie.mkv --size 3221225472 --mime video/x-matroska | jget node_id)
"\$B/pvfs" --data-dir "\$R" loc add "\$BIG" --here "\$FT/downloads/big-movie.mkv" >/dev/null
echo "CATALOG_SECS=\$(( \$(date +%s) - T0 ))"
echo "BIG=\$BIG"
EOS
)
eval "$(echo "$S1" | grep -E '^(BIG|BIG_SHA|GEN_SECS|SHA_SECS|CATALOG_SECS)=')"
[ "${#BIG}" -eq 64 ] && ok "3 GiB file cataloged in ${CATALOG_SECS}s (gen ${GEN_SECS}s, sha ${SHA_SECS}s)" || fail "big add: $S1"
gate scale-catalog
S2=$(ssh "$OWNER" 'bash -s' <<'EOS'
set -u
B=$HOME/.local/bin; FT=$HOME/fleet-test
T0=$(date +%s)
TIERJ=$("$B/pvfs" --json --data-dir "$FT/owner/.pvfs" tier)
SECS=$(( $(date +%s) - T0 ))
echo "TIER_SECS=$SECS"
echo "TIERJSON=$TIERJ"
echo "STORE_GB=$(du -sBM "$FT/central-store" | cut -f1)"
EOS
)
eval "$(echo "$S2" | grep -E '^(TIER_SECS|STORE_GB)=')"
RATE=$(( TIER_SECS > 0 ? 3072 / TIER_SECS : 3072 ))
[ "$TIER_SECS" -gt 0 ] && ok "tier pulled 3 GiB over the LAN in ${TIER_SECS}s (~${RATE} MB/s), store now $STORE_GB" || fail "tier: $S2"
echo "$S2" | grep -o 'TIERJSON=.*' | head -1
S3=$(ssh "$EDGE" "BIG=$BIG BIG_SHA=$BIG_SHA bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; R="\$FT/replica/.pvfs"
"\$B/pvfs" --json replica sync "\$FT/replica" >/dev/null
BEFORE=\$(df --output=avail -BM "\$HOME" | tail -1 | tr -dc 0-9)
T0=\$(date +%s)
EVICTJ=\$("\$B/pvfs" --json --data-dir "\$R" evict)
EVICT_SECS=\$(( \$(date +%s) - T0 ))
AFTER=\$(df --output=avail -BM "\$HOME" | tail -1 | tr -dc 0-9)
echo "EVICTJSON=\$EVICTJ"
echo "FREED_MB=\$(( AFTER - BEFORE ))"; echo "EVICT_SECS=\$EVICT_SECS"
T0=\$(date +%s)
SSHA=\$("\$B/pvfs" --data-dir "\$R" cat "\$BIG" 2>/dev/null | sha256sum | cut -d' ' -f1)
echo "STREAM_SECS=\$(( \$(date +%s) - T0 ))"
[ "\$SSHA" = "\$BIG_SHA" ] && echo "S3=ok" || echo "S3=no(\$SSHA)"
EOS
)
eval "$(echo "$S3" | grep -E '^(FREED_MB|EVICT_SECS|STREAM_SECS)=')"
echo "$S3" | grep -o 'EVICTJSON=.*' | head -1
[ "${FREED_MB:-0}" -gt 2500 ] && ok "evict freed ${FREED_MB} MB on the edge in ${EVICT_SECS}s" || fail "evict freed only ${FREED_MB:-?} MB"
echo "$S3" | grep -q "S3=ok" && ok "3 GiB streamed back bit-perfect in ${STREAM_SECS}s (~$(( STREAM_SECS > 0 ? 3072 / STREAM_SECS : 3072 )) MB/s)" || fail "scale stream hash mismatch"

say "G: doc 18 — daemon mode: the fleet runs itself (serve jobs, zero cron)"
G_OUT=$(ssh "$EDGE" "LIB=$LIB bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; R="\$FT/replica/.pvfs"
for j in follow sync export; do "\$B/pvfs" --data-dir "\$R" serve enable \$j >/dev/null || echo "G1=no(\$j)"; done
"\$B/pvfs" --data-dir "\$R" export "\$LIB" "\$FT/daemon-view" --mode copy --prune --keep-fresh >/dev/null 2>&1 \
  && echo "G1=ok" || echo "G1=no(export)"
pkill -HUP -f "pvfsd --mount \$FT/replica" && echo "G2=ok" || echo "G2=no"
sleep 1
"\$B/pvfs" --json --data-dir "\$R" serve status | grep -q '"runner":"on"' && echo "G3=ok" || echo "G3=no"
EOS
)
echo "$G_OUT" | grep -q "G1=ok" && ok "edge: jobs enabled + kept-fresh view recorded" || fail "edge jobs setup: $G_OUT"
echo "$G_OUT" | grep -q "G3=ok" && ok "edge daemon reloaded jobs on SIGHUP (runner on)" || fail "edge SIGHUP"
# a new file appears on the owner — the edge view must refresh with NO command run
NEWSHA=$(ssh "$OWNER" 'FT=$HOME/fleet-test; head -c 262144 /dev/urandom > "$FT/library/movies/beta.mkv"
"$HOME/.local/bin/pvfs" --data-dir "$FT/owner/.pvfs" scan '"$LIB"' >/dev/null
sha256sum "$FT/library/movies/beta.mkv" | cut -d" " -f1')
VOK=""
for _ in $(seq 1 120); do
  GOT=$(ssh "$EDGE" 'sha256sum "$HOME/fleet-test/daemon-view/movies/beta.mkv" 2>/dev/null | cut -d" " -f1')
  [ "$GOT" = "$NEWSHA" ] && { VOK=1; break; }
  sleep 1
done
[ -n "$VOK" ] && ok "owner's new file reached the edge view hands-free (follow → sync → export over the LAN)" \
  || fail "daemon-mode view never refreshed"
# ingest → tier (job) → evict (job): the §7.10 loop with zero cron
ING=$(ssh "$EDGE" "LIB=$LIB bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; R="\$FT/replica/.pvfs"
head -c 1048576 /dev/urandom > "\$FT/downloads/auto-episode.mkv"
echo "ISHA=\$(sha256sum "\$FT/downloads/auto-episode.mkv" | cut -d' ' -f1)"
NID=\$("\$B/pvfs" --json --data-dir "\$R" add "\$LIB" --kind file --label auto-episode.mkv --size 1048576 | jget node_id)
"\$B/pvfs" --data-dir "\$R" loc add "\$NID" --here "\$FT/downloads/auto-episode.mkv" >/dev/null
"\$B/pvfs" --data-dir "\$R" serve enable evict >/dev/null || echo "EVICT_ENABLE_FAILED"
grep -q evict "\$R/serve.jobs" || echo "EVICT_ENABLE_FAILED"
pkill -HUP -f "pvfsd --mount \$FT/replica"   # the running supervisor learns of evict
echo "NID=\$NID"
EOS
)
eval "$(echo "$ING" | grep -E '^(NID|ISHA)=')"
echo "$ING" | grep -q EVICT_ENABLE_FAILED && fail "serve enable evict did not persist"
[ "${#NID}" -eq 64 ] && ok "edge ingested a new file (write-through + --here)" || fail "daemon-mode ingest: $ING"
ssh "$OWNER" 'B=$HOME/.local/bin; FT=$HOME/fleet-test
"$B/pvfs" --data-dir "$FT/owner/.pvfs" serve enable tier >/dev/null
pkill -HUP -f "pvfsd --mount $FT/owner"' \
  && ok "owner: tier job enabled via SIGHUP (pass due immediately)" || fail "owner tier enable"
TOK=""
for _ in $(seq 1 120); do
  ssh "$OWNER" "test -f \$HOME/fleet-test/central-store/${NID:0:2}/$NID" && { TOK=1; break; }
  sleep 1
done
[ -n "$TOK" ] && ok "tier job migrated the ingested bytes to central (no command run)" \
  || fail "tier job never migrated $NID"
EOK=""
for _ in $(seq 1 120); do
  if ! ssh "$EDGE" 'test -f "$HOME/fleet-test/downloads/auto-episode.mkv"'; then EOK=1; break; fi
  sleep 1
done
[ -n "$EOK" ] && ok "evict job reclaimed the edge bytes (fold-nudged, no command run)" \
  || fail "evict job never reclaimed the download"
SSHA=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --data-dir "$HOME/fleet-test/replica/.pvfs" cat '"$NID"' 2>/dev/null | sha256sum | cut -d" " -f1')
[ "$SSHA" = "$ISHA" ] && ok "and the file still streams bit-perfect on the edge (via central)" \
  || fail "post-daemon-evict stream mismatch"

say "H: doc 20 §2.4 — ship one app's region to the edge (P7.2b/P7.2d)"
# owner: two app subtrees become regions; a write + real bytes land inside one
H_OWNER=$(ssh "$OWNER" "ROOT=$ROOT bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; D="\$FT/owner/.pvfs"
PH=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label photos-app)
MU=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label music-app)
"\$B/pvfs" --data-dir "\$D" region mark "\$PH" >/dev/null \
  && "\$B/pvfs" --data-dir "\$D" region mark "\$MU" >/dev/null \
  && echo "H1=ok" || echo "H1=no"
AL=\$("\$B/pvfs" --data-dir "\$D" add "\$PH" --kind folder --label albums)
TR=\$("\$B/pvfs" --data-dir "\$D" add "\$MU" --kind folder --label tracks)
printf 'region-pic-bytes' > "\$FT/library/pic.txt"
PIC=\$("\$B/pvfs" --data-dir "\$D" add "\$AL" --kind file --label pic.txt --size 16)
"\$B/pvfs" --data-dir "\$D" loc add "\$PIC" "file://\$FT/library/pic.txt" >/dev/null
ls "\$D/regions/\$PH/"g-*.db >/dev/null 2>&1 && echo "H2=ok" || echo "H2=no"
echo "PH=\$PH"; echo "MU=\$MU"; echo "AL=\$AL"; echo "TR=\$TR"; echo "PIC=\$PIC"
echo "PICSHA=\$(sha256sum "\$FT/library/pic.txt" | cut -d' ' -f1)"
EOS
)
eval "$(echo "$H_OWNER" | grep -E '^(PH|MU|AL|TR|PIC|PICSHA)=')"
echo "$H_OWNER" | grep -q "H1=ok" && ok "owner marked two app regions on the served forest" || fail "region marks: $H_OWNER"
echo "$H_OWNER" | grep -q "H2=ok" && ok "region writes created the generation file" || fail "owner generation file"
# the edge's FOLLOW JOB (running since G) must sweep the region hands-free
HFOK=""
for _ in $(seq 1 60); do
  GOT=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --data-dir "$HOME/fleet-test/replica/.pvfs" ls '"$AL"' 2>/dev/null | grep -c pic.txt')
  [ "$GOT" = "1" ] && { HFOK=1; break; }
  sleep 1
done
[ -n "$HFOK" ] && ok "region content reached the edge replica hands-free (follow sweep over the LAN)" \
  || fail "follow job never swept the region"
ssh "$EDGE" 'ls "$HOME/fleet-test/replica/.pvfs/regions/'"$PH"'/"g-*.db >/dev/null 2>&1' \
  && ok "generation file landed on the edge replica" || fail "edge generation file"
# region bytes stream cross-machine through the verified read path
HSHA=$(ssh "$EDGE" '"$HOME/.local/bin/pvfs" --data-dir "$HOME/fleet-test/replica/.pvfs" cat '"$PIC"' 2>/dev/null | sha256sum | cut -d" " -f1')
[ "$HSHA" = "$PICSHA" ] && ok "region file streams to the edge, hash-verified" || fail "region cat: $HSHA"
# a region-scoped replica: photos only; music stays attested-but-unfetched
H_EDGE=$(ssh "$EDGE" "PH=$PH AL=$AL TR=$TR bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test
"\$B/pvfs" replica add "\$FT/photos-replica" --instance owner --region "\$PH" >/dev/null 2>&1 \
  && echo "H5=ok" || echo "H5=no"
S="\$FT/photos-replica/.pvfs"
"\$B/pvfs" --data-dir "\$S" ls "\$AL" 2>/dev/null | grep -q pic.txt && echo "H6=ok" || echo "H6=no"
"\$B/pvfs" --data-dir "\$S" ls "\$TR" 2>/dev/null | grep -q . && echo "H7=no" || echo "H7=ok"
EOS
)
echo "$H_EDGE" | grep -q "H5=ok" && ok "replica add --region built a scoped replica" || fail "scoped replica add: $H_EDGE"
echo "$H_EDGE" | grep -q "H6=ok" && ok "scoped replica replays the target region" || fail "scoped replica content"
echo "$H_EDGE" | grep -q "H7=ok" && ok "sibling region's interior stays unfetched (attested by its head)" || fail "sibling isolation"
# seal photos; the whole-forest replica verifies the seal on its next sync
ssh "$OWNER" '"$HOME/.local/bin/pvfs" --data-dir "$HOME/fleet-test/owner/.pvfs" region unmark '"$PH" >/dev/null \
  && ok "owner sealed the photos region" || fail "owner unmark"
ssh "$EDGE" '"$HOME/.local/bin/pvfs" replica sync "$HOME/fleet-test/replica" >/dev/null 2>&1' \
  && ok "edge replica synced + verified the sealed generation" || fail "edge seal sync"
gate regions

say "I: doc 21 — attachment kinds on the owner: staging drains, mirror survives (P8)"
I_OUT=$(ssh "$OWNER" "ROOT=$ROOT bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; D="\$FT/owner/.pvfs"
mkdir -p "\$FT/staging" "\$FT/mirror-src"
head -c 262144 /dev/urandom > "\$FT/staging/incoming.mkv"
head -c 262144 /dev/urandom > "\$FT/mirror-src/precious.raw"
PSHA=\$(sha256sum "\$FT/mirror-src/precious.raw" | cut -d' ' -f1)
MIGF=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label staging-app)
MIRF=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label mirror-app)
"\$B/pvfs" --data-dir "\$D" bind "\$MIGF" "\$FT/staging" --kind migrate --to "\$FT/drain-store" --hash-policy on_add >/dev/null \
  && echo "I1=ok" || echo "I1=no"
"\$B/pvfs" --data-dir "\$D" bind "\$MIRF" "\$FT/mirror-src" --kind mirror --to "\$FT/mirror-store" --hash-policy on_add >/dev/null \
  && echo "I2=ok" || echo "I2=no"
"\$B/pvfs" --data-dir "\$D" scan "\$MIGF" >/dev/null
"\$B/pvfs" --data-dir "\$D" scan "\$MIRF" >/dev/null
PREC=\$("\$B/pvfs" --json --data-dir "\$D" ls "\$MIRF" | pick precious.raw)
"\$B/pvfs" --data-dir "\$D" tier >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" evict >/dev/null 2>&1
[ -f "\$FT/staging/incoming.mkv" ] && echo "I3=no" || echo "I3=ok"
[ -f "\$FT/mirror-src/precious.raw" ] && echo "I4=ok" || echo "I4=no"
rm -f "\$FT/mirror-src/precious.raw"
GSHA=\$("\$B/pvfs" --data-dir "\$D" cat "\$PREC" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "\$GSHA" = "\$PSHA" ] && echo "I5=ok" || echo "I5=no(\$GSHA)"
EOS
)
echo "$I_OUT" | grep -q "I1=ok" && ok "bind --kind migrate (one command enrolls the staging disk)" || fail "bind migrate: $I_OUT"
echo "$I_OUT" | grep -q "I2=ok" && ok "bind --kind mirror (one command enrolls the backup space)" || fail "bind mirror"
echo "$I_OUT" | grep -q "I3=ok" && ok "the staging disk drained (tier landed + retired, evict reclaimed)" || fail "staging did not drain"
echo "$I_OUT" | grep -q "I4=ok" && ok "the mirror source keeps its bytes" || fail "mirror source touched"
echo "$I_OUT" | grep -q "I5=ok" && ok "content survives source deletion, bit-perfect via the mirror copy" || fail "mirror survival"
gate attachments

say "J: doc 22 — the swarm: one file, two real holders, parallel verified chunks (P9.0)"
# a 1 GiB hashed target on the owner — OUTSIDE the tiered library, in its own
# in-place binding: the mover must never retire the second holder's location
# (phase G's tier job consolidates LIB by design — found the hard way)
J_OWNER=$(ssh "$OWNER" "ROOT=$ROOT bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; D="\$FT/owner/.pvfs"
mkdir -p "\$FT/swarmdata"
head -c 1073741824 /dev/urandom > "\$FT/swarmdata/swarm.mkv"
SZ=\$("\$B/pvfs" --data-dir "\$D" add "\$ROOT" --kind folder --label swarm-zone)
"\$B/pvfs" --data-dir "\$D" bind "\$SZ" "\$FT/swarmdata" --hash-policy on_add >/dev/null 2>&1
"\$B/pvfs" --data-dir "\$D" scan "\$SZ" >/dev/null 2>&1
SW=\$("\$B/pvfs" --json --data-dir "\$D" ls "\$SZ" | pick swarm.mkv)
echo "SW=\$SW"
echo "SWSHA=\$(sha256sum "\$FT/swarmdata/swarm.mkv" | cut -d' ' -f1)"
EOS
)
eval "$(echo "$J_OWNER" | grep -E '^(SW|SWSHA)=')"
[ "${#SW}" -eq 64 ] && ok "owner cataloged the 1 GiB swarm target" || fail "swarm target: $J_OWNER"
# the edge becomes the second holder: wait for the catalog row to arrive via
# the follow job, self-heal-fetch JUST this file, log the copy --here
J_EDGE=$(ssh "$EDGE" "SW=$SW bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test; R="\$FT/replica/.pvfs"
SEEN=no
for _ in \$(seq 1 45); do
  "\$B/pvfs" --data-dir "\$R" node "\$SW" >/dev/null 2>&1 && { SEEN=yes; break; }
  sleep 1
done
[ "\$SEEN" = yes ] || echo "J1=no(catalog never arrived)"
"\$B/pvfs" --data-dir "\$R" cat "\$SW" > /dev/null 2>&1
SP="\$R/synced/\${SW:0:2}/\$SW"
[ -f "\$SP" ] && echo "J1=ok" || echo "J1=no"
"\$B/pvfs" --data-dir "\$R" loc add "\$SW" --here "\$SP" >/dev/null 2>&1 && echo "J2=ok" || echo "J2=no"
echo "EDGEPIN=\$(cat "\$R/nettls/pin" 2>/dev/null || echo MISSING)"
EOS
)
eval "$(echo "$J_EDGE" | grep -E '^EDGEPIN=')"
echo "$J_EDGE" | grep -q "J1=ok" && ok "edge holds a second copy" || fail "edge copy: $J_EDGE"
echo "$J_EDGE" | grep -q "J2=ok" && ok "edge logged its copy (--here, write-through)" || fail "edge loc add"
# a consumer on the EDGE box (where the owner's file:// path does NOT
# resolve — fetching is the only way) registers BOTH holders and swarm-pulls
J_CONS=$(ssh "$EDGE" "SW=$SW EDGEPIN=$EDGEPIN bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test
"\$B/pvfs" instance add edgelocal "127.0.0.1:7431" "\$EDGEPIN" >/dev/null 2>&1 || true
"\$B/pvfs" replica add "\$FT/consumer" --instance owner >/dev/null 2>&1 && echo "J3=ok" || echo "J3=no"
C="\$FT/consumer/.pvfs"
T0=\$(date +%s)
"\$B/pvfs" --data-dir "\$C" cat "\$SW" > /dev/null 2>"\$FT/swarm.log" && echo "J4=ok" || echo "J4=no"
echo "SECS=\$(( \$(date +%s) - T0 ))"
grep -q "swarm: .* 2 holder" "\$FT/swarm.log" && echo "J5=ok" || echo "J5=no(\$(grep swarm "\$FT/swarm.log" | head -1))"
GSHA=\$("\$B/pvfs" --data-dir "\$C" cat "\$SW" 2>/dev/null | sha256sum | cut -d' ' -f1)
echo "GSHA=\$GSHA"
EOS
)
eval "$(echo "$J_CONS" | grep -E '^(SECS|GSHA)=')"
echo "$J_CONS" | grep -q "J3=ok" && ok "consumer replica built on the edge" || fail "consumer: $J_CONS"
echo "$J_CONS" | grep -q "J4=ok" && ok "swarm fetch completed in ${SECS}s" || fail "swarm fetch"
echo "$J_CONS" | grep -q "J5=ok" && ok "BOTH holders contributed chunks (the swarm swarmed)" || fail "single-holder pull: $J_CONS"
[ "$GSHA" = "$SWSHA" ] && ok "1 GiB reassembled bit-perfect from two holders" || fail "swarm sha mismatch"
# kill -9 mid-swarm, then resume: the chaos caveat, retired
J_KILL=$(ssh "$EDGE" "SW=$SW bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test
"\$B/pvfs" replica add "\$FT/consumer2" --instance owner >/dev/null 2>&1
C="\$FT/consumer2/.pvfs"
( "\$B/pvfs" --data-dir "\$C" cat "\$SW" > /dev/null 2>"\$FT/swarm2.log" ) &
CATPID=\$!
# deterministic kill: wait for the swarm partial to EXIST (the pull is live),
# then kill mid-flight
PARTOK=no
for _ in \$(seq 1 40); do
  ls "\$C/synced/\${SW:0:2}/".*.swarmpart >/dev/null 2>&1 && { PARTOK=yes; break; }
  sleep 0.5
done
sleep 2
pkill -9 -P \$CATPID 2>/dev/null; kill -9 \$CATPID 2>/dev/null; wait \$CATPID 2>/dev/null
[ "\$PARTOK" = yes ] && ls "\$C/synced/\${SW:0:2}/".*.swarmpart >/dev/null 2>&1 && echo "J6=ok" || echo "J6=no"
"\$B/pvfs" --data-dir "\$C" cat "\$SW" > /dev/null 2>>"\$FT/swarm2.log" && echo "J7=ok" || echo "J7=no"
grep -q "swarm: resumed" "\$FT/swarm2.log" && echo "J8=ok" || echo "J8=no"
EOS
)
echo "$J_KILL" | grep -q "J6=ok" && ok "kill -9 left the resumable partial in place" || fail "no swarm partial: $J_KILL"
echo "$J_KILL" | grep -q "J7=ok" && ok "the retry completed" || fail "swarm retry"
echo "$J_KILL" | grep -q "J8=ok" && ok "and REUSED the killed run's chunks (resume proven)" || fail "no resume"
# P9.1: the streaming mount — first MiB while the 1 GiB fetch is in flight
J_MOUNT=$(ssh "$EDGE" "SW=$SW DROOT=$ROOT bash -s" <<EOS
set -u; $RHELPERS
B=\$HOME/.local/bin; FT=\$HOME/fleet-test
if [ ! -e /dev/fuse ]; then echo "J9=skip"; exit 0; fi
"\$B/pvfs" replica add "\$FT/consumer3" --instance owner >/dev/null 2>&1
C="\$FT/consumer3/.pvfs"
mkdir -p "\$FT/stream-view"
"\$B/pvfs" --data-dir "\$C" mount "\$DROOT" "\$FT/stream-view" >/dev/null 2>"\$FT/fuse.log" &
MPID=\$!
for _ in \$(seq 1 40); do [ -d "\$FT/stream-view/swarm-zone" ] && break; sleep 0.25; done
T0=\$(date +%s)
head -c 1048576 "\$FT/stream-view/swarm-zone/swarm.mkv" > "\$FT/first-mib" 2>/dev/null && echo "J9=ok" || echo "J9=no"
echo "FIRSTSECS=\$(( \$(date +%s) - T0 ))"
ls "\$C/synced/\${SW:0:2}/".*.swarmpart >/dev/null 2>&1 && echo "J10=ok" || echo "J10=no"
grep -q "mount: streaming" "\$FT/fuse.log" && echo "J11=ok" || echo "J11=no"
fusermount3 -u "\$FT/stream-view" 2>/dev/null; kill \$MPID 2>/dev/null
EOS
)
if echo "$J_MOUNT" | grep -q "J9=skip"; then
  ok "streaming mount skipped (no fuse on the edge)"
else
  eval "$(echo "$J_MOUNT" | grep -E '^FIRSTSECS=')"
  echo "$J_MOUNT" | grep -q "J9=ok" && ok "mount served the first MiB in ${FIRSTSECS}s" || fail "streaming mount read: $J_MOUNT"
  echo "$J_MOUNT" | grep -q "J10=ok" && ok "…while the 1 GiB fetch was still in flight (punch J, retired)" || fail "no in-flight partial"
  echo "$J_MOUNT" | grep -q "J11=ok" && ok "the mount took the attested streaming path" || fail "mount did not stream"
fi
gate swarm

say "cleanup — stop fleet daemons (dirs kept for inspection)"
ssh "$OWNER" 'pkill -f "pvfsd --mount $HOME/fleet-test" 2>/dev/null; true'
ssh "$EDGE"  'pkill -f "pvfsd --mount $HOME/fleet-test" 2>/dev/null; true'
ok "daemons stopped; artifacts in ~/fleet-test on both hosts"

echo
echo "fleet results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL FLEET TESTS PASSED" || exit 1
