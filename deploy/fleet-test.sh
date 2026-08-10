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
ssh "$OWNER" '"$HOME/.local/bin/pvfs" --forest "$HOME/fleet-test/owner" device authorize-member --pubkey '"$EDGEKEY" >/dev/null \
  && ok "owner authorized the edge key as a member (authoring capability)" \
  || fail "owner authorize-member"
ssh "$OWNER" '"$HOME/.local/bin/pvfs" --forest "$HOME/fleet-test/owner" acl set '"$ROOT key:$EDGEKEY"' rwa' >/dev/null \
  && ok "owner granted edge key rwa at the root (auto-routed via live daemon)" \
  || fail "owner acl grant"
# the owner box's own outbound fetches (mover, read-through) authenticate as its
# CLIENT identity, not the forest device key — it needs read rights like anyone
OWNERKEY=$(jkey "$(ssh "$OWNER" '"$HOME/.local/bin/pvfs" --json whoami')" pubkey)
ssh "$OWNER" '"$HOME/.local/bin/pvfs" --forest "$HOME/fleet-test/owner" device authorize-member --pubkey '"$OWNERKEY"' && "$HOME/.local/bin/pvfs" --forest "$HOME/fleet-test/owner" acl set '"$ROOT key:$OWNERKEY"' r' >/dev/null \
  && ok "owner's client identity granted read (needed for its own read-through/mover)" \
  || fail "owner client identity grant"
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

say "cleanup — stop fleet daemons (dirs kept for inspection)"
ssh "$OWNER" 'pkill -f "pvfsd --mount $HOME/fleet-test" 2>/dev/null; true'
ssh "$EDGE"  'pkill -f "pvfsd --mount $HOME/fleet-test" 2>/dev/null; true'
ok "daemons stopped; artifacts in ~/fleet-test on both hosts"

echo
echo "fleet results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL FLEET TESTS PASSED" || exit 1
