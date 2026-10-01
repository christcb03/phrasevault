#!/usr/bin/env bash
# PVOS D199 — lab5 rehearsal: one writer per daemon on the lab owner (the lab
# store: owner + holder, mediabox's mirror) and the lab feeder (a replica).
# Run from the Mac AFTER rolling the D199 build to those two boxes:
#
#   cd PVOS-d199-one-writer/deploy/ansible/fleet
#   ansible-playbook -i fleet-lab5.ini fleet.yml --limit pvfs-lab-store,pvfs-lab-ingest \
#     -e fleet_artifacts=/opt/pvfs-d199-one-writer/src/target </dev/null > roll.log 2>&1
#
# Then:  ./d199-lab5-rehearsal.sh [observe|plant|after|clean]
#   observe  each daemon's build, connections, threads, and the journal's
#            writer lines, busy/locked lines and fold-lock waits since start
#   plant    files staged in ~ and moved into lab5-local (the owner's watch
#            catalogues them and publishes; the feeder installs the head and
#            follows the commit) and into the feeder's staging
#   after    the rows each box holds for the planted folders, then observe
#   clean    the planted folders removed (the watches sweep their rows)
set -u
STORE=192.168.1.121 INGEST=192.168.1.158
OWNER_UNIT=pvfsd-lab5-plex FEEDER_UNIT=pvfsd-lab5-feeder
LOCAL=/srv/sim-lab5/local/Media STAGING=/srv/sim-lab5/staging/Media
ok=0 bad=0
check() { if eval "$2"; then echo "ok   $1"; ok=$((ok+1)); else echo "FAIL $1"; bad=$((bad+1)); fi; }
on() { ssh -o BatchMode=yes -o ConnectTimeout=8 "chris@$1" "$2" </dev/null; }

observe() {
  for pair in "$STORE $OWNER_UNIT" "$INGEST $FEEDER_UNIT"; do
    set -- $pair
    echo "== $2 on $1"
    on "$1" "u=$2; p=\$(systemctl show -p MainPID --value \$u); t=\$(systemctl show -p ActiveEnterTimestamp --value \$u)
      echo \"build: \$(/usr/local/bin/pvfs --version | head -1)   pid \$p since \$t\"
      echo \"index.db connections: \$(sudo ls -l /proc/\$p/fd | grep -c 'index.db\$')  log.db: \$(sudo ls -l /proc/\$p/fd | grep -c 'log.db\$')  threads: \$(ls /proc/\$p/task | wc -l)\"
      j=\$(journalctl -u \$u --since \"\$t\" --no-pager -o cat)
      echo \"busy/locked: \$(echo \"\$j\" | grep -c 'busy/locked')   fold-lock waits: \$(echo \"\$j\" | grep -c 'waiting for another pvfs process folding')   engine-open folds: \$(echo \"\$j\" | grep -c 'another pvfs process is folding')\"
      echo \"\$j\" | grep -E 'pvfsd: the writer|waited .* for the writer|held .* by|hold raise|keeps its lowered' | tail -8"
  done
}

plant() {
  on $STORE "set -e; rm -rf ~/d199-stage && mkdir -p ~/d199-stage/D199/Season\ 01
    for i in \$(seq -w 1 300); do head -c 4096 /dev/urandom > ~/d199-stage/D199/Season\ 01/e\$i.mkv; done
    head -c 200000000 /dev/urandom > ~/d199-stage/D199/film.mkv
    mv ~/d199-stage/D199 $LOCAL/D199 && rmdir ~/d199-stage && echo planted 301 files in lab5-local"
  on $INGEST "set -e; rm -rf ~/d199-stage && mkdir -p ~/d199-stage/D199-staged
    for i in \$(seq -w 1 50); do head -c 4096 /dev/urandom > ~/d199-stage/D199-staged/s\$i.mkv; done
    mv ~/d199-stage/D199-staged $STAGING/D199-staged && rmdir ~/d199-stage && echo planted 50 files in staging"
}

after() {
  local o f
  o=$(on $STORE "pvfs --json region ls 2>/dev/null | head -c 4000")
  f=$(on $INGEST "pvfs --json region ls 2>/dev/null | head -c 4000")
  echo "owner region ls: $o" | head -c 1500; echo
  echo "feeder region ls: $f" | head -c 1500; echo
  check "the owner catalogued the planted folder (its rows hold D199/)" \
    "on $STORE \"pvfs view ls D199/Season\\\\ 01 2>/dev/null | grep -c e | grep -qx 300\""
  check "the feeder's view shows them (installed from the owner's head)" \
    "on $INGEST \"pvfs view ls D199/Season\\\\ 01 2>/dev/null | grep -c e | grep -qx 300\""
  observe
}

clean() {
  on $STORE "rm -rf $LOCAL/D199" && echo "removed D199 from lab5-local"
  on $INGEST "rm -rf $STAGING/D199-staged" && echo "removed D199-staged from staging"
}

case "${1:-observe}" in
  observe) observe ;;
  plant) plant ;;
  after) after; echo "-- $ok ok, $bad failed" ;;
  clean) clean ;;
  *) echo "observe | plant | after | clean"; exit 2 ;;
esac
