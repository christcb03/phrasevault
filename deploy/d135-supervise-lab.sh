#!/bin/bash
# D135 item 3 — the owner supervises a holder, on the D69 lab: the ingest VM
# plays the NAS. Its systemd unit is stopped for the test and a NAS-shaped
# home (~/nas-sim/{bin,replica -> /srv/media-replica}) runs pvfsd the way
# the QNAP's start-pvfs.sh does, so pvfs-supervise.sh works unchanged. The
# owner's key is bound as a forced command; the owner's health job (2 min)
# finds the holder down after two misses and sends `start`.
#   owner : 192.168.1.119 (VM 300)    holder-sim : 192.168.1.158 (VM 301)
# Needs the D134 lab converged (fleet.yml with fleet-lab.ini) and D135
# binaries installed on both (fleet_artifacts → a D135 slot).
O=chris@192.168.1.119; I=chris@192.168.1.158; I_HOST=192.168.1.158
PASS=0; FAIL=0; ok(){ PASS=$((PASS+1)); echo "ok   $*"; }; fail(){ FAIL=$((FAIL+1)); echo "FAIL $*"; }
gate(){ [ "$FAIL" -gt 0 ] && { echo; echo "ABORT at: $1 ($PASS ok, $FAIL failed)"; exit 1; }; }
S(){ ssh -o BatchMode=yes "$1" "$2" 2>&1 | grep -v setpgid; }
HERE=$(cd "$(dirname "$0")" && pwd)

echo "== 0: the holder-sim home on the ingest VM; its unit stopped; the sim daemon up"
S $I 'sudo systemctl stop pvfsd-replica pvfs-mount 2>/dev/null; H=$HOME/nas-sim; mkdir -p $H/bin; ln -sfn /srv/media-replica $H/replica; cp /usr/local/bin/pvfs /usr/local/bin/pvfsd $H/bin/; cat > $H/bin/start-pvfs.sh <<EOS
#!/bin/sh
H=\$(cd "\$(dirname "\$0")/.." && pwd)
for d in /proc/[0-9]*; do a=\$(tr "\\0" " " < \$d/cmdline 2>/dev/null); case "\$a" in *"pvfsd --mount \$H/replica "*) exit 0;; esac; done
cd \$H && PATH=\$H/bin:\$PATH setsid pvfsd --mount \$H/replica --listen 0.0.0.0:7422 >> \$H/pvfsd.log 2>&1 &
EOS
chmod 755 $H/bin/start-pvfs.sh; echo READY' | grep -q READY && ok "holder-sim home laid out (bin, replica symlink, start script)" || fail "sim home"
scp -q "$HERE/../../PVOS-d135/deploy/ansible/fleet/pvfs-supervise.sh" "$I:nas-sim/bin/pvfs-supervise.sh" 2>/dev/null || scp -q /Users/chris/Projects/PVOS-d135/deploy/ansible/fleet/pvfs-supervise.sh "$I:nas-sim/bin/pvfs-supervise.sh"
S $I 'chmod 755 ~/nas-sim/bin/pvfs-supervise.sh; sh -n ~/nas-sim/bin/pvfs-supervise.sh && echo SYNTAX' | grep -q SYNTAX && ok "pvfs-supervise.sh installed on the holder-sim" || fail "script install"
S $I '~/nas-sim/bin/pvfs-supervise.sh start; sleep 2; ~/nas-sim/bin/pvfs-supervise.sh status' | tail -1 | grep -q '^serving' && ok "start by hand → serving" || fail "sim daemon not serving: $(S $I '~/nas-sim/bin/pvfs-supervise.sh status; tail -3 ~/nas-sim/pvfsd.log')"
gate sim

echo "== A: the owner's key, bound on the holder-sim as a forced command"
PUB=$(S $O 'k=$HOME/.ssh/pvfs-supervise; mkdir -p ~/.ssh; [ -f $k ] || ssh-keygen -q -t ed25519 -N "" -C pvfs-owner-supervise -f $k; cat $k.pub')
[ "${PUB%% *}" = "ssh-ed25519" ] && ok "owner supervise key present" || fail "key: $PUB"
S $I "grep -vF pvfs-owner-supervise ~/.ssh/authorized_keys > ~/.ssh/ak.new 2>/dev/null; mv ~/.ssh/ak.new ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; echo 'command=\"/home/chris/nas-sim/bin/pvfs-supervise.sh\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty $PUB' >> ~/.ssh/authorized_keys; echo BOUND" | grep -q BOUND && ok "forced-command line in the holder-sim's authorized_keys" || fail "authorized_keys"
V=$(S $O "ssh -i ~/.ssh/pvfs-supervise -o BatchMode=yes -o StrictHostKeyChecking=accept-new chris@$I_HOST version")
echo "$V" | grep -q '^pvfs ' && ok "the key runs the script's verbs: version → $(echo "$V" | head -1)" || fail "version over the channel: $V"
SH=$(S $O "ssh -i ~/.ssh/pvfs-supervise -o BatchMode=yes chris@$I_HOST 'id; ls /' 2>&1 | head -1")
echo "$SH" | grep -q 'usage:' && ok "and nothing else: a shell command gets the usage line" || fail "shell not refused: $SH"
RS=$(S $O "ssh -i ~/.ssh/pvfs-supervise -o BatchMode=yes chris@$I_HOST restart")
echo "$RS" | grep -q '^refused: serving' && ok "restart refuses a serving daemon" || fail "restart: $RS"
ST=$(S $O "ssh -i ~/.ssh/pvfs-supervise -o BatchMode=yes chris@$I_HOST start")
echo "$ST" | grep -q '^serving' && ok "start on a serving daemon does nothing" || fail "start (serving): $ST"
gate channel

echo "== B: the owner supervises the holder-sim; the health job starts it after two missed polls"
PIN=$(S $I 'cat /srv/media-replica/.pvfs/nettls/pin')
[ "${#PIN}" -eq 64 ] && ok "holder-sim pin $PIN" || fail "pin: $PIN"
S $O "cd /srv/pvfs/media && /usr/local/bin/pvfs --json fleet supervise $PIN --ssh chris@$I_HOST --key \$HOME/.ssh/pvfs-supervise" | grep -q '"supervised":true' && ok "pvfs fleet supervise registered the channel" || fail "fleet supervise"
S $I '~/nas-sim/bin/pvfs-supervise.sh status >/dev/null; pkill -f "pvfsd --mount /home/chris/nas-sim/replica"; sleep 2; ~/nas-sim/bin/pvfs-supervise.sh status' | tail -1 | grep -q '^down' && ok "holder-sim daemon stopped (status: down)" || fail "stop"
echo "     waiting for the owner's health job: two polls at 2 min, then start (up to 7 min)…"
R=$(S $O 'cd /srv/pvfs/media; for _ in $(seq 1 84); do /usr/local/bin/pvfs --json fleet health 2>/dev/null | python3 -c "
import json,sys
r=json.load(sys.stdin); p=r[\"peers\"].get(sys.argv[1]) or {}
a=(p.get(\"actions\") or [])
if a: print(\"ACTION rc=%d out=%s\" % (a[-1][\"rc\"], a[-1][\"output\"])); sys.exit(0)
sys.exit(1)" '"$PIN"' && exit 0; sleep 5; done; echo NOACTION')
echo "$R" | grep -q 'ACTION rc=0 out=started' && ok "the owner sent start and the script answered: $R" || fail "no start within 7 min: $R $(S $O 'journalctl -u pvfsd-media --since "10 min ago" --no-pager | grep -i supervise | tail -3')"
S $I 'sleep 3; ~/nas-sim/bin/pvfs-supervise.sh status' | tail -1 | grep -q '^serving' && ok "the holder-sim is serving again" || fail "not serving after start"
S $O 'cd /srv/pvfs/media; /usr/local/bin/pvfs fleet health | grep -A3 "'"${PIN:0:8}"'"' | grep -q 'supervise: start' && ok "fleet health shows the action" || fail "fleet health table"
S $O 'cd /srv/pvfs/media; for _ in $(seq 1 40); do /usr/local/bin/pvfs --json fleet health | python3 -c "import json,sys; p=json.load(sys.stdin)[\"peers\"][sys.argv[1]]; sys.exit(0 if p[\"misses\"]==0 and p[\"attempts\"]==0 else 1)" '"$PIN"' && { echo RESET; exit 0; }; sleep 5; done; echo NOTRESET' | grep -q RESET && ok "the next poll saw it up: misses and attempts reset" || fail "record not reset"
S $I 'tail -4 ~/nas-sim/supervise.log' | grep -q 'start started' && ok "the holder-sim's supervise.log has the start" || fail "supervise.log: $(S $I 'tail -3 ~/nas-sim/supervise.log')"

echo "== C: install over the channel swaps a binary pair and version reports it"
S $I 'pkill -f "pvfsd --mount /home/chris/nas-sim/replica"; sleep 2; true' >/dev/null
IN=$(S $O "cd /usr/local/bin && tar -cf - pvfs pvfsd | ssh -i ~/.ssh/pvfs-supervise -o BatchMode=yes chris@$I_HOST install")
echo "$IN" | grep -q '^installed:' && ok "install accepted a tar of pvfs+pvfsd: $IN" || fail "install: $IN"
S $I 'ls ~/nas-sim/bin/prev/pvfsd >/dev/null && ~/nas-sim/bin/pvfs-supervise.sh version | head -1' | grep -q '^pvfs ' && ok "previous pair kept in bin/prev; version reports the new one" || fail "prev/version"

echo "== D: restore — the holder-sim's own daemon down, the systemd unit back"
S $O "cd /srv/pvfs/media && /usr/local/bin/pvfs fleet supervise $PIN --off" >/dev/null
S $I 'pkill -f "pvfsd --mount /home/chris/nas-sim/replica"; sleep 2; sudo systemctl start pvfsd-replica pvfs-mount; sleep 2; systemctl is-active pvfsd-replica' | grep -q active && ok "systemd unit back; the owner no longer supervises the sim" || fail "restore"
echo; echo "supervise lab: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
