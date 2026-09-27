#!/bin/bash
# PVOS D197 — the companion keeps its runtime files. On presubuntu, a
# throwaway companion (its own vault, socket and ephemeral web port) with the
# keeper's interval cut to 10 s (PVFS_COMPANION_KEEP_SECS): its `.pid` and
# `.http` are aged four days, then deleted, and each time the keeper puts them
# right — touched, then written again byte for byte at 0600 — and `status`
# finds the web agent again. Binaries: ~/.local/bin, installed by the
# pipeline. Run from the Mac; nothing but ~/fleet-test/d197 is touched.
HOST=chris@192.168.0.184
ssh "$HOST" 'bash -s' <<'EOS'
set -u
B=$HOME/.local/bin; T=$HOME/fleet-test/d197; PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "ok   $*"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL $*"; }
age()  { echo $(( $(date +%s) - $(stat -c %Y "$1") )); }
echo "build: $("$B/pvfs" --version)"
pkill -f "[p]vfs-companion serve --vault $T" 2>/dev/null; sleep 0.5
rm -rf "$T"; mkdir -p "$T"
MN=$("$B/pvfs" --json forest init --mount "$T/forest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["mnemonic"])')
printf '%s' "$MN" | PVFS_COMPANION_PASSPHRASE=d197 "$B/pvfs-companion" init --vault "$T/c.vault" --passphrase >/dev/null 2>&1 \
  && ok "throwaway vault sealed" || fail "companion init"
SOCK="$T/c.sock"
# with_extension: the files are c.pid and c.http, beside c.sock
PIDF="$T/c.pid"; HTTPF="$T/c.http"
PVFS_COMPANION_KEEP_SECS=10 PVFS_COMPANION_PASSPHRASE=d197 nohup "$B/pvfs-companion" serve \
  --vault "$T/c.vault" --socket "$SOCK" --prompt deny --web-port 0 > "$T/c.log" 2>&1 &
echo $! > "$T/serve.pid"
for _ in $(seq 1 50); do [ -s "$HTTPF" ] && [ -s "$PIDF" ] && break; sleep 0.2; done
[ -s "$HTTPF" ] && [ -s "$PIDF" ] && ok "serve wrote c.pid and c.http beside c.sock" || fail "no runtime files: $(tail -3 "$T/c.log")"
PID0=$(cat "$PIDF"); HTTP0=$(cat "$HTTPF")
[ "$PID0" = "$(cat "$T/serve.pid")" ] && ok "the pidfile holds the serving pid" || fail "pidfile $PID0"

# 1 — four days untouched (what tmp_cleaner takes): touched at the next look
touch -a -m -d '4 days ago' "$PIDF" "$HTTPF"
[ "$(age "$PIDF")" -gt 259200 ] && [ "$(age "$HTTPF")" -gt 259200 ] && ok "both aged past three days" || fail "age $(age "$PIDF")"
sleep 12
[ "$(age "$PIDF")" -lt 30 ] && [ "$(age "$HTTPF")" -lt 30 ] \
  && ok "both touched at the next look ($(age "$PIDF") s and $(age "$HTTPF") s old)" || fail "not touched: $(age "$PIDF") $(age "$HTTPF")"
[ "$(cat "$PIDF")" = "$PID0" ] && [ "$(cat "$HTTPF")" = "$HTTP0" ] && ok "contents unchanged" || fail "contents changed"

# 2 — deleted: written again, byte for byte, owner-only
rm -f "$PIDF" "$HTTPF"
sleep 12
[ "$(cat "$PIDF" 2>/dev/null)" = "$PID0" ] && [ "$(cat "$HTTPF" 2>/dev/null)" = "$HTTP0" ] \
  && ok "both written again, byte for byte" || fail "not written again"
[ "$(stat -c %a "$PIDF" 2>/dev/null)" = "600" ] && [ "$(stat -c %a "$HTTPF" 2>/dev/null)" = "600" ] && ok "mode 0600" || fail "mode"
[ "$(grep -c 'was gone — written again' "$T/c.log")" = "2" ] && ok "the log says so, once per file" || fail "log: $(grep 'written again' "$T/c.log")"
"$B/pvfs-companion" status --vault "$T/c.vault" --socket "$SOCK" 2>&1 | grep -q "web   : identity agent on http://" \
  && ok "status finds the web agent again" || fail "status: $("$B/pvfs-companion" status --vault "$T/c.vault" --socket "$SOCK" 2>&1 | tail -3)"

kill "$(cat "$T/serve.pid")" 2>/dev/null; sleep 1
rm -rf "$T"
echo; echo "companion keep: $PASS ok, $FAIL failed"; [ "$FAIL" -eq 0 ]
EOS
