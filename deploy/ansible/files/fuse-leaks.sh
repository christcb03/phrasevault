#!/bin/bash
# PVOS D211 — pvfs FUSE mounts the test suite or the smoke run left behind.
#
# A test that mounts the view in a TempDir must unmount it (and wait) before
# the directory goes (pvfs_fuse::MountGuard). Until D211 nothing looked, and
# presubuntu had ~249 dead mounts under /dev/shm/.tmp* and /tmp/.tmp* by
# 2026-10-01. Only mounts named "pvfs" under a tempfile directory count:
# nothing else on the box is ever touched.
#
#   fuse-leaks.sh snapshot FILE   list them before the stage
#   fuse-leaks.sh check FILE      the ones that appeared since: print them,
#                                 unmount them lazily, exit 1
set -u
mode=${1:?snapshot|check}
file=${2:?file}
list() {
  awk '$1 == "pvfs" && $3 ~ /^fuse/ && ($2 ~ /^\/dev\/shm\/\.tmp/ || $2 ~ /^\/tmp\/\.tmp/) { print $2 }' /proc/mounts | sort -u
}
case "$mode" in
  snapshot)
    list > "$file"
    echo "pvfs test mounts already present: $(wc -l < "$file")"
    ;;
  check)
    [ -f "$file" ] || : > "$file"
    list > "$file.now"
    new=$(comm -13 "$file" "$file.now")
    n=$(printf '%s\n' "$new" | grep -c . || true)
    echo "fuse leaks: $n"
    if [ "$n" -gt 0 ]; then
      printf '%s\n' "$new" | sed 's/^/  leaked: /'
      printf '%s\n' "$new" | while read -r m; do
        fusermount3 -uz "$m" 2>/dev/null || fusermount -uz "$m" 2>/dev/null || true
      done
      echo "unmounted (lazily); a test is not unmounting before its directory goes"
      exit 1
    fi
    ;;
  *) echo "usage: $0 snapshot|check FILE" >&2; exit 2 ;;
esac
