#!/usr/bin/env bash
# Rebuild every lab image from scratch (--no-cache) and then verify it.
# This is the test that catches broken external build dependencies
# (apt archives, composer, museum.php.net, ...) which a warm cache hides.
set -uo pipefail
cd "$(dirname "$0")/.."
LOGDIR="$PWD/.cold-logs"; mkdir -p "$LOGDIR"
pass=0; fail=0; failed=()
for lab in $(find labs -maxdepth 1 -mindepth 1 -type d | sort); do
  name=$(basename "$lab")
  start=$(date +%s)
  {
    echo "=== docker compose build --no-cache ==="
    (cd "$lab" && docker compose build --no-cache --progress plain) || exit 1
    echo "=== verify.sh ==="
    "$lab/verify.sh"
  } >"$LOGDIR/$name.log" 2>&1
  rc=$?
  el=$(( $(date +%s) - start ))
  if [ $rc -eq 0 ]; then printf '%-42s COLD OK   (%ss)\n' "$name" "$el"; pass=$((pass+1))
  else printf '%-42s COLD FAIL (%ss) -> .cold-logs/%s.log\n' "$name" "$el" "$name"; fail=$((fail+1)); failed+=("$name"); fi
  (cd "$lab" && docker compose down -v --remove-orphans >/dev/null 2>&1 || true)
done
echo; echo "cold passed: $pass   cold failed: $fail"
[ $fail -eq 0 ] || printf 'failed: %s\n' "${failed[*]}"
