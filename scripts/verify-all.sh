#!/usr/bin/env bash
# Build, run, exploit and tear down every lab. One lab at a time (labs bind
# fixed host ports and some are CPU hungry). Usage:
#   scripts/verify-all.sh            # all labs
#   scripts/verify-all.sh 11 12 14   # only these lab numbers
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
LOGDIR="$ROOT/.verify-logs"; mkdir -p "$LOGDIR"

if [ $# -gt 0 ]; then
  LABS=()
  for n in "$@"; do
    d=$(find labs -maxdepth 1 -type d -name "${n}-*" | head -1)
    [ -n "$d" ] && LABS+=("$d") || echo "no lab matching '$n'" >&2
  done
else
  mapfile -t LABS < <(find labs -maxdepth 1 -mindepth 1 -type d | sort)
fi

pass=0; fail=0; failed=()
printf '%-42s %s\n' "LAB" "RESULT"
printf '%-42s %s\n' "------------------------------------------" "------"
for lab in "${LABS[@]}"; do
  name=$(basename "$lab")
  if [ ! -x "$lab/verify.sh" ]; then
    printf '%-42s %s\n' "$name" "SKIP (no verify.sh)"; continue
  fi
  start=$(date +%s)
  if "$lab/verify.sh" >"$LOGDIR/$name.log" 2>&1; then
    printf '%-42s %s (%ss)\n' "$name" "OK" "$(( $(date +%s) - start ))"; pass=$((pass+1))
  else
    printf '%-42s %s (%ss) -> %s\n' "$name" "FAIL" "$(( $(date +%s) - start ))" ".verify-logs/$name.log"
    fail=$((fail+1)); failed+=("$name")
  fi
done
echo
echo "passed: $pass   failed: $fail"
[ $fail -eq 0 ] || { printf 'failed labs: %s\n' "${failed[*]}"; exit 1; }
