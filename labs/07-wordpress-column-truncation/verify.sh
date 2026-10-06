#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="07-wordpress-column-truncation"
FLAG="$(tr -d '\n' < challenge/flag.txt)"
DC="docker compose"

cleanup() { $DC down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
$DC build --quiet
$DC up -d

echo "[*] waiting for http://127.0.0.1:8007/ ..."
ok=0
for _ in $(seq 1 90); do
  if curl -fs -o /dev/null "http://127.0.0.1:8007/index.php" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
if [ "$ok" -ne 1 ]; then
  echo "challenge never became healthy"; $DC logs --tail 50
  echo "VERIFY FAIL $LAB"; exit 1
fi

echo "[*] running solver ..."
solver_rc=0
OUT="$(timeout 600 $DC --profile solve run --rm --quiet-pull solver 2>&1)" || solver_rc=$?
echo "$OUT"

GOT="$(printf '%s' "$OUT" | grep -o 'PHRACK{[^}]*}' | head -n1 || true)"
if [ "$solver_rc" -eq 0 ] && [ "$GOT" = "$FLAG" ]; then
  echo "VERIFY OK $LAB"; exit 0
fi
echo "expected [$FLAG] got [$GOT]"
echo "VERIFY FAIL $LAB"; exit 1
