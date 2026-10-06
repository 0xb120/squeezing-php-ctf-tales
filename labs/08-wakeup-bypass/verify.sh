#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="08-wakeup-bypass"
FLAG="$(tr -d '\n' < challenge/flag.txt)"
LEGACY_FLAG="$(tr -d '\n' < challenge/flag-legacy.txt)"
DC="docker compose"

cleanup() { $DC down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
$DC build --quiet
$DC up -d

for port in 8008 9008; do
  echo "[*] waiting for http://127.0.0.1:${port}/ ..."
  ok=0
  for _ in $(seq 1 90); do
    if curl -fs -o /dev/null "http://127.0.0.1:${port}/index.php" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" -ne 1 ]; then
    echo "service on ${port} never became healthy"; $DC logs --tail 50
    echo "VERIFY FAIL $LAB"; exit 1
  fi
done

echo "[*] running solver ..."
solver_rc=0
OUT="$(timeout 600 $DC --profile solve run --rm --quiet-pull solver 2>&1)" || solver_rc=$?
echo "$OUT"

GOT="$(printf '%s\n' "$OUT" | sed -n 's/^FLAG: //p' | tail -n1)"
GOT_LEGACY="$(printf '%s\n' "$OUT" | sed -n 's/^LEGACY FLAG: //p' | tail -n1)"

if [ "$solver_rc" -eq 0 ] && [ "$GOT" = "$FLAG" ] && [ "$GOT_LEGACY" = "$LEGACY_FLAG" ]; then
  echo "VERIFY OK $LAB"; exit 0
fi
echo "expected      [$FLAG] got [$GOT]"
echo "expected leg. [$LEGACY_FLAG] got [$GOT_LEGACY]"
echo "VERIFY FAIL $LAB"; exit 1
