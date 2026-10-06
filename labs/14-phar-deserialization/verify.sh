#!/usr/bin/env bash
# usage: ./verify.sh   (build, run, exploit, assert the flag, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB=14-phar-deserialization
FLAG=$(cat challenge/flag.txt)
DC="docker compose"

cleanup() { $DC down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
echo "[*] building $LAB"
$DC build --quiet

echo "[*] starting challenge"
$DC up -d challenge >/dev/null

echo -n "[*] waiting for the service "
ready=0
for _ in $(seq 1 90); do
  if curl -fs --max-time 2 http://127.0.0.1:8014/ | grep -q 'phar gallery'; then
    ready=1; echo " up"; break
  fi
  echo -n "."; sleep 1
done
[ "$ready" = 1 ] || { echo; echo "VERIFY FAIL $LAB (service never came up)"; exit 1; }

echo "[*] running the exploit"
solver_rc=0
OUT=$(timeout 120 $DC --profile solve run --rm --quiet-pull -T solver 2>&1) || solver_rc=$?
echo "$OUT"

GOT=$(printf '%s' "$OUT" | grep -o 'PHRACK{[^}]*}' | tail -1 || true)
if [ "$solver_rc" -eq 0 ] && [ "$GOT" = "$FLAG" ]; then
  echo "VERIFY OK $LAB"
  exit 0
fi
echo "VERIFY FAIL $LAB (got '${GOT:-<nothing>}', want '$FLAG')"
exit 1
