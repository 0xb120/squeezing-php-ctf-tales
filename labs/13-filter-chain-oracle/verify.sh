#!/usr/bin/env bash
# usage: ./verify.sh   (build, run, exploit, assert the flag, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB=13-filter-chain-oracle
FLAG=$(cat challenge/flag.txt)
DC="docker compose"

cleanup() { $DC down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
echo "[*] building $LAB"
$DC build --quiet

echo "[*] starting challenge"
$DC up -d challenge

echo -n "[*] waiting for the service "
for _ in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
         -X POST --data-urlencode '0=/etc/hostname' \
         http://127.0.0.1:8013/ 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then echo " up"; break; fi
  echo -n "."; sleep 1
done
[ "${code:-000}" = "200" ] || { echo; echo "VERIFY FAIL $LAB (service never came up)"; exit 1; }

echo "[*] running the oracle (expected: well under 3 minutes)"
solver_rc=0
OUT=$(timeout 180 $DC --profile solve run --rm --quiet-pull -T solver 2>&1) || solver_rc=$?
echo "$OUT"

GOT=$(printf '%s' "$OUT" | grep -o 'PHRACK{[^}]*}' | tail -1 || true)
if [ "$solver_rc" -eq 0 ] && [ "$GOT" = "$FLAG" ]; then
  echo "VERIFY OK $LAB"
  exit 0
fi
echo "VERIFY FAIL $LAB (got '${GOT:-<nothing>}', want '$FLAG')"
exit 1
