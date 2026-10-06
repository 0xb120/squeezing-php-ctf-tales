#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="09-windows-path-wildcards"
FLAG="PHRACK{dos_device_wildcards_leak_your_sessid}"
URL="http://127.0.0.1:8009/"

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[*] building $LAB"
docker compose build --quiet

echo "[*] starting"
docker compose up -d --force-recreate >/dev/null

echo -n "[*] waiting for the challenge to answer "
ready=0
for _ in $(seq 1 90); do
    if curl -fsS -o /dev/null --max-time 2 "$URL" 2>/dev/null; then ready=1; break; fi
    echo -n "."
    sleep 1
done
echo
if [ "$ready" -ne 1 ]; then
    echo "VERIFY FAIL $LAB (service never came up)"
    docker compose logs --tail 40 || true
    exit 1
fi

echo "[*] running the exploit"
solver_rc=0
OUT="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)" || solver_rc=$?
echo "$OUT"

GOT="$(printf '%s' "$OUT" | grep -o 'PHRACK{[^}]*}' | tail -1 || true)"
if [ "$solver_rc" -eq 0 ] && [ "$GOT" = "$FLAG" ]; then
    echo "VERIFY OK $LAB"
    exit 0
fi

echo "VERIFY FAIL $LAB (got '${GOT:-<nothing>}', expected '$FLAG')"
exit 1
