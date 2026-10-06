#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="10-avoracle"
FLAG="PHRACK{defender_ate_my_session}"
URL="http://127.0.0.1:8010/"
SCANNER="http://127.0.0.1:9010/status"

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[*] building $LAB"
docker compose build --quiet

echo "[*] starting"
docker compose up -d --force-recreate >/dev/null

echo -n "[*] waiting for the challenge and the scanner "
ready=0
for _ in $(seq 1 90); do
    if curl -fsS -o /dev/null --max-time 2 "$URL" 2>/dev/null \
       && curl -fsS -o /dev/null --max-time 2 "$SCANNER" 2>/dev/null; then
        ready=1; break
    fi
    echo -n "."
    sleep 1
done
echo
if [ "$ready" -ne 1 ]; then
    echo "VERIFY FAIL $LAB (services never came up)"
    docker compose logs --tail 40 || true
    exit 1
fi

# The oracle is a side channel: a single flaky query only costs one bit, but a
# cold start can still upset the first probe, so allow one retry.
GOT=""
for attempt in 1 2; do
    echo "[*] running the exploit (attempt $attempt)"
    OUT="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)" || true
    echo "$OUT"
    GOT="$(printf '%s' "$OUT" | grep -o 'PHRACK{[^}]*}' | tail -1 || true)"
    [ "$GOT" = "$FLAG" ] && break
done

if [ "$GOT" = "$FLAG" ]; then
    echo "[*] scanner quarantine log:"
    docker compose logs scanner 2>&1 | grep -c 'Threat ' || true
    echo "VERIFY OK $LAB"
    exit 0
fi

echo "VERIFY FAIL $LAB (got '${GOT:-<nothing>}', expected '$FLAG')"
docker compose logs --tail 30 scanner || true
exit 1
