#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="16-php-cgi-argument-injection"
FLAG="$(tr -d '\r\n' < challenge/flag.txt)"

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "== building $LAB"
docker compose build >/dev/null

echo "== starting"
docker compose up -d >/dev/null

echo "== waiting for both gateways"
ready=0
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8016/ 2>/dev/null &&
     curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:9016/ 2>/dev/null; then
    ready=1; break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "services never became ready"
  docker compose logs --tail 50
  echo "VERIFY FAIL $LAB"; exit 1
fi

echo "== solving"
solver_rc=0
out="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)" || solver_rc=$?
echo "$out"

got="$(printf '%s' "$out" | grep -o 'PHRACK{[^}]*}' | tail -1 || true)"
if [ "$solver_rc" -eq 0 ] && [ "$got" = "$FLAG" ]; then
  echo "VERIFY OK $LAB"
  exit 0
fi
echo "expected: $FLAG"
echo "got     : ${got:-<nothing>}"
echo "VERIFY FAIL $LAB"
exit 1
