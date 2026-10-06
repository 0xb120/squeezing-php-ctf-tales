#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
#
# CVE-2019-11043 is a memory-corruption bug: the solver may need several
# rounds, so the budget here is deliberately generous.
set -euo pipefail
cd "$(dirname "$0")"

LAB="17-php-fpm-underflow"
FLAG="$(tr -d '\r\n' < challenge/flag.txt)"

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "== building $LAB"
docker compose build >/dev/null

echo "== starting"
docker compose up -d >/dev/null

echo "== waiting for nginx + php-fpm"
ready=0
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8017/index.php 2>/dev/null; then
    ready=1; break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "services never became ready"
  docker compose logs --tail 50
  echo "VERIFY FAIL $LAB"; exit 1
fi

echo "== solving (this can take a few minutes)"
solver_rc=0
out="$(timeout 900 docker compose --profile solve run --rm --quiet-pull solver 2>&1)" || solver_rc=$?
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
