#!/usr/bin/env bash
# usage: ./verify.sh   (build, run, exploit, assert the flag, tear down)
# Self-contained: the only host dependency is Docker + compose v2.
set -euo pipefail
cd "$(dirname "$0")"

LAB="03-format-string-oriented-programming"
EXPECT="PHRACK{bug_71105_taught_the_new_operator_to_speak_printf}"

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "VERIFY FAIL $LAB"; exit 1; }

echo "[verify] building $LAB ..."
docker compose build >/dev/null

echo "[verify] starting challenge ..."
docker compose up -d challenge >/dev/null

# Wait for php-fpm + nginx to answer (max ~90s).
ok=0
for _ in $(seq 1 90); do
  if docker compose exec -T challenge sh -c \
       'curl -sf -o /dev/null http://127.0.0.1/ 2>/dev/null || wget -q -O /dev/null http://127.0.0.1/'; then
    ok=1; break
  fi
  sleep 1
done
[ "$ok" = 1 ] || { echo "[verify] service never became healthy"; docker compose logs challenge | tail -30; fail; }

echo "[verify] running solver ..."
OUT="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)" || { echo "$OUT"; fail; }
echo "$OUT"

FLAG="$(printf '%s\n' "$OUT" | grep -ao 'PHRACK{[^}]*}' | tail -1 || true)"
[ -n "$FLAG" ] || { echo "[verify] no flag in solver output"; fail; }
[ "$FLAG" = "$EXPECT" ] || { echo "[verify] flag mismatch: got '$FLAG' want '$EXPECT'"; fail; }

echo "VERIFY OK $LAB"
