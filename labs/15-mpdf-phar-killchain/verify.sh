#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail

cd "$(dirname "$0")"

LAB="15-mpdf-phar-killchain"
FLAG="$(tr -d '\r\n' < challenge/flag.txt)"
COMPOSE="docker compose"

cleanup() { $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "VERIFY FAIL $LAB${1:+ - $1}"; exit 1; }

cleanup
echo "[*] building ..."
$COMPOSE build --quiet challenge >/dev/null

echo "[*] starting ..."
$COMPOSE up -d challenge >/dev/null

echo "[*] waiting for the service ..."
ok=0
for _ in $(seq 1 90); do
    if curl -fsS --max-time 3 http://127.0.0.1:8015/ 2>/dev/null | grep -q 'QuoteBuilder'; then
        ok=1; break
    fi
    sleep 1
done
[ "$ok" = 1 ] || { $COMPOSE logs challenge | tail -40; fail "service never came up"; }

echo "[*] running the exploit ..."
out="$(timeout 600 $COMPOSE --profile solve run --rm --quiet-pull -T solver 2>&1)" || { echo "$out"; fail "solver exited non-zero"; }
echo "$out"

got="$(printf '%s' "$out" | grep -o 'PHRACK{[^}]*}' | tail -1 || true)"
[ -n "$got" ] || fail "no flag in solver output"
[ "$got" = "$FLAG" ] || fail "flag mismatch: got '$got', expected '$FLAG'"

echo "VERIFY OK $LAB"
