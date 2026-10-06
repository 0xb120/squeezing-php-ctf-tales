#!/usr/bin/env bash
# usage: ./verify.sh   (build, run, exploit, assert flag, tear down)
set -euo pipefail
cd "$(dirname "$0")"

LAB="04-security-features-backfire"
EXPECT="PHRACK{preg_match_said_false_and_the_csp_never_shipped}"
COMPOSE="docker compose"

cleanup() {
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[verify] building $LAB ..."
$COMPOSE build >/dev/null

echo "[verify] starting stack ..."
$COMPOSE up -d >/dev/null

# wait for the challenge to answer HTTP (max ~90s)
echo "[verify] waiting for challenge ..."
ok=0
for i in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8004/" || true)
  if [ "$code" = "200" ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { echo "[verify] challenge did not become ready"; echo "VERIFY FAIL $LAB"; exit 1; }

# wait for the headless-browser bot (max ~90s)
echo "[verify] waiting for admin bot ..."
ok=0
for i in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:9004/health" || true)
  if [ "$code" = "200" ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { echo "[verify] bot did not become ready"; echo "VERIFY FAIL $LAB"; exit 1; }

echo "[verify] running solver (up to ~180s; the bot is a real browser) ..."
solver_rc=0
OUT="$(timeout 600 $COMPOSE --profile solve run --rm --use-aliases --quiet-pull solver 2>&1 || true)" || solver_rc=$?
echo "$OUT"

FLAG="$(printf '%s\n' "$OUT" | grep -oE 'PHRACK\{[^}]*\}' | tail -n1 || true)"
if [ "$solver_rc" -eq 0 ] && [ "$FLAG" = "$EXPECT" ]; then
  echo "VERIFY OK $LAB"
  exit 0
fi

echo "[verify] expected $EXPECT, got '${FLAG:-<none>}'"
echo "VERIFY FAIL $LAB"
exit 1
