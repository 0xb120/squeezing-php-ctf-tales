#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="05-serialize-then-replace"
FLAG="$(tr -d '\n' < challenge/flag.txt)"
PORT=8005

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
echo "[*] building $LAB ..."
docker compose build --quiet

echo "[*] starting ..."
docker compose up -d --quiet-pull

echo "[*] waiting for http://127.0.0.1:$PORT ..."
ok=0
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$PORT/index.php" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
if [ "$ok" -ne 1 ]; then
  echo "[-] service never came up"; docker compose logs --no-color | tail -40
  echo "VERIFY FAIL $LAB"; exit 1
fi

echo "[*] running the solver ..."
solver_rc=0
out="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)" || solver_rc=$?
echo "$out"

got="$(printf '%s' "$out" | grep -oE 'PHRACK\{[^}]+\}' | tail -1 || true)"
if [ "$solver_rc" -eq 0 ] && [ "$got" = "$FLAG" ]; then
  echo "VERIFY OK $LAB"
  exit 0
fi

echo "[-] expected: $FLAG"
echo "[-] got     : ${got:-<nothing>}"
docker compose logs --no-color challenge | tail -40
echo "VERIFY FAIL $LAB"
exit 1
