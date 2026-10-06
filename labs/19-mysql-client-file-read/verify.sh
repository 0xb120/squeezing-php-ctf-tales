#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="19-mysql-client-file-read"
PORT=8019
FLAG="$(tr -d '\r\n' < challenge/flag.txt)"

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[*] building $LAB"
docker compose build --quiet

echo "[*] starting challenge + rogue server"
docker compose up -d --quiet-pull challenge rogue

echo -n "[*] waiting for http://127.0.0.1:${PORT}/ "
ready=0
for _ in $(seq 1 90); do
    if curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${PORT}/"; then ready=1; break; fi
    echo -n "."
    sleep 1
done
echo
if [ "$ready" -ne 1 ]; then
    echo "[-] challenge never came up"
    docker compose logs --tail 50 || true
    echo "VERIFY FAIL $LAB"
    exit 1
fi

echo "[*] running the solver (rogue server runs inside it)"
solver_rc=0
out="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)" || solver_rc=$?
echo "$out"

got="$(printf '%s' "$out" | grep -o 'PHRACK{[^}]*}' | head -n 1 || true)"
if [ "$solver_rc" -eq 0 ] && [ "$got" = "$FLAG" ]; then
    echo "VERIFY OK $LAB"
    exit 0
fi
echo "[-] expected: $FLAG"
echo "[-] got     : ${got:-<nothing>}"
echo "VERIFY FAIL $LAB"
exit 1
