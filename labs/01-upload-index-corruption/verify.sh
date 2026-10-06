#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="01-upload-index-corruption"
PORT=8001
FLAG='PHRACK{unbalanced_brackets_forge_the_files_array}'

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "[*] building ${LAB} (compiles PHP 5.3.10 on the first run, be patient)"
docker compose build --quiet

echo "[*] starting the challenge"
docker compose up -d --quiet-pull >/dev/null

echo -n "[*] waiting for http://127.0.0.1:${PORT}/ "
ready=0
for _ in $(seq 1 90); do
    if curl -fsS -m 2 -o /dev/null "http://127.0.0.1:${PORT}/" 2>/dev/null; then
        ready=1
        break
    fi
    echo -n "."
    sleep 1
done
echo

if [ "$ready" -ne 1 ]; then
    echo "[-] challenge never came up"
    docker compose logs --no-color challenge | tail -40
    echo "VERIFY FAIL ${LAB}"
    exit 1
fi

echo "[*] running the solver"
set +e
out="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)"
rc=$?
set -e
printf '%s\n' "$out"

got="$(printf '%s' "$out" | grep -o 'PHRACK{[^}]*}' | tail -n 1 || true)"

if [ "$rc" -eq 0 ] && [ "$got" = "$FLAG" ]; then
    echo "VERIFY OK ${LAB}"
    exit 0
fi

echo "[-] solver rc=${rc} flag='${got}' expected='${FLAG}'"
echo "VERIFY FAIL ${LAB}"
exit 1
