#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="20-lfi-classic-toolkit"
PORT=8020
LEGACY_PORT=9020
FLAG="$(tr -d '\r\n' < challenge/flag.txt)"

SOLVER_TIMEOUT=240      # per solver run; the solver's own stage-4 budget is 120s
SOLVER_TRIES=2          # bounded: fail loudly instead of retrying forever

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

fail() { echo "[-] $*" >&2; echo "VERIFY FAIL ${LAB}"; exit 1; }

echo "[*] building ${LAB} (compiles PHP 5.3.3 and 5.3.4 on the first run)"
docker compose build --quiet

echo "[*] starting the challenge"
docker compose up -d --quiet-pull challenge legacy >/dev/null

wait_for() {
    local url="$1" needle="$2" name="$3" i
    for i in $(seq 1 90); do
        if curl -fsS -m 3 "$url" 2>/dev/null | grep -q "$needle"; then
            echo "[+] ${name} is up"
            return 0
        fi
        sleep 1
    done
    docker compose logs --no-color --tail=40 || true
    fail "${name} did not become healthy in 90s"
}

wait_for "http://127.0.0.1:${PORT}/index.php"          'php 8\.'   "modern wing (php 8.2.33)"
wait_for "http://127.0.0.1:${LEGACY_PORT}/index.php"   'php 5\.3\.3' "legacy wing (php 5.3.3)"
wait_for "http://127.0.0.1:${LEGACY_PORT}/v534/index.php" 'php 5\.3\.4' "legacy wing (php 5.3.4)"

got=""
out=""
for try in $(seq 1 "${SOLVER_TRIES}"); do
    echo "[*] running the solver (attempt ${try}/${SOLVER_TRIES}, hard timeout ${SOLVER_TIMEOUT}s)"
    set +e
    out="$(timeout "${SOLVER_TIMEOUT}" docker compose --profile solve run --rm --quiet-pull -T solver 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$out"
    if [ "$rc" -eq 124 ]; then
        echo "[-] solver hit the ${SOLVER_TIMEOUT}s timeout"
        continue
    fi
    got="$(printf '%s' "$out" | grep -o 'PHRACK{[^}]*}' | tail -n 1 || true)"
    [ "$rc" -eq 0 ] && [ -n "$got" ] && break
    echo "[-] solver rc=${rc}, flag='${got}'"
    got=""
done

[ -n "$got" ]        || fail "solver never produced a flag in ${SOLVER_TRIES} attempt(s)"
[ "$got" = "$FLAG" ] || fail "wrong flag: got '${got}', want '${FLAG}'"

echo "VERIFY OK ${LAB}"
