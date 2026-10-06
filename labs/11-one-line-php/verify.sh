#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="11-one-line-php"
FLAG='PHRACK{upload_progress_wrote_my_shell_for_me}'
URL="http://127.0.0.1:8011/"

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "VERIFY FAIL $LAB: $*" >&2; exit 1; }

echo "[*] building $LAB"
docker compose build --quiet

echo "[*] starting challenge"
docker compose up -d challenge >/dev/null

echo "[*] waiting for the web server"
for _ in $(seq 1 90); do
    if curl -fs --max-time 2 "$URL" | grep -q 'highlight_file'; then
        ready=1; break
    fi
    sleep 1
done
[ "${ready:-0}" = 1 ] || fail "challenge did not become healthy in 90s"

echo "[*] running the exploit"
solver_rc=0
out="$(timeout 600 docker compose --profile solve run --rm --quiet-pull -T solver 2>&1)" || solver_rc=$?
echo "$out"

got="$(printf '%s' "$out" | grep -o 'PHRACK{[^}]*}' | head -n1 || true)"
[ "$solver_rc" -eq 0 ] || fail "solver exited $solver_rc (124 = timed out after 600s)"
[ -n "$got" ]        || fail "no flag in solver output"
[ "$got" = "$FLAG" ] || fail "wrong flag: got '$got', want '$FLAG'"

echo "VERIFY OK $LAB"
