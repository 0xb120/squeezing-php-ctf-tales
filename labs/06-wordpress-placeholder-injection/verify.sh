#!/usr/bin/env bash
# usage: ./verify.sh            (build, run, exploit, assert, clean up)
set -euo pipefail
cd "$(dirname "$0")"

LAB="06-wordpress-placeholder-injection"
FLAG="$(tr -d '\n' < challenge/flag.txt)"
SQLI_FLAG="$(tr -d '\n' < challenge/flag-sqli.txt)"
PORT=8006

fail() {
  echo "[-] $*"
  docker compose logs --no-color challenge 2>/dev/null | tail -40 || true
  echo "VERIFY FAIL $LAB"
  exit 1
}

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
[ "$ok" -eq 1 ] || fail "service never came up"

echo "[*] running the solver ..."
set +e
out="$(timeout 600 docker compose --profile solve run --rm --quiet-pull solver 2>&1)"
rc=$?
set -e
echo "$out"

[ "$rc" -eq 0 ] || fail "solver exited $rc (124 = timed out after 600s)"

# Anchored extraction: only the solver's own summary lines count, never a
# flag that happens to appear somewhere in the progress output.
got="$(printf '%s\n' "$out" | sed -n 's/^FLAG: //p' | tail -n1)"
got_sqli="$(printf '%s\n' "$out" | sed -n 's/^SQLI FLAG: //p' | tail -n1)"

[ "$got" = "$FLAG" ] \
  || fail "stage 1 (object injection): expected [$FLAG] got [${got:-<nothing>}]"
[ "$got_sqli" = "$SQLI_FLAG" ] \
  || fail "stage 2 (double prepare SQLi): expected [$SQLI_FLAG] got [${got_sqli:-<nothing>}]"

echo "[+] stage 1 (object injection)    : $got"
echo "[+] stage 2 (double prepare SQLi) : $got_sqli"
echo "VERIFY OK $LAB"
exit 0
