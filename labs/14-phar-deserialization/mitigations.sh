#!/usr/bin/env bash
# Demonstrates which defences actually stop PHAR deserialization.
# Everything runs in throwaway containers; nothing is installed on the host.
set -euo pipefail
cd "$(dirname "$0")"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp solve/solve.py "$WORK/"

# 1. build the polyglot with the lab's own pure-python PHAR writer
cat > "$WORK/make.py" <<'PY'
import sys
sys.path.insert(0, "/w")
from solve import PhpObject, build_phar, gif_header
payload = PhpObject("ThumbnailCache", {
    "name": "pwned.txt",
    "content": PhpObject("ImageNote", {"width": 1, "height": 1, "note": "PWNED"}),
})
open("/w/poc.gif", "wb").write(
    build_phar({"note.txt": b"x"}, payload, prefix=gif_header()))
print("poc.gif written")
PY

cat > "$WORK/probe.php" <<'PHP'
<?php
class ImageNote {
    public $width = 0, $height = 0, $note = '';
    public function __toString() { return "<!-- {$this->width}x{$this->height} -->" . $this->note; }
}
class ThumbnailCache {
    public $name; public $content = null;
    public function __destruct() {
        if ($this->content !== null) { echo "  !! __destruct fired: ", (string) $this->content, "\n"; }
    }
}
if (getenv('UNREGISTER')) { stream_wrapper_unregister('phar'); echo "  (phar wrapper unregistered)\n"; }
echo "  PHP ", PHP_VERSION,
     "  phar.readonly=", ini_get('phar.readonly'),
     "  phar.require_hash=", ini_get('phar.require_hash'), "\n";
var_dump(@file_exists('phar:///w/poc.gif/note.txt'));
PHP

docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "$WORK:/w" -w /w python:3.12-alpine python make.py

run() { docker run --rm -v "$WORK:/w" -w /w "$@"; }

echo
echo "== 1. PHP 7.4, stock ini (the lab)  -> VULNERABLE"
run php:7.4.33-cli php probe.php

echo
echo "== 2. PHP 7.4 with phar.readonly=1 (already the default) -> STILL VULNERABLE"
echo "      (phar.readonly only forbids *writing* phars from PHP)"
run php:7.4.33-cli php -d phar.readonly=1 probe.php

echo
echo "== 3. PHP 7.4 + stream_wrapper_unregister('phar') -> FIXED"
run -e UNREGISTER=1 php:7.4.33-cli php probe.php

echo
echo "== 4. PHP 8.2 (metadata is no longer unserialized automatically) -> FIXED"
run php:8.2.33-cli php probe.php
