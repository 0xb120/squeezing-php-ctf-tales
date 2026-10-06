#!/usr/bin/env python3
"""
A deliberately small CGI/1.1 gateway (the "web server") in front of a real,
unmodified php-cgi binary.

It exists so that the PHP side of the lab is 100% genuine: every byte of option
parsing, of the CVE-2012-1823 guard and of the ini handling is done by the
distribution's php-cgi.  The gateway only does what a web server does: fill in
the CGI environment, decide the child's argv, pipe the body in and the response
out.

Two argv policies are implemented, selected with $MODE:

  MODE=classic
      The "legacy" gateway.  It builds argv out of the query string
      unconditionally, i.e. it ignores the "only if there is no unencoded '='"
      clause of RFC 3875 section 4.4.  Plenty of CGI front ends have been this
      sloppy; it is also what makes php-cgi's own guard useless, because that
      guard only looks at query strings that contain no '='.

  MODE=worstfit
      RFC 3875 section 4.4 to the letter (argv only when the raw query string
      contains no unencoded '='), *plus* a model of the Windows UTF-16 -> ANSI
      "Best Fit" conversion that the real CVE-2024-4577 relies on.  QUERY_STRING
      is handed to php-cgi exactly as it arrived on the wire - the Best Fit
      table is applied to argv only, which is precisely the asymmetry Orange
      Tsai and splitline exploited.
"""

import os
import re
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PHP_CGI = os.environ.get("PHP_CGI", "/usr/bin/php-cgi")
DOCROOT = os.environ.get("DOCROOT", "/var/www/html")
MODE = os.environ.get("MODE", "classic")
PORT = int(os.environ.get("PORT", "80"))

# --------------------------------------------------------------------------
# Windows "Best Fit" model.
#
# When a Windows program is started through an ANSI entry point, the UTF-16
# command line is converted to the process ANSI code page with
# WideCharToMultiByte(CP_ACP, ...).  Characters that have no representation in
# the code page are not dropped: Windows substitutes a look-alike.  A handful of
# those look-alikes are documented in
# https://devco.re/blog/2025/01/09/worstfit-unveiling-hidden-transformers-in-windows-ansi/
# The table below is a small, faithful excerpt - enough to turn a harmless soft
# hyphen into an option prefix.
# --------------------------------------------------------------------------
BEST_FIT = {
    0x00AD: "-",   # SOFT HYPHEN               -> '-'   (cp932 / cp936 / cp950)
    0x02D7: "-",   # MODIFIER LETTER MINUS SIGN-> '-'
    0x2010: "-",   # HYPHEN                    -> '-'
    0x2011: "-",   # NON-BREAKING HYPHEN       -> '-'
    0x2012: "-",   # FIGURE DASH               -> '-'
    0x2013: "-",   # EN DASH                   -> '-'
    0x2014: "-",   # EM DASH                   -> '-'
    0x2015: "-",   # HORIZONTAL BAR            -> '-'
    0x2212: "-",   # MINUS SIGN                -> '-'
    0xFE63: "-",   # SMALL HYPHEN-MINUS        -> '-'
    0x221E: "8",   # INFINITY                  -> '8'   (cp1252)
    0x00A5: "\\",  # YEN SIGN                  -> '\'   (cp932, JP)
    0x20A9: "\\",  # WON SIGN                  -> '\'   (cp949, KR)
    0x2044: "/",   # FRACTION SLASH            -> '/'
    0x2215: "/",   # DIVISION SLASH            -> '/'
    0x2018: "'",
    0x2019: "'",
    0x201C: '"',
    0x201D: '"',
    0x00A6: "|",
}


def best_fit(text: str) -> str:
    """UTF-16 -> ANSI with Best Fit substitution (modelled)."""
    out = []
    for ch in text:
        cp = ord(ch)
        if cp in BEST_FIT:
            out.append(BEST_FIT[cp])
        elif 0xFF01 <= cp <= 0xFF5E:
            # Fullwidth forms collapse onto their ASCII twin: U+FF0D -> '-',
            # U+FF0F -> '/', U+FF1D -> '=', U+FF3C -> '\' ...
            out.append(chr(cp - 0xFEE0))
        elif cp < 0x80:
            out.append(ch)
        else:
            # No look-alike: the real conversion emits the default character.
            out.append("?")
    return "".join(out)


def percent_decode_to_text(chunk: str) -> str:
    """%XX -> raw bytes -> text, the way a Windows server would see it.

    The raw bytes are interpreted as UTF-16-able text: valid UTF-8 first (so the
    multi-byte look-alikes such as %EF%BC%8D work), otherwise byte-per-byte as
    cp1252/latin-1 (so a lone %AD is U+00AD, the soft hyphen).
    """
    raw = urllib.parse.unquote_to_bytes(chunk)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def c_string(text: str) -> str:
    """argv elements are NUL-terminated C strings: everything after the first
    NUL byte is simply not there, exactly as execve() would see it."""
    return text.split("\x00", 1)[0]


def build_argv(raw_qs: str):
    """Decide the child's argv from the raw query string."""
    if not raw_qs:
        return []

    if MODE == "worstfit":
        # RFC 3875 4.4: a query string that contains an unencoded '=' is *not*
        # a command line.  Windows servers honour this - which is why the real
        # CVE-2024-4577 payload spells its '=' as %3D.
        if "=" in raw_qs:
            return []
        return [c_string(best_fit(percent_decode_to_text(p)))
                for p in raw_qs.split("+")]

    # MODE=classic: the sloppy gateway.  argv is built from every query string.
    return [c_string(urllib.parse.unquote_to_bytes(p).decode("latin-1"))
            for p in raw_qs.split("+")]


def cgi_environ(handler, script_filename, script_name, path_info, raw_qs):
    env = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_SOFTWARE": "tiny-cgid/0.1 (%s)" % MODE,
        "SERVER_PROTOCOL": handler.request_version,
        "SERVER_NAME": handler.server.server_name,
        "SERVER_PORT": str(handler.server.server_port),
        "REQUEST_METHOD": handler.command,
        "REQUEST_URI": handler.path,
        "SCRIPT_NAME": script_name,
        "SCRIPT_FILENAME": script_filename,
        "DOCUMENT_ROOT": DOCROOT,
        "QUERY_STRING": raw_qs,          # <- RAW, exactly as it came in
        "REMOTE_ADDR": handler.client_address[0],
        "REMOTE_PORT": str(handler.client_address[1]),
        "REDIRECT_STATUS": "1",          # php-cgi refuses to run without this
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    if path_info:
        env["PATH_INFO"] = path_info
        env["PATH_TRANSLATED"] = os.path.join(DOCROOT, path_info.lstrip("/"))
    ctype = handler.headers.get("Content-Type")
    if ctype:
        env["CONTENT_TYPE"] = ctype
    clen = handler.headers.get("Content-Length")
    if clen:
        env["CONTENT_LENGTH"] = clen
    for name, value in handler.headers.items():
        key = "HTTP_" + re.sub(r"[^A-Z0-9]", "_", name.upper())
        if key in ("HTTP_CONTENT_TYPE", "HTTP_CONTENT_LENGTH"):
            continue
        env[key] = value
    return env


class Handler(BaseHTTPRequestHandler):
    server_version = "tiny-cgid/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s - %s\n" % (MODE, self.client_address[0], fmt % args))

    # ------------------------------------------------------------------
    def handle_one(self):
        raw_path, sep, raw_qs = self.path.partition("?")
        if not sep:
            raw_qs = ""

        script_name = urllib.parse.unquote(raw_path)
        if script_name.endswith("/"):
            script_name += "index.php"
        if script_name == "":
            script_name = "/index.php"

        # No directory traversal: this lab is about argv, not about ../
        candidate = os.path.normpath(os.path.join(DOCROOT, script_name.lstrip("/")))
        if not candidate.startswith(DOCROOT + os.sep) and candidate != DOCROOT:
            return self.simple(403, b"forbidden\n")
        if not os.path.isfile(candidate):
            return self.simple(404, b"no such script\n")

        body = b""
        clen = int(self.headers.get("Content-Length") or 0)
        if clen:
            body = self.rfile.read(clen)

        argv = build_argv(raw_qs)
        env = cgi_environ(self, candidate, script_name, "", raw_qs)

        try:
            proc = subprocess.run(
                [PHP_CGI] + argv,
                env=env, input=body, cwd=os.path.dirname(candidate),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
            )
        except subprocess.TimeoutExpired:
            return self.simple(504, b"php-cgi timed out\n")

        if proc.stderr:
            sys.stderr.write(proc.stderr.decode("latin-1", "replace"))

        self.send_cgi_response(proc.stdout)

    do_GET = do_POST = do_HEAD = handle_one

    # ------------------------------------------------------------------
    def send_cgi_response(self, out: bytes):
        head, sep, body = out.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = out.partition(b"\n\n")
        if not sep:
            head, body = b"", out

        status = 200
        reason = "OK"
        headers = []
        for line in head.splitlines():
            if b":" not in line:
                continue
            name, _, value = line.partition(b":")
            name = name.strip().decode("latin-1")
            value = value.strip().decode("latin-1")
            if name.lower() == "status":
                parts = value.split(" ", 1)
                try:
                    status = int(parts[0])
                except ValueError:
                    status = 500
                reason = parts[1] if len(parts) > 1 else ""
                continue
            headers.append((name, value))

        self.send_response(status, reason)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def simple(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def drop_privileges(user="www-data"):
    """Bind as root (port 80), then hand php-cgi to an unprivileged user."""
    if os.geteuid() != 0:
        return
    import pwd
    pw = pwd.getpwnam(user)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.environ["HOME"] = pw.pw_dir


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    drop_privileges()
    sys.stderr.write("tiny-cgid: mode=%s docroot=%s php-cgi=%s port=%d uid=%d\n"
                     % (MODE, DOCROOT, PHP_CGI, PORT, os.geteuid()))
    srv.serve_forever()


if __name__ == "__main__":
    main()
