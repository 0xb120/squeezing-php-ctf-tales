#!/usr/bin/env python3
"""
PluginHub package registry - internal service.

Only reachable from the application network, so the administrative endpoints
trust the X-Registry-Role header instead of doing real authentication.
"""

import os
import socketserver
import urllib.parse
from http.server import BaseHTTPRequestHandler

FLAG_PATH = "/flag.txt"
CACHE_DIR = "/pkgcache"
LISTEN = ("0.0.0.0", 8080)

BANNER = (
    "PluginHub package registry 1.4\n"
    "\n"
    "  GET  /                    this banner\n"
    "  GET  /packages            list published packages\n"
    "  GET  /packages/<name>     fetch a published package\n"
    "\n"
    "administrative (application server only, POST + X-Registry-Role: admin):\n"
    "  POST /admin/export        dest=<filename>   dump the sealed vault bundle\n"
    "                                              into the shared package cache\n"
)


class Registry(BaseHTTPRequestHandler):
    # HTTP/1.1 with persistent connections: the nightly backup job pipelines.
    protocol_version = "HTTP/1.1"
    server_version = "PluginHubRegistry/1.4"
    sys_version = ""

    def log_message(self, fmt, *args):
        print("[registry] %s - %s" % (self.address_string(), fmt % args), flush=True)

    def _reply(self, code, body, ctype="text/plain; charset=utf-8"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    # ----------------------------------------------------------------- GET --

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path in ("/", "/index"):
            return self._reply(200, BANNER)

        if path == "/packages":
            try:
                names = sorted(
                    n for n in os.listdir(CACHE_DIR)
                    if os.path.isfile(os.path.join(CACHE_DIR, n))
                )
            except OSError:
                names = []
            return self._reply(200, "".join(n + "\n" for n in names) or "(empty)\n")

        if path.startswith("/packages/"):
            name = os.path.basename(path[len("/packages/"):])
            target = os.path.join(CACHE_DIR, name)
            if name and os.path.isfile(target):
                with open(target, "rb") as fh:
                    return self._reply(200, fh.read())
            return self._reply(404, "no such package\n")

        if path.startswith("/admin/"):
            return self._reply(405, "administrative endpoints are POST only\n")

        return self._reply(404, "not found\n")

    # ---------------------------------------------------------------- POST --

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path != "/admin/export":
            return self._reply(404, "not found\n")

        if (self.headers.get("X-Registry-Role") or "").strip().lower() != "admin":
            return self._reply(403, "X-Registry-Role: admin required\n")

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        fields = urllib.parse.parse_qs(body)
        dest = os.path.basename((fields.get("dest") or [""])[0].strip())

        if not dest or dest in (".", ".."):
            return self._reply(400, "dest= is required\n")

        try:
            with open(FLAG_PATH, "rb") as fh:
                bundle = fh.read()
        except OSError:
            return self._reply(500, "vault bundle is missing\n")

        target = os.path.join(CACHE_DIR, dest)
        with open(target, "wb") as fh:
            fh.write(bundle)
        os.chmod(target, 0o644)

        return self._reply(200, "exported %s (%d bytes)\n" % (dest, len(bundle)))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    os.makedirs(CACHE_DIR, exist_ok=True)
    print("[registry] listening on %s:%d" % LISTEN, flush=True)
    Server(LISTEN, Registry).serve_forever()
