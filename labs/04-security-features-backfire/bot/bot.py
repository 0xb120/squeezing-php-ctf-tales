#!/usr/bin/env python3
"""
notes.lab admin bot.

A real headless Chromium. It keeps the flag in a cookie scoped to the
challenge origin and opens whatever same-origin URL you report to it.

  POST /report   url=<http://challenge/...>
  GET  /         html form
  GET  /health   readiness probe

Driving Chromium is done over the Chrome DevTools Protocol with a hand
rolled WebSocket client, so the image needs nothing but python3 + chromium.
"""
import base64
import json
import os
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHALLENGE_ORIGIN = os.environ.get("CHALLENGE_ORIGIN", "http://challenge")
COOKIE_NAME = os.environ.get("COOKIE_NAME", "flag")
VISIT_SECONDS = float(os.environ.get("VISIT_SECONDS", "6"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
DEVTOOLS_PORT = int(os.environ.get("DEVTOOLS_PORT", "9222"))
CHROME = os.environ.get("CHROME_BIN", "/usr/bin/chromium-browser")

with open(os.environ.get("FLAG_FILE", "/flag.txt")) as fh:
    FLAG = fh.read().strip()


def log(*a):
    print("[bot]", *a, flush=True)


# --------------------------------------------------------------------------
# minimal RFC6455 client (text frames only, which is all CDP speaks)
# --------------------------------------------------------------------------
class WebSocket:
    def __init__(self, url, timeout=30):
        if not url.startswith("ws://"):
            raise ValueError("ws:// only: %r" % url)
        hostport, _, path = url[5:].partition("/")
        host, _, port = hostport.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            (
                "GET /%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n" % (path, hostport, key)
            ).encode()
        )
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise IOError("websocket handshake: connection closed")
            self.buf += chunk
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0] + b" ":
            raise IOError("websocket handshake failed: %r" % head[:120])

    def _exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise IOError("websocket closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _frame(self, opcode, payload):
        mask = os.urandom(4)
        hdr = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        hdr += mask
        return bytes(hdr) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    def send(self, text):
        self.sock.sendall(self._frame(0x1, text.encode()))

    def recv(self):
        parts = []
        while True:
            b0, b1 = self._exact(2)
            fin, opcode = b0 & 0x80, b0 & 0x0F
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._exact(8))[0]
            mask = self._exact(4) if b1 & 0x80 else None
            data = self._exact(n)
            if mask:
                data = bytes(c ^ mask[i % 4] for i, c in enumerate(data))
            if opcode == 0x8:
                raise IOError("websocket close frame")
            if opcode == 0x9:
                self.sock.sendall(self._frame(0xA, data))
                continue
            if opcode == 0xA:
                continue
            parts.append(data)
            if fin:
                return b"".join(parts).decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.sendall(self._frame(0x8, b""))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class CDP:
    def __init__(self, ws):
        self.ws = ws
        self.seq = 0

    def call(self, method, params=None, timeout=25):
        self.seq += 1
        want = self.seq
        self.ws.send(json.dumps({"id": want, "method": method, "params": params or {}}))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == want:
                if "error" in msg:
                    raise RuntimeError("%s: %s" % (method, msg["error"]))
                return msg.get("result", {})
        raise TimeoutError(method)


# --------------------------------------------------------------------------
# chromium
# --------------------------------------------------------------------------
CHROME_ARGS = [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-software-rasterizer",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--window-size=1024,768",
    "--remote-debugging-address=127.0.0.1",
    "--remote-debugging-port=%d" % DEVTOOLS_PORT,
    "--user-data-dir=/tmp/chrome-profile",
    "about:blank",
]

_chrome = None
_chrome_lock = threading.Lock()


def devtools(path, method="GET"):
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (DEVTOOLS_PORT, path), method=method
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(body)
    except ValueError:
        return body


def start_chrome():
    global _chrome
    with _chrome_lock:
        if _chrome is not None and _chrome.poll() is None:
            return
        log("starting chromium ...")
        _chrome = subprocess.Popen(
            [CHROME] + CHROME_ARGS,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(120):
            try:
                ver = devtools("/json/version")
                log("chromium up:", ver.get("Browser"))
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError("chromium did not expose devtools in time")


def visit(url):
    """open `url` in a fresh tab that already holds the flag cookie."""
    start_chrome()
    tab = devtools("/json/new?about:blank", method="PUT")
    tab_id = tab["id"]
    ws = None
    try:
        ws = WebSocket(tab["webSocketDebuggerUrl"])
        cdp = CDP(ws)
        cdp.call("Network.enable")
        cdp.call(
            "Network.setCookie",
            {
                "name": COOKIE_NAME,
                "value": FLAG,
                "url": CHALLENGE_ORIGIN + "/",
                "path": "/",
                "httpOnly": False,
                "secure": False,
                "sameSite": "Lax",
            },
        )
        cdp.call("Page.enable")
        cdp.call("Page.navigate", {"url": url})
        time.sleep(VISIT_SECONDS)
        try:
            res = cdp.call(
                "Runtime.evaluate",
                {"expression": "document.title + '|' + location.href"},
            )
            log("visited:", res.get("result", {}).get("value"))
        except Exception as exc:
            log("post-visit probe failed:", exc)
    finally:
        if ws is not None:
            ws.close()
        try:
            devtools("/json/close/" + tab_id)
        except Exception:
            pass


WORK = queue.Queue()


def worker():
    while True:
        url = WORK.get()
        try:
            log("visiting", url[:180])
            visit(url)
            log("done")
        except Exception as exc:
            log("visit failed:", repr(exc))
            try:
                with _chrome_lock:
                    global _chrome
                    if _chrome is not None:
                        _chrome.kill()
                        _chrome = None
            except Exception:
                pass
        finally:
            WORK.task_done()


# --------------------------------------------------------------------------
# report endpoint
# --------------------------------------------------------------------------
FORM = b"""<!doctype html><meta charset="utf-8"><title>notes.lab admin bot</title>
<style>body{background:#11131a;color:#c8ccd4;font:14px/1.5 ui-monospace,monospace;padding:2rem}
h1{color:#e8b84b;font-size:1.2rem}input{width:100%%;box-sizing:border-box;background:#0d0f15;
color:#c8ccd4;border:1px solid #2d323f;border-radius:4px;padding:.5rem;font:inherit}
button{background:#e8b84b;border:0;border-radius:4px;padding:.45rem 1rem;margin-top:.6rem;
font:inherit;font-weight:600;cursor:pointer}p{color:#6d7480}</style>
<h1>admin bot</h1><p>i am a real headless chromium. i hold an admin cookie for
<code>%s</code> and i will open any URL on that origin.</p>
<form method="post" action="/report"><input name="url" placeholder="%s/?xss=...">
<button>report</button></form>""" % (
    CHALLENGE_ORIGIN.encode(),
    CHALLENGE_ORIGIN.encode(),
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _reply(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            return self._reply(200, "ok", "text/plain")
        if path == "/report":
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            return self._submit(qs.get("url", [""])[0])
        return self._reply(200, FORM)

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/report":
            return self._reply(404, "not found", "text/plain")
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype == "application/json":
            try:
                url = json.loads(raw).get("url", "")
            except ValueError:
                url = ""
        else:
            url = urllib.parse.parse_qs(raw).get("url", [""])[0]
        return self._submit(url)

    def _submit(self, url):
        url = (url or "").strip()
        if not url.startswith(CHALLENGE_ORIGIN + "/"):
            return self._reply(
                400, "the admin only opens links on %s\n" % CHALLENGE_ORIGIN, "text/plain"
            )
        if WORK.qsize() > 32:
            return self._reply(429, "queue full, try again\n", "text/plain")
        WORK.put(url)
        return self._reply(200, "queued, the admin will look at it shortly\n", "text/plain")


def main():
    threading.Thread(target=worker, daemon=True).start()
    try:
        start_chrome()
    except Exception as exc:
        log("warm-up failed, will retry per visit:", exc)
    srv = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    log("report endpoint on :%d, origin %s" % (LISTEN_PORT, CHALLENGE_ORIGIN))
    srv.serve_forever()


if __name__ == "__main__":
    main()
