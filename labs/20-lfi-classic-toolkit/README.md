# 20 — The LFI Classic Toolkit

A museum with four exhibits, one per decade of turning `include()` into code
execution. Everything here predates filter chains. Everything here except one
exhibit still works.

## Article reference

Phrack #72, "The Art of PHP - My CTF Journey and Untold Stories!" by Orange
Tsai — section **4.1 "Twenty Years of Evolving LFI to RCE"**, the pages
*before* Level 0.

That passage splits twenty years of LFI-to-RCE into two approaches — finding
attacker-controllable files on the server, and abusing built-in wrappers to
bypass restrictions — and names four landmarks. This lab is those four
landmarks, one per stage:

| Stage | Technique | Origin |
|---|---|---|
| 1 | NUL-byte / over-long-path truncation against a fixed `.php` suffix | the pre-2011 LFI folklore; killed by PHP 5.3.4 |
| 2 | Loose base64 decoding in `php://filter` | Stefan Esser, *Advisory 03/2009: Piwik Cookie unserialize() Vulnerability* (article ref [52]) |
| 3 | `zip://` to defeat a fixed `.php` requirement | CODEGATE 2015 "Owlur" (article ref [53]) |
| 4 | The RFC1867 temporary-file race with `phpinfo()` assistance | Brett Moore, *LFI With PHPInfo Assistance* (article ref [51]); Gynvael Coldwind's Windows variant is ref [50] |

Labs 11, 12 and 13 pick the story up from here (`session.upload_progress`,
filter chains, the filter-chain oracle). Lab 12 in particular defines its
threat model by switching this lab's toolkit **off** — `file_uploads = Off`,
read-only filesystem, no writable path anywhere. This lab is what it is
switching off.

## Difficulty / category

**Medium** (stages 1–3) rising to **hard** (stage 4) — web / local file
inclusion / PHP internals / race conditions.

## Run it

```sh
make up        # modern wing: http://127.0.0.1:8020/
               # legacy wing: http://127.0.0.1:9020/       (php 5.3.3)
               #              http://127.0.0.1:9020/v534/  (php 5.3.4)
make solve     # runs solve/solve.py inside a container
make verify    # build + run + exploit + assert flag + tear down
make down
```

> The solver must run **inside** the compose network (`make solve` does this).
> See "Honest limitations" below for why stage 4 cannot be won through a
> published port on this Docker host.

## Your goal

Each of the first three exhibits guards one fragment of the curator key. The
curator's desk (exhibit 4) wants all three, and behind it is `/flag.txt`,
mode `0400 root:root`. `/readflag` is setuid root and will print it — if you
can *run* something.

* Exhibit 1 renders a template: `include($_GET['page'] . '.php')`. The
  fragment is in a file with no `.php` extension, outside the document root.
* Exhibit 2 exports curator notes to disk. Notes may not contain a PHP open
  tag, and every export is prefixed with a guard line that exits immediately.
* Exhibit 3 accepts photographs. PNG only — the name is checked and so are the
  bytes. Its viewer is another `include($view . '.php')`.
* Exhibit 4 is a `phpinfo()` page plus a diagnostic loader that includes any
  path with no dot in it. `file_uploads` is on. Nothing you can write has a
  dotless name.

`allow_url_fopen` and `allow_url_include` are both `Off`.
`session.upload_progress` is `Off` (that is lab 11's trick, not this one).

## Hints

<details>
<summary>Hint 1 — exhibit 1</summary>

The suffix is concatenated in PHP, but the path is eventually handed to
`open(2)` as a C string. Two things used to end a C string early: a byte you
can send in a query parameter, and a length nobody bounds-checked. One of the
two still worked in 2010 — and the museum kept an interpreter from 2010 in
the legacy wing. Compare `/stage1.php` with `/v534/stage1.php`.
</details>

<details>
<summary>Hint 2 — exhibit 2</summary>

`php://filter` is not only a read filter. `file_put_contents()` takes a path
too, and the filter list applies to everything written through it. Now ask
what `convert.base64-decode` does with a byte that is not in its alphabet —
and what that does to a guard line nobody can remove.
</details>

<details>
<summary>Hint 3 — exhibit 3</summary>

`getimagesize()` reads the front of the file. Archive formats are read from
the back. A stream wrapper that is not a "URL" wrapper is unaffected by
`allow_url_include`, and one of them takes a fragment: `wrapper://file#entry`.
The application will helpfully append `.php` to whatever you give it — which
is exactly what the entry inside the archive should be called.
</details>

<details>
<summary>Hint 4 — exhibit 4</summary>

PHP writes every uploaded file to `/tmp/phpXXXXXX` and unlinks it when the
request ends. `phpinfo()` prints `$_FILES`, so it tells you the name. The
whole problem is that the request ends. Make the response enormous — every
request header you send is echoed back in `$_SERVER`, which `phpinfo()` prints
*after* `$_FILES` — and then stop reading it. A server that cannot finish
writing has not finished the request.
</details>

## What you will learn

* Exactly which upstream change killed NUL-byte path truncation (PHP 5.3.4,
  `strlen(filename) != filename_length`), demonstrated live against 5.3.3,
  5.3.4 and 8.2.33 of the same application.
* Why the "path longer than `PATH_MAX`" half of the folklore never worked on
  Linux in the first place, with the source to prove it.
* `php://filter/write=`: that stream filters apply to writes, and that
  `convert.base64-decode` silently eats every byte outside its alphabet — the
  same property labs 11 and 12 exploit in the read direction.
* How to build a PNG that is also a ZIP, why `cat a.png b.zip` is not good
  enough for modern libzip, and why `zip://` walks through
  `allow_url_include = Off`.
* How PHP's RFC1867 upload handling creates and destroys temporary files, and
  how to turn a microsecond race into a several-second window with nothing but
  a small `SO_RCVBUF` and 700 KiB of request headers.

## Honest limitations

* **Stage 1, over-long paths.** Only the NUL-byte half of the truncation
  folklore is reproduced. The "repeat `/.` past 4096 bytes" half **does not
  work on any Linux build we could obtain** — `virtual_file_ex()` has rejected
  `path_length >= MAXPATHLEN` since at least PHP 4.4.9. It is swept for at run
  time by `solve.py` and by the lab's own tests (lengths 40…9000, six payload
  shapes, PHP 5.3.3 and 5.3.4: no hits). The surviving references for that
  trick are Windows-centric; this lab makes no Windows claim. See WRITEUP.md.
* **Stage 4 through a published port.** The exploit holds the `phpinfo()`
  response open by refusing to read it, which only stalls PHP if TCP
  back-pressure reaches the server. Docker's userland proxy (`docker-proxy`,
  used for `127.0.0.1:8020`) drains the container socket into a 4 MiB host-side
  buffer, so PHP finishes the request before you ever see the temporary
  filename. Measured: 0/32 attempts through the published port, 30/30
  container-to-container. `make solve` and `make verify` run the solver inside
  the compose network, where it is deterministic.
* **The key fragments are a curriculum device, not a privilege boundary.**
  Stages 2, 3 and 4 all end in code execution as `www-data` on the modern
  wing, so once you have solved stage 2 you can read stage 3's fragment off
  the disk (and vice versa). Fragment 1 genuinely requires stage 1 — it exists
  only inside the legacy container — and the flag genuinely requires code
  execution, because `/flag.txt` is `0400 root:root`.
* **Two services, one application.** Exhibits 2–4 need a PHP that this 2010
  build was not compiled with, and the point of exhibits 2–4 is that they
  still work on a current interpreter. So the same `src/` tree is deployed
  twice: on `php:8.2.33-apache` (port 8020) and, cut down to exhibit 1, on
  PHP 5.3.3/5.3.4 compiled from `museum.php.net` (port 9020).
