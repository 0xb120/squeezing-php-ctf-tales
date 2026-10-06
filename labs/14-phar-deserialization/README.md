# 14 — PHAR deserialization: `file_exists()` is an `unserialize()`

An image gallery that only accepts real images, and one endpoint that does
nothing at all except check whether a file is there. That is enough for a
shell.

## Article reference

Phrack #72, *"The Art of PHP - My CTF Journey and Untold Stories!"* by Orange
Tsai — section **4.2, "PHAR Deserialization"**, subsection **"Level 0 - What
is PHAR?"**.

The technique first appeared in Orange Tsai's **"Baby^H Master PHP 2017"**
challenge at HITCON CTF 2017, and was independently found and pushed into the
real world by **Sam Thomas** (*"It's a PHP Unserialization Vulnerability Jim,
but Not as We Know It"*, Black Hat USA 2018).

## Difficulty / category

**medium** — web / PHP deserialization / file formats.

## Run it

```sh
make up           # http://127.0.0.1:8014/
make solve        # run the reference exploit in a container
make verify       # build -> exploit -> assert the flag -> tear down
make mitigations  # show which defences actually work (PHP 8, ini, wrappers)
make down
```

Three files, ~120 lines of PHP in total:

* `index.php` — the front page.
* `upload.php` — `POST` an image in the `image` field. Extension must be
  `.gif`/`.jpg`/`.jpeg`, the magic bytes must match, and `getimagesize()` has
  to agree with both. Accepted files are stored as
  `uploads/<sha1 of the content>.<ext>`.
* `check.php` — `GET /check.php?file=<path>`; runs `file_exists()` on your
  input and prints **nothing**.
* `lib/gallery.php` — the gallery's model classes. Read it.

## Your goal

Read `/flag.txt`. It is only readable by the web server user and there is no
endpoint that prints file contents, so you need code execution.

`check.php` never echoes anything and never includes anything — but on this
PHP version, *touching* a file can be a lot more than touching a file.

## Hints

<details><summary>Hint 1 — what does "touching a file" mean?</summary>

`file_exists()` goes through PHP's stream layer, which means the path you pass
can select a *wrapper*: `file://`, `http://`, `data://`, `php://`… and
`phar://`. Ask yourself what a wrapper has to do before it can answer
"does `phar://x.gif/inside.txt` exist?" — it has to parse the archive.

Now go and read what a PHAR archive stores in its header, and check the PHP
version printed on the front page.

</details>

<details><summary>Hint 2 — you need to plant the archive</summary>

The upload endpoint is not a formality: extension, magic bytes and
`getimagesize()` all have to pass. But a PHAR does not need to *start* with
its stub — PHP finds the archive by searching the file for the
`__HALT_COMPILER();` token, so anything at all may come before it.

A 13-byte GIF header is enough for `getimagesize()`.

</details>

<details><summary>Hint 3 — what to put in the payload</summary>

The field that gets deserialized is the archive's *metadata*, so you need a
POP chain among the classes that are loaded by `check.php`. Look at
`lib/gallery.php`: which magic methods run without anyone calling them, and
what do they do with their properties?

The `data/` directory is writable by the web server and is served by Apache.

</details>

## What you will learn

* Why `phar://` turns **every** file-system function (`file_exists`,
  `filesize`, `is_dir`, `md5_file`, `getimagesize`, `copy`, …) into an
  `unserialize()` entry point on PHP ≤ 7.4.
* The PHAR file format byte by byte — stub, manifest, per-file entries,
  contents, signature, `GBMB` — implemented from scratch in Python (see
  `solve/solve.py` and the writeup's diagram).
* Why polyglots work here: PHP locates the manifest by scanning for
  `__HALT_COMPILER();`, so image validation and archive parsing can both
  succeed on the same bytes.
* Writing a `__destruct` → `__toString` POP chain from application classes
  that were never meant to be reachable.
* Which mitigations actually mitigate: PHP 8.0's removal of automatic metadata
  deserialization (RFC), `stream_wrapper_unregister('phar')`, and why
  `phar.readonly=1` is **not** a defence (run `make mitigations`).
