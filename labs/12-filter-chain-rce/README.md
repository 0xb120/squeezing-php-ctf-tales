# 12 — Filter Chain RCE

`include($_GET['page'])` on a read-only filesystem with uploads disabled.
There is nothing to poison, nothing to plant, nothing to write. Get a shell.

## Article reference

Phrack #72, "The Art of PHP - My CTF Journey and Untold Stories!" by Orange
Tsai — section **4.1 "Twenty Years of Evolving LFI to RCE", Level 1 "The End
of LFI"**.

Based on **hxp CTF 2021 — "includer's revenge"** (Bruno "0xbb" Bierbaumer) and
on the solution @loknop published for it, which itself grew out of an
unintended `php://filter` solution @gynvael found at Insomni'hack 2018.

## Difficulty / category

**Hard** — web / local file inclusion / stream filters.

## Run it

```sh
make up        # http://127.0.0.1:8012/
make solve     # runs solve/solve.py inside a container
make verify    # build + run + exploit + assert flag + tear down
make down
```

## Your goal

"Paperclip" renders its pages by `include()`ing whatever path you pass in
`?page=`. Yes, really. But:

* the container filesystem is mounted **read-only** (`/tmp` is a root-owned
  tmpfs the web user cannot write to);
* `file_uploads = Off`, so there are no `/tmp/phpXXXXXX` temporaries;
* `session.upload_progress.enabled = Off`, so lab 11's trick is dead;
* `allow_url_fopen = Off` and `allow_url_include = Off`, so no RFI, no
  `data://`;
* Apache's `access.log`/`error.log` are symlinks to the container's stdout and
  stderr, so there is no log file to poison;
* `/flag.txt` is mode `0400 root:root` — `?page=/flag.txt` gets you nothing.
  `/readflag` is setuid root and will print it, but only if you can *run* it.

`/usr/local/lib/php/pearcmd.php` *is* on the box (every official `php:*` image
ships it) and `register_argc_argv` is `On`, so the classic
`?page=/usr/local/lib/php/pearcmd.php&+config-create+...` chain really does
reach PEAR — and then dies on `Could not create "..."`, because there is no
writable directory anywhere. Saying so here saves you the half hour; the
writeup explains it.

Every technique that needs an attacker-controlled file on disk is off the
table. Execute code anyway.

## Hints

<details>
<summary>Hint 1</summary>

`php://` is not a "URL wrapper" as far as `allow_url_include` is concerned, so
`php://filter` still works. Filters do not only *read* data, they *transform*
it — and a chain of them is applied left to right. What if the file you point
at is irrelevant and the chain itself produces the bytes?
</details>

<details>
<summary>Hint 2</summary>

Two filters matter. `convert.base64-decode` silently skips every byte that is
not in the base64 alphabet. And converting *to* certain iconv charsets emits a
fixed escape sequence first — `convert.iconv.UTF8.CSISO2022KR` puts `\x1b$)C`
in front of everything, of which only `C` is a base64 character. Put those two
together on a stream that is already base64 text.
</details>

<details>
<summary>Hint 3</summary>

One pass gets you one chosen character at the *front* of the text. Re-encode
with `convert.base64-encode` so the stream is base64 text again, kill the `=`
padding that re-encoding adds (UTF-7 escapes `=` into something harmless), and
repeat. Walk the base64 of your payload backwards and you build it forwards.
Finish with one last `convert.base64-decode`.
</details>

## What you will learn

* Why `php://filter` survives `allow_url_fopen`, `allow_url_include` and a
  read-only filesystem.
* The exact tolerance of `convert.base64-decode` and how it becomes a
  primitive rather than a bug.
* How stateful iconv conversions leak charset-designator bytes into the
  stream, and how to mangle those bytes into an arbitrary base64 alphabet.
* How to write a filter chain generator from scratch.
* Why PHP finally decided (RFC "Limit maximum number of filter chains",
  implemented in PHP 8.6) that 16 filters ought to be enough for anybody.
