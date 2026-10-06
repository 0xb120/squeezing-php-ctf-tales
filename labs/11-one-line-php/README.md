# 11 — One Line PHP

One line of PHP, one `include()`, and a filesystem you are not supposed to be
able to write to. Prove otherwise.

## Article reference

Phrack #72, "The Art of PHP - My CTF Journey and Untold Stories!" by Orange
Tsai — section **4.1 "Twenty Years of Evolving LFI to RCE", Level 0 "The LFI
Arms Race"**.

The challenge is a faithful recreation of **HITCON CTF 2018 — "One Line PHP
Challenge"** by Orange Tsai (3 solves out of 1816 teams). Its seed is
**PHP bug #72681**, "PHP Session Data Injection Vulnerability", reported by
Taoguang "Ryat" Chen — specifically the note in that report about the
`session.upload_progress` feature.

## Difficulty / category

**Hard** — web / local file inclusion / PHP internals.

## Run it

```sh
make up        # http://127.0.0.1:8011/
make solve     # runs solve/solve.py inside a container
make verify    # build + run + exploit + assert flag + tear down
make down
```

## Your goal

The whole application is the single line of PHP the page shows you. It will
`include()` any path you hand it — but only if the first line of that path's
content starts with the six bytes `@<?php`. Nothing on the box starts with
those bytes, the upload directory is not web-reachable, remote includes are
disabled, and the session directory is mode `1733` so you cannot even list
it. Read `/flag.txt` anyway.

> **There is more than one way in.** The intended solution is the 2018 one:
> make PHP write a file for you, then include it. A second, much shorter path
> also works on this box — a `php://filter` chain that synthesises the `@<?php`
> magic bytes out of nothing, so the check and the `include()` both read
> invented data and no file is ever written. It is a real, historically
> important solve (it is what happened to this challenge after 2021), and
> `WRITEUP.md` documents it in full under "Going further". It is *not* the
> point of this lab: `labs/12-filter-chain-rce` teaches filter chains properly,
> and this lab teaches `session.upload_progress`. Do the intended route first —
> the contrast between the two is the actual lesson.

## The box's configuration

The original challenge published its `php.ini`, so this one does too. This is
exactly what `challenge/Dockerfile` writes to
`/usr/local/etc/php/conf.d/zz-challenge.ini` on top of `php:7.2.34-apache`:

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

Every one of those is PHP 7.2's own default — compiled-in, and identical to
`php.ini-production` — except two: `session.save_path` is the Debian/Ubuntu
package default (and that directory really is `1733 root:root` on Debian, which
is why you cannot list it), and `expose_php = Off`, which is cosmetic. So
nothing here is a lab-flavoured weakening; a stock Debian PHP 7.2 box in 2018
looked exactly like this.

## Hints

<details>
<summary>Hint 1</summary>

`session_start()` is never called, so there can be no session file — right?
Check what PHP does with a `multipart/form-data` request body that happens to
contain a field named `PHP_SESSION_UPLOAD_PROGRESS`, and remember that *you*
pick the `PHPSESSID` cookie, so *you* pick the path of the file it writes.
</details>

<details>
<summary>Hint 2</summary>

Two problems remain. First, `session.upload_progress.cleanup` is `On`, so the
record is deleted as soon as the upload *finishes* — so do not let it finish.
Second, PHP puts `session.upload_progress.prefix` in front of your data, and
`@<?php` has to be at offset 0. No stream filter can delete bytes from the
front of a stream, but one of them is very relaxed about what it *skips*.
</details>

<details>
<summary>Hint 3</summary>

`convert.base64-decode` ignores every byte outside the base64 alphabet and
eats the rest four characters at a time. Stack several of them and work out,
on paper, exactly how many characters of the fixed prefix survive each pass
and where the group boundaries land. Padding characters of your own choosing
are allowed. Watch out for what a stray `=` does to a filter chain.
</details>

## What you will learn

* How `session.upload_progress` turns *any* PHP endpoint into an
  attacker-controlled file write, with no `session_start()` anywhere.
* How the PHP `php` session serializer lays out a session file on disk, and
  why the `upload_progress_` prefix is the real difficulty of the challenge.
* The exact skipping/grouping behaviour of `convert.base64-decode`, and how to
  do the alignment arithmetic for a stack of them.
* Why `=` is fatal inside a filter chain, how stream filters are applied per
  8 KiB bucket, and how to use that to make a probabilistic exploit
  deterministic.
* How to convert a race condition into a plain, reliable window by simply not
  finishing an HTTP request.
