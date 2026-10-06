# 16 — Hack the Scoreboard (php-cgi argument injection)

A scoreboard served by CGI. The query string is not data — it is a command line.

## Article reference

Phrack #72, *"The Art of PHP - My CTF Journey and Untold Stories!"* by Orange Tsai,
section **5.1 - Hack the Scoreboard!**.

The lab recreates two bugs, twelve years apart, that share one root cause:

* **CVE-2012-1823** — found by the **Eindbazen** team on the scoreboard of Nullcon
  HackIM CTF. `?-s` dumps source, `?-d ...` gets you code execution.
* **CVE-2024-4577** — **Orange Tsai** and **splitline (Splitline NG)**, the
  *WorstFit* research: the 2012 patch is bypassed on Windows because the ANSI
  "Best Fit" conversion happens **after** PHP has inspected the raw bytes.

## Difficulty / category

**medium** — web / CGI / argument injection. No memory corruption, no race.

## Run it

```sh
make up        # classic  http://127.0.0.1:8016/
               # worstfit http://127.0.0.1:9016/
make solve     # run the exploit in a container
make verify    # build + up + solve + assert the flag + tear down
make down
```

Both ports serve the same scoreboard, from the same image, with the same real
`php-cgi` binary (Debian bookworm, PHP 8.2.x — current and fully patched).
Only the **web server in front of it** differs.

## Your goal

The round flag is in `/flag.txt` inside the container. It is outside the document
root, it is not readable over HTTP, and the application never touches it: there is
no file-read bug in the PHP. What you *can* influence is how the web server starts
`php-cgi` — and a process that starts with attacker-chosen arguments is a process
that runs attacker-chosen code.

Port 8016 is the 2012 scenario. Port 9016 is the same server pretending to be a
Windows box, and the payload that works there will not work on 8016 (and vice
versa). Get the flag from **both**.

## Hints

<details>
<summary>Hint 1</summary>

The CGI specification (RFC 3875, §4.4) says that a query string with no unencoded
`=` is not a set of key/value pairs at all: it is a *command line*, to be split on
`+` and handed to the program as arguments. `php-cgi` is a program with a rich set
of command-line options — `php-cgi -h` lists them. Two of them are worth your time.

</details>

<details>
<summary>Hint 2</summary>

Try `?-s` first. It does nothing, and the reason is a five-line guard added to
`sapi/cgi/cgi_main.c` in 2012. Read it carefully — in particular, read the
*condition* under which it runs at all, not just what it does:

```c
if ((query_string = getenv("QUERY_STRING")) != NULL && strchr(query_string, '=') == NULL) {
```

On 8016 the front end is not as picky as the guard assumes. On 9016 the front end
is picky — but a hyphen is not the only way to spell a hyphen.

</details>

<details>
<summary>Hint 3</summary>

`-d` sets an ini directive, and two of them turn any PHP process into a shell:

```
-d allow_url_include=1 -d auto_prepend_file=php://input
```

`php://input` is your POST body. On 9016, remember that `=` must not appear
unencoded in the query string, and that `0xAD` is a *soft* hyphen.

</details>

## What you will learn

* Why the CGI argv convention is an argument-injection primitive by design.
* What the CVE-2012-1823 patch actually checks, and the exact shape of a query
  string that walks straight past it.
* `-s` (source disclosure) and `-d auto_prepend_file` (code execution) as a
  two-step escalation, the way the Eindbazen team demonstrated it.
* How Windows "Best Fit" ANSI conversion resurrects a 12-year-old patched bug
  (CVE-2024-4577) — and why the upstream answer was eventually "on Windows, do
  not parse arguments at all".
* Reading a real upstream patch and reasoning about *when it is armed*, not just
  what it blocks.

> **Emulation notice**
>
> The PHP is real: both ports run an unmodified Debian `php-cgi` 8.2.x that
> contains the CVE-2012-1823 guard *and* the CVE-2024-4577 hardening. Every option
> parse, every `skip_getopt` decision and every ini change you trigger is done by
> that binary. What is **modelled** is the operating system around it:
>
> * **Port 9016 (`worstfit`)** — Windows converts a UTF-16 command line to the
>   process ANSI code page and substitutes look-alike characters for the ones it
>   cannot represent (`U+00AD` → `-`, `U+221E` → `8`, ...). That conversion is a
>   Windows kernel/CRT behaviour and cannot happen on Linux, so the front end
>   applies a small Best Fit table to the child's `argv` itself. Crucially it does
>   this **only to argv**: `QUERY_STRING` is handed to `php-cgi` exactly as it
>   arrived on the wire, which is the whole point of the bug — PHP's guard
>   inspects the raw bytes, the conversion happens afterwards. The 2024 patch that
>   would stop this lives inside `#ifdef PHP_WIN32` and is therefore compiled out
>   of any Linux build, including this one.
> * **Port 8016 (`classic`)** — the front end deliberately ignores the "only when
>   there is no unencoded `=`" clause of RFC 3875 and builds `argv` from every
>   query string. That permissiveness is the modelled part; it stands in for the
>   pre-2012 world in which the query string reached `argv` unconditionally.
>   php-cgi's guard is untouched, and you can watch it refuse `?-s`.
>
> Neither port pretends a shim is PHP. If you want to see where the boundary is,
> read `challenge/gateway/cgi_gateway.py` — it is about 200 lines.
