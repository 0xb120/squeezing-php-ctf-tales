# 17 — From CTF to Real World (php-fpm buffer underflow)

One newline in a URL, one NUL byte written one byte too early, and php-fpm starts
taking `php.ini` directives from you.

## Article reference

Phrack #72, *"The Art of PHP - My CTF Journey and Untold Stories!"* by Orange Tsai,
section **5.2 - From CTF to Real World!**.

The bug is **CVE-2019-11043**. The anomaly was first noticed by **@d90pwn** while
playing an unrelated frontend challenge at **Real World CTF 2019**; the root cause
and the exploitation technique are **Emil "neex" Lerner**'s, with the final
`php.ini` chain found by **@beched**. Orange Tsai's analysis of the bug is the
canonical writeup.

## Difficulty / category

**hard** — web / memory corruption / data-only exploitation. No shellcode, no ROP,
no information leak: the entire exploit is one NUL byte and a lot of arithmetic.

## Run it

```sh
make up        # http://127.0.0.1:8017/index.php
make solve     # run the exploit in a container
make verify    # build + up + solve + assert the flag + tear down
make down
```

Stack: `nginx:1.31.5-alpine` in front of `php:7.2.23-fpm` over FastCGI.
PHP 7.2.23 is the last 7.2 release before the fix landed in 7.2.24.

## Your goal

`/flag.txt` lives in the php-fpm container, readable only by the pool user. The
application (`/var/www/html/index.php`) is three lines of `htmlspecialchars`: no
include, no file read, no eval, no upload, nothing to inject into. There is no bug
in the PHP code and there never will be.

Look one layer down instead. Start by asking what the server does with a URL that
contains a newline, and pay attention to *lengths*: the same request with a
slightly longer query string does not behave the same way.

## Hints

<details>
<summary>Hint 1</summary>

nginx is configured with

```nginx
fastcgi_split_path_info ^(.+?\.php)(/.*)$;
fastcgi_param PATH_INFO $fastcgi_path_info;
```

and no `try_files`. PCRE's `.` does not match a newline and `$` is an anchor. What
value does `$fastcgi_path_info` have for `/index.php/foo%0Abar`, and what does
php-fpm do with a `PATH_INFO` it never expected to be empty?

</details>

<details>
<summary>Hint 2</summary>

`sapi/fpm/fpm/fpm_main.c`, `init_request_info()`:

```c
path_info = env_path_info ? env_path_info + pilen - slen : NULL;
...
old = path_info[0];
path_info[0] = 0;
```

With `pilen == 0` that pointer goes *backwards* out of its buffer, and then one
byte is zeroed. Where does it land? php-fpm stores all FastCGI variables in a
bump allocator (`main/fastcgi.c`, `fcgi_data_seg`) whose first field is the write
cursor `pos`. Zero the low byte of `pos` and the next variable stored overwrites
something already there.

</details>

<details>
<summary>Hint 3</summary>

You cannot choose *where* the byte lands directly — you choose it by controlling
the total size of the FastCGI environment. Two convenient knobs: the length of the
query string, and the length of a junk request header. Sweep the first one and
watch for a response that differs from the others (a 502 is a worker that died).

Once a later write lands on top of `PHP_VALUE`, every request can carry one
`php.ini` directive, and directives set that way stick inside that worker. Nine of
them turn an error message into a web shell. neex's tool does exactly this — read
it, then write your own.

</details>

## What you will learn

* How an nginx regexp and a PCRE newline rule combine into an empty `PATH_INFO`.
* Reading a real buffer underflow: pointer arithmetic with unsigned/`int` lengths
  that nobody ever expected to be zero.
* Data-only exploitation: turning a single NUL-byte write into RCE with no leak,
  no write-what-where, and no code pointers.
* How php-fpm's `PHP_VALUE` FastCGI variable is applied, and why a poisoned
  directive persists in a worker across requests.
* Why the exploit is probabilistic, and how brute-forcing two length parameters
  (`qsl`, `pisos`) replaces "know the heap layout".
* The remediation that costs one line of nginx configuration.

> **Note on faithfulness**
>
> Nothing is emulated in this lab. nginx and php-fpm are stock upstream images, the
> configuration is the one from the original advisory, and the memory corruption
> that gets you the flag is the real CVE-2019-11043 happening inside a real
> `php-fpm` worker. The only concession to lab ergonomics is a fixed pool of two
> workers (`pm = static`, `pm.max_children = 2`), which shortens the "infect a
> worker" loop; the exploit works the same way against a bigger pool, it just takes
> more rounds. See `challenge/fpm/zzz-lab.conf`.
