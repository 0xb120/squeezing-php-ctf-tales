# 13 — The End of AFR: an error-based filter-chain oracle

The entire application is one line of PHP, it prints nothing, and you still
have to read a file off the box.

## Article reference

Phrack #72, *"The Art of PHP - My CTF Journey and Untold Stories!"* by Orange
Tsai — section **4.1, "Level 2 - The End of AFR"**.

The original challenge is **`minimal-php`** by **@hashkitten**, DownUnderCTF
2022. Nobody solved it during the competition. The technique was later turned
into general-purpose tooling by **Rémi "Remsio" Matasse** (Synacktiv) and
**Charles "cfreal" Fol** (Ambionics). This lab recreates the challenge
verbatim and asks you to rebuild the oracle.

## Difficulty / category

**insane** — web / PHP stream filters / side channels.

## Run it

```sh
make up        # http://127.0.0.1:8013/
make solve     # run the reference exploit in a container
make verify    # build -> exploit -> assert the flag -> tear down
make down
```

The service is:

```php
<?php file($_POST[0]);
```

`POST /` with a single parameter named `0`, whose value is the *path or stream
URL* handed to `file()`. There is no output, ever. The response body is always
empty.

> One quirk worth knowing before you start: a request that does **not** carry
> the `0` parameter makes `file()` throw a `ValueError` on PHP 8, which is also
> a 500. Always send the parameter.

## Your goal

Read `/flag.txt` inside the container. You cannot see file contents, you cannot
see error messages (`display_errors` is off) and `file()` returns its result
into the void. What you *can* see is the HTTP status code: **200 when the
script finishes, 500 when PHP aborts**. Turn that single bit into an arbitrary
file read.

`memory_limit` is 128M — the same value the article quotes — and it is not an
accident.

## Hints

<details><summary>Hint 1 — what can a filter chain do for you?</summary>

`php://filter/<f1>|<f2>|.../resource=<path>` applies filters left to right
while the file is being read. Some filters *shrink* the stream, some *grow*
it. If you can make the stream grow without bound, PHP dies. If you can make
growth *conditional* on the content, the crash itself is your output channel.

Start by finding a filter that quadruples the length of whatever goes through
it, and check how many times you have to repeat it to break 128M.

</details>

<details><summary>Hint 2 — the conditional part</summary>

`dechunk` is a HTTP chunked-transfer decoder. Feed it something that is not
chunked-encoded and watch what it does with the first line. Try it on
`/etc/passwd` versus `/etc/hostname` (the container hostname is a hex string)
with `php -r` locally:

```sh
php -r 'var_dump(file_get_contents("php://filter/dechunk/resource=/etc/passwd"));'
php -r 'var_dump(file_get_contents("php://filter/dechunk/resource=/etc/hostname"));'
```

Now you have "is the first byte of this stream a hex digit?" as a yes/no
question. One bit. What is missing is (a) reaching bytes that are not the
first one and (b) asking about more than 22 of the 256 possible values.

</details>

<details><summary>Hint 3 — moving bytes around</summary>

`convert.base64-encode` turns the file into a 64-symbol alphabet, which is a
much friendlier thing to classify. Endianness conversions permute characters
inside fixed-size groups (`convert.iconv.UCS-4LE.10646-1:1993` reverses every
4 characters, `convert.iconv.CSUNICODE.UCS-2BE` swaps every pair), and some
iconv conversions *prepend* bytes to the stream — which shifts the grouping.
Combine them and you can walk the whole string, two characters at a time.

For the classification itself: EBCDIC code pages move ASCII letters around
wildly. `iconv -l` lists about a thousand of them. Brute force pairs offline
until you own a set of tests that separates all 64 symbols.

</details>

## What you will learn

* How `php://filter` chains are actually evaluated, and that filters compose
  as stream transformations rather than as string functions.
* Turning PHP's `memory_limit` into a boolean side channel (`4^n` amplification
  with `convert.iconv.L1.UCS-4LE`).
* The exact semantics of the `dechunk` stream filter and why it works as a
  content-dependent "erase".
* Building a positional gadget out of endianness conversions plus a
  BOM-prepending conversion, so that arbitrary offsets can be rotated to
  offset 0.
* Deriving a character-classification decision tree by brute forcing iconv
  code-page pairs — and why the ten ASCII digits need a different trick from
  the letters.
* That "no output" is not the same as "not exploitable".
