# 05 — Serialize, Then Replace

A string filter that runs *after* `serialize()` is not a filter. It is a
length-field editor.

## Article reference

Recreates section **2.1 "The Serialize-Then-Replace Pattern"** of
*"The Art of PHP - My CTF Journey and Untold Stories!"* by **Orange Tsai**
(Phrack #72), chapter 2 *"One unserialize() to Rule Them All"*.

Based on:

* **0CTF 2016 Quals — `piapiapia`** (reference [25] of the article),
  <https://ctftime.org/task/2130>
* **"Rusty Joomla Remote Code Execution"** by **Alessandro "kiks" Groppo**
  (reference [26]), Joomla 3.0.0–3.4.6 pre-auth object injection,
  <https://www.hacktivesecurity.com/blog/2019/10/03/rusty-joomla-rce/>

## Difficulty / category

**medium** — web / PHP object injection / deserialization.

## Run it

```sh
make up          # http://127.0.0.1:8005/
make solve       # run the reference exploit
make verify      # build + run + exploit + assert + tear down
make down
make logs        # PHP warnings go to the container log, not to the page
```

## Your goal

**PhotoVault** is a three-page profile service. You sign up, you pick a
nickname, you write a bio. Nothing you submit is ever sent back to you as
markup, there is no upload, no `include`, no SQL. The profile is stored
server-side and read back on every page view — you never get to touch the
stored record directly.

Somewhere between "the user typed this" and "the bytes hit the disk", the
application does one extra thing to be safe. That extra thing is the whole
challenge.

Read `/flag.txt`. It is owned by `root:www-data`, mode `0640` — so you need to
be the web server, not just read a file the web server happens to serve.

## Hints

<details>
<summary>Hint 1</summary>

You cannot reach `unserialize()` with bytes of your own choosing… directly.
But you *can* influence the bytes that PHP hands to it. Have a look at what
`save_profile()` does between `serialize()` and `file_put_contents()`, and
remember what a PHP serialized string actually looks like:

```
s:5:"hello";
  ^ the length is written once, in advance
```
</details>

<details>
<summary>Hint 2</summary>

The filter makes the blob *shorter*, but the `s:<n>:` prefix that PHP already
wrote stays the same. So the parser will read `n` bytes for that value and
happily walk past its real end, chewing through the serialized framing of the
properties that follow.

Properties are serialized in **declaration order**: `nickname`, `username`,
`bio`. Which one should carry the padding, and which one should carry the
payload?
</details>

<details>
<summary>Hint 3</summary>

Count. The number of bytes you have to swallow is exactly the distance from
the end of your real nickname to the first byte of your bio value:

```
";s:8:"username";s:<len>:"<username>";s:3:"bio";s:<len>:"
```

That distance must be an exact multiple of the number of bytes the filter
removes per occurrence — pick a username length that makes it line up.

Two classes in `lib.php` are there for the thumbnail cache. One has a
`__destruct()`, the other a `__toString()`. `file_get_contents()` accepts
stream wrappers.
</details>

## What you will learn

* Why PHP's serialization format is *length-prefixed*, and why any byte-level
  transformation applied to a serialized blob is an object-injection primitive.
* How to make an over-long `s:<n>:` length prefix swallow the serialized
  framing that follows it, so an attacker-controlled string value is re-parsed
  as object structure.
* How to compute the padding arithmetic instead of brute-forcing it.
* Building a two-gadget POP chain: `__destruct()` → `__toString()`, with the
  `data://` stream wrapper as the payload source.
* Why Joomla's `str_replace(chr(0).'*'.chr(0), '\0\0\0', $data)` session
  round-trip and 0CTF's `preg_replace('/where/', 'hacker', $blob)` are the
  same bug in opposite directions.
