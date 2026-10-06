# 15 — QuoteBuilder (mPDF PHAR kill chain)

Paste HTML, get a PDF back. Nothing is ever written to disk that you control… is it?

## Article reference

Phrack #72, *"The Art of PHP - My CTF Journey and Untold Stories!"* by Orange Tsai —
section **4.2 "PHAR Deserialization"**, the **"Level Max - Laravel (w/ mPDF) Kill Chain"**
finale.

The technique is built from two real mPDF issues:

* [mpdf/mpdf#949](https://github.com/mpdf/mpdf/issues/949) — Anton (**@ByQwert**), 2019:
  `phar://` in an `<img src>` turns mPDF's HTML→PDF conversion into `unserialize()`.
  Patched in mPDF 7.1.8 with a stream-wrapper blacklist.
* [mpdf/mpdf#1381](https://github.com/mpdf/mpdf/issues/1381) — **@Cyku**: the blacklist is
  only applied to one of the two paths mPDF opens, *and* mPDF writes CSS `data:` URIs to
  a cache file with a weakly random name — which is enough for a full RCE chain.

The object chain at the end is the real Laravel one, the same gadget
[PHPGGC](https://github.com/ambionics/phpggc) ships as `Laravel/RCE6`.

> **Version notice** — this lab deliberately runs on `php:7.4-apache` (PHP **7.4.33**).
> PHP 8.0 implemented the RFC *"Don't automatically unserialize Phar metadata"*, so from
> PHP 8 on, opening a `phar://` path no longer deserializes anything and this entire
> technique is dead. Nothing in this lab is emulated or shimmed: the mPDF code, the
> Laravel gadget classes and the PHP behaviour are all the genuine article, pinned to the
> versions listed at the bottom of this file.

## Difficulty & category

**Difficulty: insane** · *deserialization / PHAR / gadget chains / file smuggling*

## Run it

```sh
make up        # build + start, then browse http://127.0.0.1:8015/
make solve     # run the reference exploit in a container
make verify    # build -> up -> exploit -> assert flag -> tear down
make down      # stop and clean up
```

## Your goal

`QuoteBuilder` takes a blob of HTML and renders it to PDF server-side. The developer
blacklisted the obvious things (`<?`, `<script`, `phar://`, `php://`, …) and told himself
that was enough, because "it only draws a document".

Read `/flag.txt`. The file belongs to `root` and is mode `0400`, so the web user cannot
read it no matter which file it is tricked into opening — you will need to run a command.

## Hints

<details>
<summary>Hint 1</summary>

PHP ≤ 7.4 deserializes a PHAR archive's *metadata* field whenever **any** file operation
touches a `phar://` path — `fopen`, `file_exists`, `getimagesize`, `file_get_contents`.
A PDF renderer does a lot of file operations on things the document points at.

So: (a) how do you make the renderer open a `phar://` path, and (b) how does a PHAR file
get onto a server that has no upload form?

</details>

<details>
<summary>Hint 2</summary>

(a) The blacklist in front of the renderer is a plain substring match on the HTML you
submit. mPDF percent-decodes one of the two attributes it uses to locate an image before
it opens it, and its own `phar://` filter only inspects the *other* one. Diff mPDF
`8.0.10`'s `src/Image/ImageProcessor.php::getImage()` against `8.0.16`'s and the missing
check is obvious. `src/Tag/Img.php` tells you which attribute that is.

(b) mPDF does not keep CSS `data:` URIs in memory. Look at what
`src/CssManager.php::ReadCSS()` does with `url(data:image/...;base64,...)`, and where the
result ends up — the landing page's Diagnostics block already tells you the directory.

</details>

<details>
<summary>Hint 3</summary>

The cache filename contains a number that mPDF picks per data URI. The number is
cryptographically random but the *range* is tiny, and the cache files are not deleted
when the request ends. One HTML document can contain a `<style>` block **and** a few
thousand `<img>` tags, and nothing stops you from submitting more than one document.

Watch out: mPDF keeps a `$failedImages` map keyed by the `src` attribute, so every probe
tag needs a **different** `src` or only the first one is ever attempted.

Once you have code execution: the flag is not readable by `www-data`. Look around `/` for
something that is.

</details>

## What you will learn

* Why `phar://` turned every PHP file operation into a deserialization sink, and why
  PHP 8.0 had to kill automatic metadata unserialization.
* How to build a PHAR archive **by hand** — stub, manifest, file entries, signature and
  the `GBMB` trailer — without `phar.readonly=0` and without PHP at all.
* File smuggling: getting attacker-controlled *bytes* onto a target's filesystem through
  a feature that was never meant to be an upload (a CSS `data:` URI cache).
* Why "random but small" temp filenames are not a security control, and how an attacker
  collapses a 1-in-10000 guess into a handful of requests.
* Reading a patch to find what it missed: mPDF 7.1.8 filtered `$file` but not
  `$orig_srcpath`, so the fix survived only until someone looked at the second argument.
* Blacklist bypass by normalisation order — the application matches on the raw string,
  the library `rawurldecode()`s it afterwards.
* Real framework POP chains: `Illuminate\Broadcasting\PendingBroadcast::__destruct()` →
  `Illuminate\Bus\Dispatcher::dispatchToQueue()` → `call_user_func()`.

## Notes on what is real and what is not

Everything in the exploitation path is real, unmodified upstream code:

| Stage | Status |
| --- | --- |
| `mpdf/mpdf` **8.0.10** — `ORIG_SRC` reaches `fopen()` unchecked | real, unpatched upstream code (fixed in 8.0.16) |
| `mpdf/mpdf` **8.0.10** — CSS `data:` URI cached as `_tempCSSidata<random_int(1,10000)>_<i>.<ext>` | real, unpatched upstream code |
| `rawurldecode()` of `ORIG_SRC` defeating the app's substring blacklist | real mPDF behaviour (`ImageProcessor::urldecodeParts()`) |
| PHAR metadata auto-unserialization | real PHP **7.4.33** behaviour |
| `illuminate/broadcasting` + `illuminate/bus` **8.83.27** POP chain | real Laravel code, the PHPGGC `Laravel/RCE6` gadget |
| `QuoteBuilder` itself (the ~60-line app) | written for this lab |

The only deliberate concession: the landing page prints a Diagnostics block with mPDF's
cache directory. Guessing an installation path is not the lesson, so the lab hands it to
you. The `ext-gd` extension is **not** compiled into the image; mPDF declares it as a
requirement but no code path used here touches it (see the note in `challenge/Dockerfile`).
