# 01 — Corrupting Upload File Indices

PixelDrop accepts artwork. It checks the extension, it checks the size, it even
checks `is_uploaded_file()`. So why is it reading files you never uploaded?

## Article reference

Recreates the "Corrupting Upload File Indices" trick mentioned in the opening
of chapter 1 of *The Art of PHP - My CTF Journey and Untold Stories!*
(Orange Tsai, Phrack #72), reference **[15]**:

> Adam Iwaniuk, *"Overriding $_FILES array during uploading multiple files in
> php"* (March 2011) — the paper that first described how PHP's
> `main/rfc1867.c` builds the `$_FILES` index names, and how a single upload
> field can forge structures that should need several.

There is no CVE: PHP quietly hardened the parser in **5.3.11** and the class of
bug has been dead in every release since.

## Difficulty and category

**Difficulty:** medium
**Category:** web / PHP internals / file upload

## Run it

```sh
make up       # builds the image, then serves http://127.0.0.1:8001/
make solve    # runs the exploit from a container
make verify   # build -> up -> exploit -> assert the flag -> tear down
make down     # stop and remove everything
```

> The first `make up` compiles PHP 5.3.10 from source inside the build stage
> (roughly 2-4 minutes on a warm machine). There is no official `php:*` image
> older than 5.3.29, and 5.3.29 already carries the fix, so the interpreter has
> to be built. Everything else is stock Debian + Apache. Nothing is shimmed or
> emulated: the parser you are attacking is the real `main/rfc1867.c` from the
> 5.3.10 tarball, pinned by SHA-256.

## Your goal

PixelDrop stores what you drop into a public gallery. The flag is on the
container filesystem at `/flag.txt`, far outside the web root, and nothing in
the application ever opens it. Get PixelDrop to put it in the gallery for you.

The only input you control is a `multipart/form-data` request body — the field
names, the `filename=` values, the per-part headers and the bytes. That is more
control than it looks like.

## Hints

<details>
<summary>Hint 1</summary>

Read the intake code carefully. PixelDrop has two intake paths and only picks
one of them based on what `$_FILES['file']['tmp_name']` *is*, not on what the
request claimed to be. What decides that?

</details>

<details>
<summary>Hint 2</summary>

PHP decides whether an upload field is "an array field" by looking at the *last
character* of the field name, but it builds the `$_FILES` key strings with two
different `snprintf()` formats depending on that decision. Try a field name
where those two views disagree — for example one that contains brackets but
does not end with `]`.

`var_dump($_FILES)` on a throwaway PHP 5.3.10 script is your friend here.

</details>

<details>
<summary>Hint 3</summary>

Once you can decide where the property name (`name`, `type`, `tmp_name`,
`error`, `size`) lands inside the structure, ask which of the five values PHP
writes are attacker-controlled *strings*. `filename=` is pushed through
`basename()`. The part's `Content-Type` header is not.

</details>

## What you will learn

- How `main/rfc1867.c` turns `multipart/form-data` field names into `$_FILES`
  keys, and why array upload fields take a completely different code path.
- How an inconsistency between "is this an array field?" and "where do I splice
  the property name in?" lets one request forge arbitrary `$_FILES` shapes.
- Which `$_FILES` values an attacker can fully control, and which ones PHP
  sanitises.
- Why `copy()`/`file_get_contents()` on `$_FILES[...]['tmp_name']` is an
  arbitrary file read, and why `is_uploaded_file()` / `move_uploaded_file()`
  exist in the first place.
- How to read a PHP hardening commit backwards to work out which versions are
  exploitable.
