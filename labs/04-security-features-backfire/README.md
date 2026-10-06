# 04 — When Security Features Make You Less Secure

> Two hardening features, chained. Each one, by doing its job, disarms the other layer that was protecting the app.

## Article reference

Recreates **§1.2 "When Security Features Make You Less Secure"** of *"The Art of
PHP — My CTF Journey and Untold Stories!"* by **Orange Tsai** (Phrack #72).

The lab combines two "security feature backfires":

* **PCRE `pcre.backtrack_limit`** — a limit added to stop ReDoS, abused to make a
  regex *filter* silently fail open. (Orange credits this class of trick to the
  community; the limit itself dates back to PHP 5.2.)
* **`max_input_vars`** — added after the 2011 hash-collision DoS
  (Klink & Wälde, 28C3 [19]) to cap request parameters. Turned into a
  header-cancellation primitive by **Philippe "pilvar" Dourassov**,
  *"Secret Web Hacking Knowledge"*, Insomni'hack 2024 [20].

## Difficulty / category

**Medium** · web · client-side (XSS) + PHP internals.

## Run it

```sh
make up        # build + start the vulnerable app and the admin bot
# challenge:  http://127.0.0.1:8004/
# admin bot:  http://127.0.0.1:9004/   (report a URL for the admin to visit)

make solve     # run the reference exploit end-to-end
make verify    # build -> run -> exploit -> assert flag -> tear down
make down      # stop and remove everything
```

## Your goal

`notes.lab` previews a note you supply in `?xss=`. The developer was thorough:
every note is first checked by a small regex **WAF**, and *on top of that* every
response carries a strict **`Content-Security-Policy: default-src 'none'`** so
that even a WAF bypass could never run script. The site admin reviews reported
notes in their browser, and their session cookie holds the flag. Get script to
run in the admin's browser and steal that cookie. You will need to defeat
**both** defences at once — beating only one gets you nothing.

## Hints

<details>
<summary>Hint 1 — the WAF</summary>

`preg_match()` has three possible return values, not two: `1`, `0`, and
`false`. The filter is written `if (preg_match($re, $in)) { block(); }`. What
does the engine return when the regex is *too expensive to finish*? Look up
`pcre.backtrack_limit` and think about what a long, ambiguous input does to a
greedy pattern.
</details>

<details>
<summary>Hint 2 — the CSP</summary>

The CSP is sent with `header()`. PHP refuses to send headers once **any** byte
of body has been emitted — even a byte PHP itself printed. Is there a way to
make PHP print something *before your script's first line even runs*? Count your
GET parameters.
</details>

<details>
<summary>Hint 3 — chaining and ordering</summary>

Both tricks live in the same request. One needs your payload padded so the
regex explodes; the other needs 1000+ parameters. Careful: `max_input_vars`
keeps only the **first** N parameters and drops the rest — so where in the query
string does `xss=` have to sit? Then report `http://challenge/?xss=...` to the
admin bot and catch its cookie.
</details>

## What you will learn

* `preg_match()` returns `false` (not `0`) on `PREG_BACKTRACK_LIMIT_ERROR`, and
  why `if (preg_match(...))` filters fail *open*.
* How `pcre.backtrack_limit` (a ReDoS mitigation) becomes a filter-bypass.
* How exceeding `max_input_vars` makes PHP emit a startup warning **before** the
  script runs, cancelling every later `header()` call ("headers already sent").
* Why `display_errors`/`html_errors` being on (the `php:*-apache` default) turns
  that warning into a real CSP bypass and re-enables reflected XSS.
* End-to-end client-side exfiltration against a real headless-browser bot.

> **Emulation notice.** Nothing here is emulated. The challenge is stock
> `php:8.2.33-apache`; both behaviours are genuine PHP/PCRE behaviour. The ini
> settings are pinned explicitly in `challenge/php.ini`, which documents which
> of them are the image's own defaults and which this lab sets on purpose
> (`output_buffering=0` is the load-bearing one). The admin bot is a **real headless Chromium 124**
> (`zenika/alpine-chrome`) driven over the DevTools protocol — not a checker.
