# 08 — Sleepy Cats Catch No Mice

The same class, the same payload, two PHP versions. On one of them the guard
never even wakes up; on the other you have to talk it into handing your data
back to you.

## Article reference

Recreates section **2.2 "Sleepy Cats Catch No Mice"** of *"The Art of PHP - My
CTF Journey and Untold Stories!"* (Orange Tsai, Phrack #72) — the SugarCRM-style
`__wakeup()` that scrubs every property, PHP silently skipping `__wakeup()`
altogether, and Paul Axe's "Reference Trick".

Based on:

* Taoguang "Ryat" Chen, PHP bug **#72663** — *Create an Unexpected Object and
  Don't Invoke `__wakeup()` in Deserialization* (**CVE-2016-7124**, fixed in
  5.6.25 / 7.0.10) — reference [29] of the article.
* Paul Axe, **WCTF 2019 "P Door"** — reference [30],
  <https://github.com/paul-axe/ctf/blob/master/wctf2019/p-door/p-door.pdf>
* inhann, *A new way to bypass `__wakeup()` and build POP chain* (2022) —
  reference [31], <https://inhann.top/2022/05/17/bypass_wakeup/>

## Difficulty

**hard** — category: PHP object injection / unserializer internals.

## Run it

```sh
make up             # http://127.0.0.1:8008/  (modern)  +  http://127.0.0.1:9008/ (legacy)
make solve          # full exploit: all five stages
make solve-legacy   # just the one-byte CVE-2016-7124 demo, both services side by side
make verify         # build, exploit, assert both flags, tear down
make down
```

| service     | port | PHP     | flag                       |
|-------------|------|---------|----------------------------|
| `challenge` | 8008 | 8.2.33  | **the main objective**     |
| `legacy`    | 9008 | 7.0.9   | its own second flag        |

Both containers serve **byte-for-byte identical** application source. Only the
interpreter differs.

## Your goal

`postbox` keeps your unsent draft in a `draft` cookie as
`base64(serialize($draft))`, and the developers know exactly what that means:
`DraftMessage::__wakeup()` scrubs every single property of any draft that
arrives from outside. Only the subject line is allowed to survive, because
support needs it for the audit log.

`unserialize()` is called with an `allowed_classes` list, so you have exactly
two classes to work with, and `DraftMessage::__destruct()` is the only method
that does anything interesting. Get `/flag.txt` into the outbox spool.

The main flag is on **8008**. The legacy service on **9008** has its own flag and
falls over to a much older trick — do that one first if you want the warm-up.

## Hints

<details>
<summary>Hint 1 — the legacy service</summary>

`O:12:"DraftMessage":3:{...}` — what does PHP do with the `3`? What happens if
you claim there are more properties than you actually supply? Look up when PHP
7.0.10 was released and what it fixed.

</details>

<details>
<summary>Hint 2 — the modern service</summary>

Read `__wakeup()` again, all four lines of it, and pay attention to the *order*:
it saves something, scrubs, and then **writes something back**. The scrub is
only fatal if the property you care about is a separate value from the one that
gets written back afterwards.

</details>

<details>
<summary>Hint 3 — the modern service</summary>

PHP's serialization format can express aliasing. Two properties can be made to
share one zval, and the unserializer numbers every value it creates, starting at
1 for the outermost one. If `attachments` *is* `subject`, then the line that
restores `subject` restores `attachments` too.

</details>

## What you will learn

* CVE-2016-7124 at the source level: why an inflated property count in the `O:`
  header makes `object_common2()` bail out *before* the `__wakeup()` call while
  the object is already fully populated and already scheduled for destruction.
* The `R:` reference token: how the unserializer's value table is indexed, and
  how to make two properties alias the same zval.
* The Reference Trick: turning a defensive `__wakeup()` into the very thing that
  hands your payload back to you.
* A measured answer (not folklore) to "does the duplicate-array-key
  fast-destruct trick bypass `__wakeup()`?" — see the writeup.
* Building a POP chain under an `allowed_classes` whitelist.
