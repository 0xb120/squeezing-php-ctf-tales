# 03 — Format-String Oriented Programming

> `new $_GET['driver']()` in PHP 7.0.0 doesn't just pick a class — it hands your
> string to PHP's own `printf`. A class name of `%p` is a format string.

## Article reference

Recreates **section 1.1, "Formatting Objects for Fun and Profit!"** of
*"The Art of PHP — My CTF Journey and Untold Stories!"* by **Orange Tsai**
(Phrack #72). The lab combines the two ingredients Orange calls
*Format-String Oriented Programming*:

- **Arbitrary Object Instantiation** — `new $model()` with an attacker-controlled
  class name (a bug class tracked since 2015).
- **PHP bug #71105 / CVE-2015-8617** — *"Format String Vulnerability in Class Name
  Error Message"*, reported by **Andrew (andrew@jmpesp.org)**. Present **only in
  PHP 7.0.0**; fixed in 7.0.1. See <https://bugs.php.net/bug.php?id=71105>.

## Difficulty & category

- **Difficulty: insane**
- **Category:** memory disclosure / format-string / PHP internals

This one really is insane: the vulnerability is a C-level format-string bug that
lives *inside a scripting language*, it only exists in a single point release of
PHP, exploiting it crashes the interpreter on every wrong guess, and the flag is
never on disk in a readable form — you have to walk it out of the worker's stack.

## Run it

```sh
make up        # build + start the vulnerable service
# -> http://127.0.0.1:8003/?driver=NullDriver
make solve     # run the automated exploit
make verify    # build -> up -> solve -> assert flag -> down
make down      # stop + clean up
```

The app is `http://127.0.0.1:8003/`. It takes one parameter, `?driver=`.

## Your goal

The service boots each of its "driver" implementations by name and renders a
node **licence** in memory that contains the node's `deploy_key` — that key is
the flag. The licence is never sent to you. There is no file-read parameter and
no path traversal. Get the deploy key out of the running PHP process using only
the one thing you control: the class name passed to `new`.

## Hints

<details>
<summary>Hint 1</summary>

Pass a class that does not exist and read the error carefully. Now pass
`?driver=%p-%p-%p`. Does that look like a class-not-found message, or like
something else entirely?
</details>

<details>
<summary>Hint 2</summary>

You are talking to a real C `printf`. `%p` leaks a machine word; `%s`
dereferences a word as a C string. The licence blob is built on the heap right
before the vulnerable line, so a pointer to it is sitting on the stack. Every
wrong `%s` segfaults a worker — that's fine, php-fpm respawns it — so keep going.
</details>

<details>
<summary>Hint 3</summary>

`%.0s` consumes one stack word **without** dereferencing it (it is
`strnlen(ptr, 0)`), so `%.0s%.0s…%s` is a stack walk: N copies of `%.0s` to skip
N words, then `%s` to print the (N+1)th as a string. Sweep N until `%s` prints
the licence text. Positional args (`%7$s`) do **not** work in this build — you
must walk.
</details>

## What you will learn

- Why arbitrary object instantiation (`new $userInput()`) is a primitive, not
  just a nuisance.
- How PHP 7.0.0's uncaught-error path fed the class name through
  `main/spprintf.c` as a format string (bug #71105 / CVE-2015-8617).
- Exactly which conversions PHP's internal formatter supports (`%p`, `%s`,
  `%x`, `%c`, `%n`, width/precision) and which crash it.
- Using `%p` as a read primitive and `%.0s…%s` as a stack-walking string-deref
  primitive to disclose heap memory.
- Reading a binary's mitigations (`readelf -d`, PIE/RELRO/NX/canary) and why the
  `%n` write-to-RCE escalation is or isn't reachable here.

## A note on realism

Everything here is genuine PHP 7.0.0 behaviour — the container ships the official
unmodified `php:7.0.0-fpm` binary. Nothing is shimmed. The only thing the
challenge *shapes* is where the flag lives (in a heap blob referenced from the
stack) so that a deterministic format-string disclosure exists. The exploitation
itself is a real C format-string attack against a real interpreter.
