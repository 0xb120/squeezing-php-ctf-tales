# 22 — The hashDoS fix that became RCE

> A one-line security patch turned a denial-of-service bug into remote code
> execution. PHP 5.3.9 is the only build that ever shipped it.

## Article reference

Recreates the closing remark of **§1.2 "When Security Features Make You Less
Secure"** of *"The Art of PHP — My CTF Journey and Untold Stories!"* by
**Orange Tsai** (Phrack #72). At the end of that section Orange mentions, almost
in passing, that a patch for the hash-collision complexity attack once
"accidentally upgraded the simple DoS issue into full-blown remote code
execution" (article reference **[21]**).

This is that story: **CVE-2012-0830**.

* The 28C3 hashDoS talk by **Alexander "alech" Klink** and **Julian "zeri"
  Wälde** (2011, article ref **[19]**, CVE-2011-4885) forced PHP to add the
  `max_input_vars` directive in **5.3.9** to cap the number of request
  parameters.
* The check that enforces the cap, added to `php_register_variable_ex()` in
  `main/php_variables.c`, was wrong. On the array-variable path it fails to
  `return` after refusing the parameter, and keeps running with a **stale
  `zval` pointer**. That is a string→`HashTable` type confusion an attacker can
  groom into an indirect call through a controlled function pointer.
* **PHP 5.3.10** (02 Feb 2012) fixed it with a three-line `else { … return; }`.
  5.3.9 is the *only* released build affected — which is why lab 01 pins 5.3.10.

Reported by **Stefan Esser**; first public analysis by **Dustin Schultz**
(thexploit.com, ref [21]); crash PoC by **pilate**; deepest public exploitation
notes by **Stefan Esser** (EDB-ID 18460, x86-64) and **Worawit "sleepya"
Wangwarunyoo** (x86-32).

## Difficulty / category

**Insane** · binary exploitation (memory corruption) · PHP interpreter internals.

## Run it

```sh
make up        # build (compiles PHP 5.3.9 from source) + start the app
# challenge:  http://127.0.0.1:8022/

make solve     # run the reference exploit end-to-end
make verify    # build -> run -> exploit -> assert flag -> tear down
make down      # stop and remove everything
```

The first build takes a few minutes: PHP 5.3.9 is compiled from the
`museum.php.net` tarball (pinned by SHA-256) because no official image ships a
build that old.

## Your goal

"Sticky" is a note-preview box. You type a note, it hands the note back to you
with the HTML escaped. There is no database, no session, no `include()`, no file
access — the entire application is one `echo htmlspecialchars($_POST['note'])`.
There is nothing to exploit *in the application*. The flag is at `/flag.txt`,
readable only by running code on the box. Read it.

The bug is not in the app. It is in the interpreter that runs it.

> **Emulation notice.** Nothing here is emulated. The interpreter is a genuine
> PHP 5.3.9 compiled from the original source tarball, and the vulnerability is
> the real CVE-2012-0830. Two things are *pinned for reproducibility*, not
> faked, and both are documented in the writeup: the container starts php-cgi
> under `setarch -R` (ASLR off) with a fixed 8 MiB stack rlimit, so the heap
> layout is deterministic and the exercise is exploitation rather than an
> address-brute-force research project. On a stock 2012 server the same bug is
> exploitable with ASLR on by brute-forcing addresses across thousands of
> requests (Stefan Esser's estimate: ~4000 crashes); that is out of scope here
> and discussed in "Going further".

## Hints

<details>
<summary>Hint 1 — where is the bug?</summary>

It is not in `index.php`. Count your POST parameters. PHP 5.3.9 added
`max_input_vars` (default 1000) to defend against the 2011 hash-collision DoS.
What happens if you send *more* than 1000 parameters — and what if the parameter
that trips the limit is an **array** (`a[0]=...`) rather than a scalar? Read
`main/php_variables.c` from the 5.3.9 tarball and diff it against 5.3.10.
</details>

<details>
<summary>Hint 2 — the primitive</summary>

When the limit is hit on the array path, `php_register_variable_ex()` skips the
code that would create the array element but forgets to `return`. It then runs
`symtable1 = Z_ARRVAL_PP(gpc_element_p)` with a `gpc_element_p` left over from
the *previous* parameter — a plain string you control. `Z_ARRVAL_PP` reads a
`HashTable *` out of your string's bytes. You now own a fake `HashTable`. What
does the code do with `symtable1` on the very next line?
</details>

<details>
<summary>Hint 3 — from fake table to code execution</summary>

The next `zend_hash` insert on your fake table calls
`ht->pDestructor(p->pData)`. `pDestructor` is a field in the struct you control,
and `p` comes from `ht->arBuckets[0]`, another field you control. Lay out a
valid `HashTable` + one `Bucket` inside your string, set `pDestructor` to libc
`system`, and make `p->pData` point at your command string. The app echoes your
note back to you — use that same echo to leak a heap address and self-locate
your string. `system()` runs during request startup, *before* php-cgi sends its
CGI headers, so its stdout becomes the HTTP response.
</details>

## What you will learn

* How the `max_input_vars` hashDoS mitigation was implemented, and the exact
  three-line bug (missing `return`) that CVE-2012-0830 was.
* Turning a "stale pointer after a rejected input" into a **string→`HashTable`
  type confusion** in the Zend engine.
* The layout of Zend's `HashTable` / `Bucket` structs and how
  `_zend_hash_index_update_or_next_insert()` reaches an attacker-controlled
  `pDestructor` indirect call.
* Using a benign reflection sink (`htmlspecialchars` echo) as both an **infoleak
  oracle** (defeat heap ASLR by self-locating) and an exploit delivery channel.
* CGI header injection to exfiltrate command output through Apache + mod_cgid.
* How a single defensive commit can be strictly worse than the DoS it fixed —
  the theme of the whole chapter (cross-reference lab
  `04-security-features-backfire`, which weaponises the *same* `max_input_vars`
  directive in a completely different way).
