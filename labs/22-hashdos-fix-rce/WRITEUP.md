# 22 — The hashDoS fix that became RCE — Writeup

## TL;DR

PHP 5.3.9 introduced `max_input_vars` to fix the 28C3 hash-collision DoS
(CVE-2011-4885). The enforcement check added to `php_register_variable_ex()`
(`main/php_variables.c`) is wrong: on the **array** path, when the element count
reaches the limit, the code skips creating the element but **does not
`return`** — it runs `symtable1 = Z_ARRVAL_PP(gpc_element_p)` with a
`gpc_element_p` still pointing at the *previous* parameter, an attacker-supplied
**string** zval. `Z_ARRVAL_PP` reinterprets the string's bytes as a
`HashTable *`, giving the attacker a fully controlled fake hash table. The next
insert reaches `_zend_hash_index_update_or_next_insert()`, which calls
`ht->pDestructor(p->pData)` — an indirect call through a function pointer that
lives in the fake table. That is **CVE-2012-0830**, fixed the next release
(5.3.10) with a three-line `else { … return; }`. The lab ships a note-preview
app whose only sink is `echo htmlspecialchars($_POST['note'])`; the exploit uses
that echo both to leak a heap address (self-locate the fake table under ASLR-off)
and to deliver a fake `HashTable` whose `pDestructor` is libc `system`. Flag:
`PHRACK{max_input_vars_handed_me_a_fake_hashtable}`.

## The bug

### The mitigation that created it

The 2011 hashDoS work of Klink & Wälde (28C3, article ref [19], CVE-2011-4885)
showed that a POST body with thousands of keys chosen to collide in PHP's hash
table degrades insertion to O(n²) and pins a CPU. PHP 5.3.9 (10 Jan 2012)
responded not by fixing the hash table but by **capping the number of input
variables**: the `max_input_vars` directive (default 1000). The cap is enforced
right where GET/POST/COOKIE variables are registered, in
`php_register_variable_ex()`.

Here is the relevant code as it shipped in **PHP 5.3.9**
(`main/php_variables.c`, the `is_array` branch that handles `a[...]=` style
parameters):

```c
/* php-5.3.9/main/php_variables.c  (array path) */
if (zend_symtable_find(symtable1, escaped_index, index_len + 1,
                       (void **) &gpc_element_p) == FAILURE
    || Z_TYPE_PP(gpc_element_p) != IS_ARRAY) {
    if (zend_hash_num_elements(symtable1) <= PG(max_input_vars)) {
        if (zend_hash_num_elements(symtable1) == PG(max_input_vars)) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                "Input variables exceeded %ld. ...", PG(max_input_vars));
        }
        MAKE_STD_ZVAL(gpc_element);
        array_init(gpc_element);
        zend_symtable_update(symtable1, escaped_index, index_len + 1,
                             &gpc_element, sizeof(zval *),
                             (void **) &gpc_element_p);
    }
    /*  <-- BUG: no `else`. When num_elements > max_input_vars we fall
        through here WITHOUT having assigned gpc_element_p.               */
}
if (index != escaped_index) {
    efree(escaped_index);
}
}
symtable1 = Z_ARRVAL_PP(gpc_element_p);   /* line 207: uses a STALE pointer */
```

When `zend_hash_num_elements(symtable1) > PG(max_input_vars)`, the `if` body is
skipped. There is no `else`, so control reaches line 207 and dereferences
`gpc_element_p` — which was **never assigned on this iteration**. It still holds
whatever it pointed at from the previous parameter's processing. If the previous
parameter was a plain scalar (the `plain_var` path), `gpc_element_p` points at
that scalar's `zval`, whose `value` field is a **copy of the attacker-supplied
string data**. `Z_ARRVAL_PP(gpc_element_p)` expands to
`(*gpc_element_p)->value.ht`, i.e. it reads a `HashTable *` out of the first 8
bytes of the attacker's string. `symtable1` is now a pointer the attacker fully
controls.

### The fix (5.3.10)

Diffing the two tarballs from `museum.php.net` shows exactly what was added.
`diff -u php-5.3.9/main/php_variables.c php-5.3.10/main/php_variables.c`:

```diff
@@ -198,6 +203,13 @@
 						MAKE_STD_ZVAL(gpc_element);
 						array_init(gpc_element);
 						zend_symtable_update(symtable1, escaped_index, index_len + 1, &gpc_element, sizeof(zval *), (void **) &gpc_element_p);
+					} else {
+						if (index != escaped_index) {
+							efree(escaped_index);
+						}
+						zval_dtor(val);
+						efree(var_orig);
+						return;
 					}
```

That `else { … return; }` — refuse the parameter and **stop** instead of falling
through — is the entire fix (upstream commit `40d8cd1f12…` on `PHP-5.3`, "fix UMR
in php_register_variable_ex, reported by Stefan Esser", released as PHP 5.3.10 on
02 Feb 2012; the php.net 5.3.10 changelog: "Fixed arbitrary remote code execution
vulnerability reported by Stefan Esser, CVE-2012-0830."). The same commit adds
two sibling `== FAILURE` guards on the `zend_hash_next_index_insert()` calls. The
NVD note says it plainly: *"this vulnerability exists because of an incorrect fix
for CVE-2011-4885."* A defensive patch created a memory-corruption RCE. That is
the punchline of §1.2, and the reason lab 01 pins 5.3.10 rather than 5.3.9.

### From type confusion to an indirect call

The line after the confusion is the payoff. The loop continues, `index` becomes
the array key (`"0"` for `a[0]`), and because there is no further `[`, control
`goto`s `plain_var` and calls `zend_symtable_update(symtable1, "0", …)`. A
numeric key routes to `_zend_hash_index_update_or_next_insert()`
(`Zend/zend_hash.c`):

```c
/* Zend/zend_hash.c */
nIndex = h & ht->nTableMask;               /* mask=0  -> nIndex = 0        */
p = ht->arBuckets[nIndex];                 /* arBuckets[0] we control      */
while (p != NULL) {
    if ((p->nKeyLength == 0) && (p->h == h)) {   /* make both match (=0)   */
        ...
        if (ht->pDestructor) {
            ht->pDestructor(p->pData);     /* <-- indirect call, controlled */
        }
        UPDATE_DATA(ht, p, pData, nDataSize);
        ...
```

Every field on the path — `nTableMask`, `arBuckets`, the `Bucket`'s `h` /
`nKeyLength` / `pData`, and `pDestructor` — is read out of the string we
supplied. Set `pDestructor = system` and `p->pData` = pointer to a command
string, and PHP calls `system("…")` for us. The Zend `HashTable` and `Bucket`
structs (64-bit) are:

```c
typedef struct _hashtable {
    uint nTableSize;            /* +0  */
    uint nTableMask;            /* +4  -> 0, so (h & mask) == 0            */
    uint nNumOfElements;        /* +8  -> 0                               */
    ulong nNextFreeElement;     /* +16 */
    Bucket *pInternalPointer;   /* +24 */
    Bucket *pListHead;          /* +32 */
    Bucket *pListTail;          /* +40 */
    Bucket **arBuckets;         /* +48 -> &fakeBucketSlot                  */
    dtor_func_t pDestructor;    /* +56 -> system                          */
    ...
} HashTable;                    /* sizeof == 72 on x86-64                  */
```

## Building the exploit

The challenge app is deliberately empty of bugs: `index.php` is just
`echo htmlspecialchars($_POST['note'])`. Everything below happens in the
interpreter, driven entirely by the shape of the POST body. All of it was
developed against the real binary; the evidence quoted here is from the running
container (`labs/22-hashdos-fix-rce`).

### Step 0 — build PHP 5.3.9 and confirm the crash

The Dockerfile compiles PHP 5.3.9 from the `museum.php.net` tarball (pinned
SHA-256 `424c6312…`), multi-stage, and serves it through Apache + mod_cgid — the
same recipe lab 01 uses for 5.3.10. A CGI SAPI is chosen on purpose: we corrupt
memory and crash the interpreter, and a fresh php-cgi process is forked per
request, so a crash is a 500 for one request and nothing more.

The bug's raw form (from the original bug report #60708) is a one-liner: any POST
with more than `max_input_vars` parameters whose last one is an array segfaults.
Sending 1002 fillers + `note[0]=zz` with a garbage `HashTable *` in `note`
crashes php-cgi immediately:

```
### crash test (garbage arBuckets in the fake table)
Segmentation fault (core dumped)   RC=139
```

### Step 1 — prove the type confusion in gdb

Breaking at `php_variables.c:207` with `note` set to a fake table whose
`arBuckets = 0x4141414141414141`:

```
Breakpoint 1, php_register_variable_ex (var_name="note[0]", ...) at main/php_variables.c:207
207     symtable1 = Z_ARRVAL_PP(gpc_element_p);
SYMTABLE1=0x555555994cf8          <- points into our note string
ZVAL=0x555555994f60 TYPE=6        <- previous zval is a string (IS_STRING=6)
```

`symtable1` is the string data. `TYPE=6` (`IS_STRING`) confirms the stale
`gpc_element_p` is the previous *string* parameter, exactly as CVE-2012-0830
describes. Continuing crashes at `_zend_hash_index_update_or_next_insert` while
walking `arBuckets` — `p=0x4141414141414141`.

### Step 2 — an infoleak oracle to defeat heap ASLR

We need the absolute address of our own note string to build self-referential
pointers (`arBuckets` must point at a slot that points at a `Bucket`, all inside
the note). We get it from the app's own echo.

Point `arBuckets` at a known-NULL qword (deep in php-cgi's `.bss`,
`0x555555899000` — part of the pinned binary, fixed under ASLR-off). Then
`arBuckets[0]` is NULL, the `while` loop is skipped, php allocates a fresh
`Bucket`, and `CONNECT_TO_GLOBAL_DLLIST` writes that bucket's address into the
fake table's `pListHead`/`pListTail` — which live at offsets 32/40 of our note
string. The app echoes the note straight back (we invert `htmlspecialchars`
exactly: `&lt;`→`<`, `&gt;`→`>`, `&quot;`→`"`, `&amp;`→`&`, single quote
untouched). Reading offset 24/32/40 yields a live heap pointer:

```
bss 0x555555899000 -> st=200 leaked=0x5555559cb5d0
```

To turn the leaked bucket address into the note's address, we sweep `arBuckets`
downward from the leak. Whenever it lands *inside our own note buffer*, php
writes the fresh bucket pointer at `*(arBuckets)`, i.e. into the echoed note at
offset `arBuckets - note`. Reading that offset back gives the absolute base:

```
locate: 91 reqs, base=0x55555599e000 off=2216 blob=0x55555599d758
```

So the note string sits at `0x55555599d758`, and — because ASLR is off and the
request body is byte-for-byte identical each time — it is there on every request
(verified deterministic across five independent solver runs).

### Step 3 — the indirect call to `system`

With the note address known, lay out inside the note:

* the `HashTable` header: `nTableMask=0`, `nNumOfElements=0`,
  `arBuckets = note+72`, `pDestructor = system`;
* at `note+72`: a `Bucket *` = `note+128`;
* at `note+128`: a fake `Bucket` with `h=0`, `nKeyLength=0`,
  `pData = note+152`;
* at `note+152`: the shell command string.

`system` is libc `system@@GLIBC_2.2.5` at `libc_base + 0x4c490`. libc_base is
fixed (`0x7ffff7cfe000`) because ASLR is off and the base image / stack rlimit
are pinned. The insert on `note[0]` then executes
`ht->pDestructor(p->pData)` = `system(note+152)`:

```
[+] leaked heap pointer: 0x5555559cb5d0
[+] note string (fake HashTable) @ 0x55555599d758
[+] calling system() @ 0x7ffff7d4a490 through fake pDestructor
uid=33(www-data) gid=33(www-data) groups=33(www-data)      <- system("id") output
```

Confirmed genuine remote code execution as `www-data`, and php-cgi returns to a
clean exit (`RC=0`) afterwards — the insert finishes normally once `system`
returns.

### Step 4 — exfiltration through CGI header injection

The corruption fires during **request startup**, before php-cgi emits its own
CGI headers. So `system()`'s stdout is the *first* thing on the CGI pipe. We make
that stdout a valid CGI header block followed by the flag; Apache/mod_cgid parses
it as the response headers and hands the flag back as the HTTP body:

```
command: printf 'Content-Type: text/plain\n\nFLAG_BEGIN:'; cat /flag.txt; printf ':FLAG_END\n'
response: FLAG_BEGIN:PHRACK{max_input_vars_handed_me_a_fake_hashtable}:FLAG_END
          Content-type: text/html   <- php-cgi's own headers, now part of the body
          <!doctype html> ...
```

No second channel, no writable web directory: the flag comes straight back over
HTTP.

## The exploit

`solve/solve.py` (Python 3 stdlib only) automates the four steps:

1. `leak_heap_pointer()` — fake table with `arBuckets` at the `.bss` NULL qword;
   read a live heap pointer out of the echoed note.
2. `locate_note()` — sweep `arBuckets` downward until it lands in the note
   buffer; recover the note's absolute address from the write it induces.
3. `exploit()` — build the `HashTable` + `Bucket` + command in the note, set
   `pDestructor = system`, and POST it.
4. Parse the flag out of the CGI-header-injected response.

It is fully self-calibrating for the heap layout (leak + locate every run) and
retries the whole sequence up to five times. The only baked-in constants are the
two ASLR-off image bases, and they are what the pinned toolchain guarantees. End
to end it is ~95 requests and finishes in a couple of seconds.

## Fixing it

* **The actual fix**, PHP 5.3.10: add the missing `else { … return; }` so a
  refused parameter stops instead of running on with an unassigned
  `gpc_element_p`. Never let an early-out skip the assignment of a pointer that a
  later line unconditionally dereferences.
* **The deeper lesson**: adding a *limit* is not free. The `max_input_vars`
  check was bolted onto a hot, pointer-heavy function under time pressure, and
  the new early-exit path was not wired into the function's cleanup/return
  discipline. A safer design keeps a single exit path (or initialises
  `gpc_element_p = NULL` and checks it) so a new guard cannot leave a stale
  pointer live.
* **Defence in depth that actually helped**: the Suhosin patch (RHEL/CentOS
  builds of the era) hardened the request-variable handling enough that this
  specific corruption was far less exploitable — a reminder that the mitigation
  that matters is the one on the allocation/pointer discipline, not the one that
  merely counts inputs.

## Going further

* **RCE was achieved here**, not just a crash — genuine `system()` execution
  through the fake `pDestructor`, exfiltrated over HTTP. This is further than the
  public 2012 state of the art went in print: Stefan Esser's EDB-ID 18460
  demonstrated **RIP control** on x86-64 (making PHP jump to
  `0x1111111111111111`) but shipped no shellcode; Worawit "sleepya" documented an
  x86-32 arbitrary read + heap infoleak but wrote "it is highly possible to do
  code execution" without landing it publicly. The difference here is entirely
  the lab's deterministic layout — see below.
* **The one thing this lab pins: ASLR.** The container runs php-cgi under
  `setarch -R` (ADDR_NO_RANDOMIZE) with a fixed 8 MiB stack rlimit, so the note
  string, the heap, php-cgi and libc all sit at fixed addresses. That is why the
  solver can hardcode `system`'s address and self-locate the note in ~90
  requests. **On a stock 2012 server with ASLR on, the same primitive is still
  exploitable but much harder**: you brute-force addresses across many crashing
  requests (Esser's public estimate: ~4000 crashes to hit a code address), and
  you first need an infoleak for libc — the note-echo oracle used here leaks
  *heap* only. Full ASLR-on exploitation (leak libc via a second confusion, then
  a one-shot) is a research exercise deliberately left out of scope; the writeup
  documents the blocker precisely rather than shipping an exploit that only works
  with the mitigation off by accident.
* **32-bit** needs a 32-bit fake `HashTable` (Esser: "32bit requires you to
  create a fake 32bit Hashtable instead of a 64bit one"); the struct offsets and
  pointer width change but the chain is identical.
* **Same directive, opposite trick.** Lab `04-security-features-backfire`
  weaponises `max_input_vars` on a *modern* PHP: exceeding it emits a startup
  warning *before* the script runs, which cancels a later `header()` and defeats
  a CSP (pilvar / Insomni'hack 2024, ref [20]). Same feature, born from the same
  28C3 talk — one lab abuses the *warning it prints*, this lab abuses the *broken
  code that prints it*. Read them back to back: they are the two halves of "when
  security features make you less secure."

## References

* Orange Tsai, "The Art of PHP — My CTF Journey and Untold Stories!",
  Phrack #72, §1.2 (ref [21] is this bug).
* CVE-2012-0830 — <https://nvd.nist.gov/vuln/detail/CVE-2012-0830>
  ("The php_register_variable_ex function … allows remote attackers to execute
  arbitrary code … NOTE: this vulnerability exists because of an incorrect fix
  for CVE-2011-4885.").
* Dustin Schultz, "Critical PHP Remote Vulnerability Introduced in Fix for PHP
  Hashtable Collision DOS", thexploit.com (article ref [21]), archived:
  <https://web.archive.org/web/20120206184648/http://thexploit.com/sec/critical-php-remote-vulnerability-introduced-in-fix-for-php-hashtable-collision-dos/>
* Upstream fix — php-src commit `40d8cd1f122873af7e21dfe4cad24702c4be48f9`
  ("fix UMR in php_register_variable_ex, reported by Stefan Esser"), released as
  PHP 5.3.10 — <https://github.com/php/php-src/commit/40d8cd1f122873af7e21dfe4cad24702c4be48f9>
* PHP bug #60708, "Segmentation fault, use max_input_vars" (the original crash
  report, 11 Jan 2012) — <https://bugs.php.net/bug.php?id=60708>
* Stefan Esser, EDB-ID 18460, "PHP 5.4.0RC6 (x64) — Denial of Service"
  (RIP-control PoC) — <https://www.exploit-db.com/exploits/18460>
* Worawit "sleepya" Wangwarunyoo, "Mini-PoC for PHP 5.3.9 RCE (CVE-2012-0830)"
  — <http://auntitled.blogspot.com/2012/02/mini-poc-for-php-rce-cve-2012-0830.html>
* pilate, crash PoC — <https://gist.github.com/1725489>
* Alexander "alech" Klink & Julian "zeri" Wälde, "Effective Denial of Service
  attacks against web application platforms", 28C3, 2011 (article ref [19],
  CVE-2011-4885) —
  <https://fahrplan.events.ccc.de/congress/2011/Fahrplan/attachments/2007_28C3_Effective_DoS_on_web_application_platforms.pdf>
* Companion lab: `labs/04-security-features-backfire` (the other half of §1.2).
