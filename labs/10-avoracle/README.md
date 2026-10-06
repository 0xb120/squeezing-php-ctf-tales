# 10 — AVOracle

The antivirus reads your session file. You get to write half of it. That is
enough to make the antivirus read the other half out loud, one bit at a time.

## Article reference

Phrack #72, *"The Art of PHP - My CTF Journey and Untold Stories!"* by Orange
Tsai — chapter 3 **"When Windows Breaks..."**, section **3.2 "Let's Make Windows
Defender Angry!"**.

The technique is **AVOracle**, by Ryo "icchy" Ichikawa, first shown in the
challenge *"Gyotaku The Flag"* at WCTF 2019 and brought back in a PHP flavour at
TokyoWesterns CTF the same year.
Slides: https://github.com/icchy/wctf2019-gtf/blob/master/wctf2019-gtf-slides.pdf

## Difficulty / category

**hard** — web / side channel / antivirus abuse.

## Run it

```sh
make up             # http://127.0.0.1:8010/   (Defender console on :9010)
make solve          # runs solve/solve.py inside a container
make solve-passive  # same exploit, waiting for the scan timer instead of poking it
make verify         # build -> up -> exploit -> assert flag -> tear down
make down
```

## Your goal

`inkstone` is a note-taking workstation. It keeps two things in your PHP session:
the nickname you chose, and the machine's licence key — in that order, in the
same file, under `C:\Windows\Temp\`. The application never prints the licence
key, and there is no file read, no include, no deserialisation bug.

The machine also has real-time antivirus protection watching that directory.

Recover the licence key. It is a `PHRACK{...}` flag.

## Hints

<details>
<summary>Hint 1</summary>

You cannot read the session file. But something else on the box reads it,
constantly, and it *acts* on what it reads: it deletes files it does not like.

`GET /status.php` tells you whether your session file is still there. That is
an output channel you control the input of.
</details>

<details>
<summary>Hint 2</summary>

The scanner does not just grep for byte patterns. It emulates script it finds
inside the file — including a small DOM — and matches its signatures against
what that script *produces*, for example the string handed to `eval()`.

The Defender console at `http://127.0.0.1:9010/status` will tell you the exact
signature name it detects; the scanner's source is in `scanner/defender.js` if
you would rather read the engine than guess.
</details>

<details>
<summary>Hint 3</summary>

Your nickname is written into the file *before* the licence key. So a nickname
ending in `<body>` puts the licence key inside the document body, where script
in the same file can reach it as `document.body.innerHTML`.

Then: emit the signature only when a condition about that string is true. The
file's disappearance is your `if`. Binary search the character code and you
need ~7 requests per character, not 95.
</details>

## What you will learn

* Why an antivirus that (a) scans a file as a whole, (b) emulates script inside
  it, and (c) deletes what it flags, is a *decryption oracle* for any secret
  that shares a file with attacker-controlled bytes.
* How PHP writes `$_SESSION` to disk — key order, `key|s:len:"value";`, raw
  bytes, no escaping — and why that makes session files such good oracle
  substrates.
* Turning a 1-bit side channel into a full read with a binary search over
  character codes, and parallelising it across independent sessions.
* That "the secret is never printed" is not a confidentiality boundary when
  something else on the box is willing to look at it for you.
* Why security products enlarge the attack surface they are meant to shrink.

> **Emulation notice**
>
> This container runs Linux. Windows Defender cannot run here, so it is
> **modelled**, and you should know exactly where the line is.
>
> **Real** — the challenge service is genuine PHP 8.2 under Apache. The session
> file is written by PHP's own `files` session handler, with PHP's own
> serialiser and key ordering; the nickname you post really is stored verbatim
> on disk next to the flag; `status.php` really is just
> `isset($_SESSION['flag'])`. The exploit primitive — *the file is gone, so my
> guess was right* — is exactly the one icchy used against the real Defender.
>
> **Modelled** — `scanner/defender.js` (~200 lines of Node) stands in for
> Defender's real-time protection. It polls the shared session directory every
> 400 ms and, for each file: flags it if the raw bytes contain the signature;
> otherwise extracts `<script>...</script>` blocks and runs them in node's `vm`
> with a hand-written DOM shim (`document.body.innerHTML` is the text after
> `<body>`, plus `document.write`, `WScript.Echo` and a hooked `eval`), and
> flags the file if the signature appears in anything that script hands to
> those. Flagged files are deleted and logged.
>
> **The signature is fake on purpose.** It is
> `PHRACK-STANDARD-ANTIVIRUS-TEST-FILE!`, *not* the real EICAR string. Writing
> real EICAR into a Docker volume would make the antivirus on **your** machine
> react, which is both rude and a good way to lose your lab. The article makes
> the same joke.
>
> **Known divergences from real Defender.** MpEngine is a real JScript/VBScript
> emulator with thousands of signatures, ActiveX/WScript objects, string
> deobfuscation, timeouts and anti-emulation heuristics; this is a `vm` call
> with five globals and one signature. Our hooked `eval()` inspects the string
> it is given but does not then execute it. There is no quarantine, no cloud
> lookup, no AMSI, no on-access hooking — this is a polling loop, so the oracle
> has a latency of one scan interval rather than being synchronous with the
> write. The scanner also exposes a `/scan` endpoint that runs a pass on
> demand; it exists purely so the solver does not have to sleep 400 ms per
> query, and `make solve-passive` shows the exploit working without it. Node's
> `vm` is not a security boundary: the emulator builds its globals inside the
> context so no host object leaks in, but do not expose this service to
> anything you do not trust.
