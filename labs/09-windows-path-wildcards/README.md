# 09 — Windows Path Madness

A caption-rendering endpoint that only ever answers "font found" or "font not
found". That is one bit. One bit is enough.

## Article reference

Phrack #72, *"The Art of PHP - My CTF Journey and Untold Stories!"* by Orange
Tsai — chapter 3 **"When Windows Breaks..."**, section **3.1 "Windows Path
Madness"**.

The lab recreates the PHPCMS-era classic: an `api.php?op=creatimg&font=...`
endpoint used as a filename oracle through DOS-device wildcards, to brute-force
the randomised PHP session filename in `C:\xampp\tmp\` and then include it.
Original research: USH.it's *PHP filesystem attack vectors — Take Two* and
Vorontsov & Gerkis' *Oddities of PHP file access in Windows*; the same trick was
used in the wild against PHPCMS (backup filename guessing) and DedeCMS (admin
directory discovery). The `::$INDEX_ALLOCATION` ADS behaviour modelled in the
bonus endpoint is Soroush Dalili's.

## Difficulty / category

**medium** — web / filesystem oracle / LFI.

## Run it

```sh
make up        # http://127.0.0.1:8009/
make solve     # runs solve/solve.py inside a container
make verify    # build -> up -> exploit -> assert flag -> tear down
make down
```

## Your goal

`phpcms-lite` runs on a Windows box. Anonymous visitors share a single
server-side "visitor book" session whose id is generated when the box boots and
is never handed out — no cookie is set, nothing echoes it. The compiled-template
loader will happily `include` any file out of `C:\xampp\tmp\`, but only if you
name it exactly: letters, digits and underscores, nothing else.

The flag lives in `C:\flag.txt`, outside the document root. Read it.

## Hints

<details>
<summary>Hint 1</summary>

`?op=creatimg` answers `200` with a PNG when the font file is there and `404`
when it is not. That is a `file_exists()` you can steer, and `font` is
concatenated onto a directory path with no filtering at all — including `..`.

Which directory would be interesting? The session save path of a XAMPP box is
`C:\xampp\tmp`, and it is the same directory the template loader reads from.
</details>

<details>
<summary>Hint 2</summary>

Three characters are illegal in a Windows filename but are *not* rejected on
the way down to the kernel, where the DOS-devices path parser expands them:

| you send | the kernel understands |
|---|---|
| `<` | `*` |
| `>` | `?` |
| `"` | `.` |

So `sess_a<` asks Windows "is there any file starting with `sess_a`?". Repeat.
</details>

<details>
<summary>Hint 3</summary>

You now know the exact name of the session file, and `?op=tplcache` will
`include()` it. `include()` runs PHP tags. What ends up inside a PHP session
file? Whatever the app put in `$_SESSION` — and `?op=sign` puts your string
there verbatim.
</details>

## What you will learn

* Why `<`, `>` and `"` survive PHP's `file_exists()`/`fopen()` on Windows and
  turn a boolean response into a filename oracle.
* How to brute-force a 26-character `session.sid` character by character with
  ~600 requests instead of 32^26 guesses.
* Session-file poisoning: `$_SESSION` values are written to disk as raw bytes,
  so a stored string becomes code the moment the file is `include`d.
* Why "the filename is random" is not an access control.
* NTFS Alternate Data Streams: `name::$INDEX_ALLOCATION` turning an arbitrary
  file write into an arbitrary `mkdir` (the trick that revives the MySQL UDF
  chain by creating a missing `plugin` directory).
* Windows path trivia you can abuse elsewhere: case insensitivity, trailing
  dots and spaces being silently stripped, `/` and `\` being interchangeable.

> **Emulation notice**
>
> This container runs Linux. Windows path handling cannot run here, so it is
> **modelled**, and you should know exactly where the line is.
>
> **Real** — everything in `challenge/src/api.php`, `index.php` and `cms.php`
> is genuine PHP 7.4 running under Apache: the string concatenation of the
> `font` parameter onto a base directory, the `$_SESSION` write, PHP's own
> session serialiser and session id generation (26 characters over a
> 32-symbol alphabet — the lab sets `session.sid_length=26` and
> `session.sid_bits_per_character=5`, which is php.ini-production's
> recommendation, not PHP's compiled-in default of 32 hex characters), and
> the `include` of the session file
> which really does execute the PHP tags you stored in it. The whole exploit
> chain — oracle, brute force, poisoned session, code execution — is real.
>
> **Modelled** — `challenge/src/winpath.php` is a shim that stands in for the
> Win32 path layer. On Windows you would call `file_exists()` and the *kernel*
> would expand the wildcards; here `WinPath::exists()` does it in PHP, against
> the real container filesystem. The shim implements: `<` → `*`, `>` → `?`,
> `"` → `.`, case-insensitive component matching, `\` and `/` as equivalent
> separators, trailing dots and spaces stripped from each component, `C:`
> mapped to the container root, `::$DATA` treated as the file itself, and
> `name::$INDEX_ALLOCATION` on write creating a directory and then failing.
>
> **Known divergences from real Windows.** The shim uses plain glob semantics,
> while Windows uses `RtlIsNameInExpression` with `DOS_STAR` / `DOS_QM` /
> `DOS_DOT`, which behave differently around the last dot of a name (`DOS_QM`
> can match zero characters at the end of a name, `DOS_STAR` stops at the final
> dot). Short (8.3) names, `\\?\` prefixes, reserved device names (`CON`,
> `NUL`, `COM1`...), UNC paths and real ADS storage are not modelled. Directory
> enumeration order is `sort()`ed here, not NTFS B-tree order. None of that
> changes the technique — but do not treat `winpath.php` as a reference
> implementation of Windows.
