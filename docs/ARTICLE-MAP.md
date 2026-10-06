# Article → lab map

Source: **"The Art of PHP - My CTF Journey and Untold Stories!"**, Orange Tsai,
*Phrack* #72 (2025-08-19) —
<https://phrack.org/issues/72/the-art-of-php-my-ctf-journey-and-untold-stories>

The article is a tour of PHP security seen through fifteen years of CTF. It is
not a lab manual: it names techniques, the people who invented them, and the
competitions where they were born, then moves on. This repository turns each of
those mentions into something you can actually run, break and read about.

Below, every technical item in the article is mapped to the lab that recreates
it. "Real" means the lab reproduces the genuine bug on a genuinely affected
build; "Modelled" means the behaviour cannot exist in a Linux container (Windows
APIs, Windows Defender) and is reproduced by a documented shim, with the PHP
side still being real PHP.

| Article section | Topic | Lab | Fidelity |
|---|---|---|---|
| 1. intro | Corrupting upload file indices in `$_FILES` (Adam Iwaniuk) | `01-upload-index-corruption` | Real |
| 1.1 | Arbitrary Object Instantiation (`new $class()`), CVE-2015-1033 lineage | `02-arbitrary-object-instantiation` | Real |
| 1.1 | Format-String Oriented Programming — PHP bug #71105, PHP 7.0.0 only | `03-format-string-oriented-programming` | Real, partial (disclosure only; the `%n`→GOT→`system()` step is documented, not weaponised) |
| 1.2 | `pcre.backtrack_limit` and `max_input_vars` as attack tools; CSP bypass | `04-security-features-backfire` | Real |
| 1.2 | CVE-2012-0830: the hash-collision-DoS *fix* that became RCE | `22-hashdos-fix-rce` | Real, full RCE on PHP 5.3.9 built from source (ASLR pinned off for reproducibility) |
| 2.1 | The "serialize-then-replace" pattern (Rusty Joomla shape) | `05-serialize-then-replace` | Real (shrink direction; *piapiapia*'s grow direction is documented, not implemented) |
| 2.1 | WordPress "Double Preparing" SQL injection, and the `wpdb::prepare()` placeholder escaping introduced to stop it → object injection | `06-wordpress-placeholder-injection` (two stages) | Real behaviour, minimal wpdb reimplementation |
| 2. intro | `maybe_unserialize()` + MySQL column truncation / 4-byte emoji | `07-wordpress-column-truncation` | Real |
| 2.2 | `__wakeup()` bypasses: CVE-2016-7124, Paul Axe's reference trick | `08-wakeup-bypass` | Real (both a modern and a PHP 7.0.9 service) |
| 3.1 | Windows path madness: DOS device wildcards as a filename oracle | `09-windows-path-wildcards` | Modelled |
| 3.2 | AVOracle — Windows Defender's JScript emulation as a side channel | `10-avoracle` | Modelled |
| 4.1 pre-history | The classic LFI toolkit: NUL/long-path truncation, `zip://`, loose base64, the `phpinfo()` temp-file race | `20-lfi-classic-toolkit` | Real (NUL truncation on PHP 5.3.3; the over-long-path variant does not exist on Linux and the lab proves why) |
| 4.1 Level 0 | *One Line PHP Challenge*, `session.upload_progress` → LFI → RCE | `11-one-line-php` | Real |
| 4.1 Level 1 | `php://filter` chains: LFI → RCE with no file at all (loknop) | `12-filter-chain-rce` | Real |
| 4.1 Level 2 | *minimal-php*: blind file read from a memory-error oracle (hashkitten) | `13-filter-chain-oracle` | Real |
| 4.1 Level Max | CVE-2024-2961: iconv/glibc OOB write reached through filter chains | `21-iconv-cve-2024-2961` | Real OOB write on unpatched glibc 2.36-9+deb12u4; graded objective is the allocator abort, not RCE |
| 4.2 Level 0 | PHAR deserialisation: any file operation is an `unserialize()` | `14-phar-deserialization` | Real (PHP 7.x) |
| 4.2 Level Max | mPDF data-URI cache + `phar://` + framework POP chain | `15-mpdf-phar-killchain` | Real (mPDF 8.0.10 + real Laravel gadgets) |
| 5.1 | PHP-CGI argument injection: CVE-2012-1823 and CVE-2024-4577 | `16-php-cgi-argument-injection` | Real (unmodified, fully patched php-cgi) but **both** modes are modelled: a deliberately RFC-non-compliant CGI gateway supplies argv, and the Windows ANSI Best-Fit layer is a table in that gateway |
| 5.2 | CVE-2019-11043: php-fpm buffer underflow → RCE (neex) | `17-php-fpm-underflow` | Real |
| Honorable mention | Restricted-environment jailbreaks (`ini_set`, `open_basedir`) | `18-ini-set-jailbreak` | Real |
| Honorable mention | Attacking the MySQL *client*: rogue server → arbitrary file read | `19-mysql-client-file-read` | Real |

## Mentioned but deliberately not turned into a lab

Each entry says where, if anywhere, the topic is actually discussed. If an entry
does not name a file, the repository does not cover it at all.

* **CTF and binary-exploitation lore** — cLEMENCy, Xbox Doom, QR pancakes, the
  slot machine, One-Gadget, ret-to-csu, House of Orange, the FreeBSD and ELF
  parser tricks, the Chromium / VirtualBox / CS:GO 0days, Binary Golf, LiveCTF,
  the Game Boy RCE, Vudo and Smashing the Stack. Not PHP. Not covered anywhere.
* **`unserialize()` memory corruption** — the PornHub chain, Stefan Esser's
  fake-`zval` post-exploitation, and the `DateTimeZone` UAF (bug #68942).
  Reproducing a specific heap layout on a specific old build is a research
  project rather than a lab. **Not discussed in any writeup**; go to the
  original sources in the article's reference list [34][35][36].
* **GMP deserialisation type confusion, `phpinfo()` type confusion, UTF-8
  length-counting bugs** ([87][88][89]) — single CVEs rather than technique
  families. **Not discussed in any writeup.**
* **The Semicolon Trick** ([49]) — Orange's own WCTF 2016 challenge, but the
  Black Hat 2018 subject is path normalisation across Tomcat/nginx/Java proxies,
  not PHP language behaviour. Not covered.
* **HTTPoxy, TLS Poison, Laravel debug-mode RCE** ([38][39][40]) — named as
  examples of cross-application bugs, not as PHP language issues. Not covered.
* **The RIPS PHP Security Advent Calendar** ([86]) — a challenge collection, not
  a technique. Not covered; go and solve it, it is excellent.
* **`imap_open()` command execution** ([93], CVE-2018-19518) — attempted and
  found dead: `18-ini-set-jailbreak/WRITEUP.md` records that ext-imap is absent
  from the modern base images and that every obtainable `libc-client` is
  patched.
* **mysqlnd/PDO password buffer overflow** ([90]) — `19-mysql-client-file-read`
  states plainly that it is not reproduced.

## Partial reproductions

These are covered by a lab, but the lab stops short of the full chain. Each one
is documented in the lab's own writeup:

* `03-format-string-oriented-programming` — leaks the flag from process memory
  with a real format-string bug, but does not land the `%n` → GOT → `system()`
  write the article describes.
* `05-serialize-then-replace` — implements the shrink direction only; 0CTF
  *piapiapia*'s grow direction is explained, not built.
* `16-php-cgi-argument-injection` — the php-cgi binary is real and unmodified,
  but it is a current, fully patched one: both modes reach it through a
  deliberately non-compliant CGI gateway.
* `21-iconv-cve-2024-2961` — lands the real out-of-bounds write and a deterministic
  allocator abort, but not the RCE cfreal built on it; the writeup names the
  blockers and reports the measured sweep that failed to find a groom.
* `09-windows-path-wildcards`, `10-avoracle` — Windows path semantics and
  Defender's scanner are models, with their divergences listed in each README.

Every lab's `WRITEUP.md` credits the original researchers and links their work.
