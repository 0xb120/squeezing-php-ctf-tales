# The Art of PHP — CTF labs

Self-contained Docker labs for the techniques in
**"The Art of PHP - My CTF Journey and Untold Stories!"** by Orange Tsai,
published in *Phrack* #72 —
<https://phrack.org/issues/72/the-art-of-php-my-ctf-journey-and-untold-stories>

Precisely: every technique in the article that is **PHP-specific and
reproducible in a Linux container**. The article also ranges over CTF lore,
binary exploitation and single one-off CVEs; `docs/ARTICLE-MAP.md` lists exactly
what is covered, what is deliberately out of scope, and which labs reproduce
only part of a chain. Several labs stop short of the article's final step and
say so in their own writeups — that is the house rule: a documented limitation
is fine, a false claim is not.

The article walks through fifteen years of PHP security as seen from inside the
CTF scene: forgotten bugs brought back to life by challenge authors, the long
war around `unserialize()`, the ways Windows breaks PHP, the twenty-year road
from LFI to RCE, and the 0days that participants popped while playing. It names
the techniques and the people behind them — it does not hand you an environment
to try them in. That is what this repository is for.

Every lab is one technique, one vulnerable service, one flag, one writeup.

## Quick start

```sh
cd labs/12-filter-chain-rce
make up            # build and start the vulnerable service
open http://127.0.0.1:8012
make solve         # run the reference exploit
make verify        # build + run + exploit + assert the flag + tear down
make down
```

The only host dependency is Docker (with the compose v2 plugin). Exploits run
inside a `solver` container, so there is nothing to install and nothing to
uninstall.

To check the whole set (slow — it builds every image):

```sh
make verify        # or: scripts/verify-all.sh 11 12 13
```

## The labs

| # | Lab | Technique | Difficulty | Port |
|---|-----|-----------|------------|------|
| 01 | `01-upload-index-corruption` | Forging `$_FILES` structures from a single upload field | medium | 8001 |
| 02 | `02-arbitrary-object-instantiation` | `new $class()` with no gadget classes in the app | medium | 8002 |
| 03 | `03-format-string-oriented-programming` | A real format-string bug in PHP 7.0.0 (bug #71105) | insane | 8003 |
| 04 | `04-security-features-backfire` | `pcre.backtrack_limit` + `max_input_vars` → CSP bypass | medium | 8004 |
| 05 | `05-serialize-then-replace` | Length corruption in serialized data → object injection | medium | 8005 |
| 06 | `06-wordpress-placeholder-injection` | Double-prepare SQLi, and the placeholder escaping added to stop it (CVE-2017-18356) | hard | 8006 |
| 07 | `07-wordpress-column-truncation` | MySQL truncation + `maybe_unserialize()` | medium | 8007 |
| 08 | `08-wakeup-bypass` | Defeating `__wakeup()` guards (CVE-2016-7124, reference trick) | hard | 8008 |
| 09 | `09-windows-path-wildcards` | DOS device wildcards as a filename oracle | medium | 8009 |
| 10 | `10-avoracle` | Turning an antivirus verdict into a read primitive | hard | 8010 |
| 11 | `11-one-line-php` | `session.upload_progress` → LFI → RCE | hard | 8011 |
| 12 | `12-filter-chain-rce` | `php://filter` chains: RCE without controlling any file | hard | 8012 |
| 13 | `13-filter-chain-oracle` | Blind arbitrary file read from a PHP memory error | insane | 8013 |
| 14 | `14-phar-deserialization` | `phar://` turns any file operation into `unserialize()` | medium | 8014 |
| 15 | `15-mpdf-phar-killchain` | mPDF data-URI cache + `phar://` + Laravel POP chain | insane | 8015 |
| 16 | `16-php-cgi-argument-injection` | CVE-2012-1823 and its 2024 revival, CVE-2024-4577 | medium | 8016 |
| 17 | `17-php-fpm-underflow` | CVE-2019-11043: one NUL byte into full RCE | hard | 8017 |
| 18 | `18-ini-set-jailbreak` | Escaping `open_basedir` / `disable_functions` | medium | 8018 |
| 19 | `19-mysql-client-file-read` | A rogue MySQL server reading the client's files | medium | 8019 |
| 20 | `20-lfi-classic-toolkit` | The pre-filter-chain LFI toolkit: NUL truncation, `zip://`, loose base64, the `phpinfo()` race | hard | 8020 |
| 21 | `21-iconv-cve-2024-2961` | An out-of-bounds write in glibc's `iconv`, reached from a filter chain | insane | 8021 |
| 22 | `22-hashdos-fix-rce` | CVE-2012-0830: the hashDoS fix that became remote code execution | insane | 8022 |

`docs/ARTICLE-MAP.md` maps each section of the article to its lab and states,
for each one, whether the bug is reproduced for real or modelled by a shim.

## How to use a lab

1. Read the lab's `README.md` — scenario, goal, and progressive hints. No
   spoilers there.
2. Try it. Every lab is solvable with the tools you already have plus a text
   editor; nothing needs an internet connection once the image is built.
3. Stuck? The hints are graded. After that, `WRITEUP.md` has the full solution,
   the PHP internals behind it, and links to the original research.
4. `solve/solve.py` is the reference exploit — read it as source material, it is
   written to be read.

## Safety

These services are deliberately vulnerable. Several of them give unauthenticated
remote code execution *by design*.

* Every lab binds to `127.0.0.1` only. Do not change that.
* Do not run them on a machine that is exposed, shared, or that you care about.
* Lab 10 models an antivirus engine with a **fake** signature string, never the
  real EICAR test file, precisely so that nothing on your host reacts to it.
* Tear labs down when you are done: `make down` in the lab, or `make clean` at
  the top level.

## Credits

Every technique here belongs to the researchers who invented it. The article is
by **Orange Tsai**, and it credits — among many others — Adam Iwaniuk, Arseniy
Sharoglazov, Philippe Dourassov, Taoguang "Ryat" Chen, Paul Axe, Stefan Esser,
Ryo "icchy" Ichikawa, Yuhang "wupco" Wu, @loknop, @hashkitten, Rémi "Remsio"
Matasse, Charles "cfreal" Fol, Sam Thomas, Gynvael Coldwind, Emil "neex" Lerner,
the Eindbazen team, and Splitline NG. Each lab's writeup links back to their
original publications; go and read them.

The labs, the vulnerable code and the writeups in this repository are original
work built from the public descriptions of those techniques.

## Layout

```
docs/LAB-CONVENTIONS.md   the contract every lab follows
docs/ARTICLE-MAP.md       article section -> lab, and what is real vs modelled
scripts/verify-all.sh     build + exploit + tear down every lab
labs/NN-slug/             one lab: README, WRITEUP, compose, challenge, solve, verify
```
