# 18 — PHPlayground: `ini_set()` walks out of the jail

A "safe" PHP playground that `eval()`s your code behind `disable_functions`
and `open_basedir`. The flag is in `/flag.txt`, outside the jail. Get it.

## Article reference

Recreates the *Honorable Mention* entry in "The Art of PHP — My CTF Journey and
Untold Stories!" by Orange Tsai (Phrack #72): *"All those creative tricks for
restricted environment jailbreaks, like abusing `ini_set()` [92] or
`imap_open()` [93]."*

- [92] Blaklis — InsomniHack Finals 2019, *Phuck3*:
  <https://github.com/Blaklis/my-challenges/tree/master/phuck3>
- [93] PHP bug #76428 — *Command execution through `imap_open`* (CVE-2018-19518):
  <https://bugs.php.net/bug.php?id=76428>

## Difficulty / category

Medium — web / PHP restricted-environment jailbreak.

## Run it

```sh
make up        # build + start; playground on http://127.0.0.1:8018/
make solve     # run the automated exploit (stage 1: open_basedir escape)
make verify    # build -> exploit -> assert flag -> tear down
make down      # stop and clean up
```

Optional command-execution stage (see the writeup):

```sh
make preload   # compile the LD_PRELOAD payload (solve/hook.so)
make rce       # stage 1 + stage 2 (RCE despite disable_functions)
```

## Your goal

The playground runs your PHP with `open_basedir` pinned to
`/var/www/sandbox/` and with every obvious command-execution function stripped
by `disable_functions`. A plain `file_get_contents('/flag.txt')` is refused.
Convince PHP to read a file that lives outside the jail.

## Hints

<details>
<summary>Hint 1</summary>

`open_basedir` is a runtime-writable directive (`PHP_INI_ALL`). What does the
runtime handler actually check before it lets you *change* it? It only compares
the new value against the current one — and it does that comparison relative to
your current working directory.
</details>

<details>
<summary>Hint 2</summary>

`mkdir()` and `chdir()` are not on the ban list. If your cwd is *below* the
jail root, a relative `open_basedir` re-expands against the cwd on every check.
Move down one directory, relax the jail by one level, then walk back up with
`chdir('..')`.
</details>

<details>
<summary>Hint 3</summary>

Newer PHP refuses an `open_basedir` value whose first path component is
literally `..`. `./..` is not `..` to that check, but expands to the same
place. After that, each `chdir('..')` drags the relative jail up with you until
you reach `/`.
</details>

## What you will learn

- Why the PHP manual says `open_basedir` "is just an extra safety net, that is
  in no way comprehensive, and can therefore not be relied upon when security
  is needed."
- The difference between `PHP_INI_ALL`, `PHP_INI_PERDIR` and `PHP_INI_SYSTEM`,
  and why `php_admin_value` vs `php_value` in Apache decides whether
  `open_basedir` can be rewritten from the sandbox at all.
- How the runtime `open_basedir` tightening check (`OnUpdateBaseDir`) can be
  defeated by relative paths, and how PHP 8.3 fixed it.
- That `disable_functions` protects only the names on the list: `putenv()` +
  `mail()` + `LD_PRELOAD` still gets you a shell.
