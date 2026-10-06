# 07 — A Pile of Poo in the usermeta Table

A blog engine that stores profile fields "type-agnostically", a MySQL that was
never told to be strict, and a column that is one byte per character too narrow.

## Article reference

Recreates the opening of chapter 2 of *"The Art of PHP - My CTF Journey and
Untold Stories!"* (Orange Tsai, Phrack #72), **2. One `unserialize()` to Rule
Them All** — the part where WordPress happily re-hydrates anything coming out of
the database that "looks serialized", so that a *storage* bug becomes an object
injection.

Based on:

* Stefan Esser, *MySQL and SQL Column Truncation Vulnerabilities* (2008) —
  reference [23] of the article.
* Tom Van Goethem, *WordPress <= 3.6.1 PHP Object Injection* (2013),
  <https://tom.vg/2013/09/wordpress-php-object-injection/> — reference [24], the
  Pile of Poo Emoji (U+1F4A9) variant.
* Simon Scannell / Sonar, *WordPress < 5.8.3 Object Injection* — reference [22].

## Difficulty

**medium** — category: PHP object injection / storage-layer type confusion.

## Run it

```sh
make up          # http://127.0.0.1:8007/
make solve       # run the exploit in a container
make verify      # build, exploit, assert the flag, tear down
make down
```

The stack is a PHP 8.1.34 + Apache front end talking to MySQL 5.7.44 that runs
with an **empty `sql_mode`** — the way a lot of shared hosting still does.

## Your goal

`inkpress` lets you edit a profile. The bio and the display preferences are
stored in a WordPress-shaped `usermeta` table by a helper pair that serializes
containers on the way in and restores them on the way out. The developers were
burned by an object-injection advisory once already and shipped a fix so that a
plain string can *never* come back out of the database as an object.

Their fix is correct — for the value the application hands to the database.
Get the database to hand something else back, build an object graph out of the
two harmless-looking classes in `gadgets.php`, and read `/flag.txt`. The flag is
`PHRACK{...}`.

## Hints

<details>
<summary>Hint 1</summary>

Read `looks_serialized()` in `challenge/src/meta.php` very carefully, then read
`update_user_meta()`. The anti-injection fix is a *suffix*. Which single byte of
the stored value decides whether `unserialize()` is ever called?

</details>

<details>
<summary>Hint 2</summary>

`sql_mode` is empty, so MySQL never refuses data — it *adjusts* it and raises a
warning nobody reads. Look at the column definition in
`challenge/db/01-schema.sql`: both its declared length and its character set are
interesting, and each of them gives you a way to make the server drop bytes off
the end of your value.

</details>

<details>
<summary>Hint 3</summary>

`unserialize()` only needs the value to *start* with a complete serialized
object; it does not care what follows. So put your object first, make the server
delete everything after it, and the application's suffix disappears with it.
`ActivityLog::__destruct()` string-casts everything in `$entries`.

</details>

## What you will learn

* How WordPress' `maybe_unserialize()` / `is_serialized()` pair turns "a string
  in a database column" into an `unserialize()` sink, and why a trailing-byte
  check is a terrible security boundary.
* MySQL column truncation, both flavours: over-length values against a
  `VARCHAR(n)`, and 4-byte UTF-8 characters against a 3-byte `utf8` (utf8mb3)
  column — and what `sql_mode = ''` has to do with it.
* Building a two-hop POP chain (`__destruct` → string cast → `__toString`) out
  of classes that look completely benign on their own.
* Why "sanitise on write" loses to a storage layer that silently rewrites what
  you wrote.
