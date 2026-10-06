# 06 — WordPress Placeholder Injection

Two flags, one story. First the mistake: `wpdb::prepare()` used to be a bare
`vsprintf()`, so preparing an already prepared string handed the attacker
sprintf's argument swapping. Then the fix: WordPress now hides every `%`
behind a 66-byte random token and puts it back just before the query runs —
serialize something in between and the length prefix lies by 65 bytes per
percent sign.

## Article reference

Recreates the second half of section **2.1 "The Serialize-Then-Replace
Pattern"** of *"The Art of PHP - My CTF Journey and Untold Stories!"* by
**Orange Tsai** (Phrack #72), chapter 2 *"One unserialize() to Rule Them All"*
— both the "Prepare Twice, Inject Once!" box and the "dirty fix" it provoked.

Based on:

* **Slavco Mihajloski, "WordPress SQLi"** (reference [27]), 2017-08-22 — the
  "double preparing" problem that made WordPress 4.8.3 introduce
  `wpdb::placeholder_escape()`. **Stage 2** is this bug.
  <https://web.archive.org/web/20191219110854/https://medium.com/websec/wordpress-sqli-bbb2afcc8e94>
* **Karim El Ouerghemmi & Slavco Mihajloski, "Privilege Escalation in 2.3M
  WooCommerce Shops"** (reference [28]), RIPS, 2018-02-26 — **CVE-2017-18356**,
  the real-world instance of the primitive the fix created. **Stage 1** is this
  bug.
  <https://web.archive.org/web/20200127173002/https://blog.ripstech.com/2018/woocommerce-php-object-injection/>

## Difficulty / category

**hard** — web / PHP object injection / SQL injection / WordPress internals.

> **Emulation notice**
>
> This lab does **not** run WordPress. `challenge/src/wp-lite.php` is a ~450
> line re-implementation of the handful of WordPress pieces the two bugs need.
>
> **Faithful** (behaviour copied 1:1 from WordPress — see WRITEUP.md for the
> upstream file, version and line of each):
> `wpdb::prepare()` in **both** of its historical shapes — the 4.8.1 one
> (plain `vsprintf()`, quote-normalisation, `%f`→`%F`, `(?<!%)%s`→`'%s'`, no
> percent escaping at all) and the 4.8.3 one (`$allowed_format`, "escape any
> unescaped percents", final `add_placeholder_escape()`), including positional
> specifiers such as `%1$s`;
> `wpdb::_real_escape()` / `wpdb::escape_by_ref()` in both shapes;
> `wpdb::placeholder_escape()` returning `'{' . hash_hmac('sha256', uniqid($salt, true), $salt) . '}'`
> from a per-process `static`; `add_placeholder_escape()` /
> `remove_placeholder_escape()` as plain `str_replace()`;
> `remove_placeholder_escape()` registered on the `query` filter at priority 0
> and applied to the *whole* SQL string inside `wpdb::query()`;
> `maybe_serialize()` / `maybe_unserialize()` / `is_serialized()`;
> `get_option()` / `update_option()` / `get_transient()` / `set_transient()`
> storing the serialized blob through `$wpdb`;
> the `delete_metadata()` "delete for every object" branch that stage 2
> attacks, copied from `wp-includes/meta.php`.
>
> **Divergence you must know about**: in real WordPress the two stages
> **cannot coexist**. `add_placeholder_escape()` is precisely what makes
> double preparing harmless, so a ≥ 4.8.3 install is immune to stage 2, and a
> ≤ 4.8.2 install has no placeholder token for stage 1 to corrupt. MiniPress
> therefore carries both versions of `wpdb::prepare()` at once, selected per
> database handle by `wpdb::$wp_version`: the site runs the 4.8.3 one, and the
> bundled `minipress-metatools` plugin ships its own handle pinned to `'4.8.1'`
> (plugins really did vendor old core code, and plenty of sites never took the
> 4.8.3 update). Each branch is a line-for-line transcription of its release —
> the only thing invented is the switch between them.
>
> **Residual cross-stage shortcut**: stage 1 hands you an arbitrary file read
> as `www-data`, and `www-data` must be able to write
> `/var/lib/minipress/minipress.sqlite`. A player who has finished stage 1 can
> therefore dump that database file and read the stage-2 flag out of it without
> injecting anything. Two stages in one container cannot be fully isolated when
> one of them *is* an arbitrary file read; deleting the flag file at build time
> is as far as that can be pushed. Do stage 2 properly — it is the point.
>
> **Simplified** (and why):
> the storage engine is **SQLite** instead of MySQL — the bugs live entirely in
> PHP string handling, and the only MySQL-specific behaviour involved is
> `mysqli_real_escape_string()`, which (like the SQLite `''` doubling used
> here) does not escape `%`. This keeps the lab to a single container with no
> database wait loop. `--` comments to end of line in both engines.
> `prepare()` understands `%s`, `%d`, `%f` and positional variants but not
> `%i` identifier placeholders; there are no `_doing_it_wrong()` diagnostics
> and no placeholder/argument count check; the hook system is 30 lines; and
> there is no post/user/capability model — the "shop manager" role WooCommerce
> required is simply "anyone can add a product", and stage 2 needs no login at
> all where Slavco's original needed an author account.
> On PHP 8 a malformed format string raises `ValueError` instead of emitting a
> warning, so upstream's `@vsprintf()` is reproduced with a `try`/`catch` that
> returns `false` — the PHP 5/7 result.
>
> Everything that produces the two vulnerabilities is real WordPress
> behaviour. Stage 1 is still present in current WordPress: the 4.8.3
> placeholder escape is working exactly as designed here.

## Run it

```sh
make up          # http://127.0.0.1:8006/
make solve       # run the reference exploit (both stages)
make verify      # build + run + exploit + assert + tear down
make down
make logs
```

## Your goal

**MiniPress** is a toy shop. You can add products, you can search the
catalogue by SKU, and there is a bundled maintenance plugin that previews
which products an orphaned-meta sweep would touch.

1. The search caches the *whole* query object in a transient for thirty days —
   the same thing WooCommerce's `[products]` shortcode used to do with
   `WP_Query`. The search page prints the SQL it ran. Look at it closely.
   **Read `/flag.txt`** (owned `root:www-data`, mode `0640`).

2. The maintenance plugin at `tools.php` is older than the rest of the shop
   and it never prints a `meta_value` — only the product ids it matched. One
   of the rows in that table is the store licence key. **Make the tool hand it
   to you.** There is no `flag-sqli.txt` in the running container: it is read
   into the database when the image is built and deleted in the same step, so
   the flag is a `wpl_productmeta` row and the tool is the way to it.

The two goals are independent; either can be solved first.

## Hints

### Stage 1 — the transient

<details>
<summary>Hint 1</summary>

Search for something containing a `%` and read the `$q->request` box at the
bottom of the page. That 66-character `{...}` blob is
`wpdb::placeholder_escape()`: since WordPress 4.8.3, `prepare()` replaces every
`%` in the finished query with a random per-request token, and puts it back
with `remove_placeholder_escape()` on the `query` filter, *immediately before
the query executes*.

Now ask: what happens to a token that is sitting inside a value which is being
*written* to the database?
</details>

<details>
<summary>Hint 2</summary>

`set_transient()` → `update_option()` → `maybe_serialize()` → `$wpdb->update()`
→ `prepare()` → `$wpdb->query()` → the `query` filter.

`serialize()` runs **before** the filter. The `s:<n>:` prefix therefore counts
66 bytes for each token, and the row that actually lands in the database counts
one. 66 − 1 = 65 bytes of drift per `%`, and nothing fixes the prefix.

The cached object is `WPL_Query { $request, $found, $posts }` and `$posts`
holds `WPL_Post { $ID, $post_title, $post_content }`. Which fields do you
control?
</details>

<details>
<summary>Hint 3</summary>

The distance from the end of the real `request` value to the first byte of a
product's `post_content` must be an exact multiple of **65**. You have two
knobs: how many `%` you put in the search (that is the multiplier) and how long
the product title is (that is the fine adjustment). Product IDs are
`AUTOINCREMENT`, so you can predict the next one.

Two classes in `theme.php` do the rest: one has `__destruct()`, one has
`__toString()`.
</details>

### Stage 2 — the maintenance plugin

<details>
<summary>Hint 4</summary>

`tools.php` prints the query it ran. Put a `%` in `meta_value` and compare
that box with what the search page shows you for the same character. They do
not agree — the two pages are not talking to the same database handle.

Read the header of `challenge/src/meta.php`: the plugin says which WordPress
release it was written against.
</details>

<details>
<summary>Hint 5</summary>

The plugin builds its `WHERE` in two steps:

```php
$value_clause = $wpdb->prepare( ' AND meta_value = %s', $meta_value );
$sql          = $wpdb->prepare( "SELECT ... WHERE meta_key = %s $value_clause", $meta_key );
```

The output of the first call is the *format string* of the second. What does
`vsprintf()` do with a format string an attacker wrote? Note that
`prepare()` rewrites `%s` into `'%s'` — including any `%s` that arrived in the
query rather than in the arguments.

The exact payload shape is in the Phrack article, in the box titled
"Prepare Twice, Inject Once!".
</details>

<details>
<summary>Hint 6</summary>

Two constraints when you build the injected SQL:

* the value is still escaped by `_real_escape()` before it is formatted, so
  every `'` you send comes out doubled. Your injection has to be quote-free —
  `char(72,101,...)` builds a string literal without one.
* the query only ever selects one column, and the page only prints that
  column. `OR 1=1` proves you are in, but it will only ever give you product
  ids.
</details>

## What you will learn

* Why `wpdb::prepare()` was never safe to nest, and what "double preparing"
  actually does: `%1$%s` becomes `%1$'%s'`, sprintf reads the `'` as a *padding
  flag*, and the quote that should have closed the value is re-emitted after
  it instead.
* How `sprintf()` argument swapping (`%1$s`) turns a format string into an SQL
  injection primitive even when every value was escaped correctly.
* What `wpdb::placeholder_escape()` actually does, why WordPress 4.8.3 added
  it, and why it is not a bug in itself.
* How that *defensive* escape/unescape round trip becomes an object-injection
  primitive as soon as `serialize()` happens between the two halves.
* Why "cache the whole `WP_Query` in a transient" — advice that used to be in
  the WordPress codex — was a remote object-injection sink (CVE-2017-18356).
* `maybe_unserialize()` / `is_serialized()`: WordPress will happily
  `unserialize()` anything that merely *looks* serialized, and `is_serialized()`
  never validates interior lengths.
* Computing a length-corruption offset that depends on data you only partially
  control (auto-increment IDs, digit counts of length prefixes).
* That a security fix is a design change, and design changes have their own
  attack surface.
