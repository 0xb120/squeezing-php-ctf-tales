<?php
/*
 * wp-lite.php
 *
 * A deliberately small re-implementation of the WordPress pieces this lab
 * needs.  Every function below mirrors the behaviour of its namesake in
 * WordPress trunk:
 *
 *   wp-includes/class-wpdb.php   -> wpdb::prepare(), wpdb::_real_escape(),
 *                                   wpdb::escape_by_ref(),
 *                                   wpdb::placeholder_escape(),
 *                                   wpdb::add_placeholder_escape(),
 *                                   wpdb::remove_placeholder_escape(),
 *                                   wpdb::query(), wpdb::get_col()
 *   wp-includes/functions.php    -> maybe_serialize(), maybe_unserialize(),
 *                                   is_serialized()
 *   wp-includes/option.php       -> get_option(), update_option(),
 *                                   delete_option(), get_transient(),
 *                                   set_transient()
 *   wp-includes/plugin.php       -> add_filter(), has_filter(), apply_filters()
 *
 * wpdb::prepare() exists here in BOTH of its historical shapes, selected per
 * handle by wpdb::$wp_version:
 *
 *   '4.8.3'  what WordPress shipped on 2017-10-31 and still ships today.
 *   '4.8.1'  what it replaced -- plain vsprintf() semantics, no percent
 *            escaping anywhere.  This is the version the "double preparing"
 *            technique was written against.
 *
 * See WRITEUP.md for the upstream source of each one and for the list of
 * simplifications.
 */

define('AUTH_SALT', 'j!9Q]3,2#uT+zM-k^wG7&b8F(rN5*vE0');
define('DAY_IN_SECONDS', 86400);
define('WPL_DB', '/var/lib/minipress/minipress.sqlite');

/* ------------------------------------------------------- hooks (plugin.php) */

$GLOBALS['wpl_filters'] = array();

function add_filter($tag, $callback, $priority = 10)
{
    $GLOBALS['wpl_filters'][$tag][$priority][] = $callback;
    return true;
}

function has_filter($tag, $callback)
{
    if (!isset($GLOBALS['wpl_filters'][$tag])) {
        return false;
    }
    foreach ($GLOBALS['wpl_filters'][$tag] as $priority => $callbacks) {
        foreach ($callbacks as $cb) {
            if ($cb === $callback) {
                return $priority;
            }
        }
    }
    return false;
}

function apply_filters($tag, $value)
{
    if (!isset($GLOBALS['wpl_filters'][$tag])) {
        return $value;
    }
    $buckets = $GLOBALS['wpl_filters'][$tag];
    ksort($buckets);
    foreach ($buckets as $callbacks) {
        foreach ($callbacks as $cb) {
            $value = call_user_func($cb, $value);
        }
    }
    return $value;
}

/* --------------------------------------------- serialization (functions.php) */

function is_serialized($data, $strict = true)
{
    if (!is_string($data)) {
        return false;
    }
    $data = trim($data);
    if ('N;' === $data) {
        return true;
    }
    if (strlen($data) < 4 || ':' !== $data[1]) {
        return false;
    }
    if ($strict) {
        $last = substr($data, -1);
        if (';' !== $last && '}' !== $last) {
            return false;
        }
    } else {
        $semicolon = strpos($data, ';');
        $brace     = strpos($data, '}');
        if (false === $semicolon && false === $brace) {
            return false;
        }
        if (false !== $semicolon && $semicolon < 3) {
            return false;
        }
        if (false !== $brace && $brace < 4) {
            return false;
        }
    }
    $token = $data[0];
    switch ($token) {
        case 's':
            if ($strict) {
                if ('"' !== substr($data, -2, 1)) {
                    return false;
                }
            } elseif (strpos($data, '"') === false) {
                return false;
            }
            // fall through -- exactly like WordPress does
        case 'a':
        case 'O':
        case 'E':
            return (bool) preg_match("/^{$token}:[0-9]+:/s", $data);
        case 'b':
        case 'i':
        case 'd':
            $end = $strict ? '$' : '';
            return (bool) preg_match("/^{$token}:[0-9.E+-]+;$end/", $data);
    }
    return false;
}

function maybe_serialize($data)
{
    if (is_array($data) || is_object($data)) {
        return serialize($data);
    }
    if (is_serialized($data, false)) {
        return serialize($data);
    }
    return $data;
}

function maybe_unserialize($data)
{
    if (is_serialized($data)) {         // "looks serialized" -> wake it up
        return @unserialize(trim($data));
    }
    return $data;
}

/* --------------------------------------------------------- wpdb (class-wpdb) */

class wpdb
{
    /** @var PDO */
    public $pdo;
    public $last_error = '';

    /*
     * Which wpdb::prepare() this handle runs.  '4.8.3' is the current
     * WordPress behaviour and the default for every MiniPress query;
     * '4.8.1' is the pre-fix behaviour and is used by the bundled
     * minipress-metatools plugin (see meta.php).
     */
    public $wp_version = '4.8.3';

    public function __construct($path)
    {
        $this->pdo = new PDO('sqlite:' . $path);
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /*
     * mysqli_real_escape_string() stand-in.  SQLite string literals only need
     * the single quote doubled; like MySQL, it does NOT touch '%'.
     *
     * WordPress 4.8.1 (wp-db.php:1168) returned the escaped string here.
     * WordPress 4.8.3 (wp-db.php:1168) ends the same method with
     * add_placeholder_escape(), so a value can never carry a live '%' into a
     * query string any more.  That one extra call is the whole fix.
     */
    public function _real_escape($string)
    {
        if (!is_scalar($string) && !is_null($string)) {
            return '';
        }
        $escaped = str_replace("'", "''", (string) $string);

        if ($this->wp_version === '4.8.1') {
            return $escaped;
        }
        return $this->add_placeholder_escape($escaped);
    }

    /* wp-db.php:1252 -- floats are passed through untouched. */
    public function escape_by_ref(&$string)
    {
        if (!is_float($string)) {
            $string = $this->_real_escape($string);
        }
    }

    public function prepare($query, ...$args)
    {
        if (is_null($query)) {
            return null;
        }
        // This is not meant to be foolproof -- but it will catch obviously
        // incorrect usage.  WordPress calls _doing_it_wrong() here.
        if (strpos($query, '%') === false) {
            return $query;
        }

        if ($this->wp_version === '4.8.1') {
            return $this->prepare_4_8_1($query, $args);
        }
        return $this->prepare_4_8_3($query, $args);
    }

    /*
     * wpdb::prepare() as it shipped up to and including WordPress 4.8.1
     * (wp-includes/wp-db.php:1291), transcribed line for line; only
     * _doing_it_wrong() and the func_get_args() dance are dropped.
     *
     *   https://github.com/WordPress/WordPress/blob/4.8.1/wp-includes/wp-db.php#L1291
     *
     * There is no percent escaping of any kind in here: $query is handed to
     * vsprintf() exactly as the caller assembled it, so any format specifier
     * that made it into the query string is a live format specifier.
     */
    private function prepare_4_8_1($query, $args)
    {
        // If args were passed as an array (as in vsprintf), move them up
        if (isset($args[0]) && is_array($args[0])) {
            $args = $args[0];
        }
        $query = str_replace("'%s'", '%s', $query);           // in case someone mistakenly already singlequoted it
        $query = str_replace('"%s"', '%s', $query);           // doublequote unquoting
        $query = preg_replace('|(?<!%)%f|', '%F', $query);    // Force floats to be locale unaware
        $query = preg_replace('|(?<!%)%s|', "'%s'", $query);  // quote the strings, avoiding escaped strings like %%s
        array_walk($args, array($this, 'escape_by_ref'));

        /*
         * Upstream is `return @vsprintf( $query, $args );`.  On PHP 5 and 7
         * the '@' swallowed the warning a malformed format string produced
         * and vsprintf() returned false; PHP 8 raises ValueError /
         * ArgumentCountError instead, so catching Throwable is how you get
         * the 4.8.1 *result* on a modern interpreter.
         */
        try {
            return vsprintf($query, $args);
        } catch (Throwable $e) {
            error_log('wpdb::prepare(4.8.1): ' . $e->getMessage());
            return false;
        }
    }

    /*
     * wpdb::prepare() as rewritten by the 4.8.3 security release
     * (wp-includes/wp-db.php:1292) and still the shape used today:
     *
     *   https://github.com/WordPress/WordPress/blob/4.8.3/wp-includes/wp-db.php#L1292
     *
     * Two things were added.  $allowed_format teaches prepare() what a real
     * placeholder looks like -- including positional ones such as %1$s -- so
     * that everything else can be escaped as a literal percent; and the
     * finished query is run through add_placeholder_escape().
     *
     * Dropped here: _doing_it_wrong(), wp_load_translations_early() and the
     * placeholder/argument count check (diagnostics only).
     */
    private function prepare_4_8_3($query, $args)
    {
        // If args were passed as an array (as in vsprintf), move them up.
        if (isset($args[0]) && is_array($args[0]) && count($args) === 1) {
            $args = $args[0];
        }

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

        $query = str_replace("'%s'", '%s', $query);              // Strip any existing single quotes.
        $query = str_replace('"%s"', '%s', $query);              // Strip any existing double quotes.
        $query = preg_replace('/(?<!%)%s/', "'%s'", $query);     // Quote the strings, avoiding escaped strings like %%s.
        $query = preg_replace("/(?<!%)(%($allowed_format)?f)/", '%\\2F', $query);   // Force floats to be locale unaware.
        $query = preg_replace("/%(?:%|$|(?!($allowed_format)?[sdF]))/", '%%\\1', $query);  // Escape any unescaped percents.

        array_walk($args, array($this, 'escape_by_ref'));

        try {
            $query = vsprintf($query, $args);
        } catch (Throwable $e) {
            error_log('wpdb::prepare(4.8.3): ' . $e->getMessage());
            return false;
        }

        return $this->add_placeholder_escape($query);
    }

    public function placeholder_escape()
    {
        static $placeholder;

        if (!$placeholder) {
            $salt        = defined('AUTH_SALT') && AUTH_SALT ? AUTH_SALT : (string) rand();
            $placeholder = '{' . hash_hmac('sha256', uniqid($salt, true), $salt) . '}';
        }

        if (false === has_filter('query', array($this, 'remove_placeholder_escape'))) {
            add_filter('query', array($this, 'remove_placeholder_escape'), 0);
        }

        return $placeholder;
    }

    public function add_placeholder_escape($query)
    {
        return str_replace('%', $this->placeholder_escape(), $query);
    }

    public function remove_placeholder_escape($query)
    {
        return str_replace($this->placeholder_escape(), '%', $query);
    }

    public function query($sql)
    {
        if (!is_string($sql)) {                 // prepare() bailed
            $this->last_error = 'wpdb::prepare() returned no query';
            return false;
        }
        $sql = apply_filters('query', $sql);
        try {
            $this->last_error = '';
            return $this->pdo->exec($sql);
        } catch (PDOException $e) {
            $this->last_error = $e->getMessage();
            error_log('wpdb: ' . $e->getMessage());
            return false;
        }
    }

    public function get_results($sql)
    {
        if (!is_string($sql)) {                 // prepare() bailed
            $this->last_error = 'wpdb::prepare() returned no query';
            return array();
        }
        $sql = apply_filters('query', $sql);
        try {
            $this->last_error = '';
            return $this->pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->last_error = $e->getMessage();
            error_log('wpdb: ' . $e->getMessage());
            return array();
        }
    }

    public function get_var($sql)
    {
        $rows = $this->get_results($sql);
        if (!$rows) {
            return null;
        }
        return array_values($rows[0])[0];
    }

    /* wpdb::get_col() -- the first column of every row, as strings. */
    public function get_col($sql)
    {
        $out = array();
        foreach ($this->get_results($sql) as $row) {
            $out[] = array_values($row)[0];
        }
        return $out;
    }
}

$wpdb = new wpdb(WPL_DB);

/* ------------------------------------------------------- options / transients */

function get_option($name, $default = false)
{
    global $wpdb;
    $value = $wpdb->get_var(
        $wpdb->prepare("SELECT option_value FROM wpl_options WHERE option_name = %s", $name)
    );
    if ($value === null) {
        return $default;
    }
    return maybe_unserialize($value);
}

function update_option($name, $value)
{
    global $wpdb;
    $serialized = maybe_serialize($value);
    $exists     = $wpdb->get_var(
        $wpdb->prepare("SELECT option_id FROM wpl_options WHERE option_name = %s", $name)
    );
    if ($exists === null) {
        return $wpdb->query($wpdb->prepare(
            "INSERT INTO wpl_options (option_name, option_value) VALUES (%s, %s)",
            $name, $serialized
        ));
    }
    return $wpdb->query($wpdb->prepare(
        "UPDATE wpl_options SET option_value = %s WHERE option_name = %s",
        $serialized, $name
    ));
}

function delete_option($name)
{
    global $wpdb;
    return $wpdb->query($wpdb->prepare("DELETE FROM wpl_options WHERE option_name = %s", $name));
}

function set_transient($key, $value, $ttl)
{
    update_option('_transient_timeout_' . $key, time() + $ttl);
    update_option('_transient_' . $key, $value);
}

function get_transient($key)
{
    $timeout = get_option('_transient_timeout_' . $key);
    if ($timeout !== false && (int) $timeout < time()) {
        delete_option('_transient_timeout_' . $key);
        delete_option('_transient_' . $key);
        return false;
    }
    return get_option('_transient_' . $key, false);
}
