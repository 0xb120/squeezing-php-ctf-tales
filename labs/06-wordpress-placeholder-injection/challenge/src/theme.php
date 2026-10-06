<?php
/*
 * MiniPress "storefront" theme + the query objects the shop plugin caches.
 */

/* The object the shop plugin stores in a transient (cf. WP_Query). */
class WPL_Query
{
    public $request = '';      // the SQL that was actually run
    public $found   = 0;
    public $posts   = array(); // WPL_Post[]
}

class WPL_Post
{
    public $ID           = 0;
    public $post_title   = '';
    public $post_content = '';
}

/* Theme helper: renders a partial, substituting {{token}} style variables. */
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

/* Theme helper: prints a note in the page footer once the request is over. */
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

function wpl_install()
{
    global $wpdb;

    $wpdb->query("CREATE TABLE IF NOT EXISTS wpl_options (
        option_id    INTEGER PRIMARY KEY AUTOINCREMENT,
        option_name  TEXT UNIQUE,
        option_value TEXT)");

    $wpdb->query("CREATE TABLE IF NOT EXISTS wpl_products (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        sku     TEXT,
        title   TEXT,
        content TEXT)");

    if (get_option('minipress_seeded') === false) {
        foreach (array(
            array('TEE-01',  'Phrack T-Shirt',  'Black, 100% cotton, smells faintly of ozone.'),
            array('MUG-02',  'Segfault Mug',    'Holds 0x200 millilitres. Dishwasher safe.'),
            array('CAP-03',  'Null Byte Cap',   'One size terminates all.'),
        ) as $row) {
            wpl_add_product($row[0], $row[1], $row[2]);
        }
        update_option('minipress_seeded', 1);
    }
}

function wpl_add_product($sku, $title, $content)
{
    global $wpdb;
    $wpdb->query($wpdb->prepare(
        "INSERT INTO wpl_products (sku, title, content) VALUES (%s, %s, %s)",
        $sku, $title, $content
    ));
    return (int) $wpdb->pdo->lastInsertId();
}

function esc_html($value)
{
    if (is_object($value) && !method_exists($value, '__toString')) {
        return '(object ' . get_class($value) . ')';
    }
    if (is_array($value)) {
        return '(array)';
    }
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function wpl_header($title)
{
    echo "<!doctype html><meta charset=utf-8><title>MiniPress - $title</title>";
    echo "<style>body{font:14px/1.6 monospace;max-width:56em;margin:2em auto;padding:0 1em}";
    echo "pre{white-space:pre-wrap;word-break:break-all;background:#f4f4f4;padding:.6em}";
    echo "input,textarea{font:inherit;width:100%}fieldset{margin:1em 0}</style>";
    echo "<h1>MiniPress</h1><p><a href='index.php'>shop</a> | <a href='product.php'>add product</a>";
    echo " | <a href='tools.php'>meta tools</a></p>";
}
