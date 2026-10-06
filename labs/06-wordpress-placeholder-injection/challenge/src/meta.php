<?php
/*
 * minipress-metatools 1.4.2  --  "orphaned product meta cleanup"
 *
 * A bundled MiniPress plugin.  It was written against WordPress 4.8.1 and
 * its author never re-tested it after the 4.8.3 security release, so the
 * plugin ships its own database handle pinned to the old behaviour instead
 * (WPL_Meta_DB below).  The rest of MiniPress keeps using the current
 * $wpdb.
 *
 * The cleanup routine is modelled on WordPress' own delete_metadata(), the
 * function Slavco Mihajloski used to demonstrate "double preparing" in
 * August 2017.  wp-includes/meta.php:366 in 4.8.1:
 *
 *     if ( $delete_all ) {
 *         $value_clause = '';
 *         if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value ) {
 *             $value_clause = $wpdb->prepare( " AND meta_value = %s", $meta_value );
 *         }
 *
 *         $object_ids = $wpdb->get_col( $wpdb->prepare(
 *             "SELECT $type_column FROM $table WHERE meta_key = %s $value_clause",
 *             $meta_key ) );
 *     }
 *
 * The clause is prepared, and then the prepared clause is pasted into the
 * *query* argument of a second prepare().  MiniPress only runs the SELECT
 * half: the tool reports which products would lose a row.
 */

final class WPL_Meta_DB extends wpdb
{
    /* WordPress 4.8.1: prepare() is plain vsprintf(), _real_escape() does
       not hide percent signs, add_placeholder_escape() does not exist. */
    public $wp_version = '4.8.1';

    /* Reuse MiniPress' connection rather than opening a second one. */
    public function __construct(wpdb $core)
    {
        $this->pdo = $core->pdo;
    }
}

$wpdb_meta = new WPL_Meta_DB($wpdb);

function wpl_meta_install()
{
    global $wpdb, $wpdb_meta;

    $wpdb->query("CREATE TABLE IF NOT EXISTS wpl_productmeta (
        meta_id    INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        meta_key   TEXT,
        meta_value TEXT)");

    if (get_option('minipress_meta_seeded') !== false) {
        return;
    }

    $rows = array(
        array(1, '_thumbnail_id', '42'),
        array(1, '_price',        '19.00'),
        array(1, '_stock',        '12'),
        array(2, '_thumbnail_id', '43'),
        array(2, '_price',        '12.50'),
        array(2, '_stock',        '3'),
        array(3, '_thumbnail_id', '44'),
        array(3, '_price',        '24.00'),
        array(3, '_stock',        '0'),
        /* an orphan: the product was deleted, the meta row was not */
        array(9, '_thumbnail_id', '45'),
    );

    /*
     * The store licence lives in the meta table too, attached to no product.
     * Nothing in MiniPress ever prints a meta_value; the cleanup tool only
     * reports product ids.
     */
    $licence = @file_get_contents('/flag-sqli.txt');
    if ($licence === false) {
        /* Only reachable if the image was built wrong -- the flag file is
           read once at build time and deleted immediately afterwards. */
        error_log('minipress-metatools: /flag-sqli.txt missing, not seeding');
        return;
    }
    $rows[] = array(0, '_minipress_license', trim($licence));

    foreach ($rows as $r) {
        $wpdb->query($wpdb->prepare(
            "INSERT INTO wpl_productmeta (product_id, meta_key, meta_value) VALUES (%s, %s, %s)",
            $r[0], $r[1], $r[2]
        ));
    }

    update_option('minipress_meta_seeded', 1);
}

/**
 * Dry run of delete_metadata( $type, null, $meta_key, $meta_value, true ):
 * which products would be touched?
 *
 * Returns array($sql, $object_ids).
 */
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

    if (!is_string($sql)) {
        return array(false, array());
    }
    return array($sql, $wpdb_meta->get_col($sql));
}
