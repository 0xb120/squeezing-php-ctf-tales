<?php
require __DIR__ . '/bootstrap.php';
global $wpdb_meta;

$meta_key   = isset($_GET['meta_key'])   ? substr((string) $_GET['meta_key'], 0, 128)   : '';
$meta_value = isset($_GET['meta_value']) ? substr((string) $_GET['meta_value'], 0, 512) : '';

wpl_header('meta tools');

echo '<h3>orphaned meta cleanup <small>(minipress-metatools 1.4.2)</small></h3>';
echo '<p>Dry run: list the products a <code>delete_metadata()</code> sweep would touch.</p>';
echo '<form method="get"><fieldset><legend>meta sweep</legend>';
echo '<label>meta_key <input name="meta_key" autocomplete="off" value="' . esc_html($meta_key) . '"></label>';
echo '<label>meta_value <input name="meta_value" autocomplete="off" value="' . esc_html($meta_value) . '"></label>';
echo '<p><button>preview</button></p></fieldset></form>';

if ($meta_key === '') {
    echo '<p>try <code>tools.php?meta_key=_thumbnail_id&amp;meta_value=42</code></p>';
    return;
}

list($sql, $object_ids) = wpl_meta_delete_preview($meta_key, $meta_value);

if ($sql === false) {
    echo '<p>wpdb::prepare() refused that input.</p>';
    return;
}

echo '<p>' . count($object_ids) . ' product(s) would be affected</p><ul>';
foreach ($object_ids as $oid) {
    echo '<li>product_id <code>' . esc_html($oid) . '</code></li>';
}
echo '</ul>';

if ($wpdb_meta->last_error !== '') {
    echo '<h4>sqlite error</h4><pre>' . esc_html($wpdb_meta->last_error) . '</pre>';
}

echo '<h4>$wpdb->last_query</h4><pre>' . esc_html($sql) . '</pre>';
