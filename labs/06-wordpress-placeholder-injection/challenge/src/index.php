<?php
require __DIR__ . '/bootstrap.php';
global $wpdb;

$rows = $wpdb->get_results("SELECT id, sku, title, content FROM wpl_products ORDER BY id ASC");

wpl_header('shop');
echo '<p>Search the catalogue by SKU. Results are cached in a transient.</p>';
echo '<form method="get" action="search.php"><fieldset><legend>find products</legend>';
echo '<label>sku list (comma separated) <input name="sku" value="TEE-01, MUG-02"></label>';
echo '<p><button>search</button></p></fieldset></form>';

echo '<h3>catalogue</h3><ul>';
foreach ($rows as $r) {
    echo '<li><code>' . esc_html($r['sku']) . '</code> &mdash; ' . esc_html($r['title']) . '</li>';
}
echo '</ul>';

/* theme footer: rendered lazily, flushed when the request ends */
$notice           = new WPL_Footer_Notice();
$notice->show     = true;
$notice->text     = new WPL_Template_Tag();
$notice->text->template = __DIR__ . '/partials/footer.txt';
$notice->text->vars     = array('{{count}}' => (string) count($rows));
