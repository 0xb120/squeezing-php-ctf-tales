<?php
require __DIR__ . '/bootstrap.php';
global $wpdb;

$sku = isset($_GET['sku']) ? substr((string) $_GET['sku'], 0, 256) : '';

wpl_header('search');

if ($sku === '') {
    echo '<p>usage: <code>search.php?sku=TEE-01,MUG-02</code></p>';
    return;
}

$transient = 'product_query_' . md5($sku);
$q         = get_transient($transient);
$cached    = true;

if (!($q instanceof WPL_Query)) {
    $cached = false;

    $skus = array_map('trim', explode(',', $sku));
    $in   = implode(', ', array_fill(0, count($skus), '%s'));

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
}

echo '<p>' . ($cached ? 'served from the transient cache' : 'fresh query &mdash; cached for 30 days') . '</p>';
echo '<p>' . esc_html($q->found) . ' product(s) found</p>';

foreach (is_array($q->posts) ? $q->posts : array() as $p) {
    if (!($p instanceof WPL_Post)) {
        continue;
    }
    echo '<h3>' . esc_html($p->post_title) . '</h3><p>' . esc_html($p->post_content) . '</p>';
}

echo '<h4>$q-&gt;request</h4><pre>' . esc_html($q->request) . '</pre>';

$notice                 = new WPL_Footer_Notice();
$notice->show           = true;
$notice->text           = new WPL_Template_Tag();
$notice->text->template = __DIR__ . '/partials/footer.txt';
$notice->text->vars     = array('{{count}}' => esc_html($q->found));
