<?php
require __DIR__ . '/bootstrap.php';

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $sku     = isset($_POST['sku'])     ? (string) $_POST['sku']     : '';
    $title   = isset($_POST['title'])   ? (string) $_POST['title']   : '';
    $content = isset($_POST['content']) ? (string) $_POST['content'] : '';

    if (!preg_match('/^[A-Za-z0-9_-]{1,32}$/', $sku)) {
        $msg = '<p>sku must be 1-32 chars of [A-Za-z0-9_-].</p>';
    } elseif (strlen($title) > 255) {
        $msg = '<p>title too long (255 max).</p>';
    } elseif (strlen($content) > 1024) {
        $msg = '<p>content too long (1024 max).</p>';
    } else {
        $id  = wpl_add_product($sku, $title, $content);
        $msg = '<p>added product id=' . (int) $id . '</p>';
    }
}

wpl_header('add product');
echo $msg;
echo '<form method="post"><fieldset><legend>new product</legend>';
echo '<label>sku <input name="sku" autocomplete="off"></label>';
echo '<label>title <input name="title" autocomplete="off"></label>';
echo '<label>description <textarea name="content" rows="5"></textarea></label>';
echo '<p><button>add</button></p></fieldset></form>';
