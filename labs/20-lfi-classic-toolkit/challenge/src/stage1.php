<?php
// ---------------------------------------------------------------------------
// EXHIBIT 1 - "the label printer".
//
// Labels are PHP templates in exhibits/.  The curator picks the template,
// we add the extension, so obviously nothing but a template can be printed.
// ---------------------------------------------------------------------------
include __DIR__ . '/_style.php';
$page = isset($_GET['page']) ? $_GET['page'] : 'exhibits/label-welcome';
echo "<h2>1 &mdash; the label printer</h2>\n";
echo '<p>template: <code>' . htmlspecialchars($page) . ".php</code></p>\n<pre>";
include($page . '.php');
echo "</pre>\n";
