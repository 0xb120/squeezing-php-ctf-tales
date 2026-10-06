<?php
// ---------------------------------------------------------------------------
// EXHIBIT 4 - "the curator's desk".
//
// Diagnostics for the museum IT contractor.  Locked behind the curator key.
// The ?run= helper loads an internal diagnostic script; it refuses anything
// with a dot in it, so it cannot walk out of the tree or pick up a .php,
// a .png or a .card that somebody uploaded.
// ---------------------------------------------------------------------------
$want = trim(@file_get_contents('/opt/museum/curator.hash'));
$key  = isset($_REQUEST['key']) ? $_REQUEST['key'] : '';

if ($want === '' || !hash_equals($want, hash('sha256', $key))) {
    header('HTTP/1.0 403 Forbidden');
    header('Content-Type: text/plain');
    die("the curator's desk is locked.\nkey = <fragment1>:<fragment2>:<fragment3>\n");
}

if (isset($_GET['run'])) {
    $path = $_GET['run'];
    if (strpos($path, '.') !== false) {
        header('Content-Type: text/plain');
        die("diagnostic paths may not contain a dot\n");
    }
    include($path);
    exit;
}

phpinfo();
