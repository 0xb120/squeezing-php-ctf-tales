<?php
require __DIR__ . '/lib.php';

$user = current_user();
if ($user === null) {
    http_response_code(403);
    exit;
}

$file = THUMBS . '/' . md5($user) . '.png';

if (!is_file($file)) {
    $c       = new ThumbnailCache();
    $c->path = $file;
    $c->data = new RemoteImage();
    $c->data->src = __DIR__ . '/assets/default.png';
    unset($c);                 // destructor flushes the cache entry
}

header('Content-Type: image/png');
header('Cache-Control: no-store');
readfile($file);
