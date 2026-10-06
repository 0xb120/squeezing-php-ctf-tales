<?php
require __DIR__ . '/lib/gallery.php';
header('Content-Type: text/plain');

function reject($why)
{
    http_response_code(400);
    exit("rejected: $why\n");
}

if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
    reject('no file');
}
$tmp = $_FILES['image']['tmp_name'];
if (filesize($tmp) > 200 * 1024) {
    reject('too big');
}

// 1. extension whitelist
$ext = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));
$allowed = ['gif' => IMAGETYPE_GIF, 'jpg' => IMAGETYPE_JPEG, 'jpeg' => IMAGETYPE_JPEG];
if (!isset($allowed[$ext])) {
    reject('extension must be .gif/.jpg/.jpeg');
}

// 2. magic bytes
$head = file_get_contents($tmp, false, null, 0, 6);
$magic = ($head === 'GIF87a' || $head === 'GIF89a') ? IMAGETYPE_GIF
       : (substr($head, 0, 3) === "\xFF\xD8\xFF" ? IMAGETYPE_JPEG : null);
if ($magic === null) {
    reject('not an image (magic bytes)');
}

// 3. the real parser has to agree with both of the above
$info = @getimagesize($tmp);
if ($info === false || $info[2] !== $magic || $info[2] !== $allowed[$ext]) {
    reject('not an image (getimagesize)');
}

$name = hash_file('sha1', $tmp) . '.' . $ext;
if (!move_uploaded_file($tmp, UPLOAD_DIR . '/' . $name)) {
    reject('could not store the file');
}
echo "stored: uploads/$name\n";
echo "size:   {$info[0]}x{$info[1]}\n";
