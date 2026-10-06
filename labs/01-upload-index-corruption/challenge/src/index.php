<?php
/*
 * PixelDrop - a tiny artwork drop box.
 *
 * Two intake paths, because the desktop uploader we shipped in 2009 posts a
 * whole batch at once and the browser form posts a single file.
 */

$UPLOAD_DIR = '/var/www/html/uploads';
$MAX_BYTES  = 65536;
$ALLOWED    = array('png', 'jpg', 'gif');

function name_ok($name)
{
    global $ALLOWED;

    if (!is_string($name) || $name === '') {
        return false;
    }
    if (basename($name) !== $name) {          /* no directory components */
        return false;
    }
    if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $name)) {
        return false;
    }
    $dot = strrpos($name, '.');
    if ($dot === false) {
        return false;
    }
    return in_array(strtolower(substr($name, $dot + 1)), $ALLOWED, true);
}

function size_ok($size)
{
    global $MAX_BYTES;

    if (!is_scalar($size) || !is_numeric($size)) {
        return false;
    }
    return ($size > 0 && $size <= $MAX_BYTES);
}

/*
 * $strict is set for the single-file browser form. The batch path predates
 * is_uploaded_file() being part of our review checklist.
 */
function accept_one($tmp, $name, $size, $err, $strict)
{
    global $UPLOAD_DIR;

    if (!is_scalar($err) || $err != UPLOAD_ERR_OK) {
        return 'skipped: upload error';
    }
    if (!name_ok($name)) {
        return 'rejected: only ' . implode('/', $GLOBALS['ALLOWED']) . ' artwork is accepted';
    }
    if (!size_ok($size)) {
        return 'rejected: bad size';
    }
    if (!is_scalar($tmp) || $tmp === '') {
        return 'rejected: empty payload';
    }

    $dest = $UPLOAD_DIR . '/' . $name;

    if ($strict) {
        if (!is_uploaded_file($tmp)) {
            return 'rejected: not an uploaded file';
        }
        if (!move_uploaded_file($tmp, $dest)) {
            return 'failed: could not store the file';
        }
    } else {
        /* legacy batch intake */
        if (!@copy($tmp, $dest)) {
            return 'failed: could not store the file';
        }
    }
    return 'stored as uploads/' . $name;
}

function pick($bag, $key)
{
    if (is_array($bag) && array_key_exists($key, $bag)) {
        return $bag[$key];
    }
    return null;
}

$report = array();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['file'])) {
        $report[] = 'no "file" field in this request';
    } else {
        $f = $_FILES['file'];

        if (!is_array($f['tmp_name'])) {
            /* single drop from the browser form */
            $report[] = accept_one($f['tmp_name'], $f['name'], $f['size'], $f['error'], true);
        } else {
            /* batch drop from the desktop uploader */
            foreach ($f['tmp_name'] as $k => $tmp) {
                $report[] = '[' . $k . '] ' . accept_one(
                    $tmp,
                    pick($f['name'], $k),
                    pick($f['size'], $k),
                    pick($f['error'], $k),
                    false
                );
            }
        }
    }
}

$gallery = array();
foreach (scandir($UPLOAD_DIR) as $entry) {
    if ($entry !== '.' && $entry !== '..') {
        $gallery[] = $entry;
    }
}
sort($gallery);

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PixelDrop</title>
<style>
body{font:14px/1.5 monospace;max-width:52em;margin:2em auto;padding:0 1em;background:#101014;color:#d8d8dc}
h1{font-size:1.4em;letter-spacing:.08em}a{color:#7ec7ff}
.box{border:1px solid #333;padding:1em;margin:1em 0;background:#17171d}
.rep{color:#ffd479}
small{color:#888}
</style>
</head>
<body>
<h1>PixelDrop</h1>
<p><small>artwork drop box &mdash; png / jpg / gif, 64 KiB max</small></p>

<div class="box">
<form method="post" enctype="multipart/form-data">
  <input type="hidden" name="MAX_FILE_SIZE" value="65536">
  <input type="file" name="file">
  <button type="submit">drop it</button>
</form>
<p><small>Batch mode is still supported for the legacy desktop uploader:
post several <code>file[]</code> parts in one request.</small></p>
</div>

<?php if ($report): ?>
<div class="box">
<strong>intake report</strong>
<ul>
<?php foreach ($report as $line): ?>
  <li class="rep"><?php echo htmlspecialchars($line, ENT_QUOTES, 'UTF-8'); ?></li>
<?php endforeach; ?>
</ul>
</div>
<?php endif; ?>

<div class="box">
<strong>gallery</strong>
<?php if (!$gallery): ?>
<p><small>nothing dropped yet</small></p>
<?php else: ?>
<ul>
<?php foreach ($gallery as $entry): ?>
  <li><a href="uploads/<?php echo rawurlencode($entry); ?>"><?php echo htmlspecialchars($entry, ENT_QUOTES, 'UTF-8'); ?></a></li>
<?php endforeach; ?>
</ul>
<?php endif; ?>
</div>

<p><small>PixelDrop on PHP <?php echo htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8'); ?></small></p>
</body>
</html>
