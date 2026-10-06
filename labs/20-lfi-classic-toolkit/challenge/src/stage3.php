<?php
// ---------------------------------------------------------------------------
// EXHIBIT 3 - "the photo wall".
//
// Photographs are PNG and only PNG: the name is checked, and the bytes are
// checked with getimagesize() so a renamed script cannot get in.
// The gallery view is a template, and we add the .php ourselves.
// ---------------------------------------------------------------------------
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['photo'])) {
    $f = $_FILES['photo'];
    if ($f['error'] !== UPLOAD_ERR_OK) {
        $msg = 'refused: upload error ' . (int)$f['error'];
    } elseif ($f['size'] > 512 * 1024) {
        $msg = 'refused: 512 KiB maximum';
    } elseif (!preg_match('/\.png$/i', $f['name'])) {
        $msg = 'refused: .png only';
    } else {
        $info = @getimagesize($f['tmp_name']);
        if (!$info || $info[2] !== IMAGETYPE_PNG) {
            $msg = 'refused: that is not a PNG';
        } else {
            $name = sha1_file($f['tmp_name']) . '.png';
            move_uploaded_file($f['tmp_name'], __DIR__ . '/uploads/' . $name);
            $msg = 'stored as <code>uploads/' . $name . '</code> ('
                 . (int)$info[0] . 'x' . (int)$info[1] . ')';
        }
    }
}

include __DIR__ . '/_style.php';
echo "<h2>3 &mdash; the photo wall</h2>\n";
if ($msg !== '') { echo '<p class="msg">' . $msg . "</p>\n"; }
?>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="photo"> <button type="submit">upload</button>
</form>
<?php
$view = isset($_GET['view']) ? $_GET['view'] : 'exhibits/photo-wall';
echo '<p>view: <code>' . htmlspecialchars($view) . ".php</code></p>\n<pre>";
include($view . '.php');
echo "</pre>\n";
