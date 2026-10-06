<?php
// ---------------------------------------------------------------------------
// EXHIBIT 2 - "the note keeper".
//
// Curator notes are exported to disk as .php files so the reader can just
// include() them.  Two things make that safe:
//   * every export is prefixed with the guard line, so a note that is reached
//     directly does nothing at all;
//   * notes may not contain an opening PHP tag in the first place.
// ---------------------------------------------------------------------------
define('GUARD', "; <?php exit; ?> DO NOT REMOVE THIS LINE\n");

if (isset($_GET['note'])) {
    $name = basename($_GET['note']);
    $path = __DIR__ . '/notes/' . $name . '.php';
    if (!file_exists($path)) { header('HTTP/1.0 404 Not Found'); die("no such note\n"); }
    include($path);
    exit;
}

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $file = isset($_POST['file']) ? $_POST['file'] : '';
    $body = isset($_POST['body']) ? $_POST['body'] : '';
    if ($file === '' || strlen($file) > 160 || strpos($file, '..') !== false) {
        $msg = 'refused: bad note name';
    } elseif (preg_match('/<\?|<%|<script/i', $body)) {
        $msg = 'refused: notes may not contain code';
    } else {
        $n = @file_put_contents($file . '.php', GUARD . $body);
        $msg = ($n === false)
             ? 'refused: cannot write there'
             : 'exported ' . $n . ' bytes to ' . htmlspecialchars($file) . '.php';
    }
}

include __DIR__ . '/_style.php';
echo "<h2>2 &mdash; the note keeper</h2>\n";
if ($msg !== '') { echo '<p class="msg">' . $msg . "</p>\n"; }
?>
<p>Notes are exported below <code>notes/</code> and read back with
<code>?note=&lt;name&gt;</code>. Every export starts with:</p>
<pre>; &lt;?php exit; ?&gt; DO NOT REMOVE THIS LINE</pre>
<form method="post">
  <label>note file <input name="file" value="notes/scratch" size="60"></label><br>
  <label>note body<br><textarea name="body">a perfectly ordinary curator note</textarea></label><br>
  <button type="submit">export</button>
</form>
