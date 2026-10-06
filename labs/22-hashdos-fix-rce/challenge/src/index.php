<?php
/*
 * Sticky 0.9 - a note preview box.
 *
 * There is no database, no session, no file access and no include(): you type
 * a note, it hands the note back to you with the HTML escaped. That really is
 * the whole application.
 */
$note = isset($_POST['note']) ? $_POST['note'] : '';
?>
<!doctype html>
<html><head><meta charset="utf-8"><title>Sticky 0.9</title>
<style>body{font:14px/1.5 monospace;max-width:52em;margin:2em auto;padding:0 1em}
pre{background:#f4f4f4;padding:1em;overflow-x:auto;white-space:pre-wrap}</style>
</head><body>
<h1>Sticky <small>0.9</small></h1>
<p>Paste a note and see how it will look. Nothing is stored.</p>
<form method="post" action="/">
  <textarea name="note" rows="6" cols="64"></textarea><br>
  <button type="submit">preview</button>
</form>
<h2>preview</h2>
<pre id="preview"><?php echo htmlspecialchars($note); ?></pre>
<hr>
<p><small>powered by PHP <?php echo PHP_VERSION; ?> (cgi)</small></p>
</body></html>
