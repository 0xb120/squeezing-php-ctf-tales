<?php require __DIR__ . '/lib/gallery.php'; ?>
<!doctype html><meta charset="utf-8"><title>phar gallery</title>
<style>body{font:14px/1.5 monospace;max-width:52em;margin:3em auto;padding:0 1em}
code{background:#eee;padding:.1em .3em}</style>
<h1>phar gallery</h1>
<p>A three-file image gallery. Nothing fancy.</p>

<h2>1. upload an image</h2>
<form method="post" action="upload.php" enctype="multipart/form-data">
  <input type="file" name="image"> <button>upload</button>
</form>
<p>Only real GIF/JPEG images are accepted. Files land in <code>uploads/</code>.</p>

<h2>2. check that a file is there</h2>
<p><code>GET /check.php?file=&lt;path&gt;</code> - returns nothing at all, it
just runs <code>file_exists()</code> on whatever you give it.</p>

<h2>debug</h2>
<p>PHP <?= PHP_VERSION ?>, phar.readonly=<?= ini_get('phar.readonly') ?>,
phar.require_hash=<?= ini_get('phar.require_hash') ?></p>
