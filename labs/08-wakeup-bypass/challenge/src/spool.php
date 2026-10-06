<?php
require __DIR__ . '/draft.php';
?>
<!doctype html><meta charset="utf-8"><title>postbox &mdash; spool</title>
<style>body{font:14px/1.5 ui-monospace,monospace;max-width:52rem;margin:2rem auto;padding:0 1rem}
pre{background:#f4f4f4;padding:.6rem;overflow:auto;white-space:pre-wrap;word-break:break-all}</style>
<h1>outbox spool</h1><p><a href="index.php">&larr; back</a></p>
<pre><?= htmlspecialchars((string) @file_get_contents(SPOOL_FILE)) ?></pre>
