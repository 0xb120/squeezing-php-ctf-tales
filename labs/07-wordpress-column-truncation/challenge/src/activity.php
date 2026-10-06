<?php
session_start();
require __DIR__ . '/meta.php';
?>
<!doctype html><meta charset="utf-8"><title>inkpress &mdash; activity</title>
<style>body{font:14px/1.5 ui-monospace,monospace;max-width:52rem;margin:2rem auto;padding:0 1rem}
pre{background:#f4f4f4;padding:.6rem;overflow:auto;white-space:pre-wrap;word-break:break-all}</style>
<h1>activity log</h1><p><a href="index.php">&larr; back</a></p>
<pre><?= htmlspecialchars((string) @file_get_contents(ACTIVITY_LOG)) ?></pre>
