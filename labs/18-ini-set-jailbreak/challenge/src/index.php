<?php
// PHPlayground - the public UI.  Not jailed: it only prints HTML.
$php = PHP_VERSION;
$dis = ini_get('disable_functions');
?><!doctype html>
<meta charset="utf-8">
<title>PHPlayground</title>
<style>
 body{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;max-width:56rem;margin:2rem auto;padding:0 1rem;background:#111;color:#ddd}
 h1{font-size:1.3rem} textarea{width:100%;height:11rem;background:#000;color:#9f9;border:1px solid #444;padding:.6rem}
 pre{background:#000;border:1px solid #444;padding:.6rem;overflow:auto} button{padding:.4rem 1rem}
 .k{color:#7cf} small{color:#888}
</style>
<h1>PHPlayground <small>&mdash; run PHP snippets safely*</small></h1>
<p>Your snippet is <span class="k">eval()</span>'d inside a jail:</p>
<ul>
  <li>PHP <?= htmlspecialchars($php) ?></li>
  <li><span class="k">open_basedir</span> = <code>/var/www/sandbox/</code> (set by the web server, per-directory)</li>
  <li><span class="k">disable_functions</span> = <code><?= htmlspecialchars($dis) ?></code></li>
</ul>
<p><small>* the operations team says the jail is airtight. The flag is in <code>/flag.txt</code>, well outside it.</small></p>
<form method="post" action="/sandbox/run.php">
  <textarea name="code" placeholder="echo 'hello';">echo getcwd(), "\n";
var_dump(file_get_contents('/flag.txt'));</textarea>
  <p><button type="submit">Run</button></p>
</form>
