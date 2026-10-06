<?php
require __DIR__ . '/cms.php';
cms_session_start();
cms_header('phpcms-lite');
?>
<h1>phpcms-lite 9.6.0</h1>
<p>running on <code>Windows NT / Apache / PHP <?= PHP_VERSION ?></code></p>
<p>DocumentRoot <code>C:\xampp\htdocs</code> &mdash; tmp <code>C:\xampp\tmp</code></p>

<h2>api.php</h2>
<ul>
  <li><code>?op=creatimg&amp;txt=TEXT&amp;font=NAME</code> &mdash; render TEXT with a
      font from <code><?= htmlspecialchars(FONT_DIR) ?></code>.
      <a href="api.php?op=creatimg&amp;txt=hello&amp;font=default.ttf">try it</a></li>
  <li><code>?op=sign&amp;name=NAME</code> &mdash; sign the visitor book (stored in the
      shared session).</li>
  <li><code>?op=cachewrite&amp;name=NAME&amp;data=TEXT</code> &mdash; write a cache entry to
      <code>C:\xampp\caches\</code> (not web-reachable).</li>
  <li><code>?op=tplcache&amp;tpl=NAME</code> &mdash; load a compiled template from
      <code><?= htmlspecialchars(TMP_DIR) ?></code>.</li>
</ul>

<h2>visitor book</h2>
<p>last signature: <code><?= htmlspecialchars((string)($_SESSION['visitor'] ?? '-')) ?></code></p>
