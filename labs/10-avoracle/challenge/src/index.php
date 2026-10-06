<?php
require __DIR__ . '/app.php';
ink_start();
ink_header('inkstone');
?>
<h1>inkstone 0.3</h1>
<p>workstation <code>WIN-INKSTONE</code> &mdash; PHP <?= PHP_VERSION ?> &mdash;
   real-time protection <strong>on</strong></p>

<p>Your nickname and this workstation's licence key are kept in your session
   file, under <code>C:\Windows\Temp\</code>.</p>

<form action="profile.php" method="post">
  <label>nickname <input name="nick" value="<?= htmlspecialchars((string)($_SESSION['nick'] ?? '')) ?>"></label>
  <button>save</button>
</form>

<ul>
  <li><code>POST /profile.php</code> (<code>nick=</code>) &mdash; store your nickname</li>
  <li><code>GET /status.php</code> &mdash; is your session still there?</li>
  <li>Defender console: <code>http://127.0.0.1:9010/status</code></li>
</ul>

<p>session id: <code><?= htmlspecialchars(session_id()) ?></code></p>
