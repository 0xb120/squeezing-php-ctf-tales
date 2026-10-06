<?php
/*
 * nullcon-ish scoreboard, served by php-cgi behind a tiny CGI gateway.
 *
 * Ops note (do not ship this comment to production, ha):
 *   the round flag lives in /flag.txt, outside the document root, mode 0440,
 *   owned by the same user php-cgi runs as.  The web tree is read-only, so
 *   there is nothing to steal in here.
 */

$scores = [
    'Eindbazen'      => 1337,
    'Orange Tsai'    => 1231,
    'more smoked leet chicken' => 998,
    'splitline'      => 731,
    'your team'      => 0,
];
arsort($scores);

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<title>Scoreboard</title>
<style>body{font:14px/1.5 monospace;margin:2rem}td{padding:.15rem 1.5rem .15rem 0}</style>
<h1>&#127942; Scoreboard</h1>
<table>
<?php $rank = 1; foreach ($scores as $team => $points): ?>
  <tr><td><?= $rank++ ?></td><td><?= htmlspecialchars($team) ?></td><td><?= (int)$points ?></td></tr>
<?php endforeach; ?>
</table>
<p>round 3 of 5 &middot; scores freeze in 01:12:44</p>
<!-- served by <?= php_sapi_name() ?> <?= PHP_VERSION ?> -->
