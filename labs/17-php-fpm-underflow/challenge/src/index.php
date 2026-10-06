<?php
/*
 * Real World CTF 2019 - "the frontend challenge".
 *
 * The whole point of this page is that there is nothing interesting in it:
 * no include, no file read, no eval.  Everything you can reach from here is
 * a static string.  The bug is one layer below.
 */
$notes = [
    ['d90pwn',  'the URL with a newline returns weird stuff'],
    ['beched',  'php.ini through FastCGI variables?'],
    ['neex',    'pos LSB -> 0x00 and the next write lands on top of the old one'],
];
?>
<!doctype html>
<title>RWCTF notes</title>
<style>body{font:14px/1.6 monospace;margin:2rem}</style>
<h1>notes board</h1>
<ul>
<?php foreach ($notes as [$who, $what]): ?>
  <li><b><?= htmlspecialchars($who) ?></b>: <?= htmlspecialchars($what) ?></li>
<?php endforeach; ?>
</ul>
<p>php <?= PHP_VERSION ?> / <?= php_sapi_name() ?> / pid <?= getmypid() ?></p>
