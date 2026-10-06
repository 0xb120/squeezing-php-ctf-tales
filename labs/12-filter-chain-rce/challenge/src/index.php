<?php
// "Paperclip" - a minimal static page viewer.
// Pages live in ./pages/ and are plain PHP templates, so we just include them.
$page = $_GET['page'] ?? 'pages/home.php';
?>
<!doctype html>
<title>Paperclip</title>
<style>body{font:14px/1.5 monospace;margin:2rem auto;max-width:46rem}nav a{margin-right:1rem}</style>
<h1>Paperclip</h1>
<nav>
  <a href="?page=pages/home.php">home</a>
  <a href="?page=pages/about.php">about</a>
  <a href="?page=pages/notes.php">notes</a>
</nav>
<hr>
<?php include($page); ?>
