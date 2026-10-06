<!doctype html>
<meta charset="utf-8">
<title>Museum of Local File Inclusion</title>
<style>
 body{font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem auto;max-width:52rem;padding:0 1rem;color:#1b1b1b}
 h1{font-size:1.3rem} h2{font-size:1.05rem;margin-top:2rem}
 nav a{margin-right:1rem} hr{border:0;border-top:1px solid #ccc;margin:1.2rem 0}
 code,pre{background:#f3f3f3} pre{padding:.6rem;overflow-x:auto}
 .msg{background:#fff7d6;border-left:3px solid #d9a400;padding:.4rem .6rem}
 form{margin:.8rem 0} input,textarea{font:inherit} textarea{width:100%;height:6rem}
 .year{color:#777}
</style>
<h1>Museum of Local File Inclusion</h1>
<nav>
<a href="index.php">lobby</a>
<?php
$__nav = array(
    'stage1.php' => '1. label printer',
    'stage2.php' => '2. note keeper',
    'stage3.php' => '3. photo wall',
    'stage4.php' => "4. curator's desk",
);
foreach ($__nav as $__f => $__t) {
    if (file_exists(dirname(__FILE__) . '/' . $__f)) {
        echo '<a href="' . $__f . '">' . $__t . "</a>\n";
    }
}
?>
</nav>
<hr>
