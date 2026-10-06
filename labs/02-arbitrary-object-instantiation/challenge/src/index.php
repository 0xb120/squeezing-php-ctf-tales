<?php
/*
 * PluginHub - front controller.
 *
 * Plugins are instantiated by class name. Constructor arguments come from the
 * request as a JSON array so that operators can wire a plugin up without
 * editing any configuration file.
 *
 * This build ships no plugins of its own yet: the marketplace is still empty.
 */

define('PKG_CACHE', '/var/www/pkgcache');

$diagnostics = array();

set_error_handler(function ($no, $str, $file, $line) use (&$diagnostics) {
    $diagnostics[] = $str;
    return true;
});

/* ------------------------------------------------------------------ loader */

$plugin  = isset($_GET['plugin']) ? (string) $_GET['plugin'] : '';
$argsRaw = isset($_GET['args']) ? (string) $_GET['args'] : '[]';
$loaderResult = null;

if ($plugin !== '') {
    $args = json_decode($argsRaw, true);
    if (!is_array($args)) {
        $args = array();
    }

    try {
        $instance = new $plugin(...array_values($args));
        $loaderResult = 'initialised ' . get_class($instance);
    } catch (Throwable $e) {
        $loaderResult = get_class($e) . ': ' . $e->getMessage();
    }
}

restore_error_handler();

/* ----------------------------------------------------------- package cache */

$packages = array();
if (is_dir(PKG_CACHE)) {
    foreach (scandir(PKG_CACHE) as $entry) {
        if ($entry !== '.' && $entry !== '..' && is_file(PKG_CACHE . '/' . $entry)) {
            $packages[] = $entry;
        }
    }
    sort($packages);
}

$pkgName = isset($_GET['pkg']) ? basename((string) $_GET['pkg']) : '';
$pkgBody = null;
if ($pkgName !== '' && $pkgName !== '.' && $pkgName !== '..') {
    $path = PKG_CACHE . '/' . $pkgName;
    $pkgBody = is_file($path) ? file_get_contents($path) : '(not in the cache)';
}

function h($s)
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PluginHub</title>
<style>
body{font:14px/1.55 monospace;max-width:56em;margin:2em auto;padding:0 1em;background:#0f1115;color:#dcdce2}
h1{font-size:1.4em;letter-spacing:.08em}
a{color:#7ec7ff}
.box{border:1px solid #2a2d36;padding:1em;margin:1em 0;background:#161922}
pre{white-space:pre-wrap;word-break:break-all;margin:.4em 0;color:#ffd479}
input,button{font:inherit;background:#0f1115;color:#dcdce2;border:1px solid #2a2d36;padding:.3em}
input[type=text]{width:100%;box-sizing:border-box;margin:.2em 0}
small{color:#8a8f9c}
</style>
</head>
<body>
<h1>PluginHub</h1>
<p><small>plugin host &mdash; build 1.4 &mdash; marketplace sync is handled by the
internal registry, see <a href="registry-api.txt">registry-api.txt</a></small></p>

<div class="box">
<strong>load a plugin</strong>
<form method="get">
  <label>class<input type="text" name="plugin" value="<?php echo h($plugin); ?>" placeholder="PluginHub\Example"></label>
  <label>constructor arguments (JSON array)<input type="text" name="args" value="<?php echo h($argsRaw); ?>" placeholder='["arg1", {"opt": 1}]'></label>
  <button type="submit">load</button>
</form>
<p><small>No plugins are bundled with this build yet.</small></p>
</div>

<?php if ($loaderResult !== null): ?>
<div class="box">
<strong>loader result</strong>
<pre><?php echo h($loaderResult); ?></pre>
<?php if ($diagnostics): ?>
<strong>diagnostics</strong>
<?php foreach ($diagnostics as $d): ?>
<pre><?php echo h($d); ?></pre>
<?php endforeach; ?>
<?php endif; ?>
</div>
<?php endif; ?>

<div class="box">
<strong>package cache</strong>
<?php if (!$packages): ?>
<p><small>empty &mdash; nothing has been synced from the registry yet</small></p>
<?php else: ?>
<ul>
<?php foreach ($packages as $p): ?>
  <li><a href="?pkg=<?php echo rawurlencode($p); ?>"><?php echo h($p); ?></a></li>
<?php endforeach; ?>
</ul>
<?php endif; ?>
<?php if ($pkgBody !== null): ?>
<strong><?php echo h($pkgName); ?></strong>
<pre><?php echo h($pkgBody); ?></pre>
<?php endif; ?>
</div>

<p><small>PHP <?php echo h(PHP_VERSION); ?></small></p>
</body>
</html>
