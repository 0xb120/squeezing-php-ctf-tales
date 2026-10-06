<?php
/*
 * The sandboxed evaluator.
 *
 * Apache pins open_basedir to /var/www/sandbox/ for this directory, and
 * php.ini strips every function that could spawn a process.  Whatever the
 * visitor sends is eval()'d with those two restrictions in place.
 */
header('Content-Type: text/plain; charset=utf-8');

chdir(__DIR__);

$code = $_POST['code'] ?? $_GET['code'] ?? '';
if (isset($_REQUEST['b64']) && $code !== '') {
    $code = base64_decode($code, true);
    if ($code === false) { http_response_code(400); exit("bad base64\n"); }
}

echo "== PHPlayground =============================\n";
echo "php          : " . PHP_VERSION . "\n";
echo "cwd          : " . getcwd() . "\n";
echo "open_basedir : " . ini_get('open_basedir') . "\n";
echo "=============================================\n";

if ($code === '') { exit("(nothing to run)\n"); }

try {
    eval($code);
} catch (Throwable $e) {
    echo "\n[!] " . get_class($e) . ': ' . $e->getMessage() . "\n";
}
echo "\n== done =====================================\n";
