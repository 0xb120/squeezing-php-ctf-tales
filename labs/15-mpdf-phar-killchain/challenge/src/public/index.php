<?php
/**
 * QuoteBuilder - "paste some HTML, get a PDF quote".
 *
 * Deliberately vulnerable lab target: the HTML is handed straight to mPDF.
 * Do not deploy this.
 */
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

// mPDF's stock temporary directory (Mpdf\Config\ConfigVariables: __DIR__ . '/../../tmp').
define('TEMP_DIR', dirname(__DIR__) . '/vendor/mpdf/mpdf/tmp');

/** A little "hardening" the developer was proud of. */
function reject_dangerous(string $html): void
{
    foreach (['<?', '<script', '<iframe', 'javascript:', 'php://', 'phar://', 'file://'] as $needle) {
        if (stripos($html, $needle) !== false) {
            http_response_code(400);
            exit("refused: '{$needle}' is not allowed in a quote template\n");
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['html'])) {
    $html = (string) $_POST['html'];
    reject_dangerous($html);

    $mpdf = new \Mpdf\Mpdf([
        'tempDir'       => TEMP_DIR,
        'exposeVersion' => true,
    ]);
    $mpdf->SetTitle('QuoteBuilder export');
    $mpdf->WriteHTML($html);
    $pdf = $mpdf->Output('', \Mpdf\Output\Destination::STRING_RETURN);

    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="quote.pdf"');
    header('X-Renderer: mPDF/' . \Mpdf\Mpdf::VERSION);
    echo $pdf;
    exit;
}

$cacheDir = TEMP_DIR . '/mpdf';
?>
<!doctype html>
<meta charset="utf-8">
<title>QuoteBuilder</title>
<style>
 body{font:14px/1.5 monospace;max-width:60em;margin:3em auto;padding:0 1em;background:#101216;color:#d8dee9}
 h1{font-size:1.3em;color:#88c0d0} textarea{width:100%;height:14em;background:#161a21;color:#d8dee9;border:1px solid #2e3440}
 button{padding:.5em 1.2em;margin-top:.6em} pre{background:#161a21;padding:.8em;overflow:auto;border-left:3px solid #2e3440}
 .diag{color:#6b7787;font-size:.9em;background:#161a21;padding:.8em;border-left:3px solid #2e3440}
</style>
<h1>QuoteBuilder &mdash; HTML &rarr; PDF</h1>
<p>Paste the HTML of a customer quote. It is rendered server-side and sent back as a PDF.</p>
<form method="post">
  <textarea name="html"><h1>Quote #1337</h1>
<p>Widgets, 12 x 4.99 EUR</p></textarea><br>
  <button type="submit">Render PDF</button>
</form>
<pre class="diag"><b>Diagnostics</b> (debug build)
<?php
$user = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'www-data';
$files = is_dir($cacheDir) ? count(glob($cacheDir . '/*')) : 0;
printf("renderer  : mPDF %s on PHP %s\n", \Mpdf\Mpdf::VERSION, PHP_VERSION);
printf("app root  : %s\n", dirname(__DIR__));
printf("cache dir : %s (%d entries)\n", $cacheDir, $files);
printf("worker    : %s\n", $user);
?></pre>
