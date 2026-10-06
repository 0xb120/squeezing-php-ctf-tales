<?php
/**
 * The vulnerable app. Three endpoints, ~60 lines, no framework.
 *
 * Everything that touches the filesystem goes through WinPath, which is the
 * emulation of the Win32 path layer (see winpath.php). On a real Windows box
 * you would simply call file_exists()/include and Windows would do this for
 * you -- that is the whole point of the bug.
 */
require __DIR__ . '/winpath.php';
require __DIR__ . '/cms.php';

cms_session_start();
$op = (string) ($_GET['op'] ?? '');

switch ($op) {

    /* ---- 1. the oracle -------------------------------------------------
     * Renders a caption image. The font is picked by name inside the fonts
     * directory; if the font file is not there we bail out with a 404.
     */
    case 'creatimg':
        $txt  = (string) ($_GET['txt'] ?? 'phpcms');
        $font = (string) ($_GET['font'] ?? 'default.ttf');

        if (!WinPath::exists(FONT_DIR . $font)) {
            http_response_code(404);
            header('Content-Type: text/plain');
            exit("font not found\n");
        }
        header('Content-Type: image/png');
        exit(cms_png($txt));

    /* ---- 2. the write primitive ---------------------------------------
     * Stores the visitor signature in the shared session.
     */
    case 'sign':
        $_SESSION['visitor'] = (string) ($_GET['name'] ?? '');
        header('Content-Type: text/plain');
        exit("signed, thanks!\n");

    /* ---- 3. the read primitive ----------------------------------------
     * Loads a compiled template out of the tmp directory. The name is
     * validated hard: letters, digits and underscores only, so no traversal,
     * no wildcard, no extension trickery.
     */
    case 'tplcache':
        $tpl = (string) ($_GET['tpl'] ?? '');
        if (!preg_match('/\A[A-Za-z0-9_]{1,64}\z/', $tpl)) {
            http_response_code(400);
            exit("bad template name\n");
        }
        $real = WinPath::resolve(TMP_DIR . $tpl);
        if ($real === null || !is_file($real)) {
            http_response_code(404);
            exit("no such compiled template\n");
        }
        header('Content-Type: text/plain');
        include $real;
        exit;

    /* ---- 4. the cache writer (bonus, not needed for the flag) ----------
     * Persists a small string under C:\xampp\caches\ (outside the document root).
     */
    case 'cachewrite':
        $name = (string) ($_GET['name'] ?? '');
        $data = (string) ($_GET['data'] ?? '');
        if ($name === '' || strpbrk($name, '/\\') !== false) {
            http_response_code(400);
            exit("bad cache name\n");
        }
        $n = WinPath::writeFile('C:\\xampp\\caches\\' . $name, $data);
        header('Content-Type: text/plain');
        exit($n === false ? "write failed\n" : "wrote $n bytes\n");

    default:
        http_response_code(404);
        exit("unknown op\n");
}
