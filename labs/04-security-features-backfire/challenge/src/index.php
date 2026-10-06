<?php
/* --------------------------------------------------------------------------
 * notes.lab  --  "preview a note" endpoint
 *
 * Security posture, as designed by a very diligent developer:
 *
 *   layer 1 : every note goes through a regex WAF before it is rendered,
 *             so tags carrying event handlers / script can never get through.
 *   layer 2 : defence in depth -- a strict Content-Security-Policy is emitted
 *             on every response, so even a WAF bypass cannot execute script.
 *
 * Two independent layers. What could possibly go wrong?
 * -------------------------------------------------------------------------- */

$xss = isset($_GET['xss']) ? $_GET['xss'] : '';

/* ---- layer 1: the regex WAF ------------------------------------------- */
$WAF = array(
    /* R1 -- any tag that carries an inline event handler:
             <svg onload=..>, <img  onerror=..>, <body onpageshow=..>, ...
             the (?:[^>]|\s)*? part swallows whatever attribute junk sits
             between the tag name and the handler.  Note [\s\/]: '/' is a
             valid attribute separator, so <svg/onload=..> must match too.                        */
    '/<\s*[a-z][a-z0-9]*(?:[^>]|\s)*?[\s\/]on[a-z]+\s*=/i',

    /* R2 -- script tags and script-bearing URI schemes                    */
    '/<\s*\/?\s*script\b|javascript\s*:|data\s*:\s*text\s*\/\s*html/i',
);

foreach ($WAF as $i => $rule) {
    if (preg_match($rule, $xss)) {
        http_response_code(403);
        exit('blocked by WAF rule #' . ($i + 1));
    }
}

/* ---- layer 2: defence in depth ---------------------------------------- */
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>notes.lab &mdash; note preview</title>
<style>
 body{background:#11131a;color:#c8ccd4;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:2rem}
 .wrap{max-width:70ch;margin:auto}
 h1{color:#e8b84b;font-size:1.2rem;margin:0 0 .2rem}
 .sub{color:#6d7480;margin:0 0 1.5rem}
 .card{background:#181b24;border:1px solid #262a36;border-radius:6px;padding:1rem;margin:1rem 0}
 .lbl{color:#6d7480;text-transform:uppercase;font-size:.72rem;letter-spacing:.1em;margin:0 0 .5rem}
 input[type=text]{width:100%;box-sizing:border-box;background:#0d0f15;color:#c8ccd4;border:1px solid #2d323f;border-radius:4px;padding:.5rem;font:inherit}
 button{background:#e8b84b;color:#11131a;border:0;border-radius:4px;padding:.45rem 1rem;font:inherit;font-weight:600;cursor:pointer;margin-top:.6rem}
 a{color:#7aa2f7} code{color:#9ece6a}
</style>
</head>
<body>
<div class="wrap">
  <h1>notes.lab</h1>
  <p class="sub">paste a note, see how it renders. hardened by a regex WAF <em>and</em> a strict CSP.</p>

  <form method="get" class="card">
    <p class="lbl">your note</p>
    <input type="text" name="xss" value="" placeholder="hello world" autofocus>
    <button type="submit">preview</button>
  </form>

  <div class="card">
    <p class="lbl">preview</p>
<?php echo $xss; ?>
  </div>

  <p class="sub">
    found something? the site admin reviews reported notes:
    <a href="/report.html">report a note &rarr;</a>
  </p>
</div>
</body>
</html>
