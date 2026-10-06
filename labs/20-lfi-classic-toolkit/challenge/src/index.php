<?php include __DIR__ . '/_style.php'; ?>
<p>Four exhibits, one per decade of turning <code>include($_GET['page'])</code>
into code execution. Each exhibit hands out one fragment of the curator key;
the curator's desk wants all three.</p>

<h2>1 &mdash; the label printer <span class="year">(1999&ndash;2010)</span></h2>
<p>Prints an exhibit label. The template name is yours, the <code>.php</code>
suffix is ours.</p>

<h2>2 &mdash; the note keeper <span class="year">(2009)</span></h2>
<p>Exports a curator note to disk. Every exported note starts with the guard
line, so a note can never run on its own.</p>

<h2>3 &mdash; the photo wall <span class="year">(2015)</span></h2>
<p>Accepts exhibit photographs. PNG only, checked twice.</p>

<h2>4 &mdash; the curator's desk <span class="year">(2011)</span></h2>
<p>Diagnostics and the vault. Needs the whole curator key.</p>

<hr>
<p class="year">wing: <?php
  $w = @file_get_contents('/opt/museum/wing');
  echo htmlspecialchars($w ? trim(substr($w, strpos($w, '=') + 1)) : 'modern');
  echo ' &middot; php ', htmlspecialchars(PHP_VERSION);
?></p>
