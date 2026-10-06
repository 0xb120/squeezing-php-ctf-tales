<?php
// The whole "vulnerability".  It produces no output whatsoever.
require __DIR__ . '/lib/gallery.php';

file_exists($_GET['file'] ?? '');
