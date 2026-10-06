<?php
$dir = __DIR__ . '/../uploads';
$n = 0;
foreach (glob($dir . '/*.png') as $p) { $n++; }
echo "photo wall: $n photograph(s) on display\n";
