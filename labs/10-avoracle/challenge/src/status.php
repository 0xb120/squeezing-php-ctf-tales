<?php
/**
 * "Is my session still alive?" -- read-only, so this endpoint never writes the
 * session back to disk.
 */
require __DIR__ . '/app.php';
session_start(['read_and_close' => true]);

header('Content-Type: text/plain');
if (isset($_SESSION['flag'])) {
    echo "SESSION OK\n";
} else {
    echo "SESSION LOST\n";
}
