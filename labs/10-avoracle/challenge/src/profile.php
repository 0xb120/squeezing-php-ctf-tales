<?php
/**
 * Stores the nickname. Whatever you send is written into the session file
 * verbatim -- it is only ever printed back through htmlspecialchars(), so
 * from the application's point of view there is nothing to escape.
 */
require __DIR__ . '/app.php';
ink_start();

$nick = (string) ($_POST['nick'] ?? $_GET['nick'] ?? '');
if (strlen($nick) > 4096) {
    http_response_code(413);
    exit("nickname too long\n");
}
ink_store($nick);

header('Content-Type: text/plain');
echo "saved " . strlen($nick) . " bytes to session " . session_id() . "\n";
