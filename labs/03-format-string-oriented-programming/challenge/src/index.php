<?php
/**
 * Fleet Console 0.3 - node bootstrap endpoint.
 *
 * A node licence is a small signed blob that says how many driver slots this
 * node may bring up. We never render the licence - it carries the node deploy
 * key - we only walk it and count the slots it authorises.
 */
require __DIR__ . '/drivers.php';

header('Content-Type: text/plain; charset=utf-8');

$licence = "-----BEGIN FLEET LICENCE-----\n"
         . "node=web-01\n"
         . "issued=2015-12-11\n"
         . "deploy_key=" . trim(file_get_contents('/flag.txt')) . "\n"
         . "slots=driver:cache driver:queue driver:mailer\n"
         . "-----END FLEET LICENCE-----\n";

// Operators may pin a specific driver implementation per request.
$driver = isset($_GET['driver']) ? $_GET['driver'] : 'NullDriver';

$slots = 0;
preg_replace_callback('~driver:([a-z]+)~', function (array $m) use ($driver, &$slots) {
    $probe = new $driver();          // arbitrary object instantiation
    $probe->probe($m[1]);
    $slots++;
    return '';
}, $licence);

echo "fleet-console 0.3 (php " . PHP_VERSION . ")\n";
echo "node=web-01 driver=" . $driver . " slots_probed=" . $slots . "\n";
