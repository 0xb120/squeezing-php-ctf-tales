#!/bin/sh
# Boot the "Windows" box: pick a fresh random session id for the shared
# visitor-book session, seed the session file, then hand over to Apache.
set -e

# 26 characters out of the sid alphabet this box is configured for
# (session.sid_length=26, session.sid_bits_per_character=5 -> 0-9a-v; see
# challenge/Dockerfile).  That is php.ini-production's recommendation, not
# PHP's compiled-in default, which is 32 hex characters (sid_length=32,
# sid_bits_per_character=4).
CMS_BOOK_SID=$(php -r '
    $c = "0123456789abcdefghijklmnopqrstuv";
    $s = "";
    for ($i = 0; $i < 26; $i++) { $s .= $c[random_int(0, 31)]; }
    echo $s;
')
export CMS_BOOK_SID

printf '%s' 'visitor|s:9:"anonymous";' > "/xampp/tmp/sess_${CMS_BOOK_SID}"
chown www-data:www-data "/xampp/tmp/sess_${CMS_BOOK_SID}"
chmod 0600 "/xampp/tmp/sess_${CMS_BOOK_SID}"

exec "$@"
