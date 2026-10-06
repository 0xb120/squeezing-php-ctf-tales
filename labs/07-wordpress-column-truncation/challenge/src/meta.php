<?php
/**
 * inkpress -- the metadata layer.
 *
 * Values are stored "type-agnostically" in usermeta.meta_value: arrays and
 * objects get serialize()d on the way in and are restored on the way out,
 * scalars are stored verbatim.  That is the whole WordPress idea, re-written
 * small enough to read in one sitting.
 */

define('META_REVISION_TAG', '|r7');
// The activity log lives OUTSIDE the document root: it echoes back whatever
// the dashboard notices contained, so Apache has no business serving it
// directly. activity.php is the only reader.
define('ACTIVITY_LOG', '/var/inkpress/activity.log');

function db(): mysqli
{
    static $db = null;
    if ($db === null) {
        $db = new mysqli(
            getenv('DB_HOST') ?: 'db',
            getenv('DB_USER') ?: 'inkpress',
            getenv('DB_PASS') ?: 'inkpress',
            getenv('DB_NAME') ?: 'inkpress'
        );
        // the connection charset has been 'utf8' since the blog was installed;
        // nobody ever migrated it to utf8mb4 (WordPress only did so in 4.2)
        $db->set_charset('utf8');
    }
    return $db;
}

/**
 * Cheap "does this look like serialize() output?" sniff.
 *
 * Same shape as WordPress' is_serialized(): a couple of structural checks and
 * one regex per type token.  In strict mode the candidate must additionally
 * END with ';' or '}', which is what keeps ordinary user text out of
 * unserialize().
 */
function looks_serialized(string $data, bool $strict = true): bool
{
    $data = trim($data);
    if ($data === 'N;') {
        return true;
    }
    if (strlen($data) < 4 || $data[1] !== ':') {
        return false;
    }
    if ($strict) {
        $last = $data[strlen($data) - 1];
        if ($last !== ';' && $last !== '}') {
            return false;
        }
    }
    switch ($data[0]) {
        case 'a':
        case 'O':
        case 's':
            return (bool) preg_match('/^[aOs]:[0-9]+:/s', $data);
        case 'b':
        case 'i':
        case 'd':
            return (bool) preg_match('/^[bid]:[0-9.E+-]+;' . ($strict ? '$' : '') . '/', $data);
    }
    return false;
}

function maybe_serialize($value)
{
    return (is_array($value) || is_object($value)) ? serialize($value) : $value;
}

function maybe_unserialize($value)
{
    if (is_string($value) && looks_serialized($value)) {
        return @unserialize($value);
    }
    return $value;
}

/**
 * Hardening added after our last object-injection advisory: every *scalar* we
 * write gets a schema-revision tag glued to the end.  A tagged value can never
 * end in ';' or '}', so looks_serialized() will refuse it and a plain string
 * can never be revived as an object.  Serialized containers are exempt -- they
 * have to survive the round trip.
 */
function update_user_meta(int $uid, string $key, $value): void
{
    $stored = maybe_serialize($value);
    if (is_string($value)) {
        $stored .= META_REVISION_TAG;
    }

    $st = db()->prepare(
        'INSERT INTO usermeta (user_id, meta_key, meta_value) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value)'
    );
    $st->bind_param('iss', $uid, $key, $stored);
    $st->execute();
    $st->close();
}

function get_user_meta(int $uid, string $key)
{
    $st = db()->prepare('SELECT meta_value FROM usermeta WHERE user_id = ? AND meta_key = ?');
    $st->bind_param('is', $uid, $key);
    $st->execute();
    $row = $st->get_result()->fetch_row();
    $st->close();
    if ($row === null) {
        return null;
    }

    $value = maybe_unserialize($row[0]);
    if (is_string($value) && substr($value, -strlen(META_REVISION_TAG)) === META_REVISION_TAG) {
        $value = substr($value, 0, -strlen(META_REVISION_TAG));
    }
    return $value;
}

function current_user(): int
{
    if (empty($_SESSION['uid'])) {
        $login = 'guest_' . bin2hex(random_bytes(4));
        $st = db()->prepare('INSERT INTO users (login) VALUES (?)');
        $st->bind_param('s', $login);
        $st->execute();
        $_SESSION['uid']   = db()->insert_id;
        $_SESSION['login'] = $login;
        $st->close();
    }
    return (int) $_SESSION['uid'];
}
