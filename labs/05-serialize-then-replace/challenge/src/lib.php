<?php
/*
 * PhotoVault - a very small profile service.
 *
 * Profiles live in a server-side store as PHP-serialized objects.  They are
 * written back on every profile update and read back on every page view.
 */

const STORE  = '/var/lib/vault';
const THUMBS = '/var/www/html/thumbs';

class Profile
{
    public $nickname;
    public $username;
    public $bio;

    public function __construct($nickname = '', $username = '', $bio = '')
    {
        $this->nickname = $nickname;
        $this->username = $username;
        $this->bio      = $bio;
    }
}

/* Keeps a generated thumbnail on disk so we only build it once. */
class ThumbnailCache
{
    public $path = null;   // where the thumbnail is stored
    public $data = '';     // the bytes (anything stringable will do)

    public function __destruct()
    {
        if ($this->path !== null) {
            @file_put_contents($this->path, (string) $this->data);
        }
    }
}

/* Pulls an image lazily through a stream wrapper (local path, http, ...). */
class RemoteImage
{
    public $src = '';

    public function __toString()
    {
        $raw = @file_get_contents($this->src);
        return $raw === false ? '' : $raw;
    }
}

function valid_username($u)
{
    return is_string($u) && preg_match('/^[A-Za-z0-9_]{3,32}$/', $u) === 1;
}

function profile_file($username)
{
    return STORE . '/profiles/' . $username . '.ser';
}

function save_profile(Profile $p)
{
    $blob = serialize($p);

    /*
     * Defence in depth: profile fields end up in media paths further down the
     * road, so make sure nothing we persist can be used to walk out of the
     * media directory later on.
     */
    $blob = str_replace('../', '', $blob);

    file_put_contents(profile_file($p->username), $blob);
}

function load_profile($username)
{
    $f = profile_file($username);
    if (!is_file($f)) {
        return null;
    }
    return unserialize(file_get_contents($f));
}

function current_user()
{
    $sid = isset($_COOKIE['vault_sid']) ? $_COOKIE['vault_sid'] : '';
    if (!preg_match('/^[a-f0-9]{32}$/', $sid)) {
        return null;
    }
    $f = STORE . '/sess/' . $sid;
    return is_file($f) ? file_get_contents($f) : null;
}

function start_session($username)
{
    $sid = bin2hex(random_bytes(16));
    file_put_contents(STORE . '/sess/' . $sid, $username);
    setcookie('vault_sid', $sid, 0, '/');
    return $sid;
}

function e($v)
{
    return is_string($v) ? htmlspecialchars($v, ENT_QUOTES, 'UTF-8') : '(not a string)';
}

function page($title, $body)
{
    echo "<!doctype html><meta charset=utf-8><title>PhotoVault - $title</title>";
    echo "<style>body{font:14px/1.5 monospace;max-width:48em;margin:2em auto;padding:0 1em}";
    echo "input,textarea{width:100%;font:inherit}fieldset{margin:1em 0}pre{white-space:pre-wrap}</style>";
    echo "<h1>PhotoVault</h1>$body";
}
