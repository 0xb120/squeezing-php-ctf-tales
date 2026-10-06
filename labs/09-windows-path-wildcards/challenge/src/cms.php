<?php
/**
 * Minimal PHPCMS-flavoured bootstrap.
 *
 * The site keeps one server-side "visitor book" session that every anonymous
 * visitor shares, so no session cookie is ever handed out (session.use_cookies
 * is off in php.ini). The session id is generated once, when the box boots.
 */

const FONT_DIR = 'C:\\xampp\\htdocs\\statics\\fonts\\';
const TMP_DIR  = 'C:\\xampp\\tmp\\';

function cms_session_start(): void
{
    $sid = (string) getenv('CMS_BOOK_SID');
    if ($sid === '') {
        http_response_code(500);
        exit("site not installed\n");
    }
    session_id($sid);
    session_start();
}

function cms_png(string $text): string
{
    // A 1x1 PNG. Rendering real glyphs needs GD + a TrueType font; the lab
    // only cares about "did the endpoint produce an image or not".
    $png = base64_decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='
    );
    return $png . "\x00" . substr($text, 0, 64);
}

function cms_header(string $title): void
{
    echo "<!doctype html><meta charset=utf-8><title>$title</title>",
         "<style>body{font-family:monospace;max-width:52em;margin:2em auto;",
         "background:#101418;color:#c8d0d8}a{color:#7fd}h1{color:#fa5}",
         "code{background:#1b2128;padding:.1em .3em}</style>";
}
