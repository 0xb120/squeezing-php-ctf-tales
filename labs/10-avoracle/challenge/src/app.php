<?php
/**
 * inkstone -- a tiny profile page. ~40 lines, no framework.
 *
 * The session holds two things: the nickname you chose, and the workstation's
 * licence key. They live in the same file on disk, in that order.
 */

const FLAG_FILE = '/flag.txt';

function ink_start(): void
{
    session_start();
}

/**
 * Rebuild the session from scratch on every write so the key order on disk is
 * always "nick first, licence second" regardless of what was there before.
 */
function ink_store(string $nick): void
{
    $_SESSION = [];
    $_SESSION['nick'] = $nick;
    $_SESSION['flag'] = trim((string) @file_get_contents(FLAG_FILE));
}

function ink_header(string $title): void
{
    echo "<!doctype html><meta charset=utf-8><title>$title</title>",
         "<style>body{font-family:monospace;max-width:52em;margin:2em auto;",
         "background:#0f1216;color:#cdd6e0}a{color:#7fd}h1{color:#f96}",
         "code{background:#1a1f26;padding:.1em .3em}form{margin:1em 0}",
         "input{font:inherit;background:#1a1f26;color:#cdd6e0;border:1px solid #333;",
         "padding:.3em;width:30em}</style>";
}
