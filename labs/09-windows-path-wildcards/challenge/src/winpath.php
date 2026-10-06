<?php
/**
 * winpath.php — EMULATION LAYER. This file is NOT part of the vulnerable
 * application logic; it is the Linux stand-in for the Win32 path layer that
 * PHP sits on top of when it runs on Windows.
 *
 * On Windows, PHP hands the path it was given straight to the Win32 file API
 * (CreateFileW / FindFirstFileW ...). Everything below happens *inside
 * Windows*, not inside PHP:
 *
 *   - "DOS devices" path parsing keeps three legacy wildcard characters alive
 *     in filenames that are handed to FindFirstFile():
 *
 *         '<'  DOS_STAR  ~ '*'      (match a run of characters)
 *         '>'  DOS_QM    ~ '?'      (match a single character)
 *         '"'  DOS_DOT   ~ '.'      (match a literal dot)
 *
 *     They are illegal in a *stored* filename, so nothing on disk can ever
 *     contain them — but they survive the trip from PHP down to the kernel,
 *     where they are expanded. A function whose only observable behaviour is
 *     "the file was found" / "the file was not found" therefore becomes a
 *     filename oracle.
 *
 *   - Path components are case insensitive.
 *   - Trailing dots and trailing spaces are stripped from every component
 *     ("index.php." and "index.php   " both open "index.php").
 *   - '/' and '\' are interchangeable separators.
 *   - NTFS Alternate Data Streams: "file:stream:$DATA" addresses a stream of
 *     "file"; the default stream "file::$DATA" is the file itself. Writing to
 *     "name::$INDEX_ALLOCATION" asks NTFS for the directory-index stream,
 *     which makes the create call materialise a *directory* named "name" and
 *     then fail — an arbitrary file write turned into a mkdir primitive.
 *
 * The functions below reproduce those rules on a normal Linux filesystem so
 * the challenge can be played in a container. See README.md "Emulation notice"
 * for exactly which parts are faithful and which are simplified.
 */

final class WinPath
{
    /** Container directory that plays the role of the C: drive. */
    const DRIVE_ROOT = '/';

    /** Characters Win32 expands as wildcards, mapped to their glob meaning. */
    const WILDCARDS = ['<' => '*', '>' => '?', '"' => '.'];

    /**
     * Resolve a Windows-style path to the real Linux path it ends up opening,
     * or null when Win32 would answer "file not found".
     */
    public static function resolve(string $winPath): ?string
    {
        [$path, ] = self::splitStream($winPath);

        $path = str_replace('\\', '/', $path);

        // "C:/x" and "/x" are both absolute here; anything else is relative to
        // the drive root as well (the app never relies on a CWD).
        $path = preg_replace('#^[A-Za-z]:#', '', $path);

        $real  = rtrim(self::DRIVE_ROOT, '/');
        $parts = explode('/', $path);

        foreach ($parts as $part) {
            // '.' and '..' are resolved by the path canonicaliser before the
            // trailing-dot rule gets a chance to eat them.
            if ($part !== '.' && $part !== '..') {
                $part = self::stripTrailingJunk($part);
            }
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                $real = ($real === '') ? '' : dirname($real);
                if ($real === '.' || $real === '/') {
                    $real = '';
                }
                continue;
            }
            $match = self::matchInDir($real === '' ? '/' : $real, $part);
            if ($match === null) {
                return null;
            }
            $real = ($real === '' ? '' : $real) . '/' . $match;
        }

        return $real === '' ? '/' : $real;
    }

    /** file_exists() as Windows answers it. */
    public static function exists(string $winPath): bool
    {
        return self::resolve($winPath) !== null;
    }

    /**
     * Win32 CreateFile()-flavoured write, kept minimal: it only exists so the
     * ::$INDEX_ALLOCATION behaviour can be demonstrated. Returns the number of
     * bytes written, or false when the call failed the way Windows fails it.
     */
    public static function writeFile(string $winPath, string $data)
    {
        [$path, $stream] = self::splitStream($winPath);

        $parent = self::resolve(dirname(str_replace('\\', '/', $path)));
        if ($parent === null) {
            return false;
        }
        $leaf = self::stripTrailingJunk(basename(str_replace('\\', '/', $path)));
        if ($leaf === '' || strpbrk($leaf, '<>"') !== false) {
            return false;   // wildcards are illegal in a name being created
        }
        $target = $parent . '/' . $leaf;

        if (strcasecmp($stream, '$INDEX_ALLOCATION') === 0) {
            // NTFS: the directory index stream only exists on a directory, so
            // the object is created as a directory and the write then fails.
            if (!is_dir($target)) {
                @mkdir($target, 0777);
            }
            return false;
        }
        if ($stream !== '' && strcasecmp($stream, '$DATA') !== 0) {
            // A named stream. We model it as a sidecar file so that the stream
            // is not visible through a normal directory listing.
            $target .= '.__ads__' . preg_replace('/[^A-Za-z0-9_.-]/', '_', $stream);
        }
        return @file_put_contents($target, $data);
    }

    /* ------------------------------------------------------------------ */

    /**
     * Split "name:stream:$TYPE" / "name::$TYPE" into [name, type].
     * A leading drive letter ("C:\...") is not a stream separator.
     */
    private static function splitStream(string $p): array
    {
        $prefix = '';
        if (preg_match('#^([A-Za-z]:)(.*)$#s', $p, $m)) {
            $prefix = $m[1];
            $p      = $m[2];
        }
        $sep = strpos($p, ':');
        if ($sep === false) {
            return [$prefix . $p, ''];
        }
        $name = substr($p, 0, $sep);
        $rest = substr($p, $sep + 1);
        // "::$DATA" -> stream name empty, type $DATA; ":foo:$DATA" -> foo
        $bits   = explode(':', $rest);
        $type   = end($bits);
        $stream = ($bits[0] !== '') ? $bits[0] : $type;
        return [$prefix . $name, $stream];
    }

    /** Windows drops trailing dots and spaces from every path component. */
    private static function stripTrailingJunk(string $part): string
    {
        return rtrim($part, ". \t");
    }

    /**
     * Enumerate $dir the way FindFirstFile() does and return the first entry
     * matching $pattern, or null. Matching is case insensitive and expands the
     * three DOS wildcard characters.
     */
    private static function matchInDir(string $dir, string $pattern): ?string
    {
        if (!is_dir($dir)) {
            return null;
        }
        $hasWildcard = strpbrk($pattern, '<>"') !== false;

        $entries = @scandir($dir);
        if ($entries === false) {
            return null;
        }
        sort($entries, SORT_STRING);   // deterministic "directory order"

        $rx = $hasWildcard ? self::toRegex($pattern) : null;
        foreach ($entries as $e) {
            if ($e === '.' || $e === '..') {
                continue;
            }
            if ($rx === null) {
                if (strcasecmp($e, $pattern) === 0) {
                    return $e;
                }
            } elseif (preg_match($rx, $e)) {
                return $e;
            }
        }
        return null;
    }

    /** Turn a DOS wildcard pattern into a case-insensitive PCRE. */
    private static function toRegex(string $pattern): string
    {
        $out = '';
        $len = strlen($pattern);
        for ($i = 0; $i < $len; $i++) {
            $c = $pattern[$i];
            if (isset(self::WILDCARDS[$c])) {
                $g = self::WILDCARDS[$c];
                $out .= ($g === '*') ? '.*' : (($g === '?') ? '.' : '\\.');
            } else {
                $out .= preg_quote($c, '#');
            }
        }
        return '#^' . $out . '$#i';
    }
}
