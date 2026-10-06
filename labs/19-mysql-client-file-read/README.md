# 19 — Nimbus Panel: the MySQL server that reads *your* files

An admin panel that "health-checks" a customer database by connecting to
host/port/user/password you provide. You control the server it connects to.

## Article reference

Recreates the *Honorable Mention* entry in "The Art of PHP — My CTF Journey and
Untold Stories!" by Orange Tsai (Phrack #72): *"Attacking the MySQL client-side
is another fascinating approach — such as triggering memory corruption [90] via
a malicious MySQL server, or leveraging PHAR deserialization [91] again."*

- [90] Charles "cfreal" Fol — mysqlnd/PDO password buffer overflow:
  <https://bugs.php.net/bug.php?id=81719>
- [91] LoRexxar & Dawu (Knownsec 404) — *MySQL Client Arbitrary File Reading
  Attack Chain Extension*:
  <https://medium.com/@knownsec404team/mysql-client-arbitrary-file-reading-attack-chain-extension-727bb63f578c>

This lab implements the **arbitrary file read** primitive (the foundation of
both references) and the **`phar://` deserialisation** chain extension. It does
*not* recreate cfreal's memory-corruption RCE.

## Difficulty / category

Medium — web / protocol / `LOAD DATA LOCAL INFILE` abuse.

## Run it

```sh
make up        # challenge on http://127.0.0.1:8019/  + rogue MySQL on 127.0.0.1:9019
make solve     # automated exploit (starts its own rogue server, reads /flag.txt, then phar RCE)
make verify    # build -> exploit -> assert flag -> tear down
make down      # stop and clean up
```

Drive it by hand: `make up`, open <http://127.0.0.1:8019/>, and in the "connect
to a customer database" form put `host = <your IP>`, `port = 9019` (the rogue
server started by `make up`), any user/password, then "run health check". The
rogue server prints the file it stole. See the writeup for pointing it at a
different file or running the rogue server straight on the host with
`make rogue`.

## Your goal

The flag is at `/flag.txt` inside the challenge container and is **not**
reachable over HTTP. The panel connects out to a MySQL server of your choosing
and runs a query. That is the whole attack surface — make the "server" do
something the panel never asked for.

## Hints

<details>
<summary>Hint 1</summary>

`LOAD DATA LOCAL INFILE` is driven by the *server*, not the client. Any query
response may be a "please send me this local file" packet, and a client with
local-infile enabled obeys it. The panel enables it for its nightly importer.
</details>

<details>
<summary>Hint 2</summary>

You do not need a real MySQL server. You need ~150 lines that speak the
handshake, say "auth OK", and answer the first query with a `0xFB` packet
naming `/flag.txt`. The client uploads the file to you.
</details>

<details>
<summary>Hint 3</summary>

Same primitive, bigger payload: answer with a `phar://…` path instead of a
plain file. Opening a phar parses its manifest and `unserialize()`s the
metadata. The panel ships a class with a `__destruct` that writes a file —
point its properties at a PHP web shell under `uploads/`.
</details>

## What you will learn

- The MySQL client/server handshake, `COM_QUERY`, and the `0xFB` LOCAL INFILE
  request packet — byte by byte.
- Why "connect to this database" is an SSRF-grade primitive when the client has
  `local_infile` on.
- How an arbitrary *file read* is upgraded to `phar://` deserialisation and, via
  a `__destruct` gadget, to remote code execution.
- The `mysqli.allow_local_infile` / `MYSQLI_OPT_LOCAL_INFILE` settings and how
  to switch this class of bug off.
