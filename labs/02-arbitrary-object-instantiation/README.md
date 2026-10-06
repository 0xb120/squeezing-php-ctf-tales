# 02 — Arbitrary Object Instantiation

PluginHub lets you load any plugin class you like, with any constructor
arguments you like. It just does not ship a single plugin. Good luck.

## Article reference

Recreates the attack primitive that opens section **1.1 — "Formatting Objects
for Fun and Profit!"** of *The Art of PHP - My CTF Journey and Untold Stories!*
(Orange Tsai, Phrack #72):

```php
<?php
    $model = $_GET['model'];
    $object = new $model();
```

Original sources, both cited by the article:

- **[16]** CVE-2015-1033 — *"PHP Object Instantiation issues in HumHub"*,
  Midnight Blue, the 2015 report that put this bug class on the map:
  <https://www.midnightblue.nl/blog/cve-2015-1033-humhub-php-object-instantiation-issues>
- **[17]** Arseniy Sharoglazov (@_mohemiv, PT SWARM), *"Exploiting Arbitrary
  Object Instantiations in PHP without Custom Classes"*:
  <https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/>

## Difficulty and category

**Difficulty:** medium
**Category:** web / PHP built-in classes / SSRF

## Run it

```sh
make up       # builds both images, then serves http://127.0.0.1:8002/
make solve    # runs the exploit from a container
make verify   # build -> up -> exploit -> assert the flag -> tear down
make down     # stop and remove everything
```

Two services come up:

- `challenge` — PluginHub, PHP 7.4.33 + `ext-soap`, published on
  `127.0.0.1:8002`.
- `registry` — the internal package registry. **Not published**, and not even
  on the same compose network as you: it lives alone with `challenge` on an
  `internal: true` network, as `registry:8080`. The solver container is on the
  other network, so it can talk to PluginHub and to nothing else.

## Your goal

The flag never touches the front-end. It is `/flag.txt` **inside the `registry`
container** (built from `registry/flag.txt`, mode `0400`) — not in the web root,
not on the challenge container's filesystem at all — and the registry will only
hand it over to a request that looks like it came from the application server
itself.

You cannot reach the registry — there is no route from your container to it at
all. PluginHub can. All PluginHub gives you is one line of code:

```php
$instance = new $plugin(...array_values($args));
```

where `$plugin` is a class name from the query string and `$args` is a JSON
array from the query string. PluginHub declares **no classes of its own** and
registers no autoloader, so everything you use has to be a class PHP itself
provides.

Read `registry-api.txt` on the front page: it tells you exactly what the
registry wants to see. The hard part is saying it.

## Hints

<details>
<summary>Hint 1</summary>

`get_declared_classes()` is a long list on a stock PHP build. You want a
constructor that (a) takes a URL and (b) takes a second argument that lets you
influence the request it makes. Which bundled extension exists here that is not
in a default `php:7.4-apache` image? The `Dockerfile` is in the repo.

</details>

<details>
<summary>Hint 2</summary>

`new SoapClient($wsdl, $options)` fetches `$wsdl` over HTTP the moment the
object is constructed — that is your SSRF. But the registry's administrative
endpoint is not a GET, and it wants a header you cannot set with a URL.

Look at what PHP's SOAP extension does with the `user_agent` option. Does it
validate it?

</details>

<details>
<summary>Hint 3</summary>

A header value that contains `\r\n\r\n` does not just add headers — it ends the
header block. Whatever you write after it is read by the server as a brand new
request, with a method and a body of your choosing. Count your `Content-Length`
carefully.

Then remember you never see the response: find the side effect instead.

</details>

## What you will learn

- Why `new $class(...)` with attacker-controlled input is a serious bug even
  when the application contains zero gadget classes.
- How to pick exploitation primitives out of PHP's built-in class set, and how
  to enumerate them with the Reflection API.
- `SoapClient` as an SSRF primitive: the WSDL fetch fires from the constructor,
  before any method call.
- CRLF injection through the `user_agent` SOAP option, and how to escalate it
  from "extra headers" to full HTTP request smuggling.
- How to finish a *blind* SSRF: look for a state change you can observe from
  the front-end instead of a response you can read.
- Three more built-in-class primitives that genuinely work on this image
  (`SimpleXMLElement` as a response reader and as an XXE trigger,
  `SplFileObject` as a filesystem oracle, `PDO` as a file creator) — all
  documented and measured in `WRITEUP.md`.
