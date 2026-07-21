# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Reproducer for OBI issue https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2706.

Models GitLab Gitaly's backchannel wire layout: an HTTP/2-looking stream tunneled
inside a length-prefixed, separately-framed transport (yamux). We do NOT use a
real gRPC/HTTP2 library and we deliberately write this in Python, because:

  * A real grpc-go client is recognized by OBI's Go uprobe tracer, which injects
    the HPACK traceparent in the *user* buffer (before the transport frames it)
    and marks the connection so the sk_msg injector bails — no corruption.
  * Any Go process is special-cased by OBI's Go tracer, whose per-connection
    tracking diverts the sk_msg flow away from the raw HPACK-injection path.

Python is instrumented by OBI's generic tracer, so its outbound sockets go
through the raw sk_msg context-propagation path — exactly the path Gitaly's
yamux-tunneled connection falls into.

Wire protocol (mimicking yamux: a length header and its body are SEPARATE
writes, and the length is committed before the body is sent):

    [24-byte HTTP/2 client preface]                 (its own write -> offset 0)
    then, repeatedly:
      [4-byte big-endian body length L]             (its own write)
      [L-byte body = one HTTP/2 HEADERS frame]       (its own write, injection target)

When OBI classifies the socket as HTTP/2 (preface at offset 0) and splices an
HPACK "traceparent" into the HEADERS-frame body, the body grows past the L that
was already committed in the separate length write. The receiver then reads L
bytes (a truncated/rewritten frame) and the injected tail desyncs every
subsequent frame — the same failure Gitaly logs as "yamux: Invalid protocol
version".

The traceparent OBI tries to propagate comes from an inbound HTTP request: the
test calls the client's /call endpoint WITH a Traceparent header, and the client
performs the downstream yamux exchange inside that request. Without an active
trace to propagate, OBI has nothing to inject.

Endpoints (both roles):
    GET  /health -> 200 once the plumbing is up
    GET  /stats  -> {"successes","failures","corruption"}
    POST /reset  -> zero the counters
Client only:
    GET  /call   -> perform one downstream yamux exchange (send Traceparent!)
"""

import json
import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 24-byte HTTP/2 client connection preface.
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# A minimal, valid HTTP/2 HEADERS frame with END_HEADERS set:
#   length=3, type=0x01 (HEADERS), flags=0x04 (END_HEADERS), stream=1,
#   HPACK payload = :method POST (0x83), :scheme http (0x86), :path / (0x84).
# This is the injector's target: it rewrites the 3-byte length field and splices
# an HPACK traceparent onto the end.
HEADERS_FRAME = bytes([0x00, 0x00, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
                       0x83, 0x86, 0x84])

# HEADERS frames sent per /call (each an independent injection target).
FRAMES_PER_CALL = 5


class Counters:
    def __init__(self):
        self._lock = threading.Lock()
        self.successes = 0
        self.failures = 0
        self.corruption = 0

    def add(self, field, n=1):
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def snapshot(self):
        with self._lock:
            return {"successes": self.successes,
                    "failures": self.failures,
                    "corruption": self.corruption}


C = Counters()


def recvn(sock, n):
    """Read exactly n bytes, or None on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ---- server role ----

def handle_conn(conn):
    """Read the preface then length-prefixed HEADERS frames, verifying framing.

    Any deviation (wrong preface, absurd length, altered body) means the wire
    stream was corrupted by mid-stream injection -> count it.
    """
    try:
        pre = recvn(conn, len(PREFACE))
        if pre != PREFACE:
            C.add("corruption")
            return
        while True:
            hdr = recvn(conn, 4)
            if hdr is None:
                return
            length = struct.unpack(">I", hdr)[0]
            if length != len(HEADERS_FRAME):
                # The committed length no longer matches the body actually on the
                # wire: injection shifted the framing.
                C.add("corruption")
                return
            body = recvn(conn, length)
            if body is None:
                return
            if body != HEADERS_FRAME:
                # The HEADERS frame was mutated (length field rewritten / bytes
                # spliced in) — the exact #2706 corruption.
                C.add("corruption")
                return
    except OSError:
        C.add("corruption")
    finally:
        conn.close()


def run_server():
    grpc_port = int(os.environ.get("GRPC_PORT", "50051"))
    ready = {"v": False}
    threading.Thread(target=run_status, args=(lambda: ready["v"], None), daemon=True).start()

    lis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lis.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lis.bind(("", grpc_port))
    lis.listen(128)
    print(f"yamux server on :{grpc_port}", flush=True)
    ready["v"] = True
    while True:
        conn, _ = lis.accept()
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


# ---- client role ----

def make_downstream_call(target):
    """Open a fresh connection and perform one preface + N-HEADERS exchange.

    A fresh connection per call guarantees the HTTP/2 preface flows again while
    OBI is attached (OBI keys HTTP/2 detection on the preface at offset 0 of a
    write). Called synchronously inside the /call HTTP handler so OBI propagates
    that request's Traceparent into these downstream writes.
    """
    host, port = target.rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=5)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Own write -> preface at offset 0 -> OBI flags the socket HTTP/2.
        s.sendall(PREFACE)
        for _ in range(FRAMES_PER_CALL):
            # Length and body as SEPARATE writes (like yamux). The length is
            # committed before the body; injection into the body breaks the
            # contract.
            s.sendall(struct.pack(">I", len(HEADERS_FRAME)))
            s.sendall(HEADERS_FRAME)
        C.add("successes")
    finally:
        s.close()


def run_client():
    target = os.environ.get("TARGET", "server:50051")

    def on_call():
        try:
            make_downstream_call(target)
        except OSError:
            # A downstream failure is the client-side face of the corruption:
            # the injected bytes desynced the stream and the peer tore it down.
            C.add("failures")
            raise

    # The client is "healthy" as soon as its HTTP server can answer — downstream
    # connectivity is exercised separately via /call.
    run_status(lambda: True, on_call)


# ---- HTTP status endpoint ----

def make_handler(healthy, on_call):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _send(self, code, body=b""):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send(200 if healthy() else 503, b"ok")
            elif self.path == "/stats":
                self._send(200, json.dumps(C.snapshot()).encode())
            elif self.path.startswith("/call") and on_call is not None:
                try:
                    on_call()
                    self._send(200, b"ok")
                except Exception as exc:  # noqa: BLE001
                    self._send(500, str(exc).encode())
            else:
                self._send(404)

    return Handler


def run_status(healthy, on_call):
    port = int(os.environ.get("HEALTH_PORT", "8080"))
    print(f"status HTTP server on :{port}", flush=True)
    ThreadingHTTPServer(("", port), make_handler(healthy, on_call)).serve_forever()


def main():
    mode = os.environ.get("MODE")
    if mode == "server":
        run_server()
    elif mode == "client":
        run_client()
    else:
        raise SystemExit(f"MODE must be 'server' or 'client', got {mode!r}")


if __name__ == "__main__":
    main()
