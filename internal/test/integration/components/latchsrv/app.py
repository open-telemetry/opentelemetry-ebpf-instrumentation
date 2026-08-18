# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Serves inbound requests on a keep-alive connection and issues outgoing requests
# from the same thread. RESPONSE_MODE picks how the response says where it ends;
# in every mode but "inflight" the outgoing calls happen after the response is
# provably over, so they must not inherit the inbound request's trace. In
# "inflight" the calls happen while the response is still open, so they must.

import os
import socket
from urllib.request import urlopen

PORT = int(os.environ.get("PORT", "8080"))
TARGETS = [t for t in os.environ.get("TARGETS", "").split(",") if t]
MODE = os.environ.get("RESPONSE_MODE", "cl")

RESPONSES = {
    "cl": [b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"],
    "chunked": [
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"2\r\nok\r\n0\r\n\r\n"
    ],
    # headers and body written separately: the response completes on a later send
    "multiwrite": [
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n",
        b"ok",
    ],
    "nobody": [b"HTTP/1.1 204 No Content\r\n\r\n"],
}

# enough header bytes that no single parsing window can hold them
_PADDING = b"".join(
    b"X-Pad-%02d: %s\r\n" % (i, b"p" * 120) for i in range(20)
)
RESPONSES["bigheaders"] = [
    b"HTTP/1.1 200 OK\r\n" + _PADDING + b"Content-Length: 2\r\n\r\nok"
]

# chunked response left open across the outgoing calls: the terminal chunk is
# only written after them, so the calls belong to the inbound request
INFLIGHT_START = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"2\r\nok\r\n"
)
INFLIGHT_END = b"0\r\n\r\n"


def call_targets(conn):
    for target in TARGETS:
        try:
            urlopen(target, timeout=5).read()
        except Exception as err:  # noqa: BLE001 - keep serving on target hiccups
            print("target %s failed: %s" % (target, err), flush=True)


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT))
srv.listen(8)
print("listening on %d, mode=%s, targets=%s" % (PORT, MODE, TARGETS), flush=True)

while True:
    conn, _ = srv.accept()
    while True:
        try:
            request = conn.recv(65536)
        except OSError:
            break

        if not request:
            break

        if MODE == "inflight":
            conn.sendall(INFLIGHT_START)
            call_targets(conn)
            conn.sendall(INFLIGHT_END)
            continue

        for piece in RESPONSES[MODE]:
            conn.sendall(piece)

        call_targets(conn)

    conn.close()
