#!/usr/bin/env python3
# h2c client that repeatedly fires bursts of STREAMS requests on one connection,
# writing all their HEADERS in a single send() to force one multiplexed buffer.
# Each burst uses a fresh random id and paths /burst/<id>/stream/<i> so the test
# can group captured spans by burst.
import os
import secrets
import socket
import sys
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ResponseReceived

HOST = os.getenv("TARGET_HOST", "h2mux-server")
PORT = int(os.getenv("TARGET_PORT", "8080"))
STREAMS = int(os.getenv("STREAMS", "5"))
ONESHOT = os.getenv("ONESHOT", "").lower() in ("1", "true", "yes")


def burst() -> int:
    burst_id = secrets.randbelow(1_000_000)  # unique per burst; every request in it carries this id
    sock = socket.create_connection((HOST, PORT))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn = H2Connection(config=H2Configuration(client_side=True))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    want = set()
    for i in range(STREAMS):
        sid = conn.get_next_available_stream_id()
        conn.send_headers(
            sid,
            [
                (b":method", b"GET"),
                (b":path", f"/burst/{burst_id}/stream/{i}".encode()),
                (b":scheme", b"http"),
                (b":authority", HOST.encode()),
            ],
            end_stream=True,
        )
        want.add(sid)
    sock.sendall(conn.data_to_send())  # all STREAMS HEADERS in ONE write

    got = set()
    while len(got) < STREAMS:
        data = sock.recv(65535)
        if not data:
            break
        for event in conn.receive_data(data):
            if isinstance(event, ResponseReceived):
                got.add(event.stream_id)
        out = conn.data_to_send()
        if out:
            sock.sendall(out)
    sock.close()
    ok = len(want & got)
    print(f"burst id={burst_id} streams={STREAMS} responded={ok}", flush=True)
    return ok


def main() -> None:
    if ONESHOT:
        sys.exit(0 if burst() == STREAMS else 1)
    while True:
        try:
            burst()
        except Exception as e:  # keep generating traffic across transient errors
            print(f"burst error: {e}", flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()
