#!/usr/bin/env python3
# Minimal h2c (cleartext HTTP/2) server that deterministically multiplexes: it
# withholds responses until BATCH streams have arrived, then writes them all in
# a single send() so the instrumented process emits one write buffer carrying
# many streams. /health is answered immediately; any other path returns 200.
import os
import socket
import threading

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, StreamEnded

PORT = int(os.getenv("PORT", "8080"))
BATCH = int(os.getenv("BATCH", "5"))  # flush responses only once this many streams are pending


def send_one_response(conn: H2Connection, stream_id: int) -> None:
    body = b"ok"
    conn.send_headers(
        stream_id,
        [
            (b":status", b"200"),
            (b"content-type", b"text/plain"),
            (b"content-length", str(len(body)).encode()),
        ],
    )
    conn.send_data(stream_id, body, end_stream=True)


def handle(sock: socket.socket) -> None:
    conn = H2Connection(config=H2Configuration(client_side=False))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    paths: dict[int, str] = {}
    ready: list[int] = []  # streams that have fully arrived (END_STREAM seen)

    try:
        while True:
            data = sock.recv(65535)
            if not data:
                return
            for event in conn.receive_data(data):
                if isinstance(event, RequestReceived):
                    hdrs = dict(event.headers)
                    paths[event.stream_id] = hdrs.get(b":path", b"/").decode()
                elif isinstance(event, StreamEnded):
                    ready.append(event.stream_id)

            # Flush control frames (SETTINGS ack, etc.) that h2 queued.
            ctrl = conn.data_to_send()
            if ctrl:
                sock.sendall(ctrl)

            # Health probes shouldn't wait for a batch — answer them immediately.
            for sid in [s for s in ready if paths.get(s) == "/health"]:
                send_one_response(conn, sid)
                ready.remove(sid)
                paths.pop(sid, None)
                sock.sendall(conn.data_to_send())

            # Once BATCH real requests are queued, answer them ALL in ONE send().
            if len(ready) >= BATCH:
                batch = ready[:BATCH]
                del ready[:BATCH]
                for sid in batch:
                    send_one_response(conn, sid)
                    paths.pop(sid, None)
                sock.sendall(conn.data_to_send())  # single write, BATCH streams
    finally:
        sock.close()


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(128)
    print(f"h2mux server listening on :{PORT} (BATCH={BATCH})", flush=True)
    while True:
        client, _ = srv.accept()
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
