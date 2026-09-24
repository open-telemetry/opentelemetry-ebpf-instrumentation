#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""h2c server that answers a whole batch of streams with one send().

It waits until STREAMS requests have arrived before answering, so the reply is
one buffer with many streams, which is what the test needs. It also reports
how many request HEADERS frames came in a single recv(), so the test can tell
the streams really shared one buffer, and how many were cut across recv()
calls, for the test that reads READ_SIZE bytes at a time.
"""

import os
import socket
import sys
import threading

from h2hpack import Decoder, Encoder
from wire import (
    CLIENT_PREFACE,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_ACK,
    FRAME_CONTINUATION,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    GRPC_CONTENT_TYPE,
    GRPC_STATUSES,
    HTTP_STATUSES,
    MODE_GRPC,
    MODE_HTTP,
    build_frame,
    count_headers,
    emit,
    parse_burst_path,
    split_frames,
)

READ_SIZE = int(os.getenv("READ_SIZE", "65536"))
RESPONSE_BODY = b"ok"


class Stream:
    __slots__ = ("id", "index", "burst", "content_type", "cut")

    def __init__(self, stream_id, burst, index, content_type):
        self.id = stream_id
        self.burst = burst
        self.index = index
        self.content_type = content_type
        self.cut = False


def serve_connection(conn, batch):
    encoder = Encoder()
    decoder = Decoder()

    leftover = b""
    ready = []
    greeted = False
    arrived = 0
    # a HEADERS frame whose block still waits for CONTINUATION frames
    block = None

    with conn:
        while True:
            chunk = conn.recv(READ_SIZE)
            if not chunk:
                return

            if not greeted:
                if not chunk.startswith(CLIENT_PREFACE):
                    print("connection did not open with the HTTP/2 preface", flush=True)
                    return
                chunk = chunk[len(CLIENT_PREFACE):]
                greeted = True
                conn.sendall(build_frame(FRAME_SETTINGS, 0, 0))

            aligned = not leftover
            frames, leftover = split_frames(leftover + chunk)
            headers_in_read = count_headers(frames)

            for position, frame in enumerate(frames):
                if frame.type == FRAME_CONTINUATION and block is not None:
                    block.payload += frame.payload
                    block.flags |= frame.flags & FLAG_END_HEADERS
                    frame = block
                if frame.type == FRAME_HEADERS and not frame.flags & FLAG_END_HEADERS:
                    block = frame
                    continue
                block = None

                stream = handle_frame(conn, decoder, frame)
                if stream is not None:
                    # only the first frame can hold bytes an earlier recv() returned
                    stream.cut = not aligned and position == 0
                    ready.append(stream)
                    arrived = headers_in_read if aligned else 0

            while len(ready) >= batch:
                respond(conn, encoder, ready[:batch], arrived)
                del ready[:batch]


def handle_frame(conn, decoder, frame):
    """Answers connection frames, and returns a request once it has fully arrived."""
    if frame.type == FRAME_SETTINGS:
        if not frame.flags & FLAG_ACK:
            conn.sendall(build_frame(FRAME_SETTINGS, FLAG_ACK, 0))
        return None

    if frame.type != FRAME_HEADERS:
        return None

    fields = dict(decoder.decode(frame.payload))
    burst, index = parse_burst_path(fields.get(":path", ""))
    if burst is None:
        print("unexpected path {!r}".format(fields.get(":path", "")), flush=True)
        return None
    if not frame.ends_stream():
        return None

    return Stream(frame.stream_id, burst, index, fields.get("content-type", ""))


def respond(conn, encoder, group, req_headers_in_one_read):
    """Writes the whole batch of responses with one send()."""
    mode = MODE_GRPC if group[0].content_type == GRPC_CONTENT_TYPE else MODE_HTTP
    statuses = GRPC_STATUSES if mode == MODE_GRPC else HTTP_STATUSES

    out = b""
    for stream in group:
        status = str(statuses[stream.index % len(statuses)])
        if mode == MODE_GRPC:
            out += build_frame(
                FRAME_HEADERS, FLAG_END_HEADERS, stream.id,
                encoder.encode([(":status", "200"), ("content-type", GRPC_CONTENT_TYPE)]),
            )
            out += build_frame(FRAME_DATA, 0, stream.id, RESPONSE_BODY)
            out += build_frame(
                FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream.id,
                encoder.encode([("grpc-status", status)]),
            )
            continue

        out += build_frame(
            FRAME_HEADERS, FLAG_END_HEADERS, stream.id,
            encoder.encode([
                (":status", status),
                ("content-type", "text/plain"),
                ("content-length", str(len(RESPONSE_BODY))),
            ]),
        )
        out += build_frame(FRAME_DATA, FLAG_END_STREAM, stream.id, RESPONSE_BODY)

    record = {
        "burst": group[0].burst,
        "mode": mode,
        "req_headers_in_one_read": req_headers_in_one_read,
        "cut_req_headers": sum(1 for stream in group if stream.cut),
    }
    if any(stream.burst != group[0].burst for stream in group):
        record["error"] = "batch had streams from more than one burst"

    conn.sendall(out)
    emit("H2MUX_SERVER", record)


def main():
    port = int(os.getenv("PORT", "8080"))
    batch = int(os.getenv("STREAMS", "5"))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(64)
    print("h2mux server listening on :{}, batching {} streams".format(port, batch), flush=True)

    while True:
        conn, _ = listener.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=serve_connection, args=(conn, batch), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
