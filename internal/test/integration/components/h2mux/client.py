#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""h2c client that sends a whole burst of requests with one send().

Each burst has STREAMS requests on one connection. The client reports how many
of the server's response HEADERS frames came back in a single recv(), so the
test only checks bursts that really shared one buffer.

Connections are replaced every few bursts: OBI detects HTTP/2 from the
connection preface, so the test needs connections opened after OBI started,
but each connection must live long enough for the HPACK dynamic tables to be
used.
"""

import os
import random
import socket
import threading
import time

from h2hpack import Decoder, Encoder
from wire import (
    CLIENT_PREFACE,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_ACK,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    GRPC_CONTENT_TYPE,
    method_for,
    MODE_GRPC,
    MODE_HTTP,
    build_frame,
    burst_path,
    count_headers,
    emit,
    split_frames,
)

READ_SIZE = 65536
BURSTS_PER_CONNECTION = 8
RESPONSE_TIMEOUT = 20
BURST_INTERVAL = float(os.getenv("BURST_INTERVAL_MS", "500")) / 1000


class Session:
    def __init__(self, conn, mode, streams, authority):
        self.conn = conn
        self.mode = mode
        self.streams = streams
        self.authority = authority
        self.id = str(random.randrange(1_000_000))
        self.encoder = Encoder()
        self.decoder = Decoder()
        self.leftover = b""
        self.next_stream_id = 1
        self.statuses = {}
        self.open = {}

    def burst(self, index):
        burst_id = str(random.randrange(1_000_000))
        self.statuses = {}
        self.open = {}

        content_type = GRPC_CONTENT_TYPE if self.mode == MODE_GRPC else "text/plain"

        out = b""
        for stream in range(self.streams):
            stream_id = self.next_stream_id
            self.next_stream_id += 2
            self.open[stream_id] = stream
            out += build_frame(
                FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream_id,
                self.encoder.encode([
                    (":method", method_for(stream)),
                    (":scheme", "http"),
                    (":authority", self.authority),
                    (":path", burst_path(burst_id, stream)),
                    ("content-type", content_type),
                ]),
            )

        record = {
            "burst": burst_id,
            "mode": self.mode,
            "conn": self.id,
            "index": index,
        }

        self.conn.sendall(out)

        header_reads, headers_in_first_read = self.collect_responses()
        if header_reads == 1:
            record["resp_headers_in_one_read"] = headers_in_first_read

        record["exchanges"] = [
            {
                "method": method_for(stream),
                "path": burst_path(burst_id, stream),
                "status": self.statuses.get(stream_id, 0),
            }
            for stream_id, stream in sorted(self.open.items())
        ]
        emit("H2MUX_CLIENT", record)

    def collect_responses(self):
        """Reads until every stream has ended.

        Returns how many reads had response headers, and how many headers the
        first of those reads had; a burst only counts when one read had them
        all.
        """
        pending = len(self.open)
        header_reads = 0
        headers_in_first_read = 0

        while pending:
            chunk = self.conn.recv(READ_SIZE)
            if not chunk:
                raise ConnectionError("server closed the connection")

            aligned = not self.leftover
            frames, self.leftover = split_frames(self.leftover + chunk)

            headers = count_headers(frames)
            if headers:
                header_reads += 1
                if header_reads == 1 and aligned:
                    headers_in_first_read = headers

            for frame in frames:
                if self.handle_response_frame(frame):
                    pending -= 1

        return header_reads, headers_in_first_read

    def handle_response_frame(self, frame):
        """Saves a stream's status and reports whether the stream has ended.

        gRPC sends its status in the trailers, so the final status is not the
        one in the first HEADERS frame.
        """
        if frame.type == FRAME_SETTINGS:
            if not frame.flags & FLAG_ACK:
                self.conn.sendall(build_frame(FRAME_SETTINGS, FLAG_ACK, 0))
            return False

        if frame.type == FRAME_HEADERS:
            for name, value in self.decoder.decode(frame.payload):
                if name == ":status" and frame.stream_id not in self.statuses:
                    self.statuses[frame.stream_id] = int(value)
                elif name == "grpc-status":
                    self.statuses[frame.stream_id] = int(value)

        return frame.ends_stream()


def drive_connection(host, port, mode, streams):
    conn = socket.create_connection((host, port))
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.settimeout(RESPONSE_TIMEOUT)

    with conn:
        conn.sendall(CLIENT_PREFACE + build_frame(FRAME_SETTINGS, 0, 0))

        session = Session(conn, mode, streams, "{}:{}".format(host, port))

        for index in range(BURSTS_PER_CONNECTION):
            session.burst(index)
            time.sleep(BURST_INTERVAL)


def run_mode(host, port, mode, streams):
    while True:
        try:
            drive_connection(host, port, mode, streams)
        except Exception as err:  # keep sending traffic after an error
            print("{} connection: {}".format(mode, err), flush=True)
            time.sleep(BURST_INTERVAL)


def main():
    host = os.getenv("TARGET_HOST", "h2mux-server")
    port = int(os.getenv("TARGET_PORT", "8080"))
    streams = int(os.getenv("STREAMS", "5"))

    for mode in (MODE_HTTP, MODE_GRPC):
        threading.Thread(target=run_mode, args=(host, port, mode, streams), daemon=True).start()

    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
