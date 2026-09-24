# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""HTTP/2 framing, written by hand.

HTTP/2 libraries send each stream on its own, so they never put several
streams in one buffer, which is what this test needs.
"""

import json
import struct

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_HEADER_LEN = 9

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_SETTINGS = 0x4
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4

GRPC_CONTENT_TYPE = "application/grpc"
MODE_HTTP = "http"
MODE_GRPC = "grpc"

# Status codes that are not in the HPACK static table: each one is added to the
# dynamic table the first time and sent as an index after that. A reader that
# missed a block then reads every later index wrong, and the per-stream checks
# catch it.
HTTP_STATUSES = [201, 202, 203, 205, 207, 208, 226, 214, 209, 210, 211, 212]
GRPC_STATUSES = [1, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14]
# GET and POST are in the static table; the others go through the dynamic table,
# so requests are tested the same way as responses. They repeat when a burst has
# more streams than there are methods.
METHODS = ["GET", "POST", "PATCH", "DELETE", "OPTIONS", "HEAD"]


def method_for(stream):
    return METHODS[stream % len(METHODS)]


class Frame:
    __slots__ = ("type", "flags", "stream_id", "payload")

    def __init__(self, type_, flags, stream_id, payload):
        self.type = type_
        self.flags = flags
        self.stream_id = stream_id
        self.payload = payload

    def ends_stream(self):
        return bool(self.flags & FLAG_END_STREAM)


def build_frame(type_, flags, stream_id, payload=b""):
    header = struct.pack(
        ">BHBBI", len(payload) >> 16, len(payload) & 0xFFFF, type_, flags, stream_id
    )
    return header + payload


def split_frames(buf):
    """Returns every complete frame at the front of buf, and what is left."""
    frames = []
    pos = 0
    while len(buf) - pos >= FRAME_HEADER_LEN:
        length = int.from_bytes(buf[pos:pos + 3], "big")
        if len(buf) - pos < FRAME_HEADER_LEN + length:
            break
        body = pos + FRAME_HEADER_LEN
        frames.append(
            Frame(
                buf[pos + 3],
                buf[pos + 4],
                int.from_bytes(buf[pos + 5:pos + 9], "big") & 0x7FFFFFFF,
                buf[body:body + length],
            )
        )
        pos = body + length
    return frames, buf[pos:]


def count_headers(frames):
    return sum(1 for frame in frames if frame.type == FRAME_HEADERS)


def burst_path(burst_id, stream):
    return "/burst/{}/stream/{}".format(burst_id, stream)


def parse_burst_path(path):
    parts = path.strip("/").split("/")
    if len(parts) != 4 or parts[0] != "burst" or parts[2] != "stream":
        return None, 0
    if not parts[3].isdigit():
        return None, 0
    return parts[1], int(parts[3])


def emit(prefix, record):
    print("{} {}".format(prefix, json.dumps(record)), flush=True)
