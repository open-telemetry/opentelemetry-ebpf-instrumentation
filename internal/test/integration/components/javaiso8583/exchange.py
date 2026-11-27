# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import json
import multiprocessing
import socket
import socketserver
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from time import sleep
from urllib.parse import urlencode
from urllib.request import urlopen


def frame(message, *, ascii_length=False):
    size = len(message)
    prefix = f"{size:04d}".encode() if ascii_length else size.to_bytes(2, "big")
    return prefix + message


def read_frame(reader):
    prefix = reader.read(2)
    if prefix.isdigit():
        prefix += reader.read(2)
        size = int(prefix)
    else:
        size = int.from_bytes(prefix, "big")
    return prefix + reader.read(size)


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        first = self.rfile.peek(1)[:1]
        if first == b"\x01":  # FastCGI PARAMS
            header = self.rfile.read(8)
            self.rfile.read(int.from_bytes(header[4:6], "big") + 8)
            self.wfile.write(b"\x01\x06" + header[2:4] + b"\x00" * 4)
            return
        if first == b"\x32":  # MQTT QoS 1 PUBLISH
            _, size = self.rfile.read(2)
            self.rfile.read(size)
            self.wfile.write(b"\x40\x02\x00\x01")  # PUBACK for packet 1
            return
        message = read_frame(self.rfile)
        if message[2:6] == b"0100":
            second = read_frame(self.rfile)
            self.wfile.write(authorization_reply(second[-6:], b"51"))
            sleep(0.05)
            self.wfile.write(authorization_reply(message[-6:], b"00"))
            return
        if message[2:6] == b"0102":
            second = read_frame(self.rfile)
            self.wfile.write(authorization_reply(message[-6:], b"00", b"0112"))
            third = read_frame(self.rfile)
            self.wfile.write(authorization_reply(second[-6:], b"51", b"0112"))
            sleep(0.05)
            self.wfile.write(authorization_reply(third[-6:], b"96", b"0112"))
            return
        if message[2:6] == b"0130":
            read_frame(self.rfile)
            read_frame(self.rfile)


def authorization_reply(stan, code, mti=b"0110"):
    return frame(mti + b"0020000002000000" + stan + code)


def expect_reply(conn, expected):
    if conn.recv(len(expected), socket.MSG_WAITALL) != expected:
        raise ValueError("unexpected multiplexed authorization response")


def multiplexed_authorizations():
    # Both requests are outstanding before either reply. Omit DE7 so timing requires DE11.
    with socket.create_connection(("127.0.0.1", 8583), timeout=2) as conn:
        conn.sendall(frame(b"01000020000000000000123456"))
        sleep(0.05)
        conn.sendall(frame(b"01000020000000000000123457"))
        expect_reply(conn, authorization_reply(b"123457", b"51"))
        expect_reply(conn, authorization_reply(b"123456", b"00"))


def interleaved_authorizations():
    with socket.create_connection(("127.0.0.1", 8583), timeout=2) as conn:
        conn.sendall(frame(b"01020020000000000000123451"))
        sleep(0.05)
        conn.sendall(frame(b"01020020000000000000123452"))
        expect_reply(conn, authorization_reply(b"123451", b"00", b"0112"))
        # B is outstanding throughout this pause. C starts the next TCP record.
        sleep(0.2)
        conn.sendall(frame(b"01020020000000000000123453"))
        expect_reply(conn, authorization_reply(b"123452", b"51", b"0112"))
        expect_reply(conn, authorization_reply(b"123453", b"96", b"0112"))


def serve_echo():
    with socketserver.TCPServer(("127.0.0.1", 8583), Echo) as server:
        server.serve_forever()


def endpoints_traced():
    query = 'iso8583_request_duration_seconds_count{mti=~"0120|0420"} > 0'
    url = "http://lgtm:9090/api/v1/query?" + urlencode({"query": query})
    try:
        with urlopen(url, timeout=2) as response:
            series = json.load(response)["data"]["result"]
    except OSError:
        return False
    return {item["metric"]["request_type"] for item in series} == {"client", "server"}


class Client(BaseHTTPRequestHandler):
    def do_GET(self):
        # The switch batches two replies, then sends a third on the same connection.
        replies = []
        now = datetime.now(timezone.utc)
        for mti, age in ((b"0130", 5), (b"0230", 8), (b"0430", 12)):
            stamp = (now - timedelta(seconds=age)).strftime("%m%d%H%M%S").encode()
            bitmap = b"0220000000000000"
            fields = stamp + b"123456"
            if mti == b"0230":
                # DE48 makes the first write 218 bytes. The final 38-byte reply fills the inline buffer.
                bitmap = b"0220000000010000"
                fields += b"139" + b"X" * 139
            replies.append(frame(mti + bitmap + fields))
        with socket.create_connection(("127.0.0.1", 8583), timeout=2) as conn:
            conn.sendall(replies[0] + replies[1])
            sleep(0.05)
            conn.sendall(replies[2])
            conn.shutdown(socket.SHUT_WR)
            conn.recv(1)
        stamp = (now - timedelta(seconds=3)).strftime("%m%d%H%M%S")
        packed_reply = bytes.fromhex("0330 0200000000000000 " + stamp)
        with socket.create_connection(("127.0.0.1", 8583), timeout=2) as conn:
            conn.sendall(frame(packed_reply, ascii_length=True))
            conn.shutdown(socket.SHUT_WR)
            conn.recv(1)
        # Exercise only genuine ISO replies until both Python endpoints are being traced.
        if self.path == "/ready":
            self.send_response(200 if endpoints_traced() else 503)
            self.end_headers()
            return

        multiplexed_authorizations()
        interleaved_authorizations()

        # A separate TCP write can start with a complete ISO reply inside an MQTT payload.
        payload = frame(b"06100200000000000000" + stamp.encode())
        topic_and_id = b"\x00\x08payments\x00\x01"
        with socket.create_connection(("127.0.0.1", 8583), timeout=2) as conn:
            conn.sendall(bytes([0x32, len(topic_and_id) + len(payload)]) + topic_and_id)
            sleep(0.05)
            conn.sendall(payload)
            with conn.makefile("rb") as reader:
                if reader.read(4) != b"\x40\x02\x00\x01":
                    self.send_error(502)
                    return
        # The first FastCGI write also decodes as a complete ISO reply with a current DE7.
        params = b"\x02\x05XY" + bytes.fromhex(stamp)
        params += b"\x0e\x03REQUEST_METHODGET\x0b\x0dREQUEST_URI/fcgi-overlap" + b"\x01\x01XY" * 124
        header = b"\x01\x04\x07\x10"
        packet = header + len(params).to_bytes(2, "big") + b"\x00\x00" + params + header + b"\x00" * 4
        boundary = 2 + int.from_bytes(header[:2], "big")
        with socket.create_connection(("127.0.0.1", 8583), timeout=2) as conn:
            conn.sendall(packet[:boundary])
            sleep(0.05)
            conn.sendall(packet[boundary:])
            with conn.makefile("rb") as reader:
                if reader.read(8) != b"\x01\x06" + header[2:4] + b"\x00" * 4:
                    self.send_error(502)
                    return
        # A complete ISO reply in a separate HTTP body write still belongs to the GET.
        body = frame(b"05100200000000000000" + stamp.encode(), ascii_length=True)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    multiprocessing.Process(target=serve_echo, daemon=True).start()
    HTTPServer(("0.0.0.0", 8080), Client).serve_forever()
