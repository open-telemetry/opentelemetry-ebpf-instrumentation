# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from proton import Message
from proton.utils import BlockingConnection

BROKER_URL = os.getenv("AMQP_URL", "amqp://artemis:artemis@artemis:5672")
QUEUE_NAME = os.getenv("AMQP_QUEUE", "oats-python-amqp")


def amqp_roundtrip() -> str:
    deadline = time.time() + 30
    last_err = None

    while time.time() < deadline:
        conn = None
        try:
            payload = f"python-amqp-{time.time_ns()}"
            queue_name = f"{QUEUE_NAME}-{time.time_ns()}"
            conn = BlockingConnection(BROKER_URL, timeout=5)
            receiver = conn.create_receiver(queue_name)
            sender = conn.create_sender(queue_name)
            sender.send(Message(body=payload))

            recv_deadline = time.time() + 5
            while time.time() < recv_deadline:
                incoming = receiver.receive(timeout=1)
                if incoming is None:
                    continue

                body = incoming.body
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="replace")
                else:
                    body = str(body)

                receiver.accept()
                if body == payload:
                    conn.close()
                    return payload

            raise RuntimeError(f"timed out waiting for payload {payload!r}")
        except Exception as exc:  # noqa: BLE001 - test helper retries broker startup
            last_err = exc
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
            time.sleep(1)

    raise RuntimeError(f"AMQP roundtrip failed: {last_err}")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/message":
            self.send_response(404)
            self.end_headers()
            return

        try:
            payload = amqp_roundtrip()
        except Exception as exc:  # noqa: BLE001
            body = str(exc).encode()
            self.send_response(500)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = payload.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
