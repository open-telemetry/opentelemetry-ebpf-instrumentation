# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from nats.aio.client import Client as NATS


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_NATS_URL = "nats://nats:4222"
DEFAULT_SUBJECT = "updates.orders"
DELIVERY_WAIT_SECONDS = 5
CONNECT_WAIT_SECONDS = 20


class NATSService:
    def __init__(self, nats_url: str, subject: str):
        self.nats_url = nats_url
        self.subject = subject
        self.loop = asyncio.new_event_loop()
        self.loop_ready = threading.Event()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.delivered = threading.Event()
        self.state_lock = threading.Lock()
        self.expected_payload = ""
        self.counter = 0
        self.nc = None

    def start(self):
        self.thread.start()
        self.loop_ready.wait()
        asyncio.run_coroutine_threadsafe(self._connect(), self.loop).result(
            timeout=CONNECT_WAIT_SECONDS
        )

    def publish(self):
        payload = self._next_payload()
        with self.state_lock:
            self.expected_payload = payload
            self.delivered.clear()

        asyncio.run_coroutine_threadsafe(self._publish(payload), self.loop).result(
            timeout=CONNECT_WAIT_SECONDS
        )
        if not self.delivered.wait(DELIVERY_WAIT_SECONDS):
            raise TimeoutError("timed out waiting for NATS delivery")

        return payload

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop_ready.set()
        self.loop.run_forever()

    async def _connect(self):
        while True:
            try:
                self.nc = NATS()
                await self.nc.connect(servers=[self.nats_url], name="python-nats-test")
                await self.nc.subscribe(self.subject, cb=self._on_message)
                await self.nc.flush()
                return
            except Exception as exc:
                logger.info("waiting for NATS at %s: %s", self.nats_url, exc)
                await asyncio.sleep(1)

    async def _on_message(self, msg):
        payload = msg.data.decode()
        with self.state_lock:
            if payload == self.expected_payload:
                self.delivered.set()

    async def _publish(self, payload: str):
        if self.nc is None:
            raise RuntimeError("NATS client is not connected")

        # Adding headers forces the header-aware HPUB/HMSG wire format in the official client.
        await self.nc.publish(self.subject, payload.encode(), headers={"X-Test": "python"})
        await self.nc.flush()

    def _next_payload(self):
        with self.state_lock:
            self.counter += 1
            return f"python-nats-{self.counter}"


service = NATSService(
    os.getenv("NATS_URL", DEFAULT_NATS_URL),
    os.getenv("NATS_SUBJECT", DEFAULT_SUBJECT),
)


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/publish":
            self.send_response(404)
            self.end_headers()
            return

        try:
            payload = service.publish()
        except Exception as exc:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(exc).encode())
            return

        body = json.dumps(
            {
                "published": True,
                "subject": service.subject,
                "payload": payload,
            }
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)


def main():
    service.start()
    server = HTTPServer(("", 8080), RequestHandler)
    logger.info("serving HTTP on :8080")
    server.serve_forever()


if __name__ == "__main__":
    main()
