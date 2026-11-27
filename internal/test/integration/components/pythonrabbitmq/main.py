# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import os
import time
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pika
from kombu import Connection, Exchange, Producer, Queue, binding

BROKER_URL = os.getenv("AMQP_URL", "amqp://guest:guest@127.0.0.1:5672/")
TIMEOUT_SECONDS = 5

# The queues are exclusive: RabbitMQ deprecates transient queues that are not
PIKA_QUEUE = "oats-pika"

KOMBU_EXCHANGE = Exchange("oats-kombu", type="direct", durable=False)
KOMBU_QUEUE = Queue("oats-kombu", exchange=KOMBU_EXCHANGE, routing_key="kombu", exclusive=True)

# py-amqp reads a one-byte body and its frame end in reads too short to be traced,
# and the second delivery follows the first one's body
KOMBU_SHORT_KEYS = ("short-a", "short-b")
KOMBU_SHORT_QUEUE = Queue(
    "oats-kombu-short",
    bindings=[binding(KOMBU_EXCHANGE, routing_key=key) for key in KOMBU_SHORT_KEYS],
    exclusive=True,
)


def pika_roundtrip(url: str, queue: str) -> None:
    """Publishes twice to the default exchange: one message is delivered to a
    consumer (Basic.Deliver), the other is pulled (Basic.Get-Ok)."""
    connection = pika.BlockingConnection(pika.URLParameters(url))
    try:
        channel = connection.channel()
        channel.queue_declare(queue=queue, exclusive=True)
        channel.basic_qos(prefetch_count=1)

        channel.basic_publish(exchange="", routing_key=queue, body=b"consumed")
        for method, _, _ in channel.consume(queue, inactivity_timeout=TIMEOUT_SECONDS):
            if method is None:
                raise TimeoutError("no delivery")
            channel.basic_ack(method.delivery_tag)
            break
        channel.cancel()

        channel.basic_publish(exchange="", routing_key=queue, body=b"pulled")
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            method, _, _ = channel.basic_get(queue, auto_ack=True)
            if method is not None:
                return
            time.sleep(0.1)
        raise TimeoutError("nothing to get")
    finally:
        connection.close()


def kombu_roundtrip(queue: Queue, routing_keys: tuple[str, ...], body: bytes) -> None:
    """Publishes a message per routing key to a direct exchange and consumes them
    through py-amqp, Celery's client."""
    received = []

    def on_message(_body, message) -> None:
        message.ack()
        received.append(message)

    with Connection(BROKER_URL, transport="pyamqp", connect_timeout=TIMEOUT_SECONDS) as conn:
        producer = Producer(conn)
        for routing_key in routing_keys:
            producer.publish(body, exchange=KOMBU_EXCHANGE, routing_key=routing_key, declare=[queue])
        with conn.Consumer(queue, callbacks=[on_message]):
            while len(received) < len(routing_keys):
                conn.drain_events(timeout=TIMEOUT_SECONDS)


ROUTES = {
    "/pika": partial(pika_roundtrip, BROKER_URL, PIKA_QUEUE),
    "/pika-tls": partial(pika_roundtrip, os.getenv("AMQPS_URL", "amqps://localhost:5671/"), "oats-pika-tls"),
    "/kombu": partial(kombu_roundtrip, KOMBU_QUEUE, ("kombu",), b"kombu"),
    "/kombu-short": partial(kombu_roundtrip, KOMBU_SHORT_QUEUE, KOMBU_SHORT_KEYS, b"x"),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        roundtrip = ROUTES.get(self.path)
        if roundtrip is None:
            self.send_response(404)
            self.end_headers()
            return

        try:
            roundtrip()
        except Exception as exc:  # noqa: BLE001 - the error becomes the response
            self.reply(500, str(exc).encode())
            return
        self.reply(200, b"OK")

    def reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
