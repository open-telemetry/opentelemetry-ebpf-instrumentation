# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# An asyncio HTTP server that makes exactly one outbound TLS request per inbound
# request. asyncio implements TLS with ssl.MemoryBIO (SSLContext.wrap_bio), so the
# ciphertext OpenSSL produces inside SSL_write is handed to the event loop and only
# reaches the socket later, outside the uprobe window that OBI uses to bind an SSL
# to a connection.
#
# Every client span this app produces must name the upstream server. Under load the
# event loop is serving an inbound request whenever the outbound ciphertext reaches
# the socket, which is what makes a mis-bound SSL point at the inbound caller.

import asyncio
import logging
import os
import ssl
import sys

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
UPSTREAM_HOST = os.getenv("UPSTREAM_HOST", "tlsupstream")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_PORT", "8380"))
UPSTREAM_PATH = os.getenv("UPSTREAM_PATH", "/greeting")

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
log = logging.getLogger("memorybio")

# The upstream serves a self-signed certificate whose CN is a bare name, so it can
# only be reached without verification. The peer a span should name comes from the
# socket.
tls = ssl.create_default_context()
tls.check_hostname = False
tls.verify_mode = ssl.CERT_NONE

REQUEST = (
    f"GET {UPSTREAM_PATH} HTTP/1.1\r\n"
    f"Host: {UPSTREAM_HOST}:{UPSTREAM_PORT}\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode()

RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


async def call_upstream():
    reader, writer = await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT, ssl=tls)
    try:
        writer.write(REQUEST)
        await writer.drain()
        await reader.read()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


async def handle(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
        await call_upstream()
        writer.write(RESPONSE)
        await writer.drain()
    except Exception as err:  # noqa: BLE001 - a failed call must stay visible
        log.error("request failed: %s", err)
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN_PORT)
    log.info("listening on %d, calling https://%s:%d%s",
             LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT, UPSTREAM_PATH)
    async with server:
        await server.serve_forever()


asyncio.run(main())
