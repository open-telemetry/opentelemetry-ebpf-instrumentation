#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""HTTP server with USDT probes via python-stapsdt + libstapsdt.

Mirrors custom_span_c semantics:
  GET /order?id=<int>&customer=<str>   paired custom_span_py:order_start/order_end
  GET /cache?key=<str>                  single-shot custom_span_py:cache_hit
  GET /smoke                            readiness probe
"""

import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import stapsdt

PORT = int(os.environ.get("PORT", "8392"))

# python-stapsdt only describes argument sizes (1/2/4/8 bytes). Pointers to
# strings are also 8-byte values, so we declare uint64 here and pass Python
# strings to fire(); python-stapsdt wraps them in c_char_p so libstapsdt
# receives a register-sized pointer. OBI's custom_span rewriter sees the
# user-declared `type: string` attr and translates the register-only spec
# into a user-memory deref at uprobe time.
provider = stapsdt.Provider("custom_span_py")
order_start = provider.add_probe(
    "order_start", stapsdt.ArgTypes.uint64, stapsdt.ArgTypes.uint64
)
order_end = provider.add_probe(
    "order_end", stapsdt.ArgTypes.uint64, stapsdt.ArgTypes.int32
)
cache_hit = provider.add_probe(
    "cache_hit", stapsdt.ArgTypes.uint64
)
provider.load()


import ctypes


def process_order(order_id: int, customer: str) -> None:
    # Allocate a backing buffer locally so the address we hand the probe stays
    # valid until both order_start.fire and order_end.fire have returned. A
    # bare `c_char_p(bytes)` is unsafe because ctypes does not anchor the
    # source bytes object's lifetime to the c_char_p.
    buf = ctypes.create_string_buffer(customer.encode("ascii"))
    order_start.fire(order_id, ctypes.c_void_p(ctypes.addressof(buf)))
    time.sleep(0.02)
    order_end.fire(order_id, 0)


def cache_lookup(key: str) -> None:
    buf = ctypes.create_string_buffer(key.encode("ascii"))
    cache_hit.fire(ctypes.c_void_p(ctypes.addressof(buf)))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/smoke":
            self._ok()
            return
        if u.path == "/order":
            order_id = int(q.get("id", ["1"])[0] or 1)
            customer = q.get("customer", ["anonymous"])[0]
            process_order(order_id, customer)
            self._ok()
            return
        if u.path == "/cache":
            key = q.get("key", ["default"])[0]
            cache_lookup(key)
            self._ok()
            return
        self.send_response(404)
        self.end_headers()

    def _ok(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"custom_span_python listening on :{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
