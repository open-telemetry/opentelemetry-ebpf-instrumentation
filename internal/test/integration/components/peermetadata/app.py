# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import http.server
import socket
import sys
import time
import urllib.request


def destination(host):
    return f"http://{socket.gethostbyname(host)}:8080"


def call(url):
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/target":
            body = self.server.destination.encode()
        elif self.path.startswith("/call/idle/"):
            target = self.server.destination.removesuffix(":8080") + ":8082"
            body = call(target + self.path.removeprefix("/call/idle"))
        elif self.path.startswith("/call/"):
            body = call(self.server.destination + self.path.removeprefix("/call"))
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(port, target=""):
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.destination = target
    server.serve_forever()


def run_caller(target):
    while True:
        try:
            call(target + "/second-caller")
        except OSError as error:
            print(error, flush=True)
        time.sleep(0.5)


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "server":
        serve(int(sys.argv[2]))
    elif mode == "client":
        serve(8081, destination(sys.argv[2]))
    else:
        run_caller(destination(sys.argv[2]))
