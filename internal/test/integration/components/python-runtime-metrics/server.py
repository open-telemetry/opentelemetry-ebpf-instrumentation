# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import gc
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def collect_generation(generation):
    cycles = []
    for _ in range(100):
        cycle = []
        cycle.append(cycle)
        cycles.append(cycle)
    del cycles
    gc.collect(generation)
    return gc.get_stats()


gc.disable()
for initial_generation in range(3):
    collect_generation(initial_generation)

children = set()
child_controls = {}


def fork_child(server, connection):
    start_read_fd, start_write_fd = os.pipe()
    stats_read_fd, stats_write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(start_write_fd)
        os.close(stats_read_fd)
        connection.close()
        os.set_inheritable(start_read_fd, True)
        os.set_inheritable(stats_write_fd, True)
        os.execl(
            "/usr/local/bin/python3",
            "python3",
            "/controlled.py",
            str(start_read_fd),
            str(stats_write_fd),
        )

    os.close(start_read_fd)
    os.close(stats_write_fd)
    child_controls[pid] = (start_write_fd, stats_read_fd)
    children.add(pid)
    return {"pid": pid}


def collect_child(pid):
    start_write_fd, stats_read_fd = child_controls.pop(pid)
    os.write(start_write_fd, b"1")
    os.close(start_write_fd)
    payload = b""
    while chunk := os.read(stats_read_fd, 4096):
        payload += chunk
    os.close(stats_read_fd)
    return {"pid": pid, "stats": json.loads(payload)}


def fork_automatic_child(connection):
    pid = os.fork()
    if pid == 0:
        connection.close()
        os.execl("/usr/local/bin/python3", "python3", "/automatic.py")

    children.add(pid)
    return {"pid": pid}


def stop_children():
    for pid in list(children):
        control = child_controls.pop(pid, None)
        if control:
            os.close(control[0])
            os.close(control[1])
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        children.remove(pid)
    return gc.get_stats()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/stats":
            self.respond(gc.get_stats())
            return
        if path.startswith("/collect/"):
            generation = int(path.rsplit("/", 1)[1])
            if generation not in range(3):
                self.send_error(400)
                return
            self.respond(collect_generation(generation))
            return
        if path == "/fork":
            self.respond(fork_child(self.server, self.connection))
            return
        if path.startswith("/collect-child/"):
            self.respond(collect_child(int(path.rsplit("/", 1)[1])))
            return
        if path == "/fork-automatic":
            self.respond(fork_automatic_child(self.connection))
            return
        if path == "/stop-children":
            self.respond(stop_children())
            return
        if path == "/exit":
            self.respond(collect_generation(2))
            threading.Timer(0.1, lambda: os._exit(0)).start()
            return
        self.send_error(404)

    def respond(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
