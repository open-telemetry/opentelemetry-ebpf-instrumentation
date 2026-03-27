import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pymemcache.client.base import Client


def new_client() -> Client:
    return Client(("memcached", 11211), connect_timeout=5, timeout=5)


def memcached_path() -> bytes:
    client = new_client()
    try:
        client.set("session-key", b"value", expire=300)
        value = client.get("session-key")
        client.delete("session-key")
    finally:
        client.close()

    if value is None:
        raise RuntimeError("memcached get returned no value")

    return value


def memcached_error_path() -> None:
    # Trigger a CLIENT_ERROR by trying to increment a non-numeric value.
    # memcached responds: CLIENT_ERROR cannot increment or decrement non-numeric value
    client = new_client()
    try:
        client.set("error-key", b"not-a-number", expire=300)
        client.incr("error-key", 1)
    except Exception:
        pass
    finally:
        client.close()


def memcached_noreply_path() -> None:
    with socket.create_connection(("memcached", 11211), timeout=5) as conn:
        conn.sendall(b"set touch-key 0 300 5 noreply\r\nvalue\r\ntouch touch-key 60 noreply\r\n")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/memcached":
            value = memcached_path()
            self._write_response(value)
        elif self.path == "/memcached-error":
            memcached_error_path()
            self._write_response(b"error triggered")
        elif self.path == "/memcached-noreply":
            memcached_noreply_path()
            self._write_response(b"noreply triggered")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write_response(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"Server running: port=8080 process_id={os.getpid()}")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
