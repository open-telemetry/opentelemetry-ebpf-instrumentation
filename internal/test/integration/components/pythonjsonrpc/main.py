"""
JSON-RPC 2.0 server for integration testing.

Uses the json-rpc library (https://pypi.org/project/json-rpc/) for
JSON-RPC dispatch, served over HTTP with the stdlib http.server.
"""

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from jsonrpc import JSONRPCResponseManager, dispatcher
from jsonrpcclient import Ok, parse_json, request_json


@dispatcher.add_method(name="tools/list")
def tools_list():
    return {"tools": [{"name": "calculator"}, {"name": "search"}]}


@dispatcher.add_method(name="tools/call")
def tools_call(name="unknown"):
    return {"content": f"called {name}"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        response = JSONRPCResponseManager.handle(body, dispatcher)
        resp_body = response.json.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        if self.path == "/smoke":
            self.send_response(200)
            self.end_headers()
        elif self.path == "/call":
            self.call_remote()
        else:
            self.send_response(404)
            self.end_headers()

    def call_remote(self):
        request = urllib.request.Request(
            os.environ["JSONRPC_TARGET"],
            data=request_json("tools/list").encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            parsed = parse_json(response.read().decode("utf-8"))
        if isinstance(parsed, Ok):
            status, resp_body = 200, json.dumps(parsed.result).encode("utf-8")
        else:
            status, resp_body = 502, parsed.message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format, *args):
        print(f"[jsonrpc-server] {format % args}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("JSON-RPC server running on port 8080")
    server.serve_forever()
