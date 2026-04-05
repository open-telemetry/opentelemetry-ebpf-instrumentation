"""
JSON-RPC 2.0 server and client for integration testing.

The server exposes JSON-RPC methods at /rpc.
A trigger endpoint at /trigger sends a JSON-RPC request to itself (client-side span)
so both server and client spans can be validated.
"""

import json
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


def handle_jsonrpc(body):
    """Process a JSON-RPC 2.0 request and return a response."""
    try:
        req = json.loads(body)
    except json.JSONDecodeError:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32700, "message": "Parse error"},
            "id": None,
        }

    method = req.get("method", "")
    req_id = req.get("id")

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "result": {"tools": [{"name": "calculator"}, {"name": "search"}]},
            "id": req_id,
        }
    elif method == "tools/call":
        params = req.get("params", {})
        return {
            "jsonrpc": "2.0",
            "result": {"content": f"called {params.get('name', 'unknown')}"},
            "id": req_id,
        }
    elif method == "fail":
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": req_id,
        }
    else:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": req_id,
        }


class JSONRPCHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/rpc":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            response = handle_jsonrpc(body)
            resp_body = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/smoke":
            self.send_response(200)
            self.end_headers()
        elif self.path == "/trigger":
            # Make a JSON-RPC client call to ourselves to generate a client span
            rpc_request = json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 42,
            }).encode("utf-8")
            req = urllib.request.Request(
                "http://localhost:8080/rpc",
                data=rpc_request,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                result = resp.read().decode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            resp_body = result.encode("utf-8")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        elif self.path == "/trigger-error":
            # Make a JSON-RPC client call that returns an error
            rpc_request = json.dumps({
                "jsonrpc": "2.0",
                "method": "fail",
                "id": 99,
            }).encode("utf-8")
            req = urllib.request.Request(
                "http://localhost:8080/rpc",
                data=rpc_request,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                result = resp.read().decode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            resp_body = result.encode("utf-8")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[jsonrpc-server] {format % args}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), JSONRPCHandler)
    print(f"JSON-RPC server running on port 8080")
    server.serve_forever()
