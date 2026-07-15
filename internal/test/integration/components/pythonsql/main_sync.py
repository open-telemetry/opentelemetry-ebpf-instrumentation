from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import sys

import psycopg


DB_CONFIG = {
    "dbname": "sqltest",
    "user": "postgres",
    "password": "postgres",
    "host": "sqlserver",
    "port": "5432",
}


def execute_query(query):
    conn = psycopg.connect(**DB_CONFIG)
    try:
        cur = conn.cursor()
        try:
            cur.execute(query)
            cur.fetchall()
        finally:
            cur.close()
    finally:
        conn.close()


class RequestHandler(BaseHTTPRequestHandler):
    def send_ok_headers(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        # end_headers writes directly to the unbuffered socket.
        self.end_headers()

    def do_GET(self):
        if self.path == "/query":
            execute_query("SELECT * FROM accounting.contacts WHERE id = 1")
            self.send_ok_headers()
            self.wfile.write(b"OK")
            return

        if self.path == "/query_after_headers":
            self.send_ok_headers()
            # The 200 headers are already out; surface query failures in the
            # body and the container log, otherwise the client only sees the
            # successful status and the root cause stays hidden.
            try:
                execute_query("SELECT * FROM accounting.contacts WHERE id = 2")
            except Exception as e:
                print(f"query after headers failed: {e}", file=sys.stderr, flush=True)
                self.wfile.write(f"ERROR: {e}".encode())
                return
            self.wfile.write(b"OK")
            return

        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}", flush=True)
    HTTPServer(("", 8080), RequestHandler).serve_forever()
