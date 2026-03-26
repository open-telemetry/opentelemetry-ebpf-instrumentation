from http.server import BaseHTTPRequestHandler, HTTPServer
import os

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
    cur = conn.cursor()
    try:
        cur.execute(query)
    finally:
        cur.close()
        conn.close()


class RequestHandler(BaseHTTPRequestHandler):
    def send_ok(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def do_GET(self):
        if self.path == "/query":
            execute_query("SELECT * FROM accounting.contacts WHERE id = 1")
            self.send_ok()
            self.wfile.write(b"OK")
            return

        if self.path == "/query_after_headers":
            # Commit the response headers first, then run the Postgres query,
            # then write the response body while the request is still open.
            self.send_ok()
            execute_query("SELECT * FROM accounting.contacts WHERE id = 2")
            self.wfile.write(b"OK")
            return

        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    HTTPServer(("", 8080), RequestHandler).serve_forever()
