# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Resolves the valkey service name in a loop, then speaks the Redis protocol to
# it. On Alpine, musl resolves over an unconnected UDP socket (bind + sendto, no
# connect), so the socket tuple has no peer associated with it.
#
# The name is served by the compose network's embedded DNS, so the lookup does
# not depend on an upstream resolver.

import os
import socket
import sys
import time

HOST = "valkey"
PORT = 6379

INTERVAL_SECONDS = float(os.getenv("DNS_LOOKUP_INTERVAL_SECONDS", "1"))
CONNECT_TIMEOUT_SECONDS = 2

PING = b"*1\r\n$4\r\nPING\r\n"


def resolve_and_ping():
    try:
        addrs = socket.getaddrinfo(HOST, PORT, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as err:
        print(f"lookup failed name={HOST} error={err}", flush=True)
        return

    sockaddr = addrs[0][4]
    try:
        with socket.create_connection(sockaddr, CONNECT_TIMEOUT_SECONDS) as conn:
            conn.sendall(PING)
            reply = conn.recv(64)
            print(f"resolved {HOST}={sockaddr[0]} ping={reply.decode().strip()}", flush=True)
    except OSError as err:
        print(f"ping failed host={HOST} error={err}", flush=True)


def main():
    print(f"dnsclient running: pid={os.getpid()} host={HOST}", flush=True)

    while True:
        resolve_and_ping()
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
