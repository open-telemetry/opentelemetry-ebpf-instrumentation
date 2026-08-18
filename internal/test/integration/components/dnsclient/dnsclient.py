# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Resolves the valkey service name in a loop, then speaks the Redis protocol to
# it. On Alpine, musl resolves over an unconnected UDP socket (bind + sendto, no
# connect), so the socket tuple has no peer associated with it.
#
# The name is served by the compose network's embedded DNS, so the lookup does
# not depend on an upstream resolver.
#
# Alongside each lookup, the workload runs an unrelated UDP exchange that looks
# as much like DNS as a non-DNS flow can: an unconnected socket, a peer that the
# receive never names, and a payload that parses as a DNS response. Only the port
# distinguishes it from the real resolver traffic, so it exercises the tier that
# classifies an answer by the socket it arrives on. None of it may be reported as
# a DNS lookup.

import os
import socket
import struct
import sys
import threading
import time

HOST = "valkey"
PORT = 6379

INTERVAL_SECONDS = float(os.getenv("DNS_LOOKUP_INTERVAL_SECONDS", "1"))
CONNECT_TIMEOUT_SECONDS = 2

PING = b"*1\r\n$4\r\nPING\r\n"

# A real non-DNS port, so the send is positively classified as something other
# than DNS rather than being merely unrecognized
NON_DNS_PORT = 8125
NON_DNS_HOST = "127.0.0.1"

# The name encoded in the decoy payload. If any of this traffic is reported as
# DNS, it surfaces as a lookup for this name.
FALSE_POSITIVE_LABELS = ("falsepositive", "test")
RECV_TIMEOUT_SECONDS = 2


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


def dns_shaped_response():
    """A well-formed DNS response, so nothing but the port marks it as non-DNS."""
    # id, flags (QR=1, RD=1, RA=1), qdcount=1, ancount/nscount/arcount=0
    header = struct.pack("!HHHHHH", 0x4242, 0x8180, 1, 0, 0, 0)

    question = b"".join(
        bytes([len(label)]) + label.encode() for label in FALSE_POSITIVE_LABELS
    )
    question += b"\x00"
    question += struct.pack("!HH", 1, 1)  # type A, class IN

    return header + question


def start_echo_sink():
    """Returns the decoy peer, which echoes whatever it is sent."""
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind((NON_DNS_HOST, NON_DNS_PORT))

    def serve():
        while True:
            payload, peer = sink.recvfrom(512)
            sink.sendto(payload, peer)

    threading.Thread(target=serve, daemon=True).start()


def exchange_non_dns(probe):
    """One decoy round trip on an unconnected socket.

    The reply is taken with recv() rather than recvfrom(), so the kernel is given
    no address buffer to fill and the receive carries no peer. That leaves the
    socket as the only thing the answer could be classified by.
    """
    probe.sendto(dns_shaped_response(), (NON_DNS_HOST, NON_DNS_PORT))

    try:
        probe.recv(512)
    except OSError as err:
        print(f"decoy exchange failed error={err}", flush=True)


def main():
    print(f"dnsclient running: pid={os.getpid()} host={HOST}", flush=True)

    start_echo_sink()

    # never connected, so its tuple has no peer, exactly like musl's resolver socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind((NON_DNS_HOST, 0))
    probe.settimeout(RECV_TIMEOUT_SECONDS)

    while True:
        resolve_and_ping()
        exchange_non_dns(probe)
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
