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


# Interleaving: a resolver socket that carries unrelated traffic while a query
# is still outstanding. The query goes out, something unrelated happens on the
# same socket, and only then does the nameless answer arrive. Both sequences
# have to leave the lookup reportable.
#
# The answers come from the delayed responder rather than from the compose
# resolver, because the interleaved step and the answer would otherwise race:
# whichever datagram lands first is the one the next receive returns, and the
# receive-side sequence needs the unrelated datagram to be the one it reads. The
# responder holds its answer back long enough that the ordering is not a matter
# of timing.
#
# The responder runs in its own container, so its own DNS traffic is outside the
# instrumented PID namespace and does not appear in the telemetry under test.
RESPONDER_HOST = "dnsresponder"
RESPONDER_PORT = 5353

# Long enough that the interleaved step is ordered ahead of the answer by
# construction: the unrelated datagram travels over loopback and lands in
# microseconds, so nothing about the ordering rests on timing.
RESPONDER_DELAY_SECONDS = 0.5

# Answered by the delayed responder, so neither name has to exist in the compose
# network. A lookup reported under one of these names, with no error, means the
# answer was paired with its query across the interleaved step.
INTERLEAVED_SEND_NAME = "interleaved-send.test"
INTERLEAVED_RECV_NAME = "interleaved-recv.test"

# Discards whatever it is sent, so the send-side sequence gets an unrelated send
# on the socket without also putting a datagram in its receive queue
BLACKHOLE_PORT = 8126


def encode_labels(name):
    return (
        b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
        + b"\x00"
    )


def dns_query(name, txid):
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # rd=1, qdcount=1
    return header + encode_labels(name) + struct.pack("!HH", 1, 1)  # type A, class IN


def dns_answer_for(query):
    """A NOERROR response echoing the question, with one A record."""
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    question = query[12:]
    # name as a pointer back to the question, then type A, class IN, ttl, rdlength
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
    return header + question + answer


def run_responder():
    """Answers every query after a delay, so callers can order what follows."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", RESPONDER_PORT))
    print(f"dnsresponder listening: port={RESPONDER_PORT}", flush=True)

    while True:
        query, peer = sock.recvfrom(512)
        if len(query) < 12:
            continue
        time.sleep(RESPONDER_DELAY_SECONDS)
        sock.sendto(dns_answer_for(query), peer)


def start_blackhole_sink():
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind((NON_DNS_HOST, BLACKHOLE_PORT))

    def serve():
        while True:
            sink.recvfrom(512)

    threading.Thread(target=serve, daemon=True).start()


def interleave_non_dns_send(sock):
    """An unrelated send, which says nothing about the query already in flight."""
    sock.sendto(dns_shaped_response(), (NON_DNS_HOST, BLACKHOLE_PORT))


def interleave_non_dns_receive(sock):
    """An unrelated receive that names its non-DNS peer explicitly."""
    sock.sendto(dns_shaped_response(), (NON_DNS_HOST, NON_DNS_PORT))

    _, peer = sock.recvfrom(512)
    if peer[1] != NON_DNS_PORT:
        # the delayed answer overtook the echo, so this iteration did not
        # exercise the interleaving; say so rather than reporting a lookup that
        # proves nothing
        raise OSError(f"expected the echo reply first, got a datagram from {peer}")


def interleaved_lookup(name, txid, interleave, responder_ip):
    """One lookup with an unrelated step between the query and its answer.

    The answer is taken with recv() rather than recvfrom(), so the kernel fills
    in no address and the answer carries no peer. Classifying it therefore rests
    entirely on the window the query opened, which the interleaved step must not
    have closed.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))  # bound but never connected, so its tuple has no peer
    sock.settimeout(RECV_TIMEOUT_SECONDS)

    try:
        sock.sendto(dns_query(name, txid), (responder_ip, RESPONDER_PORT))
        interleave(sock)
        sock.recv(512)
        print(f"interleaved lookup answered name={name}", flush=True)
    except OSError as err:
        print(f"interleaved lookup failed name={name} error={err}", flush=True)
    finally:
        sock.close()


def main():
    if os.getenv("DNS_RESPONDER"):
        return run_responder()

    print(f"dnsclient running: pid={os.getpid()} host={HOST}", flush=True)

    start_echo_sink()
    start_blackhole_sink()

    # resolved once, so the responder's own name does not add a lookup per
    # iteration; it still shows up once, at startup
    responder_ip = socket.gethostbyname(RESPONDER_HOST)
    print(f"responder resolved: {RESPONDER_HOST}={responder_ip}", flush=True)

    # never connected, so its tuple has no peer, exactly like musl's resolver socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind((NON_DNS_HOST, 0))
    probe.settimeout(RECV_TIMEOUT_SECONDS)

    # Every lookup needs its own transaction id. Lookups are paired with their
    # answers on (pid, transaction id), so two outstanding queries sharing an id
    # collide: the second displaces the first, and the displaced one is reported
    # as an unanswered lookup even though its answer did arrive.
    txid = 0

    def next_txid():
        nonlocal txid
        txid = (txid + 1) & 0xFFFF
        return txid

    while True:
        resolve_and_ping()
        exchange_non_dns(probe)
        interleaved_lookup(
            INTERLEAVED_SEND_NAME, next_txid(), interleave_non_dns_send, responder_ip
        )
        interleaved_lookup(
            INTERLEAVED_RECV_NAME, next_txid(), interleave_non_dns_receive, responder_ip
        )
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
