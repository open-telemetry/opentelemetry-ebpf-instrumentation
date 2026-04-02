# OBI NATS protocol parser

This document describes the NATS parser that OBI provides for plain TCP traffic.

## Protocol Overview

NATS uses a line-oriented text protocol. Each frame starts with a control line terminated by `\r\n`.
Frames that carry data include a byte count in the control line, followed by the payload bytes and a trailing `\r\n`.

OBI creates spans from the message-carrying commands:

- `PUB`: client publish
- `HPUB`: client publish with headers
- `MSG`: server-delivered message
- `HMSG`: server-delivered message with headers

Control traffic such as `INFO`, `CONNECT`, `SUB`, `UNSUB`, `PING`, `PONG`, `+OK`, and `-ERR` is parsed only for validation and ignored for span creation.

## Protocol Parsing

NATS traffic is detected in `ReadTCPRequestIntoSpan` in [pkg/ebpf/common/tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go).
The parser itself lives in [pkg/ebpf/common/nats_detect_transform.go](../../../pkg/ebpf/common/nats_detect_transform.go).

Unlike request/response protocols, NATS mixes control frames and message frames on the same connection. OBI scans the buffered traffic in both directions, skipping control-only traffic when possible. When one TCP event contains both a client publish and a server-delivered message, OBI emits the publish span as the main span and a second server span for the delivered message.

### Header-Aware Frames

Official clients switch from `PUB`/`MSG` to `HPUB`/`HMSG` when headers are present. OBI supports both formats and only needs the subject plus the payload length fields to create spans.

### False-Positive Guard for CONNECT

`CONNECT` is ambiguous because HTTP proxies use lines such as `CONNECT host:port HTTP/1.1`.
To avoid misclassifying proxy traffic as NATS, OBI only accepts `CONNECT` and `INFO` frames when the rest of the line is valid JSON, which matches the NATS protocol.

## Limitations

- Only publish and delivered-message frames create spans.
- Subject metadata from subscription setup is not cached; spans rely on the subject carried by `PUB`/`HPUB` and `MSG`/`HMSG`.
- TLS-encrypted NATS traffic is not parsed by this TCP-level detector.
