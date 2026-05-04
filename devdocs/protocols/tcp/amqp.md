# OBI AMQP protocol parser

This document describes the AMQP 1.0 protocol parser that OBI provides.

## Protocol Overview

AMQP 1.0 is a binary, frame-oriented messaging protocol standardized by OASIS. A TCP connection opens with an 8-byte protocol header that negotiates the layer (plain AMQP, AMQP over TLS, or SASL), after which the peers exchange variable-size frames with fixed headers. Each frame carries either an AMQP performative (connection, session and link control, or message transfer) or a SASL performative (authentication).

OBI only handles AMQP 1.0. AMQP 0-9-1, which RabbitMQ uses by default, is rejected at the protocol header.

## Packet Structure

### Protocol Header

The 8-byte protocol header is sent by both peers at the start of the connection and again whenever the layer switches (for example SASL to AMQP).

```
Protocol Header (8 bytes):
  magic        => "AMQP"  (4 bytes)
  protocol_id  => UINT8   (0 = AMQP, 2 = AMQP-TLS, 3 = SASL)
  major        => UINT8   (must be 1)
  minor        => UINT8   (must be 0)
  revision     => UINT8   (must be 0)
```

### Frame Header

Every AMQP or SASL frame starts with a fixed 8-byte header.

```
Frame Header (8 bytes):
  size    => UINT32 big-endian  (bytes 0-3, total frame size including header)
  doff    => UINT8              (byte 4, data offset in 4-byte words, minimum 2)
  type    => UINT8              (byte 5, 0x00 AMQP frame, 0x01 SASL frame)
  channel => UINT16 big-endian  (bytes 6-7)
```

The frame body begins at `doff * 4` from the start of the frame. Bytes between the fixed header and the body are extended header space.

### Described Performative Constructor

The first bytes of a frame body identify the performative using an AMQP described type.

```
Performative Constructor:
  described_type => 0x00
  format_code    => 0x53 (smallulong, 1-byte descriptor value)
                  | 0x80 (ulong,      8-byte big-endian descriptor value)
  descriptor     => UINT8 or UINT64 big-endian
```

Different client libraries emit either encoding; the parser accepts both. An AMQP frame with an empty body is a valid heartbeat and carries no performative.

## Supported Performatives

| Frame type | Descriptor | Name         | Span-worthy |
|------------|------------|--------------|-------------|
| AMQP       | `0x10`     | OPEN         | no          |
| AMQP       | `0x11`     | BEGIN        | no          |
| AMQP       | `0x12`     | ATTACH       | no          |
| AMQP       | `0x13`     | FLOW         | no          |
| AMQP       | `0x14`     | TRANSFER     | **yes**     |
| AMQP       | `0x15`     | DISPOSITION  | no          |
| AMQP       | `0x16`     | DETACH       | no          |
| AMQP       | `0x17`     | END          | no          |
| AMQP       | `0x18`     | CLOSE        | no          |
| SASL       | `0x40`     | MECHANISMS   | no          |
| SASL       | `0x41`     | INIT         | no          |
| SASL       | `0x42`     | CHALLENGE    | no          |
| SASL       | `0x43`     | RESPONSE     | no          |
| SASL       | `0x44`     | OUTCOME      | no          |

Non-transfer performatives are recognized so the scanner can validate the stream, but they do not produce spans.

## Protocol Parsing

AMQP packets are detected via a userspace heuristic in `ReadTCPRequestIntoSpan` ([tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go)). `matchAMQP` delegates to `ProcessPossibleAMQPEvent`, which parses the request and response buffers with `amqpparser.Parse`; a payload is accepted when it presents a 1.0 protocol header or a valid descriptor-bearing frame. A bare heartbeat frame is not distinctive enough on its own and is only accepted after stronger AMQP evidence in the same payload.

The parser lives in the [amqpparser package](../../../pkg/internal/ebpf/amqpparser), split across [protocol.go](../../../pkg/internal/ebpf/amqpparser/protocol.go) (the 8-byte header), [frame.go](../../../pkg/internal/ebpf/amqpparser/frame.go) (frame header and described performative), and [parser.go](../../../pkg/internal/ebpf/amqpparser/parser.go) (stream parsing). Span creation starts in `ProcessPossibleAMQPEvent` in [amqp_detect_transform.go](../../../pkg/ebpf/common/amqp_detect_transform.go).

### Multi-Stage Handshakes

A single TCP stream may contain an optional SASL protocol header, then SASL frames, then an AMQP protocol header, then AMQP frames. The scanner accepts repeated protocol headers and mixed SASL/AMQP frame sequences on the same stream so this handshake is fully recognized.

### Multiple Frames per Segment

The scanner iterates frames in a captured TCP segment up to a bounded parser limit. Control frames that precede TRANSFER within the same segment are parsed for state, and every TRANSFER found before that limit can produce a span.

### Truncation Handling

eBPF attaches mid-flight, so captures can start inside a frame or end before a frame completes.

- The scanner tolerates partial captures: if the final frame is short, the partial-descriptor path recovers the performative code from the frame header and the first constructor bytes without requiring the rest of the body.
- Invalid or inconsistent structure (bad protocol magic, wrong version, impossible data offsets, unknown frame type) returns an error without crashing.

## Span Semantics

TRANSFER frames map to messaging spans. Operation is inferred from traffic direction because the minimal parser does not descend into the TRANSFER payload:

- client -> server: `publish`
- server -> client: `process`

Both operations use `EventTypeAMQPClient`. The OpenTelemetry span kind is `producer` for `publish` and `consumer` for `process`, matching the Kafka and MQTT client span model.

Handshake and control-only traffic (OPEN, BEGIN, FLOW, SASL negotiation, etc.) is recognized but produces no spans.

## Integration test harness

End-to-end tests live in [internal/test/oats/amqp/](../../../internal/test/oats/amqp/) and run OATS scenarios against an ActiveMQ Artemis broker. Test clients are under [internal/test/integration/components/javaamqp/](../../../internal/test/integration/components/javaamqp/) and [internal/test/integration/components/pythonamqp/](../../../internal/test/integration/components/pythonamqp/).

## Limitations

- **Userspace heuristic only**: there is no kernel-assigned AMQP protocol type; detection runs after the packet reaches userspace.
- **AMQP 1.0 only**: AMQP 0-9-1 (RabbitMQ's default) is rejected at the protocol header.
- **TRANSFER only**: only TRANSFER performatives produce spans.
- **Plaintext frame parsing only**: AMQP-TLS protocol headers are recognized, but encrypted frame payloads cannot be decoded.
- **No destination extraction**: link `target`/`source` and other addressing details inside the TRANSFER performative are not decoded. As a consequence, AMQP spans emit an empty `messaging.destination.name`, do not emit `messaging.client.id`, use a generic span name (`publish` / `process`), and have empty Prometheus destination labels. Users relying on destination-level attribution should treat the current AMQP support as traffic-level only.
- **Direction-inferred operation**: `publish` vs `process` is derived from traffic direction. Broker-to-consumer deliveries arrive on what OBI sees as the server side and are therefore labeled `process`.
