# OBI MQTT protocol parser

This document describes the MQTT protocol parser that OBI provides.

## Protocol Overview

MQTT (Message Queuing Telemetry Transport) is a lightweight publish/subscribe messaging protocol designed for constrained devices. OBI supports MQTT versions 3.1.1 and 5.0.

### Packet Structure

All MQTT packets start with a fixed header:

```
Fixed Header:
  packet_type   => 4 bits (high nibble of byte 0)
  flags         => 4 bits (low nibble of byte 0)
  remaining_len => 1-4 bytes (variable-length encoding)
```

The `packet_type` identifies the control packet type (1-15, 0 is reserved).
The `remaining_len` specifies the number of bytes remaining in the packet (variable header + payload).

### Supported Packet Types

OBI tracks the following packet types for span creation:

- **PUBLISH (type 3)**: Creates `publish` spans with topic name and QoS level.
- **SUBSCRIBE (type 8)**: Creates `process` spans with the first topic filter.

Control packets (CONNECT, CONNACK, PINGREQ, etc.) are parsed but ignored for span creation.

### PUBLISH Packet Format

```
Variable Header:
  topic_length  => UINT16 (big-endian)
  topic_name    => UTF-8 string
  packet_id     => UINT16 (only if QoS > 0)

Payload:
  message       => bytes (not parsed)
```

QoS level is extracted from the fixed header flags (bits 1-2).

### SUBSCRIBE Packet Format

```
Variable Header:
  packet_id     => UINT16

Payload (repeated):
  filter_length => UINT16
  topic_filter  => UTF-8 string
  options       => UINT8 (QoS in lower 2 bits)
```

## Protocol Parsing

MQTT packets are detected via userspace heuristics in `ReadTCPRequestIntoSpan` ([tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go)). The `isMQTT` function validates the packet type range and remaining length encoding.

Parsing logic is in the [mqttparser package](../../../pkg/internal/ebpf/mqttparser), with `ProcessMQTTEvent` in [mqtt_detect_transform.go](../../../pkg/ebpf/common/mqtt_detect_transform.go) handling span creation.

### Multiple Packets per Segment

The parser handles multiple MQTT packets in a single TCP segment. It iterates through packets and returns the first span-worthy packet (PUBLISH or SUBSCRIBE).

### Truncation Handling

The parser tolerates truncated packets:

- Fixed header is validated first (minimum 2 bytes)
- Topic/filter parsing fails gracefully if data is incomplete
- Partial packets return errors without crashing

## Limitations

- **No kernel-space detection**: MQTT is detected in userspace only. The `ProtocolTypeMQTT` constant exists for future kernel-space support.
- **First subscription only**: For SUBSCRIBE packets with multiple topic filters, only the first filter is used in the span.
- **Payload not captured**: Message payload size and content are not included in spans.
