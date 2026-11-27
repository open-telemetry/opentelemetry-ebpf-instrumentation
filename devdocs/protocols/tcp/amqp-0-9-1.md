# OBI AMQP 0-9-1 protocol parser

OBI traces RabbitMQ client operations over AMQP 0-9-1 on plaintext TCP connections and TLS connections using OpenSSL.

## Protocol Overview

Each frame has a seven-byte header containing the frame type, channel, and payload size. A frame-end marker follows the payload (`0xCE`). A method frame identifies the operation. Content header and body frames carry the message properties and data.

| Method | Client operation | Span kind |
|--------|------------------|-----------|
| `Basic.Publish` | `publish` | Producer |
| `Basic.Deliver` | `process` | Consumer |
| `Basic.Get-Ok` | `receive` | Client |

## Protocol Parsing

The [eBPF parser](../../../bpf/generictracer/protocol_amqp.h) recognizes the eight-byte AMQP 0-9-1 greeting. On an existing connection, it can also recognize a complete Basic method frame.

For example, a RabbitMQ client can receive a whole delivery in one socket read. The eBPF parser uses each frame's payload size to locate its end marker and advance to the next frame.

| Frame in this read | What the eBPF parser does |
|--------------------|---------------------------|
| Method: `Basic.Deliver` | Reads the class and method IDs, then saves the offset and length of the method payload. |
| Content header: message properties and body size | Steps over the properties using the frame size. |
| Body: `{"order":1234}` | Steps over the order data using the frame size. |

When a frame spans reads, the parser keeps its position for the next read. When several deliveries arrive together, it sends one event to Go per recorded method. Each event contains up to 256 bytes of that method's payload.

The [Go parser](../../../pkg/internal/ebpf/amqpparser/amqp091.go) decodes the exchange, routing key, and delivery tag from the captured `Basic.Deliver` payload. If the exchange is `shop` and the routing key is `orders.created`, OBI emits the span `process shop:orders.created` with `messaging.system=rabbitmq`. The destination uses the exchange or routing key alone when only one is present, and `amq.default` when both are empty. Deliveries do not carry the queue name.

## Limitations

- Sends are parsed from a frame boundary. Splitting a frame across sends can cause missed spans.
- OBI captures up to 256 bytes of the method payload. A short capture can truncate destination names or prevent span creation.
- Span duration measures the time OBI spends walking the buffer and emitting the event. OBI omits messaging operation duration histograms for AMQP 0-9-1.
- Trace context propagation through message headers and applications instrumented by OBI's Go tracer are unsupported.
