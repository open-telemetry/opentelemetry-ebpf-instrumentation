# OBI Kafka protocol parser

This document describes the Kafka protocol parser that OBI provides.

## Protocol Overview

The [Kafka protocol definition](https://Kafka.apache.org/protocol#protocol_messages) defines the schema and types of Kafka messages.

All requests and responses bring have as first the following field:

```
RequestOrResponse:
  message_size => INT32
```

`message_size` gives the size of the subsequent request or response message in bytes.

Each message in Kafka request starts with a header in the following format:

```
Request Header:
  request_api_key => INT16
  request_api_version => INT16
  correlation_id => INT32
  client_id => NULLABLE_STRING
```

the `request_api_key` defines the type of request, for example, `produce` or `fetch`.
the `request_api_version` defines the version of the request, each message type has its own set of versions, and they increment independently.
the `correlation_id` is used to correlate requests and responses.

Current request types OBI is tracking are:

- *Produce (api key 0)*: OBI tracks these requests and produces `produce` spans.
- *Fetch (api key 1)*: OBI tracks these requests and produces `consume` spans.
- *Metadata (api key 3)*: OBI tracks these requests (and mainly the responses) to correlate topic names with fetch requests from v13 and above.

### Flexible Messages

From a specific version onwards, Kafka introduced flexible messages, flexible messages introduce multiple changes to the message format, including:

- Change from `Request Header v1` to `Request Header v2`, which introduces a new field `tagged_fields` at the end of the header.
- Change in the way strings and arrays are encoded (using varints instead of fixed length integers). Examples are `NULLABLE_STRING` and `ARRAY` were changed to `COMPACT_NULLABLE_STRING` and `COMPACT_ARRAY` respectively.
each message type has its own version from which it becomes flexible, you can find it in the `flexibleVersions` json field in the [Kafka message definitions](https://github.com/apache/Kafka/tree/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message).

## Protocol Parsing

Currently the Kafka packet is sent to userspace, and goes through the function `ReadTCPRequestIntoSpan` in [tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go)
and gets parsed into a potential Kafka info structure by the function `ProcessKafkaEvent` in [Kafka_detect_transform.go](../../../pkg/ebpf/common/Kafka_detect_transform.go)
most of the Kafka parsing logic is in the file [Kafka_parser package](../../../pkg/internal/ebpf/Kafkaparser), where each message type has its own parser.

It's important to state that these parser ignore any fields that are not relevant for tracing, as well as being able to work on truncated packets.  Each parser also tries to handle all different versions of each message type, as well as any nested structures.

OBI running with the default configuration gets the Metadata response at 128 bytes. If the response is larger than that, which in large clusters is very likely since the Metadata response contains all broker Metadata, OBI will miss the topic id mappings. To solve that, OBI can be run with the `OTEL_EBPF_BPF_BUFFER_SIZE_KAFKA` and use the large buffer feature. So, request/response analysis is performed in the kernel and if an event is of interest to us (currently only for Metadata), is sent to userspace using a large buffer event.

### Tracking topic names for fetch requests v13 and above

From fetch api version 13 and above, the topic names are no longer present in the fetch request, and were changed to include the topic ids instead.
In order to be able to track the topic names, OBI tracks the Metadata requests and responses, in the Metadata response, the topic names and their corresponding topic ids are present.
After successfully parsing a Metadata response, OBI stores the topic names and their corresponding topic ids in the `KafkaTopicUUIDToName` cache
when parsing a fetch request of version 13 or above, OBI looks up the topic id in the cache to get the topic name.
This cache can be configured via the `ebpf.KafkaTopicUUIDCacheSize` config option.
If OBI does not find the topic id in the cache, it sets the topic name to `*`.

This works but with some limitations:

- Since Metadata requests are usually sent at the beginning of a consumer lifecycle, or perhaps after a rebalance, OBI might miss some topic ids if the Metadata request was sent before OBI started.
