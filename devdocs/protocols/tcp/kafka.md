# OBI Kafka protocol parser

This document describes the Kafka protocol parser that OBI provides.

## Protocol Overview

The kafka protocol definition [kafka protocol definition](https://kafka.apache.org/protocol#protocol_messages) defines the schema and types of kafka messages.
Each message in Kafka starts with a header in the following format:

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

current request types obi is tracking are:

- *produce (api key 0)*: obi tracks these requests and produces `produce` spans.
- *fetch (api key 1)*: obi tracks these requests and produces `consume` spans.
- *metadata (api key 3)*: obi tracks these requests (and mainly the responses) to correlate topic names with fetch requests from v13 and above.
  
(unfortunately there is no way to anchor the documentation to a specific message.)

### Flexible Messages

From a specific version onwards, kafka introduced flexible messages, flexible messages introduce multiple changes to the message format, including:

- change from `Request Header v1` to `Request Header v2`, which introduces a new field `tagged_fields` at the end of the header.
- change in the way strings and arrays are encoded (using varints instead of fixed length integers). Examples are `NULLABLE_STRING` and `ARRAY` were changed to `COMPACT_NULLABLE_STRING` and `COMPACT_ARRAY` respectively.
each message type has its own version from which it becomes flexible, you can find it in the `flexibleVersions` json field in the [kafka message definitions](https://github.com/apache/kafka/tree/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message).

## Protocol Parsing

currently the kafka packet is sent to userspace, and goes through the function `ReadTCPRequestIntoSpan` in [tcp_detect_transform.go](../../../pkg/ebpf/common/tcp_detect_transform.go)
and gets parsed into a potential kafka info structure by the function `ProcessKafkaEvent` in [kafka_detect_transform.go](../../../pkg/ebpf/common/kafka_detect_transform.go)
most of the kafka parsing logic is in the file [kafka_parser package](../../../pkg/internal/ebpf/kafkaparser), where each message type has its own parser.
its important to state that these parser ignore any fields that are not relevant for tracing, as well as being able to work on truncated packets (as the BPF program captures only the first 256 bytes of each packet without large buffers).
each parser also tries to handle all different versions of each message type, as well as any nested structures.

### Tracking topic names for fetch requests v13 and above

from fetch api version 13 and above, the topic names are no longer present in the fetch request, and were changed to include the topic ids instead.
in order to be able to track the topic names, obi tracks the metadata requests and responses, in the metadata response, the topic names and their corresponding topic ids are present.
after successfully parsing a metadata response, obi stores the topic names and their corresponding topic ids in the `kafkaTopicUUIDToName` cache
when parsing a fetch request of version 13 or above, obi looks up the topic id in the cache to get the topic name.
this cache can be configured via the `ebpf.KafkaTopicUUIDCacheSize` config option.
if obi does not find the topic id in the cache, it sets the topic name to `*`.
this works but with some limitations:

- since metadata requests are usually sent at the beginning of a consumer lifecycle, or perhaps after a rebalance, obi might miss some topic ids if the metadata request was sent before obi started.
- currently the metadata response is capped at 128 bytes, if the response is larger than that, which in large clusters is very likely since the metadata response contains all broker metadata, obi will miss the topic id mappings.
