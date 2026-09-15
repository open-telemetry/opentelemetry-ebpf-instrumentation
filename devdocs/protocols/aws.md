# AWS protocols over HTTP

OBI enriches outbound HTTP client spans for AWS S3, SQS, and SNS when
`OTEL_EBPF_HTTP_AWS_ENABLED=true`.

- S3 extraction identifies operations, buckets, and object keys from HTTP requests.
- SQS extraction reads the `x-amz-target` operation and JSON request and response bodies.
- SNS extraction reads AWS Query API requests and XML responses.

## Supported SNS operations

OBI recognizes the following subset of
[Amazon SNS API actions](https://docs.aws.amazon.com/sns/latest/api/API_Operations.html):

- Publishing: `Publish`, `PublishBatch`
- Topic management: `CreateTopic`, `DeleteTopic`, `ListTopics`,
  `GetTopicAttributes`, `SetTopicAttributes`, `AddPermission`, `RemovePermission`
- Subscription management: `Subscribe`, `Unsubscribe`, `ConfirmSubscription`,
  `ListSubscriptions`, `ListSubscriptionsByTopic`, `GetSubscriptionAttributes`,
  `SetSubscriptionAttributes`

All add `cloud.region` and `aws.request_id` to HTTP client spans.
Additional attributes depend on the operation and captured request and response data.
