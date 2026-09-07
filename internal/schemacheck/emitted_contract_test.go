// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

// declaredSpanAttributes returns the attribute keys a span group carries,
// including the ones it inherits: weaver resolves `extends` before publishing,
// so a consumer reading the registry sees the flattened set.
// declaredLevel reports the requirement level a group states for one attribute,
// as a bare word; a conditional level yields the condition's key. A group
// inherits the levels of whatever it extends, so the chain is followed.
func declaredLevel(t *testing.T, groupID, name string) string {
	t.Helper()

	attrs := carrierAttributes(t)
	for id := groupID; id != ""; id = groupExtends(t, id) {
		for _, a := range attrs {
			if a.group != id || a.name != name {
				continue
			}
			var word string
			if err := a.level.Decode(&word); err == nil {
				return word
			}
			var mapping map[string]string
			if err := a.level.Decode(&mapping); err == nil {
				for k := range mapping {
					return k
				}
			}
		}
	}

	return ""
}

func groupExtends(t *testing.T, groupID string) string {
	t.Helper()

	for _, path := range carrierFiles(t) {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f carrierGroupsFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)

		for _, g := range f.Groups {
			if g.ID == groupID {
				return g.Extends
			}
		}
	}

	return ""
}

func declaredSpanAttributes(t *testing.T, groupID string) []string {
	t.Helper()

	groups := map[string]carrierGroup{}
	for _, path := range carrierFiles(t) {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f carrierGroupsFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)

		for _, g := range f.Groups {
			groups[g.ID] = g
		}
	}

	group, ok := groups[groupID]
	require.Truef(t, ok, "no group %q under %s", groupID, obiGroupsDir)
	require.Equalf(t, "span", group.Type, "group %q is not a span group", groupID)

	seen := map[string]struct{}{}
	walked := map[string]struct{}{}
	keys := make([]string, 0, len(group.Attributes))

	for id := groupID; id != ""; {
		g, ok := groups[id]
		require.Truef(t, ok, "group %q extends %q, which no registry file declares", groupID, id)

		for _, a := range g.Attributes {
			key := a.Ref
			if key == "" {
				key = a.ID
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}

		require.NotContainsf(t, walked, g.Extends, "extends cycle through %q", g.Extends)
		walked[id] = struct{}{}
		id = g.Extends
	}

	return keys
}

// A templated attribute is emitted one key per header, while the registry
// declares the template root once. Compare against the root.
var attributeTemplates = []string{"http.request.header", "http.response.header"}

func templateRoot(key string) string {
	for _, t := range attributeTemplates {
		if strings.HasPrefix(key, t+".") {
			return t
		}
	}
	return key
}

func emittedSpanAttributes(span *request.Span, optional ...attr.Name) []string {
	optionalAttrs := make(map[attr.Name]struct{}, len(optional))
	for _, name := range optional {
		optionalAttrs[name] = struct{}{}
	}

	seen := map[string]struct{}{}
	keys := make([]string, 0)
	for _, kv := range tracesgen.TraceAttributesSelector(span, optionalAttrs) {
		key := templateRoot(string(kv.Key))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

// Weaver resolves an emitted attribute against the registry's global attribute
// map, so it accepts a key that is declared on some other carrier. Nothing in
// the weaver-validated suites would notice an attribute going missing from the
// group that is supposed to describe this span. These tests pin the two sides
// together: a span populated in every field the emitter reads must produce
// exactly the keys its group declares.
func TestEmittedSpanAttributesMatchDeclaredGroup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		groupID  string
		span     *request.Span
		optional []attr.Name
		// Attributes the group declares that this span does not carry. A group
		// covers every span of its kind, so an attribute one of them omits is
		// declared below `required` rather than dropped; naming it here keeps
		// the rest of the set exact.
		absent []string
	}{
		{
			name:    "grpc server",
			groupID: "span.obi.rpc.grpc.server",
			span: &request.Span{
				Type:         request.EventTypeGRPC,
				Path:         "/pkg.Service/Method",
				Host:         "10.0.0.1",
				HostPort:     50051,
				Peer:         "10.0.0.2",
				PeerPort:     54321,
				Status:       2,
				ProtoVersion: request.ProtoVersionHTTP2,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "grpc client",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.rpc.grpc.client",
			span: &request.Span{
				Type:         request.EventTypeGRPCClient,
				Path:         "/pkg.Service/Method",
				Host:         "10.0.0.1",
				HostPort:     50051,
				Peer:         "10.0.0.2",
				PeerPort:     54321,
				Status:       2,
				ProtoVersion: request.ProtoVersionHTTP2,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "onc rpc client",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.rpc.onc_rpc.client",
			span: &request.Span{
				Type:         request.EventTypeSunRPCClient,
				Method:       "MOUNTPROC_EXPORT",
				Path:         "nfs",
				Route:        "5",
				Statement:    "AUTH_UNIX",
				SubType:      3,
				Host:         "10.0.0.1",
				HostPort:     2049,
				Peer:         "10.0.0.2",
				PeerPort:     54321,
				Status:       1,
				ProtoVersion: request.ProtoVersionHTTP11,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			// NATS is the only broker that reports an envelope size.
			name:    "nats producer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.nats.producer",
			span: &request.Span{
				Type:          request.EventTypeNATSClient,
				Method:        request.MessagingPublish,
				Path:          "my-subject",
				Statement:     "nats-client-1",
				Host:          "10.0.0.1",
				HostPort:      4222,
				Peer:          "10.0.0.1",
				PeerPort:      54321,
				ContentLength: 128,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			// Kafka reports the offset only on a process operation, so the
			// producer group must not declare it.
			name:    "kafka producer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.kafka.producer",
			span: &request.Span{
				Type:          request.EventTypeKafkaClient,
				Method:        request.MessagingPublish,
				Path:          "my-topic",
				Statement:     "producer-1",
				Host:          "10.0.0.1",
				HostPort:      9092,
				Peer:          "10.0.0.1",
				PeerPort:      54321,
				MessagingInfo: &request.MessagingInfo{HasPartition: true, Partition: 3, Offset: 42},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			// MQTT carries neither partition metadata nor an envelope size.
			name:    "mqtt consumer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.mqtt.consumer",
			span: &request.Span{
				Type:      request.EventTypeMQTTClient,
				Method:    request.MessagingProcess,
				Path:      "my/topic",
				Statement: "mqtt-client-1",
				Host:      "10.0.0.1",
				HostPort:  1883,
				Peer:      "10.0.0.1",
				PeerPort:  54321,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "jsonrpc client",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.jsonrpc.client",
			span: &request.Span{
				Type:                request.EventTypeHTTPClient,
				SubType:             request.HTTPSubtypeJSONRPC,
				Method:              "POST",
				Path:                "/rpc",
				Host:                "10.0.0.1",
				HostPort:            8545,
				Peer:                "10.0.0.1",
				PeerPort:            54321,
				Status:              200,
				ProtoVersion:        request.ProtoVersionHTTP11,
				RequestHeaders:      map[string][]string{"x-trace": {"1"}, "user-agent": {"curl/8.0"}},
				ResponseHeaders:     map[string][]string{"x-reply": {"2"}},
				RequestBodyContent:  "{}",
				ResponseBodyContent: "{}",
				JSONRPC: &request.JSONRPC{
					// Go net/rpc qualifies the method, which is what makes the
					// span report rpc.method_original alongside rpc.method.
					Method:           "Arith.Multiply",
					ServiceQualified: true,
					Version:          "2.0",
					RequestID:        "1",
					ErrorCode:        -32600,
				},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.UserAgentOriginal,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "onc rpc server",
			groupID: "span.obi.rpc.onc_rpc.server",
			span: &request.Span{
				Type:         request.EventTypeSunRPCServer,
				Method:       "MOUNTPROC_EXPORT",
				Path:         "nfs",
				Route:        "5",
				Statement:    "AUTH_UNIX",
				SubType:      3,
				Host:         "10.0.0.1",
				HostPort:     2049,
				Peer:         "10.0.0.2",
				PeerPort:     54321,
				Status:       1,
				ProtoVersion: request.ProtoVersionHTTP11,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "amqp producer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.amqp.producer",
			span: &request.Span{
				Type:     request.EventTypeAMQPClient,
				Method:   request.MessagingPublish,
				Path:     "my-exchange",
				Host:     "10.0.0.1",
				HostPort: 5672,
				Peer:     "10.0.0.1",
				PeerPort: 54321,
				Status:   1,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "kafka consumer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.kafka.consumer",
			span: &request.Span{
				Type:          request.EventTypeKafkaClient,
				Method:        request.MessagingProcess,
				Path:          "my-topic",
				Statement:     "consumer-1",
				Host:          "10.0.0.1",
				HostPort:      9092,
				Peer:          "10.0.0.1",
				PeerPort:      54321,
				Status:        1,
				MessagingInfo: &request.MessagingInfo{HasPartition: true, Partition: 3, Offset: 42, ConsumerGroup: "my-group"},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			// The kind follows the operation, not the side, so a server-side
			// producer lands in the same group as a client-side one. It differs
			// by one attribute: service.peer.name is appended only for the
			// client event types, which is why the group declares it as
			// recommended rather than required.
			name:    "kafka producer observed server-side",
			groupID: "span.obi.messaging.kafka.producer",
			span: &request.Span{
				Type:          request.EventTypeKafkaServer,
				Method:        request.MessagingPublish,
				Path:          "my-topic",
				Statement:     "producer-1",
				Host:          "10.0.0.1",
				HostPort:      9092,
				HostName:      "broker-1",
				Peer:          "10.0.0.1",
				PeerPort:      54321,
				MessagingInfo: &request.MessagingInfo{HasPartition: true, Partition: 3},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
			absent: []string{"service.peer.name"},
		},
		{
			name:    "kafka client",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.kafka.client",
			span: &request.Span{
				Type:          request.EventTypeKafkaClient,
				Method:        request.MessagingReceive,
				Path:          "my-topic",
				Statement:     "consumer-1",
				Host:          "10.0.0.1",
				HostPort:      9092,
				Peer:          "10.0.0.1",
				PeerPort:      54321,
				MessagingInfo: &request.MessagingInfo{HasPartition: true, Partition: 3},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "mqtt producer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.mqtt.producer",
			span: &request.Span{
				Type:      request.EventTypeMQTTClient,
				Method:    request.MessagingPublish,
				Path:      "my/topic",
				Statement: "mqtt-client-1",
				Host:      "10.0.0.1",
				HostPort:  1883,
				Peer:      "10.0.0.1",
				PeerPort:  54321,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "mqtt client",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.mqtt.client",
			span: &request.Span{
				Type:      request.EventTypeMQTTClient,
				Method:    request.MessagingReceive,
				Path:      "my/topic",
				Statement: "mqtt-client-1",
				Host:      "10.0.0.1",
				HostPort:  1883,
				Peer:      "10.0.0.1",
				PeerPort:  54321,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "nats consumer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.nats.consumer",
			span: &request.Span{
				Type:          request.EventTypeNATSClient,
				Method:        request.MessagingProcess,
				Path:          "my-subject",
				Statement:     "nats-client-1",
				Host:          "10.0.0.1",
				HostPort:      4222,
				Peer:          "10.0.0.1",
				PeerPort:      54321,
				ContentLength: 128,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "nats client",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.nats.client",
			span: &request.Span{
				Type:          request.EventTypeNATSClient,
				Method:        request.MessagingReceive,
				Path:          "my-subject",
				Statement:     "nats-client-1",
				Host:          "10.0.0.1",
				HostPort:      4222,
				Peer:          "10.0.0.1",
				PeerPort:      54321,
				ContentLength: 128,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "amqp consumer",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.amqp.consumer",
			span: &request.Span{
				Type:     request.EventTypeAMQPClient,
				Method:   request.MessagingProcess,
				Path:     "my-exchange",
				Host:     "10.0.0.1",
				HostPort: 5672,
				Peer:     "10.0.0.1",
				PeerPort: 54321,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "amqp client",
			absent:  []string{"service.peer.name"},
			groupID: "span.obi.messaging.amqp.client",
			span: &request.Span{
				Type:     request.EventTypeAMQPClient,
				Method:   request.MessagingSettle,
				Path:     "my-exchange",
				Host:     "10.0.0.1",
				HostPort: 5672,
				Peer:     "10.0.0.1",
				PeerPort: 54321,
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "elasticsearch client",
			groupID: "span.obi.elasticsearch.client",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeElasticsearch,
				// Outside the semconv enum, so http.request.method clamps to
				// _OTHER and http.request.method_original carries the wire value.
				Method: "SEARCH",
				Path:   "/my-index/_search",
				// An IP rather than a name: networkPeerAttributes omits
				// network.peer.* for a hostname, since server.address carries it.
				Host:         "10.0.0.1",
				HostPort:     9200,
				HostName:     "es-1",
				Peer:         "10.0.0.1",
				PeerPort:     54321,
				Status:       500,
				ProtoVersion: request.ProtoVersionHTTP11,
				DBNamespace:  "my-index",
				Elasticsearch: &request.Elasticsearch{
					DBSystemName:     "elasticsearch",
					DBOperationName:  "search",
					DBCollectionName: "my-index",
					DBQueryText:      `{"query":{"match_all":{}}}`,
					NodeName:         "node-1",
				},
			},
			optional: []attr.Name{
				attr.DBQueryText,
				attr.HTTPRequestMethodOrig,
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "aws s3 client",
			groupID: "span.obi.aws.s3.client",
			span: &request.Span{
				Type:         request.EventTypeHTTPClient,
				SubType:      request.HTTPSubtypeAWSS3,
				Host:         "10.0.0.1",
				HostPort:     443,
				HostName:     "s3-1",
				Status:       500,
				ProtoVersion: request.ProtoVersionHTTP11,
				AWS: &request.AWS{S3: request.AWSS3{
					Meta: request.AWSMeta{
						RequestID:         "req-1",
						ExtendedRequestID: "ext-1",
						Region:            "us-east-1",
					},
					Method: "GetObject",
					Bucket: "my-bucket",
					Key:    "reports/q3.pdf",
				}},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
		{
			name:    "aws sqs client",
			groupID: "span.obi.aws.sqs.client",
			span: &request.Span{
				Type:         request.EventTypeHTTPClient,
				SubType:      request.HTTPSubtypeAWSSQS,
				Host:         "10.0.0.1",
				HostPort:     443,
				HostName:     "sqs-1",
				Status:       500,
				ProtoVersion: request.ProtoVersionHTTP11,
				AWS: &request.AWS{SQS: request.AWSSQS{
					Meta: request.AWSMeta{
						RequestID:         "req-2",
						ExtendedRequestID: "ext-2",
						Region:            "us-east-1",
					},
					OperationName: "SendMessage",
					OperationType: "send",
					Destination:   "my-queue",
					QueueURL:      "https://sqs.us-east-1.amazonaws.com/1/my-queue",
					MessageID:     "msg-1",
				}},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declared := declaredSpanAttributes(t, tc.groupID)
			emitted := emittedSpanAttributes(tc.span, tc.optional...)

			for _, name := range tc.absent {
				require.NotContainsf(t, emitted, name,
					"%q is listed as absent but the exporter emitted it", name)
				require.Containsf(t, declared, name,
					"%q is listed as absent but %s does not declare it", name, tc.groupID)
				require.NotEqualf(t, "required", declaredLevel(t, tc.groupID, name),
					"%s declares %q required, so a span in the group cannot omit it", tc.groupID, name)
				declared = slices.DeleteFunc(declared, func(d string) bool { return d == name })
			}

			assert.ElementsMatch(t, declared, emitted,
				"%s must declare exactly the attributes the exporter emits for this span", tc.groupID)
		})
	}
}

// An OpenAI exchange is recognized from its response headers regardless of the
// URL path, so it can reach the exporters with no operation classified. The
// groups still declare the operation name required, so both exporters must
// report it for that span.
func TestUnclassifiedGenAIOperationIsStillEmitted(t *testing.T) {
	span := &request.Span{
		Type:    request.EventTypeHTTPClient,
		SubType: request.HTTPSubtypeOpenAI,
		Path:    "/v1/unrecognized",
		GenAI:   &request.GenAI{OpenAI: &request.VendorOpenAI{}},
	}

	for _, groupID := range []string{
		"span.obi.gen_ai.inference.client",
		"metric.obi.gen_ai.client.operation.duration",
		"metric.obi.gen_ai.client.token.usage",
	} {
		require.Equalf(t, "required", declaredLevel(t, groupID, "gen_ai.operation.name"),
			"%s no longer declares gen_ai.operation.name required", groupID)
	}

	var spanValue string
	for _, kv := range tracesgen.TraceAttributesSelector(span, map[attr.Name]struct{}{}) {
		if kv.Key == "gen_ai.operation.name" {
			spanValue = kv.Value.AsString()
		}
	}
	assert.NotEmpty(t, spanValue, "the trace exporter omitted gen_ai.operation.name or sent it empty")

	getter, ok := request.SpanOTELGetters(request.UnresolvedNames{})(attr.GenAIOperationName)
	require.True(t, ok)
	assert.NotEmpty(t, getter(span).Value.AsString(), "the metric getter omitted gen_ai.operation.name or sent it empty")
}
