// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
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

// declaredSpan returns the span a registry file defines under `type`, and the
// internal attribute groups the registry defines, keyed by id.
func declaredSpan(t *testing.T, spanType string) (registrySpan, map[string]registryAttributeGroup) {
	t.Helper()

	var span registrySpan
	found := false
	groups := map[string]registryAttributeGroup{}
	for _, f := range registryFiles(t) {
		for _, s := range f.Spans {
			if s.Type == spanType {
				span, found = s, true
			}
		}
		for _, g := range f.AttributeGroups {
			groups[g.ID] = g
		}
	}
	require.Truef(t, found, "no span %q under %s", spanType, obiGroupsDir)
	return span, groups
}

// spanRefs returns the attribute references a span carries, including the ones
// of the attribute groups it references with `ref_group`: weaver resolves them
// before publishing, so a consumer reading the registry sees the flattened set.
func spanRefs(t *testing.T, spanType string) []carrierAttrRef {
	t.Helper()

	span, groups := declaredSpan(t, spanType)
	var refs []carrierAttrRef
	for _, a := range span.Attributes {
		if a.RefGroup == "" {
			refs = append(refs, a)
			continue
		}
		g, ok := groups[a.RefGroup]
		require.Truef(t, ok, "span %q references attribute group %q, which no registry file declares", spanType, a.RefGroup)
		refs = append(refs, g.Attributes...)
	}
	return refs
}

// declaredLevel reports the requirement level a span states for one attribute,
// as a bare word; a conditional level yields the condition's key.
func declaredLevel(t *testing.T, spanType, name string) string {
	t.Helper()

	for _, a := range spanRefs(t, spanType) {
		if a.Ref == name {
			return levelWord(a.RequirementLevel)
		}
	}

	return ""
}

// declaredMetricLevel is declaredLevel for a metric definition.
func declaredMetricLevel(t *testing.T, metricName, name string) string {
	t.Helper()

	for _, f := range registryFiles(t) {
		for _, m := range f.Metrics {
			if m.Name != metricName {
				continue
			}
			for _, a := range m.Attributes {
				if a.Ref == name {
					return levelWord(a.RequirementLevel)
				}
			}
		}
	}

	return ""
}

// levelWord reports a requirement level as a bare word; a conditional level
// yields the condition's key.
func levelWord(level yaml.Node) string {
	var word string
	if err := level.Decode(&word); err == nil {
		return word
	}
	var mapping map[string]string
	if err := level.Decode(&mapping); err == nil {
		for k := range mapping {
			return k
		}
	}

	return ""
}

func declaredSpanAttributes(t *testing.T, spanType string) []string {
	t.Helper()

	seen := map[string]struct{}{}
	var keys []string
	for _, a := range spanRefs(t, spanType) {
		if _, dup := seen[a.Ref]; dup {
			continue
		}
		seen[a.Ref] = struct{}{}
		keys = append(keys, a.Ref)
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

// The server branch emits the same HTTP set whatever the subtype, so every
// server span that references attributes.obi.http.server starts from this span.
func populatedHTTPServerSpan(subType int) *request.Span {
	return &request.Span{
		Type:                request.EventTypeHTTP,
		SubType:             subType,
		Method:              "SEARCH",
		Path:                "/v1/things",
		FullPath:            "/v1/things?q=1",
		Route:               "/v1/things",
		Statement:           "https" + request.SchemeHostSeparator + "api.example.com",
		Host:                "10.0.0.1",
		HostPort:            8443,
		Peer:                "10.0.0.2",
		PeerPort:            54321,
		Status:              500,
		ProtoVersion:        request.ProtoVersionHTTP11,
		UserAgent:           "curl/8.0",
		RequestHeaders:      map[string][]string{"x-trace": {"1"}},
		ResponseHeaders:     map[string][]string{"x-reply": {"2"}},
		RequestBodyContent:  "{}",
		ResponseBodyContent: "{}",
	}
}

var httpSpanOptional = []attr.Name{
	attr.HTTPUrlQuery,
	attr.HTTPRequestMethodOrig,
	attr.HTTPRequestBodySize,
	attr.HTTPResponseBodySize,
	attr.OBIHTTPResponseObserved,
	attr.UserAgentOriginal,
	attr.NetworkPeerAddress,
	attr.NetworkPeerPort,
	attr.NetworkProtocolVersion,
	attr.ErrorType,
	attr.SkipSpanMetrics,
	attr.ServicePeerName,
}

// emittedSpanCase is a span populated in every field the emitter reads for its
// protocol, and the span definition it must be described by.
type emittedSpanCase struct {
	name     string
	spanType string
	span     *request.Span
	optional []attr.Name
	// Attributes the span definition declares that this span does not carry. A
	// definition covers every span of its kind, so an attribute one of them
	// omits is declared below `required` rather than dropped; naming it here
	// keeps the rest of the set exact.
	absent []string
}

func emittedSpanCases() []emittedSpanCase {
	return []emittedSpanCase{
		{
			name:     "grpc server",
			spanType: "obi.rpc.grpc.server",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "grpc client",
			absent:   []string{"service.peer.name"},
			spanType: "obi.rpc.grpc.client",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "onc rpc client",
			absent:   []string{"service.peer.name"},
			spanType: "obi.rpc.onc_rpc.client",
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
				attr.ServicePeerName,
			},
		},
		{
			// NATS is the only broker that reports an envelope size.
			name:     "nats producer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.nats.producer",
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
				attr.ServicePeerName,
			},
		},
		{
			// Kafka reports the offset only on a process operation, so the
			// producer group must not declare it.
			name:     "kafka producer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.kafka.producer",
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
				attr.ServicePeerName,
			},
		},
		{
			// MQTT carries neither partition metadata nor an envelope size.
			name:     "mqtt consumer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.mqtt.consumer",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "jsonrpc client",
			absent:   []string{"service.peer.name"},
			spanType: "obi.jsonrpc.client",
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
					Method:    "Arith.Multiply",
					Version:   "2.0",
					RequestID: "1",
					ErrorCode: -32600,
				},
			},
			optional: []attr.Name{
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.UserAgentOriginal,
				attr.ErrorType,
				attr.SkipSpanMetrics,
				attr.ServicePeerName,
			},
		},
		{
			name:     "onc rpc server",
			spanType: "obi.rpc.onc_rpc.server",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "amqp producer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.amqp.producer",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "kafka consumer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.kafka.consumer",
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
				attr.ServicePeerName,
			},
		},
		{
			// The kind follows the operation, not the side, so a server-side
			// producer lands in the same group as a client-side one. It differs
			// by one attribute: service.peer.name is appended only for the
			// client event types, which is why the group declares it as
			// recommended rather than required.
			name:     "kafka producer observed server-side",
			spanType: "obi.messaging.kafka.producer",
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
				attr.ServicePeerName,
			},
			absent: []string{"service.peer.name"},
		},
		{
			name:     "mqtt producer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.mqtt.producer",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "nats consumer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.nats.consumer",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "amqp consumer",
			absent:   []string{"service.peer.name"},
			spanType: "obi.messaging.amqp.consumer",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "elasticsearch client",
			spanType: "obi.elasticsearch.client",
			span: &request.Span{
				Type:    request.EventTypeHTTPClient,
				SubType: request.HTTPSubtypeElasticsearch,
				Method:  "POST",
				Path:    "/my-index/_search",
				// An IP rather than a name: networkPeerAttributes omits
				// network.peer.* for a hostname, since server.address carries it.
				Host:         "10.0.0.1",
				HostPort:     9200,
				HostName:     "es-1",
				Peer:         "10.0.0.1",
				PeerPort:     54321,
				Status:       500,
				ProtoVersion: request.ProtoVersionHTTP11,
				DBNamespace:  "my-cluster",
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
				attr.HTTPResponseBodySize,
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.NetworkProtocolVersion,
				attr.ErrorType,
				attr.SkipSpanMetrics,
				attr.ServicePeerName,
			},
		},
		{
			name:     "aws s3 client",
			spanType: "obi.aws.s3.client",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "aws sqs client",
			spanType: "obi.aws.sqs.client",
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
				attr.ServicePeerName,
			},
		},
		{
			name:     "http server",
			spanType: "obi.http.server",
			span:     populatedHTTPServerSpan(request.HTTPSubtypeNone),
			optional: httpSpanOptional,
			absent:   []string{"obi.http.response.observed"},
		},
		{
			name:     "http server with an unobserved response",
			spanType: "obi.http.server",
			span: func() *request.Span {
				s := populatedHTTPServerSpan(request.HTTPSubtypeNone)
				s.ResponseObservation = request.ResponseReceived
				return s
			}(),
			optional: httpSpanOptional,
			absent:   []string{"http.response.status_code", "error.type"},
		},
		{
			name:     "graphql server",
			spanType: "obi.graphql.server",
			span: func() *request.Span {
				s := populatedHTTPServerSpan(request.HTTPSubtypeGraphQL)
				s.GraphQL = &request.GraphQL{
					Document:      "query Q { things { id } }",
					OperationName: "Q",
					OperationType: "query",
				}
				return s
			}(),
			optional: append([]attr.Name{attr.GraphQLDocument}, httpSpanOptional...),
			absent:   []string{"obi.http.response.observed"},
		},
		{
			name:     "mcp server",
			spanType: "obi.mcp.server",
			span: func() *request.Span {
				s := populatedHTTPServerSpan(request.HTTPSubtypeMCP)
				s.GenAI = &request.GenAI{MCP: &request.MCPCall{
					Method:            request.MCPMethodToolsCall,
					ToolName:          "search",
					ToolType:          "function",
					ToolCallArguments: `{"q":"x"}`,
					ToolCallResult:    `{"hits":0}`,
					ResourceURI:       "file:///tmp/x",
					PromptName:        "summarize",
					SessionID:         "s-1",
					ProtocolVer:       "2025-06-18",
					RequestID:         "1",
					ErrorCode:         -32602,
				}}
				return s
			}(),
			optional: append([]attr.Name{attr.GenAIToolCallArguments, attr.GenAIToolCallResult}, httpSpanOptional...),
			absent:   []string{"obi.http.response.observed"},
		},
		{
			name:     "jsonrpc server",
			spanType: "obi.jsonrpc.server",
			span: func() *request.Span {
				s := populatedHTTPServerSpan(request.HTTPSubtypeJSONRPC)
				s.JSONRPC = &request.JSONRPC{
					Method:           "Arith.Multiply",
					ServiceQualified: true,
					Version:          "2.0",
					RequestID:        "1",
					ErrorCode:        -32600,
				}
				return s
			}(),
			optional: httpSpanOptional,
			absent:   []string{"obi.http.response.observed"},
		},
		{
			name:     "http client",
			spanType: "obi.http.client",
			span: &request.Span{
				Type:                request.EventTypeHTTPClient,
				Method:              "SEARCH",
				Path:                "/v1/things",
				FullPath:            "/v1/things?q=1",
				Statement:           "https" + request.SchemeHostSeparator + "api.example.com",
				Host:                "10.0.0.1",
				HostPort:            443,
				HostName:            "api.example.com",
				Peer:                "10.0.0.2",
				PeerPort:            54321,
				Status:              500,
				ProtoVersion:        request.ProtoVersionHTTP11,
				RequestHeaders:      map[string][]string{"x-trace": {"1"}, "user-agent": {"curl/8.0"}},
				ResponseHeaders:     map[string][]string{"x-reply": {"2"}},
				RequestBodyContent:  "{}",
				ResponseBodyContent: "{}",
			},
			optional: httpSpanOptional,
			absent:   []string{"obi.http.response.observed"},
		},
		{
			name:     "sql client",
			spanType: "obi.db.sql.client",
			span: &request.Span{
				Type:           request.EventTypeSQLClient,
				Method:         "SELECT",
				Path:           "users",
				Statement:      "SELECT * FROM users WHERE id = 1",
				DBQuerySummary: "SELECT users",
				DBNamespace:    "app",
				Host:           "10.0.0.1",
				HostPort:       5432,
				HostName:       "postgres",
				Peer:           "10.0.0.2",
				PeerPort:       54321,
				Status:         1,
				SQLError:       &request.SQLError{Code: 1062, Message: "duplicate"},
			},
			optional: []attr.Name{
				attr.DBQueryText,
				attr.DBQuerySummary,
				attr.NetworkPeerAddress,
				attr.NetworkPeerPort,
				attr.ErrorType,
				attr.SkipSpanMetrics,
				attr.ServicePeerName,
			},
		},
	}
}

// Weaver resolves an emitted attribute against the registry's global attribute
// map, so it accepts a key that is declared on some other carrier. Nothing in
// the weaver-validated suites would notice an attribute going missing from the
// span definition that is supposed to describe this span. These tests pin the
// two sides together: a span populated in every field the emitter reads must
// produce exactly the keys its span definition declares.
func TestEmittedSpanAttributesMatchDeclaredGroup(t *testing.T) {
	for _, tc := range emittedSpanCases() {
		t.Run(tc.name, func(t *testing.T) {
			declared := declaredSpanAttributes(t, tc.spanType)
			emitted := emittedSpanAttributes(tc.span, tc.optional...)

			for _, name := range tc.absent {
				require.NotContainsf(t, emitted, name,
					"%q is listed as absent but the exporter emitted it", name)
				require.Containsf(t, declared, name,
					"%q is listed as absent but %s does not declare it", name, tc.spanType)
				require.NotEqualf(t, "required", declaredLevel(t, tc.spanType, name),
					"%s declares %q required, so a span of that type cannot omit it", tc.spanType, name)
				declared = slices.DeleteFunc(declared, func(d string) bool { return d == name })
			}

			assert.ElementsMatch(t, declared, emitted,
				"%s must declare exactly the attributes the exporter emits for this span", tc.spanType)
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

	require.Equal(t, "required", declaredLevel(t, "obi.gen_ai.inference.client", "gen_ai.operation.name"),
		"obi.gen_ai.inference.client no longer declares gen_ai.operation.name required")
	for _, metric := range []string{"gen_ai.client.operation.duration", "gen_ai.client.token.usage"} {
		require.Equalf(t, "required", declaredMetricLevel(t, metric, "gen_ai.operation.name"),
			"%s no longer declares gen_ai.operation.name required", metric)
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
