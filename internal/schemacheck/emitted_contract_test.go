// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schemacheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

type spanGroupsFile struct {
	Groups []struct {
		ID         string `yaml:"id"`
		Type       string `yaml:"type"`
		Attributes []struct {
			Ref string `yaml:"ref"`
			ID  string `yaml:"id"`
		} `yaml:"attributes"`
	} `yaml:"groups"`
}

// declaredSpanAttributes returns the attribute keys a span group carries.
// Groups are read verbatim: the emitted contract is what a given carrier
// declares, not what it inherits.
func declaredSpanAttributes(t *testing.T, groupID string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(obiGroupsDir, "*", "spans.yaml"))
	require.NoError(t, err)

	for _, path := range matches {
		body, err := os.ReadFile(path)
		require.NoError(t, err)

		var f spanGroupsFile
		require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)

		for _, g := range f.Groups {
			if g.Type != "span" || g.ID != groupID {
				continue
			}
			keys := make([]string, 0, len(g.Attributes))
			for _, a := range g.Attributes {
				key := a.Ref
				if key == "" {
					key = a.ID
				}
				keys = append(keys, key)
			}
			return keys
		}
	}

	require.FailNowf(t, "span group not found", "no group %q under %s", groupID, obiGroupsDir)
	return nil
}

func emittedSpanAttributes(span *request.Span, optional ...attr.Name) []string {
	optionalAttrs := make(map[attr.Name]struct{}, len(optional))
	for _, name := range optional {
		optionalAttrs[name] = struct{}{}
	}

	seen := map[string]struct{}{}
	keys := make([]string, 0)
	for _, kv := range tracesgen.TraceAttributesSelector(span, optionalAttrs) {
		key := string(kv.Key)
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
	}{
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

			assert.ElementsMatch(t, declared, emitted,
				"%s must declare exactly the attributes the exporter emits for this span", tc.groupID)
		})
	}
}
