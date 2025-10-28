// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func TestOtlpOptions_AsMetricHTTP(t *testing.T) {
	type testCase struct {
		in  OTLPOptions
		len int
	}
	testCases := []testCase{
		{in: OTLPOptions{Endpoint: "foo"}, len: 1},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", URLPath: "/foo"}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
		{in: OTLPOptions{Endpoint: "foo", URLPath: "/foo", SkipTLSVerify: true}, len: 3},
		{in: OTLPOptions{Endpoint: "foo", URLPath: "/foo", Insecure: true, SkipTLSVerify: true}, len: 4},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Len(t, tc.in.AsMetricHTTP(), tc.len)
		})
	}
}

func TestOtlpOptions_AsMetricGRPC(t *testing.T) {
	type testCase struct {
		in  OTLPOptions
		len int
	}
	testCases := []testCase{
		{in: OTLPOptions{Endpoint: "foo"}, len: 1},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Len(t, tc.in.AsMetricGRPC(), tc.len)
		})
	}
}

func TestOtlpOptions_AsTraceHTTP(t *testing.T) {
	type testCase struct {
		in  OTLPOptions
		len int
	}
	testCases := []testCase{
		{in: OTLPOptions{Endpoint: "foo"}, len: 1},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", URLPath: "/foo"}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
		{in: OTLPOptions{Endpoint: "foo", URLPath: "/foo", SkipTLSVerify: true}, len: 3},
		{in: OTLPOptions{Endpoint: "foo", URLPath: "/foo", Insecure: true, SkipTLSVerify: true}, len: 4},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Len(t, tc.in.AsTraceHTTP(), tc.len)
		})
	}
}

func TestOtlpOptions_AsTraceGRPC(t *testing.T) {
	type testCase struct {
		in  OTLPOptions
		len int
	}
	testCases := []testCase{
		{in: OTLPOptions{Endpoint: "foo"}, len: 1},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", SkipTLSVerify: true}, len: 2},
		{in: OTLPOptions{Endpoint: "foo", Insecure: true, SkipTLSVerify: true}, len: 3},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			assert.Len(t, tc.in.AsTraceGRPC(), tc.len)
		})
	}
}

func TestParseOTELEnvVar(t *testing.T) {
	type testCase struct {
		envVar   string
		expected map[string]string
	}

	testCases := []testCase{
		{envVar: "foo=bar", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz=baz", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "foo=bar,baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo=bar, baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz= ", expected: map[string]string{"foo": "bar", "baz": "baz="}},
		{envVar: ",a=b , c=d,=", expected: map[string]string{"a": "b", "c": "d"}},
		{envVar: "=", expected: map[string]string{}},
		{envVar: "====", expected: map[string]string{}},
		{envVar: "a====b", expected: map[string]string{"a": "===b"}},
		{envVar: "", expected: map[string]string{}},
	}

	const dummyVar = "foo"

	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			actual := map[string]string{}

			apply := func(k string, v string) {
				actual[k] = v
			}

			t.Setenv(dummyVar, tc.envVar)

			parseOTELEnvVar(nil, dummyVar, apply)

			assert.True(t, reflect.DeepEqual(actual, tc.expected))
		})
	}
}

func TestParseOTELEnvVarPerService(t *testing.T) {
	type testCase struct {
		envVar   string
		expected map[string]string
	}

	testCases := []testCase{
		{envVar: "foo=bar", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz", expected: map[string]string{"foo": "bar"}},
		{envVar: "foo=bar,baz=baz", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "foo=bar,baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo=bar, baz=baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz ", expected: map[string]string{"foo": "bar", "baz": "baz"}},
		{envVar: "  foo = bar , baz =baz= ", expected: map[string]string{"foo": "bar", "baz": "baz="}},
		{envVar: ",a=b , c=d,=", expected: map[string]string{"a": "b", "c": "d"}},
		{envVar: "=", expected: map[string]string{}},
		{envVar: "====", expected: map[string]string{}},
		{envVar: "a====b", expected: map[string]string{"a": "===b"}},
		{envVar: "", expected: map[string]string{}},
	}

	const dummyVar = "foo"

	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			actual := map[string]string{}

			apply := func(k string, v string) {
				actual[k] = v
			}

			parseOTELEnvVar(&svc.Attrs{EnvVars: map[string]string{dummyVar: tc.envVar}}, dummyVar, apply)

			assert.True(t, reflect.DeepEqual(actual, tc.expected))
		})
	}
}

func TestParseOTELEnvVar_nil(t *testing.T) {
	actual := map[string]string{}

	apply := func(k string, v string) {
		actual[k] = v
	}

	parseOTELEnvVar(nil, "NOT_SET_VAR", apply)

	assert.True(t, reflect.DeepEqual(actual, map[string]string{}))
}

func TestResolveOTLPEndpoint(t *testing.T) {
	type expected struct {
		e      string
		common bool
	}

	type testCase struct {
		endpoint string
		common   string
		expected expected
	}

	testCases := []testCase{
		{endpoint: "e1", common: "c1", expected: expected{e: "e1", common: false}},
		{endpoint: "e1", common: "", expected: expected{e: "e1", common: false}},
		{endpoint: "", common: "c1", expected: expected{e: "c1", common: true}},
		{endpoint: "", common: "", expected: expected{e: "", common: false}},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			ep, common := ResolveOTLPEndpoint(tc.endpoint, tc.common)

			assert.Equal(t, ep, tc.expected.e)
			assert.Equal(t, common, tc.expected.common)
		})
	}
}

func TestGetFilteredResourceAttrs(t *testing.T) {
	type testCase struct {
		name            string
		baseAttrs       []attribute.KeyValue
		attrSelector    attributes.Selection
		extraAttrs      []attribute.KeyValue
		prefixPatterns  []string
		expectedAttrs   []string
		unexpectedAttrs []string
	}

	testMetric := attributes.Name{
		Section: "test.metric",
	}

	testCases := []testCase{
		{
			name: "No filtering configuration",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "opentelemetry-ebpf-instrumentation"),
			},
			attrSelector: attributes.Selection{},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
			},
			prefixPatterns: []string{"process."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.command_args",
				"process.pid",
			},
			unexpectedAttrs: []string{},
		},
		{
			name: "With filtering configuration excluding process.command_args",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "opentelemetry-ebpf-instrumentation"),
			},
			attrSelector: attributes.Selection{
				testMetric.Section: attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.command_args"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.pid",
			},
			unexpectedAttrs: []string{
				"process.command_args",
			},
		},
		{
			name: "With filtering configuration using glob patterns",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "opentelemetry-ebpf-instrumentation"),
			},
			attrSelector: attributes.Selection{
				testMetric.Section: attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.*"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
				attribute.String("host.name", "test-host"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"host.name",
			},
			unexpectedAttrs: []string{
				"process.command_args",
				"process.pid",
			},
		},
		{
			name: "With different exclusion patterns",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "opentelemetry-ebpf-instrumentation"),
			},
			attrSelector: attributes.Selection{
				testMetric.Section: attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.command_args", "host.*"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
				attribute.String("host.name", "test-host"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.pid",
			},
			unexpectedAttrs: []string{
				"process.command_args",
				"host.name",
			},
		},
		{
			name: "Testing selector order - specific patterns override general ones",
			baseAttrs: []attribute.KeyValue{
				attribute.String("service.name", "test-service"),
				attribute.String("telemetry.sdk.name", "opentelemetry-ebpf-instrumentation"),
			},
			attrSelector: attributes.Selection{
				"*": attributes.InclusionLists{
					Include: []string{"*"},
					Exclude: []string{"process.*", "host.*"},
				},
				"test.*": attributes.InclusionLists{
					Exclude: []string{"container.*"},
				},
				"test.metric": attributes.InclusionLists{
					Include: []string{"process.pid", "host.name"},
				},
			},
			extraAttrs: []attribute.KeyValue{
				attribute.String("process.command_args", "/bin/test --arg1 --arg2"),
				attribute.String("process.pid", "12345"),
				attribute.String("host.name", "test-host"),
				attribute.String("container.id", "container123"),
			},
			prefixPatterns: []string{"test."},
			expectedAttrs: []string{
				"service.name",
				"telemetry.sdk.name",
				"process.pid",
				"host.name",
			},
			unexpectedAttrs: []string{
				"process.command_args",
				"container.id",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetFilteredAttributesByPrefix(tc.baseAttrs, tc.attrSelector, tc.extraAttrs, tc.prefixPatterns)

			attrMap := make(map[string]attribute.Value)
			for _, attr := range result {
				attrMap[string(attr.Key)] = attr.Value
			}

			for _, attrName := range tc.expectedAttrs {
				_, ok := attrMap[attrName]
				assert.True(t, ok, "Expected attribute %s not found in result", attrName)
			}

			for _, attrName := range tc.unexpectedAttrs {
				_, ok := attrMap[attrName]
				assert.False(t, ok, "Unexpected attribute %s found in result", attrName)
			}
		})
	}
}

func TestResourceAttrsFromEnv(t *testing.T) {
	tests := []struct {
		name          string
		resourceAttrs string
		envVars       map[string]string
		expectedAttrs map[string]string
	}{
		{
			name:          "Simple key-value pairs without variables",
			resourceAttrs: "service.name=test-service,service.version=1.0.0",
			envVars:       map[string]string{},
			expectedAttrs: map[string]string{
				"service.name":    "test-service",
				"service.version": "1.0.0",
			},
		},
		{
			name:          "Environment variables with ${VAR} syntax",
			resourceAttrs: "k8s.pod.name=${POD_NAME},k8s.node.name=${NODE_NAME}",
			envVars: map[string]string{
				"POD_NAME":  "test-pod-123",
				"NODE_NAME": "test-node-456",
			},
			expectedAttrs: map[string]string{
				"k8s.pod.name":  "test-pod-123",
				"k8s.node.name": "test-node-456",
			},
		},
		{
			name:          "Environment variables with $(VAR) syntax",
			resourceAttrs: "k8s.pod.name=$(OTEL_RESOURCE_ATTRIBUTES_POD_NAME),k8s.node.name=$(OTEL_RESOURCE_ATTRIBUTES_NODE_NAME)",
			envVars: map[string]string{
				"OTEL_RESOURCE_ATTRIBUTES_POD_NAME":  "test-pod-789",
				"OTEL_RESOURCE_ATTRIBUTES_NODE_NAME": "test-node-012",
			},
			expectedAttrs: map[string]string{
				"k8s.pod.name":  "test-pod-789",
				"k8s.node.name": "test-node-012",
			},
		},
		{
			name:          "Mixed syntax with default values",
			resourceAttrs: "k8s.pod.name=$(POD_NAME:-default-pod),k8s.node.name=${NODE_NAME:-default-node}",
			envVars:       map[string]string{},
			expectedAttrs: map[string]string{
				"k8s.pod.name":  "default-pod",
				"k8s.node.name": "default-node",
			},
		},
		{
			name:          "Complex real-world example",
			resourceAttrs: "service.name=my-service,k8s.pod.name=$(OTEL_RESOURCE_ATTRIBUTES_POD_NAME),k8s.node.name=$(OTEL_RESOURCE_ATTRIBUTES_NODE_NAME),k8s.namespace.name=${K8S_NAMESPACE:-default}",
			envVars: map[string]string{
				"OTEL_RESOURCE_ATTRIBUTES_POD_NAME":  "web-server-pod-abc123",
				"OTEL_RESOURCE_ATTRIBUTES_NODE_NAME": "worker-node-xyz789",
				"K8S_NAMESPACE":                      "production",
			},
			expectedAttrs: map[string]string{
				"service.name":       "my-service",
				"k8s.pod.name":       "web-server-pod-abc123",
				"k8s.node.name":      "worker-node-xyz789",
				"k8s.namespace.name": "production",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			t.Setenv("OTEL_RESOURCE_ATTRIBUTES", tt.resourceAttrs)

			attrs := ResourceAttrsFromEnv(nil)

			attrMap := make(map[string]string)
			for _, attr := range attrs {
				attrMap[string(attr.Key)] = attr.Value.Emit()
			}

			assert.Len(t, attrMap, len(tt.expectedAttrs), "Number of attributes should match")
			for k, v := range tt.expectedAttrs {
				assert.Equal(t, v, attrMap[k], "Attribute %s should have value %s", k, v)
			}
		})
	}
}
