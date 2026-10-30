// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestNormalize(t *testing.T) {
	incl := Selection{
		"obi_network_flow_bytes": InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric_sum":  InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara.total":  InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}
	incl.Normalize()
	assert.Equal(t, Selection{
		"obi.network.flow":  InclusionLists{Include: []string{"foo", "bar"}},
		"some.other.metric": InclusionLists{Include: []string{"attr", "other"}},
		"tralari.tralara":   InclusionLists{Include: []string{"a1", "a2", "a3"}},
	}, incl)
}

func TestFor(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{
		SelectionCfg: Selection{
			"obi.network.flow": InclusionLists{
				Include: []string{"obi.ip", "src.*", "k8s.*"},
				Exclude: []string{"k8s.*.name", "k8s.*.type", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"obi.ip",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(NetworkFlow))
}

func TestFor_GlobEntries(t *testing.T) {
	// include all groups just to verify that other attributes aren't anyway selected
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{
				Include: []string{"obi.ip"},
				// won't be excluded from the final snapshot because they are
				// re-included in the next inclusion list
				Exclude: []string{"k8s.*.type"},
			},
			"obi.network.flow": InclusionLists{
				Include: []string{"src.*", "k8s.*"},
				Exclude: []string{"k8s.*.name", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"k8s.dst.namespace",
		"k8s.dst.node.ip",
		"k8s.dst.owner.type",
		"k8s.dst.type",
		"k8s.src.namespace",
		"k8s.src.node.ip",
		"k8s.src.owner.type",
		"k8s.src.type",
		"obi.ip",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(NetworkFlow))
}

// if no include lists are defined, it takes the default arguments
func TestFor_GlobEntries_NoInclusion(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes|GroupNetCIDR, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{
				Exclude: []string{"*dst*"},
			},
			"obi.network.flow": InclusionLists{
				Exclude: []string{"k8s.*.namespace", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"direction",
		"k8s.cluster.name",
		"k8s.src.owner.name",
		"k8s.src.owner.type",
		"src.cidr",
	}, p.For(NetworkFlow))
}

func TestFor_GlobEntries_Order(t *testing.T) {
	// verify that policies are overridden from more generic to more concrete
	p, err := NewAttrSelector(0, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{
				Include: []string{"*"},
			},
			"obi.network.*": InclusionLists{
				Exclude: []string{"dst.*", "transport", "*direction", "iface", "*zone"},
			},
			"obi.network.flow": InclusionLists{
				Include: []string{"dst.name"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"client.port",
		"dst.name",
		"network.protocol.name",
		"network.type",
		"obi.ip",
		"server.port",
		"src.address",
		"src.name",
		"src.port",
	}, p.For(NetworkFlow))
}

func TestFor_GlobEntries_Order_Default(t *testing.T) {
	// verify that policies are overridden from more generic to more concrete
	var g AttrGroups
	g.Add(GroupAppKube)
	g.Add(GroupKubernetes)
	p, err := NewAttrSelector(g, &SelectorConfig{
		SelectionCfg: Selection{
			"*": InclusionLists{}, // assuming default set
			"http.*": InclusionLists{
				Exclude: []string{"*"},
			},
			"http.server.request.duration": InclusionLists{
				Include: []string{"server.port"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"server.port",
	}, p.For(HTTPServerDuration))
}

func TestFor_HTTPRouteAttributesByDirection(t *testing.T) {
	serverMetrics := []Name{HTTPServerDuration, HTTPServerRequestSize, HTTPServerResponseSize}
	clientMetrics := []Name{HTTPClientDuration, HTTPClientRequestSize, HTTPClientResponseSize}

	p, err := NewAttrSelector(GroupHTTPRoutes, &SelectorConfig{})
	require.NoError(t, err)
	for _, metric := range serverMetrics {
		assert.Contains(t, p.For(metric), attr.HTTPRoute, metric.Section)
		assert.NotContains(t, p.For(metric), attr.HTTPUrlTemplate, metric.Section)
	}
	for _, metric := range clientMetrics {
		assert.NotContains(t, p.For(metric), attr.HTTPRoute, metric.Section)
	}
	// semconv makes url.template opt-in on the stable duration metric and
	// conditionally required on the development body-size metrics
	assert.NotContains(t, p.For(HTTPClientDuration), attr.HTTPUrlTemplate)
	assert.Contains(t, p.For(HTTPClientRequestSize), attr.HTTPUrlTemplate)
	assert.Contains(t, p.For(HTTPClientResponseSize), attr.HTTPUrlTemplate)

	p, err = NewAttrSelector(GroupHTTPRoutes, &SelectorConfig{SelectionCfg: Selection{
		HTTPClientDuration.Section: InclusionLists{Include: []string{"url.template"}},
	}})
	require.NoError(t, err)
	assert.Contains(t, p.For(HTTPClientDuration), attr.HTTPUrlTemplate, "url.template can be opted into on the client duration")

	p, err = NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	for _, metric := range append(serverMetrics, clientMetrics...) {
		assert.NotContains(t, p.For(metric), attr.HTTPRoute, metric.Section)
		assert.NotContains(t, p.For(metric), attr.HTTPUrlTemplate, metric.Section)
	}
}

func TestFor_RemovedHTTPMetricAttributes(t *testing.T) {
	p, err := NewAttrSelector(GroupHTTPRoutes, &SelectorConfig{
		SelectionCfg: Selection{"*": InclusionLists{Include: []string{"*"}}},
	})
	require.NoError(t, err)
	for _, metric := range []Name{
		HTTPServerDuration, HTTPServerRequestSize, HTTPServerResponseSize,
		HTTPClientDuration, HTTPClientRequestSize, HTTPClientResponseSize,
		RPCServerDuration,
	} {
		assert.NotContains(t, p.For(metric), attr.HTTPUrlPath, metric.Section)
		assert.NotContains(t, p.For(metric), attr.ClientAddr, metric.Section)
	}
	assert.Contains(t, p.For(DBServerDuration), attr.ClientAddr)
}

func TestFor_KubeDisabled(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{
		SelectionCfg: Selection{
			"obi.network.flow": InclusionLists{
				Include: []string{"target.instance", "obi.ip", "src.*", "k8s.*"},
				Exclude: []string{"src.port", "*zone"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"obi.ip",
		"src.address",
		"src.name",
	}, p.For(NetworkFlow))
}

func TestFor_NotNormalizedSection(t *testing.T) {
	for _, key := range []Section{
		DotnetProcessMemoryWorkingSet.Section,
		Section(DotnetProcessMemoryWorkingSet.Prom),
	} {
		selection := Selection{
			key: InclusionLists{Include: []string{"k8s.namespace.name"}},
		}
		selection.Normalize()
		p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{SelectionCfg: selection})
		require.NoError(t, err)
		assert.Equal(t, []attr.Name{"k8s.namespace.name"}, p.For(DotnetProcessMemoryWorkingSet), "key %q", key)
	}
}

func TestFor_NotNormalizedSection_ExactOverridesGlob(t *testing.T) {
	selection := Selection{
		"jvm.thread.*":     InclusionLists{Exclude: []string{"*"}},
		"jvm.thread.count": InclusionLists{Include: []string{"jvm.thread.daemon"}},
	}
	selection.Normalize()
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{SelectionCfg: selection})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{"jvm.thread.daemon"}, p.For(JVMThreadCount))

	selection = Selection{
		"jvm.thread.*":     InclusionLists{Include: []string{"*"}},
		"jvm.thread.count": InclusionLists{Exclude: []string{"jvm.thread.daemon"}},
	}
	selection.Normalize()
	p, err = NewAttrSelector(GroupKubernetes, &SelectorConfig{SelectionCfg: selection})
	require.NoError(t, err)
	assert.NotContains(t, p.For(JVMThreadCount), attr.Name("jvm.thread.daemon"))
}

func TestNilDoesNotCrash(t *testing.T) {
	assert.NotPanics(t, func() {
		p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
		require.NoError(t, err)
		assert.NotEmpty(t, p.For(NetworkFlow))
	})
}

func TestDefault(t *testing.T) {
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"direction",
		"k8s.cluster.name",
		"k8s.dst.namespace",
		"k8s.dst.owner.name",
		"k8s.dst.owner.type",
		"k8s.src.namespace",
		"k8s.src.owner.name",
		"k8s.src.owner.type",
	}, p.For(NetworkFlow))
	// the packets metric shares the same attribute groups as the bytes metric
	assert.Equal(t, p.For(NetworkFlow), p.For(NetworkFlowPackets))
}

func TestDefault_DBClientDuration(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		attr.DBCollectionName,
		attr.DBNamespace,
		attr.DBOperation,
		attr.DBResponseStatusCode,
		attr.DBSystemName,
		attr.ErrorType,
		attr.ServerAddr,
		attr.ServerPort,
	}, p.For(DBClientDuration))
}

func TestDefault_DBServerDuration(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		attr.DBCollectionName,
		attr.DBNamespace,
		attr.DBOperation,
		attr.DBResponseStatusCode,
		attr.DBSystemName,
		attr.ErrorType,
		attr.ServerAddr,
		attr.ServerPort,
	}, p.For(DBServerDuration))
}

func TestDefault_RPCClientDuration(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		attr.ErrorType,
		attr.RPCMethod,
		attr.RPCResponseStatusCode,
		attr.RPCSystem,
		attr.ServerAddr,
		attr.ServerPort,
	}, p.For(RPCClientDuration))
}

func TestDefault_RPCServerDuration(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		attr.ErrorType,
		attr.RPCMethod,
		attr.RPCResponseStatusCode,
		attr.RPCSystem,
		attr.ServerAddr,
		attr.ServerPort,
	}, p.For(RPCServerDuration))
}

// semconv declares messaging.operation.type on messaging.client.operation.duration
// only: messaging.process.duration always describes a process operation.
func TestDefault_MessagingOperationType(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Contains(t, p.For(MessagingPublishDuration), attr.MessagingOpType)
	assert.NotContains(t, p.For(MessagingProcessDuration), attr.MessagingOpType)
}

func TestDefault_MessagingSubscription(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Contains(t, p.For(MessagingPublishDuration), attr.MessagingSubscription)
	assert.Contains(t, p.For(MessagingProcessDuration), attr.MessagingSubscription)
}

func TestDefault_HTTPServerMetrics(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	for _, def := range []Name{HTTPServerDuration, HTTPServerRequestSize, HTTPServerResponseSize} {
		assert.Equal(t, []attr.Name{
			attr.ErrorType,
			attr.HTTPRequestMethod,
			attr.HTTPResponseStatusCode,
			attr.ServerAddr,
			attr.ServerPort,
			attr.HTTPURLScheme,
		}, p.For(def), def.Section)
	}
}

func TestDefault_HTTPClientMetrics(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	for _, def := range []Name{HTTPClientDuration, HTTPClientRequestSize, HTTPClientResponseSize} {
		assert.Equal(t, []attr.Name{
			attr.ErrorType,
			attr.HTTPRequestMethod,
			attr.HTTPResponseStatusCode,
			attr.ServerAddr,
			attr.ServerPort,
			attr.HTTPURLScheme,
		}, p.For(def), def.Section)
	}
}

func TestExplicitlyIncluded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selection Selection
		expected  bool
	}{
		{name: "no user selection", selection: nil, expected: false},
		{name: "selection for another metric", selection: Selection{
			"http.client.request.duration": InclusionLists{Include: []string{"server.port"}},
		}, expected: false},
		{name: "exact name", selection: Selection{
			"db.client.operation.duration": InclusionLists{Include: []string{"server.port"}},
		}, expected: true},
		{name: "prom-style name", selection: Selection{
			"db_client_operation_duration": InclusionLists{Include: []string{"server_port"}},
		}, expected: true},
		{name: "attribute glob", selection: Selection{
			"db.client.operation.duration": InclusionLists{Include: []string{"server.*"}},
		}, expected: true},
		{name: "metric and attribute globs", selection: Selection{
			"*": InclusionLists{Include: []string{"*"}},
		}, expected: true},
		{name: "unrelated include", selection: Selection{
			"db.client.operation.duration": InclusionLists{Include: []string{"db.collection.name"}},
		}, expected: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.selection.Normalize()
			p, err := NewAttrSelector(0, &SelectorConfig{SelectionCfg: tc.selection})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, p.ExplicitlyIncluded(DBClientDuration, attr.ServerPort))
		})
	}
}

func TestDefaultSensitiveQueryParamsIncludesLegacyAWSSignedURLKeys(t *testing.T) {
	assert.Contains(t, DefaultSensitiveQueryParams, "AWSAccessKeyId")
	assert.Contains(t, DefaultSensitiveQueryParams, "Signature")
	assert.Contains(t, DefaultSensitiveQueryParams, "SecurityToken")
}

func TestExtraGroupAttributes(t *testing.T) {
	var g AttrGroups
	g.Add(GroupKubernetes)
	g.Add(GroupAppKube)
	p, err := NewAttrSelector(g, &SelectorConfig{
		ExtraGroupAttributesCfg: map[string][]attr.Name{
			"k8s_app_meta": {"k8s.app.version"},
			"test":         {"test"},
		},
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []attr.Name{
		"error.type",
		"http.request.method",
		"http.response.status_code",
		"k8s.cluster.name",
		"k8s.container.name",
		"k8s.daemonset.name",
		"k8s.deployment.name",
		"k8s.job.name",
		"k8s.cronjob.name",
		"k8s.kind",
		"k8s.namespace.name",
		"k8s.node.name",
		"k8s.owner.name",
		"k8s.pod.name",
		"k8s.pod.start_time",
		"k8s.pod.uid",
		"k8s.replicaset.name",
		"k8s.statefulset.name",
		"server.address",
		"server.port",
		"url.scheme",
		"k8s.app.version",
	}, p.For(HTTPServerRequestSize))
}

func TestTraces(t *testing.T) {
	p, err := NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{"db.query.text", "db.response.error", "obi.ip", "src.*", "k8s.*"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"db.query.text",
		"db.response.error",
	}, p.For(Traces))
}

func TestTracesGenAIToolCallAttributes(t *testing.T) {
	p, err := NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{"gen_ai.tool.call.*"},
			},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, p.For(Traces))

	p, err = NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{
					"gen_ai.tool.call.arguments",
					"gen_ai.tool.call.result",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"gen_ai.tool.call.arguments",
		"gen_ai.tool.call.result",
	}, p.For(Traces))

	p, err = NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{"gen_ai.*"},
				Exclude: []string{"gen_ai.input.messages", "gen_ai.output.messages"},
			},
		},
	})
	require.NoError(t, err)
	assert.NotContains(t, p.For(Traces), attr.GenAIToolCallArguments)
	assert.NotContains(t, p.For(Traces), attr.GenAIToolCallResult)
}
