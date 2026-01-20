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
				Include: []string{"url.path"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"url.path",
	}, p.For(HTTPServerDuration))
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
		"service.name",
		"service.namespace",
		"k8s.app.version",
	}, p.For(HTTPServerRequestSize))
}

func TestTraces(t *testing.T) {
	p, err := NewAttrSelector(GroupTraces, &SelectorConfig{
		SelectionCfg: Selection{
			"traces": InclusionLists{
				Include: []string{"db.query.text", "obi.ip", "src.*", "k8s.*"},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{
		"db.query.text",
	}, p.For(Traces))
}
