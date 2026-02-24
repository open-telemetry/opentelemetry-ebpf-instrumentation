// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const timeout = 5 * time.Second

// Helper to return a pointer to an int value for the numeric comparisons
func intPtr(i int) *int {
	return &i
}

func TestAttributeFilter(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"obi.ip":            MatchDefinition{Match: "148.*"},
		"k8s.src.namespace": MatchDefinition{NotMatch: "debug"},
		"k8s.app.version":   MatchDefinition{Match: "*"},
	}, nil, map[string][]attr.Name{
		"k8s_app_meta": {"k8s.app.version"},
	}, ebpf.RecordStringGetters, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(t.Context())

	// records not matching both the ip and src namespace will be dropped
	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "debug",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "128.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "141.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralari",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
	})

	// the whole batch will be dropped (won't go to the out channel)
	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "128.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "141.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralari",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
	})

	// no record will be dropped
	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
	})

	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
	}, filtered)

	filtered = testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.132.1.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "foo",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				OBIIP: "148.133.2.1",
				Metadata: map[attr.Name]string{
					"k8s.src.namespace": "tralar",
					"k8s.app.version":   "v0.0.1",
				},
			},
		},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}
}

func TestAttributeFilter_NumericComparisons(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	// Test multiple numeric comparisons: status code must be in [200, 400) range
	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"http.response.status_code": MatchDefinition{GreaterEquals: intPtr(200), LessThan: intPtr(400)},
	}, nil, map[string][]attr.Name{}, ebpf.RecordStringGetters, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(t.Context())

	// Send batch with mixed status codes
	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "404", // >= 400, should be filtered out
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "199", // < 200, should be filtered out
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "304",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "500", // >= 400, should be filtered out
				},
			},
		},
	})

	// Only records with status_code in [200, 400) should pass
	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "304",
				},
			},
		},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}
}

func TestAttributeFilter_NumericEquality(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"http.response.status_code": MatchDefinition{Equals: intPtr(200)},
	}, nil, map[string][]attr.Name{}, ebpf.RecordStringGetters, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(t.Context())

	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "201",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
	})

	// Only records with status_code == 200 should pass
	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}
}

func TestAttributeFilter_NumericNotEquals(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"http.response.status_code": MatchDefinition{NotEquals: intPtr(500)},
	}, nil, map[string][]attr.Name{}, ebpf.RecordStringGetters, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(t.Context())

	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "500",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "404",
				},
			},
		},
	})

	// Records with status_code != 500 should pass
	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "404",
				},
			},
		},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}
}

func TestAttributeFilter_NumericAndGlob(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"http.response.status_code": MatchDefinition{GreaterEquals: intPtr(200), LessThan: intPtr(300)},
		"http.request.method":       MatchDefinition{Match: "GET"},
	}, nil, map[string][]attr.Name{}, ebpf.RecordStringGetters, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(t.Context())

	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
					attr.HTTPRequestMethod:      "GET",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
					attr.HTTPRequestMethod:      "POST", // Wrong method
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "404", // Wrong status
					attr.HTTPRequestMethod:      "GET",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "201",
					attr.HTTPRequestMethod:      "GET",
				},
			},
		},
	})

	// Only records with status_code in [200, 300) AND method == "GET" should pass
	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200",
					attr.HTTPRequestMethod:      "GET",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "201",
					attr.HTTPRequestMethod:      "GET",
				},
			},
		},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}
}

func TestAttributeFilter_NumericGlobMixed(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))

	// Filter for error responses (>= 400) with write methods (POST, PUT, PATCH)
	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"http.response.status_code": MatchDefinition{GreaterEquals: intPtr(400)},
		"http.request.method":       MatchDefinition{Match: "P*"},
	}, nil, map[string][]attr.Name{}, ebpf.RecordStringGetters, input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(t.Context())

	input.Send([]*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "404",
					attr.HTTPRequestMethod:      "POST",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "500",
					attr.HTTPRequestMethod:      "GET", // Doesn't match P*
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "200", // < 400
					attr.HTTPRequestMethod:      "POST",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "403",
					attr.HTTPRequestMethod:      "PUT",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "422",
					attr.HTTPRequestMethod:      "PATCH",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "401",
					attr.HTTPRequestMethod:      "DELETE", // Doesn't match P*
				},
			},
		},
	})

	// Only records with status_code >= 400 AND method matching "P*" should pass
	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "404",
					attr.HTTPRequestMethod:      "POST",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "403",
					attr.HTTPRequestMethod:      "PUT",
				},
			},
		},
		{
			Attrs: ebpf.RecordAttrs{
				Metadata: map[attr.Name]string{
					attr.HTTPResponseStatusCode: "422",
					attr.HTTPRequestMethod:      "PATCH",
				},
			},
		},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}
}

func TestAttributeFilter_VerificationError(t *testing.T) {
	testCases := []AttributeFamilyConfig{
		// non-existing attribute
		{"super-attribute": MatchDefinition{Match: "foo"}},
		// valid attribute without match definition
		{"obi.ip": MatchDefinition{}},
		// valid attribute with double match definition
		{"obi.ip": MatchDefinition{Match: "foo", NotMatch: "foo"}},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
			output := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10))
			_, err := ByAttribute[*ebpf.Record](tc, nil, map[string][]attr.Name{}, ebpf.RecordStringGetters, input, output)(t.Context())
			assert.Error(t, err)
		})
	}
}

func TestAttributeFilter_SpanMetrics(t *testing.T) {
	// if the attributes are not existing, we should just ignore them
	input := msg.NewQueue[[]*request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]*request.Span](msg.ChannelBufferLen(10))
	filterFunc, err := ByAttribute[*request.Span](AttributeFamilyConfig{
		"client": MatchDefinition{NotMatch: "filtered"},
		"server": MatchDefinition{NotMatch: "filtered"},
	}, nil, map[string][]attr.Name{}, request.SpanPromGetters(request.UnresolvedNames{}), input, output)(t.Context())
	require.NoError(t, err)

	out := output.Subscribe()
	go filterFunc(t.Context())

	// will drop filtered events
	input.Send([]*request.Span{
		{Type: request.EventTypeHTTP, PeerName: "someclient", Host: "filtered"},
		{Type: request.EventTypeHTTPClient, PeerName: "filtered", Host: "someserver"},
		{Type: request.EventTypeHTTPClient, PeerName: "aserver", Host: "aclient"},
	})

	// no record will be dropped
	input.Send([]*request.Span{
		{Type: request.EventTypeHTTP, PeerName: "client", Host: "server"},
		{Type: request.EventTypeHTTPClient, PeerName: "server", Host: "client"},
	})

	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*request.Span{
		{Type: request.EventTypeHTTPClient, PeerName: "aserver", Host: "aclient"},
	}, filtered)

	filtered = testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*request.Span{
		{Type: request.EventTypeHTTP, PeerName: "client", Host: "server"},
		{Type: request.EventTypeHTTPClient, PeerName: "server", Host: "client"},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}
}
