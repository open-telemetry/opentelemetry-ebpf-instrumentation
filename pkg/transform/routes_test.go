// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

func TestUnmatchedWildcard(t *testing.T) {
	for _, tc := range []UnmatchType{"", UnmatchWildcard, "invalid_value"} {
		t.Run(string(tc), func(t *testing.T) {
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			router, err := RoutesProvider(&RoutesConfig{Unmatch: tc, Patterns: []string{"/user/:id"}},
				input, output)(t.Context())
			require.NoError(t, err)
			out := output.Subscribe()
			defer input.Close()
			go router(t.Context())
			input.Send([]request.Span{{Path: "/user/1234"}})
			assert.Equal(t, []request.Span{{
				Path:  "/user/1234",
				Route: "/user/:id",
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/some/path"}})
			assert.Equal(t, []request.Span{{
				Path:  "/some/path",
				Route: "/**",
			}}, testutil.ReadChannel(t, out, testTimeout))
		})
	}
}

func TestUnmatchedPath(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{Unmatch: UnmatchPath, Patterns: []string{"/user/:id"}},
		input, output)(t.Context())
	require.NoError(t, err)
	out := output.Subscribe()
	defer input.Close()
	go router(t.Context())
	input.Send([]request.Span{{Path: "/user/1234"}})
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	input.Send([]request.Span{{Path: "/some/path"}})
	assert.Equal(t, []request.Span{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestUnmatchedEmpty(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{Unmatch: UnmatchUnset, Patterns: []string{"/user/:id"}},
		input, output)(t.Context())
	require.NoError(t, err)
	out := output.Subscribe()
	defer input.Close()
	go router(t.Context())
	input.Send([]request.Span{{Path: "/user/1234"}})
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, testutil.ReadChannel(t, out, testTimeout))
	input.Send([]request.Span{{Path: "/some/path"}})
	assert.Equal(t, []request.Span{{
		Path: "/some/path",
	}}, testutil.ReadChannel(t, out, testTimeout))
}

func TestUnmatchedAuto(t *testing.T) {
	for _, tc := range []UnmatchType{UnmatchHeuristic} {
		t.Run(string(tc), func(t *testing.T) {
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			router, err := RoutesProvider(&RoutesConfig{Unmatch: tc, Patterns: []string{"/user/:id"}, WildcardChar: "*"},
				input, output)(t.Context())
			require.NoError(t, err)
			out := output.Subscribe()
			defer input.Close()
			go router(t.Context())
			input.Send([]request.Span{{Path: "/user/1234"}})
			assert.Equal(t, []request.Span{{
				Path:  "/user/1234",
				Route: "/user/:id",
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/some/path", Type: request.EventTypeHTTP}})
			assert.Equal(t, []request.Span{{
				Path:  "/some/path",
				Route: "/some/path",
				Type:  request.EventTypeHTTP,
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/customer/1/job/2", Type: request.EventTypeHTTP}})
			assert.Equal(t, []request.Span{{
				Path:  "/customer/1/job/2",
				Route: "/customer/*/job/*",
				Type:  request.EventTypeHTTP,
			}}, testutil.ReadChannel(t, out, testTimeout))
			input.Send([]request.Span{{Path: "/customer/lfdsjd/job/erwejre", Type: request.EventTypeHTTPClient}})
			assert.Equal(t, []request.Span{{
				Path:  "/customer/lfdsjd/job/erwejre",
				Route: "/customer/*/job/*",
				Type:  request.EventTypeHTTPClient,
			}}, testutil.ReadChannel(t, out, testTimeout))
		})
	}
}

func TestUnmatchedAutoLowCardinality(t *testing.T) {
	trie := clusterurl.NewPathTrie(3, '*')
	for _, tc := range []UnmatchType{UnmatchLowCardinality} {
		t.Run(string(tc), func(t *testing.T) {
			input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			router, err := RoutesProvider(&RoutesConfig{Unmatch: tc, WildcardChar: "*"},
				input, output)(t.Context())
			require.NoError(t, err)
			out := output.Subscribe()
			defer input.Close()
			go router(t.Context())
			input.Send([]request.Span{{Path: "/v1/user/1234", Type: request.EventTypeHTTP, Service: svc.Attrs{PathTrie: trie}}})
			s := testutil.ReadChannel(t, out, testTimeout)
			// Heuristic only detects the last component as an ID, 1234 -> *
			assert.Equal(t, "/v1/user/1234", s[0].Path)
			assert.Equal(t, "/v1/user/*", s[0].Route)
			input.Send([]request.Span{{Path: "/v2/user/1234", Type: request.EventTypeHTTP, Service: svc.Attrs{PathTrie: trie}}})
			// Heuristic only detects the last component as an ID, 1234 -> *
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v2/user/1234", s[0].Path)
			assert.Equal(t, "/v2/user/*", s[0].Route)
			input.Send([]request.Span{{Path: "/v3/user/1234", Type: request.EventTypeHTTP, Service: svc.Attrs{PathTrie: trie}}})
			// Heuristic only detects the last component as an ID, 1234 -> *
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v3/user/1234", s[0].Path)
			assert.Equal(t, "/v3/user/*", s[0].Route)
			input.Send([]request.Span{{Path: "/v4/user/1234", Type: request.EventTypeHTTPClient, Service: svc.Attrs{PathTrie: trie}}})
			// We finally blow the cardinality of the first path segment, v4 -> *
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v4/user/1234", s[0].Path)
			assert.Equal(t, "/*/user/*", s[0].Route)
			input.Send([]request.Span{{Path: "/v1/user/1234", Type: request.EventTypeHTTPClient, Service: svc.Attrs{PathTrie: trie}}})
			// From now on, even previously matched routes are collapsed
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v1/user/1234", s[0].Path)
			assert.Equal(t, "/*/user/*", s[0].Route)
			// let's blow cardinality of the second path component, "user"
			input.Send([]request.Span{{Path: "/v1/user-one/1234", Type: request.EventTypeHTTPClient, Service: svc.Attrs{PathTrie: trie}}})
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v1/user-one/1234", s[0].Path)
			assert.Equal(t, "/*/user-one/*", s[0].Route)
			input.Send([]request.Span{{Path: "/v1/user-two/1234", Type: request.EventTypeHTTPClient, Service: svc.Attrs{PathTrie: trie}}})
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v1/user-two/1234", s[0].Path)
			assert.Equal(t, "/*/user-two/*", s[0].Route)
			input.Send([]request.Span{{Path: "/v1/user-three/1234", Type: request.EventTypeHTTPClient, Service: svc.Attrs{PathTrie: trie}}})
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v1/user-three/1234", s[0].Path)
			assert.Equal(t, "/*/*/*", s[0].Route)
			input.Send([]request.Span{{Path: "/v1/user/1234", Type: request.EventTypeHTTPClient, Service: svc.Attrs{PathTrie: trie}}})
			// From now on, even previously matched routes are collapsed
			s = testutil.ReadChannel(t, out, testTimeout)
			assert.Equal(t, "/v1/user/1234", s[0].Path)
			assert.Equal(t, "/*/*/*", s[0].Route)
		})
	}
}

func TestIgnoreRoutes(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{
		Unmatch: UnmatchPath, Patterns: []string{"/user/:id", "/v1/metrics"},
		IgnorePatterns: []string{"/v1/metrics/*", "/v1/traces/*", "/exact"},
	}, input, output)(t.Context())
	require.NoError(t, err)
	out := output.Subscribe()
	defer input.Close()
	go router(t.Context())
	input.Send([]request.Span{{Path: "/user/1234"}})
	input.Send([]request.Span{{Path: "/v1/metrics"}}) // this is in routes and ignore, ignore takes precedence
	input.Send([]request.Span{{Path: "/v1/traces/1234/test"}})
	input.Send([]request.Span{{Path: "/v1/metrics/1234/test"}}) // this is in routes and ignore, ignore takes precedence
	input.Send([]request.Span{{Path: "/v1/traces"}})
	input.Send([]request.Span{{Path: "/exact"}})
	input.Send([]request.Span{{Path: "/some/path"}})
	assert.Equal(t, []request.Span{{
		Path:  "/user/1234",
		Route: "/user/:id",
	}}, filterIgnored(func() []request.Span { return testutil.ReadChannel(t, out, testTimeout) }))
	assert.Equal(t, []request.Span{{
		Path:  "/some/path",
		Route: "/some/path",
	}}, filterIgnored(func() []request.Span { return testutil.ReadChannel(t, out, testTimeout) }))
}

func TestIgnoreMode(t *testing.T) {
	s := request.Span{Path: "/user/1234"}
	setSpanIgnoreMode(IgnoreTraces, &s)
	assert.True(t, request.IgnoreTraces(&s))
	setSpanIgnoreMode(IgnoreMetrics, &s)
	assert.True(t, request.IgnoreMetrics(&s))
}

func BenchmarkRoutesProvider_Wildcard(b *testing.B) {
	benchProvider(b, UnmatchWildcard)
}

func BenchmarkRoutesProvider_Heuristic(b *testing.B) {
	benchProvider(b, UnmatchHeuristic)
}

func benchProvider(b *testing.B, unmatch UnmatchType) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	router, err := RoutesProvider(&RoutesConfig{Unmatch: unmatch, Patterns: []string{
		"/users/{id}",
		"/users/{id}/product/{pid}",
	}}, input, output)(b.Context())
	if err != nil {
		b.Fatal(err)
	}
	inCh, outCh := make(chan []request.Span, 10), make(chan []request.Span, 10)
	// 40% of unmatched routes
	benchmarkInput := []request.Span{
		{Type: request.EventTypeHTTP, Path: "/users/123"},
		{Type: request.EventTypeHTTP, Path: "/users/123/product/456"},
		{Type: request.EventTypeHTTP, Path: "/users"},
		{Type: request.EventTypeHTTP, Path: "/products/34322"},
		{Type: request.EventTypeHTTP, Path: "/users/123/delete"},
	}
	go router(b.Context())
	for b.Loop() {
		inCh <- benchmarkInput
		<-outCh
	}
}

func filterIgnored(reader func() []request.Span) []request.Span {
	for {
		input := reader()
		output := make([]request.Span, 0, len(input))
		for i := range input {
			s := &input[i]

			if request.IgnoreMetrics(s) {
				continue
			}

			if request.IgnoreTraces(s) {
				continue
			}

			output = append(output, *s)
		}

		if len(output) > 0 {
			return output
		}
	}
}
