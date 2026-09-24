// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFind(t *testing.T) {
	m := NewMatcher([]string{
		"/foo/bar/bae/",
		"/foo/:id",
		"/foo/{id}/push",
		"/ski/*",
		"/snow/mobile/*",
		"/",
	})

	assert.Equal(t, "/", m.Find("/"))
	assert.Equal(t, "/foo/bar/bae/", m.Find("/foo/bar/bae"))
	assert.Equal(t, "/foo/:id", m.Find("/foo/1234"))
	assert.Equal(t, "/foo/:id", m.Find("/foo/someId"))
	assert.Equal(t, "/foo/{id}/push", m.Find("/foo/5678/push"))

	assert.Empty(t, m.Find("/foo"))
	assert.Empty(t, m.Find("/foo/bar"))
	assert.Empty(t, m.Find("/foo/bar/bae/baz"))
	assert.Empty(t, m.Find("/traca"))
	assert.Empty(t, m.Find("/foo/1234/down"))
	assert.Empty(t, m.Find("/foo/5678/push/up"))

	assert.Equal(t, "/ski/*", m.Find("/ski"))
	assert.Equal(t, "/ski/*", m.Find("/ski/doo"))
	assert.Equal(t, "/ski/*", m.Find("/ski/doo/new/"))

	assert.Empty(t, m.Find("/snow/man"))
	assert.Equal(t, "/snow/mobile/*", m.Find("/snow/mobile"))
	assert.Equal(t, "/snow/mobile/*", m.Find("/snow/mobile/long"))
}

func TestFindPartialSegmentWildcard(t *testing.T) {
	m := NewMatcher([]string{
		"/@:username/lists/:id",
		"/@:username/followers",
	})

	// the motivating case: prefix before a colon placeholder
	assert.Equal(t, "/@:username/lists/:id", m.Find("/@gouthamve/lists/my-list"))
	assert.Equal(t, "/@:username/lists/:id", m.Find("/@alice/lists/42"))
	assert.Equal(t, "/@:username/followers", m.Find("/@bob/followers"))

	// the literal prefix is still required, and the placeholder needs at least one char
	assert.Empty(t, m.Find("/gouthamve/lists/my-list"))
	assert.Empty(t, m.Find("/@/followers"))
}

// TestFindPatternsInDefinitionOrder documents that patterns sharing a path
// position are evaluated in definition order: it is up to the user to declare the
// more specific pattern before a catch-all that would otherwise shadow it.
func TestFindPatternsInDefinitionOrder(t *testing.T) {
	// specific pattern declared first: it takes precedence over the catch-all
	specificFirst := NewMatcher([]string{
		"/@:username/profile",
		"/:section/profile",
	})
	assert.Equal(t, "/@:username/profile", specificFirst.Find("/@carol/profile"))
	assert.Equal(t, "/:section/profile", specificFirst.Find("/settings/profile"))

	// catch-all declared first: it shadows the more specific pattern that follows
	catchAllFirst := NewMatcher([]string{
		"/:section/profile",
		"/@:username/profile",
	})
	assert.Equal(t, "/:section/profile", catchAllFirst.Find("/@carol/profile"))
}

func TestFindPatternFallsBackToAnyPath(t *testing.T) {
	m := NewMatcher([]string{
		"/admin/*",
		"/admin/:id/settings",
	})

	assert.Equal(t, "/admin/*", m.Find("/admin"))
	assert.Equal(t, "/admin/*", m.Find("/admin/token"))
	assert.Equal(t, "/admin/:id/settings", m.Find("/admin/token/settings"))
}

func TestFindExactChildFallsBackToAnyPath(t *testing.T) {
	const (
		exact    = "/files/static"
		suffixed = "/files/<path:name>/metadata"
	)
	m := NewMatcher([]string{exact, suffixed})

	assert.Equal(t, exact, m.Find("/files/static"))
	assert.Equal(t, suffixed, m.Find("/files/static/x/metadata"))
}

func TestFindDotnetParameters(t *testing.T) {
	m := NewMatcher([]string{
		"/customers/{id:int}",
		"/orders/{id:int:min(1)}",
		"/archive/{id?}",
		"/{controller=Home}",
		"/files/{**path}",
	})

	assert.Equal(t, "/customers/{id:int}", m.Find("/customers/42"))
	assert.Equal(t, "/orders/{id:int:min(1)}", m.Find("/orders/7"))
	assert.Equal(t, "/archive/{id?}", m.Find("/archive/2026"))
	assert.Equal(t, "/{controller=Home}", m.Find("/Products"))
	assert.Equal(t, "/files/{**path}", m.Find("/files/a/b/c"))
}

func TestFindSymfonyInlineConstraint(t *testing.T) {
	m := NewMatcher([]string{
		"/orders/{id<\\d+>}",
		// A regex quantifier, e.g. {4}, must not be mistaken for the outer
		// "{...}" placeholder delimiters and reject the whole segment.
		"/years/{year<\\d{4}>}",
	})

	assert.Equal(t, "/orders/{id<\\d+>}", m.Find("/orders/42"))
	assert.Equal(t, "/years/{year<\\d{4}>}", m.Find("/years/2026"))
	assert.Empty(t, m.Find("/orders/42/history"))
}

func TestFindNonTerminalPathParam(t *testing.T) {
	const route = "/files/<path:name>/metadata"
	m := NewMatcher([]string{route})

	for _, tt := range []struct {
		name string
		path string
		want string
	}{
		{name: "one segment", path: "/files/a/metadata", want: route},
		{name: "multiple segments", path: "/files/a/b/metadata", want: route},
		{name: "repeated suffix", path: "/files/a/metadata/b/metadata", want: route},
		{name: "missing suffix", path: "/files/a/b"},
		{name: "wrong suffix", path: "/files/a/b/details"},
		{name: "extra segment after suffix", path: "/files/a/metadata/extra"},
		{name: "empty parameter", path: "/files/metadata"},
		{name: "bare prefix", path: "/files"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, m.Find(tt.path))
		})
	}
}

func TestFindCatchAllCoexistence(t *testing.T) {
	const (
		exact    = "/files"
		catchAll = "/files/<path:name>"
		suffixed = "/files/<path:name>/metadata"
	)

	for _, tt := range []struct {
		name   string
		routes []string
	}{
		{name: "catch-all first", routes: []string{catchAll, suffixed, exact}},
		{name: "catch-all last", routes: []string{exact, suffixed, catchAll}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMatcher(tt.routes)
			assert.Equal(t, exact, m.Find("/files"))
			assert.Equal(t, suffixed, m.Find("/files/a/metadata"))
			assert.Equal(t, suffixed, m.Find("/files/a/b/metadata"))
			assert.Equal(t, catchAll, m.Find("/files/a"))
			assert.Equal(t, catchAll, m.Find("/files/a/b/details"))
			assert.Equal(t, catchAll, m.Find("/files/metadata"))
		})
	}
}
