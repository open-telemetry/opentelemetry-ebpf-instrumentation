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
