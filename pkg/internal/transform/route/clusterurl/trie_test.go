// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clusterurl

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathTrie_BasicInsertAndLookup(t *testing.T) {
	trie := NewPathTrie(2)

	// Insert first path
	result := trie.Insert("test/bar-attach-generic-product-apjkmyp/files/multi-test-version-jwbCm/test")
	assert.Equal(t, "/test/bar-attach-generic-product-apjkmyp/files/multi-test-version-jwbCm/test", result)

	// Insert second path with different second segment
	result = trie.Insert("test/apjkmyp/files/jwbCm/test")
	assert.Equal(t, "/test/apjkmyp/files/jwbCm/test", result)

	// Insert third path - should trigger collapse at second segment (cardinality > 2)
	result = trie.Insert("test/xyz/files/abc/test")
	assert.Equal(t, "/test/*/files/*/test", result)

	// Lookup should now return collapsed path
	result = trie.Lookup("test/anything-new/files/something/test")
	assert.Equal(t, "/test/*/files/*/test", result)
}

func TestPathTrie_CardinalityThreshold(t *testing.T) {
	trie := NewPathTrie(3)

	// Add paths up to threshold
	assert.Equal(t, "/api/v1/users", trie.Insert("api/v1/users"))
	assert.Equal(t, "/api/v2/users", trie.Insert("api/v2/users"))
	assert.Equal(t, "/api/v3/users", trie.Insert("api/v3/users"))

	// Next insert should trigger collapse
	assert.Equal(t, "/api/*/users", trie.Insert("api/v4/users"))

	// Verify lookup uses collapsed path
	assert.Equal(t, "/api/*/users", trie.Lookup("api/v999/users"))
}

func TestPathTrie_CardinalitySecondaryThreshold(t *testing.T) {
	trie := NewPathTrie(3)

	// Add paths up to threshold
	assert.Equal(t, "/api/v1/items/teddy_bear", trie.Insert("api/v1/items/teddy_bear"))
	assert.Equal(t, "/api/v1/items/sports_car", trie.Insert("api/v1/items/sports_car"))
	assert.Equal(t, "/api/v1/items/t-shirt", trie.Insert("api/v1/items/t-shirt"))

	assert.Equal(t, "/api/v1/items/t-shirt", trie.Lookup("api/v1/items/t-shirt"))

	// Add paths up to threshold
	assert.Equal(t, "/api/v1/customers", trie.Insert("api/v1/customers"))
	assert.Equal(t, "/api/v1/admin", trie.Insert("api/v1/admin"))

	// Next insert should trigger collapse
	assert.Equal(t, "/api/v1/*", trie.Insert("api/v1/users"))

	// Let's trigger the secondary collapse now
	assert.Equal(t, "/api/v2/items", trie.Insert("api/v2/items"))
	assert.Equal(t, "/api/v3/items", trie.Insert("api/v3/items"))

	assert.Equal(t, "/api/*/items", trie.Insert("api/v4/items"))
	for i := range 3 {
		trie.Insert("api/v4/items" + strconv.Itoa(i))
	}
	assert.Equal(t, "/api/*/*", trie.Lookup("api/v4/items"))
	assert.Equal(t, "/api/*/*/t-shirt", trie.Lookup("api/v4/items/t-shirt"))

	// trigger the third level collapse
	assert.Equal(t, "/api/*/*/*", trie.Insert("api/v1/customers/list"))

	assert.Equal(t, "/api/*/*/*", trie.Lookup("api/v4/items/t-shirt"))
}

func TestPathTrie_CascadingCollapse(t *testing.T) {
	trie := NewPathTrie(2)

	// Build tree: /root/child1/grandchild1
	//             /root/child1/grandchild2
	//             /root/child2/grandchild3
	trie.Insert("root/child1/grandchild1")
	trie.Insert("root/child1/grandchild2")
	trie.Insert("root/child2/grandchild3")

	// This should trigger collapse at "child" level
	// which should cascade to grandchildren
	result := trie.Insert("root/child3/grandchild4")

	// After collapse, all should be wildcards
	assert.Equal(t, "/root/*/*", result)
}

func TestPathTrie_EmptyPath(t *testing.T) {
	trie := NewPathTrie(2)

	assert.Empty(t, trie.Insert(""))
	assert.Empty(t, trie.Lookup(""))
}

func TestPathTrie_SingleSegment(t *testing.T) {
	trie := NewPathTrie(2)

	result := trie.Insert("test")
	assert.Equal(t, "/test", result)

	result = trie.Lookup("test")
	assert.Equal(t, "/test", result)
}

func TestPathTrie_PreserveExistingPaths(t *testing.T) {
	trie := NewPathTrie(2)

	// Insert paths
	trie.Insert("api/users/123")
	trie.Insert("api/users/456")

	// Before collapse, lookups should return exact matches
	assert.Equal(t, "/api/users/123", trie.Lookup("api/users/123"))
	assert.Equal(t, "/api/users/456", trie.Lookup("api/users/456"))

	// Trigger collapse
	trie.Insert("api/users/789")

	// After collapse, all should use wildcard
	assert.Equal(t, "/api/users/*", trie.Lookup("api/users/123"))
	assert.Equal(t, "/api/users/*", trie.Lookup("api/users/999"))
}

func TestPathTrie_ComplexPaths(t *testing.T) {
	trie := NewPathTrie(3)

	paths := []string{
		"bar/test/test/bar-attach-generic-product-apjkmyp/files/multi-test-version-jwbCm/test",
		"bar/test/test/bar-attach-generic-registry-apjkmyp/files/push-metrics-test-OYboK/test",
		"bar/test/test/another-product-xyz/files/version-abc/test",
	}

	for _, path := range paths {
		trie.Insert(path)
	}

	// Should not collapse yet (cardinality = 3, threshold = 3)
	result := trie.Lookup(paths[0])
	assert.Contains(t, result, "bar-attach-generic-product-apjkmyp")

	// Fourth path should trigger collapse
	trie.Insert("bar/test/test/fourth-product/files/version-def/test")

	result = trie.Lookup("bar/test/test/any-product/files/any-version/test")
	assert.Equal(t, "/bar/test/test/*/files/*/test", result)
}

func BenchmarkPathTrie_Insert(b *testing.B) {
	trie := NewPathTrie(10)

	paths := []string{
		"/users/fdklsd/j4elk/23993/job/2",
		"/v1/products/22",
		"/products/1/org/3",
		"/attach?session_id=ddfsdsf&track_id=sjdklnfldsn",
		"GET /user_space/",
		"/api/hello.world",
		"123/ljgdflgjf",
		"",
	}

	for b.Loop() {
		for i := 0; i < len(paths); i++ {
			trie.Insert(paths[i])
		}
	}
}

func BenchmarkPathTrie_Lookup(b *testing.B) {
	trie := NewPathTrie(10)

	// Pre-populate trie
	for i := 0; i < 100; i++ {
		trie.Insert("api/v1/users/" + strconv.Itoa(i) + "/posts/456")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.Lookup("api/v1/users/999/posts/888")
	}
}
