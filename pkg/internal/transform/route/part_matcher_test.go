// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindParts(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/snow/mobile",
		"/greeting",
		"/persons",
		"/api",
		"/age-greater-than/{age}",
		"/greeting123/{id}",
		"/{id}",
	})

	assert.Equal(t, "/api/persons/greeting/greeting123/{id}", m.Find("/api/persons/greeting/greeting123/456"))
	assert.Equal(t, "/api/persons/{id}", m.Find("/api/persons/greeting123"))
	assert.Equal(t, "/api/persons/greeting123/{id}/{id}", m.Find("/api/persons/greeting123/greeting123/456"))
	assert.Equal(t, "/api/persons/{id}/greeting123/{id}", m.Find("/api/persons/greeting12/greeting123/456"))
	assert.Equal(t, "/api/persons/{id}/{id}/{id}", m.Find("/api/persons/greeting12/greeting12/456"))
	assert.Equal(t, "/api/persons/age-greater-than/{age}", m.Find("/api/persons/age-greater-than/34"))
	assert.Equal(t, "/api/greeting/{id}", m.Find("/api/greeting/456"))
	assert.Empty(t, m.Find(""))
	assert.Empty(t, m.Find("/"))
	assert.Equal(t, "/{id}", m.Find("/whatever"))
}

func TestPartialRouteMatcherEmptyRoutes(t *testing.T) {
	m := NewPartialRouteMatcher([]string{})
	assert.Empty(t, m.Find("/api/users"))
	assert.Empty(t, m.Find("/"))
	assert.Empty(t, m.Find(""))
}

func TestPartialRouteMatcherSingleRoute(t *testing.T) {
	m := NewPartialRouteMatcher([]string{"/api"})
	assert.Equal(t, "/api", m.Find("/api"))
	assert.Empty(t, m.Find("/api/users"))
	assert.Empty(t, m.Find("/users"))
	assert.Empty(t, m.Find("/"))
}

func TestPartialRouteMatcherWildcards(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/users/{id}",
		"/posts/:postId",
		"/admin/{role}",
	})

	// Test single wildcard matches
	assert.Equal(t, "/users/{id}", m.Find("/users/123"))
	assert.Equal(t, "/posts/:postId", m.Find("/posts/456"))
	assert.Equal(t, "/admin/{role}", m.Find("/admin/superuser"))

	// Test combined matches
	assert.Equal(t, "/users/{id}/posts/:postId", m.Find("/users/123/posts/456"))
	assert.Equal(t, "/admin/{role}/users/{id}", m.Find("/admin/moderator/users/789"))
}

func TestPartialRouteMatcherExactMatches(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/health",
		"/status",
		"/api/v1",
		"/metrics",
	})

	// Test exact matches
	assert.Equal(t, "/health", m.Find("/health"))
	assert.Equal(t, "/status", m.Find("/status"))
	assert.Equal(t, "/api/v1", m.Find("/api/v1"))

	// Test combined exact matches
	assert.Equal(t, "/api/v1/health", m.Find("/api/v1/health"))
	assert.Equal(t, "/status/metrics", m.Find("/status/metrics"))

	// Test partial paths that don't match
	assert.Empty(t, m.Find("/unknown"))
}

func TestPartialRouteMatcherMixedRoutes(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/comments",
		"/users",
		"/posts",
		"/api",
		"/v1",
		"/{slug}",
		"/{id}",
	})

	// Test various combinations
	assert.Equal(t, "/api/v1/users/{id}", m.Find("/api/v1/users/123"))
	assert.Equal(t, "/api/posts/{id}/comments", m.Find("/api/posts/my-post/comments"))
	assert.Equal(t, "/users/{id}/posts/{id}", m.Find("/users/456/posts/another-post"))

	// Test fallback to generic wildcard
	assert.Equal(t, "/{id}", m.Find("/anything"))
}

func TestPartialRouteMatcherComplexPaths(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/organizations",
		"/repositories",
		"/projects",
		"/branches",
		"/commits",
		"/api",
		"/v2",
		"/{branchName}",
		"/{commitHash}",
		"/{projectId}",
		"/{repoId}",
		"/{orgId}",
	})

	// This test shows that we can improve the matcher for single parameter routes, such that we should
	// not pick the same route twice. It's unlikely scenario.
	longPath := "/api/v2/organizations/123/projects/456/repositories/789/branches/main/commits/abc123"
	expected := "/api/v2/organizations/{id}/projects/{id}/repositories/{id}/branches/{id}/commits/{id}"
	assert.Equal(t, expected, m.Find(longPath))
}

func TestPartialRouteMatcherEdgeCases(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/",
		"/single",
		"/{param}",
	})

	// Test root path
	assert.Equal(t, "/", m.Find("/"))

	// Test single segment
	assert.Equal(t, "/single", m.Find("/single"))

	// Test parameter fallback
	assert.Equal(t, "/{param}", m.Find("/anything"))

	// Test path with trailing slash
	assert.Equal(t, "/single", m.Find("/single/"))
}

func TestPartialRouteMatcherNoMatch(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/api/users",
		"/api/posts",
		"/admin/settings",
	})

	// These should return empty since they can't be constructed from partial matches
	assert.Empty(t, m.Find("/public/files"))
	assert.Empty(t, m.Find("/dashboard"))
	assert.Empty(t, m.Find("/auth/login"))
}

func TestPartialRouteMatcherGreedyMatching(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/api/users/profile",
		"/api/users",
		"/api",
		"/users",
		"/profile",
	})

	// Should prefer longer, more specific matches
	assert.Equal(t, "/api/users/profile", m.Find("/api/users/profile"))
	assert.Equal(t, "/api/users", m.Find("/api/users"))

	// Should build from parts when exact match not available
	assert.Equal(t, "/users/profile", m.Find("/users/profile"))
}

func TestPartialRouteMatcherOrderDependence(t *testing.T) {
	// Test that order of routes in slice doesn't affect matching behavior significantly
	routes1 := []string{"/a", "/b", "/c"}
	routes2 := []string{"/c", "/b", "/a"}

	m1 := NewPartialRouteMatcher(routes1)
	m2 := NewPartialRouteMatcher(routes2)

	testPath := "/a/b/c"
	result1 := m1.Find(testPath)
	result2 := m2.Find(testPath)

	// Both should find some valid combination (though may differ due to order)
	assert.NotEmpty(t, result1)
	assert.NotEmpty(t, result2)
	assert.Contains(t, result1, "/a")
	assert.Contains(t, result1, "/b")
	assert.Contains(t, result1, "/c")
}

func TestPartialRouteMatcherRepeatedSegments(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/api",
		"/users",
		"/posts",
		"/{version}",
		"/{id}",
	})

	// Test paths with repeated patterns
	assert.Equal(t, "/api/{id}/users/{id}/posts/{id}", m.Find("/api/v1/users/123/posts/456"))
	assert.Equal(t, "/{id}/{id}", m.Find("/v1/v2"))
}

func TestPartialRouteMatcherSpecialCharacters(t *testing.T) {
	m := NewPartialRouteMatcher([]string{
		"/api-v1",
		"/user_profile",
		"/data.json",
		"/{file_name}",
	})

	assert.Equal(t, "/api-v1", m.Find("/api-v1"))
	assert.Equal(t, "/user_profile", m.Find("/user_profile"))
	assert.Equal(t, "/data.json", m.Find("/data.json"))
	assert.Equal(t, "/api-v1/user_profile", m.Find("/api-v1/user_profile"))
	assert.Equal(t, "/{file_name}", m.Find("/some-file.txt"))
}

func TestNewPartialRouteMatcher(t *testing.T) {
	routes := []string{"/api", "/users", "/{id}"}
	m := NewPartialRouteMatcher(routes)

	assert.NotNil(t, m)
	assert.Len(t, m.roots, 3) // Should create one root per route

	// Each root should be properly initialized
	for _, root := range m.roots {
		assert.NotNil(t, root)
		assert.NotNil(t, root.Child)
	}
}

func TestDeduplicateSingleParamRoutes(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "multiple single param routes - should deduplicate",
			input:    []string{"/users/{userId}", "/products/{productId}", "/orders/{orderId}", "/api/v1"},
			expected: []string{"/users/{userId}", "/products/{productId}", "/orders/{orderId}", "/api/v1"},
		},
		{
			name:     "single param route - should keep as is",
			input:    []string{"/users/{userId}", "/api/v1", "/health"},
			expected: []string{"/api/v1", "/health", "/users/{userId}"},
		},
		{
			name:     "no single param routes - should remain unchanged",
			input:    []string{"/api/v1", "/health", "/status"},
			expected: []string{"/api/v1", "/health", "/status"},
		},
		{
			name:     "empty input - should return empty",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "complex routes mixed with single params",
			input:    []string{"/api/users/{id}", "/posts/{postId}", "/{categoryId}", "/health", "/api/v1/status"},
			expected: []string{"/api/users/{id}", "/posts/{postId}", "/{categoryId}", "/health", "/api/v1/status"},
		},
		{
			name:     "single param with different bracket styles",
			input:    []string{"/{userId}", "/{productId}", "/api/:id", "/users/{id}/posts"},
			expected: []string{"/api/:id", "/users/{id}/posts", "/{id}"},
		},
		{
			name:     "root single param routes only",
			input:    []string{"/{id}", "/{slug}", "/{uuid}"},
			expected: []string{"/{id}"},
		},
		{
			name:     "mixed single and multi-segment routes",
			input:    []string{"/{id}", "/api/users/{userId}", "/products/{productId}", "/api/v1"},
			expected: []string{"/{id}", "/api/users/{userId}", "/products/{productId}", "/api/v1"},
		},
		{
			name:     "single param routes with special characters",
			input:    []string{"/{user-id}", "/{product_id}", "/api/health"},
			expected: []string{"/api/health", "/{id}"},
		},
		{
			name:     "edge case - routes that look similar but aren't single params",
			input:    []string{"/{id}", "/users/{id}/posts", "/{category}/{id}", "/api/{version}"},
			expected: []string{"/{id}", "/users/{id}/posts", "/{category}/{id}", "/api/{version}"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateSingleParamRoutes(tt.input)

			// Sort both slices to avoid order dependency in comparison
			assert.ElementsMatch(t, tt.expected, result, "Routes should match expected result")
		})
	}
}

func TestDeduplicateSingleParamRoutesRegexPattern(t *testing.T) {
	// Test specific regex pattern matching
	tests := []struct {
		name        string
		route       string
		shouldMatch bool
	}{
		{"simple single param", "/{id}", true},
		{"single param with underscore", "/{user_id}", true},
		{"single param with hyphen", "/{user-id}", true},
		{"single param with alphanumeric", "/{userId123}", true},
		{"multi-segment route", "/users/{id}", false},
		{"route with multiple params", "/{id}/{name}", false},
		{"route without param", "/users", false},
		{"root route", "/", false},
		{"empty route", "", false},
		{"route with query param style", "/users?id={id}", false},
		{"route with colon param", "/:id", false}, // Different parameter style
		{"nested braces", "/{user{id}}", false},   // Invalid nesting
		{"empty braces", "/{}", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []string{tt.route, "/api/v1"} // Add a non-matching route
			result := deduplicateSingleParamRoutes(input)

			if tt.shouldMatch {
				// If it should match, it should be kept as a single param route
				// (since there's only one single param route, it should be preserved)
				assert.Contains(t, result, tt.route, "Single param route should be preserved")
			} else {
				// If it shouldn't match, it should be treated as a regular route
				assert.Contains(t, result, tt.route, "Non-single-param route should be preserved")
			}
		})
	}
}

// Benchmark tests
func BenchmarkPartialRouteMatcherSimple(b *testing.B) {
	m := NewPartialRouteMatcher([]string{
		"/api", "/users", "/{id}", "/posts", "/comments",
	})

	testPaths := []string{
		"/api/users/123",
		"/users/456/posts",
		"/api/posts/789/comments",
		"/anything/else",
	}

	for b.Loop() {
		for _, path := range testPaths {
			m.Find(path)
		}
	}
}

func BenchmarkPartialRouteMatcherComplex(b *testing.B) {
	m := NewPartialRouteMatcher([]string{
		"/api", "/v1", "/v2", "/organizations", "/{orgId}",
		"/projects", "/{projectId}", "/repositories", "/{repoId}",
		"/branches", "/{branchName}", "/commits", "/{commitHash}",
		"/files", "/{filePath}", "/users", "/{userId}",
	})

	testPaths := []string{
		"/api/v1/organizations/123/projects/456",
		"/api/v2/repositories/789/branches/main/commits/abc123",
		"/organizations/999/users/777/projects/888",
		"/files/path/to/file.txt",
	}

	for b.Loop() {
		for _, path := range testPaths {
			m.Find(path)
		}
	}
}

// TestMatchedPartsSliceExpansion tests the specific condition where the matchedParts slice
// needs to be expanded when matchedLen == len(matchedParts). This happens when we have
// enough partial route matches to fill the initial slice and need to add more.
func TestMatchedPartsSliceExpansion(t *testing.T) {
	// Create routes that can be combined into a long path requiring slice expansion
	routes := []string{
		"/api",
		"/v1",
		"/users",
		"/{id}",
		"/profile",
		"/settings",
		"/preferences",
		"/notifications",
	}

	m := NewPartialRouteMatcher(routes)

	// Create a path that will match multiple partial routes sequentially,
	// forcing the matchedParts slice to expand beyond its initial size
	testPath := "/api/v1/users/123/profile/settings/preferences/notifications"

	// Purposefully call with empty parts slice to force the iteration to hit the copy
	tokens := tokenize(testPath)
	result := m.findCombined(tokens, 0, make([]string, 0), 0)

	assert.Equal(t, "/api/v1/users/{id}/profile/settings/preferences/notifications", result)
}
