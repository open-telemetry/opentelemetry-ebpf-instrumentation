// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route

import "testing"

func TestCombinedRouteMatcherCompleteRouteTakesPrecedence(t *testing.T) {
	m := NewCombinedRouteMatcher(
		[]string{"/users/{id}"},
		[]string{"/users"},
	)

	got := m.Find("/users/123")
	want := "/users/{id}"

	if got != want {
		t.Errorf("Find() = %q, want %q", got, want)
	}
}

func TestCombinedRouteMatcherFallsBackToPartialRoutes(t *testing.T) {
	m := NewCombinedRouteMatcher(
		[]string{"/orders/{id}"},
		[]string{"/api", "/users"},
	)

	got := m.Find("/api/users")
	want := "/api/users"

	if got != want {
		t.Errorf("Find() = %q, want %q", got, want)
	}
}

func TestCombinedRouteMatcherDoesNotCombineCompleteAndPartialRoutes(t *testing.T) {
	m := NewCombinedRouteMatcher(
		[]string{"/users/{id}"},
		[]string{"/api"},
	)

	got := m.Find("/api/users/123")

	if got != "" {
		t.Errorf("Find() = %q, want empty string", got)
	}
}

func TestCombinedRouteMatcherAbsoluteRoot(t *testing.T) {
	m := NewCombinedRouteMatcher(nil, []string{"/"})

	got := m.Find("/")
	if got != "/" {
		t.Errorf("Find() = %q, want %q", got, "/")
	}
}
