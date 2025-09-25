// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import "testing"

func TestIsITabEntry(t *testing.T) {
	cases := []struct {
		name string
		sym  string
		want bool
	}{
		{"new prefix", "go:itab.*net/http.response,net/http.ResponseWriter", true},
		{"old prefix", "go.itab.*net/http.response,net/http.ResponseWriter", true},
		{"not itab", "go:typelink.blah", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isITabEntry(c.sym); got != c.want {
				t.Errorf("isITabEntry(%q) = %v, want %v", c.sym, got, c.want)
			}
		})
	}
}

func TestITabType(t *testing.T) {
	cases := []struct {
		name string
		sym  string
		want string
	}{
		{"valid new", "go:itab.*net/http.response,net/http.ResponseWriter", "*net/http.response"},
		{"valid old", "go.itab.*net/http.response,net/http.ResponseWriter", "*net/http.response"},
		{"short", "go:itab.", ""},
		{"no comma", "go:itab.something", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := iTabType(c.sym); got != c.want {
				t.Errorf("iTabType(%q) = %q, want %q", c.sym, got, c.want)
			}
		})
	}
}
