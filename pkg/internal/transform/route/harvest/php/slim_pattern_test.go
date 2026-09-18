// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlimRouteVariants(t *testing.T) {
	assert.Equal(t,
		[]string{"/news", "/news/{*params}"},
		slimRouteVariants("/news[/{params:.*}]"),
	)
	assert.Equal(t,
		[]string{"/users/{id}"},
		slimRouteVariants("/users/{id:[0-9]{4}}"),
	)
}

func TestNormalizeSlimPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{name: "plain placeholder", pattern: "/users/{id}", want: "/users/{id}"},
		{name: "regex", pattern: "/users/{id:[0-9]+}", want: "/users/{id}"},
		{name: "regex quantifier", pattern: "/users/{id:[0-9]{4}}", want: "/users/{id}"},
		{name: "catch all", pattern: "/news/{params:.*}", want: "/news/{*params}"},
		{name: "multiple placeholders", pattern: "/{year:[0-9]{4}}/{slug:[a-z-]+}", want: "/{year}/{slug}"},
		{name: "unclosed placeholder", pattern: "/users/{id:[0-9]+", want: "/users/{id:[0-9]+"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, normalizeSlimPattern(test.pattern))
		})
	}
}
