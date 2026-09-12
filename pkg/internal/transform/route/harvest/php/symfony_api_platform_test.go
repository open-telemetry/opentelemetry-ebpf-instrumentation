// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractAPIPlatformRoutesFindsEveryAttributeInGroup(t *testing.T) {
	routes := newRouteSet()

	extractAPIPlatformRoutes(lexPHP([]byte(`
        #[SomeAttribute, Get(uriTemplate: '/books/{id}')]
        #[ApiResource(
            uriTemplate: '/books',
            operations: [new GetCollection(uriTemplate: '/public-books')],
        )]
        #[Unknown(uriTemplate: '/ignored')]
        #[Post(uriTemplate: $dynamic)]
        #[Get(uriTemplate: '/unterminated')
        final class Book {}
    `)), routes)

	assert.Equal(t, routeSet{
		"/books/{id}":   {},
		"/books":        {},
		"/public-books": {},
	}, routes)
}

func TestIsAPIPlatformAttribute(t *testing.T) {
	for _, name := range []string{
		"ApiResource", "Delete", "Get", "GetCollection", "GraphQlOperation", "Patch", "Post", "Put",
		"apiresource", `\ApiPlatform\Metadata\GET`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.True(t, isAPIPlatformAttribute(lexPHP([]byte(name+"()"))))
		})
	}

	assert.False(t, isAPIPlatformAttribute(nil))
	assert.False(t, isAPIPlatformAttribute(lexPHP([]byte(`'Get'`))))
	assert.False(t, isAPIPlatformAttribute(lexPHP([]byte(`Unknown()`))))
}

func TestAddAPIPlatformURITemplates(t *testing.T) {
	tokens := lexPHP([]byte(`ApiResource(
        URITEMPLATE: '/books',
        operations: [
            new Get(uriTemplate: '/books/{id}'),
            new Post(uriTemplate: $dynamic),
        ],
        uriTemplate = '/wrong-separator',
        uriTemplate: 42,
    )`))
	routes := newRouteSet()

	addAPIPlatformURITemplates(tokens, routes)

	assert.Equal(t, routeSet{
		"/books":      {},
		"/books/{id}": {},
	}, routes)
}
