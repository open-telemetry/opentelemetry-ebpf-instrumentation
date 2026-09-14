// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSymfonyLegacyAnnotations(t *testing.T) {
	tokens := lexPHP([]byte(`
        /** @Route("/api") */
        class Controller {
            /** @Route(path="/users") @Rest\Get("/members") */
            public function users() {
                /** @Route("/nested") */
                function nested() {}
            }

            /** unrelated documentation */
            public function ignored() {}
        }

        /** @Route("/health") */
        function health() {}
    `))
	routes := newRouteSet()

	extractSymfonyLegacyAnnotations(tokens, true, routes)

	assert.Equal(t, routeSet{
		"/api/users":   {},
		"/api/members": {},
		"/health":      {},
	}, routes)
}

func TestExtractSymfonyLegacyMethods(t *testing.T) {
	tokens := lexPHP([]byte(`{
        /** @Route("/users") */
        function users() {
            /** @Route("/nested") */
            function nested() {}
        }
        /** @Rest\Post("/status") */
        function status();
    }`))
	end := matchingClosingToken(tokens, 0, "{", "}")
	routes := newRouteSet()

	extractSymfonyLegacyMethods(tokens, 1, end, []string{"/api"}, true, routes)

	assert.Equal(t, routeSet{
		"/api/users":  {},
		"/api/status": {},
	}, routes)
}

func TestExtractSymfonyLegacyMethodsIgnoresStringLiteralsThatLookLikeBraces(t *testing.T) {
	tokens := lexPHP([]byte(`{
        function broken() {
            return '{';
        }
        /** @Route("/after") */
        function after() {}
    }`))
	end := matchingClosingToken(tokens, 0, "{", "}")
	routes := newRouteSet()

	extractSymfonyLegacyMethods(tokens, 1, end, nil, false, routes)

	assert.Equal(t, routeSet{"/after": {}}, routes)
}

func TestLegacyAnnotationPaths(t *testing.T) {
	comment := `/**
        * @Route("/route")
        * @Routing\Route(path='/qualified')
        * @Rest\Get("/rest-get")
        * @POST(path="/rest-post")
        */`

	assert.Equal(t, []string{"/route", "/qualified"}, legacyAnnotationPaths(comment, false))
	assert.Equal(t, []string{"/route", "/qualified", "/rest-get", "/rest-post"}, legacyAnnotationPaths(comment, true))
	assert.Empty(t, legacyAnnotationPaths("/** no routes */", true))
}

func TestLegacyAnnotationPathsFindsNamedPathNotInFirstPosition(t *testing.T) {
	comment := `/**
        * @Route(name="blog_show", path="/blog/{id}")
        * @Rest\Get(name="rest_show", path="/rest/{id}")
        */`

	assert.Equal(t, []string{"/blog/{id}"}, legacyAnnotationPaths(comment, false))
	assert.Equal(t, []string{"/blog/{id}", "/rest/{id}"}, legacyAnnotationPaths(comment, true))
}

func TestAnnotationMatches(t *testing.T) {
	pattern := regexp.MustCompile(`route:\s*([^\s]+)`)

	assert.Equal(t, []string{"/one", "/two"}, annotationMatches(pattern, "route: /one ignored route: /two"))
	assert.Empty(t, annotationMatches(pattern, "no match"))
	assert.Empty(t, annotationMatches(regexp.MustCompile(`route`), "route"))
}
