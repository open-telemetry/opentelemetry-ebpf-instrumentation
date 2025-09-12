// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clusterurl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:testifylint
func TestClusterURL(t *testing.T) {
	csf, err := NewClusterURLClassifier(DefaultConfig())
	assert.NoError(t, err)
	assert.Empty(t, csf.ClusterURL(""))
	assert.Equal(t, "/users/*/j4elk/*/job/*", csf.ClusterURL("/users/fdklsd/j4elk/23993/job/2"))
	assert.Equal(t, "*", csf.ClusterURL("123"))
	assert.Equal(t, "/*", csf.ClusterURL("/123"))
	assert.Equal(t, "*/", csf.ClusterURL("123/"))
	assert.Equal(t, "*/*", csf.ClusterURL("123/ljgdflgjf"))
	assert.Equal(t, "/*", csf.ClusterURL("/**"))
	assert.Equal(t, "/u/*", csf.ClusterURL("/u/2"))
	assert.Equal(t, "/v1/products/*", csf.ClusterURL("/v1/products/2"))
	assert.Equal(t, "/v1/products/*", csf.ClusterURL("/v1/products/22"))
	assert.Equal(t, "/v1/products/*", csf.ClusterURL("/v1/products/22j"))
	assert.Equal(t, "/products/*/org/*", csf.ClusterURL("/products/1/org/3"))
	assert.Equal(t, "/products//org/*", csf.ClusterURL("/products//org/3"))
	assert.Equal(t, "/v1/k6-test-runs/*", csf.ClusterURL("/v1/k6-test-runs/1"))
	assert.Equal(t, "/attach", csf.ClusterURL("/attach"))
	assert.Equal(t, "/usuarios/*/j4elk/*/trabajo/*", csf.ClusterURL("/usuarios/fdklsd/j4elk/23993/trabajo/2"))
	assert.Equal(t, "/Benutzer/*/j4elk/*/Arbeit/*", csf.ClusterURL("/Benutzer/fdklsd/j4elk/23993/Arbeit/2"))
	assert.Equal(t, "/utilisateurs/*/j4elk/*/tache/*", csf.ClusterURL("/utilisateurs/fdklsd/j4elk/23993/tache/2"))
	assert.Equal(t, "/products/", csf.ClusterURL("/products/"))
	assert.Equal(t, "/user-space/", csf.ClusterURL("/user-space/"))
	assert.Equal(t, "/user_space/", csf.ClusterURL("/user_space/"))
	assert.Equal(t, "/api/hello.world", csf.ClusterURL("/api/hello.world"))
	assert.Equal(t, "/api/hello.world.again", csf.ClusterURL("/api/hello.world.again"))
	assert.Equal(t, "/api.backup/hello.world", csf.ClusterURL("/api.backup/hello.world"))
	assert.Equal(t, "GET /user_space/", csf.ClusterURL("GET /user_space/"))
	assert.Equal(t, "POST /user_space/", csf.ClusterURL("POST /user_space/"))
	assert.Equal(t, "PUT /user_space/", csf.ClusterURL("PUT /user_space/"))
	assert.Equal(t, "DELETE /user_space/", csf.ClusterURL("DELETE /user_space/"))
	assert.Equal(t, "OPTIONS /user_space/", csf.ClusterURL("OPTIONS /user_space/"))
	assert.Equal(t, "HEAD /user_space/", csf.ClusterURL("HEAD /user_space/"))
	assert.Equal(t, "PATCH /user_space/", csf.ClusterURL("PATCH /user_space/"))
	assert.Equal(t, "TRACE /user_space/", csf.ClusterURL("TRACE /user_space/"))
	assert.Equal(t, "CONNECT /user_space/", csf.ClusterURL("CONNECT /user_space/"))
	assert.Equal(t, "/attach", csf.ClusterURL("/attach?session_id=ddfsdsf&track_id=sjdklnfldsn"))
	assert.Equal(t, "/attach", csf.ClusterURL("/attach#section-1"))
	assert.Equal(t, "HTTP GET", csf.ClusterURL("HTTP GET"))
	assert.Equal(t, "GET /api/cart", csf.ClusterURL("GET /api/cart?sessionId=55f4e5ea-5d6d-482a-80c4-799e3c72dfb0&currencyCode=USD"))
	assert.Equal(t, "/getquote", csf.ClusterURL("/getquote"))
	assert.Equal(t, "", csf.ClusterURL("?"))
	assert.Equal(t, "", csf.ClusterURL("attach12?"))
	assert.Equal(t, "", csf.ClusterURL("1?"))
	assert.Equal(t, "", csf.ClusterURL("*&"))
	assert.Equal(t, "", csf.ClusterURL("12#"))
	assert.Equal(t, "/a", csf.ClusterURL("/a#"))
}

func BenchmarkClusterURLWithCache(b *testing.B) {
	cfg := DefaultConfig()
	cfg.CacheSize = 1000
	csf, err := NewClusterURLClassifier(cfg)
	if err != nil {
		b.Fatal(err)
	}

	// Test cases representing different scenarios
	testCases := []string{
		"/users/fdklsd/j4elk/23993/job/2",
		"/v1/products/22",
		"/products/1/org/3",
		"/attach?session_id=ddfsdsf&track_id=sjdklnfldsn",
		"GET /user_space/",
		"/api/hello.world",
		"123/ljgdflgjf",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, testCase := range testCases {
			_ = csf.ClusterURL(testCase)
		}
	}
}

func BenchmarkClusterURLWithoutCache(b *testing.B) {
	cfg := DefaultConfig()
	cfg.CacheSize = 1
	csf, err := NewClusterURLClassifier(cfg)
	if err != nil {
		b.Fatal(err)
	}

	// Test cases representing different scenarios
	testCases := []string{
		"/users/fdklsd/j4elk/23993/job/2",
		"/v1/products/22",
		"/products/1/org/3",
		"/attach?session_id=ddfsdsf&track_id=sjdklnfldsn",
		"GET /user_space/",
		"/api/hello.world",
		"123/ljgdflgjf",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, testCase := range testCases {
			_ = csf.ClusterURL(testCase)
		}
	}
}
