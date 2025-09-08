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
	assert.Equal(t, "", m.Find(""))
	assert.Equal(t, "", m.Find("/"))
	assert.Equal(t, "/{id}", m.Find("/whatever"))
}
