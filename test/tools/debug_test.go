// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToJSON(t *testing.T) {
	obj := struct {
		A string
		B int
	}{A: "A", B: 2}

	assert.JSONEq(t, `{"A":"A","B":2}`, ToJSON(obj))
}

func TestToJSON_Fail(t *testing.T) {
	type A struct {
		A *A
	}
	assert.Panics(t, func() {
		a := A{}
		a.A = &a
		ToJSON(a)
	})
}
