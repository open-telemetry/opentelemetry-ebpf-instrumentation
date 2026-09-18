// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSymfonyConfigTraversal(t *testing.T) {
	traversal := newSymfonyConfigTraversal()

	assert.True(t, traversal.enter("routes.yaml", "/v1"))
	assert.False(t, traversal.enter("routes.yaml", "/v2"))

	traversal.leave("routes.yaml")
	assert.True(t, traversal.enter("routes.yaml", "/v2"))

	traversal.leave("routes.yaml")
	assert.False(t, traversal.enter("routes.yaml", "/v1"))
	assert.Empty(t, traversal.active)
}
