// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package img

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsing(t *testing.T) {
	t.Run("full coords", func(t *testing.T) {
		i := Docker("foo/bar:latest@sha256:123456")
		assert.Equal(t, "foo/bar", i.Repository())
		assert.Equal(t, "latest@sha256:123456", i.Tag())
	})
	t.Run("no sha", func(t *testing.T) {
		i := Docker("foo/bar:latest")
		assert.Equal(t, "foo/bar", i.Repository())
		assert.Equal(t, "latest", i.Tag())
	})
	t.Run("no tag, only sha", func(t *testing.T) {
		i := Docker("foo/bar@sha256:123456")
		assert.Equal(t, "foo/bar", i.Repository())
		assert.Equal(t, "sha256:123456", i.Tag())
	})
	t.Run("no tag, no sha", func(t *testing.T) {
		i := Docker("foo/bar")
		assert.Equal(t, "foo/bar", i.Repository())
		assert.Empty(t, i.Tag())
	})
}
