// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package uprobe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceFSTarget(t *testing.T) {
	assert.Equal(t, "/proc/123/exe:0x42", traceFSTarget("/proc/123/exe", 0x42, 0))
	assert.Equal(t, "/proc/123/map_files/1000-2000:0xc0b0(0x18)",
		traceFSTarget("/proc/123/map_files/1000-2000", 0xc0b0, 0x18))
}
