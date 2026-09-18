// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnescapeMountPath(t *testing.T) {
	tests := map[string]struct {
		path string
		want string
	}{
		"unchanged":              {path: "/sys/kernel/tracing", want: "/sys/kernel/tracing"},
		"mountinfo escapes":      {path: `/trace\040space\011tab\012line\134slash`, want: "/trace space\ttab\nline\\slash"},
		"unknown escape":         {path: `/trace\043hash`, want: `/trace\043hash`},
		"escaped backslash only": {path: `/trace\134040space`, want: `/trace\040space`},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, unescapeMountPath(test.path))
		})
	}
}

func TestRandomTraceFSGroup(t *testing.T) {
	group, err := randomTraceFSGroup()

	require.NoError(t, err)
	assert.Regexp(t, `^obi_[0-9a-f]{16}$`, group)
}

func TestTraceFSEventCommand(t *testing.T) {
	tests := map[string]struct {
		path         string
		address      uint64
		refCtrOffset uint64
		ret          bool
		group        string
		name         string
		want         string
	}{
		"uprobe": {
			path:    "/proc/123/exe",
			address: 0x42,
			group:   "obi_abcd",
			name:    "probe_0",
			want:    "p:obi_abcd/probe_0 /proc/123/exe:0x42",
		},
		"uretprobe": {
			path:    "/proc/123/exe",
			address: 0x42,
			ret:     true,
			group:   "obi_abcd",
			name:    "probe_1",
			want:    "r:obi_abcd/probe_1 /proc/123/exe:0x42",
		},
		"USDT reference counter": {
			path:         "/proc/123/map_files/1000-2000",
			address:      0xc0b0,
			refCtrOffset: 0x18,
			group:        "obi_abcd",
			name:         "probe_2",
			want:         "p:obi_abcd/probe_2 /proc/123/map_files/1000-2000:0xc0b0(0x18)",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, traceFSEventCommand(
				test.path,
				test.address,
				test.refCtrOffset,
				test.ret,
				test.group,
				test.name,
			))
		})
	}
}
