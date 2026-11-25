// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon_test

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
)

// A map left out of ShrinkRustMaps stays full size on every node.
func TestShrinkRustMapsCoversEveryRustMap(t *testing.T) {
	for name, load := range map[string]func() (*ebpf.CollectionSpec, error){
		"generictracer": generictracer.LoadBpf,
		"gotracer":      gotracer.LoadBpf,
		"tpinjector":    tpinjector.LoadBpf,
	} {
		t.Run(name, func(t *testing.T) {
			spec, err := load()
			require.NoError(t, err)

			ebpfcommon.ShrinkRustMaps(spec)

			rustMaps := 0
			for mapName, m := range spec.Maps {
				if strings.HasPrefix(mapName, "rust") {
					assert.Equal(t, uint32(1), m.MaxEntries, mapName)
					rustMaps++
				}
			}
			assert.Positive(t, rustMaps)
		})
	}
}
