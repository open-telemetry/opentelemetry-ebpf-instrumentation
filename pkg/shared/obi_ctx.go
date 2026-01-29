// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package shared // import "go.opentelemetry.io/obi/pkg/shared"

import (
	"fmt"
	"os"
	"path"

	"github.com/cilium/ebpf"
)

const TracesCtxV1MapName = "traces_ctx_v1"

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../bpf/shared/obi_ctx.c -- -I../../bpf

func LoadOrCreateCtxMap(bpfFsPath string) (*ebpf.Map, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading %s spec: %w", TracesCtxV1MapName, err)
	}

	otelPath := namespacedBpfFsPath(bpfFsPath)
	if err := os.MkdirAll(otelPath, 0o1700); err != nil {
		return nil, fmt.Errorf("creating bpffs otel path: %w", err)
	}

	var maps BpfMaps
	err = spec.LoadAndAssign(&maps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: otelPath,
			LoadPinOptions: ebpf.LoadPinOptions{
				ReadOnly: true, // BPF_F_RDONLY
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating new %s map: %w", TracesCtxV1MapName, err)
	}

	return maps.TracesCtxV1, nil
}

func TeardownCtxMap(bpfFsPath string) error {
	m, err := LoadOrCreateCtxMap(namespacedBpfFsPath(bpfFsPath))
	if err != nil {
		// no pinned map, nothing to do
		return nil
	}

	if err := m.Unpin(); err != nil {
		return fmt.Errorf("unpinning %s map: %w", TracesCtxV1MapName, err)
	}

	if err := m.Close(); err != nil {
		return fmt.Errorf("closing %s map: %w", TracesCtxV1MapName, err)
	}

	return nil
}

func namespacedBpfFsPath(bpfFsPath string) string {
	return path.Join(bpfFsPath, "otel")
}
