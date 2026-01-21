package shared

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
)

const (
	ObiCtxPinPath = "/sys/fs/bpf"
	ObiCtxMapName = "obi_ctx"
)

var mu sync.Mutex

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../bpf/shared/obi_ctx.c -- -I../../bpf

func LoadOrCreateCtxMap() (*ebpf.Map, error) {
	mu.Lock()
	defer mu.Unlock()

	m, err := loadPinnedCtxMap()
	if err != nil {
		return createPinnedCtxMap()
	}

	return m, nil
}

func loadPinnedCtxMap() (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(ObiCtxPinPath, ObiCtxMapName), &ebpf.LoadPinOptions{
		ReadOnly: true, // BPF_F_RDONLY
	})
}

func createPinnedCtxMap() (*ebpf.Map, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading %s spec: %w", ObiCtxMapName, err)
	}

	mapSpec, ok := spec.Maps[ObiCtxMapName]
	if !ok {
		return nil, fmt.Errorf("spec does not contain %s map", ObiCtxMapName)
	}

	m, err := ebpf.NewMapWithOptions(mapSpec, ebpf.MapOptions{
		PinPath: ObiCtxPinPath,
		LoadPinOptions: ebpf.LoadPinOptions{
			ReadOnly: true, // BPF_F_RDONLY
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating new %s map: %w", ObiCtxMapName, err)
	}

	return m, nil
}
