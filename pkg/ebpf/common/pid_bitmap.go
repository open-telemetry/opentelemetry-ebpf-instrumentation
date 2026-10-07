// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// PIDBitmapWords is the size of a pid-indexed BPF bitmap such as valid_pids (bpf/pid/pid.h)
const PIDBitmapWords = uint32(BpfValidPidsSizeK_validPidsWords)

// PIDBitmap mirrors a pid-indexed BPF bitmap: one bit per pid, as OBI's /proc numbers it
type PIDBitmap struct {
	mu sync.Mutex
	// the words as last written to the BPF map
	words []uint64
}

// Rebuild sets exactly the bits of pids, writing only the words that changed
func (b *PIDBitmap) Rebuild(m *ebpf.Map, pids []app.PID, log *slog.Logger) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.words == nil {
		b.words = make([]uint64, PIDBitmapWords)
	}

	want := map[uint32]uint64{}
	for _, pid := range pids {
		if uint64(pid) >= uint64(PIDBitmapWords)*64 {
			log.Warn("pid beyond the BPF PID filter, it won't be instrumented", "pid", pid)
			continue
		}
		want[uint32(pid/64)] |= 1 << (pid % 64)
	}

	for word, bits := range b.words {
		if _, ok := want[uint32(word)]; bits != 0 && !ok {
			want[uint32(word)] = 0
		}
	}

	written := 0
	for word, bits := range want {
		if b.words[word] == bits {
			continue
		}
		if err := m.Put(word, bits); err != nil {
			return fmt.Errorf("writing word %d of the BPF PID filter: %w", word, err)
		}
		b.words[word] = bits
		written++
	}
	log.Debug("BPF PID filter rebuilt", "pids", len(pids), "wordsWritten", written)

	return nil
}

// Contains reports whether the last rebuild set pid's bit
func (b *PIDBitmap) Contains(pid app.PID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	word := uint64(pid) / 64
	return word < uint64(len(b.words)) && b.words[word]&(1<<(pid%64)) != 0
}
