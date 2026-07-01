// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package gometa decodes Go runtime type metadata from a stripped binary.
// Targets Go 1.21+ on amd64/arm64.
package gometa // import "go.opentelemetry.io/obi/pkg/internal/gometa"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrNoTypelinks  = errors.New("gometa: .typelink section missing")
	ErrNoRodata     = errors.New("gometa: .rodata section missing")
	ErrUnresolvable = errors.New("gometa: could not locate types base")
)

// Walker holds one binary's parsed type metadata.
type Walker struct {
	rdata     []byte
	rdataAddr uint64
	typelinks []int32
	typesBase uint64
	textBase  uint64
	cache     map[uint64]*Type
}

// Open parses the type tables of a Go ELF.
func Open(ef *elf.File) (*Walker, error) {
	rodata := ef.Section(".rodata")
	if rodata == nil {
		return nil, ErrNoRodata
	}
	rdata, err := rodata.Data()
	if err != nil {
		return nil, fmt.Errorf("gometa: read .rodata: %w", err)
	}
	tl := ef.Section(".typelink")
	if tl == nil {
		return nil, ErrNoTypelinks
	}
	tlData, err := tl.Data()
	if err != nil {
		return nil, fmt.Errorf("gometa: read .typelink: %w", err)
	}
	links := make([]int32, len(tlData)/4)
	for i := range links {
		links[i] = int32(binary.LittleEndian.Uint32(tlData[i*4:]))
	}
	w := &Walker{
		rdata:     rdata,
		rdataAddr: rodata.Addr,
		typelinks: links,
		cache:     make(map[uint64]*Type),
	}
	if text := ef.Section(".text"); text != nil {
		w.textBase = text.Addr
	}
	base, ok := w.findTypesBase()
	if !ok {
		return nil, ErrUnresolvable
	}
	w.typesBase = base
	return w, nil
}

// TypeByName finds a type by its runtime name (e.g. "*main.checkout").
func (w *Walker) TypeByName(name string) *Type {
	var found *Type
	w.Types(func(t *Type) bool {
		if t.Name == name {
			found = t
			return false
		}
		return true
	})
	return found
}

// Types yields every reachable type once (typelinks + Elem + struct fields).
func (w *Walker) Types(yield func(*Type) bool) {
	seen := make(map[uint64]struct{}, len(w.typelinks))
	var visit func(*Type) bool
	visit = func(t *Type) bool {
		if t == nil {
			return true
		}
		if _, ok := seen[t.va]; ok {
			return true
		}
		seen[t.va] = struct{}{}
		if !yield(t) {
			return false
		}
		if e := t.Elem(); e != nil && !visit(e) {
			return false
		}
		if t.Kind == Struct {
			for _, f := range t.Fields() {
				if !visit(f.Type) {
					return false
				}
			}
		}
		return true
	}
	for _, off := range w.typelinks {
		if !visit(w.typeAt(w.typesBase + uint64(int64(off)))) {
			return
		}
	}
}

// findTypesBase picks the page-aligned candidate inside .rodata whose
// typelink offsets decode as valid _type records.
func (w *Walker) findTypesBase() (uint64, bool) {
	candidates := []uint64{w.rdataAddr}
	for off := uint64(0x1000); off < uint64(len(w.rdata)); off += 0x1000 {
		candidates = append(candidates, w.rdataAddr+off)
	}
	bestBase := uint64(0)
	bestHits := 0
	for _, base := range candidates {
		h := w.scoreBase(base)
		if h > bestHits {
			bestHits = h
			bestBase = base
		}
	}
	if bestHits == 0 {
		return 0, false
	}
	return bestBase, true
}

func (w *Walker) scoreBase(base uint64) int {
	sample := len(w.typelinks)
	if sample > 64 {
		sample = 64
	}
	score := 0
	for i := 0; i < sample; i++ {
		raw, ok := w.readRawType(base + uint64(int64(w.typelinks[i])))
		if !ok {
			continue
		}
		k := raw.Kind & kindMask
		if k == 0 || k > 26 {
			continue
		}
		if raw.Size == 0 || raw.Size > 1<<20 {
			continue
		}
		if raw.Hash == 0 {
			continue
		}
		score++
	}
	return score
}

// rdataSlice returns n bytes at va within .rodata.
func (w *Walker) rdataSlice(va uint64, n int) ([]byte, bool) {
	if va < w.rdataAddr {
		return nil, false
	}
	off := va - w.rdataAddr
	end := off + uint64(n)
	if end > uint64(len(w.rdata)) {
		return nil, false
	}
	return w.rdata[off:end], true
}
