// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience // import "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// This file contains convenience functions around the cilium/ebpf
// CollectionSpec.Variables API.
// This wrapper has been deprecated in the main cilium/ebpf codebase.

const PinInternal = ebpf.PinType(100)

const (
	outgoingTraceHandoffMap       = "outgoing_trace_handoff"
	outgoingTraceHandoffEpochMap  = "outgoing_trace_handoff_epoch"
	outgoingTraceHandoffCPUClaims = "outgoing_trace_handoff_cpu_claims"
)

func roundToNearestMultiple(x, n uint32) uint32 {
	if x < n {
		return n
	}

	if x%n == 0 {
		return x
	}

	return (x + n/2) / n * n
}

// RingBuf and UserRingbuf max_entries must be page-aligned: both go through the kernel's ringbuf_map_alloc
func alignMaxEntriesIfRingBuf(m *ebpf.MapSpec) {
	if m.Type == ebpf.RingBuf || m.Type == ebpf.UserRingbuf {
		m.MaxEntries = roundToNearestMultiple(m.MaxEntries, uint32(os.Getpagesize()))
	}
}

// configureOutgoingTraceHandoffMaps keeps the allocation guard ABI identical
// in every collection spec. The map is keyed by the kernel's possible CPU ID
// range, including CPUs that are currently offline but may later be hot-added.
func configureOutgoingTraceHandoffMaps(spec *ebpf.CollectionSpec) error {
	claims := spec.Maps[outgoingTraceHandoffCPUClaims]
	if claims == nil {
		return nil
	}

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("querying possible CPUs for outgoing trace handoff: %w", err)
	}
	if possibleCPUs <= 0 {
		return fmt.Errorf("querying possible CPUs for outgoing trace handoff: invalid count %d", possibleCPUs)
	}
	claims.MaxEntries = uint32(possibleCPUs)
	return nil
}

// initializeOutgoingTraceHandoffEpoch binds every generated token to the live
// authority map instance. ResolveMaps calls this while holding the shared map
// lock, before any program in the collection can be attached. Later
// collection loads validate and reuse the value; they never reset it or the
// per-CPU counters.
func initializeOutgoingTraceHandoffEpoch(sharedMaps map[string]*ebpf.Map) error {
	authority := sharedMaps[outgoingTraceHandoffMap]
	epoch := sharedMaps[outgoingTraceHandoffEpochMap]
	if authority == nil && epoch == nil {
		return nil
	}
	if authority == nil || epoch == nil {
		return fmt.Errorf(
			"outgoing trace handoff map group is incomplete: authority=%t epoch=%t",
			authority != nil,
			epoch != nil,
		)
	}

	info, err := authority.Info()
	if err != nil {
		return fmt.Errorf("querying outgoing trace handoff authority map: %w", err)
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return errors.New("querying outgoing trace handoff authority map: kernel map ID unavailable")
	}

	key := uint32(0)
	var current uint64
	if err := epoch.Lookup(key, &current); err != nil {
		return fmt.Errorf("reading outgoing trace handoff epoch: %w", err)
	}
	expected := uint64(id)
	switch {
	case current == 0:
		if err := epoch.Put(key, expected); err != nil {
			return fmt.Errorf("initializing outgoing trace handoff epoch: %w", err)
		}
	case current != expected:
		return fmt.Errorf(
			"outgoing trace handoff epoch mismatch: stored=%d authority_map_id=%d",
			current,
			expected,
		)
	}
	return nil
}

// ResolveMaps sets up internal maps and ensures sane max entries values
func ResolveMaps(spec *ebpf.CollectionSpec, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex) (*ebpf.CollectionOptions, error) {
	collOpts := ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{}}

	mu.Lock()
	defer mu.Unlock()

	if err := configureOutgoingTraceHandoffMaps(spec); err != nil {
		return nil, err
	}

	for k, v := range spec.Maps {
		alignMaxEntriesIfRingBuf(v)

		if v.Pinning != PinInternal {
			continue
		}

		v.Pinning = ebpf.PinNone
		internalMap := sharedMaps[k]

		var err error

		if internalMap == nil {
			internalMap, err = ebpf.NewMap(v)
			if err != nil {
				return nil, fmt.Errorf("failed to load shared map: %w", err)
			}

			sharedMaps[k] = internalMap
			runtime.SetFinalizer(internalMap, (*ebpf.Map).Close)
		}

		collOpts.MapReplacements[k] = internalMap
	}

	if err := initializeOutgoingTraceHandoffEpoch(sharedMaps); err != nil {
		return nil, err
	}

	return &collOpts, nil
}

// LoadSpec loads a BPF collection spec into the provided objects, handling
// constant rewriting, PinInternal map resolution, and bpffs pin path setup.
// Notes about some parameters:
// - constants: optional map of BPF constants to rewrite (may be nil)
// - sharedMaps: map store for PinInternal maps, shared across specs within the same agent
// - pinPath: bpffs pin path for PinByName maps (empty string to skip)
// - cache: optional kernel BTF cache shared across loads (may be nil)
func LoadSpec(spec *ebpf.CollectionSpec, objects any, constants map[string]any, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, pinPath string, cache *btf.Cache) error {
	if constants != nil {
		if err := RewriteConstants(spec, constants); err != nil {
			return fmt.Errorf("rewriting BPF constants: %w", err)
		}
	}

	collOpts, err := ResolveMaps(spec, sharedMaps, mu)
	if err != nil {
		return fmt.Errorf("resolving maps: %w", err)
	}

	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}
	collOpts.Maps = ebpf.MapOptions{PinPath: pinPath}
	collOpts.Cache = cache

	if err := spec.LoadAndAssign(objects, collOpts); err != nil {
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	return nil
}

const (
	MaxMapEntries       uint32 = 1 << 24
	MinMapEntries       uint32 = 64
	MinResizableMapSize uint32 = 64
)

// isResizableMapType returns true for map types where scaling MaxEntries
// is meaningful. Excludes special map types whose MaxEntries has fixed
// semantics (e.g. ProgramArray entries are tail-call slots, not data), and
// array types, whose MaxEntries is a valid index space rather than a capacity
// (e.g. valid_pids is indexed using a constant shared with userspace).
func isResizableMapType(t ebpf.MapType) bool {
	switch t {
	case ebpf.Array, ebpf.PerCPUArray,
		ebpf.ProgramArray, ebpf.PerfEventArray, ebpf.CGroupArray,
		ebpf.ArrayOfMaps, ebpf.HashOfMaps,
		ebpf.DevMap, ebpf.SockMap, ebpf.CPUMap, ebpf.XSKMap, ebpf.SockHash,
		ebpf.DevMapHash, ebpf.ReusePortSockArray:
		return false
	default:
		return true
	}
}

// SetupMapSizes scales all resizable maps in the spec by globalScaleFactor.
// If globalScaleFactor > 0, sizes are doubled that many times (left shift).
// If globalScaleFactor < 0, sizes are halved that many times (right shift).
// Maps with PinByName are skipped regardless of scale factor.
func SetupMapSizes(spec *ebpf.CollectionSpec, globalScaleFactor int) {
	if globalScaleFactor == 0 {
		return
	}

	for _, mSpec := range spec.Maps {
		if !isResizableMapType(mSpec.Type) {
			continue
		}

		if mSpec.MaxEntries < MinResizableMapSize {
			continue
		}

		if mSpec.Pinning == ebpf.PinByName {
			continue
		}

		oldEntries := mSpec.MaxEntries
		var newEntries uint32

		if globalScaleFactor > 0 {
			newEntries = oldEntries << uint32(globalScaleFactor)
			if newEntries < oldEntries {
				newEntries = MaxMapEntries
			}
		} else {
			newEntries = oldEntries >> uint32(-globalScaleFactor)
		}

		if newEntries < MinMapEntries && oldEntries >= MinMapEntries {
			newEntries = MinMapEntries
		}
		if newEntries > MaxMapEntries {
			newEntries = MaxMapEntries
		}

		mSpec.MaxEntries = newEntries
	}
}

// MissingConstantsError is returned by [ebpf.CollectionSpec.RewriteConstants].
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return "some constants are missing from .rodata: " + strings.Join(m.Constants, ", ")
}

// RewriteConstants replaces the value of multiple constants.
//
// The constant must be defined like so in the C program:
//
//	volatile const type foobar;
//	volatile const type foobar = default;
//
// Replacement values must be of the same length as the C sizeof(type).
// If necessary, they are marshaled according to the same rules as
// map values.
//
// From Linux 5.5 the verifier will use constants to eliminate dead code.
//
// Returns an error wrapping [MissingConstantsError] if a constant doesn't exist.
func RewriteConstants(cs *ebpf.CollectionSpec, consts map[string]any) error {
	var missing []string
	for n, c := range consts {
		v, ok := cs.Variables[n]
		if !ok {
			missing = append(missing, n)
			continue
		}

		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", n)
		}

		if err := v.Set(c); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", n, err)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %w", &MissingConstantsError{Constants: missing})
	}

	return nil
}
