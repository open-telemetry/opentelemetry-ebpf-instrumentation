// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

// tracked_sock_cookies mirrors sock_dir membership one-to-one and sockhashes
// are not resizable: scaling the shadow map below the sockhash guarantees
// eviction of live sockets' cookies, silently disarming the FIONREAD fixup
func TestScaleDownKeepsTrackedSockCookiesAtSockDirSize(t *testing.T) {
	const sockDirSize = 65535

	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"sock_dir": {
				Type:       ebpf.SockHash,
				KeySize:    8,
				ValueSize:  4,
				MaxEntries: sockDirSize,
			},
			"tracked_sock_cookies": {
				Type:       ebpf.LRUHash,
				KeySize:    8,
				ValueSize:  1,
				MaxEntries: sockDirSize,
			},
			"other_lru": {
				Type:       ebpf.LRUHash,
				KeySize:    8,
				ValueSize:  8,
				MaxEntries: 1024,
			},
		},
	}

	cfg := &obi.Config{}
	cfg.EBPF.MapsConfig = config.MapsConfig{GlobalScaleFactor: -1}
	setupBPFMapSizes(spec, cfg)

	assert.Equal(t, uint32(sockDirSize), spec.Maps["sock_dir"].MaxEntries,
		"sockhashes are not resizable")
	assert.Equal(t, uint32(sockDirSize), spec.Maps["tracked_sock_cookies"].MaxEntries,
		"the shadow map must never be smaller than the sockhash it mirrors")
	assert.Equal(t, uint32(512), spec.Maps["other_lru"].MaxEntries,
		"unrelated maps still scale")
}

// scaling up is harmless for the pairing: a larger shadow map is a superset
func TestScaleUpStillScalesTrackedSockCookies(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"tracked_sock_cookies": {
				Type:       ebpf.LRUHash,
				KeySize:    8,
				ValueSize:  1,
				MaxEntries: 65535,
			},
		},
	}

	cfg := &obi.Config{}
	cfg.EBPF.MapsConfig = config.MapsConfig{GlobalScaleFactor: 1}
	setupBPFMapSizes(spec, cfg)

	assert.Equal(t, uint32(131070), spec.Maps["tracked_sock_cookies"].MaxEntries)
}

func TestRuntimeAllocatedHashMapsAllowedFromKernel61(t *testing.T) {
	assert.False(t, runtimeAllocatedHashMapsAllowed(0, 0), "unknown kernel")
	assert.False(t, runtimeAllocatedHashMapsAllowed(4, 18))
	assert.False(t, runtimeAllocatedHashMapsAllowed(5, 15))
	assert.False(t, runtimeAllocatedHashMapsAllowed(6, 0))
	assert.True(t, runtimeAllocatedHashMapsAllowed(6, 1))
	assert.True(t, runtimeAllocatedHashMapsAllowed(7, 0))
}

func TestPreallocateHashMapsOnlyTouchesHashMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"hash":        {Type: ebpf.Hash, Flags: unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG},
			"percpu_hash": {Type: ebpf.PerCPUHash, Flags: unix.BPF_F_NO_PREALLOC},
			"sk_storage":  {Type: ebpf.SkStorage, Flags: unix.BPF_F_NO_PREALLOC},
			"lpm_trie":    {Type: ebpf.LPMTrie, Flags: unix.BPF_F_NO_PREALLOC},
		},
	}

	preallocateHashMaps(spec)

	assert.Equal(t, uint32(unix.BPF_F_RDONLY_PROG), spec.Maps["hash"].Flags, "other flags are kept")
	assert.Zero(t, spec.Maps["percpu_hash"].Flags)
	assert.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), spec.Maps["sk_storage"].Flags,
		"socket storage requires BPF_F_NO_PREALLOC")
	assert.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), spec.Maps["lpm_trie"].Flags,
		"LPM tries require BPF_F_NO_PREALLOC")
}
