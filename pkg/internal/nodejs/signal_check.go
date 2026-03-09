// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	sigusr1 = 10
	// Offset of the signum field within the uv_signal_s struct (libuv 1.x, x86-64).
	// This offset is stable across all libuv 1.x versions (used by Node.js 4.x through 22.x+).
	// Layout: UV_HANDLE_FIELDS (0x60) + uv_signal_cb (0x08) = 0x68.
	uvSignalSigNumOffset = 0x68
	// Offsets of the RB-tree left/right child pointers within uv_signal_s.
	// These are part of UV_SIGNAL_PRIVATE_FIELDS.tree_entry, which follows signum.
	uvSignalTreeLeftOffset  = 0x70
	uvSignalTreeRightOffset = 0x78
	// Maximum number of tree nodes to visit to prevent runaway reads.
	maxTreeNodes = 64
	// Maximum valid signal number (Linux).
	maxSignalNum = 64
)

// hasUserSIGUSR1Handler checks whether a Node.js process has a JavaScript-level
// SIGUSR1 handler registered (via process.on('SIGUSR1', ...)).
//
// It does this by reading libuv's internal uv__signal_tree (an RB-tree of active
// signal handles) from the process's memory. If any node in the tree has signum == 10,
// the process has a custom SIGUSR1 handler and it is NOT safe to send SIGUSR1.
//
// Returns true if a custom handler is detected, false if safe to proceed.
// Returns false on any error (fail-open: if we can't determine, attempt injection).
func hasUserSIGUSR1Handler(pid int, elfFile *elf.File) bool {
	treeAddr, err := findSymbolVAddr(elfFile, "uv__signal_tree")
	if err != nil {
		return false
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	mem, err := os.Open(memPath)
	if err != nil {
		return false
	}
	defer mem.Close()

	rootPtr, err := readPtr(mem, int64(treeAddr))
	if err != nil || rootPtr == 0 {
		return false
	}

	return walkTreeForSignal(mem, rootPtr, sigusr1)
}

// findSymbolVAddr looks up a symbol's virtual address in the ELF symbol tables.
func findSymbolVAddr(f *elf.File, name string) (uint64, error) {
	for _, lookup := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := lookup()
		if err != nil {
			if errors.Is(err, elf.ErrNoSymbols) {
				continue
			}
			return 0, err
		}
		for _, s := range syms {
			if s.Name == name && s.Value != 0 {
				return s.Value, nil
			}
		}
	}
	return 0, fmt.Errorf("symbol %q not found", name)
}

// walkTreeForSignal performs an iterative traversal of the libuv signal RB-tree
// looking for a node with the given signal number.
func walkTreeForSignal(mem *os.File, rootPtr uint64, signum int) bool {
	stack := []uint64{rootPtr}
	visited := make(map[uint64]struct{}, maxTreeNodes)

	for len(stack) > 0 && len(visited) < maxTreeNodes {
		nodeAddr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if nodeAddr == 0 {
			continue
		}
		if _, seen := visited[nodeAddr]; seen {
			continue
		}
		visited[nodeAddr] = struct{}{}

		nodeSigNum, err := readInt32(mem, int64(nodeAddr)+uvSignalSigNumOffset)
		if err != nil {
			return false
		}

		// Sanity check: signal numbers should be in [1, 64]
		if nodeSigNum < 1 || nodeSigNum > maxSignalNum {
			return false
		}

		if nodeSigNum == int32(signum) {
			return true
		}

		left, err := readPtr(mem, int64(nodeAddr)+uvSignalTreeLeftOffset)
		if err != nil {
			return false
		}
		right, err := readPtr(mem, int64(nodeAddr)+uvSignalTreeRightOffset)
		if err != nil {
			return false
		}

		if left != 0 {
			stack = append(stack, left)
		}
		if right != 0 {
			stack = append(stack, right)
		}
	}

	return false
}

func readPtr(f *os.File, offset int64) (uint64, error) {
	var buf [8]byte
	_, err := f.ReadAt(buf[:], offset)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

func readInt32(f *os.File, offset int64) (int32, error) {
	var buf [4]byte
	_, err := f.ReadAt(buf[:], offset)
	if err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(buf[:])), nil
}
