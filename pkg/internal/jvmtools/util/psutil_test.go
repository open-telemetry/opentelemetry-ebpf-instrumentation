// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package util

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestNamespaceFlag(t *testing.T) {
	tests := []struct {
		name string
		want int
		ok   bool
	}{
		{name: "net", want: unix.CLONE_NEWNET, ok: true},
		{name: "ipc", want: unix.CLONE_NEWIPC, ok: true},
		{name: "mnt", want: unix.CLONE_NEWNS, ok: true},
		{name: "pid", ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := namespaceFlag(test.name)
			if ok != test.ok {
				t.Fatalf("namespaceFlag(%q) ok = %v, want %v", test.name, ok, test.ok)
			}
			if got != test.want {
				t.Fatalf("namespaceFlag(%q) = %d, want %d", test.name, got, test.want)
			}
		})
	}
}
