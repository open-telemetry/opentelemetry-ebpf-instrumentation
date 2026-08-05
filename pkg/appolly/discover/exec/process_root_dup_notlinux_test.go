// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package exec

import (
	"os"
	"testing"
)

func TestDuplicateProcessRootFailsClosed(t *testing.T) {
	original, err := os.CreateTemp(t.TempDir(), "process-root-*")
	if err != nil {
		t.Fatal(err)
	}
	fileInfo := New(Init{ProcessRoot: original})

	if duplicate := fileInfo.DuplicateProcessRoot(); duplicate != nil {
		_ = duplicate.Close()
		t.Fatal("DuplicateProcessRoot returned a descriptor on an unsupported platform")
	}
	if err := fileInfo.CloseProcessRoot(); err != nil {
		t.Fatal(err)
	}
}
