// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package exec

import (
	"os"
	"testing"
)

func TestDuplicateProcessRootOwnsIndependentDescriptor(t *testing.T) {
	original, err := os.CreateTemp(t.TempDir(), "process-root-*")
	if err != nil {
		t.Fatal(err)
	}
	fileInfo := New(Init{ProcessRoot: original})

	duplicate := fileInfo.DuplicateProcessRoot()
	if duplicate == nil {
		t.Fatal("DuplicateProcessRoot returned nil")
	}
	if err := fileInfo.CloseProcessRoot(); err != nil {
		t.Fatal(err)
	}
	if _, err := duplicate.Stat(); err != nil {
		t.Fatalf("duplicate descriptor closed with original: %v", err)
	}
	if err := duplicate.Close(); err != nil {
		t.Fatal(err)
	}
}
