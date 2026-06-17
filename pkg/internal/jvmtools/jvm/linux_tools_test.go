// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import "testing"

func TestSemopRejectsEmptyOperations(t *testing.T) {
	if err := semop(0, nil); err == nil {
		t.Fatal("expected empty semop to fail")
	}
}
