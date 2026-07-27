// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"runtime"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestFindINodeForPID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping FindINodeForPID test on non-linux platform")
	}

	// Use our own PID — guaranteed to exist and have a valid /proc/<pid>/exe
	self := app.PID(os.Getpid())

	dev, ino, err := FindINodeForPID(self)
	if err != nil {
		t.Fatalf("FindINodeForPID(%d) returned error: %v", self, err)
	}
	if dev == 0 {
		t.Errorf("FindINodeForPID(%d) returned dev 0, expected a non-zero device", self)
	}
	if ino == 0 {
		t.Errorf("FindINodeForPID(%d) returned inode 0, expected a non-zero inode", self)
	}

	// A non-existent PID should return an error
	_, _, err = FindINodeForPID(app.PID(999999999))
	if err == nil {
		t.Error("FindINodeForPID with invalid PID should return an error")
	}
}
