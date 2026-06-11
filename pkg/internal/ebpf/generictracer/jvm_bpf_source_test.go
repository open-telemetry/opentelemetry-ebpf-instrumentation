// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package generictracer

import (
	"os"
	"strings"
	"testing"
)

func TestJVMHeapSummaryBPFUsesNamespaceTID(t *testing.T) {
	source, err := os.ReadFile("../../../../bpf/generictracer/jvm.c")
	if err != nil {
		t.Fatal(err)
	}

	text := string(source)
	if strings.Contains(text, "e->ns_tid = e->ns_pid;") {
		t.Fatal("JVM heap summary BPF must not copy namespace TGID into namespace TID")
	}
	if !strings.Contains(text, "e->ns_tid = get_task_tid();") {
		t.Fatal("JVM heap summary BPF must populate namespace TID with get_task_tid()")
	}
}
