// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// to be changed in tests
var processStartTime = procs.StartTime

// InjectionTarget is everything the injector reads about a process. Callers
// copy these values out of the Instrumentable up front, so injection can run
// concurrently with the rest of the discovery pipeline without sharing that
// object.
type InjectionTarget struct {
	Type svc.InstrumentableType
	Pid  app.PID
	// TempDirEnv is the process' TMPDIR, empty when it does not set one.
	TempDirEnv string
	// StartTime pins the target to one incarnation of Pid. Injection is queued
	// by numeric PID and can run long after discovery saw the process, so the
	// kernel may have recycled that PID for an unrelated program in the
	// meantime. Zero when the start time could not be read, in which case the
	// target cannot be identified and injection refuses it.
	StartTime uint64
}

func InjectionTargetFrom(ie *ebpf.Instrumentable) InjectionTarget {
	pid := ie.FileInfo.Pid()

	// A failure here means the process is already gone or /proc is unreadable.
	// StartTime stays zero, which the injector treats as an unidentifiable
	// target and refuses.
	startTime, _ := processStartTime(pid)

	return InjectionTarget{
		Type:       ie.Type,
		Pid:        pid,
		TempDirEnv: ie.FileInfo.ServiceAttrs().EnvVars["TMPDIR"],
		StartTime:  startTime,
	}
}
