// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
)

// InjectionTarget is everything the injector reads about a process. Callers
// copy these values out of the Instrumentable up front, so injection can run
// concurrently with the rest of the discovery pipeline without sharing that
// object.
type InjectionTarget struct {
	Type svc.InstrumentableType
	Pid  app.PID
	// TempDirEnv is the process' TMPDIR, empty when it does not set one.
	TempDirEnv string
}

func InjectionTargetFrom(ie *ebpf.Instrumentable) InjectionTarget {
	return InjectionTarget{
		Type:       ie.Type,
		Pid:        ie.FileInfo.Pid(),
		TempDirEnv: ie.FileInfo.ServiceAttrs().EnvVars["TMPDIR"],
	}
}
