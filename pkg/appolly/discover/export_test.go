// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/obi"
)

func SelectedServiceAttrsForTest(cfg *obi.Config, process *services.ProcessInfo) *svc.Attrs {
	previous := processInfo
	processInfo = func(ProcessAttrs) (*services.ProcessInfo, error) { return process, nil }
	defer func() { processInfo = previous }()

	matcher := Matcher{
		Log: slog.Default(), Criteria: FindingCriteria(cfg),
		ProcessHistory: map[app.PID]ProcessMatch{},
	}
	matched := matcher.filter([]Event[ProcessAttrs]{{Type: EventCreated, Obj: ProcessAttrs{pid: process.Pid}}})
	if len(matched) == 0 {
		return nil
	}
	ty := typer{cfg: cfg}
	attrs := ty.makeServiceAttrs(&matched[0].Obj)
	return &attrs
}
