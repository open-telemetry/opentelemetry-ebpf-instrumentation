// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/obi"
)

func SelectedServiceAttrsForTest(cfg *obi.Config, process *services.ProcessInfo) *svc.Attrs {
	matcher := Matcher{Log: slog.Default(), Criteria: FindingCriteria(cfg)}
	matched := matcher.matchCriteria(ProcessAttrs{}, process)
	if matched == nil {
		return nil
	}
	ty := typer{cfg: cfg}
	attrs := ty.makeServiceAttrs(matched)
	return &attrs
}
