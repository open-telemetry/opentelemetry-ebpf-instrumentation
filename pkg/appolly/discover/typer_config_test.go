// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/convert"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestMakeServiceAttrsExceptionDefaultInclude(t *testing.T) {
	enabled, disabled := true, false
	for _, regex := range []bool{false, true} {
		kind := "glob"
		match := schema.RuleProcessMatch{ExePathGlob: []string{"/srv/app"}}
		if regex {
			kind = "regex"
			match = schema.RuleProcessMatch{ExePathRegex: "^/srv/app$"}
		}
		for _, order := range []schema.MatchOrder{schema.MatchOrderFirstMatchWins, schema.MatchOrderLastMatchWins} {
			for _, tc := range []struct {
				name      string
				global    bool
				overrides []*bool
			}{
				{name: "selective enable", overrides: []*bool{&enabled}},
				{name: "explicit disable", global: true, overrides: []*bool{&disabled}},
				{name: "overlapping overrides", overrides: []*bool{&enabled, &disabled}},
				{name: "first omission", global: true, overrides: []*bool{nil, &disabled}},
				{name: "last omission", global: true, overrides: []*bool{&disabled, nil}},
			} {
				t.Run(kind+"/"+string(order)+"/"+tc.name, func(t *testing.T) {
					rules := make([]schema.Rule, 0, len(tc.overrides))
					for _, override := range tc.overrides {
						rule := schema.Rule{
							Action: schema.CaptureActionInclude,
							Match:  schema.RuleMatch{Process: match},
						}
						if override != nil {
							rule.Refine.Exceptions = &services.ExceptionsOverride{Enabled: override}
						}
						rules = append(rules, rule)
					}
					cfg, err := convert.V2ToRuntime(&schema.Extension{
						Version: schema.SupportedVersion,
						Capture: schema.Capture{
							Policy: schema.CapturePolicy{
								DefaultAction: schema.CaptureActionInclude,
								MatchOrder:    order,
							},
							Exceptions: services.ExceptionsConfig{Enabled: tc.global},
							Rules:      rules,
						},
					})
					require.NoError(t, err)
					cfg.Logs.Endpoint = "http://localhost:4318/v1/logs"

					winner := tc.overrides[0]
					if order == schema.MatchOrderLastMatchWins {
						winner = tc.overrides[len(tc.overrides)-1]
					}
					want := tc.global
					if winner != nil {
						want = *winner
					}
					for _, path := range []string{"/srv/app", "/srv/other"} {
						process := &services.ProcessInfo{Pid: 1234, ExePath: path}
						got := discover.SelectedServiceAttrsForTest(cfg, process)
						require.NotNil(t, got)
						if path == "/srv/other" {
							require.Equal(t, tc.global, got.Exceptions.Enabled, "fallback-only match")
						} else {
							require.Equal(t, want, got.Exceptions.Enabled, "explicit rule match")
						}
					}
				})
			}
		}
	}
}
