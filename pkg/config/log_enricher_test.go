// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogEnricherConfigValidate(t *testing.T) {
	t.Parallel()

	valid := LogEnricherConfig{
		FieldNames: LogEnricherFieldNames{
			TraceID: "trace.id",
			SpanID:  "span.id",
		},
		PlainText: LogEnricherPlainTextConfig{
			Enabled:   true,
			Placement: LogEnricherPlacementSuffix,
			Multiline: LogEnricherMultilineFirstLine,
		},
	}
	require.NoError(t, valid.Validate())

	tests := []struct {
		name   string
		mutate func(*LogEnricherConfig)
	}{
		{name: "empty trace field", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.TraceID = "" }},
		{name: "empty span field", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.SpanID = "" }},
		{name: "duplicate fields", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.SpanID = cfg.FieldNames.TraceID }},
		{name: "whitespace", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.TraceID = "trace id" }},
		{name: "equals", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.TraceID = "trace=id" }},
		{name: "control", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.TraceID = "trace\x00id" }},
		{name: "C1 control", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.TraceID = "trace\u0080id" }},
		{name: "Unicode whitespace", mutate: func(cfg *LogEnricherConfig) { cfg.FieldNames.TraceID = "trace\u1680id" }},
		{name: "invalid placement", mutate: func(cfg *LogEnricherConfig) { cfg.PlainText.Placement = "middle" }},
		{name: "invalid multiline", mutate: func(cfg *LogEnricherConfig) { cfg.PlainText.Multiline = "logical_event" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := valid
			test.mutate(&cfg)

			require.Error(t, cfg.Validate())
		})
	}
}
