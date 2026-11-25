// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestRunWithContextInfoMarksExternalSpanExport(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
		want bool
	}{
		{name: "default export queue", want: false},
		{
			name: "overridden export queue",
			opts: []Option{OverrideAppExportQueue(msg.NewQueue[[]request.Span]())},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// no features enabled: Run applies the options and returns without starting a pipeline
			cfg := &obi.Config{}
			require.False(t, cfg.Enabled(obi.FeatureAppO11y))
			ctxInfo := &global.ContextInfo{}

			require.NoError(t, RunWithContextInfo(t.Context(), cfg, ctxInfo, tc.opts...))

			assert.Equal(t, tc.want, ctxInfo.ExternalSpanExport)
		})
	}
}
