// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// The SQL branch is a separate emission path from the two HTTP ones, so its
// exclusion needs asserting on its own.
func TestTraceAttributesSelector_DBQuerySummaryIsExcludable(t *testing.T) {
	span := &request.Span{
		Type: request.EventTypeSQLClient, Method: "SELECT", Path: "users",
		DBSystem: "postgresql", DBQuerySummary: "SELECT users",
	}

	t.Run("present by default", func(t *testing.T) {
		v, ok := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), "db.query.summary")
		require.True(t, ok)
		assert.Equal(t, "SELECT users", v.AsString())
	})

	t.Run("excluded by selection", func(t *testing.T) {
		selected, err := UserSelectedAttributes(&attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{
				attributes.Traces.Section: attributes.InclusionLists{
					Exclude: []string{string(attr.DBQuerySummary)},
				},
			},
		})
		require.NoError(t, err)

		_, ok := attrValue(TraceAttributesSelector(span, selected), "db.query.summary")
		assert.False(t, ok)
	})
}
