// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

func TestHTTPRequestTraceToSpan_QueryRedaction(t *testing.T) {
	p := [100]uint8{}
	copy(p[:], "/search")
	q := [100]uint8{}
	copy(q[:], "q=hello&sig=secret")

	tr := ebpfcommon.HTTPRequestTrace{Type: 1, Path: p, RawQuery: q, Status: 200}
	s := ebpfcommon.HTTPRequestTraceToSpan(nil, &tr)

	defaultAttrs, err := tracesgen.UserSelectedAttributes(&attributes.SelectorConfig{})
	require.NoError(t, err)

	selected := tracesgen.AttrsToMap(tracesgen.TraceAttributesSelector(&s, defaultAttrs, "sig"))
	val, ok := selected.Get("url.query")
	require.True(t, ok)
	assert.Equal(t, "q=hello&sig=REDACTED", val.Str())
}
