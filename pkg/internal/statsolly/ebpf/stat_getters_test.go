// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestTCPResetCauseIsOmittedWhenNotInferred(t *testing.T) {
	otelGetter, ok := StatGetters(attr.NetworkTCPResetCause)
	require.True(t, ok)
	promGetter, ok := StatStringGetters(attr.NetworkTCPResetCause)
	require.True(t, ok)

	for _, tc := range []struct {
		name string
		stat *Stat
		want string
	}{
		{name: "application", stat: resetStat(CodeResetCauseApplication), want: "application"},
		{name: "timeout", stat: resetStat(CodeResetCauseTimeout), want: "timeout"},
		{name: "not inferred", stat: resetStat(CodeResetCauseUnknown)},
		{name: "not a reset", stat: &Stat{Type: StatTypeTCPRetransmit, TCPRetransmit: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == "" {
				assert.Equal(t, attribute.KeyValue{}, otelGetter(tc.stat))
			} else {
				assert.Equal(t, attribute.String(string(attr.NetworkTCPResetCause), tc.want), otelGetter(tc.stat))
			}
			assert.Equal(t, tc.want, promGetter(tc.stat))
		})
	}
}

func resetStat(cause TCPResetCauseCode) *Stat {
	return &Stat{
		Type: StatTypeTCPReset,
		TCPReset: &TCPReset{
			Direction: uint8(CodeDirectionTransmit),
			Cause:     uint8(cause),
		},
	}
}
