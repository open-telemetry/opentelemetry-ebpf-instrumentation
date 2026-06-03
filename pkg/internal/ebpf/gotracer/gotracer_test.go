// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/config"
)

func TestGoChannelSpanLinkProbeGate(t *testing.T) {
	const ino = uint64(42)

	for _, tt := range []struct {
		name       string
		cfgEnabled bool
		haveOffset bool
		wantProbe  bool
	}{
		{
			name:       "disabled config skips probes even with offsets",
			cfgEnabled: false,
			haveOffset: true,
			wantProbe:  false,
		},
		{
			name:       "enabled config skips probes without offsets",
			cfgEnabled: true,
			haveOffset: false,
			wantProbe:  false,
		},
		{
			name:       "enabled config and offsets attaches probes",
			cfgEnabled: true,
			haveOffset: true,
			wantProbe:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &Tracer{
				log:                     slog.Default(),
				cfg:                     &config.EBPFTracer{GoChannelSpanLinks: tt.cfgEnabled},
				currentBinaryIno:        ino,
				channelLinkOffsetsByIno: map[uint64]bool{ino: tt.haveOffset},
			}

			probes := tracer.GoProbes()
			_, haveSendProbe := probes["runtime.chansend1"]
			_, haveRecv1Probe := probes["runtime.chanrecv1"]
			_, haveRecv2Probe := probes["runtime.chanrecv2"]

			assert.Equal(t, tt.wantProbe, haveSendProbe)
			assert.Equal(t, tt.wantProbe, haveRecv1Probe)
			assert.Equal(t, tt.wantProbe, haveRecv2Probe)
		})
	}
}
