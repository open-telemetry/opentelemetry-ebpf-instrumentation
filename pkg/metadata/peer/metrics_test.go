// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
)

func TestInventoryTracksDynamicMetricsSelection(t *testing.T) {
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)

	for _, test := range []struct {
		name  string
		owner app.PID
	}{
		{name: "process PID"},
		{name: "inherited selection", owner: 42},
	} {
		t.Run(test.name, func(t *testing.T) {
			selectedPID := test.owner
			if selectedPID == 0 {
				selectedPID = pid
			}
			selector := discover.NewDynamicSelector()
			selector.Traces().AddPIDs(uint32(selectedPID))
			if selectedPID != pid {
				selector.AppMetrics().AddPIDs(uint32(pid))
			}
			socket, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			cfg := peer.DefaultConfig()
			cfg.Enabled, cfg.ListenAddress = true, "127.0.0.1"
			cfg.PeerCIDRs = []string{"127.0.0.0/8"}
			cfg.Port = socket.Addr().(*net.TCPAddr).Port
			cfg.RefreshInterval = 20 * time.Millisecond
			require.NoError(t, socket.Close())
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			agent, err := peer.New(ctx, cfg, "host", true, selector.AppMetrics())
			require.NoError(t, err)
			events := make(chan exec.ProcessEvent, 1)
			done := make(chan struct{})
			go func() { defer close(done); agent.Run(ctx, events) }()
			t.Cleanup(func() { cancel(); <-done })
			file := exec.New(exec.Init{Pid: pid, StartTime: start, Service: svc.Attrs{
				UID: svc.UID{Name: "api", Namespace: "shop"}, ProcPID: pid,
				DynamicSelectorPID: test.owner, Features: export.FeatureGraph,
			}})
			events <- exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file}
			client := &http.Client{Timeout: time.Second}
			t.Cleanup(client.CloseIdleConnections)
			endpoint := "http://127.0.0.1:" + strconv.Itoa(cfg.Port) + peer.MetadataPath
			waitForParticipation := func(enabled bool) {
				t.Helper()
				expected := peer.Service{Name: "api", Namespace: "shop", ServiceGraph: enabled}
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					resp, err := client.Get(endpoint)
					require.NoError(ct, err)
					defer resp.Body.Close()
					var snapshot peer.Snapshot
					require.NoError(ct, json.NewDecoder(resp.Body).Decode(&snapshot))
					assert.Equal(ct, []peer.Service{expected}, snapshot.Services)
				}, time.Second, 20*time.Millisecond)
			}
			waitForParticipation(false)
			selector.AppMetrics().AddPIDs(uint32(selectedPID))
			waitForParticipation(true)
			selector.AppMetrics().RemovePIDs(uint32(selectedPID))
			waitForParticipation(false)
		})
	}
}
