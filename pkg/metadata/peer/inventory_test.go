// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestIdleInstrumentedListenerInventory(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	file := exec.New(exec.Init{Pid: pid, StartTime: start, Service: svc.Attrs{UID: svc.UID{Name: "idle-api", Namespace: "shop"}}})
	processes := map[processKey]*exec.FileInfo{}
	updateProcesses(processes, exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})
	store := newStore("host", DefaultConfig())
	refreshInventory(t.Context(), processes, store)
	service := Service{Name: "idle-api", Namespace: "shop"}
	require.ElementsMatch(t, []Service{service}, store.services)
	require.Contains(t, store.listeners, Listener{
		Endpoint: Endpoint{IP: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, Service: service,
	})
	updateProcesses(processes, exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: file})
	refreshInventory(t.Context(), processes, store)
	require.Empty(t, store.services)
	require.Empty(t, store.listeners)
	processes[processKey{pid: int32(pid), start: start + 1}] = file
	refreshInventory(t.Context(), processes, store)
	require.Empty(t, store.services)
}
