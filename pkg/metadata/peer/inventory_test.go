// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	stdexec "os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
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
	updateProcesses(t.Context(), processes, exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})
	store := newStore("host", DefaultConfig())
	refreshInventory(t.Context(), processes, store)
	service := Service{Name: "idle-api", Namespace: "shop"}
	require.ElementsMatch(t, []Service{service}, store.services)
	require.Contains(t, store.listeners, Listener{
		Endpoint: Endpoint{IP: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}, Service: service,
	})
	updateProcesses(t.Context(), processes, exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: file})
	refreshInventory(t.Context(), processes, store)
	require.Empty(t, store.services)
	require.Empty(t, store.listeners)
	processes[processKey{pid: int32(pid), start: start + 1}] = file
	refreshInventory(t.Context(), processes, store)
	require.Empty(t, store.services)
}

func TestInventoryPollRefreshesAtStartup(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	file := exec.New(exec.Init{Pid: pid, StartTime: start, Service: svc.Attrs{
		UID: svc.UID{Name: "api", Namespace: "shop"}, Features: export.FeatureGraph,
	}})
	inventory := &processInventory{processes: map[processKey]*exec.FileInfo{{pid: int32(pid), start: start}: file}}
	store := newStore("host", DefaultConfig())
	store.graphEnabled = true
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		inventory.poll(ctx, store, time.Hour)
	}()
	t.Cleanup(func() { cancel(); <-done })
	endpoint := Endpoint{IP: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	service := Service{Name: "api", Namespace: "shop", ServiceGraph: true}
	require.Eventually(t, func() bool {
		resolved, match := store.destinationService(endpoint)
		return match == listenerUnique && resolved == service
	}, 2*time.Second, 10*time.Millisecond)
}

func TestInventoryRefreshesAfterProcessEvents(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	file := exec.New(exec.Init{Pid: pid, StartTime: start, Service: svc.Attrs{
		UID: svc.UID{Name: "api", Namespace: "shop"}, Features: export.FeatureGraph,
	}})
	store := newStore("host", DefaultConfig())
	store.graphEnabled = true
	ctx, cancel := context.WithCancel(t.Context())
	events := make(chan exec.ProcessEvent, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runInventory(ctx, events, store, time.Hour)
	}()
	t.Cleanup(func() { cancel(); <-done })
	events <- exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file}
	endpoint := Endpoint{IP: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port}
	service := Service{Name: "api", Namespace: "shop", ServiceGraph: true}
	require.Eventually(t, func() bool {
		resolved, match := store.destinationService(endpoint)
		return match == listenerUnique && resolved == service
	}, 2*time.Second, 10*time.Millisecond)
	events <- exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: file}
	require.Eventually(t, func() bool {
		snapshot := store.snapshot(nil, time.Now())
		return len(snapshot.Services) == 0 && len(snapshot.Listeners) == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestInventoryFindsChildOnlyListener(t *testing.T) {
	worker, address, stopWorker := startInventoryProcess(t, "listen", nil)
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	parent := exec.New(exec.Init{
		Pid: pid, StartTime: start,
		Service: svc.Attrs{UID: svc.UID{Name: "api", Namespace: "shop"}},
	})
	processes := map[processKey]*exec.FileInfo{}
	updateProcesses(t.Context(), processes, exec.ProcessEvent{Type: exec.ProcessEventCreated, File: parent})
	store := newStore("host", DefaultConfig())
	refreshInventory(t.Context(), processes, store)
	endpoint, err := netip.ParseAddrPort(address)

	require.NoError(t, err)
	require.Contains(t, store.listeners, Listener{
		Endpoint: Endpoint{IP: endpoint.Addr().String(), Port: int(endpoint.Port())},
		Service:  Service{Name: "api", Namespace: "shop"},
	})

	stopWorker()
	updateProcesses(t.Context(), processes, exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: worker})
	refreshInventory(t.Context(), processes, store)
	require.Empty(t, store.listeners)
	require.Equal(t, []Service{{Name: "api", Namespace: "shop"}}, store.services)
}

func TestInventoryRetainsWorkerListenerAfterParentTermination(t *testing.T) {
	for _, terminationEvent := range []bool{true, false} {
		name := "termination event"
		if !terminationEvent {
			name = "polling expiration"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			inherited, err := listener.(*net.TCPListener).File()
			require.NoError(t, err)
			t.Cleanup(func() { _ = inherited.Close() })
			worker, _, stopWorker := startInventoryProcess(t, "inherited", []*os.File{inherited})
			pid := app.PID(os.Getpid())
			start, err := procs.StartTime(pid)
			require.NoError(t, err)
			parent := exec.New(exec.Init{
				Pid: pid, StartTime: start,
				Service: svc.Attrs{UID: svc.UID{Name: "api", Namespace: "shop"}},
			})
			processes := map[processKey]*exec.FileInfo{}
			updateProcesses(t.Context(), processes, exec.ProcessEvent{Type: exec.ProcessEventCreated, File: parent})
			require.Same(t, parent, processes[processKey{pid: int32(worker.Pid()), start: worker.StartTime()}])
			store := newStore("host", DefaultConfig())
			refreshInventory(t.Context(), processes, store)
			expected := Listener{
				Endpoint: Endpoint{IP: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port},
				Service:  Service{Name: "api", Namespace: "shop"},
			}
			require.ElementsMatch(t, []Listener{expected}, store.listeners)

			require.NoError(t, listener.Close())
			require.NoError(t, inherited.Close())
			if terminationEvent {
				updateProcesses(t.Context(), processes, exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: parent})
			} else {
				delete(processes, processKey{pid: int32(pid), start: start})
				processes[processKey{pid: int32(pid), start: start + 1}] = parent
			}
			refreshInventory(t.Context(), processes, store)
			require.Equal(t, []Service{expected.Service}, store.services)
			require.ElementsMatch(t, []Listener{expected}, store.listeners)

			stopWorker()
			updateProcesses(t.Context(), processes, exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: worker})
			refreshInventory(t.Context(), processes, store)
			require.Empty(t, store.services)
			require.Empty(t, store.listeners)
		})
	}
}

func TestInventoryProcess(t *testing.T) {
	mode := os.Getenv("OBI_PEER_INVENTORY_TEST_PROCESS")
	if mode == "" {
		return
	}

	var listener net.Listener
	var err error
	switch mode {
	case "listen":
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	case "inherited":
		file := os.NewFile(3, "listener")
		listener, err = net.FileListener(file)
		require.NoError(t, file.Close())
	}
	require.NoError(t, err)
	address := "ready"
	if listener != nil {
		defer listener.Close()
		address = listener.Addr().String()
	}
	_, err = fmt.Fprintln(os.Stdout, address)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, os.Stdin)
	require.NoError(t, err)
}

func startInventoryProcess(t *testing.T, mode string, files []*os.File) (*exec.FileInfo, string, func()) {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	t.Cleanup(cancel)
	command := stdexec.CommandContext(ctx, executable, "-test.run=^TestInventoryProcess$")
	command.Env = append(os.Environ(), "OBI_PEER_INVENTORY_TEST_PROCESS="+mode)
	command.ExtraFiles = files
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	require.NoError(t, err)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		require.NoError(t, input.Close())
		require.NoError(t, command.Wait())
	}
	t.Cleanup(stop)
	address, err := bufio.NewReader(output).ReadString('\n')
	require.NoError(t, err)
	pid := app.PID(command.Process.Pid)
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	file := exec.New(exec.Init{
		Pid: pid, StartTime: start,
		Service: svc.Attrs{UID: svc.UID{Name: "api", Namespace: "shop"}},
	})
	return file, strings.TrimSpace(address), stop
}

func TestInventoryServiceGraphParticipation(t *testing.T) {
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	traceOnly := services.NewExportModes()
	traceOnly.AllowTraces()
	for _, test := range []struct {
		name     string
		enabled  bool
		features export.Features
		modes    services.ExportModes
		graph    bool
	}{
		{name: "no metrics exporter", features: export.FeatureAll},
		{name: "graph feature disabled", enabled: true, features: export.FeatureSpanOTel},
		{name: "metrics disabled for service", enabled: true, features: export.FeatureAll, modes: traceOnly},
		{name: "graph feature enabled", enabled: true, features: export.FeatureGraph, graph: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			attrs := svc.Attrs{UID: svc.UID{Name: "api", Namespace: "shop"}, Features: test.features, ExportModes: test.modes}
			file := exec.New(exec.Init{Pid: pid, StartTime: start, Service: attrs})
			processes := map[processKey]*exec.FileInfo{{pid: int32(pid), start: start}: file}
			store := newStore("host", DefaultConfig())
			store.graphEnabled = test.enabled
			refreshInventory(t.Context(), processes, store)
			snapshot := store.snapshot(nil, time.Now())
			require.Equal(t, []Service{{Name: "api", Namespace: "shop", ServiceGraph: test.graph}}, snapshot.Services)
		})
	}
}

func TestDualStackListenerResolvesIPv4(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)
	if address.IP.String() != "::" {
		t.Skip("dual-stack listener unavailable")
	}
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(address.Port)), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	file := exec.New(exec.Init{Pid: pid, StartTime: start, Service: svc.Attrs{UID: svc.UID{Name: "api", Namespace: "shop"}}})
	processes := map[processKey]*exec.FileInfo{{pid: int32(pid), start: start}: file}
	store := newStore("host", DefaultConfig())
	refreshInventory(t.Context(), processes, store)
	service := Service{Name: "api", Namespace: "shop"}
	require.Contains(t, store.listeners, Listener{
		Endpoint: Endpoint{IP: "::", Port: address.Port}, Service: service,
	})
	endpoint := Endpoint{IP: "127.0.0.1", Port: address.Port}
	resolved, match := store.destinationService(endpoint)
	require.Equal(t, listenerUnique, match)
	require.Equal(t, service, resolved)
	snapshot := store.snapshot(nil, time.Now())
	resolved, match = indexSnapshot(&snapshot).destinationService(endpoint)
	require.Equal(t, listenerUnique, match)
	require.Equal(t, service, resolved)
}
