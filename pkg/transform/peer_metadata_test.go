// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestPeerMetadataBypass(t *testing.T) {
	for _, kubernetes := range []bool{false, true} {
		cfg := peer.Config{Enabled: kubernetes, Port: -1}
		info := &global.ContextInfo{}
		if kubernetes {
			info.K8sInformer = kube.NewMetadataProvider(kube.MetadataConfig{Enable: kubeflags.EnabledTrue}, imetrics.NoopReporter{})
		}
		input, output := msg.NewQueue[[]request.Span](), msg.NewQueue[[]request.Span]()
		result := output.Subscribe()
		run, err := PeerMetadataProvider(info, cfg, config.InstanceIDConfig{}, false, nil, input, output)(t.Context())
		require.NoError(t, err)
		go run(t.Context())
		input.Send([]request.Span{{HostName: "existing"}})
		require.Equal(t, "existing", (<-result)[0].HostName)
		input.Close()
	}
}

func TestPeerMetadataPipelineEnrichmentAndShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	metadataSocket, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg := peer.DefaultConfig()
	cfg.Enabled, cfg.ListenAddress = true, "127.0.0.1"
	cfg.PeerCIDRs = []string{"127.0.0.0/8"}
	cfg.Port = metadataSocket.Addr().(*net.TCPAddr).Port
	cfg.RefreshInterval = 20 * time.Millisecond
	require.NoError(t, metadataSocket.Close())
	input, output := msg.NewQueue[[]request.Span](), msg.NewQueue[[]request.Span]()
	events := msg.NewQueue[exec.ProcessEvent]()
	result := output.Subscribe()
	run, err := PeerMetadataProvider(&global.ContextInfo{}, cfg,
		config.InstanceIDConfig{OverrideHostname: "local-host"}, false, events, input, output)(t.Context())
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { defer close(done); run(t.Context()) }()
	pid := app.PID(os.Getpid())
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	file := exec.New(exec.Init{Pid: pid, StartTime: start, Service: svc.Attrs{UID: svc.UID{Name: "api", Namespace: "shop"}}})
	events.Send(exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	url := "http://127.0.0.1:" + strconv.Itoa(cfg.Port) + peer.MetadataPath
	require.Eventually(t, func() bool {
		response, err := client.Get(url)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		var snapshot peer.Snapshot
		return json.NewDecoder(response.Body).Decode(&snapshot) == nil && len(snapshot.Services) == 1
	}, 2*time.Second, 20*time.Millisecond)
	input.Send([]request.Span{{Type: request.EventTypeHTTPClient, Host: "127.0.0.1", HostPort: listener.Addr().(*net.TCPAddr).Port, HostName: "dns-name"}})
	select {
	case spans := <-result:
		require.Equal(t, "api", spans[0].HostName)
		require.Equal(t, "shop", spans[0].OtherNamespace)
	case <-time.After(time.Second):
		t.Fatal("enriched span was not forwarded")
	}
	input.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("metadata stage did not stop")
	}
	_, ok := <-result
	require.False(t, ok)
	reopened, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port)))
	require.NoError(t, err)
	reopened.Close()
}
