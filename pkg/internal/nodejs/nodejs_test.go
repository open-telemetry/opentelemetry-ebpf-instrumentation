// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/obi"
)

// nodejs.enabled is the global injection opt-out: with the flag off the
// injector stays disabled even when the application_runtime feature would
// otherwise trigger the agent for runtime metrics.
func TestEnabledFlagDisablesInjectionEntirely(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = false
	cfg.Metrics.Features = export.FeatureApplicationRuntime
	require.False(t, NewNodeInjector(&cfg, nil).Enabled())

	cfg.NodeJS.Enabled = true
	require.True(t, NewNodeInjector(&cfg, nil).Enabled())
}

func TestAcceptsSkipsDeno(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.TracePrinter = debug.TracePrinterText

	injector := NewNodeInjector(&cfg, nil)
	require.True(t, injector.Enabled())
	require.False(t, injector.Accepts(&ebpf.Instrumentable{Type: svc.InstrumentableDeno}))
	require.True(t, injector.Accepts(&ebpf.Instrumentable{Type: svc.InstrumentableNodejs}))
}

// conversationLog records, in order, what the injector tracked and what the
// inspector was asked
type conversationLog struct {
	mu             sync.Mutex
	events         []string
	ns             uint32
	client, server netip.AddrPort
}

func (l *conversationLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *conversationLog) track(ns uint32, client, server netip.AddrPort) func() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ns, l.client, l.server = ns, client, server
	l.events = append(l.events, "track")
	return func() { l.add("release") }
}

// fakeInspector answers the injector as a Node.js inspector does, or with 404s
// when it is some other server, and points the injector at itself
func fakeInspector(t *testing.T, isInspector bool, log *conversationLog) netip.AddrPort {
	t.Helper()

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.RemoteAddr + " " + r.URL.Path)

		switch {
		case !isInspector:
			http.NotFound(w, r)
		case r.URL.Path == "/json/version":
			_, _ = w.Write([]byte(`{"Browser":"node.js/v26.0.0"}`))
		case r.URL.Path == "/json/list":
			_ = json.NewEncoder(w).Encode([]inspectorTarget{{WebSocketDebuggerURL: "ws://127.0.0.1:9229/target"}})
		default:
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()

			var req cdpRequest
			if conn.ReadJSON(&req) == nil {
				_ = conn.WriteJSON(cdpResponse{ID: req.ID})
			}
		}
	}))
	t.Cleanup(srv.Close)

	addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
	oldAddr, oldPort := inspectorAddr, inspectorPort
	inspectorAddr, inspectorPort = addr.Addr().String(), int(addr.Port())
	t.Cleanup(func() { inspectorAddr, inspectorPort = oldAddr, oldPort })

	return addr
}

// The target is instrumented before it is injected, so the injector's whole
// conversation must be tracked, from before its first request to after its last
func TestInjectorTracksItsInspectorConnection(t *testing.T) {
	for _, tc := range []struct {
		name        string
		isInspector bool
		signaled    bool
		wantPaths   []string
	}{
		{"inspector", true, false, []string{"/json/version", "/json/list", "/target"}},
		{"not an inspector", false, false, []string{"/json/version"}},
		{"inspector opened by SIGUSR1", true, true, []string{"/json/list", "/target"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &conversationLog{}
			server := fakeInspector(t, tc.isInspector, log)

			cfg := obi.DefaultConfig
			injector := NewNodeInjector(&cfg, log.track)
			target := InjectionTarget{Pid: app.PID(os.Getpid()), Ns: 33}
			if tc.signaled {
				require.NoError(t, injector.injectViaSignaledInspector(target))
			} else {
				injected, err := injector.injectViaOpenInspector(target)
				require.NoError(t, err)
				require.Equal(t, tc.isInspector, injected)
			}

			log.mu.Lock()
			defer log.mu.Unlock()

			want := []string{"track"}
			for _, path := range tc.wantPaths {
				want = append(want, log.client.String()+" "+path)
			}
			want = append(want, "release")
			assert.Equal(t, want, log.events)
			assert.Equal(t, uint32(33), log.ns)
			assert.Equal(t, server, log.server)
		})
	}
}

func TestInjectorWithoutConnTracker(t *testing.T) {
	fakeInspector(t, true, &conversationLog{})

	cfg := obi.DefaultConfig
	injected, err := NewNodeInjector(&cfg, nil).injectViaOpenInspector(InjectionTarget{Pid: app.PID(os.Getpid())})
	require.NoError(t, err)
	require.True(t, injected)
}

func TestTrackConnIgnoresNonTCPConns(t *testing.T) {
	log := &conversationLog{}
	cfg := obi.DefaultConfig

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	NewNodeInjector(&cfg, log.track).trackConn(33, client)()
	assert.Empty(t, log.events)
}
