// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
)

// newEvaluateRecordingServer answers every Runtime.evaluate and records the
// expression it carried, so a test can assert on the conversation itself
// rather than on its side effects.
func newEvaluateRecordingServer(t *testing.T, seen chan<- string) *httptest.Server {
	t.Helper()

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}

			var req struct {
				ID     int `json:"id"`
				Params struct {
					Expression string `json:"expression"`
				} `json:"params"`
			}

			if err := json.Unmarshal(msg, &req); err == nil {
				select {
				case seen <- req.Params.Expression:
				default:
				}
			}

			if err := conn.WriteJSON(cdpResponse{
				ID:     req.ID,
				Result: map[string]any{"result": map[string]any{"type": "number", "value": 2}},
			}); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

func dialRecordingInspector(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	wsConn, _, err := upgradeConnWithTimeout(conn, wsURL, 0, testInspectorTimeout)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("upgrade websocket: %v", err)
	}

	t.Cleanup(func() { _ = wsConn.Close() })

	return wsConn
}

// process._debugEnd() closes the application's debugger port. It must be sent
// when this injection is what opened that port, and must not be sent when the
// application was already listening: closing a port the operator asked for with
// --inspect drops any attached debugger, and nothing reopens it short of
// restarting the process.
func TestInjectClosesOnlyAnInspectorItOpened(t *testing.T) {
	for _, tc := range []struct {
		name           string
		closeInspector bool
		wantDebugEnd   bool
	}{
		{"opened by this injection", true, true},
		{"already open, as under --inspect", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 8)
			srv := newEvaluateRecordingServer(t, seen)
			wsConn := dialRecordingInspector(t, srv)

			cfg := obi.DefaultConfig
			i := NewNodeInjector(&cfg)

			payload, err := evaluateRequest("1+1", 1)
			require.NoError(t, err)

			require.NoError(t, i.injectFileWS(wsConn, payload, tc.closeInspector))

			close(seen)

			var expressions []string
			for e := range seen {
				expressions = append(expressions, e)
			}

			require.Contains(t, expressions, "1+1", "the agent itself should always be evaluated")

			if tc.wantDebugEnd {
				require.Contains(t, expressions, "process._debugEnd();",
					"an inspector this injection opened must be closed again")

				return
			}

			require.NotContains(t, expressions, "process._debugEnd();",
				"an inspector the application already had open must be left alone")
		})
	}
}
