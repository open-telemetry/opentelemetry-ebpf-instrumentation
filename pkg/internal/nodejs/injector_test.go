// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const (
	testEvaluateTimeout           = 50 * time.Millisecond
	testEvaluateSlowResponseDelay = 4 * testEvaluateTimeout
	testEvaluateReturnTimeout     = time.Second
)

func TestSendEvaluateTimesOutWhenInspectorDoesNotRespond(t *testing.T) {
	done := make(chan struct{})
	wsConn := newTestInspectorConn(t, func(conn *websocket.Conn) {
		defer conn.Close()

		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}

		<-done
	})
	defer close(done)

	err := runSendEvaluateWithTimeout(t, wsConn, testEvaluateTimeout)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	assertTimeoutError(t, err)
}

func TestSendEvaluateTimesOutWhenInspectorRespondsTooSlowly(t *testing.T) {
	done := make(chan struct{})
	wsConn := newTestInspectorConn(t, func(conn *websocket.Conn) {
		defer conn.Close()

		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}

		select {
		case <-time.After(testEvaluateSlowResponseDelay):
		case <-done:
			return
		}

		_ = conn.WriteJSON(cdpResponse{
			ID: 1,
			Result: map[string]any{
				"result": map[string]any{
					"type":  "number",
					"value": 2,
				},
			},
		})
	})
	defer close(done)

	err := runSendEvaluateWithTimeout(t, wsConn, testEvaluateTimeout)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	assertTimeoutError(t, err)
}

func newTestInspectorConn(t *testing.T, handle func(*websocket.Conn)) *websocket.Conn {
	t.Helper()

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		handle(conn)
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() {
		_ = wsConn.Close()
	})

	return wsConn
}

func runSendEvaluateWithTimeout(t *testing.T, wsConn *websocket.Conn, timeout time.Duration) error {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sendEvaluateWithTimeout(wsConn, "1+1", 1, timeout)
	}()

	select {
	case err := <-errCh:
		return err
	case <-time.After(testEvaluateReturnTimeout):
		_ = wsConn.Close()
		t.Fatal("sendEvaluateWithTimeout did not return")
		return nil
	}
}

func assertTimeoutError(t *testing.T, err error) {
	t.Helper()

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected timeout error, got %v", err)
	}
}
