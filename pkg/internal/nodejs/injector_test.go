// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const (
	testInspectorTimeout          = 50 * time.Millisecond
	testEvaluateSlowResponseDelay = 4 * testInspectorTimeout
	testInspectorOperationTimeout = time.Second
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

	err := runSendEvaluateWithTimeout(t, wsConn, testInspectorTimeout)
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

	err := runSendEvaluateWithTimeout(t, wsConn, testInspectorTimeout)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	assertTimeoutError(t, err)
}

func TestHTTPGetTimesOutWhenInspectorDoesNotRespond(t *testing.T) {
	conn := newPipeInspectorConn(t, func(conn net.Conn, done <-chan struct{}) {
		defer conn.Close()

		if !readHTTPRequest(conn) {
			return
		}

		<-done
	})

	err := runWithOperationTimeout(t, "httpGetWithTimeout", func() error {
		_, err := httpGetWithTimeout(conn, "/json/list", testInspectorTimeout)
		return err
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	assertTimeoutError(t, err)
}

func TestHTTPGetTimesOutWhenInspectorResponseBodyStalls(t *testing.T) {
	conn := newPipeInspectorConn(t, func(conn net.Conn, done <-chan struct{}) {
		defer conn.Close()

		if !readHTTPRequest(conn) {
			return
		}

		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{"))
		<-done
	})

	err := runWithOperationTimeout(t, "httpGetWithTimeout", func() error {
		_, err := httpGetWithTimeout(conn, "/json/list", testInspectorTimeout)
		return err
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	assertTimeoutError(t, err)
}

func TestUpgradeConnTimesOutWhenInspectorDoesNotRespond(t *testing.T) {
	conn := newPipeInspectorConn(t, func(conn net.Conn, done <-chan struct{}) {
		defer conn.Close()

		if !readHTTPRequest(conn) {
			return
		}

		<-done
	})

	err := runWithOperationTimeout(t, "upgradeConnWithTimeout", func() error {
		wsConn, _, err := upgradeConnWithTimeout(conn, "ws://127.0.0.1/json", testInspectorTimeout)
		if wsConn != nil {
			_ = wsConn.Close()
		}

		return err
	})
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

func newPipeInspectorConn(t *testing.T, handle func(net.Conn, <-chan struct{})) net.Conn {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	handlerDone := make(chan struct{})

	go func() {
		defer close(handlerDone)
		handle(serverConn, done)
	}()

	t.Cleanup(func() {
		close(done)
		_ = clientConn.Close()
		_ = serverConn.Close()
		<-handlerDone
	})

	return clientConn
}

func readHTTPRequest(conn net.Conn) bool {
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return false
	}

	_ = req.Body.Close()
	return true
}

func runSendEvaluateWithTimeout(t *testing.T, wsConn *websocket.Conn, timeout time.Duration) error {
	t.Helper()

	return runWithOperationTimeout(t, "sendEvaluateWithTimeout", func() error {
		return sendEvaluateWithTimeout(wsConn, "1+1", 1, timeout)
	})
}

func runWithOperationTimeout(t *testing.T, name string, run func() error) error {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		errCh <- run()
	}()

	select {
	case err := <-errCh:
		return err
	case <-time.After(testInspectorOperationTimeout):
		t.Fatalf("%s did not return", name)
		return nil
	}
}

func assertTimeoutError(t *testing.T, err error) {
	t.Helper()

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return
	}

	if os.IsTimeout(err) {
		return
	}

	t.Fatalf("expected timeout error, got %v", err)
}
