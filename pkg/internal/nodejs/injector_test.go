// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
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

func TestSendEvaluateClearsDeadlines(t *testing.T) {
	wsConn := newRespondingTestInspectorConn(t)

	if err := runSendEvaluateWithTimeout(t, wsConn, testInspectorTimeout); err != nil {
		t.Fatalf("send evaluate: %v", err)
	}

	time.Sleep(2 * testInspectorTimeout)
	assertWebSocketUsable(t, wsConn)
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
		wsConn, _, err := upgradeConnWithTimeout(conn, "ws://127.0.0.1/json", 0, testInspectorTimeout)
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

func TestUpgradeConnClearsDeadline(t *testing.T) {
	srv := newRespondingTestInspectorServer(t)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial websocket server: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	wsConn, _, err := upgradeConnWithTimeout(conn, wsURL, 0, testInspectorTimeout)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("upgrade websocket: %v", err)
	}
	t.Cleanup(func() {
		_ = wsConn.Close()
	})

	time.Sleep(2 * testInspectorTimeout)
	assertWebSocketUsable(t, wsConn)
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

func newRespondingTestInspectorConn(t *testing.T) *websocket.Conn {
	t.Helper()

	srv := newRespondingTestInspectorServer(t)
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

func newRespondingTestInspectorServer(t *testing.T) *httptest.Server {
	t.Helper()

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}

			if err := conn.WriteJSON(cdpResponse{
				ID: 1,
				Result: map[string]any{
					"result": map[string]any{
						"type":  "number",
						"value": 2,
					},
				},
			}); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	return srv
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

func assertWebSocketUsable(t *testing.T, wsConn *websocket.Conn) {
	t.Helper()

	err := runWithOperationTimeout(t, "websocket use after deadline", func() error {
		if err := wsConn.WriteMessage(websocket.TextMessage, []byte(`{"id":1}`)); err != nil {
			return err
		}

		_, _, err := wsConn.ReadMessage()
		return err
	})
	if err != nil {
		t.Fatalf("expected websocket to remain usable: %v", err)
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

// gorilla's read API only exposes reassembled messages, so detecting
// fragmentation requires parsing frames off the raw TCP stream.
type frameHeader struct {
	fin        bool
	opcode     byte
	payloadLen uint64
}

type frameResult struct {
	header frameHeader
	err    error
}

func readFrameHeader(br *bufio.Reader) (frameHeader, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return frameHeader{}, fmt.Errorf("reading frame header: %w", err)
	}

	h := frameHeader{fin: hdr[0]&0x80 != 0, opcode: hdr[0] & 0x0f, payloadLen: uint64(hdr[1] & 0x7f)}
	switch h.payloadLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return frameHeader{}, fmt.Errorf("reading extended length: %w", err)
		}
		h.payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return frameHeader{}, fmt.Errorf("reading extended length: %w", err)
		}
		h.payloadLen = binary.BigEndian.Uint64(ext[:])
	}
	return h, nil
}

func newFrameInspectingServer(results chan<- frameResult) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			results <- frameResult{err: fmt.Errorf("hijacking connection: %w", err)}
			return
		}
		defer conn.Close()

		key := r.Header.Get("Sec-WebSocket-Key")
		sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, err = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		if err == nil {
			err = brw.Flush()
		}
		if err != nil {
			results <- frameResult{err: fmt.Errorf("writing upgrade response: %w", err)}
			return
		}

		header, err := readFrameHeader(brw.Reader)
		results <- frameResult{header: header, err: err}

		// drain until the client disconnects: closing while it still has
		// frames in flight resets its write
		_, _ = io.Copy(io.Discard, brw)
	}))
}

// The Node.js inspector closes the connection on fragmented messages, so the
// injection payload must always leave as one final frame.
func TestInjectionPayloadIsNeverFragmented(t *testing.T) {
	// larger than gorilla's 4096-byte default write buffer
	payload, err := evaluateRequest("(()=>{"+strings.Repeat("x();", 4096)+"})()", 1)
	if err != nil {
		t.Fatalf("marshaling evaluate request: %v", err)
	}

	sendPayload := func(writeBufferSize int) frameHeader {
		results := make(chan frameResult, 1)
		srv := newFrameInspectingServer(results)
		defer srv.Close()

		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatalf("dial test inspector: %v", err)
		}
		defer conn.Close()

		wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
		wsConn, _, err := upgradeConnWithTimeout(conn, wsURL, writeBufferSize, testInspectorOperationTimeout)
		if err != nil {
			t.Fatalf("upgrade websocket: %v", err)
		}
		defer wsConn.Close()

		if err := wsConn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatalf("writing payload: %v", err)
		}

		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("reading first frame: %v", result.err)
			}
			return result.header
		case <-time.After(testInspectorOperationTimeout):
			t.Fatal("timeout waiting for the first frame")
			return frameHeader{}
		}
	}

	sized := sendPayload(len(payload))
	if !sized.fin || sized.opcode != 1 || sized.payloadLen != uint64(len(payload)) {
		t.Fatalf("expected a single final text frame with %d bytes, got fin=%v opcode=%d len=%d",
			len(payload), sized.fin, sized.opcode, sized.payloadLen)
	}

	// control: prove the default buffer still fragments this payload
	unsized := sendPayload(0)
	if unsized.fin {
		t.Fatal("expected the default write buffer to fragment the payload; " +
			"if gorilla no longer fragments, this test and the sizing rationale should be revisited")
	}
}

// evalRequest reads back the expression a Runtime.evaluate request carries.
type evalRequest struct {
	ID     int        `json:"id"`
	Method string     `json:"method"`
	Params evalParams `json:"params"`
}

// The inspector is a debugging interface, so OBI closes the one it opened
// itself with SIGUSR1 and leaves an inspector the process asked for alone.
func TestInjectionClosesOnlyAnInspectorOBIOpened(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mayClose     bool
		wantDebugEnd bool
	}{
		{name: "opened by OBI", mayClose: true, wantDebugEnd: true},
		{name: "opened by the process", mayClose: false, wantDebugEnd: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expressions := make(chan string, 2)
			wsConn := newTestInspectorConn(t, func(conn *websocket.Conn) {
				defer conn.Close()

				for {
					_, msg, err := conn.ReadMessage()
					if err != nil {
						return
					}

					var req evalRequest
					if err := json.Unmarshal(msg, &req); err != nil {
						return
					}
					expressions <- req.Params.Expression

					if err := conn.WriteJSON(cdpResponse{ID: req.ID}); err != nil {
						return
					}
				}
			})

			injector := newTestInjector()
			payload, err := evaluateRequest("void 0;", agentRequestID)
			if err != nil {
				t.Fatalf("marshaling evaluate request: %v", err)
			}

			if err := injector.injectFileWS(1, wsConn, payload, tc.mayClose); err != nil {
				t.Fatalf("injecting: %v", err)
			}

			// injectFileWS closes the inspector from a defer, so by the time it
			// returns every message it sends has already been answered
			if got := <-expressions; got != "void 0;" {
				t.Fatalf("expected the agent payload first, got %q", got)
			}

			select {
			case got := <-expressions:
				if !tc.wantDebugEnd {
					t.Fatalf("expected no further evaluation, got %q", got)
				}
				if got != debugEndExpression {
					t.Fatalf("expected %q, got %q", debugEndExpression, got)
				}
			case <-time.After(testInspectorOperationTimeout):
				if tc.wantDebugEnd {
					t.Fatalf("timeout waiting for %q", debugEndExpression)
				}
			}
		})
	}
}

// A failed injection leaves the inspector listening, so the cleanup path has
// to reach it over a connection of its own and evaluate process._debugEnd().
func TestSendDebugEndEvaluatesDebugEnd(t *testing.T) {
	expressions := make(chan string, 1)
	srv := newScriptedInspectorServer(t, inspectorScript{expressions: expressions})

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test inspector: %v", err)
	}
	defer conn.Close()

	if err := newTestInjector().sendDebugEnd(conn); err != nil {
		t.Fatalf("sending debug end: %v", err)
	}

	select {
	case got := <-expressions:
		if got != debugEndExpression {
			t.Fatalf("expected %q, got %q", debugEndExpression, got)
		}
	case <-time.After(testInspectorOperationTimeout):
		t.Fatal("timeout waiting for the evaluated expression")
	}
}

// inspectorScript configures the stand-in inspector: how many initial
// /json/list requests report no debugging targets, which is how an injection
// attempt is made to fail after the inspector is already open.
type inspectorScript struct {
	emptyLists  int
	expressions chan<- string
	// notAnInspector answers /json/version with something the injector will
	// not accept, so injectFile falls through to SIGUSR1 instead of injecting
	// into an inspector it found already open
	notAnInspector bool
	// refuseUpgrade rejects the WebSocket upgrade, the way an inspector that
	// has stopped serving its debugger session would
	refuseUpgrade bool
	// hangUpAfterFirstEvaluate answers one evaluation and then drops the
	// session, so a following process._debugEnd() cannot be delivered
	hangUpAfterFirstEvaluate bool
}

// newScriptedInspectorServer serves /json/version, /json/list and the debugger
// WebSocket on one connection, the way the real inspector does, reporting
// every expression it is asked to evaluate.
func newScriptedInspectorServer(t *testing.T, script inspectorScript) *httptest.Server {
	t.Helper()

	upgrader := websocket.Upgrader{}
	remainingEmptyLists := &atomic.Int64{}
	remainingEmptyLists.Store(int64(script.emptyLists))

	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json/version":
			if script.notAnInspector {
				_, _ = w.Write([]byte("not an inspector"))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Browser":"node.js/v22.0.0"}`))

			return
		case "/json/list":
			targets := []inspectorTarget{{
				WebSocketDebuggerURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
			}}
			if remainingEmptyLists.Add(-1) >= 0 {
				targets = nil
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(targets)

			return
		}

		if script.refuseUpgrade {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

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

			var req evalRequest
			if err := json.Unmarshal(msg, &req); err != nil {
				return
			}
			script.expressions <- req.Params.Expression

			if err := conn.WriteJSON(cdpResponse{ID: req.ID}); err != nil {
				return
			}

			if script.hangUpAfterFirstEvaluate {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

// pointInjectorAtServer makes the injector dial srv instead of the real
// inspector port, and keeps the connect budgets short enough that a failing
// attempt does not stall the test.
func pointInjectorAtServer(t *testing.T, srv *httptest.Server) {
	t.Helper()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("splitting test inspector address: %v", err)
	}

	parsed, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parsing test inspector port: %v", err)
	}

	setInspectorDialTarget(t, parsed)
}

// setInspectorDialTarget points the injector at port and shortens the connect
// budgets, restoring both when the test ends.
func setInspectorDialTarget(t *testing.T, port int) {
	t.Helper()

	oldPort, oldConnect, oldClose := inspectorPort, inspectorConnectWait, inspectorCloseWait
	inspectorPort = port
	inspectorConnectWait = testInspectorTimeout
	inspectorCloseWait = testInspectorTimeout

	t.Cleanup(func() {
		inspectorPort = oldPort
		inspectorConnectWait = oldConnect
		inspectorCloseWait = oldClose
	})
}

func awaitExpression(t *testing.T, expressions <-chan string) string {
	t.Helper()

	select {
	case got := <-expressions:
		return got
	case <-time.After(testInspectorOperationTimeout):
		t.Fatal("timeout waiting for an evaluated expression")
		return ""
	}
}

// closeInspector reaches the inspector over a connection of its own, because
// the one the failed injection used is gone by the time it runs.
func TestCloseInspectorEvaluatesDebugEnd(t *testing.T) {
	expressions := make(chan string, 1)
	srv := newScriptedInspectorServer(t, inspectorScript{expressions: expressions})
	pointInjectorAtServer(t, srv)

	newTestInjector().closeInspector(1)

	if got := awaitExpression(t, expressions); got != debugEndExpression {
		t.Fatalf("expected %q, got %q", debugEndExpression, got)
	}
}

// A failure after the inspector is open must not leave the debugging
// interface listening.
func TestFailedInjectionClosesTheInspector(t *testing.T) {
	expressions := make(chan string, 1)
	// the first /json/list reports no targets, failing the injection
	srv := newScriptedInspectorServer(t, inspectorScript{emptyLists: 1, expressions: expressions})
	pointInjectorAtServer(t, srv)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test inspector: %v", err)
	}

	if err := newTestInjector().injectViaConn(1, conn, true); err == nil {
		t.Fatal("expected the injection to fail")
	}

	if got := awaitExpression(t, expressions); got != debugEndExpression {
		t.Fatalf("expected %q, got %q", debugEndExpression, got)
	}
}

// An inspector the process asked for stays open even when the injection fails.
func TestFailedInjectionLeavesAProcessOwnedInspectorOpen(t *testing.T) {
	expressions := make(chan string, 1)
	srv := newScriptedInspectorServer(t, inspectorScript{emptyLists: 1, expressions: expressions})
	pointInjectorAtServer(t, srv)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test inspector: %v", err)
	}

	if err := newTestInjector().injectViaConn(1, conn, false); err == nil {
		t.Fatal("expected the injection to fail")
	}

	select {
	case got := <-expressions:
		t.Fatalf("expected no evaluation, got %q", got)
	case <-time.After(testInspectorTimeout):
	}
}

// injectFile reaches the inspector two ways - finding it already open, or
// opening it with SIGUSR1 - and a failed injection has to close it in both.
func TestInjectFileClosesTheInspectorAfterAFailedInjection(t *testing.T) {
	for _, tc := range []struct {
		name           string
		notAnInspector bool
	}{
		{name: "inspector already open"},
		{name: "inspector opened by SIGUSR1", notAnInspector: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubProcessWithoutInspectorFlag(t)
			catchSIGUSR1(t)

			expressions := make(chan string, 1)
			// the first /json/list reports no targets, failing the injection
			srv := newScriptedInspectorServer(t, inspectorScript{
				emptyLists:     1,
				expressions:    expressions,
				notAnInspector: tc.notAnInspector,
			})
			pointInjectorAtServer(t, srv)

			if err := newTestInjector().injectFile(os.Getpid(), nil); err == nil {
				t.Fatal("expected the injection to fail")
			}

			if got := awaitExpression(t, expressions); got != debugEndExpression {
				t.Fatalf("expected %q, got %q", debugEndExpression, got)
			}
		})
	}
}

// When the inspector never answers after SIGUSR1 there is nothing to close,
// and the cleanup attempt must not turn that into a hang or a panic.
func TestInjectFileReportsAnInspectorThatNeverOpens(t *testing.T) {
	stubProcessWithoutInspectorFlag(t)
	catchSIGUSR1(t)

	// a port nothing listens on: closed by the time the injector dials it
	srv := newScriptedInspectorServer(t, inspectorScript{})
	pointInjectorAtServer(t, srv)
	srv.Close()

	err := newTestInjector().injectFile(os.Getpid(), nil)
	if err == nil {
		t.Fatal("expected an error when the inspector never opens")
	}

	if !strings.Contains(err.Error(), "failed to connect to inspector after SIGUSR1") {
		t.Fatalf("expected the SIGUSR1 connect failure, got %v", err)
	}
}

// catchSIGUSR1 keeps the default disposition, which terminates the process,
// from killing the test run when the injector signals it.
func catchSIGUSR1(t *testing.T) {
	t.Helper()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	t.Cleanup(func() {
		signal.Stop(signals)
	})
}

// captureInjectorLogs returns an injector that logs into the returned buffer,
// so tests can assert on what an operator would see.
func captureInjectorLogs(t *testing.T) (*NodeInjector, *bytes.Buffer) {
	t.Helper()

	logs := &bytes.Buffer{}
	injector := newTestInjector()
	injector.log = slog.New(slog.NewTextHandler(logs, nil))

	return injector, logs
}

// A successful injection closes the inspector OBI opened, over the same
// session it injected through.
func TestInjectViaConnInjectsThenClosesTheInspector(t *testing.T) {
	expressions := make(chan string, 2)
	srv := newScriptedInspectorServer(t, inspectorScript{expressions: expressions})
	pointInjectorAtServer(t, srv)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test inspector: %v", err)
	}

	if err := newTestInjector().injectViaConn(1, conn, true); err != nil {
		t.Fatalf("injecting: %v", err)
	}

	if got := awaitExpression(t, expressions); got == debugEndExpression {
		t.Fatal("expected the agent payload before the close")
	}

	if got := awaitExpression(t, expressions); got != debugEndExpression {
		t.Fatalf("expected %q, got %q", debugEndExpression, got)
	}
}

// The one outcome an operator has to act on: OBI could not close the
// inspector, so it says so instead of failing silently.
func TestCloseInspectorReportsAnInspectorItCannotClose(t *testing.T) {
	expressions := make(chan string, 1)
	srv := newScriptedInspectorServer(t, inspectorScript{
		expressions:   expressions,
		refuseUpgrade: true,
	})
	pointInjectorAtServer(t, srv)

	injector, logs := captureInjectorLogs(t)
	injector.closeInspector(1)

	if !strings.Contains(logs.String(), "could not close the Node.js inspector") {
		t.Fatalf("expected a warning about the inspector staying open, got: %s", logs.String())
	}
}

// The same warning is due when the injection itself succeeded and only the
// close failed: the agent is in, but the debugging interface is still open.
func TestInjectionReportsACloseItCouldNotComplete(t *testing.T) {
	expressions := make(chan string, 1)
	srv := newScriptedInspectorServer(t, inspectorScript{
		expressions:              expressions,
		hangUpAfterFirstEvaluate: true,
	})
	pointInjectorAtServer(t, srv)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test inspector: %v", err)
	}

	injector, logs := captureInjectorLogs(t)
	if err := injector.injectViaConn(1, conn, true); err != nil {
		t.Fatalf("injecting: %v", err)
	}

	if !strings.Contains(logs.String(), "could not close the Node.js inspector") {
		t.Fatalf("expected a warning about the inspector staying open, got: %s", logs.String())
	}
}
