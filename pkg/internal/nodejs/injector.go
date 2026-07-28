// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

type inspectorTarget struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type cdpRequest struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type cdpResponse struct {
	ID     int            `json:"id"`
	Result map[string]any `json:"result,omitempty"`
	Error  map[string]any `json:"error,omitempty"`
}

type evalParams struct {
	Expression            string `json:"expression"`
	IncludeCommandLineAPI bool   `json:"includeCommandLineAPI"`
}

const inspectorRequestTimeout = 5 * time.Second

// Gorilla websocket library fragments any message larger than the write
// buffer into WebSocket continuation frames. Node and Deno inspector
// does not reassemble them - they parse only the
// first frame and reject the rest with a JSON parse error.
// We need to size the buffer accordingly so Gorilla sends the
// Runtime.evaluate message in a single (unfragmented) WebSocket frame
const wsWriteBufferSize = 1 << 20

// IMPORTANT: the code in this file needs to run in the network namespace of the
// target process in order to be able to connect to its inspector port - the
// network namespace switching is done by the withNetNS function, which locks
// the current go routine to the current thread, ensuring the current thread
// runs in the right network namespace - as a result, we need to manually
// initiate the connection, as net/http and gorilla/websocket dialers may
// spawn go routines of their own, which can potentially end up on a different
// thread (and consequently, in the wrong namespace)

func connect(addr string, port int) (net.Conn, error) {
	ip := net.ParseIP(addr).To4()

	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported, got: %s", addr)
	}

	sa := &syscall.SockaddrInet4{
		Port: port,
	}

	copy(sa.Addr[:], ip)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect: %w", err)
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("tcp:%s:%d", addr, port))

	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("failed to create os.File from fd")
	}

	conn, err := net.FileConn(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("fileconn: %w", err)
	}

	file.Close()

	return conn, nil
}

func connectWait(ip string, port int, timeout time.Duration, interval time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)

	for {
		conn, err := connect(ip, port)

		if err == nil {
			return conn, nil
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s:%d", ip, port)
		}

		time.Sleep(interval)
		continue
	}
}

func httpGet(conn net.Conn, path string) ([]byte, error) {
	return httpGetWithTimeout(conn, path, inspectorRequestTimeout)
}

func httpGetWithTimeout(conn net.Conn, path string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("request error: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return []byte{}, fmt.Errorf("connection deadline error: %w", err)
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	if err = req.Write(conn); err != nil {
		return []byte{}, fmt.Errorf("error writing request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return []byte{}, fmt.Errorf("error reading response: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("response body error: %w", err)
	}

	return body, nil
}

func (i *NodeInjector) requestDebuggerURL(conn net.Conn) (string, error) {
	res, err := httpGet(conn, "/json/list")
	if err != nil {
		return "", err
	}

	i.log.Debug("received response", "response", res)

	var targets []inspectorTarget

	if err := json.Unmarshal(res, &targets); err != nil {
		return "", fmt.Errorf("invalid JSON %w", err)
	}

	if len(targets) == 0 {
		return "", errors.New("no debugging targets available")
	}

	return targets[0].WebSocketDebuggerURL, nil
}

func upgradeConn(conn net.Conn, wsURL string) (*websocket.Conn, *http.Response, error) {
	return upgradeConnWithTimeout(conn, wsURL, inspectorRequestTimeout)
}

func upgradeConnWithTimeout(conn net.Conn, wsURL string, timeout time.Duration) (*websocket.Conn, *http.Response, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, fmt.Errorf("connection deadline error: %w", err)
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		NetDial: func(_, _ string) (net.Conn, error) {
			return conn, nil
		},
		WriteBufferSize: wsWriteBufferSize,
	}

	wsConn, resp, err := dialer.Dial(wsURL, nil)
	return wsConn, resp, err
}

func sendEvaluate(wsConn *websocket.Conn, exp string, id int) error {
	return sendEvaluateWithTimeout(wsConn, exp, id, inspectorRequestTimeout)
}

func sendCommandWithTimeout(
	wsConn *websocket.Conn,
	method string,
	params any,
	id int,
	timeout time.Duration,
) (cdpResponse, error) {
	req := cdpRequest{
		ID:     id,
		Method: method,
		Params: params,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return cdpResponse{}, fmt.Errorf("failed to serialize request: %w", err)
	}

	deadline := time.Now().Add(timeout)

	if err := wsConn.SetWriteDeadline(deadline); err != nil {
		return cdpResponse{}, fmt.Errorf("websocket write deadline error: %w", err)
	}
	defer func() {
		_ = wsConn.SetWriteDeadline(time.Time{})
		_ = wsConn.SetReadDeadline(time.Time{})
	}()

	if err := wsConn.SetReadDeadline(deadline); err != nil {
		return cdpResponse{}, fmt.Errorf("websocket read deadline error: %w", err)
	}

	if err := wsConn.WriteMessage(websocket.TextMessage, data); err != nil {
		return cdpResponse{}, fmt.Errorf("websocket write error: %w", err)
	}

	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		return cdpResponse{}, fmt.Errorf("websocket read error: %w", err)
	}

	var resp cdpResponse

	if err := json.Unmarshal(msg, &resp); err != nil {
		return cdpResponse{}, fmt.Errorf("response unmarshal error: %w", err)
	}

	if resp.Error != nil {
		return resp, fmt.Errorf("protocol error: %+v", resp.Error)
	}

	return resp, nil
}

func sendEvaluateWithTimeout(wsConn *websocket.Conn, exp string, id int, timeout time.Duration) error {
	resp, err := sendCommandWithTimeout(wsConn, "Runtime.evaluate", evalParams{
		Expression:            exp,
		IncludeCommandLineAPI: true,
	}, id, timeout)
	if err != nil {
		return err
	}

	result := resp.Result["result"]

	if resultMap, ok := result.(map[string]any); ok {
		if subtype, ok := resultMap["subtype"]; ok && subtype == "error" {
			return fmt.Errorf("exception: %v", resultMap["description"])
		}
	}

	if ed, ok := resp.Result["exceptionDetails"]; ok {
		return fmt.Errorf("uncaught exception: %v", ed)
	}

	return nil
}

// runIfWaitingForDebugger releases a runtime that was started paused with
// --inspect-brk. It is a no-op when the runtime is not waiting for a debugger,
// so it is safe on the --inspect and SIGUSR1 paths too.
func runIfWaitingForDebugger(wsConn *websocket.Conn, id int) error {
	_, err := sendCommandWithTimeout(wsConn, "Runtime.runIfWaitingForDebugger", nil, id, inspectorRequestTimeout)
	return err
}

func (i *NodeInjector) injectFileWS(
	wsConn *websocket.Conn,
	runtimeType svc.InstrumentableType,
) error {
	defer func() {
		_ = sendEvaluate(wsConn, "process._debugEnd();", 2)
	}()

	var script []byte
	switch runtimeType {
	case svc.InstrumentableDeno:
		script = _extractorDenoBytes
	case svc.InstrumentableNodejs:
		script = _extractorBytes
	default:
		// must never happen unless a bug in our code
		return fmt.Errorf("unexpected instrumentable type %s. Aborting injection", runtimeType)
	}

	if err := sendEvaluate(wsConn, string(script), 1); err != nil {
		return err
	}

	// Resume the process if it was started paused with --inspect-brk. Harmless
	// no-op otherwise.
	if err := runIfWaitingForDebugger(wsConn, 3); err != nil {
		return err
	}

	i.log.Info("Script successfully injected", "runtime", runtimeType.String())

	return nil
}

func (i *NodeInjector) injectViaConn(conn net.Conn, runtimeType svc.InstrumentableType) error {
	wsURL, err := i.requestDebuggerURL(conn)
	if err != nil {
		conn.Close()
		return err
	}

	i.log.Debug("found debugger url", "url", wsURL)

	wsConn, _, err := upgradeConn(conn, wsURL)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to connect to inspector WebSocket: %w", err)
	}

	return i.injectFileWS(wsConn, runtimeType)
}
