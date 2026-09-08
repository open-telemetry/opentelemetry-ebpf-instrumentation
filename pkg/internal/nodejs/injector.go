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

const inspectorHost = "127.0.0.1"

var inspectorPort = 9229

const debugEndExpression = "process._debugEnd();"

const (
	agentRequestID    = 1
	debugEndRequestID = 2
)

const (
	inspectorConnectInterval = 200 * time.Millisecond
	inspectorCloseInterval   = 200 * time.Millisecond
)

// The cleanup budget is kept short: the injector runs synchronously from the
// attacher loop, so it delays every other process being instrumented.
var (
	inspectorConnectWait = 5 * time.Second
	inspectorCloseWait   = 2 * time.Second
)

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

func upgradeConn(conn net.Conn, wsURL string, writeBufferSize int) (*websocket.Conn, *http.Response, error) {
	return upgradeConnWithTimeout(conn, wsURL, writeBufferSize, inspectorRequestTimeout)
}

func upgradeConnWithTimeout(conn net.Conn, wsURL string, writeBufferSize int, timeout time.Duration) (*websocket.Conn, *http.Response, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, fmt.Errorf("connection deadline error: %w", err)
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		// Messages larger than the write buffer are sent as fragmented
		// websocket frames, which the Node.js inspector does not support
		// (it abruptly closes the connection). The caller sizes writeBufferSize
		// to the payload so every message is sent as a single frame.
		WriteBufferSize: writeBufferSize,
		ReadBufferSize:  64 * 1024,
		NetDial: func(_, _ string) (net.Conn, error) {
			return conn, nil
		},
	}

	wsConn, resp, err := dialer.Dial(wsURL, nil)
	return wsConn, resp, err
}

func evaluateRequest(exp string, id int) ([]byte, error) {
	req := cdpRequest{
		ID:     id,
		Method: "Runtime.evaluate",
		Params: evalParams{
			Expression:            exp,
			IncludeCommandLineAPI: true,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}
	return data, nil
}

func sendEvaluate(wsConn *websocket.Conn, exp string, id int) error {
	return sendEvaluateWithTimeout(wsConn, exp, id, inspectorRequestTimeout)
}

func sendEvaluateWithTimeout(wsConn *websocket.Conn, exp string, id int, timeout time.Duration) error {
	data, err := evaluateRequest(exp, id)
	if err != nil {
		return err
	}
	return sendMessageWithTimeout(wsConn, data, timeout)
}

func sendMessageWithTimeout(wsConn *websocket.Conn, data []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	if err := wsConn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("websocket write deadline error: %w", err)
	}
	defer func() {
		_ = wsConn.SetWriteDeadline(time.Time{})
		_ = wsConn.SetReadDeadline(time.Time{})
	}()

	if err := wsConn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("websocket read deadline error: %w", err)
	}

	if err := wsConn.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("websocket write error: %w", err)
	}

	// NOTE: the next message is assumed to be the response to `data`: valid as
	// long as no CDP event domain is enabled on this session (e.g.
	// Runtime.enable), since events would interleave before the response
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("websocket read error: %w", err)
	}

	var resp cdpResponse

	if err := json.Unmarshal(msg, &resp); err != nil {
		return fmt.Errorf("response unmarshal error: %w", err)
	}

	if resp.Error != nil {
		return fmt.Errorf("protocol error: %+v", resp.Error)
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

// injectFileWS evaluates the agent, then always closes the WebSocket and, when
// OBI opened the inspector, closes that too. A failed injection is left to the
// caller: it cleans up over a fresh connection, which this stalled or broken
// session cannot do.
func (i *NodeInjector) injectFileWS(pid int, wsConn *websocket.Conn, payload []byte, openedByOBI bool) error {
	defer wsConn.Close()

	if err := sendMessageWithTimeout(wsConn, payload, inspectorRequestTimeout); err != nil {
		return err
	}

	i.log.Info("Script successfully injected")

	if openedByOBI {
		if err := sendEvaluate(wsConn, debugEndExpression, debugEndRequestID); err != nil {
			i.logInspectorStaysOpen(pid, err)
		}
	}

	return nil
}

// injectViaConn drives the injection over an established inspector
// connection. Every failure after the inspector is open would otherwise leave
// the debugging interface listening, so a failed attempt closes it again when
// OBI is the one that opened it.
func (i *NodeInjector) injectViaConn(pid int, conn net.Conn, openedByOBI bool) (err error) {
	defer func() {
		if err != nil && openedByOBI {
			i.closeInspector(pid)
		}
	}()

	payload, err := evaluateRequest(i.agentCode(), agentRequestID)
	if err != nil {
		conn.Close()
		return err
	}

	wsConn, err := i.dialInspectorWS(conn, payload)
	if err != nil {
		return err
	}

	return i.injectFileWS(pid, wsConn, payload, openedByOBI)
}

// dialInspectorWS opens the debugger session that carries payload, taking
// ownership of conn: it is closed on every failure.
func (i *NodeInjector) dialInspectorWS(conn net.Conn, payload []byte) (*websocket.Conn, error) {
	wsURL, err := i.requestDebuggerURL(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	i.log.Debug("found debugger url", "url", wsURL)

	// buffer sized to the payload: the inspector rejects fragmented messages
	wsConn, _, err := upgradeConn(conn, wsURL, len(payload))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to connect to inspector WebSocket: %w", err)
	}

	return wsConn, nil
}

// closeInspector makes a best-effort attempt to close an inspector that OBI
// opened but could not inject into, over a connection of its own: the one the
// injection used is already gone or unusable by this point.
func (i *NodeInjector) closeInspector(pid int) {
	conn, err := connectWait(inspectorHost, inspectorPort, inspectorCloseWait, inspectorCloseInterval)
	if err != nil {
		i.log.Debug("no inspector to close", "pid", pid, "error", err)
		return
	}

	if err := i.sendDebugEnd(conn); err != nil {
		i.logInspectorStaysOpen(pid, err)
		return
	}

	i.log.Info("closed the Node.js inspector after a failed injection", "pid", pid)
}

func (i *NodeInjector) sendDebugEnd(conn net.Conn) error {
	payload, err := evaluateRequest(debugEndExpression, debugEndRequestID)
	if err != nil {
		conn.Close()
		return err
	}

	wsConn, err := i.dialInspectorWS(conn, payload)
	if err != nil {
		return err
	}
	defer wsConn.Close()

	return sendMessageWithTimeout(wsConn, payload, inspectorRequestTimeout)
}

// logInspectorStaysOpen reports the one outcome an operator has to act on: the
// inspector is open, OBI could not close it, and it stays reachable inside the
// process's network namespace until the process restarts.
func (i *NodeInjector) logInspectorStaysOpen(pid int, err error) {
	i.log.Warn("could not close the Node.js inspector: the debugging interface may stay "+
		"open until the process restarts",
		"pid", pid, "address", fmt.Sprintf("%s:%d", inspectorHost, inspectorPort), "error", err)
}
