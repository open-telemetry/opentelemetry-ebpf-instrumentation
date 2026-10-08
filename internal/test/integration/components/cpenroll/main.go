// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// cpenroll drives the context propagation enrollment tests. Every client keeps one HTTP/1.1
// connection per loop open to the echo server and only then listens on its port, so a selector
// on that port can't instrument it before its first connection exists.
//
//	cpenroll launcher --port L --server URL --start name:port,...   spawns clients on demand
//	cpenroll client --name N --port P --server URL [--control-port C]
//	cpenroll probe URL                                               exits 0 on HTTP 200
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	requestInterval = 200 * time.Millisecond
	readyTimeout    = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: cpenroll launcher|client|probe ...")
	}

	switch os.Args[1] {
	case "launcher":
		runLauncher(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "probe":
		if len(os.Args) < 3 || !ok(os.Args[2]) {
			os.Exit(1)
		}
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

func ok(url string) bool {
	resp, err := (&http.Client{Timeout: time.Second}).Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitReady(url string) error {
	deadline := time.Now().Add(readyTimeout)
	for !ok(url) {
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not ready", url)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// spawn starts a client as a child of the calling process and waits until it listens
func spawn(name string, port int, server string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "client", "--name", name, "--port", strconv.Itoa(port), "--server", server)
	cmd.Env = append(os.Environ(), "OTEL_SERVICE_NAME="+name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()

	return waitReady(fmt.Sprintf("http://127.0.0.1:%d/status", port))
}

type launcher struct {
	server string
	mu     sync.Mutex
	ports  map[string]int
	ready  bool
}

func runLauncher(args []string) {
	fs := flag.NewFlagSet("launcher", flag.ExitOnError)
	port := fs.Int("port", 0, "control port")
	server := fs.String("server", "", "echo server URL")
	start := fs.String("start", "", "clients started before anything else, as name:port,...")
	_ = fs.Parse(args)

	l := &launcher{server: *server, ports: map[string]int{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if !l.ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("GET /children", l.children)
	mux.HandleFunc("POST /spawn", l.spawn)
	mux.HandleFunc("POST /do", l.do)
	go func() { log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), mux)) }()

	for spec := range strings.SplitSeq(*start, ",") {
		if spec == "" {
			continue
		}
		name, portStr, found := strings.Cut(spec, ":")
		childPort, err := strconv.Atoi(portStr)
		if !found || err != nil {
			log.Fatalf("bad client spec %q", spec)
		}
		if err := spawn(name, childPort, l.server); err != nil {
			log.Fatal(err)
		}
		l.register(name, childPort)
	}

	l.mu.Lock()
	l.ready = true
	l.mu.Unlock()
	select {}
}

func (l *launcher) register(name string, port int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ports[name] = port
}

func (l *launcher) port(name string) (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	port, found := l.ports[name]
	return port, found
}

// statuses of every client this launcher knows, gone ones omitted
func (l *launcher) children(w http.ResponseWriter, _ *http.Request) {
	l.mu.Lock()
	ports := maps.Clone(l.ports)
	l.mu.Unlock()

	statuses := map[string]json.RawMessage{}
	for name, port := range ports {
		resp, err := (&http.Client{Timeout: time.Second}).Get(fmt.Sprintf("http://127.0.0.1:%d/status", port))
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil && resp.StatusCode == http.StatusOK {
			statuses[name] = body
		}
	}
	_ = json.NewEncoder(w).Encode(statuses)
}

func (l *launcher) spawn(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	if name == "" || err != nil {
		http.Error(w, "name and port required", http.StatusBadRequest)
		return
	}
	if err := spawn(name, port, l.server); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	l.register(name, port)
}

// forwards an action to a client; a fork registers the grandchild it starts
func (l *launcher) do(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	port, found := l.port(query.Get("name"))
	if !found {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}

	action := query.Get("action")
	target := fmt.Sprintf("http://127.0.0.1:%d/%s?%s", port, action, query.Encode())
	resp, err := (&http.Client{Timeout: readyTimeout}).Post(target, "text/plain", nil)
	if err != nil {
		// an exiting client may not answer
		if action == "exit" {
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, resp.Status, resp.StatusCode)
		return
	}

	if action == "fork" {
		childPort, _ := strconv.Atoi(query.Get("port"))
		l.register(query.Get("child"), childPort)
	}
}

type connStatus struct {
	Cookie      uint64 `json:"cookie"`
	Dials       int    `json:"dials"`
	Traceparent bool   `json:"traceparent"`
}

type clientStatus struct {
	Name    string       `json:"name"`
	PID     int          `json:"pid"`
	NSInode uint64       `json:"nsInode"`
	Conns   []connStatus `json:"conns"`
}

// one connection to the echo server, kept busy so it is never closed for idleness
type loop struct {
	mu     sync.Mutex
	status connStatus
}

func (lp *loop) snapshot() connStatus {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	return lp.status
}

func startLoop(server string) (*loop, error) {
	lp := &loop{}
	transport := &http.Transport{
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			cookie, err := socketCookie(conn)
			if err != nil {
				conn.Close()
				return nil, err
			}
			lp.mu.Lock()
			lp.status = connStatus{Cookie: cookie, Dials: lp.status.Dials + 1}
			lp.mu.Unlock()
			return conn, nil
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	first := make(chan error, 1)
	go func() {
		served := false
		for {
			resp, err := client.Get(server + "/smoke-echo")
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.Header.Get("X-Received-Traceparent") != "" {
					lp.mu.Lock()
					lp.status.Traceparent = true
					lp.mu.Unlock()
				}
			}
			if !served {
				served = err == nil
				if served {
					first <- nil
				}
			}
			time.Sleep(requestInterval)
		}
	}()

	select {
	case err := <-first:
		return lp, err
	case <-time.After(readyTimeout):
		return nil, errors.New("echo server unreachable")
	}
}

func socketCookie(conn net.Conn) (uint64, error) {
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var cookie uint64
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		return 0, err
	}
	return cookie, sockErr
}

func pidNamespace() uint64 {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0
	}
	return st.Ino
}

type client struct {
	name   string
	server string
	mu     sync.Mutex
	loops  []*loop
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	name := fs.String("name", "", "service name")
	port := fs.Int("port", 0, "port opened once connected: the one the selector matches")
	controlPort := fs.Int("control-port", 0, "port opened at start, for a client nothing spawns")
	server := fs.String("server", "", "echo server URL")
	_ = fs.Parse(args)

	c := &client{name: *name, server: *server}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", c.statusHandler)
	mux.HandleFunc("POST /connect", c.connect)
	mux.HandleFunc("POST /fork", c.fork)
	mux.HandleFunc("POST /exit", func(http.ResponseWriter, *http.Request) {
		go func() {
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
		}()
	})

	if *controlPort != 0 {
		go func() { log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *controlPort), mux)) }()
	}

	lp, err := startLoop(c.server)
	if err != nil {
		log.Fatal(err)
	}
	c.add(lp)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), mux))
}

func (c *client) add(lp *loop) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loops = append(c.loops, lp)
}

func (c *client) statusHandler(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	status := clientStatus{Name: c.name, PID: os.Getpid(), NSInode: pidNamespace()}
	for _, lp := range c.loops {
		status.Conns = append(status.Conns, lp.snapshot())
	}
	c.mu.Unlock()
	_ = json.NewEncoder(w).Encode(status)
}

func (c *client) connect(w http.ResponseWriter, _ *http.Request) {
	lp, err := startLoop(c.server)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.add(lp)
}

// the grandchild's parent is this client, whatever selects it
func (c *client) fork(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	name := r.URL.Query().Get("child")
	if name == "" || err != nil {
		http.Error(w, "child and port required", http.StatusBadRequest)
		return
	}
	if err := spawn(name, port, c.server); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
