// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command native-demo validates the OBI Frida backend using a native TLS fixture.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	incomingTrace  = "cccccccccccccccccccccccccccccccc"
	incomingParent = "dddddddddddddddd"
	response       = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n"
)

type process struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	events chan map[string]json.RawMessage
	done   chan struct{}
	err    error
}

func start(ctx context.Context, environment []string, path, logPath string, args ...string) *process {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = environment
	input, err := cmd.StdinPipe()
	must(err)
	output, err := cmd.StdoutPipe()
	must(err)
	log, err := os.Create(logPath)
	must(err)
	cmd.Stderr = log
	must(cmd.Start())
	p := &process{cmd: cmd, input: input, events: make(chan map[string]json.RawMessage, 64), done: make(chan struct{})}
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 3<<20)
		for scanner.Scan() {
			var event map[string]json.RawMessage
			if json.Unmarshal(scanner.Bytes(), &event) != nil {
				continue
			}
			p.events <- event
		}
		p.err = cmd.Wait()
		_ = log.Close()
		close(p.done)
	}()
	return p
}
func (p *process) stop()                { _ = p.input.Close(); _ = p.cmd.Process.Kill(); <-p.done }
func (p *process) command(value string) { _, err := io.WriteString(p.input, value+"\n"); must(err) }
func (p *process) next(ctx context.Context) map[string]json.RawMessage {
	select {
	case e := <-p.events:
		return e
	case <-p.done:
		panic(fmt.Sprintf("fixture exited: %v", p.err))
	case <-ctx.Done():
		panic(ctx.Err())
	}
}

type span struct {
	Trace      string `json:"traceId"`
	ID         string `json:"spanId"`
	Parent     string `json:"parentSpanId"`
	Kind       int    `json:"kind"`
	Attributes []struct {
		Key   string `json:"key"`
		Value struct {
			Int string `json:"intValue"`
		} `json:"value"`
	} `json:"attributes"`
}
type collector struct {
	sync.Mutex
	spans []span
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var export struct {
		Resources []struct {
			Scopes []struct {
				Spans []span `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.NewDecoder(r.Body).Decode(&export); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.Lock()
	for _, resource := range export.Resources {
		for _, scope := range resource.Scopes {
			for i := range scope.Spans {
				scope.Spans[i].Trace = strings.ToLower(scope.Spans[i].Trace)
				scope.Spans[i].ID = strings.ToLower(scope.Spans[i].ID)
				scope.Spans[i].Parent = strings.ToLower(scope.Spans[i].Parent)
			}
			c.spans = append(c.spans, scope.Spans...)
		}
	}
	c.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, "{}")
}

func (c *collector) snapshot() []span {
	c.Lock()
	defer c.Unlock()
	return append([]span(nil), c.spans...)
}

func ancestor(spans []span, child, root span) bool {
	visited := make(map[string]bool)
	parent := child.Parent
	for parent != "" && !visited[parent] {
		if parent == root.ID {
			return true
		}
		visited[parent] = true
		next := ""
		for _, s := range spans {
			if s.Trace == child.Trace && s.ID == parent {
				next = s.Parent
				break
			}
		}
		parent = next
	}
	return false
}

func matches(spans []span, trace, id, parent string, kind int) []span {
	var result []span
	for _, s := range spans {
		if s.Trace == trace && s.Kind == kind && (id == "" || s.ID == id) && (parent == "" || s.Parent == parent) {
			result = append(result, s)
		}
	}
	return result
}

type injected struct{ name, trace, id string }

func linked(spans []span, contexts []injected) bool {
	roots := matches(spans, incomingTrace, "", incomingParent, 2)
	if len(roots) != 1 {
		return false
	}
	for _, c := range contexts {
		clients := matches(spans, c.trace, c.id, "", 3)
		servers := matches(spans, c.trace, "", c.id, 2)
		if len(clients) != 1 || len(servers) != 1 || !ancestor(spans, clients[0], roots[0]) {
			return false
		}
	}
	return true
}

func certificate(directory string) (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	certPath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	must(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	must(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600))
	return certPath, keyPath
}

func wait(ctx context.Context, predicate func() bool) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for !predicate() {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
}

func number(event map[string]json.RawMessage, key string) int {
	var n int
	must(json.Unmarshal(event[key], &n))
	return n
}

func text(event map[string]json.RawMessage, key string) string {
	var s string
	must(json.Unmarshal(event[key], &s))
	return s
}

func assert(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func run() {
	binary := flag.String("obi", "bin/obi", "OBI built with CGO_ENABLED=0 and -tags=obi_frida")
	fixture := flag.String("fixture", "bin/openssl-native-fixture", "native OpenSSL fixture executable")
	library := flag.String("library", "", "absolute path to libfrida-core.so")
	drain := flag.Bool("drain", false, "stop OBI during a pending moving-buffer retry")
	openssl := flag.String("openssl-library-dir", "", "alternate OpenSSL directory for the controlled fixture only")
	flag.Parse()
	assert(*library != "", "--library is required")
	directory, err := os.MkdirTemp("", "obi-frida-native-")
	must(err)
	defer os.RemoveAll(directory)
	defer func() {
		if failure := recover(); failure != nil {
			for _, name := range []string{"obi.log", "peer.log", "client.log"} {
				data, _ := os.ReadFile(filepath.Join(directory, name))
				fmt.Fprintf(os.Stderr, "%s:\n%s\n", name, data)
			}
			panic(failure)
		}
	}()
	interrupt, stopInterrupt := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopInterrupt()
	ctx, cancel := context.WithTimeout(interrupt, 150*time.Second)
	defer cancel()
	cert, key := certificate(directory)
	receiver := &collector{}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	server := &http.Server{Handler: receiver, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	fixtureEnvironment := os.Environ()
	if *openssl != "" {
		fixtureEnvironment = append(fixtureEnvironment, "LD_LIBRARY_PATH="+*openssl)
	}
	peer := start(ctx, fixtureEnvironment, *fixture, filepath.Join(directory, "peer.log"), "--peer", cert, key)
	defer peer.stop()
	port := number(peer.next(ctx), "port")
	client := start(ctx, fixtureEnvironment, *fixture, filepath.Join(directory, "client.log"), "--client", strconv.Itoa(port), cert)
	defer client.stop()
	ready := client.next(ctx)
	assert(number(ready, "pid") == client.cmd.Process.Pid, "fixture identity mismatch")
	incomingPort := number(ready, "incoming_port")
	libraryPath, err := filepath.Abs(*library)
	must(err)
	config := fmt.Sprintf(`file_format: "1.0"
log_level: info
tracer_provider:
  processors:
    - batch:
        exporter:
          otlp_http:
            endpoint: http://%s/v1/traces
            encoding: json
        schedule_delay: 100
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
        min_process_age: 1ms
        poll_interval: 100ms
      rules:
        - action: include
          match:
            process:
              target_pids: [%d, %d]
      runtimes:
        frida:
          enabled: true
          library: %q
      engine:
        batching:
          batch_timeout: 100ms
          batch_length: 1
    enrich:
      enrichers:
        kubernetes:
          mode: disabled
`, listener.Addr(), peer.cmd.Process.Pid, client.cmd.Process.Pid, libraryPath)
	configPath := filepath.Join(directory, "obi.yaml")
	must(os.WriteFile(configPath, []byte(config), 0o600))
	logPath := filepath.Join(directory, "obi.log")
	log, err := os.Create(logPath)
	must(err)
	defer log.Close()
	obi := exec.CommandContext(ctx, *binary, "--config", configPath)
	obi.Stdout = log
	obi.Stderr = log
	must(obi.Start())
	obiDone := make(chan error, 1)
	go func() { obiDone <- obi.Wait(); close(obiDone) }()
	stopped := false
	defer func() {
		if !stopped {
			_ = obi.Process.Signal(syscall.SIGTERM)
			select {
			case <-obiDone:
			case <-time.After(25 * time.Second):
				_ = obi.Process.Kill()
				<-obiDone
			}
		}
	}()
	wait(ctx, func() bool {
		select {
		case exit := <-obiDone:
			panic(fmt.Sprintf("OBI exited: %v", exit))
		default:
		}
		data, _ := os.ReadFile(logPath)
		return bytes.Count(data, []byte("Frida OpenSSL agent attached")) == 2
	})
	peer.command("start")
	client.command("start")
	upstream, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(incomingPort)), 5*time.Second)
	must(err)
	defer upstream.Close()
	must(upstream.SetDeadline(time.Now().Add(30 * time.Second)))
	_, err = fmt.Fprintf(upstream, "GET /upstream HTTP/1.1\r\nHost: localhost\r\ntraceparent: 00-%s-%s-01\r\n\r\n", incomingTrace, incomingParent)
	must(err)
	prefix := -1
	count := 0
	for {
		event := client.next(ctx)
		if _, ok := event["partial_prefix"]; ok {
			prefix = number(event, "partial_prefix")
			continue
		}
		if text(event, "event") == "retry pending" {
			if *drain {
				must(obi.Process.Signal(syscall.SIGTERM))
				select {
				case err = <-obiDone:
					must(err)
					stopped = true
				case <-ctx.Done():
					panic(ctx.Err())
				}
			}
			continue
		}
		assert(text(event, "event") == "passed", "unexpected fixture event")
		assert(number(event, "retries") > 0, "moving-buffer retry was not exercised")
		count = number(event, "cases")
		fmt.Printf("PASS native OpenSSL fixture: %d cases, %d moving-buffer retries\n", number(event, "cases"), number(event, "retries"))
		break
	}
	received := make([]byte, len(response))
	_, err = io.ReadFull(upstream, received)
	must(err)
	assert(string(received) == response, "incoming response changed")
	var contexts []injected
	// The peer reports every case; OpenSSL 3.5 adds the optional ninth API.
	client.command("stop")
	<-client.done
	must(client.err)
	for index := 0; index < count; index++ {
		event := peer.next(ctx)
		name := text(event, "case")
		raw, decodeErr := hex.DecodeString(text(event, "request"))
		must(decodeErr)
		parts := bytes.SplitN(raw, []byte("\r\n\r\n"), 2)
		assert(len(parts) == 2, "missing header terminator")
		var headers []string
		for _, line := range strings.Split(string(parts[0]), "\r\n")[1:] {
			key, value, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(key, "traceparent") {
				headers = append(headers, strings.TrimSpace(value))
			}
		}
		switch name {
		case "existing":
			assert(len(headers) == 1 && headers[0] == "00-11111111111111111111111111111111-2222222222222222-01", "existing header changed")
		case "fragmented", "opaque":
			assert(len(headers) == 0, "unsupported input was modified")
		default:
			assert(len(headers) == 1, "missing injected header for "+name)
			fields := strings.Split(headers[0], "-")
			assert(len(fields) == 4 && fields[1] == incomingTrace && len(fields[2]) == 16, "invalid OBI context")
			contexts = append(contexts, injected{name: name, trace: fields[1], id: fields[2]})
		}
		if name == "partial" {
			assert(prefix >= 0 && prefix < 2048, "invalid partial prefix")
			expected := append(bytes.Repeat([]byte("p"), prefix), bytes.Repeat([]byte("q"), 2048-prefix)...)
			assert(bytes.Equal(parts[1], expected), "unsent body edits lost")
		}
		if name == "retry" {
			assert(bytes.Equal(parts[1], bytes.Repeat([]byte("r"), 256*1024)), "retry body changed")
		}
		if name == "opaque" {
			assert(bytes.Equal(raw, []byte("\x00OBI\x01\r\nX-Case: opaque\r\n\r\n")), "opaque bytes changed")
		}
	}
	peer.command("stop")
	<-peer.done
	must(peer.err)
	if *drain {
		data, _ := os.ReadFile(logPath)
		assert(stopped && bytes.Contains(data, []byte("Frida agent draining")), "missing graceful drain")
		fmt.Println("PASS OBI shutdown retained the pending buffer; native application completed its write")
		return
	}
	linkContext, finishLinks := context.WithTimeout(ctx, 20*time.Second)
	defer finishLinks()
	defer func() {
		if failure := recover(); failure != nil {
			data, _ := json.Marshal(receiver.snapshot())
			fmt.Fprintln(os.Stderr, "Exported spans:", string(data))
			panic(failure)
		}
	}()
	wait(linkContext, func() bool { return linked(receiver.snapshot(), contexts) })
	spans := receiver.snapshot()
	assert(len(matches(spans, "11111111111111111111111111111111", "", "2222222222222222", 2)) == 1, "existing server parent lost")
	root := matches(spans, incomingTrace, "", incomingParent, 2)[0]
	for _, s := range spans {
		if s.Kind != 2 && s.Kind != 3 {
			continue
		}
		status, serverPort := "", ""
		for _, a := range s.Attributes {
			if a.Key == "http.response.status_code" {
				status = a.Value.Int
			}
			if a.Key == "server.port" {
				serverPort = a.Value.Int
			}
		}
		assert(status == "200", "incorrect HTTP status")
		expected := port
		if s.ID == root.ID {
			expected = incomingPort
		}
		assert(serverPort == strconv.Itoa(expected), "incorrect server port")
	}
	for _, c := range contexts {
		fmt.Printf("PASS OTLP %s: trace=%s, client=%s, server parent=%s\n", c.name, c.trace, c.id, c.id)
	}
	fmt.Println("PASS OBI discovery, readonly input, existing context, partial counts and body edits, moving retries, and full span ancestry; no Python runtime")
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			os.Exit(1)
		}
	}()
	run()
}
