// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpftracer "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type rustTestReporter struct{ imetrics.NoopReporter }

func TestRustContextPropagation(t *testing.T) {
	binary := os.Getenv("OBI_RUST_TEST_BINARY")
	if binary == "" {
		t.Skip("build components/rustcontext and set OBI_RUST_TEST_BINARY")
	}
	if os.Getenv("OBI_RUST_TEST_DEBUG") != "" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	require.NoError(t, rlimit.RemoveMemlock())
	for _, runtime := range []string{"multi_thread", "current_thread"} {
		t.Run(runtime, func(t *testing.T) {
			testRustContextPropagation(t, binary, runtime == "current_thread")
		})
	}
}

func testRustContextPropagation(t *testing.T, binary string, currentThread bool) {
	var connections atomic.Int32
	var received sync.Map
	var downstreamHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Store(r.URL.Path, r.Header.Values("traceparent"))
		if (os.Getenv("OBI_RUST_TEST_H2") != "" || os.Getenv("OBI_RUST_TEST_H2C") != "") && r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2, got %s", r.Proto)
		}
		_, _ = io.WriteString(w, "ok")
	})
	if os.Getenv("OBI_RUST_TEST_H2C") != "" {
		downstreamHandler = h2c.NewHandler(downstreamHandler, &http2.Server{})
	}
	downstream := httptest.NewUnstartedServer(downstreamHandler)
	require.NoError(t, downstream.Listener.Close())
	listener, err := net.Listen("tcp", "127.0.0.1:18091")
	require.NoError(t, err)
	downstream.Listener = listener
	downstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	if os.Getenv("OBI_RUST_TEST_TLS") != "" {
		downstream.EnableHTTP2 = os.Getenv("OBI_RUST_TEST_H2") != ""
		if os.Getenv("OBI_RUST_TEST_RUSTLS_CLIENT") != "" {
			downstream.TLS = &tls.Config{Certificates: []tls.Certificate{rustTestCertificate(t)}}
		}
		downstream.StartTLS()
	} else {
		downstream.Start()
	}
	t.Cleanup(downstream.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	downstreamURL := downstream.URL
	if os.Getenv("OBI_RUST_TEST_RUSTLS_CLIENT") != "" {
		downstreamURL = strings.Replace(downstreamURL, "127.0.0.1", "localhost", 1)
	}
	cmd := osexec.CommandContext(ctx, binary, downstreamURL)
	cmd.Env = os.Environ()
	if os.Getenv("OBI_RUST_TEST_APP_HEADER") != "" {
		cmd.Env = append(cmd.Env, "OBI_RUST_APP_HEADER=1")
	}
	if os.Getenv("OBI_RUST_TEST_H2C") != "" {
		cmd.Env = append(cmd.Env, "OBI_RUST_H2C=1")
	}
	serverTLS := os.Getenv("OBI_RUST_TEST_SERVER") != ""
	if serverTLS || os.Getenv("OBI_RUST_TEST_RUSTLS_CLIENT") != "" {
		certificateSource := downstream
		if certificateSource.TLS == nil {
			certificateSource = httptest.NewTLSServer(nil)
			defer certificateSource.Close()
		}
		cert := certificateSource.TLS.Certificates[0]
		key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		require.NoError(t, err)
		certPath, keyPath := t.TempDir()+"/cert.der", t.TempDir()+"/key.der"
		certificate := cert.Certificate[0]
		if os.Getenv("OBI_RUST_TEST_RUSTLS_CLIENT") != "" {
			certificate = cert.Certificate[len(cert.Certificate)-1]
		}
		require.NoError(t, os.WriteFile(certPath, certificate, 0o600))
		require.NoError(t, os.WriteFile(keyPath, key, 0o600))
		cmd.Env = append(cmd.Env, "OBI_RUST_CERT="+certPath, "OBI_RUST_KEY="+keyPath)
	}
	if os.Getenv("OBI_RUST_TEST_SERVER_HTTP1") != "" {
		cmd.Env = append(cmd.Env, "OBI_RUST_SERVER_HTTP1=1")
	}
	if os.Getenv("OBI_RUST_TEST_H2") != "" {
		cmd.Env = append(cmd.Env, "OBI_RUST_H2=1")
	}
	if currentThread {
		cmd.Env = append(cmd.Env, "OBI_RUST_CURRENT_THREAD=1")
	}
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan())
	address := strings.TrimPrefix(scanner.Text(), "READY ")
	require.NotEqual(t, scanner.Text(), address)
	pid := app.PID(cmd.Process.Pid)

	cfg := obi.DefaultConfig
	cfg.EBPF.BpfDebug = os.Getenv("OBI_RUST_TEST_DEBUG") != ""
	cfg.EBPF.TrackRequestHeaders = true
	if os.Getenv("OBI_RUST_TEST_INJECT") != "" {
		cfg.EBPF.ContextPropagation = config.ContextPropagationHeaders
	}
	cfg.EBPF.BatchTimeout = 10 * time.Millisecond
	if os.Getenv("OBI_RUST_TEST_NO_USER_WRITE") != "" {
		previous := ebpfcommon.IntegrityModeOverride
		ebpfcommon.IntegrityModeOverride = true
		t.Cleanup(func() { ebpfcommon.IntegrityModeOverride = previous })
	}
	pids := ebpfcommon.NewPIDsFilter(&cfg.Discovery, slog.Default(), rustTestReporter{})
	tracer := New(pids, &cfg, rustTestReporter{})
	programs := []ebpftracer.Tracer{tracer}
	if os.Getenv("OBI_RUST_TEST_TPINJECTOR") != "" && os.Getenv("OBI_RUST_TEST_INJECT") != "" {
		programs = append(programs, tpinjector.New(&cfg, pids))
	}
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = pids
	processTracer := ebpftracer.NewProcessTracer(ebpftracer.Generic, programs, &cfg, rustTestReporter{})
	require.NoError(t, processTracer.Init(eventContext, &cfg))
	fi := rustProcessFileInfo(t, pid)
	processTracer.AllowPID(pid, fi.Ns(), fi)
	var capabilities BpfRustCapabilitiesT
	require.NoError(t, tracer.bpfObjects.RustCapabilities.Lookup(uint32(pid), &capabilities))
	executable, err := fi.OpenExecutable()
	require.NoError(t, err)
	defer executable.Close()
	require.NoError(t, processTracer.NewExecutableFile(executable, &ebpftracer.Instrumentable{
		Type: svc.InstrumentableRust, FileInfo: fi,
	}))
	spans := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	events := spans.Subscribe(msg.SubscriberName("rust-context-test"))
	runCtx, stop := context.WithCancel(ctx)
	if cfg.EBPF.BpfDebug {
		go logger.ReadDebugEventsMap(runCtx, tracer.bpfObjects.DebugEvents, slog.With("component", "rust.BPFDebug"))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		processTracer.Run(runCtx, eventContext, spans)
	}()
	t.Cleanup(func() {
		cancel()
		stop()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("Rust tracer did not stop")
		}
	})

	client := &http.Client{Timeout: 10 * time.Second}
	scheme := "http"
	if serverTLS {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
		defer client.CloseIdleConnections()
	}
	send := func(i int) error {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s/request/%d", scheme, address, i), nil)
		if err != nil {
			return err
		}
		parentID := "0000000000000001"
		if os.Getenv("OBI_RUST_TEST_FORWARDED_APP_HEADER") != "" {
			parentID = "1111111111111111"
		}
		req.Header.Set("traceparent", fmt.Sprintf("00-%032x-%s-01", i+1, parentID))
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	// The second sequential request reuses Hyper's existing connection task.
	require.NoError(t, send(0))
	require.NoError(t, send(1))
	require.EqualValues(t, 1, connections.Load(), "the warmup requests must reuse Hyper's connection")
	requests := 10
	if count := os.Getenv("OBI_RUST_TEST_REQUESTS"); count != "" {
		requests, err = strconv.Atoi(count)
		require.NoError(t, err)
		require.GreaterOrEqual(t, requests, 2)
		require.LessOrEqual(t, requests, 1000)
	}
	var wg sync.WaitGroup
	errors := make(chan error, requests)
	for i := 2; i < requests; i++ {
		wg.Go(func() { errors <- send(i) })
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	var otherSpans []request.Span
	servers := map[string]request.Span{}
	clients := map[string]request.Span{}
	deadline := time.After(20 * time.Second)
	for len(servers) < requests || len(clients) < requests {
		select {
		case batch := <-events:
			for _, span := range batch {
				if !strings.HasPrefix(span.Path, "/request/") {
					if len(otherSpans) < 20 {
						otherSpans = append(otherSpans, span)
					}
					continue
				}
				switch span.Type {
				case request.EventTypeHTTP, request.EventTypeGRPC:
					servers[span.Path] = span
				case request.EventTypeHTTPClient, request.EventTypeGRPCClient:
					clients[span.Path] = span
				}
			}
		case <-deadline:
			for _, span := range otherSpans {
				t.Logf("other span type=%d method=%s path=%q trace=%s", span.Type, span.Method, span.Path, span.TraceID)
			}
			var stats []BpfRingbufWriteStatsT
			err := tracer.bpfObjects.RingbufWriteStatsStorage.Lookup(uint32(0), &stats)
			var writes, failures uint64
			for _, cpu := range stats {
				writes += cpu.Writes
				failures += cpu.Failures
			}
			t.Logf("ringbuf writes=%d failures=%d error=%v", writes, failures, err)
			var protocol BpfRustProtocolConfigT
			_ = tracer.bpfObjects.RustProtocolConfigs.Lookup(uint32(pid), &protocol)
			t.Logf("enabled protocols: HTTP1=%d HTTP2=%d Rustls=%d", protocol.Http1, protocol.Http2, protocol.Rustls)
			for name, m := range map[string]*ebpf.Map{"TLS reads": tracer.bpfObjects.RustTlsReads, "TLS bindings": tracer.bpfObjects.RustlsConnections, "TLS buffers": tracer.bpfObjects.RustlsReadBuffers} {
				var key BpfRustTaskKeyT
				count := 0
				iterator := m.Iterate()
				value := make([]byte, m.ValueSize())
				for iterator.Next(&key, &value) {
					count++
				}
				t.Logf("%s: %d", name, count)
			}
			for i := range requests {
				path := fmt.Sprintf("/request/%d", i)
				if _, ok := clients[path]; !ok {
					t.Logf("missing client %s", path)
				}
				if _, ok := servers[path]; !ok {
					t.Logf("missing server %s; client trace=%s parent=%s", path, clients[path].TraceID, clients[path].ParentSpanID)
				}
			}
			for path, server := range servers {
				t.Logf("observed server %s trace=%s span=%s parent=%s", path, server.TraceID, server.SpanID, server.ParentSpanID)
			}
			var stream BpfHttp2ConnStreamT
			var h2 BpfHttp2GrpcRequestT
			h2Iterator := tracer.bpfObjects.OngoingHttp2Grpc.Iterate()
			for h2Iterator.Next(&stream, &h2) {
				t.Logf("pending H2 stream=%d type=%d trace=%x span=%x end=%d", stream.StreamId, h2.Type, h2.Tp.TraceId, h2.Tp.SpanId, h2.EndMonotimeNs)
			}
			var key BpfPidConnectionInfoT
			var pending BpfHttpInfoT
			iterator := tracer.bpfObjects.OngoingHttp.Iterate()
			for iterator.Next(&key, &pending) {
				t.Logf("pending HTTP ports=%d:%d status=%d submitted=%d delayed=%d len=%d response=%d", key.Conn.S_port, key.Conn.D_port, pending.Status, pending.Submitted, pending.Delayed, pending.Len, pending.RespLen)
			}
			t.Fatalf("missing Rust spans: servers=%d clients=%d", len(servers), len(clients))
		}
	}
	injected := 0
	pageFaults := 0
	for i := range requests {
		path := fmt.Sprintf("/request/%d", i)
		expected, err := trace.TraceIDFromHex(fmt.Sprintf("%032x", i+1))
		require.NoError(t, err)
		require.Equal(t, expected, servers[path].TraceID, path)
		if os.Getenv("OBI_RUST_TEST_PARTIAL_CLIENT") == "" {
			require.Equal(t, expected, clients[path].TraceID, path)
			require.Equal(t, servers[path].SpanID, clients[path].ParentSpanID, path)
		} else {
			require.NotEqual(t, expected, clients[path].TraceID, "an unproven client handoff must not borrow an unrelated parent: %s", path)
			require.Equal(t, trace.SpanID{}, clients[path].ParentSpanID, path)
		}
		if os.Getenv("OBI_RUST_TEST_INJECT") != "" {
			header, ok := received.Load(path)
			require.True(t, ok, path)
			if len(header.([]string)) == 0 {
				require.Empty(t, os.Getenv("OBI_RUST_TEST_NO_USER_WRITE"),
					"plaintext socket injection must not require user-memory writes: %s", path)
				if os.Getenv("OBI_RUST_TEST_TLS") == "" {
					require.Empty(t, os.Getenv("OBI_RUST_TEST_TPINJECTOR"),
						"plaintext socket fallback must recover failed user-memory writes: %s", path)
				}
				matched := 0
				var key BpfRustH2KeyT
				var request BpfRustHttpRequestT
				iterator := tracer.bpfObjects.RustH2Requests.Iterate()
				for iterator.Next(&key, &request) {
					if key.Pid == uint32(pid) && request.Wire.SpanId == [8]uint8(clients[path].SpanID) && request.Wire.TraceId == [16]uint8(clients[path].TraceID) {
						require.EqualValues(t, 2, request.InjectionResult, path)
						require.Equal(t, -int32(syscall.EFAULT), request.PayloadWriteError, path)
						matched++
					}
				}
				require.NoError(t, iterator.Err())
				var http1Key BpfRustWireKeyT
				var failure BpfRustHttp1FailureT
				http1Iterator := tracer.bpfObjects.RustHttp1Failures.Iterate()
				for http1Iterator.Next(&http1Key, &failure) {
					if http1Key.Pid == uint32(pid) && http1Key.TraceId == [16]uint8(expected) && failure.ParentSpanId == [8]uint8(servers[path].SpanID) {
						require.Equal(t, -int32(syscall.EFAULT), failure.PayloadWriteError, path)
						matched++
					}
				}
				require.NoError(t, http1Iterator.Err())
				require.Equal(t, 1, matched, "an absent wire header must have a recorded payload page fault: %s", path)
				pageFaults++
				continue
			}
			injected++
			require.Equal(t, []string{fmt.Sprintf("00-%s-%s-01", clients[path].TraceID, clients[path].SpanID)}, header, path)
			if os.Getenv("OBI_RUST_TEST_APP_HEADER") != "" {
				require.Equal(t, []string{fmt.Sprintf("00-%s-1111111111111111-01", expected)}, header,
					"the application owns its header: %s", path)
			}
		}
	}
	if os.Getenv("OBI_RUST_TEST_INJECT") != "" {
		require.Equal(t, requests, injected+pageFaults, "every wire header must be present or have a verified payload page fault")
		if pageFaults > 0 {
			t.Logf("wire injection skipped %d/%d requests after verified user-page faults", pageFaults, requests)
		}
	}
}

func rustTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OBI Rust test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}

func rustProcessFileInfo(t *testing.T, pid app.PID) *discexec.FileInfo {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/exe", pid)
	info, err := os.Stat(path)
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	ns, err := procs.FindNamespace(pid)
	require.NoError(t, err)
	start, err := procs.StartTime(pid)
	require.NoError(t, err)
	return discexec.New(discexec.Init{
		Service:        svc.Attrs{UID: svc.UID{Name: "rust-context"}, SDKLanguage: svc.InstrumentableRust},
		ProExeLinkPath: path, Pid: pid, Dev: stat.Dev, Ino: stat.Ino, Ns: ns, StartTime: start,
	})
}
