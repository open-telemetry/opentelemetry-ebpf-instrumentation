// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

type proxyEvent struct {
	ClientVerify   string `json:"client_verify,omitempty"`
	Role           string `json:"role"`
	ID             string `json:"id"`
	Path           string `json:"path"`
	Traceparent    string `json:"traceparent"`
	Connection     string `json:"connection"`
	Protocol       string `json:"protocol"`
	Status         int    `json:"status"`
	Upstream       string `json:"upstream"`
	UpstreamStatus string `json:"upstream_status"`
	Cache          string `json:"cache"`
}

type exportedSpan struct {
	Trace  string `json:"trace"`
	ID     string `json:"id"`
	Parent string `json:"parent"`
	Role   string `json:"role"`
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Target string `json:"reported_target,omitempty"`
	PID    int    `json:"pid"`
	Status int64  `json:"http_status"`
}

type caseResult struct {
	Name             string         `json:"name"`
	Support          string         `json:"support"`
	ContextContinues bool           `json:"context_continues"`
	FullAncestry     bool           `json:"full_ancestry"`
	ScenarioProven   bool           `json:"scenario_proven"`
	Observations     []observation  `json:"responses"`
	Events           []proxyEvent   `json:"proxy_events"`
	Spans            []exportedSpan `json:"spans"`
	Failures         []string       `json:"failures,omitempty"`
	RequiredWork     string         `json:"required_work,omitempty"`
	Error            string         `json:"harness_error,omitempty"`
	SpansBeforeDrain int            `json:"spans_before_drain"`
}

func (m *matrix) spans() ([]exportedSpan, error) {
	file, err := os.Open(filepath.Join(m.directory, "traces.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()
	var result []exportedSpan
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 16<<20)
	for scanner.Scan() {
		traces, decodeErr := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces(scanner.Bytes())
		if decodeErr != nil {
			// A collector write can still be in progress; retry on the next read.
			if !json.Valid(scanner.Bytes()) {
				continue
			}
			return nil, decodeErr
		}
		resources := traces.ResourceSpans()
		for i := 0; i < resources.Len(); i++ {
			resource := resources.At(i)
			instance, _ := resource.Resource().Attributes().Get("service.instance.id")
			_, pidText, _ := strings.Cut(instance.Str(), ":")
			pid, _ := strconv.Atoi(pidText)
			role := m.roles[pid]
			if role == "" {
				role = "client"
			}
			for j := 0; j < resource.ScopeSpans().Len(); j++ {
				spans := resource.ScopeSpans().At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					s := spans.At(k)
					attributes := s.Attributes()
					path, _ := attributes.Get("url.path")
					pathText := path.Str()
					if pathText == "" {
						full, _ := attributes.Get("url.full")
						pathText = full.Str()
					}
					status, _ := attributes.Get("http.response.status_code")
					result = append(result, exportedSpan{Trace: s.TraceID().String(), ID: s.SpanID().String(), Parent: s.ParentSpanID().String(), Role: role, Kind: strings.ToLower(s.Kind().String()), Path: normalizePath(pathText), Target: pathText, PID: pid, Status: status.Int()})
				}
			}
		}
	}
	return result, scanner.Err()
}

func normalizePath(path string) string {
	// OBI can prepend the proxy host to an absolute-form request target.
	// Normalize only for matching; retain the original attribute in Target.
	for range 2 {
		if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "//") {
			break
		}
		parsed, err := url.Parse(path)
		if err != nil {
			break
		}
		path = parsed.Path
	}
	return path
}

func rootSpan(spans []exportedSpan, o observation) (exportedSpan, bool) {
	for _, s := range spans {
		if s.PID == o.ClientPID && s.Kind == "client" && s.Path == o.Path {
			return s, true
		}
	}
	return exportedSpan{}, false
}

func descendant(spans []exportedSpan, parent exportedSpan, role, kind string) (exportedSpan, bool) {
	for _, candidate := range spans {
		if candidate.Trace != parent.Trace || candidate.Role != role || candidate.Kind != kind || candidate.Path != parent.Path {
			continue
		}
		id := candidate.Parent
		visited := make(map[string]bool)
		for id != "" && !visited[id] {
			if id == parent.ID {
				return candidate, true
			}
			visited[id] = true
			next := ""
			for _, intermediate := range spans {
				if intermediate.Trace == parent.Trace && intermediate.ID == id && intermediate.Kind == "internal" && intermediate.Role == role {
					next = intermediate.Parent
					break
				}
			}
			id = next
		}
	}
	return exportedSpan{}, false
}

func completeChain(spans []exportedSpan, root exportedSpan, proxies []string, cache bool) bool {
	parent := root
	for _, role := range proxies {
		server, ok := descendant(spans, parent, role, "server")
		if !ok {
			return false
		}
		if cache {
			return true
		}
		client, ok := descendant(spans, server, role, "client")
		if !ok {
			return false
		}
		parent = client
	}
	for _, role := range []string{"backend", "backend2"} {
		if _, ok := descendant(spans, parent, role, "server"); ok {
			return true
		}
	}
	return false
}

func evaluate(test scenario, responses []observation, events []proxyEvent, all []exportedSpan) caseResult {
	r := caseResult{Name: test.Name, Observations: responses, ContextContinues: true, FullAncestry: true, ScenarioProven: true}
	if len(responses) != max(1, test.Requests) {
		r.ContextContinues = false
		r.FullAncestry = false
		r.ScenarioProven = false
	}
	traces := make(map[string]bool)
	for _, s := range all {
		if strings.Contains(s.Path, "/"+test.Name+"/") {
			traces[s.Trace] = true
		}
	}
	for _, s := range all {
		if strings.Contains(s.Path, "/"+test.Name+"/") || (s.Kind == "internal" && traces[s.Trace]) {
			r.Spans = append(r.Spans, s)
		}
	}
	for _, e := range events {
		if strings.Contains(e.Path, "/"+test.Name+"/") {
			r.Events = append(r.Events, e)
		}
	}
	for _, o := range responses {
		root, found := rootSpan(r.Spans, o)
		if !found {
			r.Failures = append(r.Failures, fmt.Sprintf("no exported client span for PID %d %s", o.ClientPID, o.Path))
		}
		wire := o.Traceparent
		if o.Cache == "HIT" {
			for _, event := range r.Events {
				if event.ID == o.RequestID && event.Role == "nginx" {
					wire = event.Traceparent
				}
			}
		}
		fields := strings.Split(wire, "-")
		continued := found && len(fields) == 4 && fields[1] == root.Trace
		if test.Existing {
			continued = wire == existingContext
		}
		if !continued {
			r.Failures = append(r.Failures, "received context does not continue the originating client trace: "+o.RequestID)
		}
		r.ContextContinues = r.ContextContinues && continued
		linked := found && completeChain(r.Spans, root, test.Proxies, o.Cache == "HIT")
		r.FullAncestry = r.FullAncestry && linked
	}
	if !r.FullAncestry {
		r.Failures = append(r.Failures, "missing or incorrect parent edge in the expected client/proxy/origin span chain")
	}
	switch test.Name {
	case "unobserved-reverse-proxy":
		for _, span := range r.Spans {
			if span.Role == "unobserved" {
				r.ScenarioProven = false
			}
		}
	case "direct-mutual-tls", "nginx-mutual-tls-upstream":
		r.ScenarioProven = len(responses) == 1 && responses[0].ClientVerify == "SUCCESS"
	case "nginx-mutual-tls-client":
		r.ScenarioProven = false
		for _, event := range r.Events {
			if event.Role == "nginx" && event.ClientVerify == "SUCCESS" {
				r.ScenarioProven = true
			}
		}
	case "nginx-upstream-pool":
		connections := map[string]bool{}
		for _, o := range responses {
			connections[o.Backend+":"+o.Connection] = true
		}
		r.ScenarioProven = len(connections) == 1 && len(responses) == test.Requests && responses[len(responses)-1].Requests >= test.Requests
	case "nginx-load-balance":
		backends := map[string]bool{}
		for _, o := range responses {
			backends[o.Backend] = true
		}
		r.ScenarioProven = len(backends) == 2
	case "nginx-retry-503":
		r.ScenarioProven = false
		for _, event := range r.Events {
			if event.Role == "nginx" && strings.Contains(event.UpstreamStatus, "503, 200") {
				r.ScenarioProven = true
			}
		}
	case "nginx-cache":
		r.ScenarioProven = len(responses) == 2 && responses[0].Cache == "MISS" && responses[1].Cache == "HIT"
		origins := 0
		for _, event := range r.Events {
			if event.Role == "backend" {
				origins++
			}
		}
		r.ScenarioProven = r.ScenarioProven && origins == 1
	case "h1-client-apache-h2-origin", "h2-client-apache-h2-origin":
		r.ScenarioProven = len(responses) == 1 && responses[0].Protocol == "HTTP/2.0"
	}
	if test.Mode == "h2" || test.Mode == "h3" {
		frontH2 := false
		expectedProtocol := "HTTP/2.0"
		if test.Mode == "h3" {
			expectedProtocol = "HTTP/3.0"
		}
		for _, event := range r.Events {
			if event.Role == test.Service && event.Protocol == expectedProtocol {
				frontH2 = true
			}
		}
		r.ScenarioProven = r.ScenarioProven && frontH2
	}
	switch {
	case !r.ScenarioProven:
		r.Error = "the fixture did not establish its advertised pooling/retry/cache/protocol condition"
		r.Support = "harness-error"
	case r.ContextContinues && r.FullAncestry:
		r.Support = "supported-in-this-fixture"
	case r.ContextContinues:
		r.Support = "context-only"
	default:
		r.Support = "unsupported-in-this-fixture"
	}
	if test.Name == "nginx-replace-header" {
		r.Support = "proxy-policy-replaces-context"
	}
	if r.Support != "supported-in-this-fixture" {
		r.RequiredWork = requiredWork(test)
	}
	return r
}

func requiredWork(test scenario) string {
	switch {
	case test.Mode == "h3":
		return "Add QUIC/HTTP3 stream-aware request interception and QPACK/header insertion; existing TLS stream hooks do not establish end-to-end HTTP/3 context or span ancestry."
	case test.Split:
		return "Incremental HTTP/1 header parsing and safe buffer accounting across application writes; then retest proxy hop ancestry."
	case test.Mode == "https-proxy":
		return "Support nested TLS/memory BIO connection association, or instrument the HTTP serializer above TLS."
	case test.Mode == "h2" || strings.Contains(test.Name, "h2-origin"):
		return "Validate HTTP/2 observation and stream context adoption; add HPACK/frame-aware insertion or serializer hooks where outgoing HTTP/2 context is missing."
	case test.Name == "nginx-replace-header":
		return "Change the proxy's explicit header-replacement policy if end-to-end continuity is desired; instrumentation must respect application-owned context."
	case test.Prefix == "/plain/" || test.Mode == "forward-http":
		return "Integrate plaintext injection/context handoff with existing socket propagation and fix per-hop parenting; the measured --propagation headers configuration alone does not establish support."
	case test.Existing:
		return "Preserve caller-owned context while defining OBI client-span adoption and proxy outgoing parent semantics."
	default:
		return "Correlate each proxy request with its upstream attempt and reconcile the forwarded header with OBI's outgoing client span; preserve application-owned context."
	}
}

func (m *matrix) runCase(test scenario) caseResult {
	ctx, cancel := context.WithTimeout(m.ctx, 40*time.Second)
	defer cancel()
	count := max(1, test.Requests)
	responses := make([]observation, count)
	var clients []*opensslClient
	defer func() {
		for _, client := range clients {
			client.close()
		}
	}()
	failure := func(err error) caseResult {
		return caseResult{Name: test.Name, Support: "harness-error", Error: err.Error(), Observations: responses}
	}
	if test.Mode == "connect-auth" {
		address, err := m.port(test.Service, test.Port)
		if err != nil {
			return failure(err)
		}
		conn, err := net.DialTimeout("tcp4", address, 5*time.Second)
		if err != nil {
			return failure(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = fmt.Fprint(conn, "CONNECT backend:8443 HTTP/1.1\r\nHost: backend:8443\r\n\r\n")
		if err != nil {
			_ = conn.Close()
			return failure(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		_ = conn.Close()
		if err != nil {
			return failure(err)
		}
		if response.StatusCode != http.StatusProxyAuthRequired {
			return failure(fmt.Errorf("unauthenticated CONNECT returned %d, expected 407", response.StatusCode))
		}
	}

	if test.Mode != "h2" && test.Mode != "h3" && test.Mode != "https-proxy" && test.Mode != "forward-http" {
		connections := count
		if test.Reuse {
			connections = 1
		}
		for i := 0; i < connections; i++ {
			client, err := m.openClient(ctx, test, i)
			if err != nil {
				return failure(err)
			}
			clients = append(clients, client)
		}
	}
	request := func(index int) error {
		var err error
		if len(clients) == 0 {
			responses[index], err = m.curl(ctx, test, index)
		} else {
			client := clients[index%len(clients)]
			responses[index], err = client.request(test, index)
		}
		return err
	}
	if test.Concurrent {
		var wg sync.WaitGroup
		errors := make(chan error, count)
		for i := range count {
			wg.Go(func() { errors <- request(i) })
		}
		wg.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				return failure(err)
			}
		}
	} else {
		for i := range count {
			if err := request(i); err != nil {
				return failure(err)
			}
		}
	}
	for _, client := range clients {
		client.close()
	}
	clients = nil
	// Wait for asynchronous span export. A missing span is a measured outcome.
	export, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	_ = poll(export, func() (bool, error) {
		spans, err := m.spans()
		if err != nil {
			return false, err
		}
		for _, o := range responses {
			if _, found := rootSpan(spans, o); !found {
				return false, nil
			}
		}
		return true, nil
	})
	time.Sleep(time.Second)
	spans, err := m.spans()
	if err != nil {
		return failure(err)
	}
	events, err := m.proxyLogs()
	if err != nil {
		return failure(err)
	}
	return evaluate(test, responses, events, spans)
}
