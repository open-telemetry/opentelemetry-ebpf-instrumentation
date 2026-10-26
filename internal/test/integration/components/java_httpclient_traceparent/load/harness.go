// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
)

type counts struct {
	Requests       atomic.Int64
	WithHeader     atomic.Int64
	Duplicate      atomic.Int64
	TLSConnections atomic.Int64
	Spans          atomic.Int64
	Clients        atomic.Int64
	Servers        atomic.Int64
}

var metrics counts

type receiver struct {
	collector.UnimplementedTraceServiceServer
}

type spanRecord struct {
	Trace, ID, Parent, URL, Service string
	Kind                            int32
	Start, End                      uint64
}
type requestRecord struct {
	Protocol   int
	Connection string
	Headers    []string
	Spans      []spanRecord
}

var records = struct {
	sync.Mutex
	Requests map[string]*requestRecord
}{Requests: make(map[string]*requestRecord)}

func record(key string) *requestRecord {
	r := records.Requests[key]
	if r == nil {
		r = &requestRecord{}
		records.Requests[key] = r
	}
	return r
}
func (receiver) Export(_ context.Context, request *collector.ExportTraceServiceRequest) (*collector.ExportTraceServiceResponse, error) {
	for _, resource := range request.ResourceSpans {
		service := ""
		for _, attribute := range resource.Resource.GetAttributes() {
			if attribute.Key == "service.name" {
				service = attribute.Value.GetStringValue()
			}
		}
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				metrics.Spans.Add(1)
				if span.Kind == 3 {
					metrics.Clients.Add(1)
				}
				if span.Kind == 2 {
					metrics.Servers.Add(1)
				}
				url := ""
				for _, attr := range span.Attributes {
					if attr.Key == "url.full" || attr.Key == "url.path" {
						url = attr.Value.GetStringValue()
					}
				}
				trace := hex.EncodeToString(span.TraceId)
				key := trace
				if strings.Contains(url, "/backend/") {
					key = strings.Split(url, "/backend/")[1]
				} else if strings.Contains(url, "/call/") {
					key = strings.Split(url, "/call/")[1]
				}
				if len(key) == 32 {
					records.Lock()
					r := record(key)
					r.Spans = append(r.Spans, spanRecord{trace, hex.EncodeToString(span.SpanId), hex.EncodeToString(span.ParentSpanId), url, service, int32(span.Kind), span.StartTimeUnixNano, span.EndTimeUnixNano})
					records.Unlock()
				}
			}
		}
	}
	return &collector.ExportTraceServiceResponse{}, nil
}
func serve(cert, key string) {
	grpcServer := grpc.NewServer()
	collector.RegisterTraceServiceServer(grpcServer, receiver{})
	listener, err := net.Listen("tcp", ":4317")
	if err != nil {
		log.Fatal(err)
	}
	go func() { log.Fatal(grpcServer.Serve(listener)) }()
	go func() {
		log.Fatal(http.ListenAndServe(":8082", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/records" {
				records.Lock()
				defer records.Unlock()
				_ = json.NewEncoder(w).Encode(records.Requests)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]int64{"requests": metrics.Requests.Load(), "with_header": metrics.WithHeader.Load(), "duplicates": metrics.Duplicate.Load(), "tls_connections": metrics.TLSConnections.Load(), "spans": metrics.Spans.Load(), "clients": metrics.Clients.Load(), "servers": metrics.Servers.Load()})
		})))
	}()
	backend := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 128}}
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.Requests.Add(1)
		headers := r.Header.Values("Traceparent")
		records.Lock()
		record(strings.TrimPrefix(r.URL.Path, "/backend/")).Headers = append([]string{}, headers...)
		record(strings.TrimPrefix(r.URL.Path, "/backend/")).Protocol = r.ProtoMajor
		record(strings.TrimPrefix(r.URL.Path, "/backend/")).Connection = r.RemoteAddr
		records.Unlock()
		if len(headers) > 0 {
			metrics.WithHeader.Add(1)
		}
		if len(headers) > 1 {
			metrics.Duplicate.Add(1)
		}
		req, _ := http.NewRequestWithContext(r.Context(), "GET", "http://downstream:8086"+r.URL.Path, nil)
		for _, header := range headers {
			req.Header.Add("Traceparent", header)
		}
		req.Header.Set("Tracestate", r.Header.Get("Tracestate"))
		response, err := backend.Do(req)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer response.Body.Close()
		w.Header().Set("X-Traceparent-Count", strconv.Itoa(len(headers)))
		received := "00-00000000000000000000000000000000-0000000000000000-00"
		if len(headers) > 0 {
			received = headers[0]
		}
		w.Header().Set("X-Received-Traceparent", received)
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	server := &http.Server{Addr: ":8443", Handler: proxy, ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ConnState: func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			metrics.TLSConnections.Add(1)
		}
	}}
	log.Fatal(server.ListenAndServeTLS(cert, key))
}

type result struct {
	IngressReused  int64               `json:"ingress_reused"`
	IngressNew     int64               `json:"ingress_new"`
	HeaderExamples []map[string]string `json:"header_error_examples,omitempty"`
	Duration       float64             `json:"duration_seconds"`
	Requests       int64               `json:"requests"`
	Errors         int64               `json:"errors"`
	HeaderErrors   int64               `json:"header_errors"`
	RPS            float64             `json:"rps"`
	Mean           float64             `json:"mean_ms"`
	P50            float64             `json:"p50_ms"`
	P95            float64             `json:"p95_ms"`
	P99            float64             `json:"p99_ms"`
	Concurrency    int                 `json:"concurrency"`
	Rate           int                 `json:"offered_rps"`
	HeaderSize     int                 `json:"header_value_bytes"`
	Owned          bool                `json:"application_owned"`
	Enabled        bool                `json:"enabled"`
	Latencies      []float64           `json:"latencies_ms,omitempty"`
}

func load(duration time.Duration, concurrency, rate, size int, owned, enabled bool, address string) {
	var run [8]byte
	_, _ = rand.Read(run[:])
	prefix := hex.EncodeToString(run[:])
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 256, MaxConnsPerHost: 256}}
	start := time.Now()
	end := start.Add(duration)
	var mu sync.Mutex
	var requestID atomic.Uint64
	var failures, headerErrors, ingressReused, ingressNew atomic.Int64
	latencies := make([]float64, 0, 100000)
	examples := make([]map[string]string, 0, 10)
	var wg sync.WaitGroup
	jobs := make(chan time.Time, concurrency*4)
	worker := func() {
		defer wg.Done()
		for scheduled := range jobs {
			seq := requestID.Add(1)
			trace := fmt.Sprintf("%s%016x", prefix, seq)
			req, _ := http.NewRequest("GET", address+"/call/"+trace, nil)
			req.Header.Set("Traceparent", fmt.Sprintf("00-%s-%016x-01", trace, seq))
			req.Header.Set("X-Header-Bytes", strconv.Itoa(size))
			const applicationParent = "00-33333333333333333333333333333333-4444444444444444-01"
			if owned {
				req.Header.Set("X-Application-Traceparent", applicationParent)
			}
			begin := scheduled
			if begin.IsZero() {
				begin = time.Now()
			}
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				if info.Reused {
					ingressReused.Add(1)
				} else {
					ingressNew.Add(1)
				}
			}}))
			response, err := client.Do(req)
			if err != nil {
				failures.Add(1)
			} else {
				body, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				if readErr != nil || response.StatusCode != 200 || string(body) != "downstream" {
					failures.Add(1)
				}
				received := response.Header.Get("X-Received-Traceparent")
				count := response.Header.Get("X-Traceparent-Count")
				valid := count == "0" && received == "00-00000000000000000000000000000000-0000000000000000-00"
				if owned {
					valid = count == "1" && received == applicationParent
				} else if enabled {
					valid = count == "1" && len(received) == 55 && strings.HasPrefix(received, "00-"+trace+"-") && strings.HasSuffix(received, "-01")
					if valid {
						_, err = hex.DecodeString(received[36:52])
						valid = err == nil && received[36:52] != "0000000000000000"
					}
				}
				if !valid {
					headerErrors.Add(1)
					mu.Lock()
					if len(examples) < 10 {
						examples = append(examples, map[string]string{"expected_trace": trace, "received": received, "count": count})
					}
					mu.Unlock()
				}
			}
			elapsed := float64(time.Since(begin)) / float64(time.Millisecond)
			mu.Lock()
			latencies = append(latencies, elapsed)
			mu.Unlock()
		}
	}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	if rate > 0 {
		interval := time.Second / time.Duration(rate)
		for scheduled := start; scheduled.Before(end); scheduled = scheduled.Add(interval) {
			if wait := time.Until(scheduled); wait > 0 {
				time.Sleep(wait)
			}
			jobs <- scheduled
		}
	} else {
		// Each worker receives a new job after completing the last; queue at most
		// concurrency jobs so closed-loop latency measures request time only.
		for time.Now().Before(end) {
			jobs <- time.Time{}
		}
	}
	close(jobs)
	wg.Wait()
	wall := time.Since(start).Seconds()
	sort.Float64s(latencies)
	sum := 0.0
	for _, latency := range latencies {
		sum += latency
	}
	percentile := func(q float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		i := int(float64(len(latencies)-1) * q)
		return latencies[i]
	}
	r := result{Duration: wall, Requests: int64(len(latencies)), Errors: failures.Load(), HeaderErrors: headerErrors.Load(), RPS: float64(len(latencies)) / wall, Mean: sum / float64(len(latencies)), P50: percentile(.50), P95: percentile(.95), P99: percentile(.99), Concurrency: concurrency, Rate: rate, HeaderSize: size, Owned: owned, Enabled: enabled}
	r.HeaderExamples = examples
	r.IngressReused = ingressReused.Load()
	r.IngressNew = ingressNew.Load()
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
func main() {
	address := flag.String("url", "http://127.0.0.1:28080", "source HTTP base URL")
	role := flag.String("role", "load", "")
	duration := flag.Duration("duration", 20*time.Second, "")
	concurrency := flag.Int("concurrency", 32, "")
	rate := flag.Int("rate", 0, "")
	size := flag.Int("size", 128, "")
	owned := flag.Bool("owned", false, "")
	enabled := flag.Bool("enabled", false, "")
	cert := flag.String("cert", "/fixture/proxy.crt", "")
	key := flag.String("key", "/fixture/proxy.key", "")
	flag.Parse()
	if *role == "serve" {
		serve(*cert, *key)
		return
	}
	load(*duration, *concurrency, *rate, *size, *owned, *enabled, *address)
}
