// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	runtimemetrics "runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
)

var runtimeMetricsReadLoopActive uint32

const (
	runtimeMetricMaxProcessors = 256
	runtimeHistogramGoroutines = 256
	runtimeHistogramYields     = 8
)

type runtimeHistogramSnapshot struct {
	Counts []uint64  `json:"counts"`
	Bounds []float64 `json:"bounds"`
}

func main() {
	go serve(":8081")
	serve(":8080")
}

func serve(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to start server on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Server listening on %s.\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Received: %s", message)

	switch strings.TrimSpace(message) {
	case "FORCE_GC":
		runtime.GC()
	case "SET_GOMAXPROCS_ABOVE_RUNTIME_METRIC_LIMIT":
		runtime.GOMAXPROCS(runtimeMetricMaxProcessors + 1)
		runtime.GC()
	case "GENERATE_RUNTIME_HISTOGRAMS":
		generateRuntimeHistograms()
	case "RUNTIME_METRICS":
		if err := json.NewEncoder(conn).Encode(runtimeMetricValues()); err != nil {
			fmt.Printf("Failed to encode runtime metrics: %v\n", err)
		}
		return
	case "RUNTIME_HISTOGRAMS":
		if err := json.NewEncoder(conn).Encode(runtimeHistogramValues()); err != nil {
			fmt.Printf("Failed to encode runtime histograms: %v\n", err)
		}
		return
	case "START_RUNTIME_METRICS_READ_LOOP":
		startRuntimeMetricsReadLoop()
	case "STOP_RUNTIME_METRICS_READ_LOOP":
		atomic.StoreUint32(&runtimeMetricsReadLoopActive, 0)
	}

	conn.Write([]byte("ACK\n"))
}

func startRuntimeMetricsReadLoop() {
	if !atomic.CompareAndSwapUint32(&runtimeMetricsReadLoopActive, 0, 1) {
		return
	}

	go func() {
		for atomic.LoadUint32(&runtimeMetricsReadLoopActive) != 0 {
			runtimeMetricValues()
			runtime.Gosched()
		}
	}()
}

func runtimeMetricValues() map[string]float64 {
	names := []string{
		"/gc/gogc:percent",
		"/gc/gomemlimit:bytes",
		"/gc/cycles/automatic:gc-cycles",
		"/gc/cycles/forced:gc-cycles",
		"/gc/cycles/total:gc-cycles",
		"/gc/heap/goal:bytes",
		"/gc/heap/allocs:bytes",
		"/gc/heap/allocs:objects",
		"/cpu/classes/gc/mark/assist:cpu-seconds",
		"/cpu/classes/gc/mark/dedicated:cpu-seconds",
		"/cpu/classes/gc/mark/idle:cpu-seconds",
		"/cpu/classes/gc/pause:cpu-seconds",
		"/cpu/classes/idle:cpu-seconds",
		"/cpu/classes/scavenge/assist:cpu-seconds",
		"/cpu/classes/scavenge/background:cpu-seconds",
		"/cpu/classes/user:cpu-seconds",
		"/sched/goroutines:goroutines",
		"/memory/classes/heap/released:bytes",
		"/memory/classes/heap/stacks:bytes",
		"/memory/classes/total:bytes",
		"/sched/gomaxprocs:threads",
	}
	samples := make([]runtimemetrics.Sample, len(names))
	for i, name := range names {
		samples[i].Name = name
	}
	runtimemetrics.Read(samples)

	values := make(map[string]float64, len(samples))
	for _, sample := range samples {
		switch sample.Value.Kind() {
		case runtimemetrics.KindUint64:
			values[sample.Name] = float64(sample.Value.Uint64())
		case runtimemetrics.KindFloat64:
			values[sample.Name] = sample.Value.Float64()
		}
	}
	values["go.memory.used/stack"] = values["/memory/classes/heap/stacks:bytes"]
	values["go.memory.used/other"] = values["/memory/classes/total:bytes"] -
		values["/memory/classes/heap/released:bytes"] -
		values["/memory/classes/heap/stacks:bytes"]
	return values
}

func generateRuntimeHistograms() {
	start := make(chan struct{})
	ready := make(chan struct{}, runtimeHistogramGoroutines)
	var waitGroup sync.WaitGroup
	waitGroup.Add(runtimeHistogramGoroutines)
	for i := 0; i < runtimeHistogramGoroutines; i++ {
		go func() {
			defer waitGroup.Done()
			ready <- struct{}{}
			<-start
			for i := 0; i < runtimeHistogramYields; i++ {
				runtime.Gosched()
			}
		}()
	}
	for i := 0; i < runtimeHistogramGoroutines; i++ {
		<-ready
	}
	close(start)
	waitGroup.Wait()
	runtime.GC()
}

func runtimeHistogramValues() map[string]runtimeHistogramSnapshot {
	names := []string{
		"/sched/pauses/total/gc:seconds",
		"/sched/latencies:seconds",
	}
	samples := make([]runtimemetrics.Sample, len(names))
	for i, name := range names {
		samples[i].Name = name
	}
	runtimemetrics.Read(samples)

	values := make(map[string]runtimeHistogramSnapshot, len(samples))
	for _, sample := range samples {
		if sample.Value.Kind() != runtimemetrics.KindFloat64Histogram {
			continue
		}
		values[sample.Name] = snapshotRuntimeHistogram(sample.Value.Float64Histogram())
	}
	return values
}

func snapshotRuntimeHistogram(histogram *runtimemetrics.Float64Histogram) runtimeHistogramSnapshot {
	counts := append([]uint64(nil), histogram.Counts...)
	bounds := make([]float64, 0, len(histogram.Buckets)-1)
	for i := 0; i+1 < len(histogram.Buckets); i++ {
		upperBound := histogram.Buckets[i+1]
		if math.IsInf(upperBound, 0) {
			continue
		}
		bounds = append(bounds, math.Nextafter(upperBound, histogram.Buckets[i]))
	}

	return runtimeHistogramSnapshot{Counts: counts, Bounds: bounds}
}
