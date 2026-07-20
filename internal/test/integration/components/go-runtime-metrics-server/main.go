// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	runtimemetrics "runtime/metrics"
	"strings"
	"sync/atomic"
)

var runtimeMetricsReadLoopActive uint32

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
	case "RUNTIME_METRICS":
		if err := json.NewEncoder(conn).Encode(runtimeMetricValues()); err != nil {
			fmt.Printf("Failed to encode runtime metrics: %v\n", err)
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
