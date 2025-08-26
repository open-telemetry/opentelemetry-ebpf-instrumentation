// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSelectorMatch(t *testing.T) {
	fbb := InclusionLists{Include: []string{"foo_bar_baz"}}
	f := InclusionLists{Include: []string{"foo"}}
	fbt := InclusionLists{Include: []string{"foo_bar_traca"}}
	pp := InclusionLists{Include: []string{"pim_pam"}}
	selection := Selection{
		"foo.bar.baz":   fbb,
		"foo.*":         f,
		"foo.bar.traca": fbt,
		"pim.pam":       pp,
	}
	assert.Equal(t,
		[]InclusionLists{f, fbb},
		selection.Matching(Name{Section: "foo.bar.baz"}))
	assert.Equal(t,
		[]InclusionLists{f, fbt},
		selection.Matching(Name{Section: "foo.bar.traca"}))
	assert.Equal(t,
		[]InclusionLists{pp},
		selection.Matching(Name{Section: "pim.pam"}))
	assert.Empty(t, selection.Matching(Name{Section: "pam.pum"}))
}

// TestConcurrentMapAccess demonstrates the race condition between Normalize() and Matching():
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/508
//
// The race condition occurs when:
// 1. Normalize() modifies the Selection map
// 2. Matching() iterates over the Selection map
// 3. These operations happen concurrently from different goroutines
//
// To demonstrate the issue, run with the -race flag:
//
//	go test ./pkg/export/attributes/... -race
func TestConcurrentMapAccess(t *testing.T) {
	// Create a selection with multiple entries to increase chances of race condition
	selection := Selection{
		"http.server.request.duration":   {Include: []string{"*"}},
		"http.server.request.body.size":  {Include: []string{"*"}},
		"http.server.response.body.size": {Include: []string{"*"}},
		"http.client.request.duration":   {Include: []string{"*"}},
		"http.client.request.body.size":  {Include: []string{"*"}},
		"http.client.response.body.size": {Include: []string{"*"}},
		"rpc.server.duration":            {Include: []string{"*"}},
		"rpc.client.duration":            {Include: []string{"*"}},
		"db.client.operation.duration":   {Include: []string{"*"}},
		"messaging.publish.duration":     {Include: []string{"*"}},
		"messaging.receive.duration":     {Include: []string{"*"}},
		"network.flow.duration":          {Include: []string{"*"}},
		"network.flow.bytes":             {Include: []string{"*"}},
		"custom.metric.one":              {Include: []string{"service.*"}},
		"custom.metric.two":              {Include: []string{"k8s.*"}},
		"custom.metric.three":            {Include: []string{"host.*"}},
		"custom.metric.four":             {Include: []string{"process.*"}},
		"custom.metric.five":             {Include: []string{"container.*"}},
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Start multiple goroutines that call Normalize() concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					// Continuously call Normalize() which modifies the map
					selection.Normalize()
					time.Sleep(1 * time.Millisecond) // Small delay to allow other goroutines to run
				}
			}
		}()
	}

	// Start multiple goroutines that call Matching() concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metricNames := []Name{
				{Section: "http.server.request.duration"},
				{Section: "http.client.request.duration"},
				{Section: "rpc.server.duration"},
				{Section: "db.client.operation.duration"},
				{Section: "messaging.publish.duration"},
				{Section: "network.flow.duration"},
				{Section: "custom.metric.one"},
				{Section: "custom.metric.two"},
			}

			for {
				select {
				case <-done:
					return
				default:
					// Continuously call Matching() which iterates over the map
					for _, metricName := range metricNames {
						_ = selection.Matching(metricName)
					}
					time.Sleep(1 * time.Millisecond) // Small delay to allow other goroutines to run
				}
			}
		}()
	}

	// Let the race condition develop for a short time
	time.Sleep(100 * time.Millisecond)

	// Signal all goroutines to stop
	close(done)
	wg.Wait()

	t.Log("test completed - this is here as at least one usage of t required for linting")
}
