// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAndTick(t *testing.T) {
	tr := NewTracker()
	tick := tr.Register("appo11y", true)

	for range 100 {
		tick()
	}

	subs := snapshotFor(t, tr).Subsystems
	require.Contains(t, subs, "appo11y")
	assert.True(t, subs["appo11y"].Enabled)
	assert.Equal(t, uint64(100), subs["appo11y"].TickCount)
	assert.Positive(t, subs["appo11y"].LastTickUnixNs)
}

func TestDisabledSubsystemTickIsNoop(t *testing.T) {
	tr := NewTracker()
	tick := tr.Register("neto11y", false)

	for range 10 {
		tick()
	}

	subs := snapshotFor(t, tr).Subsystems
	require.Contains(t, subs, "neto11y")
	assert.False(t, subs["neto11y"].Enabled)
	assert.Equal(t, uint64(0), subs["neto11y"].TickCount)
	assert.Equal(t, int64(0), subs["neto11y"].LastTickUnixNs)
}

func TestSchemaShape(t *testing.T) {
	tr := NewTracker()
	tr.Register("appo11y", true)
	tr.Register("neto11y", false)

	resp := snapshotFor(t, tr)

	assert.Equal(t, schemaVersion, resp.SchemaVersion)
	assert.Positive(t, resp.NowUnixNs)
	assert.GreaterOrEqual(t, resp.ProcessUptimeNs, int64(0))
	assert.Len(t, resp.Subsystems, 2)
}

func TestConcurrentTickAndSnapshot(t *testing.T) {
	tr := NewTracker()
	tick := tr.Register("appo11y", true)

	const writers = 16
	const ticksEach = 1000

	var wg sync.WaitGroup
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			for range ticksEach {
				tick()
			}
		}()
	}

	// concurrent readers must not race with writers
	readerStop := make(chan struct{})
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		for {
			select {
			case <-readerStop:
				return
			default:
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, Path, nil)
				tr.ServeHTTP(rr, req)
			}
		}
	}()

	wg.Wait()
	close(readerStop)
	readerWg.Wait()

	subs := snapshotFor(t, tr).Subsystems
	assert.Equal(t, uint64(writers*ticksEach), subs["appo11y"].TickCount)
}

func TestRegisterIdempotent(t *testing.T) {
	tr := NewTracker()
	t1 := tr.Register("appo11y", true)
	t1()
	// re-register with the same name should not create a new state slot
	t2 := tr.Register("appo11y", true)
	t2()

	subs := snapshotFor(t, tr).Subsystems
	assert.Equal(t, uint64(2), subs["appo11y"].TickCount)
}

func TestServeHTTPAdvancesTime(t *testing.T) {
	tr := NewTracker()
	tick := tr.Register("appo11y", true)
	tick()

	r1 := snapshotFor(t, tr)

	time.Sleep(2 * time.Millisecond)

	r2 := snapshotFor(t, tr)

	assert.Greater(t, r2.NowUnixNs, r1.NowUnixNs)
	assert.GreaterOrEqual(t, r2.ProcessUptimeNs, r1.ProcessUptimeNs)
}

func TestListenAndServeEndToEnd(t *testing.T) {
	port := freePort(t)
	tr := NewTracker()
	tick := tr.Register("appo11y", true)
	tick()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- ListenAndServe(ctx, port, tr)
	}()

	url := "http://127.0.0.1:" + strconv.Itoa(port) + Path

	var resp *http.Response
	require.Eventually(t, func() bool {
		r, err := http.Get(url)
		if err != nil {
			return false
		}
		resp = r
		return true
	}, 3*time.Second, 20*time.Millisecond)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body response
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, schemaVersion, body.SchemaVersion)
	require.Contains(t, body.Subsystems, "appo11y")
	assert.True(t, body.Subsystems["appo11y"].Enabled)
	assert.Equal(t, uint64(1), body.Subsystems["appo11y"].TickCount)

	cancel()
	require.NoError(t, <-srvErr)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func snapshotFor(t *testing.T, tr *Tracker) response {
	t.Helper()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, Path, nil)
	tr.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var resp response
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}
