// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mcpsession

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func sessionSpan(service svc.Attrs, start, end time.Time) (*request.Span, request.Timings) {
	span := &request.Span{
		Type:     request.EventTypeHTTP,
		SubType:  request.HTTPSubtypeMCP,
		Host:     "localhost",
		HostPort: 8381,
		Service:  service,
		GenAI: &request.GenAI{MCP: &request.MCPCall{
			ProtocolVer: "2025-03-26",
			SessionID:   "session-1",
		}},
		Status: 200,
	}
	return span, request.Timings{RequestStart: start, Start: start, End: end}
}

func TestRecordPropagatesServiceToSyntheticSpan(t *testing.T) {
	service := svc.Attrs{}
	service.UID = svc.UID{Name: "mcp-app", Namespace: "test"}

	st := NewStore()
	now := time.Now()
	span, timings := sessionSpan(service, now.Add(-time.Second), now)
	st.Record("session-1", false, span, timings)

	sess, ok := st.serverSessions["session-1"]
	require.True(t, ok)
	synth := sess.SyntheticSpan()
	assert.Equal(t, service.UID, synth.Service.UID)
	assert.Equal(t, request.EventTypeHTTP, synth.Type)
	assert.Equal(t, "2025-03-26", synth.MCP().ProtocolVer)
}

func TestRecordClearsErrorOnLaterSuccess(t *testing.T) {
	service := svc.Attrs{}
	service.UID = svc.UID{Name: "mcp-app", Namespace: "test"}

	st := NewStore()
	now := time.Now()

	errSpan, errTimings := sessionSpan(service, now.Add(-2*time.Second), now.Add(-time.Second))
	errSpan.Status = 500
	errSpan.GenAI.MCP.ErrorCode = -32600
	st.Record("session-1", false, errSpan, errTimings)

	okSpan, okTimings := sessionSpan(service, now.Add(-time.Second), now)
	st.Record("session-1", false, okSpan, okTimings)

	sess, ok := st.serverSessions["session-1"]
	require.True(t, ok)
	assert.False(t, sess.HasError())
	synth := sess.SyntheticSpan()
	assert.Equal(t, 0, synth.Status)
	assert.Equal(t, 0, synth.GenAI.MCP.ErrorCode)
}

func TestRecordSetsErrorOnLaterFailure(t *testing.T) {
	service := svc.Attrs{}
	service.UID = svc.UID{Name: "mcp-app", Namespace: "test"}

	st := NewStore()
	now := time.Now()

	okSpan, okTimings := sessionSpan(service, now.Add(-2*time.Second), now.Add(-time.Second))
	st.Record("session-1", false, okSpan, okTimings)

	errSpan, errTimings := sessionSpan(service, now.Add(-time.Second), now)
	errSpan.Status = 500
	errSpan.GenAI.MCP.ErrorCode = -32600
	st.Record("session-1", false, errSpan, errTimings)

	sess, ok := st.serverSessions["session-1"]
	require.True(t, ok)
	assert.True(t, sess.HasError())
	synth := sess.SyntheticSpan()
	assert.Equal(t, 500, synth.Status)
	assert.Equal(t, -32600, synth.GenAI.MCP.ErrorCode)
}

func TestStartExpiresIdleSessionsInBackground(t *testing.T) {
	service := svc.Attrs{}
	service.UID = svc.UID{Name: "mcp-app", Namespace: "test"}

	st := NewStore()
	now := time.Now()
	span, timings := sessionSpan(service, now.Add(-time.Minute), now)
	st.Record("session-1", false, span, timings)

	closed := make(chan *Session, 1)
	go st.Start(t.Context(), 10*time.Millisecond, func(s *Session, client bool) {
		assert.False(t, client)
		closed <- s
	})

	select {
	case s := <-closed:
		assert.GreaterOrEqual(t, s.Duration(), time.Minute)
	case <-time.After(5 * time.Second):
		t.Fatal("background expiration did not close the idle session")
	}

	st.mu.Lock()
	assert.Empty(t, st.serverSessions)
	st.mu.Unlock()
}

func TestConcurrentRecordAndExpire(t *testing.T) {
	st := NewStore()
	service := svc.Attrs{}
	service.UID = svc.UID{Name: "mcp-app", Namespace: "test"}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			now := time.Now()
			span, timings := sessionSpan(service, now, now)
			st.Record("session-1", false, span, timings)
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			st.Expire(time.Nanosecond, func(*Session, bool) {})
		}
	}()
	wg.Wait()

	st.CloseAll(func(*Session, bool) {})
	st.mu.Lock()
	defer st.mu.Unlock()
	assert.Empty(t, st.clientSessions)
	assert.Empty(t, st.serverSessions)
}
