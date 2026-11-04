// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRPCMessages(t *testing.T) {
	pending := make(chan reply, 1)
	s := &Session{sessionState: sessionState{replies: map[uint64]chan reply{7: pending}, Messages: make(chan json.RawMessage, 1), Detached: make(chan struct{})}}
	s.receive([]byte(`{"type":"send","payload":["frida:rpc",7,"ok",false]}`))
	require.JSONEq(t, "false", string((<-pending).value))
	s.receive([]byte(`{"type":"error","description":"bad hook"}`))
	require.Contains(t, string(<-s.Messages), "bad hook")
}

func TestQueueOverflowKeepsNativeSessionLive(t *testing.T) {
	t.Parallel()
	s := &Session{sessionState: sessionState{Messages: make(chan json.RawMessage, 1), Detached: make(chan struct{}), Failed: make(chan struct{})}}
	s.receive([]byte(`{"type":"log"}`))
	s.receive([]byte(`{"type":"log"}`))
	select {
	case <-s.Failed:
	default:
		t.Fatal("overflow did not request shutdown")
	}
	select {
	case <-s.Detached:
		t.Fatal("overflow was mistaken for native target exit")
	default:
	}
}
