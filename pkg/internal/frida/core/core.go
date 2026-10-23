// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package core implements the small Frida Core API subset used by OBI.
package core // import "go.opentelemetry.io/obi/pkg/internal/frida/core"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

const Version = "17.24.3"

type reply struct {
	value json.RawMessage
	err   error
}

type sessionState struct {
	engine   *Engine
	script   uintptr
	Messages chan json.RawMessage
	Detached chan struct{}
	Failed   chan struct{}
	failed   sync.Once
	rpcMu    sync.Mutex
	next     uint64
	replies  map[uint64]chan reply
}

func (s *Session) receive(message []byte) {
	var event struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(message, &event) == nil && event.Type == "send" {
		var fields []json.RawMessage
		if json.Unmarshal(event.Payload, &fields) == nil && len(fields) >= 4 && string(fields[0]) == `"frida:rpc"` {
			var id uint64
			if json.Unmarshal(fields[1], &id) == nil {
				s.rpcMu.Lock()
				pending := s.replies[id]
				s.rpcMu.Unlock()
				if pending != nil {
					r := reply{value: fields[3]}
					if string(fields[2]) != `"ok"` {
						r.err = fmt.Errorf("frida RPC: %s", fields[3])
					}
					select {
					case pending <- r:
					default:
					}
				}
				return
			}
		}
	}
	select {
	case s.Messages <- append(json.RawMessage(nil), message...):
	default:
		// Stop the session rather than silently losing native errors.
		s.failed.Do(func() { close(s.Failed) })
	}
}

func (s *Session) Call(ctx context.Context, method string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.rpcMu.Lock()
	s.next++
	id := s.next
	pending := make(chan reply, 1)
	s.replies[id] = pending
	s.rpcMu.Unlock()
	defer func() {
		s.rpcMu.Lock()
		defer s.rpcMu.Unlock()
		delete(s.replies, id)
	}()
	payload, err := json.Marshal([]any{"frida:rpc", id, "call", method, []any{}})
	if err != nil {
		return nil, err
	}
	s.engine.post(s.script, string(payload), 0)
	select {
	case r := <-pending:
		return r.value, r.err
	case <-s.Detached:
		return nil, errors.New("frida session detached")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
