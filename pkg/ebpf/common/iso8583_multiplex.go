// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"slices"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

const iso8583MaxPending = 128

var iso8583Protocol = tcpMultiplexProtocol{
	match: func(x tcpExchange) bool {
		if hasISO8583Prefix(x.response) && hasISO8583Prefix(x.request) {
			return true
		}

		for op := range x.initialOperations {
			if hasISO8583Prefix(op.data) {
				return true
			}
		}

		return false
	},
	newDecoder: func(cfg *config.EBPFTracer) tcpMultiplexDecoder {
		return &iso8583Connection{zone: cfg.ISO8583TransmissionLocation}
	},
}

type iso8583Pending struct {
	message   iso8583Message
	observed  uint64
	prefix    int
	direction uint8
}

type iso8583Connection struct {
	requests []iso8583Pending
	zone     *time.Location
	prefix   int
	packed   bool
}

func (conn *iso8583Connection) remember(m iso8583Message, prefix int, direction uint8, observed uint64) {
	if observed == 0 {
		return
	}
	if len(conn.requests) == iso8583MaxPending {
		conn.requests = slices.Delete(conn.requests, 0, 1)
	}
	conn.requests = append(conn.requests, iso8583Pending{message: m, prefix: prefix, direction: direction, observed: observed})
}

// A STAN can be reused by different terminals on the same connection. Only a unique
// match can supply an observed start time for a multiplexed reply.
func (conn *iso8583Connection) take(reply iso8583Message, prefix int, direction uint8, observed uint64, direct iso8583Pending) iso8583Pending {
	if conn == nil {
		return direct
	}

	conn.requests = slices.DeleteFunc(conn.requests, func(req iso8583Pending) bool {
		return observed >= req.observed && observed-req.observed > uint64(iso8583MaxResponseTime)
	})

	index, sole, active := -1, -1, 0
	for i, req := range conn.requests {
		if req.direction == direction || req.observed > observed {
			continue
		}
		active++
		sole = i
		if reply.stan[0] == 0 || req.prefix != prefix || req.message.stan != reply.stan || !req.message.acceptsResponse(reply) {
			continue
		}
		if index >= 0 {
			return iso8583Pending{} // Multiple in-flight requests share the same identifiers.
		}
		index = i
	}

	if active == 0 {
		return direct
	}

	if index < 0 && active == 1 && direct.observed == conn.requests[sole].observed && direct.message == conn.requests[sole].message {
		index = sole // A single captured exchange can omit DE11.
	}

	if index < 0 {
		return iso8583Pending{}
	}

	req := conn.requests[index]
	conn.requests = slices.Delete(conn.requests, index, index+1)
	return req
}

func (conn *iso8583Connection) observe(event *TCPRequestInfo, op tcpOperation) []request.Span {
	stream := readISO8583Stream(op.data, conn.prefix, op.length, false)
	if !stream.complete || stream.messages[0].packed != conn.packed {
		return nil
	}

	return iso8583Responses(event, stream, op.direction == event.Direction, op.observed, conn.zone, nil, conn)
}
