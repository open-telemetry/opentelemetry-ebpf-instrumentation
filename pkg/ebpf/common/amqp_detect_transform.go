// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type AMQPInfo struct {
	Direction uint8
}

func ProcessPossibleAMQPEvent(event *TCPRequestInfo, pkt, rpkt *largebuf.LargeBuffer) ([]AMQPInfo, bool, error) {
	reqLooks, reqInfos, reqErr := processAMQPBuffer(pkt, event.Direction)
	respLooks, respInfos, respErr := processAMQPBuffer(rpkt, oppositeDirection(event.Direction))

	infos := append(reqInfos, respInfos...)
	if len(infos) > 0 {
		return infos, false, nil
	}

	if reqErr != nil && respErr != nil {
		return nil, true, errors.Join(reqErr, respErr)
	}
	if reqErr != nil {
		return nil, true, reqErr
	}
	if respErr != nil {
		return nil, true, respErr
	}
	if reqLooks || respLooks {
		return nil, true, nil
	}
	return nil, true, amqpparser.ErrNotAMQP
}

func isAMQP(pkt *largebuf.LargeBuffer) (bool, error) {
	if pkt == nil {
		return false, nil
	}
	result, err := amqpparser.Parse(pkt.UnsafeView())
	if errors.Is(err, amqpparser.ErrNotAMQP) {
		return result.LooksLikeAMQP, nil
	}
	return result.LooksLikeAMQP, err
}

func processAMQPBuffer(pkt *largebuf.LargeBuffer, direction uint8) (bool, []AMQPInfo, error) {
	if pkt == nil {
		return false, nil, nil
	}

	result, err := amqpparser.Parse(pkt.UnsafeView())
	if err != nil {
		if errors.Is(err, amqpparser.ErrNotAMQP) {
			return false, nil, nil
		}
		return result.LooksLikeAMQP, nil, err
	}
	if !result.LooksLikeAMQP {
		return false, nil, nil
	}

	infos := make([]AMQPInfo, 0, result.TransferCount)
	for i := 0; i < result.TransferCount; i++ {
		infos = append(infos, AMQPInfo{Direction: direction})
	}

	return true, infos, nil
}

func tcpToAMQPToSpan(trace *TCPRequestInfo, data AMQPInfo) request.Span {
	peer, peerPort, hostname, hostPort := amqpSpanEndpoints(trace, data.Direction)

	return request.Span{
		Type:          request.EventTypeAMQPClient,
		Method:        amqpOperation(data.Direction),
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
	}
}

func amqpOperation(direction uint8) string {
	if direction == directionSend {
		return request.MessagingPublish
	}

	return request.MessagingProcess
}

func amqpSpanEndpoints(trace *TCPRequestInfo, direction uint8) (peer string, peerPort int, host string, hostPort int) {
	connInfo := trace.ConnInfo
	if trace.Direction != direction {
		connInfo = swapConnInfo(connInfo)
	}

	source, target := (*BPFConnInfo)(&connInfo).reqHostInfo()
	if direction == directionSend {
		return source, int(connInfo.S_port), target, int(connInfo.D_port)
	}
	return target, int(connInfo.D_port), source, int(connInfo.S_port)
}

func oppositeDirection(direction uint8) uint8 {
	if direction == directionSend {
		return directionRecv
	}
	return directionSend
}

func swapConnInfo(conn BpfConnectionInfoT) BpfConnectionInfoT {
	conn.S_addr, conn.D_addr = conn.D_addr, conn.S_addr
	conn.S_port, conn.D_port = conn.D_port, conn.S_port
	return conn
}
