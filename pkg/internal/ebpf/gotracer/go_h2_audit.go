// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

const goH2AuditPath = "/debug/obi/go-h2-audit"

type goH2AuditEvent struct {
	PID                uint32 `json:"pid"`
	ProcessStart       uint64 `json:"process_start"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	SourcePort         uint16 `json:"source_port"`
	DestinationPort    uint16 `json:"destination_port"`
	StreamID           uint32 `json:"stream_id"`
	Protocol           string `json:"protocol"`
	Event              string `json:"event"`
	State              string `json:"state"`
	TraceID            string `json:"trace_id"`
	Count              uint32 `json:"count"`
	UpdatedNS          uint64 `json:"updated_ns"`
}

type goH2ActiveStream struct {
	PID                uint32 `json:"pid"`
	ProcessStart       uint64 `json:"process_start"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	SourcePort         uint16 `json:"source_port"`
	DestinationPort    uint16 `json:"destination_port"`
	StreamID           uint32 `json:"stream_id"`
	Protocol           string `json:"protocol"`
	State              string `json:"state"`
	TraceID            string `json:"trace_id"`
	UpdatedNS          uint64 `json:"updated_ns"`
}

type goH2AuditSnapshot struct {
	Events        []goH2AuditEvent   `json:"events"`
	ActiveStreams []goH2ActiveStream `json:"active_streams"`
}

func goH2ProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "http2"
	case 2:
		return "grpc"
	default:
		return "unknown"
	}
}

func goH2StateName(state uint8) string {
	switch state {
	case 1:
		return "application"
	case 2:
		return "obi_pending"
	case 3:
		return "obi_written"
	case 4:
		return "skip"
	case 5:
		return "observing"
	default:
		return "unknown"
	}
}

func goH2EventName(event uint8) string {
	switch event {
	case 1:
		return "application_traceparent"
	case 2:
		return "stream_published"
	case 3:
		return "direct_write"
	case 4:
		return "socket_write"
	case 5:
		return "cleanup"
	case 6:
		return "rollback"
	case 7:
		return "state_missing"
	case 8:
		return "encoder_hook"
	case 9:
		return "prewrite_write"
	case 10:
		return "socket_continuation_write"
	default:
		return "unknown"
	}
}

func (p *Tracer) goH2AuditSnapshot() (goH2AuditSnapshot, error) {
	snapshot := goH2AuditSnapshot{
		Events:        []goH2AuditEvent{},
		ActiveStreams: []goH2ActiveStream{},
	}

	var key BpfGoH2AuditKeyT
	var value BpfGoH2AuditValueT
	iterator := p.bpfObjects.GoH2Audit.Iterate()
	for iterator.Next(&key, &value) {
		snapshot.Events = append(snapshot.Events, goH2AuditEvent{
			PID:                key.Stream.P_conn.Pid,
			ProcessStart:       uint64(key.Stream.ProcessStartHi)<<32 | uint64(key.Stream.ProcessStartLo),
			SourceAddress:      net.IP(key.Stream.P_conn.Conn.S_addr[:]).String(),
			DestinationAddress: net.IP(key.Stream.P_conn.Conn.D_addr[:]).String(),
			SourcePort:         key.Stream.P_conn.Conn.S_port,
			DestinationPort:    key.Stream.P_conn.Conn.D_port,
			StreamID:           key.Stream.StreamId,
			Protocol:           goH2ProtocolName(key.Protocol),
			Event:              goH2EventName(key.Event),
			State:              goH2StateName(value.State),
			TraceID:            hex.EncodeToString(value.TraceId[:]),
			Count:              value.Count,
			UpdatedNS:          value.UpdatedNs,
		})
	}
	if err := iterator.Err(); err != nil {
		return goH2AuditSnapshot{}, err
	}

	var streamKey BpfGoH2StreamKeyT
	var streamValue BpfGoH2StreamValueT
	iterator = p.bpfObjects.GoH2StreamStates.Iterate()
	for iterator.Next(&streamKey, &streamValue) {
		snapshot.ActiveStreams = append(snapshot.ActiveStreams, goH2ActiveStream{
			PID:                streamKey.P_conn.Pid,
			ProcessStart:       uint64(streamKey.ProcessStartHi)<<32 | uint64(streamKey.ProcessStartLo),
			SourceAddress:      net.IP(streamKey.P_conn.Conn.S_addr[:]).String(),
			DestinationAddress: net.IP(streamKey.P_conn.Conn.D_addr[:]).String(),
			SourcePort:         streamKey.P_conn.Conn.S_port,
			DestinationPort:    streamKey.P_conn.Conn.D_port,
			StreamID:           streamKey.StreamId,
			Protocol:           goH2ProtocolName(streamValue.Protocol),
			State:              goH2StateName(streamValue.State),
			TraceID:            hex.EncodeToString(streamValue.Tp.TraceId[:]),
			UpdatedNS:          streamValue.UpdatedNs,
		})
	}
	if err := iterator.Err(); err != nil {
		return goH2AuditSnapshot{}, err
	}

	sort.Slice(snapshot.Events, func(i, j int) bool {
		left, right := snapshot.Events[i], snapshot.Events[j]
		if left.PID != right.PID {
			return left.PID < right.PID
		}
		if left.SourcePort != right.SourcePort {
			return left.SourcePort < right.SourcePort
		}
		if left.StreamID != right.StreamID {
			return left.StreamID < right.StreamID
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		return left.Event < right.Event
	})
	sort.Slice(snapshot.ActiveStreams, func(i, j int) bool {
		left, right := snapshot.ActiveStreams[i], snapshot.ActiveStreams[j]
		if left.PID != right.PID {
			return left.PID < right.PID
		}
		if left.SourcePort != right.SourcePort {
			return left.SourcePort < right.SourcePort
		}
		return left.StreamID < right.StreamID
	})

	return snapshot, nil
}

func (p *Tracer) serveGoH2Audit(w http.ResponseWriter, _ *http.Request) {
	snapshot, err := p.goH2AuditSnapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snapshot); err != nil && p.log != nil {
		p.log.Warn("encoding Go HTTP/2 audit snapshot failed", "error", err)
	}
}

func (p *Tracer) startGoH2AuditServer() func() {
	if os.Getenv("OTEL_EBPF_GO_H2_AUDIT") != "1" {
		return func() {}
	}

	port := 6061
	if configured := os.Getenv("OTEL_EBPF_GO_H2_AUDIT_PORT"); configured != "" {
		parsed, err := strconv.ParseUint(configured, 10, 16)
		if err != nil || parsed == 0 {
			p.log.Error("invalid Go HTTP/2 audit port", "port", configured)
			return func() {}
		}
		port = int(parsed)
	}

	host := os.Getenv("OTEL_EBPF_GO_H2_AUDIT_ADDR")
	if host == "" {
		host = "127.0.0.1"
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		p.log.Error("starting Go HTTP/2 audit listener failed", "error", err)
		return func() {}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(goH2AuditPath, p.serveGoH2Audit)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.log.Error("Go HTTP/2 audit listener stopped", "error", err)
		}
	}()
	p.log.Info("started Go HTTP/2 audit listener", "address", listener.Addr())

	return func() {
		if err := server.Close(); err != nil {
			p.log.Warn("closing Go HTTP/2 audit listener failed", "error", err)
		}
	}
}
