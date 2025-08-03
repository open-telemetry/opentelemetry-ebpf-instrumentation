// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package protofilter

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/netolly/flow/transport"
)

type ProtocolFilter struct {
	IsAllowed func(r *ebpf.NetFlowRecordT) bool
}

func allowNoOp(*ebpf.NetFlowRecordT) bool {
	return true
}

func NewFilter(allowed, excluded []string) (*ProtocolFilter, error) {
	if len(allowed) == 0 && len(excluded) == 0 {
		return &ProtocolFilter{IsAllowed: allowNoOp}, nil
	}

	// if the allowed list has items, only interfaces in that list are allowed
	if len(allowed) > 0 {
		allow, err := allower(allowed)
		if err != nil {
			return nil, err
		}
		return &ProtocolFilter{IsAllowed: allow}, nil
	}
	// if the allowed list is empty, any interface is allowed except if it matches the exclusion list
	exclude, err := excluder(excluded)
	if err != nil {
		return nil, err
	}
	return &ProtocolFilter{IsAllowed: exclude}, nil
}

func allower(allowed []string) (func(r *ebpf.NetFlowRecordT) bool, error) {
	allow, err := protocolsMap(allowed)
	if err != nil {
		return nil, fmt.Errorf("in network protocols: %w", err)
	}
	return func(r *ebpf.NetFlowRecordT) bool {
		_, ok := allow[transport.Protocol(r.Id.TransportProtocol)]
		return ok
	}, nil
}

func excluder(excluded []string) (func(r *ebpf.NetFlowRecordT) bool, error) {
	exclude, err := protocolsMap(excluded)
	if err != nil {
		return nil, fmt.Errorf("in network excluded protocols: %w", err)
	}
	return func(r *ebpf.NetFlowRecordT) bool {
		_, excluded := exclude[transport.Protocol(r.Id.TransportProtocol)]
		return !excluded
	}, nil
}

func protocolsMap(entries []string) (map[transport.Protocol]struct{}, error) {
	protoMap := map[transport.Protocol]struct{}{}
	for _, aStr := range entries {
		atp, err := transport.ParseProtocol(aStr)
		if err != nil {
			return nil, err
		}
		protoMap[atp] = struct{}{}
	}
	return protoMap, nil
}
