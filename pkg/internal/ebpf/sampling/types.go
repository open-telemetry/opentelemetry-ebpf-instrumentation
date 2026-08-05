// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sampling // import "go.opentelemetry.io/obi/pkg/internal/ebpf/sampling"

import "go.opentelemetry.io/obi/pkg/appolly/services"

type BPFDelegate struct {
	TraceIDUpperBound uint64
	Type              uint8
	Pad               [7]uint8
}

type BPFConfig struct {
	TraceIDUpperBound      uint64
	Root                   BPFDelegate
	RemoteParentSampled    BPFDelegate
	RemoteParentNotSampled BPFDelegate
	LocalParentSampled     BPFDelegate
	LocalParentNotSampled  BPFDelegate
	PublicationEpoch       uint32
	Type                   uint8
	Pad                    [3]uint8
}

type BPFProcessReadiness struct {
	StartTime          uint64
	Epoch              uint32
	ConfigEpoch        uint32
	Ready              uint8
	AutoSDKGlobalReady uint8
	Pad                [6]uint8
}

func toBPFConfig(config services.CanonicalSampler) BPFConfig {
	return BPFConfig{
		TraceIDUpperBound:      config.TraceIDUpperBound,
		Root:                   toBPFDelegate(config.Root),
		RemoteParentSampled:    toBPFDelegate(config.RemoteParentSampled),
		RemoteParentNotSampled: toBPFDelegate(config.RemoteParentNotSampled),
		LocalParentSampled:     toBPFDelegate(config.LocalParentSampled),
		LocalParentNotSampled:  toBPFDelegate(config.LocalParentNotSampled),
		Type:                   uint8(config.Type),
	}
}

func toBPFDelegate(delegate services.SamplerDelegate) BPFDelegate {
	return BPFDelegate{
		TraceIDUpperBound: delegate.TraceIDUpperBound,
		Type:              uint8(delegate.Type),
	}
}
