// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"

	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type SamplerName string

const (
	SamplerAlwaysOn                SamplerName = "always_on"
	SamplerAlwaysOff               SamplerName = "always_off"
	SamplerTraceIDRatio            SamplerName = "traceidratio"
	SamplerParentBasedAlwaysOn     SamplerName = "parentbased_always_on"
	SamplerParentBasedAlwaysOff    SamplerName = "parentbased_always_off"
	SamplerParentBasedTraceIDRatio SamplerName = "parentbased_traceidratio"
)

// Sampler standard configuration
// https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler
// We don't support, yet, the jaeger and xray samplers.
type SamplerConfig struct {
	Name SamplerName `yaml:"name" env:"OTEL_TRACES_SAMPLER" validate:"omitempty,oneof=always_on always_off traceidratio parentbased_always_on parentbased_always_off parentbased_traceidratio"`
	Arg  string      `yaml:"arg" env:"OTEL_TRACES_SAMPLER_ARG"`
}

type SamplerType uint8

const (
	SamplerTypeInvalid SamplerType = iota
	SamplerTypeAlwaysOn
	SamplerTypeAlwaysOff
	SamplerTypeTraceIDRatio
	SamplerTypeParentBased
)

type SamplerDelegate struct {
	Type              SamplerType
	TraceIDUpperBound uint64
}

type CanonicalSampler struct {
	Type                   SamplerType
	TraceIDUpperBound      uint64
	Root                   SamplerDelegate
	RemoteParentSampled    SamplerDelegate
	RemoteParentNotSampled SamplerDelegate
	LocalParentSampled     SamplerDelegate
	LocalParentNotSampled  SamplerDelegate
}

func (s *SamplerConfig) Canonical() (CanonicalSampler, error) {
	if s == nil {
		return canonicalParentBased(SamplerDelegate{Type: SamplerTypeAlwaysOn}), nil
	}

	switch s.Name {
	case SamplerAlwaysOn:
		return CanonicalSampler{Type: SamplerTypeAlwaysOn}, nil
	case SamplerAlwaysOff:
		return CanonicalSampler{Type: SamplerTypeAlwaysOff}, nil
	case SamplerTraceIDRatio:
		threshold, err := traceIDUpperBound(s.Arg)
		if err != nil {
			return CanonicalSampler{}, err
		}
		return CanonicalSampler{
			Type:              SamplerTypeTraceIDRatio,
			TraceIDUpperBound: threshold,
		}, nil
	case SamplerParentBasedAlwaysOff:
		return canonicalParentBased(SamplerDelegate{Type: SamplerTypeAlwaysOff}), nil
	case SamplerParentBasedTraceIDRatio:
		threshold, err := traceIDUpperBound(s.Arg)
		if err != nil {
			return CanonicalSampler{}, err
		}
		return canonicalParentBased(SamplerDelegate{
			Type:              SamplerTypeTraceIDRatio,
			TraceIDUpperBound: threshold,
		}), nil
	case SamplerParentBasedAlwaysOn, "":
		return canonicalParentBased(SamplerDelegate{Type: SamplerTypeAlwaysOn}), nil
	default:
		return CanonicalSampler{}, fmt.Errorf("unsupported sampler %q", s.Name)
	}
}

func canonicalParentBased(root SamplerDelegate) CanonicalSampler {
	return CanonicalSampler{
		Type:                   SamplerTypeParentBased,
		Root:                   root,
		RemoteParentSampled:    SamplerDelegate{Type: SamplerTypeAlwaysOn},
		RemoteParentNotSampled: SamplerDelegate{Type: SamplerTypeAlwaysOff},
		LocalParentSampled:     SamplerDelegate{Type: SamplerTypeAlwaysOn},
		LocalParentNotSampled:  SamplerDelegate{Type: SamplerTypeAlwaysOff},
	}
}

func traceIDUpperBound(arg string) (uint64, error) {
	ratio, err := strconv.ParseFloat(arg, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing sampler ratio %q: %w", arg, err)
	}
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 || ratio > 1 {
		return 0, fmt.Errorf("sampler ratio must be between 0 and 1: %q", arg)
	}
	return uint64(ratio * (1 << 63)), nil
}

func (s CanonicalSampler) ShouldSample(
	traceID oteltrace.TraceID,
	hasParent bool,
	parentRemote bool,
	parentSampled bool,
) (bool, error) {
	delegate := SamplerDelegate{
		Type:              s.Type,
		TraceIDUpperBound: s.TraceIDUpperBound,
	}
	if s.Type == SamplerTypeParentBased {
		switch {
		case !hasParent:
			delegate = s.Root
		case parentRemote && parentSampled:
			delegate = s.RemoteParentSampled
		case parentRemote:
			delegate = s.RemoteParentNotSampled
		case parentSampled:
			delegate = s.LocalParentSampled
		default:
			delegate = s.LocalParentNotSampled
		}
	}

	switch delegate.Type {
	case SamplerTypeAlwaysOn:
		return true, nil
	case SamplerTypeAlwaysOff:
		return false, nil
	case SamplerTypeTraceIDRatio:
		value := binary.BigEndian.Uint64(traceID[8:]) >> 1
		return value < delegate.TraceIDUpperBound, nil
	default:
		return false, errors.New("invalid canonical sampler delegate")
	}
}

func (s *SamplerConfig) Implementation() trace.Sampler {
	defaultSampler := func() trace.Sampler {
		return trace.ParentBased(trace.AlwaysSample())
	}
	log := slog.With("component", "otel.Sampler", "name", s.Name, "arg", s.Arg)
	switch s.Name {
	case SamplerAlwaysOn:
		return trace.AlwaysSample()
	case SamplerAlwaysOff:
		return trace.NeverSample()
	case SamplerTraceIDRatio:
		ratio, err := strconv.ParseFloat(s.Arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.TraceIDRatioBased(ratio)
	case SamplerParentBasedAlwaysOff:
		return trace.ParentBased(trace.NeverSample())
	case SamplerParentBasedTraceIDRatio:
		ratio, err := strconv.ParseFloat(s.Arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.ParentBased(trace.TraceIDRatioBased(ratio))
	case SamplerParentBasedAlwaysOn, "":
		return defaultSampler()
	default:
		log.Warn("unsupported sampler name. Defaulting to parentbased_always_on")
		return defaultSampler()
	}
}
