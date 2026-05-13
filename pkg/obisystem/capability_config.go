// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obisystem // import "go.opentelemetry.io/obi/pkg/obisystem"

type CapabilityConfig struct {
	AppO11yEnabled            bool
	NetO11yEnabled            bool
	StatsO11yEnabled          bool
	ContextPropagationEnabled bool
	NetworkSource             string
}
