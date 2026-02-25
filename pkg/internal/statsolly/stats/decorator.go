// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"net"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

type InterfaceNamer func(ifIndex int) string

// Decorate the flows with extra metadata fields that are not directly fetched by eBPF
// or by any previous pipeline stage (DNS, Kubernetes...):
// - The IP address of the agent host.
// NOTE: source and destination ip addresses are set in the attriutes for every calculated metric.
func Decorate(agentIP net.IP, input *msg.Queue[[]*ebpf.Stat], output *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	ip := agentIP.String()
	in := input.Subscribe(msg.SubscriberName("stats.Decorate"))
	return func(ctx context.Context) {
		defer output.Close()
		swarms.ForEachInput(ctx, in, nil, func(stats []*ebpf.Stat) {
			for _, stat := range stats {
				stat.Attrs.OBIIP = ip
			}
			output.Send(stats)
		})
	}
}
