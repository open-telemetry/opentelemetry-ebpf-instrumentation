// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export // import "go.opentelemetry.io/obi/pkg/internal/statsolly/export"

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func StatPrinterProvider(enabled bool, input *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	if !enabled {
		// just return a no-op
		return func(_ context.Context) {}
	}

	in := input.Subscribe(msg.SubscriberName("StatPrinter"))
	return func(_ context.Context) {
		for stats := range in {
			for _, stat := range stats {
				printStat(stat)
			}
		}
	}
}

func printStat(s *ebpf.Stat) {
	sb := strings.Builder{}
	sb.WriteString("ip=")
	sb.WriteString(s.Attrs.OBIIP)
	sb.WriteString(" src.address=")
	sb.WriteString(s.Attrs.SourceAddress)
	sb.WriteString(" dst.address=")
	sb.WriteString(s.Attrs.DestinationAddress)
	sb.WriteString(" src.name=")
	sb.WriteString(s.Attrs.SrcName)
	sb.WriteString(" dst.name=")
	sb.WriteString(s.Attrs.DstName)
	sb.WriteString(" src.port=")
	sb.WriteString(strconv.FormatUint(uint64(s.Attrs.SourcePort), 10))
	sb.WriteString(" dst.port=")
	sb.WriteString(strconv.FormatUint(uint64(s.Attrs.DestinationPort), 10))

	for k, v := range s.Attrs.Metadata {
		sb.WriteString(" ")
		sb.WriteString(string(k))
		sb.WriteString("=")
		sb.WriteString(v)
	}

	fmt.Println("stats:", sb.String())
}
