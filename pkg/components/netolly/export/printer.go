// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func FlowPrinterProvider(enabled bool, input *msg.Queue[ebpf.Record]) swarm.RunFunc {
	if !enabled {
		// just return a no-op
		return func(_ context.Context) {}
	}

	in := input.Subscribe()
	return func(_ context.Context) {
		for flow := range in {
			printFlow(&flow)
		}
	}
}

func printFlow(f *ebpf.Record) {
	sb := strings.Builder{}
	sb.WriteString("transport=")
	sb.WriteString(strconv.Itoa(int(f.Id.TransportProtocol)))
	sb.WriteByte(' ')
	sb.WriteString(attr.VendorPrefix)
	sb.WriteString(".ip=")
	sb.WriteString(f.Attrs.OBIIP)
	sb.WriteString(" iface=")
	sb.WriteString(f.Attrs.Interface)
	sb.WriteString(" iface_direction=")
	sb.WriteString(strconv.Itoa(int(f.Metrics.IfaceDirection)))
	sb.WriteString(" src.address=")
	sb.WriteString(f.SrcIP().IP().String())
	sb.WriteString(" dst.address=")
	sb.WriteString(f.DstIP().IP().String())
	sb.WriteString(" src.name=")
	sb.WriteString(f.Attrs.SrcName)
	sb.WriteString(" dst.name=")
	sb.WriteString(f.Attrs.DstName)
	sb.WriteString(" src.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.SrcPort()), 10))
	sb.WriteString(" dst.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.DstPort()), 10))

	for k, v := range f.Attrs.Metadata {
		sb.WriteString(" ")
		sb.WriteString(string(k))
		sb.WriteString("=")
		sb.WriteString(v)
	}

	fmt.Println("network_flow:", sb.String())
}
