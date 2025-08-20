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
	sb.WriteString(f.Attrs.Src.TargetName)
	sb.WriteString(" dst.name=")
	sb.WriteString(f.Attrs.Dst.TargetName)
	sb.WriteString(" src.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.SrcPort()), 10))
	sb.WriteString(" dst.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.DstPort()), 10))

	writeMeta := func(label string, meta string) {
		if meta != "" {
			sb.WriteString(fmt.Sprintf(" %s=", label))
			sb.WriteString(meta)
		}
	}

	writeMeta("k8s.cluster.name", f.Attrs.K8sClusterName)
	writeMeta("k8s.src.namespace", f.Attrs.Src.Namespace)
	writeMeta("k8s.dst.namespace", f.Attrs.Dst.Namespace)
	writeMeta("k8s.src.owner.name", f.Attrs.Src.OwnerName)
	writeMeta("k8s.dst.owner.name", f.Attrs.Dst.OwnerName)
	writeMeta("k8s.src.owner.type", f.Attrs.Src.OwnerType)
	writeMeta("k8s.dst.owner.type", f.Attrs.Dst.OwnerType)
	writeMeta("k8s.src.node.ip", f.Attrs.Src.NodeIP)
	writeMeta("k8s.dst.node.ip", f.Attrs.Dst.NodeIP)
	writeMeta("k8s.src.node.Name", f.Attrs.Src.NodeName)
	writeMeta("k8s.dst.node.Name", f.Attrs.Dst.NodeName)

	writeMeta("src.cidr", f.Attrs.Src.CIDR)
	writeMeta("dst.cidr", f.Attrs.Dst.CIDR)

	fmt.Println("network_flow:", sb.String())
}
