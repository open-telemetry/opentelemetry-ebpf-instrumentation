// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package xdp // import "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"

type question struct {
	qName  string
	qType  uint16
	qClass uint16
}

type record struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	data  []byte
}

type dnsMessage struct {
	id        uint16
	questions []*question
	answers   []*record
}
