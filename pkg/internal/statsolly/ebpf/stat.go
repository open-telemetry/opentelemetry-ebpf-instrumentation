// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"net"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

type StatType uint8

const (
	StatTypeTCPRtt StatType = iota + 1
)

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
// type IPAddr [net.IPv6len]uint8

// Stat contains accumulated metrics from a stats, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions StatGetters
// in pkg/internal/statsolly/ebpf/stat_getters.go and getDefinitions in
// pkg/export/attributes/attr_defs.go
type Stat struct {
	Type   StatType `json:"type"`
	TCPRtt *TCPRtt  `json:"-"`

	// Attrs of the stat stat: source/destination, OBI IP, etc...
	Attrs StatAttrs
}

type StatAttrs struct {
	SourceAddress      string
	DestinationAddress string

	SourcePort      int
	DestinationPort int

	// SrcName and DstName might be set from several sources along the processing/decoration pipeline:
	// - K8s entity
	// - Host name
	// - IP
	SrcName string
	DstName string

	// SrcZone and DstZone represent the Cloud availability zones of the source and destination
	SrcZone string
	DstZone string

	// OBIIP provides information about the source of the flow (the Agent that traced it)
	OBIIP    string
	Metadata map[attr.Name]string
}

type TCPRtt struct {
	Srtt uint32 `json:"srtt"`
}

// IP returns the net.IP equivalent object
func (ia *IPAddr) IP() net.IP {
	return ia[:]
}

// TODO pinoOgni not sure if this is a good idea
func (s *Stat) SrcIP() *IPAddr {
	ip := net.ParseIP(s.Attrs.SourceAddress)
	if ip == nil {
		return nil
	}

	// Convert []byte to [16]byte
	var addr IPAddr
	copy(addr[:], ip.To16())
	return &addr
}

// TODO pinoOgni not sure if this is a good idea
func (s *Stat) DstIP() *IPAddr {
	ip := net.ParseIP(s.Attrs.DestinationAddress)
	if ip == nil {
		return nil
	}

	// Convert []byte to [16]byte
	var addr IPAddr
	copy(addr[:], ip.To16())
	return &addr
}
