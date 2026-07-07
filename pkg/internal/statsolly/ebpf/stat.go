// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"structs"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

type StatType uint8

const (
	StatTypeTCPRtt StatType = iota + 1
	StatTypeTCPFailedConnection
	StatTypeTCPRetransmit
	StatTypeTCPIo
	_ // 5 reserved
	_ // 6 reserved
	StatTypeTCPConnectionSummary
)

type TCPFailReasonType string

const (
	Unknown           TCPFailReasonType = "unknown"
	ConnectionRefused TCPFailReasonType = "refused"
	ConnectionReset   TCPFailReasonType = "reset"
	TimedOut          TCPFailReasonType = "timed-out"
	HostUnreachable   TCPFailReasonType = "host-unreachable"
	NetUnreachable    TCPFailReasonType = "net-unreachable"
	Other             TCPFailReasonType = "other"
)

// TCPFailReasonTypeCode mirrors enum tcp_fail_reason in bpf/statsolly/types.h
type TCPFailReasonTypeCode uint8

const (
	CodeUnknown           TCPFailReasonTypeCode = 0
	CodeConnectionRefused TCPFailReasonTypeCode = 1
	CodeConnectionReset   TCPFailReasonTypeCode = 2
	CodeTimedOut          TCPFailReasonTypeCode = 3
	CodeHostUnreachable   TCPFailReasonTypeCode = 4
	CodeNetUnreachable    TCPFailReasonTypeCode = 5
	CodeOther             TCPFailReasonTypeCode = 255
)

type NetworkTCPHandshakeRoleType string

const (
	RoleUnknown NetworkTCPHandshakeRoleType = "unknown"
	RoleClient  NetworkTCPHandshakeRoleType = "client"
	RoleServer  NetworkTCPHandshakeRoleType = "server"
)

// NetworkTCPHandshakeRoleCode mirrors enum tcp_handshake_role in bpf/statsolly/types.h.
type NetworkTCPHandshakeRoleCode uint8

const (
	CodeRoleUnknown NetworkTCPHandshakeRoleCode = 0
	CodeRoleClient  NetworkTCPHandshakeRoleCode = 1
	CodeRoleServer  NetworkTCPHandshakeRoleCode = 2
)

type NetworkIoDirectionType string

const (
	DirectionReceive  NetworkIoDirectionType = "receive"
	DirectionTransmit NetworkIoDirectionType = "transmit"
)

// NetworkIoDirectionCode mirrors enum network_io_direction in bpf/statsolly/types.h.
type NetworkIoDirectionCode uint8

const (
	CodeDirectionReceive  NetworkIoDirectionCode = 1
	CodeDirectionTransmit NetworkIoDirectionCode = 2
)

// Stat contains accumulated metrics from a stat, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions StatGetters
// in pkg/internal/statsolly/ebpf/stat_getters.go and getDefinitions in
// pkg/export/attributes/attr_defs.go
type Stat struct {
	Type                 StatType              `json:"type"`
	TCPRtt               *TCPRtt               `json:"-"`
	TCPFailedConnection  *TCPFailedConnection  `json:"-"`
	TCPRetransmit        bool                  `json:"-"`
	TCPIo                *TCPIo                `json:"-"`
	TCPConnectionSummary *TCPConnectionSummary `json:"-"`

	// Attrs of the flow record: source/destination, OBI IP, etc...
	CommonAttrs pipe.CommonAttrs
}

type TCPRtt struct {
	SrttUs uint32 `json:"srtt_us"`
	Role   uint8  `json:"role"`
}

type TCPFailedConnection struct {
	Reason uint8 `json:"reason"`
	Role   uint8 `json:"role"`
}

type TCPIo struct {
	Direction uint8  `json:"direction"`
	Bytes     uint32 `json:"bytes"`
}

// TCPConnectionSummary holds lifetime stats for a closed TCP connection.
type TCPConnectionSummary struct {
	Role         uint8  `json:"role"`
	SrttUs       uint32 `json:"srtt_us"`
	MdevUs       uint32 `json:"mdev_us"`
	TotalRetrans uint32 `json:"total_retrans"`
	SegsOut      uint32 `json:"segs_out"`
	SegsIn       uint32 `json:"segs_in"`
	RcvOoopack   uint32 `json:"rcv_ooopack"`
}

// Conn mirrors connection_info_t from bpf/common/connection_info.h.
type Conn struct {
	_      structs.HostLayout
	S_addr [16]uint8 //nolint:revive,staticcheck
	D_addr [16]uint8 //nolint:revive,staticcheck
	S_port uint16    //nolint:revive,staticcheck
	D_port uint16    //nolint:revive,staticcheck
}

type StatsTCPRtt struct {
	_      structs.HostLayout
	Flags  uint8
	Role   uint8
	Pad    [2]uint8
	SrttUs uint32
	Conn
}

type StatsTCPFailedConnection struct {
	_      structs.HostLayout
	Flags  uint8
	Reason uint8
	Role   uint8
	Pad    [1]uint8
	Conn
}

type StatsTCPRetransmit struct {
	_     structs.HostLayout
	Flags uint8
	Pad   [3]uint8
	Conn
}

type StatsTCPIo struct {
	_         structs.HostLayout
	Flags     uint8
	Direction uint8
	Count     uint8
	Pad       [1]uint8
	Bytes     [TCPIoBatchSize]uint32
	Conn
}

// TCPIoBatchSize mirrors k_tcp_io_batch_size in bpf/statsolly/types.h.
const TCPIoBatchSize = 10

// StatsTCPConnectionSummary mirrors tcp_connection_summary_t from bpf/statsolly/k_tcp.c.
type StatsTCPConnectionSummary struct {
	_            structs.HostLayout
	Flags        uint8
	Role         uint8
	Pad          [2]uint8
	SrttUs       uint32
	MdevUs       uint32
	TotalRetrans uint32
	SegsOut      uint32
	SegsIn       uint32
	RcvOoopack   uint32
	Conn
}
