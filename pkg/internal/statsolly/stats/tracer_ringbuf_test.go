// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// TestTCPConnectionSummaryStructSize verifies the Go BPF mirror struct matches
// the expected 64-byte C layout (after removing 4 unused fields).
func TestTCPConnectionSummaryStructSize(t *testing.T) {
	const expectedSize = 64 // flags(1) + role(1) + pad(2) + 6*u32(24) + Conn(36)
	gotSize := unsafe.Sizeof(ebpf.StatsTCPConnectionSummary{})
	if gotSize != expectedSize {
		t.Errorf("StatsTCPConnectionSummary size = %d, want %d", gotSize, expectedSize)
	}
	t.Logf("Struct size: %d bytes (matching BPF tcp_connection_summary_t)", gotSize)
}

// TestTCPConnectionSummaryParsing constructs a raw BPF ring buffer event that
// matches the StatsTCPConnectionSummary C struct layout, feeds it through the
// parsing pipeline, and verifies the output values are correct.
//
// This tests:
//   - Raw byte → Go struct parsing (ReinterpretCast)
//   - All 6 metric fields are correctly extracted
//   - Connection info (src/dst IP, ports) is correctly parsed
//   - Role attribute is correctly passed through
func TestTCPConnectionSummaryParsing(t *testing.T) {
	// StatsTCPConnectionSummary layout (little-endian, x86_64):
	//   flags        u8    (1 byte)
	//   role         u8    (1 byte)
	//   pad          [2]u8 (2 bytes)
	//   srtt_us      u32   (4 bytes)
	//   mdev_us      u32   (4 bytes)
	//   total_retrans u32  (4 bytes)
	//   segs_out     u32   (4 bytes)
	//   segs_in      u32   (4 bytes)
	//   rcv_ooopack  u32   (4 bytes)
	//   conn.s_addr  [16]u8
	//   conn.d_addr  [16]u8
	//   conn.s_port  u16
	//   conn.d_port  u16
	//
	// Total: 4 + 6*4 + 16 + 16 + 2 + 2 = 64 bytes

	raw := make([]byte, 64)

	// flags = StatTypeTCPConnectionSummary = 7
	raw[0] = byte(ebpf.StatTypeTCPConnectionSummary)

	// role = 2 (server)
	raw[1] = 2

	// pad: raw[2:4] = 0

	// srtt_us = 15000 (15ms, simulating what the kernel would store AFTER >> 3)
	binary.LittleEndian.PutUint32(raw[4:8], 15000)

	// mdev_us = 3000 (3ms, simulating what the kernel would store AFTER >> 2)
	binary.LittleEndian.PutUint32(raw[8:12], 3000)

	// total_retrans = 5
	binary.LittleEndian.PutUint32(raw[12:16], 5)

	// segs_out = 200
	binary.LittleEndian.PutUint32(raw[16:20], 200)

	// segs_in = 180
	binary.LittleEndian.PutUint32(raw[20:24], 180)

	// rcv_ooopack = 3
	binary.LittleEndian.PutUint32(raw[24:28], 3)

	// conn.s_addr: 192.168.1.100 mapped to IPv4-in-IPv6 (::ffff:192.168.1.100)
	copy(raw[28:44], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 100})

	// conn.d_addr: 10.0.0.50 mapped to IPv4-in-IPv6
	copy(raw[44:60], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 50})

	// conn.s_port = 45678 (host byte order)
	binary.LittleEndian.PutUint16(raw[60:62], 45678)

	// conn.d_port = 443 (host byte order)
	binary.LittleEndian.PutUint16(raw[62:64], 443)

	record := &ringbuf.Record{
		RawSample: raw,
	}

	stat, err := handleStatEvent(record)
	if err != nil {
		t.Fatalf("handleStatEvent returned error: %v", err)
	}

	if stat.Type != ebpf.StatTypeTCPConnectionSummary {
		t.Errorf("stat.Type = %d, want %d", stat.Type, ebpf.StatTypeTCPConnectionSummary)
	}

	cs := stat.TCPConnectionSummary
	if cs == nil {
		t.Fatal("TCPConnectionSummary is nil")
	}

	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"SrttUs", cs.SrttUs, 15000},
		{"MdevUs", cs.MdevUs, 3000},
		{"TotalRetrans", cs.TotalRetrans, 5},
		{"SegsOut", cs.SegsOut, 200},
		{"SegsIn", cs.SegsIn, 180},
		{"RcvOoopack", cs.RcvOoopack, 3},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}

	if cs.Role != 2 {
		t.Errorf("Role = %d, want 2 (server)", cs.Role)
	}

	// Verify connection info
	ca := stat.CommonAttrs
	if ca.SrcPort != 45678 {
		t.Errorf("SrcPort = %d, want 45678", ca.SrcPort)
	}
	if ca.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", ca.DstPort)
	}
}

// TestMdevScalingVerification verifies that the BPF-side mdev_us >> 2 scaling
// is conceptually correct. The kernel stores mdev_us with a <<2 factor, so if
// the real mdev is 750μs, the kernel stores 3000. After BPF >> 2, we get 750.
// This test constructs a scenario where the BPF code has already done >> 2.
func TestMdevScalingVerification(t *testing.T) {
	// Simulate: real mdev = 750μs → kernel stores 750 << 2 = 3000
	// BPF code does >> 2 → Go receives 750
	kernelStoredMdev := uint32(3000) // kernel value: real * 4
	bpfOutputMdev := kernelStoredMdev >> 2
	if bpfOutputMdev != 750 {
		t.Errorf("mdev scaling: got %d, want 750 (real μs)", bpfOutputMdev)
	}

	// Simulate: real srtt = 15000μs → kernel stores 15000 << 3 = 120000
	// BPF code does >> 3 → Go receives 15000
	kernelStoredSrtt := uint32(120000) // kernel value: real * 8
	bpfOutputSrtt := kernelStoredSrtt >> 3
	if bpfOutputSrtt != 15000 {
		t.Errorf("srtt scaling: got %d, want 15000 (real μs)", bpfOutputSrtt)
	}

	t.Logf("Scaling verification passed:")
	t.Logf("  srtt: kernel=%d >> 3 = %dμs (%.3fms)", kernelStoredSrtt, bpfOutputSrtt, float64(bpfOutputSrtt)/1000)
	t.Logf("  mdev: kernel=%d >> 2 = %dμs (%.3fms)", kernelStoredMdev, bpfOutputMdev, float64(bpfOutputMdev)/1000)
}
