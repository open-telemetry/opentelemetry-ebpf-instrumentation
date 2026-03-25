// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func capturePrintStat(s *ebpf.Stat) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w

	printStat(s)

	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func ipv4Addr(ip string) pipe.IPAddr {
	parsed := net.ParseIP(ip).To16()
	var addr pipe.IPAddr
	copy(addr[:], parsed)
	return addr
}

func TestPrintStat_TCPRtt(t *testing.T) {
	s := &ebpf.Stat{
		Type: ebpf.StatTypeTCPRtt,
		TCPRtt: &ebpf.TCPRtt{
			SrttUs: 42,
		},
		CommonAttrs: pipe.CommonAttrs{
			OBIIP:   "10.0.0.1",
			SrcAddr: ipv4Addr("192.168.1.1"),
			DstAddr: ipv4Addr("10.0.0.2"),
			SrcName: "src-svc",
			DstName: "dst-svc",
			SrcPort: 1234,
			DstPort: 8080,
		},
	}

	out := capturePrintStat(s)

	for _, want := range []string{
		"ip=10.0.0.1",
		"src.address=192.168.1.1",
		"dst.address=10.0.0.2",
		"src.name=src-svc",
		"dst.name=dst-svc",
		"src.port=1234",
		"dst.port=8080",
		"srtt=42",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got: %s", want, out)
		}
	}
}

func TestPrintStat_WithMetadata(t *testing.T) {
	s := &ebpf.Stat{
		Type:   ebpf.StatTypeTCPRtt,
		TCPRtt: &ebpf.TCPRtt{SrttUs: 10},
		CommonAttrs: pipe.CommonAttrs{
			Metadata: map[attr.Name]string{
				"k8s.namespace": "default",
				"k8s.pod":       "my-pod",
			},
		},
	}

	out := capturePrintStat(s)

	for _, want := range []string{"k8s.namespace=default", "k8s.pod=my-pod"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got: %s", want, out)
		}
	}
}

func TestPrintStat_NoTCPRtt(t *testing.T) {
	s := &ebpf.Stat{
		CommonAttrs: pipe.CommonAttrs{
			OBIIP:   "1.2.3.4",
			SrcName: "a",
			DstName: "b",
		},
	}

	out := capturePrintStat(s)

	if strings.Contains(out, "srtt=") {
		t.Errorf("expected no srtt field for non-TCPRtt stat, got: %s", out)
	}
	if !strings.Contains(out, "stats:") {
		t.Errorf("expected output to start with 'stats:', got: %s", out)
	}
}

func TestPrintStat_ZeroIPAddrs(t *testing.T) {
	s := &ebpf.Stat{
		CommonAttrs: pipe.CommonAttrs{
			SrcAddr: pipe.IPAddr{}, // zero
			DstAddr: pipe.IPAddr{}, // zero
		},
	}

	out := capturePrintStat(s)

	// Zero IPAddr.String() returns "", so the fields are present but empty
	if !strings.Contains(out, "src.address=") {
		t.Errorf("expected src.address field, got: %s", out)
	}
}

func TestPrintStat_IPv6(t *testing.T) {
	parsed := net.ParseIP("2001:db8::1")
	var addr pipe.IPAddr
	copy(addr[:], parsed.To16())

	s := &ebpf.Stat{
		CommonAttrs: pipe.CommonAttrs{
			SrcAddr: addr,
		},
	}

	out := capturePrintStat(s)

	if !strings.Contains(out, "src.address=2001:db8::1") {
		t.Errorf("expected IPv6 address in output, got: %s", out)
	}
}
