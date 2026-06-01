// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitPositionCalculation(t *testing.T) {
	for _, v := range [][4]uint32{
		{0, 1, 0, 1},
		{0, 2, 0, 2},
		{0, 65, 1, 1},
		{0, 66, 1, 2},
		{0, primeHash, 0, 0},
		{0, primeHash + 1, 0, 1},
	} {
		k := makeKey(v[0], v[1])
		segment, bit := pidSegmentBit(k)
		assert.Equal(t, segment, v[2])
		assert.Equal(t, bit, v[3])
	}
}

func makeKey(first, second uint32) uint64 {
	return (uint64(first) << 32) | uint64(second)
}

func TestHandleDNSChecksSKBHeaderRead(t *testing.T) {
	srcBytes, err := os.ReadFile("../../../../bpf/generictracer/dns.h")
	require.NoError(t, err)

	src := string(srcBytes)
	handleDNSStart := strings.Index(src, "static __always_inline u8 handle_dns(")
	require.NotEqual(t, -1, handleDNSStart)

	handleDNSBufStart := strings.Index(src[handleDNSStart:], "static __always_inline u8 handle_dns_buf(")
	require.NotEqual(t, -1, handleDNSBufStart)

	handleDNS := src[handleDNSStart : handleDNSStart+handleDNSBufStart]
	switchEnd := strings.Index(handleDNS, "    default:\n        return 0;\n    }\n\n")
	require.NotEqual(t, -1, switchEnd)

	lengthCheck := strings.Index(handleDNS, "if (skb->len <= (dns_off + sizeof(struct dnshdr))) {")
	require.NotEqual(t, -1, lengthCheck)
	require.Greater(t, lengthCheck, switchEnd)

	headerRead := strings.Index(handleDNS, "if (bpf_skb_load_bytes(skb, dns_off, &hdr, sizeof(hdr))) {")
	require.NotEqual(t, -1, headerRead)
	require.Less(t, lengthCheck, headerRead)

	require.Equal(t, 1, strings.Count(handleDNS, "bpf_skb_load_bytes(skb, dns_off, &hdr, sizeof(hdr))"))
	require.NotContains(t, handleDNS, "\n    bpf_skb_load_bytes(skb, dns_off, &hdr, sizeof(hdr));")
}
