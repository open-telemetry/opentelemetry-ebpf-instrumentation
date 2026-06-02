// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"os"
	"regexp"
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
	switchPattern := regexp.MustCompile(`(?s)switch\s*\(p_info->l4_proto\)\s*\{.*?default:\s*return 0;\s*\}`)
	switchMatch := switchPattern.FindStringIndex(handleDNS)
	require.NotNil(t, switchMatch)

	lengthGuardPattern := regexp.MustCompile(`if\s*\(\s*skb->len\s*<\s*\(\s*dns_off\s*\+\s*sizeof\(struct dnshdr\)\s*\)\s*\)\s*\{`)
	lengthGuardMatch := lengthGuardPattern.FindStringIndex(handleDNS)
	require.NotNil(t, lengthGuardMatch)
	require.Greater(t, lengthGuardMatch[0], switchMatch[1])

	headerReadPattern := regexp.MustCompile(`if\s*\(\s*bpf_skb_load_bytes\s*\(\s*skb\s*,\s*dns_off\s*,\s*&hdr\s*,\s*sizeof\(hdr\)\s*\)\s*\)\s*\{`)
	headerReadMatch := headerReadPattern.FindStringIndex(handleDNS)
	require.NotNil(t, headerReadMatch)
	require.Less(t, lengthGuardMatch[0], headerReadMatch[0])

	require.Len(t, headerReadPattern.FindAllStringIndex(handleDNS, -1), 1)
	require.NotContains(t, handleDNS, "\n    bpf_skb_load_bytes(skb, dns_off, &hdr, sizeof(hdr));")
}
