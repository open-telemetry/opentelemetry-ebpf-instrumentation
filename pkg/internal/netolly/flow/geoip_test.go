// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
)

func TestMaxMindLookup(t *testing.T) {
	lookupFn, err := getLookupFn(&GeoIP{
		MaxMindInfo: MaxMindConfig{
			ASNPath:     "../../../../internal/test/geoip/GeoLite2-ASN-Test.mmdb",
			CountryPath: "../../../../internal/test/geoip/GeoIP2-Country-Test.mmdb",
		},
	})
	require.NoError(t, err)
	info, err := lookupFn(net.IPv4(216, 160, 83, 57))
	require.NoError(t, err)
	assert.Equal(t, "AS209", info.ASN)
	assert.Equal(t, "US", info.Country)
}

func TestIPInfoLookup(t *testing.T) {
	lookupFn, err := getLookupFn(&GeoIP{
		IPInfo: IPInfoConfig{
			Path: "../../../../internal/test/geoip/ipinfo_lite_sample.mmdb",
		},
	})
	require.NoError(t, err)
	info, err := lookupFn(net.IPv4(1, 7, 0, 17))
	require.NoError(t, err)
	assert.Equal(t, "AS9583", info.ASN)
	assert.Equal(t, "IN", info.Country)
}

var fileFlag = flag.String("db", "../../../../internal/test/geoip/ipinfo_lite_sample.mmdb", "db to use for geoip benchmarks")

func BenchmarkDBLookup(b *testing.B) {
	flag.Parse()
	lookupFn, err := getLookupFn(&GeoIP{
		IPInfo: IPInfoConfig{
			Path: *fileFlag,
		},
	})
	if err != nil {
		b.Fatalf("failed to load database: %s", err.Error())
	}
	for _, addrSpace := range []uint32{256, 512, 1024, 2048, math.MaxUint32} {
		b.Run(fmt.Sprintf("addr=%d", addrSpace), func(b *testing.B) {
			for b.Loop() {
				ipnum := rand.Uint32N(addrSpace)
				bytes := make([]byte, 16)
				binary.LittleEndian.PutUint32(bytes[12:], ipnum)
				ip := ebpf.IPAddr(bytes)
				_, err := lookupFn(ip.IP())
				if err != nil {
					b.Fatal(err.Error())
				}
			}
		})
	}
}

func BenchmarkDBLookupCached(b *testing.B) {
	runBench := func(b *testing.B, cacheSize int, addrSpace uint32) {
		cache := expirable.NewLRU[ebpf.IPAddr, ipInfo](cacheSize, nil, time.Hour)
		lookupFn, err := getLookupFn(&GeoIP{
			IPInfo: IPInfoConfig{
				Path: *fileFlag,
			},
		})
		if err != nil {
			b.Fatalf("failed to load database: %s", err.Error())
		}
		lookups := 0
		hits := 0
		for b.Loop() {
			lookups++
			ipnum := rand.Uint32N(addrSpace)
			bytes := make([]byte, 16)
			binary.LittleEndian.PutUint32(bytes[12:], ipnum)
			ip := ebpf.IPAddr(bytes)
			_, ok := cache.Get(ip)
			if !ok {
				i, err := lookupFn(ip.IP())
				if err != nil {
					b.Fatal(err.Error())
				}
				cache.Add(ip, i)
			} else {
				hits++
			}
		}
	}
	for _, cacheSize := range []int{256, 512, 1024} {
		for _, addrSpace := range []uint32{256, 512, 1024, math.MaxUint32} {
			b.Run(fmt.Sprintf("cache=%d;addr=%d", cacheSize, addrSpace), func(b *testing.B) {
				runBench(b, cacheSize, addrSpace)
			})
		}
	}
}
