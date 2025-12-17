// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"math/rand/v2"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func BenchmarkDBLookup(b *testing.B) {
	lookupFn, err := getLookupFn(&GeoIP{
		IPInfo: IPInfoConfig{
			Path: "../../../../internal/test/geoip/ipinfo_lite_sample.mmdb",
		},
	})
	if err != nil {
		b.Fatalf("failed to load database: %s", err.Error())
	}
	for b.Loop() {
		ip := net.IPv4(byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256)), byte(rand.IntN(256)))
		_, err := lookupFn(ip)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}
