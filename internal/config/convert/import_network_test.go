// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestV2ToRuntimeNetworkCaptureAndStatsRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := obi.DefaultConfig
	cfg.Metrics.Features = export.FeatureNetwork |
		export.FeatureStatsTCPFailedConnections |
		export.FeatureStatsTCPIo

	cfg.NetworkFlows.Enable = true
	cfg.NetworkFlows.Source = obi.EbpfSourceTC
	cfg.NetworkFlows.AgentIP = "192.0.2.1"
	cfg.NetworkFlows.AgentIPIface = obi.NetworkAgentIPIfaceLocal
	cfg.NetworkFlows.AgentIPType = "ipv4"
	cfg.NetworkFlows.Interfaces = []string{"eth0"}
	cfg.NetworkFlows.ExcludeInterfaces = []string{"lo", "docker0"}
	cfg.NetworkFlows.Protocols = []string{"tcp"}
	cfg.NetworkFlows.ExcludeProtocols = []string{"udp"}
	cfg.NetworkFlows.Direction = "egress"
	cfg.NetworkFlows.CacheMaxFlows = 300
	cfg.NetworkFlows.CacheActiveTimeout = 14 * time.Second
	cfg.NetworkFlows.Deduper = "none"
	cfg.NetworkFlows.DeduperFCTTL = 15 * time.Second
	cfg.NetworkFlows.Sampling = 16
	cfg.NetworkFlows.GuessPorts = "ordinal"
	cfg.NetworkFlows.ListenInterfaces = obi.NetworkListenInterfacesPoll
	cfg.NetworkFlows.ListenPollPeriod = 17 * time.Second
	require.NoError(t, yaml.Unmarshal([]byte("- cidr: 10.0.0.0/8\n  name: private\n"), &cfg.NetworkFlows.CIDRs))
	cfg.NetworkFlows.GeoIP.IPInfo.Path = "/var/lib/ipinfo.mmdb"
	cfg.NetworkFlows.GeoIP.MaxMindInfo.CountryPath = "/var/lib/country.mmdb"
	cfg.NetworkFlows.GeoIP.MaxMindInfo.ASNPath = "/var/lib/asn.mmdb"
	cfg.NetworkFlows.GeoIP.CacheLen = 77
	cfg.NetworkFlows.GeoIP.CacheTTL = 78 * time.Second
	cfg.NetworkFlows.ReverseDNS.Type = "local"
	cfg.NetworkFlows.ReverseDNS.CacheLen = 79
	cfg.NetworkFlows.ReverseDNS.CacheTTL = 80 * time.Second
	cfg.NetworkFlows.Print = true
	cfg.Filters.Network = filter.AttributeFamilyConfig{
		"src.address": {NotMatch: "10.*"},
	}

	require.NoError(t, yaml.Unmarshal([]byte("- cidr: 192.0.2.0/24\n  name: docs\n"), &cfg.Stats.CIDRs))
	cfg.Stats.AgentIP = "198.51.100.1"
	cfg.Stats.AgentIPIface = obi.NetworkAgentIPIfaceLocal
	cfg.Stats.AgentIPType = "ipv4"
	cfg.Stats.GeoIP.IPInfo.Path = "/var/lib/stats-ipinfo.mmdb"
	cfg.Stats.GeoIP.MaxMindInfo.CountryPath = "/var/lib/stats-country.mmdb"
	cfg.Stats.GeoIP.MaxMindInfo.ASNPath = "/var/lib/stats-asn.mmdb"
	cfg.Stats.GeoIP.CacheLen = 81
	cfg.Stats.GeoIP.CacheTTL = 82 * time.Second
	cfg.Stats.ReverseDNS.Type = "ebpf"
	cfg.Stats.ReverseDNS.CacheLen = 83
	cfg.Stats.ReverseDNS.CacheTTL = 84 * time.Second
	cfg.Stats.Print = true
	srtt := 1024
	cfg.Filters.Stats = filter.AttributeFamilyConfig{
		"srtt": {GreaterThan: &srtt},
	}

	_, ext := RuntimeToV2(&cfg)

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, cfg.NetworkFlows.CIDRs, got.NetworkFlows.CIDRs)
	require.Equal(t, cfg.Filters.Network, got.Filters.Network)
	require.Equal(t, "/var/lib/ipinfo.mmdb", got.NetworkFlows.GeoIP.IPInfo.Path)
	require.Equal(t, "/var/lib/country.mmdb", got.NetworkFlows.GeoIP.MaxMindInfo.CountryPath)
	require.Equal(t, "/var/lib/asn.mmdb", got.NetworkFlows.GeoIP.MaxMindInfo.ASNPath)
	require.Equal(t, 77, got.NetworkFlows.GeoIP.CacheLen)
	require.Equal(t, 78*time.Second, got.NetworkFlows.GeoIP.CacheTTL)
	require.Equal(t, "local", got.NetworkFlows.ReverseDNS.Type)
	require.Equal(t, 79, got.NetworkFlows.ReverseDNS.CacheLen)
	require.Equal(t, 80*time.Second, got.NetworkFlows.ReverseDNS.CacheTTL)

	require.Equal(t, cfg.Stats.CIDRs, got.Stats.CIDRs)
	require.Equal(t, cfg.Filters.Stats, got.Filters.Stats)
	require.Equal(t, "/var/lib/stats-ipinfo.mmdb", got.Stats.GeoIP.IPInfo.Path)
	require.Equal(t, "/var/lib/stats-country.mmdb", got.Stats.GeoIP.MaxMindInfo.CountryPath)
	require.Equal(t, "/var/lib/stats-asn.mmdb", got.Stats.GeoIP.MaxMindInfo.ASNPath)
	require.Equal(t, 81, got.Stats.GeoIP.CacheLen)
	require.Equal(t, 82*time.Second, got.Stats.GeoIP.CacheTTL)
	require.Equal(t, "ebpf", got.Stats.ReverseDNS.Type)
	require.Equal(t, 83, got.Stats.ReverseDNS.CacheLen)
	require.Equal(t, 84*time.Second, got.Stats.ReverseDNS.CacheTTL)
	require.True(t, got.Stats.Print)
	require.Equal(t, export.FeatureNetwork|export.FeatureStatsTCPFailedConnections|export.FeatureStatsTCPIo, got.Metrics.Features)
}

func TestV2ToRuntimePartialNetworkCapturePreservesMissingMetadataDefaults(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Network: schema.CaptureNetwork{
				Capture: schema.NetworkCapture{
					Enabled: true,
					Source:  schema.NetworkSourceTC,
					EndpointIdentity: schema.EndpointIdentity{
						AgentIPInterface: schema.AgentIPInterfaceLocal,
						AgentIPFamily:    schema.AgentIPFamilyIPv4,
					},
					Selection: schema.NetworkSelection{
						Interfaces: schema.IncludeExclude{
							Include: []string{"eth0"},
						},
						Direction: schema.NetworkDirectionEgress,
					},
					FlowLifecycle: schema.FlowLifecycle{
						MaxTrackedFlows: 99,
						ActiveTimeout:   schema.Duration(2 * time.Second),
						Deduplication: schema.Deduplication{
							Strategy:     schema.DeduplicationStrategyFirstCome,
							FirstComeTTL: schema.Duration(3 * time.Second),
						},
						Sampling:   4,
						GuessPorts: "ordinal",
					},
					InterfaceDiscovery: schema.InterfaceDiscovery{
						Mode:         schema.InterfaceDiscoveryModePoll,
						PollInterval: schema.Duration(5 * time.Second),
					},
				},
			},
		},
	})
	require.NoError(t, err)

	require.True(t, got.NetworkFlows.Enable)
	require.Equal(t, obi.EbpfSourceTC, got.NetworkFlows.Source)
	require.Equal(t, 99, got.NetworkFlows.CacheMaxFlows)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.CIDRs, got.NetworkFlows.CIDRs)
	require.Equal(t, obi.DefaultConfig.Filters.Network, got.Filters.Network)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.GeoIP.CacheLen, got.NetworkFlows.GeoIP.CacheLen)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.GeoIP.CacheTTL, got.NetworkFlows.GeoIP.CacheTTL)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ReverseDNS.Type, got.NetworkFlows.ReverseDNS.Type)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ReverseDNS.CacheLen, got.NetworkFlows.ReverseDNS.CacheLen)
	require.Equal(t, obi.DefaultConfig.NetworkFlows.ReverseDNS.CacheTTL, got.NetworkFlows.ReverseDNS.CacheTTL)
}

func TestV2ToRuntimeNetworkCaptureSkipsDivergentSignalFilters(t *testing.T) {
	t.Parallel()

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Network: schema.CaptureNetwork{
				Capture: schema.NetworkCapture{
					Filters: schema.SignalFilters{
						Traces: schema.AttributeFilters{
							"src.address": {Match: "10.*"},
						},
						Metrics: schema.AttributeFilters{
							"dst.address": {Match: "10.*"},
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.Filters.Network, got.Filters.Network)
}
