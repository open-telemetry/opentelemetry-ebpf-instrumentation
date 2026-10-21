// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRoute53Client struct {
	privateZones func(*route53.ListHostedZonesByVPCInput) (*route53.ListHostedZonesByVPCOutput, error)
	zones        func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error)
	list         func(*route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error)
}

func (f fakeRoute53Client) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return f.list(in)
}

func (f fakeRoute53Client) ListHostedZones(_ context.Context, in *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return f.zones(in)
}

func (f fakeRoute53Client) ListHostedZonesByVPC(_ context.Context, in *route53.ListHostedZonesByVPCInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesByVPCOutput, error) {
	return f.privateZones(in)
}

func route53Record(name, ip string, kind types.RRType) types.ResourceRecordSet {
	return types.ResourceRecordSet{Name: aws.String(name), Type: kind, ResourceRecords: []types.ResourceRecord{{Value: aws.String(ip)}}}
}

func route53PrivateInventory(client fakeRoute53Client, ids []string) *Route53Inventory {
	client.zones = func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
		return &route53.ListHostedZonesOutput{}, nil
	}
	client.privateZones = func(*route53.ListHostedZonesByVPCInput) (*route53.ListHostedZonesByVPCOutput, error) {
		out := &route53.ListHostedZonesByVPCOutput{}
		for _, id := range ids {
			out.HostedZoneSummaries = append(out.HostedZoneSummaries, types.HostedZoneSummary{HostedZoneId: aws.String(id)})
		}
		return out, nil
	}
	refresher := NewRoute53Inventory(client, ids)
	refresher.VPCID, refresher.VPCRegion = "vpc-local", "us-east-1"
	return refresher
}

func TestRoute53Refresh(t *testing.T) {
	calls := 0
	client := fakeRoute53Client{list: func(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
		calls++
		switch calls {
		case 1:
			assert.Equal(t, "zone-a", aws.ToString(in.HostedZoneId))
			return &route53.ListResourceRecordSetsOutput{
				IsTruncated: true, NextRecordName: aws.String("b.example."), NextRecordType: types.RRTypeA, NextRecordIdentifier: aws.String("weighted"),
				ResourceRecordSets: []types.ResourceRecordSet{route53Record("Z.Example.", "10.0.0.1", types.RRTypeA)},
			}, nil
		case 2:
			assert.Equal(t, "b.example.", aws.ToString(in.StartRecordName))
			assert.Equal(t, types.RRTypeA, in.StartRecordType)
			assert.Equal(t, "weighted", aws.ToString(in.StartRecordIdentifier))
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{
				route53Record("B.Example.", "10.0.0.1", types.RRTypeA),
				route53Record("IPv6.Example.", "2001:0db8::1", types.RRTypeAaaa),
				route53Record("alias.example.", "b.example.", types.RRTypeCname),
				route53Record("*.example.", "10.0.0.2", types.RRTypeA),
				route53Record(`\052.example.`, "10.0.0.3", types.RRTypeA),
				route53Record("invalid.example.", "invalid", types.RRTypeA),
				route53Record("wrong-family.example.", "10.0.0.4", types.RRTypeAaaa),
			}}, nil
		default:
			assert.Equal(t, "zone-b", aws.ToString(in.HostedZoneId))
			assert.Nil(t, in.StartRecordName)
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{route53Record("A.Example.", "10.0.0.1", types.RRTypeA)}}, nil
		}
	}}
	inventory := NewInventory([]MetadataRefresher{route53PrivateInventory(client, []string{"zone-a", "zone-b"})})
	inventory.refresh(t.Context())
	assert.Equal(t, 3, calls)
	name, ok := inventory.ServiceNameForIP("10.0.0.1")
	assert.True(t, ok)
	assert.Equal(t, "a.example", name)
	name, ok = inventory.ServiceNameForIP("2001:db8:0:0::1")
	assert.True(t, ok)
	assert.Equal(t, "ipv6.example", name)
	assert.Len(t, inventory.snapshot.ServiceByIP, 2)
}

func TestRoute53RetainsSnapshotAndRemovesDeletedRecords(t *testing.T) {
	fail := false
	empty := false
	client := fakeRoute53Client{list: func(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
		if fail && aws.ToString(in.HostedZoneId) == "zone-b" {
			return nil, errors.New("unavailable")
		}
		out := &route53.ListResourceRecordSetsOutput{}
		if !empty {
			out.ResourceRecordSets = []types.ResourceRecordSet{route53Record("service.example.", "10.0.0.1", types.RRTypeA)}
		}
		return out, nil
	}}
	inventory := NewInventory([]MetadataRefresher{route53PrivateInventory(client, []string{"zone-a", "zone-b"})})
	inventory.refresh(t.Context())
	changes := inventory.SubscribeContainerChanges()
	fail, empty = true, true
	inventory.refresh(t.Context())
	name, ok := inventory.ServiceNameForIP("10.0.0.1")
	assert.True(t, ok)
	assert.Equal(t, "service.example", name)
	fail = false
	inventory.refresh(t.Context())
	_, ok = inventory.ServiceNameForIP("10.0.0.1")
	assert.False(t, ok)
	select {
	case <-changes:
		t.Fatal("IP-only refresh published container changes")
	default:
	}
}

func TestRoute53PollingBackoff(t *testing.T) {
	var apiError error = &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"}
	client := fakeRoute53Client{list: func(*route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
		if apiError != nil {
			return nil, apiError
		}
		return &route53.ListResourceRecordSetsOutput{}, nil
	}}
	refresher := route53PrivateInventory(client, []string{"zone"})
	interval := refresher.RefreshInterval
	for range 100 {
		delay := refresher.RefreshDelay(true)
		assert.GreaterOrEqual(t, delay, time.Duration(0))
		assert.Less(t, delay, interval)
	}
	snapshot := &MetadataSnapshot{ServiceByIP: map[string]string{}}
	for _, multiplier := range []time.Duration{2, 4, 8, 8} {
		require.Error(t, refresher.Refresh(t.Context(), snapshot))
		require.Equal(t, multiplier*interval, refresher.backoff)
		delay := refresher.RefreshDelay(false)
		assert.GreaterOrEqual(t, delay, multiplier*interval*4/5)
		assert.LessOrEqual(t, delay, multiplier*interval*6/5)
	}
	apiError = errors.New("access denied")
	require.Error(t, refresher.Refresh(t.Context(), snapshot))
	require.Equal(t, 8*interval, refresher.backoff)
	apiError = nil
	require.NoError(t, refresher.Refresh(t.Context(), snapshot))
	require.Zero(t, refresher.backoff)
	delay := refresher.RefreshDelay(false)
	assert.GreaterOrEqual(t, delay, interval*4/5)
	assert.LessOrEqual(t, delay, interval*6/5)
}

func TestRoute53DiscoversHostedZones(t *testing.T) {
	for name, configured := range map[string][]string{"omitted": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			zoneCalls := 0
			var recordZones []string
			client := fakeRoute53Client{
				zones: func(in *route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
					zoneCalls++
					if in.Marker == nil {
						return &route53.ListHostedZonesOutput{
							HostedZones: []types.HostedZone{{Id: aws.String("/hostedzone/public"), Config: &types.HostedZoneConfig{}}},
							IsTruncated: true, NextMarker: aws.String("next"),
						}, nil
					}
					require.Equal(t, "next", aws.ToString(in.Marker))
					return &route53.ListHostedZonesOutput{HostedZones: []types.HostedZone{{Id: aws.String("/hostedzone/private"), Config: &types.HostedZoneConfig{PrivateZone: true}}}}, nil
				},
				list: func(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
					recordZones = append(recordZones, aws.ToString(in.HostedZoneId))
					return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{route53Record("service.example.", "10.0.0.1", types.RRTypeA)}}, nil
				},
				privateZones: func(in *route53.ListHostedZonesByVPCInput) (*route53.ListHostedZonesByVPCOutput, error) {
					require.Equal(t, "vpc-local", aws.ToString(in.VPCId))
					require.Equal(t, types.VPCRegionUsEast1, in.VPCRegion)
					return &route53.ListHostedZonesByVPCOutput{HostedZoneSummaries: []types.HostedZoneSummary{{HostedZoneId: aws.String("/hostedzone/private")}}}, nil
				},
			}
			refresher := NewRoute53Inventory(client, configured)
			refresher.VPCID, refresher.VPCRegion = "vpc-local", "us-east-1"
			snapshot := &MetadataSnapshot{ServiceByIP: map[string]string{}}
			require.NoError(t, refresher.Refresh(t.Context(), snapshot))
			require.Equal(t, 2, zoneCalls)
			require.Equal(t, []string{"/hostedzone/public", "/hostedzone/private"}, recordZones)
			require.Equal(t, "service.example", snapshot.ServiceByIP["10.0.0.1"])
		})
	}
}

func TestRoute53DiscoveryRefreshAndRecovery(t *testing.T) {
	zones := []types.HostedZone{{Id: aws.String("zone-a"), Config: &types.HostedZoneConfig{}}}
	var discoveryError error
	client := fakeRoute53Client{
		zones: func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
			if discoveryError != nil {
				return nil, discoveryError
			}
			return &route53.ListHostedZonesOutput{HostedZones: zones}, nil
		},
		list: func(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{route53Record(aws.ToString(in.HostedZoneId)+".example.", "8.8.8.8", types.RRTypeA)}}, nil
		},
	}
	refresher := NewRoute53Inventory(client, nil)
	inventory := NewInventory([]MetadataRefresher{refresher})
	discoveryError = errors.New("access denied")
	inventory.refresh(t.Context())
	require.Empty(t, inventory.snapshot.ServiceByIP)
	discoveryError = nil
	inventory.refresh(t.Context())
	require.Equal(t, "zone-a.example", inventory.snapshot.ServiceByIP["8.8.8.8"])
	zones = []types.HostedZone{{Id: aws.String("zone-b"), Config: &types.HostedZoneConfig{}}}
	inventory.refresh(t.Context())
	require.Equal(t, "zone-b.example", inventory.snapshot.ServiceByIP["8.8.8.8"])
	discoveryError = &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"}
	inventory.refresh(t.Context())
	require.Equal(t, 2*refresher.RefreshInterval, refresher.backoff)
	require.Equal(t, "zone-b.example", inventory.snapshot.ServiceByIP["8.8.8.8"])
	discoveryError = nil
	zones = nil
	inventory.refresh(t.Context())
	require.Empty(t, inventory.snapshot.ServiceByIP)
	require.Zero(t, refresher.backoff)
}

func TestRoute53DiscoveryNetworkScope(t *testing.T) {
	for _, tc := range []struct {
		name, vpcID, region string
		wantPrivate         bool
		configured          []string
	}{
		{name: "local VPC", vpcID: "vpc-local", region: "us-east-1", wantPrivate: true},
		{name: "explicit local VPC", vpcID: "vpc-local", region: "us-east-1", wantPrivate: true, configured: []string{"/hostedzone/public", "private", "/hostedzone/private-other", "unrelated", "unknown"}},
		{name: "explicit unknown VPC", region: "us-east-1", configured: []string{"public", "private", "unrelated"}},
		{name: "unknown VPC", region: "us-east-1"},
		{name: "unknown region", vpcID: "vpc-local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var recordZones []string
			privatePages := 0
			client := fakeRoute53Client{
				zones: func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
					return &route53.ListHostedZonesOutput{HostedZones: []types.HostedZone{
						{Id: aws.String("public"), Config: &types.HostedZoneConfig{}},
						{Id: aws.String("unrelated"), Config: &types.HostedZoneConfig{PrivateZone: true}},
						{Id: aws.String("unknown")},
					}}, nil
				},
				privateZones: func(in *route53.ListHostedZonesByVPCInput) (*route53.ListHostedZonesByVPCOutput, error) {
					require.True(t, tc.wantPrivate)
					require.Equal(t, "vpc-local", aws.ToString(in.VPCId))
					require.Equal(t, types.VPCRegionUsEast1, in.VPCRegion)
					privatePages++
					if privatePages == 1 {
						require.Nil(t, in.NextToken)
						return &route53.ListHostedZonesByVPCOutput{
							HostedZoneSummaries: []types.HostedZoneSummary{{HostedZoneId: aws.String("private")}},
							NextToken:           aws.String("next"),
						}, nil
					}
					require.Equal(t, "next", aws.ToString(in.NextToken))
					return &route53.ListHostedZonesByVPCOutput{HostedZoneSummaries: []types.HostedZoneSummary{{HostedZoneId: aws.String("private-other")}}}, nil
				},
				list: func(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
					zone := aws.ToString(in.HostedZoneId)
					recordZones = append(recordZones, zone)
					switch zone {
					case "public":
						return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{
							route53Record("a.public.", "8.8.8.8", types.RRTypeA),
							route53Record("a.public-v6.", "2606:4700:4700::1111", types.RRTypeAaaa),
							route53Record("a.private.", "10.0.0.2", types.RRTypeA),
							route53Record("a.private-v6.", "fd00::2", types.RRTypeAaaa),
							route53Record("a.shared.", "100.64.0.2", types.RRTypeA),
							route53Record("a.mapped.", "::ffff:10.0.0.2", types.RRTypeAaaa),
							route53Record("a.loopback.", "127.0.0.1", types.RRTypeA),
							route53Record("a.link-local.", "169.254.169.254", types.RRTypeA),
						}}, nil
					case "private", "private-other":
						return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{
							route53Record("z."+zone+".", "8.8.8.8", types.RRTypeA),
							route53Record("z."+zone+".", "10.0.0.2", types.RRTypeA),
						}}, nil
					default:
						t.Fatalf("unexpected zone %q", zone)
						return nil, nil
					}
				},
			}
			refresher := NewRoute53Inventory(client, tc.configured)
			refresher.VPCID, refresher.VPCRegion = tc.vpcID, tc.region
			snapshot := &MetadataSnapshot{ServiceByIP: map[string]string{}}
			require.NoError(t, refresher.Refresh(t.Context(), snapshot))
			want := map[string]string{"8.8.8.8": "a.public", "2606:4700:4700::1111": "a.public-v6"}
			if tc.wantPrivate {
				want["8.8.8.8"], want["10.0.0.2"] = "z.private", "z.private"
				require.Equal(t, []string{"public", "private", "private-other"}, recordZones)
				require.Equal(t, 2, privatePages)
			} else {
				require.Equal(t, []string{"public"}, recordZones)
				require.Zero(t, privatePages)
			}
			require.Equal(t, want, snapshot.ServiceByIP)
		})
	}
}

func TestRoute53PrivateDiscoveryFailureRetainsSnapshot(t *testing.T) {
	var apiError error
	client := fakeRoute53Client{
		zones: func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
			return &route53.ListHostedZonesOutput{}, nil
		},
		privateZones: func(in *route53.ListHostedZonesByVPCInput) (*route53.ListHostedZonesByVPCOutput, error) {
			if in.NextToken != nil {
				return nil, apiError
			}
			out := &route53.ListHostedZonesByVPCOutput{HostedZoneSummaries: []types.HostedZoneSummary{{HostedZoneId: aws.String("private")}}}
			if apiError != nil {
				out.NextToken = aws.String("next")
			}
			return out, nil
		},
		list: func(*route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{route53Record("local.example.", "10.0.0.2", types.RRTypeA)}}, nil
		},
	}
	refresher := NewRoute53Inventory(client, nil)
	refresher.VPCID, refresher.VPCRegion = "vpc-local", "us-east-1"
	inventory := NewInventory([]MetadataRefresher{refresher})
	inventory.refresh(t.Context())
	require.Equal(t, "local.example", inventory.snapshot.ServiceByIP["10.0.0.2"])
	for _, err := range []error{&smithy.GenericAPIError{Code: "AccessDenied"}, &smithy.GenericAPIError{Code: "Throttling"}} {
		apiError = err
		inventory.refresh(t.Context())
		require.Equal(t, "local.example", inventory.snapshot.ServiceByIP["10.0.0.2"])
	}
	require.Equal(t, 2*refresher.RefreshInterval, refresher.backoff)
	apiError = nil
	inventory.refresh(t.Context())
	require.Zero(t, refresher.backoff)
}

func TestRoute53InitialAccessDeniedStopsPolling(t *testing.T) {
	for _, tc := range []struct {
		name        string
		operation   string
		zones       []string
		wantDenials int
	}{
		{name: "public zones", operation: "public zones", wantDenials: 1},
		{name: "private zones", operation: "private zones", wantDenials: 1},
		{name: "records", operation: "records", wantDenials: 2},
		{name: "explicit records", operation: "records", zones: []string{"private"}, wantDenials: 1},
	} {
		for _, code := range []string{"AccessDenied", "AccessDeniedException"} {
			t.Run(tc.name+"/"+code, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var apiError error = &smithy.GenericAPIError{Code: code}
					denials := 0
					deny := func(at string) error {
						if at == tc.operation && apiError != nil {
							denials++
							return apiError
						}
						return nil
					}
					client := fakeRoute53Client{
						zones: func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
							if err := deny("public zones"); err != nil {
								return nil, err
							}
							return &route53.ListHostedZonesOutput{}, nil
						},
						privateZones: func(*route53.ListHostedZonesByVPCInput) (*route53.ListHostedZonesByVPCOutput, error) {
							if err := deny("private zones"); err != nil {
								return nil, err
							}
							return &route53.ListHostedZonesByVPCOutput{HostedZoneSummaries: []types.HostedZoneSummary{{HostedZoneId: aws.String("private")}, {HostedZoneId: aws.String("other-private")}}}, nil
						},
						list: func(*route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
							if err := deny("records"); err != nil {
								return nil, err
							}
							return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{route53Record("service.example.", "10.0.0.2", types.RRTypeA)}}, nil
						},
					}
					refresher := NewRoute53Inventory(client, tc.zones)
					refresher.RefreshInterval = time.Second
					refresher.VPCID, refresher.VPCRegion = "vpc-local", "us-east-1"
					inventory := NewInventory([]MetadataRefresher{refresher})
					var logs bytes.Buffer
					inventory.log = slog.New(slog.NewTextHandler(&logs, nil))
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					run, err := InventoryRefresherNode(inventory, time.Second)(ctx)
					require.NoError(t, err)
					done := make(chan struct{})
					go func() { defer close(done); run(ctx) }()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Fatal("unavailable source kept polling")
					}
					require.Equal(t, tc.wantDenials, denials)
					require.Equal(t, 1, strings.Count(logs.String(), "level=WARN"))
					require.Contains(t, logs.String(), "route53:ListResourceRecordSets")
					require.Contains(t, logs.String(), "restart OBI")
					require.Contains(t, logs.String(), "route53:ListHostedZonesByVPC")
					apiError = nil
					inventory.refresh(t.Context())
					require.Empty(t, inventory.snapshot.ServiceByIP)
					require.Equal(t, 1, strings.Count(logs.String(), "level=WARN"))
					restarted := NewInventory([]MetadataRefresher{refresher})
					restarted.refresh(t.Context())
					require.Equal(t, "service.example", restarted.snapshot.ServiceByIP["10.0.0.2"])
				})
			})
		}
	}
}

func TestRoute53MixedAccessVPC(t *testing.T) {
	for _, tc := range []struct {
		name          string
		denyLaterPage bool
		readableEmpty bool
		readableFirst bool
	}{
		{name: "denied zones before readable zone"},
		{name: "denied zones after readable zone", readableFirst: true},
		{name: "denied after a partial page", denyLaterPage: true},
		{name: "readable zone has no records", readableEmpty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied := true
			name := "local.example."
			client := fakeRoute53Client{
				zones: func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
					return &route53.ListHostedZonesOutput{}, nil
				},
				privateZones: func(in *route53.ListHostedZonesByVPCInput) (*route53.ListHostedZonesByVPCOutput, error) {
					require.Equal(t, "vpc-local", aws.ToString(in.VPCId))
					zones := []types.HostedZoneSummary{
						{HostedZoneId: aws.String("service-owned"), Owner: &types.HostedZoneOwner{OwningService: aws.String("efs.amazonaws.com")}},
						{HostedZoneId: aws.String("cross-account"), Owner: &types.HostedZoneOwner{OwningAccount: aws.String("other-account")}},
					}
					local := types.HostedZoneSummary{HostedZoneId: aws.String("readable")}
					if tc.readableFirst {
						zones = append([]types.HostedZoneSummary{local}, zones...)
					} else {
						zones = append(zones, local)
					}
					return &route53.ListHostedZonesByVPCOutput{HostedZoneSummaries: zones}, nil
				},
				list: func(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
					zone := aws.ToString(in.HostedZoneId)
					if zone == "readable" {
						out := &route53.ListResourceRecordSetsOutput{}
						if !tc.readableEmpty {
							out.ResourceRecordSets = []types.ResourceRecordSet{route53Record(name, "10.0.0.2", types.RRTypeA)}
						}
						return out, nil
					}
					if denied {
						if tc.denyLaterPage && in.StartRecordName == nil {
							return &route53.ListResourceRecordSetsOutput{
								IsTruncated: true, NextRecordName: aws.String("next.example."), NextRecordType: types.RRTypeA,
								ResourceRecordSets: []types.ResourceRecordSet{
									route53Record("a.partial.example.", "10.0.0.2", types.RRTypeA),
									route53Record("partial.example.", "10.0.0.9", types.RRTypeA),
								},
							}, nil
						}
						return nil, &smithy.GenericAPIError{Code: "AccessDenied"}
					}
					return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{
						route53Record(zone+".example.", "10.0.0.3", types.RRTypeA),
					}}, nil
				},
			}
			refresher := NewRoute53Inventory(client, nil)
			refresher.VPCID, refresher.VPCRegion = "vpc-local", "us-east-1"
			inventory := NewInventory([]MetadataRefresher{refresher})
			inventory.refresh(t.Context())
			want := map[string]string{}
			if !tc.readableEmpty {
				want["10.0.0.2"] = "local.example"
			}
			require.Equal(t, want, inventory.snapshot.ServiceByIP)
			name = "updated.example."
			inventory.refresh(t.Context())
			if !tc.readableEmpty {
				want["10.0.0.2"] = "updated.example"
			}
			require.Equal(t, want, inventory.snapshot.ServiceByIP)
			denied = false
			inventory.refresh(t.Context())
			want["10.0.0.3"] = "cross-account.example"
			require.Equal(t, want, inventory.snapshot.ServiceByIP)
			denied = true
			inventory.refresh(t.Context())
			delete(want, "10.0.0.3")
			require.Equal(t, want, inventory.snapshot.ServiceByIP)
		})
	}
}

func TestRoute53ExplicitZoneAllowlist(t *testing.T) {
	client := fakeRoute53Client{
		zones: func(*route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
			return &route53.ListHostedZonesOutput{HostedZones: []types.HostedZone{
				{Id: aws.String("/hostedzone/selected"), Config: &types.HostedZoneConfig{}},
				{Id: aws.String("/hostedzone/unselected"), Config: &types.HostedZoneConfig{}},
			}}, nil
		},
		list: func(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
			require.Equal(t, "/hostedzone/selected", aws.ToString(in.HostedZoneId))
			return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{
				route53Record("public.example.", "8.8.8.8", types.RRTypeA),
				route53Record("private.example.", "10.0.0.2", types.RRTypeA),
				route53Record("shared.example.", "100.64.0.2", types.RRTypeA),
			}}, nil
		},
	}
	refresher := NewRoute53Inventory(client, []string{"selected"})
	snapshot := &MetadataSnapshot{ServiceByIP: map[string]string{}}
	require.NoError(t, refresher.Refresh(t.Context(), snapshot))
	require.Equal(t, map[string]string{"8.8.8.8": "public.example"}, snapshot.ServiceByIP)
}

func TestRoute53PublicAddress(t *testing.T) {
	for _, ip := range []string{
		"0.0.0.1", "10.0.0.2", "100.64.0.0", "100.64.0.2", "100.127.255.255",
		"127.0.0.1", "169.254.1.1",
		"172.16.0.1", "192.168.0.1", "192.0.0.1", "192.0.0.8", "192.0.0.11",
		"192.0.2.1", "192.88.99.1", "192.88.99.2", "198.18.0.1", "198.19.255.255",
		"198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255", "224.0.0.1",
		"::", "::1", "fc00::1", "fe80::1", "ff02::1", "64:ff9b:1::1",
		"100::1", "100:0:0:1::1", "2001:1::4", "2001:2::1", "2001:10::1",
		"2001:db8::1", "3fff::1", "5f00::1",
	} {
		t.Run("excluded/"+ip, func(t *testing.T) {
			addr := netip.MustParseAddr(ip)
			require.False(t, route53PublicAddress(addr))
			kind := types.RRTypeAaaa
			if addr.Is4() {
				kind = types.RRTypeA
			}
			record := route53Record("service.example.", ip, kind)
			publicNames := map[string]string{}
			addRoute53Record(publicNames, record, true)
			require.Empty(t, publicNames)

			privateNames := map[string]string{}
			addRoute53Record(privateNames, record, false)
			require.Equal(t, "service.example", privateNames[ip])
		})
	}
	for _, ip := range []string{
		"8.8.8.8", "100.63.255.255", "100.128.0.0", "192.0.0.9", "192.0.0.10",
		"192.31.196.1", "192.52.193.1", "192.175.48.1", "198.17.255.255", "198.20.0.0",
		"2606:4700:4700::1111", "64:ff9b::808:808", "2001::1", "2001:1::1",
		"2001:1::2", "2001:1::3", "2001:3::1", "2001:4:112::1", "2001:20::1",
		"2001:30::1", "2001:4860:4860::8888", "2620:4f:8000::1",
	} {
		t.Run("allowed/"+ip, func(t *testing.T) {
			addr := netip.MustParseAddr(ip)
			require.True(t, route53PublicAddress(addr))
			kind := types.RRTypeAaaa
			if addr.Is4() {
				kind = types.RRTypeA
			}
			for _, public := range []bool{true, false} {
				names := map[string]string{}
				addRoute53Record(names, route53Record("service.example.", ip, kind), public)
				require.Equal(t, map[string]string{ip: "service.example"}, names)
			}
		})
	}
}
