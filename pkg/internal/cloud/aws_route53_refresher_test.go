// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/assert"
)

type fakeRoute53Client struct {
	list func(*route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error)
}

func (f fakeRoute53Client) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return f.list(in)
}

func route53Record(name, ip string, kind types.RRType) types.ResourceRecordSet {
	return types.ResourceRecordSet{Name: aws.String(name), Type: kind, ResourceRecords: []types.ResourceRecord{{Value: aws.String(ip)}}}
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
	inventory := NewInventory([]MetadataRefresher{NewRoute53Inventory(client, []string{"zone-a", "zone-b"})})
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
			return nil, errors.New("access denied")
		}
		out := &route53.ListResourceRecordSetsOutput{}
		if !empty {
			out.ResourceRecordSets = []types.ResourceRecordSet{route53Record("service.example.", "10.0.0.1", types.RRTypeA)}
		}
		return out, nil
	}}
	inventory := NewInventory([]MetadataRefresher{NewRoute53Inventory(client, []string{"zone-a", "zone-b"})})
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
