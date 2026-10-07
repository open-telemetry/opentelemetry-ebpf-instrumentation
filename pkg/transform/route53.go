// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"

	"go.opentelemetry.io/obi/pkg/internal/cloud"
	"go.opentelemetry.io/obi/pkg/metadata"
)

// route53DefaultRegion is used only when neither the configuration, the cloud
// metadata, nor the AWS SDK environment provide a region.
const route53DefaultRegion = "us-east-1"

// Route53MetadataConfig maps A/AAAA records to fully qualified names.
// Aliases, CNAMEs, and wildcard records are excluded. ECS names take precedence.
type Route53MetadataConfig struct {
	// RefreshInterval controls Route53 polling independently of other cloud sources.
	RefreshInterval time.Duration `yaml:"-" env:"-" validate:"gt=0"`
	// HostedZoneIDs restricts discovery to these hosted zones. Required when route53 is enabled.
	HostedZoneIDs []string `yaml:"-" env:"-"`
}

func route53InventoryRefresher(
	ctx context.Context,
	nodeMeta *metadata.NodeMeta,
	cloudCfg CloudMetadataConfig,
) (cloud.MetadataRefresher, error) {
	if cloudCfg.Route53.RefreshInterval <= 0 {
		return nil, errors.New("initializing Route53 name resolver: a positive refresh interval is required")
	}
	if len(cloudCfg.Route53.HostedZoneIDs) == 0 {
		return nil, errors.New("initializing Route53 name resolver: hosted_zone_ids is required")
	}
	for _, id := range cloudCfg.Route53.HostedZoneIDs {
		if strings.TrimSpace(strings.TrimPrefix(id, "/hostedzone/")) == "" {
			return nil, errors.New("initializing Route53 name resolver: hosted zone IDs must not be empty")
		}
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, route53RegionOption(nodeMeta, cloudCfg))
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration for Route53 name resolver: %w", err)
	}
	inventory := cloud.NewRoute53Inventory(route53.NewFromConfig(awsCfg), cloudCfg.Route53.HostedZoneIDs)
	inventory.RefreshInterval = cloudCfg.Route53.RefreshInterval
	return inventory, nil
}

// route53RegionOption selects the region, and therefore the AWS partition, of the Route53 client.
func route53RegionOption(nodeMeta *metadata.NodeMeta, cloudCfg CloudMetadataConfig) func(*awsconfig.LoadOptions) error {
	region := cloudCfg.Region
	if region == "" {
		region = nodeMeta.Region
	}
	if region == "" {
		return awsconfig.WithDefaultRegion(route53DefaultRegion)
	}
	return awsconfig.WithRegion(region)
}
