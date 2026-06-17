// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/appolly/meta"

import (
	"context"
	"log/slog"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/traces/hostname"
)

func hostnameFetcher(_ context.Context) (NodeMeta, error) {
	if VendorHostnameAttr == "" {
		return NodeMeta{}, nil
	}
	resolver := hostname.CreateResolver("", "", true)
	fullHostName, _, err := resolver.Query()
	if err != nil {
		slog.Warn("can't resolve hostname for fallback attribute",
			"component", "meta.hostnameFetcher",
			"attribute", VendorHostnameAttr,
			"error", err)
		return NodeMeta{}, nil
	}
	if fullHostName == "" {
		slog.Warn("resolved empty hostname for fallback attribute",
			"component", "meta.hostnameFetcher",
			"attribute", VendorHostnameAttr)
		return NodeMeta{}, nil
	}
	return NodeMeta{
		Metadata: []Entry{
			{
				Key:   attr.Name(VendorHostnameAttr),
				Value: fullHostName,
			},
		},
	}, nil
}
