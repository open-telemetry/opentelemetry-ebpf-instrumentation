// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package meta // import "go.opentelemetry.io/obi/pkg/appolly/meta"

import (
	"context"
)

// permits compilation in non-linux environments
func linuxLocalFetcher(ctx context.Context) (NodeStore, error) {
	return NodeStore{}, nil
}
