//go:build !linux

package meta

import (
	"context"
)

// permits compilation in non-linux environments
func linuxLocalFetcher(ctx context.Context) (NodeStore, error) {
	return NodeStore{}, nil
}
