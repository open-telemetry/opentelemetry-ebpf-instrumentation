// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testutil // import "go.opentelemetry.io/obi/pkg/internal/testutil"

import (
	"context"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

// PeerMetadataSnapshot fetches the snapshot that a peer metadata agent serves without TLS on a loopback port.
func PeerMetadataSnapshot(ctx context.Context, port int) (*metadatapb.Snapshot, error) {
	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	return metadatapb.NewPeerMetadataServiceClient(conn).GetSnapshot(ctx, &metadatapb.GetSnapshotRequest{})
}
