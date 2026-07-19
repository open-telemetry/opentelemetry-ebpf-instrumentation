// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	grpc_codes "google.golang.org/grpc/codes"
)

func TestGRPCStatusCodeString(t *testing.T) {
	assert.Equal(t, "OK", GRPCStatusCodeString(int(grpc_codes.OK)))
	assert.Equal(t, "INVALID_ARGUMENT", GRPCStatusCodeString(int(grpc_codes.InvalidArgument)))
	assert.Equal(t, "DEADLINE_EXCEEDED", GRPCStatusCodeString(int(grpc_codes.DeadlineExceeded)))
	assert.Equal(t, "UNAUTHENTICATED", GRPCStatusCodeString(int(grpc_codes.Unauthenticated)))
	// values outside the gRPC status enum (0-16) return "" so callers omit
	// the attribute instead of emitting an invalid enum variant
	assert.Empty(t, GRPCStatusCodeString(99))
	assert.Empty(t, GRPCStatusCodeString(200)) // HTTP status leaked through protocol detection
	assert.Empty(t, GRPCStatusCodeString(0xFFFF))
	assert.Empty(t, GRPCStatusCodeString(-1))
}
