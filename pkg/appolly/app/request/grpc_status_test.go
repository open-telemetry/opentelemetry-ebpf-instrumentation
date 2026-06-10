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
	assert.Equal(t, "CODE(99)", GRPCStatusCodeString(99))
}
