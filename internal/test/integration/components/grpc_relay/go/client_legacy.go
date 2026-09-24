// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build legacy_grpc

package main

import "google.golang.org/grpc"

func newGRPCClient(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.Dial(target, opts...)
}
