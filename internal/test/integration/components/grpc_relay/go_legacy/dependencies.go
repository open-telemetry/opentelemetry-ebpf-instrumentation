// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build legacy_grpc

package main

import (
	_ "google.golang.org/grpc"
	_ "google.golang.org/protobuf/types/known/emptypb"
)
