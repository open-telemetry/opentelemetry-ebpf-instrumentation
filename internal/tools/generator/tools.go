// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build tools

package tools // import "go.opentelemetry.io/obi/internal/tools/generator"

import (
	_ "github.com/cilium/ebpf/cmd/bpf2go"
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)
