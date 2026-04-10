// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build tools

package tools // import "go.opentelemetry.io/obi/internal/tools"

import (
	_ "github.com/cilium/ebpf/cmd/bpf2go"
	_ "github.com/grafana/go-offsets-tracker/cmd/go-offsets-tracker"
	_ "sigs.k8s.io/controller-runtime/tools/setup-envtest"
	_ "sigs.k8s.io/kind"

	_ "go.opentelemetry.io/build-tools/multimod"
)
