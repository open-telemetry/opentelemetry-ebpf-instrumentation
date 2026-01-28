// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build tools

package tools // import "go.opentelemetry.io/obi/internal/tools"

import (
	_ "github.com/cilium/ebpf/cmd/bpf2go"
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "github.com/google/go-licenses/v2"
	_ "github.com/grafana/go-offsets-tracker/cmd/go-offsets-tracker"
	_ "github.com/jcchavezs/porto/cmd/porto"
	_ "github.com/onsi/ginkgo/v2/ginkgo"
	_ "gotest.tools/gotestsum"
	_ "sigs.k8s.io/controller-runtime/tools/setup-envtest"
	_ "sigs.k8s.io/kind"

	_ "go.opentelemetry.io/build-tools/multimod"
)
