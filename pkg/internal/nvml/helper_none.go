// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (!obi_nvml_helper || !(amd64 || arm64))

package nvml // import "go.opentelemetry.io/obi/pkg/internal/nvml"

// Builds without the obi_nvml_helper tag, such as go test, do not embed the helper.
var embeddedHelper []byte
