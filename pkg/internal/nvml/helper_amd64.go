// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && obi_nvml_helper

package nvml // import "go.opentelemetry.io/obi/pkg/internal/nvml"

import _ "embed"

//go:embed embedded/obi-nvml-helper-amd64
var embeddedHelper []byte
