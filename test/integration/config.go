// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/test/tools"
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)
