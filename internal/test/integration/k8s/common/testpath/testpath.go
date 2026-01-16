// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testpath // import "go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"

import (
	"path"

	"go.opentelemetry.io/obi/internal/test/tools"
)

var (
	Root            = tools.ProjectDir()
	Output          = path.Join(Root, "testoutput")
	KindLogs        = path.Join(Output, "kind")
	IntegrationTest = path.Join(Root, "internal", "test", "integration")
	Components      = path.Join(IntegrationTest, "components")
	Manifests       = path.Join(IntegrationTest, "k8s", "manifests")
)
