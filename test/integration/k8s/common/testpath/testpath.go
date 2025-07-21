// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testpath

import "path"

var (
	Root            = path.Join("..", "..", "..", "..")
	Output          = path.Join(Root, "testoutput")
	KindLogs        = path.Join(Output, "kind")
	IntegrationTest = path.Join(Root, "test", "integration")
	Components      = path.Join(IntegrationTest, "components")
	Manifests       = path.Join(IntegrationTest, "k8s", "manifests")
)
