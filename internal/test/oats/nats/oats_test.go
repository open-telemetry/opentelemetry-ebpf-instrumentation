// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oats

import (
	"testing"

	"go.opentelemetry.io/obi/internal/test/oats/harness"
)

func TestYaml(t *testing.T) {
	harness.RunSpecs(t)
}

var _ = harness.RegisterSuite()
