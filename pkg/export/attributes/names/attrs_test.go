// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The expectations are the Prometheus labels the internal exporter emitted before these
// attributes were declared here, so this pins the derivation against silent renames.
func TestInternalAttributePrometheusLabels(t *testing.T) {
	internal := NewInternalAttributes("obi")

	for _, test := range []struct {
		attribute Name
		otel      string
		prom      string
	}{
		{internal.Goarch, "obi.goarch", "obi_goarch"},
		{internal.Goos, "obi.goos", "obi_goos"},
		{internal.Goversion, "obi.goversion", "obi_goversion"},
		{internal.Version, "obi.version", "obi_version"},
		{internal.Revision, "obi.revision", "obi_revision"},
	} {
		t.Run(test.otel, func(t *testing.T) {
			assert.Equal(t, test.otel, string(test.attribute))
			assert.Equal(t, test.prom, test.attribute.Prom())
		})
	}
}

// A component that vendors OBI can override VendorPrefix, so the attributes must be built from
// the prefix rather than baked in.
func TestInternalAttributesHonourVendorPrefix(t *testing.T) {
	vendored := NewInternalAttributes("beyla")

	assert.Equal(t, "beyla.version", string(vendored.Version))
	assert.Equal(t, "beyla_goversion", vendored.Goversion.Prom())
}
