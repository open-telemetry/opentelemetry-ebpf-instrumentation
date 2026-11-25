// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/internal/config/nodejs"

import (
	"fmt"
	"strings"
)

// ValidateFunctionReference validates the selector for a discovered
// CommonJS export. The runtime applies the glob to the full
// filename:exports.path symbol.
func ValidateFunctionReference(reference string) error {
	if strings.TrimSpace(reference) == "" || strings.ContainsAny(reference, "\r\n") {
		return fmt.Errorf("invalid node.js function reference %q", reference)
	}
	return nil
}
