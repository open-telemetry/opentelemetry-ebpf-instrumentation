// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics // import "go.opentelemetry.io/obi/pkg/export/imetrics"

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorTypeOther is the semantic-convention value for an error whose type cannot be determined.
const errorTypeOther = "_OTHER"

// ExportErrorType classifies an export failure into a low-cardinality error.type value. The
// error message is unsuitable as an attribute: it embeds endpoints and deadlines, so it mints a
// new series per distinct failure. The gRPC status code is preferred because it is the useful
// dimension for an OTLP export, falling back to the concrete Go type.
func ExportErrorType(err error) string {
	if err == nil {
		return errorTypeOther
	}

	if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
		return st.Code().String()
	}

	return fmt.Sprintf("%T", err)
}
