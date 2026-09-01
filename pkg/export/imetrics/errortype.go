// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics // import "go.opentelemetry.io/obi/pkg/export/imetrics"

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/obi/pkg/internal/errtype"
)

// ExportErrorType classifies an export failure into a low-cardinality error.type value.
// The error message is unsuitable as an attribute: it embeds endpoints and deadlines, so
// it mints a new series per distinct failure.
func ExportErrorType(err error) string {
	if err == nil {
		return errtype.Other
	}

	if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
		if code := errtype.GRPCCode(int(st.Code())); code != "" {
			return code
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return errtype.GRPCCode(int(codes.DeadlineExceeded))
	}
	if errors.Is(err, context.Canceled) {
		return errtype.GRPCCode(int(codes.Canceled))
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errtype.GRPCCode(int(codes.DeadlineExceeded))
	}

	return fmt.Sprintf("%T", unwrapCombinators(err))
}

// unwrapCombinators strips the wrappers fmt.Errorf and errors.Join add. Their types name
// the combinator rather than the failure, so the OTLP exporters — which wrap every send
// error at least once — would otherwise report a single type for every possible cause.
func unwrapCombinators(err error) error {
	for {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			errs := joined.Unwrap()
			if len(errs) == 0 || errs[0] == nil {
				return err
			}
			err = errs[0]
			continue
		}

		if fmt.Sprintf("%T", err) != "*fmt.wrapError" {
			return err
		}

		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}
