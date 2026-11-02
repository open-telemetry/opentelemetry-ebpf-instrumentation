// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon_test

import (
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
)

var _ func(*request.Span, *http.Request, *http.Response, []string) (request.Span, bool) = ebpfhttp.SQLPPSpan
