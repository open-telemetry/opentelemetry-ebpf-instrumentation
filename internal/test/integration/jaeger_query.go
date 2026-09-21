// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

func getJaeger(queryURL string) (*http.Response, error) {
	return jaeger.Get(queryURL)
}
