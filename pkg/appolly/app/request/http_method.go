// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"os"
	"strings"
	"sync"
)

// HTTPMethodOther is the semconv http.request.method value for a method outside
// the enum.
const HTTPMethodOther = "_OTHER"

// Semconv mandates this variable name for overriding the enum: a comma-separated
// list replacing the defaults below.
const envKnownMethods = "OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS"

// Method names are case-sensitive, so this set is matched exactly.
var defaultKnownHTTPMethods = map[string]struct{}{
	"CONNECT": {},
	"DELETE":  {},
	"GET":     {},
	"HEAD":    {},
	"OPTIONS": {},
	"PATCH":   {},
	"POST":    {},
	"PUT":     {},
	"QUERY":   {},
	"TRACE":   {},
}

// parseKnownHTTPMethods reads the override list, falling back to the semconv
// defaults when it is unset or contains no usable entry.
func parseKnownHTTPMethods(env string) map[string]struct{} {
	if strings.TrimSpace(env) == "" {
		return defaultKnownHTTPMethods
	}

	methods := map[string]struct{}{}
	for _, m := range strings.Split(env, ",") {
		if m = strings.TrimSpace(m); m != "" {
			methods[m] = struct{}{}
		}
	}

	if len(methods) == 0 {
		return defaultKnownHTTPMethods
	}

	return methods
}

var knownHTTPMethods = sync.OnceValue(func() map[string]struct{} {
	return parseKnownHTTPMethods(os.Getenv(envKnownMethods))
})

// IsKnownHTTPMethod reports whether method is a member of the semconv
// http.request.method enum, honoring the override. Both the trace and metric
// pipelines clamp through this so they cannot disagree on the same attribute key.
func IsKnownHTTPMethod(method string) bool {
	_, ok := knownHTTPMethods()[method]
	return ok
}
