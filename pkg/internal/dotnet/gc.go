// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

func gcGeneration(name string) (int, bool) {
	switch name {
	case "gen-0-gc-count":
		return 0, true
	case "gen-1-gc-count":
		return 1, true
	case "gen-2-gc-count":
		return 2, true
	default:
		return 0, false
	}
}
