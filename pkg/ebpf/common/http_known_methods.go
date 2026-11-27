// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	maxExtraHTTPMethods      = 16
	maxExtraHTTPMethodLength = 10
)

type extraHTTPMethod struct {
	Name [maxExtraHTTPMethodLength]byte
	Len  uint8
}

// ExtraHTTPMethodConstants provides the additional methods to BPF programs.
func ExtraHTTPMethodConstants() map[string]any {
	return extraHTTPMethodConstants(request.KnownHTTPMethods())
}

func extraHTTPMethodConstants(knownMethods []string) map[string]any {
	var methods [maxExtraHTTPMethods]extraHTTPMethod
	var count uint32
	for _, method := range knownMethods {
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "QUERY", "CONNECT":
			continue
		}
		if len(method) > maxExtraHTTPMethodLength || !validHTTPMethod(method) || count == maxExtraHTTPMethods {
			slog.Warn("HTTP method cannot be used for BPF detection", "method", method)
			continue
		}
		copy(methods[count].Name[:], method)
		methods[count].Len = uint8(len(method))
		count++
	}
	return map[string]any{"extra_http_methods": methods, "extra_http_method_count": count}
}

func validHTTPMethod(method string) bool {
	if method == "" {
		return false
	}
	for _, c := range method {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}
