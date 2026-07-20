// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"

import (
	"strings"
	"unicode/utf8"
)

func ValidUTF8String(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

func ValidTopicName(s string) bool {
	return s != "" && ValidUTF8String(s) && !strings.ContainsAny(s, "+#")
}

func ValidTopicFilter(s string) bool {
	return s != "" && ValidUTF8String(s)
}
