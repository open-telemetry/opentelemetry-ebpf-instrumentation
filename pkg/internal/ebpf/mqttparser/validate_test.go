// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser

import "testing"

func TestValidUTF8String(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"ascii", "hello", true},
		{"unicode", "sensörs/温度", true},
		{"invalid utf8", "\xff", false},
		{"truncated utf8", "\xc3", false},
		{"embedded null", "a\x00b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidUTF8String(tt.in); got != tt.want {
				t.Errorf("ValidUTF8String(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidTopicName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"simple", "sensors/temp", true},
		{"single level", "temp", true},
		{"empty", "", false},
		{"invalid utf8", "\xff", false},
		{"null byte", "a\x00b", false},
		{"multi-level wildcard", "sensors/#", false},
		{"single-level wildcard", "sensors/+/temp", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidTopicName(tt.in); got != tt.want {
				t.Errorf("ValidTopicName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidTopicFilter(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"wildcards allowed", "sensors/#", true},
		{"single-level wildcard", "sensors/+/temp", true},
		{"plain", "sensors/temp", true},
		{"empty", "", false},
		{"invalid utf8", "\xff", false},
		{"null byte", "a\x00b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidTopicFilter(tt.in); got != tt.want {
				t.Errorf("ValidTopicFilter(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
