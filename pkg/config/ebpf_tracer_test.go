// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
)

func TestContextPropagationMode_UnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ContextPropagationMode
		wantErr bool
	}{
		{
			name:  "all",
			input: "all",
			want:  ContextPropagationAll,
		},
		{
			name:  "disabled",
			input: "disabled",
			want:  ContextPropagationDisabled,
		},
		{
			name:  "headers only",
			input: "headers",
			want:  ContextPropagationHeaders,
		},
		{
			name:  "http alias",
			input: "http",
			want:  ContextPropagationHeaders,
		},
		{
			name:  "tcp only",
			input: "tcp",
			want:  ContextPropagationTCP,
		},
		{
			name:  "ip only",
			input: "ip",
			want:  ContextPropagationIPOptions,
		},
		{
			name:  "headers and tcp",
			input: "headers,tcp",
			want:  ContextPropagationHeaders | ContextPropagationTCP,
		},
		{
			name:  "tcp and ip",
			input: "tcp,ip",
			want:  ContextPropagationTCP | ContextPropagationIPOptions,
		},
		{
			name:  "headers and ip",
			input: "headers,ip",
			want:  ContextPropagationHeaders | ContextPropagationIPOptions,
		},
		{
			name:  "all three",
			input: "headers,tcp,ip",
			want:  ContextPropagationAll,
		},
		{
			name:  "with spaces",
			input: " headers , tcp , ip ",
			want:  ContextPropagationAll,
		},
		{
			name:    "invalid value",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			input:   "headers,invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ContextPropagationMode
			err := got.UnmarshalText([]byte(tt.input))

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("UnmarshalText() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContextPropagationMode_MarshalText(t *testing.T) {
	tests := []struct {
		name    string
		mode    ContextPropagationMode
		want    string
		wantErr bool
	}{
		{
			name: "all",
			mode: ContextPropagationAll,
			want: "all",
		},
		{
			name: "disabled",
			mode: ContextPropagationDisabled,
			want: "disabled",
		},
		{
			name: "headers only",
			mode: ContextPropagationHeaders,
			want: "headers",
		},
		{
			name: "tcp only",
			mode: ContextPropagationTCP,
			want: "tcp",
		},
		{
			name: "ip only",
			mode: ContextPropagationIPOptions,
			want: "ip",
		},
		{
			name: "headers and tcp",
			mode: ContextPropagationHeaders | ContextPropagationTCP,
			want: "headers,tcp",
		},
		{
			name: "tcp and ip",
			mode: ContextPropagationTCP | ContextPropagationIPOptions,
			want: "tcp,ip",
		},
		{
			name: "headers and ip",
			mode: ContextPropagationHeaders | ContextPropagationIPOptions,
			want: "headers,ip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mode.MarshalText()

			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(got) != tt.want {
				t.Errorf("MarshalText() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestContextPropagationMode_HasMethods(t *testing.T) {
	tests := []struct {
		name          string
		mode          ContextPropagationMode
		wantHeaders   bool
		wantTCP       bool
		wantIPOptions bool
		wantIsEnabled bool
	}{
		{
			name:          "all",
			mode:          ContextPropagationAll,
			wantHeaders:   true,
			wantTCP:       true,
			wantIPOptions: true,
			wantIsEnabled: true,
		},
		{
			name:          "disabled",
			mode:          ContextPropagationDisabled,
			wantHeaders:   false,
			wantTCP:       false,
			wantIPOptions: false,
			wantIsEnabled: false,
		},
		{
			name:          "headers only",
			mode:          ContextPropagationHeaders,
			wantHeaders:   true,
			wantTCP:       false,
			wantIPOptions: false,
			wantIsEnabled: true,
		},
		{
			name:          "tcp only",
			mode:          ContextPropagationTCP,
			wantHeaders:   false,
			wantTCP:       true,
			wantIPOptions: false,
			wantIsEnabled: true,
		},
		{
			name:          "ip only",
			mode:          ContextPropagationIPOptions,
			wantHeaders:   false,
			wantTCP:       false,
			wantIPOptions: true,
			wantIsEnabled: true,
		},
		{
			name:          "headers and tcp",
			mode:          ContextPropagationHeaders | ContextPropagationTCP,
			wantHeaders:   true,
			wantTCP:       true,
			wantIPOptions: false,
			wantIsEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.HasHeaders(); got != tt.wantHeaders {
				t.Errorf("HasHeaders() = %v, want %v", got, tt.wantHeaders)
			}
			if got := tt.mode.HasTCP(); got != tt.wantTCP {
				t.Errorf("HasTCP() = %v, want %v", got, tt.wantTCP)
			}
			if got := tt.mode.HasIPOptions(); got != tt.wantIPOptions {
				t.Errorf("HasIPOptions() = %v, want %v", got, tt.wantIPOptions)
			}
			if got := tt.mode.IsEnabled(); got != tt.wantIsEnabled {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.wantIsEnabled)
			}
		})
	}
}

func TestContextPropagationMode_TracerLoading(t *testing.T) {
	// Test which tracers should be loaded for each configuration
	// tpinjector handles: HTTP headers (sk_msg) and TCP options (BPF_SOCK_OPS)
	// tctracer handles: IP options only (TC egress/ingress)
	tests := []struct {
		name         string
		mode         ContextPropagationMode
		wantTPInject bool // should load tpinjector
		wantTCTracer bool // should load tctracer
	}{
		{
			name:         "tcp only",
			mode:         ContextPropagationTCP,
			wantTPInject: true,
			wantTCTracer: false,
		},
		{
			name:         "headers only",
			mode:         ContextPropagationHeaders,
			wantTPInject: true,
			wantTCTracer: false,
		},
		{
			name:         "ip only",
			mode:         ContextPropagationIPOptions,
			wantTPInject: false,
			wantTCTracer: true,
		},
		{
			name:         "headers and tcp",
			mode:         ContextPropagationHeaders | ContextPropagationTCP,
			wantTPInject: true,
			wantTCTracer: false,
		},
		{
			name:         "tcp and ip",
			mode:         ContextPropagationTCP | ContextPropagationIPOptions,
			wantTPInject: true,
			wantTCTracer: true,
		},
		{
			name:         "headers and ip",
			mode:         ContextPropagationHeaders | ContextPropagationIPOptions,
			wantTPInject: true,
			wantTCTracer: true,
		},
		{
			name:         "all",
			mode:         ContextPropagationAll,
			wantTPInject: true,
			wantTCTracer: true,
		},
		{
			name:         "disabled",
			mode:         ContextPropagationDisabled,
			wantTPInject: false,
			wantTCTracer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine what should load based on the logic in finder.go
			shouldLoadTPInject := tt.mode.HasHeaders() || tt.mode.HasTCP()
			shouldLoadTCTracer := tt.mode.HasIPOptions()

			if shouldLoadTPInject != tt.wantTPInject {
				t.Errorf("tpinjector loading = %v, want %v", shouldLoadTPInject, tt.wantTPInject)
			}
			if shouldLoadTCTracer != tt.wantTCTracer {
				t.Errorf("tctracer loading = %v, want %v", shouldLoadTCTracer, tt.wantTCTracer)
			}
		})
	}
}
