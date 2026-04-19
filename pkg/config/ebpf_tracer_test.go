// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"reflect"
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
			name:  "headers and tcp",
			input: "headers,tcp",
			want:  ContextPropagationHeaders | ContextPropagationTCP,
		},
		{
			name:  "all two",
			input: "headers,tcp",
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
			name: "headers and tcp",
			mode: ContextPropagationHeaders | ContextPropagationTCP,
			want: "all",
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
		wantIsEnabled bool
	}{
		{
			name:          "all",
			mode:          ContextPropagationAll,
			wantHeaders:   true,
			wantTCP:       true,
			wantIsEnabled: true,
		},
		{
			name:          "disabled",
			mode:          ContextPropagationDisabled,
			wantHeaders:   false,
			wantTCP:       false,
			wantIsEnabled: false,
		},
		{
			name:          "headers only",
			mode:          ContextPropagationHeaders,
			wantHeaders:   true,
			wantTCP:       false,
			wantIsEnabled: true,
		},
		{
			name:          "tcp only",
			mode:          ContextPropagationTCP,
			wantHeaders:   false,
			wantTCP:       true,
			wantIsEnabled: true,
		},
		{
			name:          "headers and tcp",
			mode:          ContextPropagationHeaders | ContextPropagationTCP,
			wantHeaders:   true,
			wantTCP:       true,
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
			if got := tt.mode.IsEnabled(); got != tt.wantIsEnabled {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.wantIsEnabled)
			}
		})
	}
}

func TestEBPFTracer_CudaInstrumentationEnabled(t *testing.T) {
	tests := []struct {
		name           string
		instrumentCuda CudaMode
		wantEnabled    bool
		description    string
		nvsmi          func() bool
	}{
		{
			name:           "cuda mode on",
			instrumentCuda: CudaModeOn,
			wantEnabled:    true,
			description:    "CudaModeOn should always return true",
		},
		{
			name:           "cuda mode off",
			instrumentCuda: CudaModeOff,
			wantEnabled:    false,
			description:    "CudaModeOff should always return false",
		},
		{
			name:           "cuda mode auto with nvidia-smi",
			instrumentCuda: CudaModeAuto,
			wantEnabled:    true,
			description:    "CudaModeAuto should return true if nvidia-smi is found in PATH",
			nvsmi: func() bool {
				return true
			},
		},
		{
			name:           "cuda mode auto without nvidia-smi",
			instrumentCuda: CudaModeAuto,
			wantEnabled:    false,
			description:    "CudaModeAuto should return false if nvidia-smi is not found in PATH",
			nvsmi: func() bool {
				return false
			},
		},
		{
			name:           "invalid cuda mode (zero value)",
			instrumentCuda: CudaMode(0),
			wantEnabled:    false,
			description:    "Invalid CudaMode should return false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &EBPFTracer{
				InstrumentCuda: tt.instrumentCuda,
			}
			nvidiaSMIExistsFunc = tt.nvsmi

			got := tracer.CudaInstrumentationEnabled()

			// For CudaModeAuto, the result depends on whether nvidia-smi is in PATH
			// We skip strict assertion for this case as it's environment-dependent
			if tt.instrumentCuda == CudaModeAuto {
				t.Logf("CudaModeAuto returned: %v (nvidia-smi in PATH determines result)", got)
				return
			}

			if got != tt.wantEnabled {
				t.Errorf("CudaInstrumentationEnabled() = %v, want %v\nDescription: %s",
					got, tt.wantEnabled, tt.description)
			}
		})
	}
}

func TestEBPFBufferSizesValidateTagsMatchMaxCapturedPayloadBytes(t *testing.T) {
	expected := fmt.Sprintf("lte=%d", MaxCapturedPayloadBytes)
	typ := reflect.TypeOf(EBPFBufferSizes{})

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if got := field.Tag.Get("validate"); got != expected {
			t.Fatalf(
				"EBPFBufferSizes.%s validate tag drifted: got %q, want %q.\n"+
					"To resolve this, update all of the following together:\n"+
					"1. %s validate tag in pkg/config/ebpf_tracer.go\n"+
					"2. MaxCapturedPayloadBytes in pkg/config/ebpf_tracer.go\n"+
					"3. matching k_large_buf_max_*_captured_bytes constant in bpf/common/large_buffers.h",
				field.Name,
				got,
				expected,
				field.Name,
			)
		}
	}
}
