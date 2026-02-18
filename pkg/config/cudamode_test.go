// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"testing"
)

func TestCudaMode_UnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    CudaMode
		wantErr bool
	}{
		{
			name:  "on",
			input: "on",
			want:  CudaModeOn,
		},
		{
			name:  "off",
			input: "off",
			want:  CudaModeOff,
		},
		{
			name:  "auto",
			input: "auto",
			want:  CudaModeAuto,
		},
		{
			name:  "on with spaces",
			input: "  on  ",
			want:  CudaModeOn,
		},
		{
			name:  "off with spaces",
			input: " off ",
			want:  CudaModeOff,
		},
		{
			name:  "auto with spaces",
			input: "	auto	",
			want:  CudaModeAuto,
		},
		{
			name:    "invalid value",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "uppercase",
			input:   "ON",
			wantErr: true,
		},
		{
			name:    "mixed case",
			input:   "Auto",
			wantErr: true,
		},
		{
			name:    "numeric",
			input:   "1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got CudaMode
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

func TestCudaMode_MarshalText(t *testing.T) {
	tests := []struct {
		name    string
		mode    CudaMode
		want    string
		wantErr bool
	}{
		{
			name: "on",
			mode: CudaModeOn,
			want: "on",
		},
		{
			name: "off",
			mode: CudaModeOff,
			want: "off",
		},
		{
			name: "auto",
			mode: CudaModeAuto,
			want: "auto",
		},
		{
			name:    "invalid mode (zero value)",
			mode:    CudaMode(0),
			wantErr: true,
		},
		{
			name:    "invalid mode (out of range)",
			mode:    CudaMode(99),
			wantErr: true,
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

func TestCudaMode_Valid(t *testing.T) {
	tests := []struct {
		name string
		mode CudaMode
		want bool
	}{
		{
			name: "on is valid",
			mode: CudaModeOn,
			want: true,
		},
		{
			name: "off is valid",
			mode: CudaModeOff,
			want: true,
		},
		{
			name: "auto is valid",
			mode: CudaModeAuto,
			want: true,
		},
		{
			name: "zero value is invalid",
			mode: CudaMode(0),
			want: false,
		},
		{
			name: "out of range value is invalid",
			mode: CudaMode(99),
			want: false,
		},
		{
			name: "negative value is invalid",
			mode: CudaMode(255), // wraps around in uint8
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mode.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCudaMode_RoundTrip(t *testing.T) {
	// Test that marshaling and unmarshaling are inverses
	modes := []CudaMode{CudaModeOn, CudaModeOff, CudaModeAuto}

	for _, mode := range modes {
		t.Run(fmt.Sprintf("mode_%d", mode), func(t *testing.T) {
			// Marshal
			bytes, err := mode.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() failed: %v", err)
			}

			// Unmarshal
			var got CudaMode
			err = got.UnmarshalText(bytes)
			if err != nil {
				t.Fatalf("UnmarshalText() failed: %v", err)
			}

			// Verify round trip
			if got != mode {
				t.Errorf("Round trip failed: got %v, want %v", got, mode)
			}
		})
	}
}

func TestCudaMode_Constants(t *testing.T) {
	// Verify constant values are as expected
	if CudaModeAuto != 1 {
		t.Errorf("CudaModeAuto = %v, want 1", CudaModeAuto)
	}
	if CudaModeOn != 2 {
		t.Errorf("CudaModeOn = %v, want 2", CudaModeOn)
	}
	if CudaModeOff != 3 {
		t.Errorf("CudaModeOff = %v, want 3", CudaModeOff)
	}

	// Verify all constants are valid
	if !CudaModeAuto.Valid() {
		t.Error("CudaModeAuto should be valid")
	}
	if !CudaModeOn.Valid() {
		t.Error("CudaModeOn should be valid")
	}
	if !CudaModeOff.Valid() {
		t.Error("CudaModeOff should be valid")
	}
}
