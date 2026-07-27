// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseServices(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    map[int]string
		wantErr string
	}{
		{
			name: "valid services",
			input: strings.Join([]string{
				"# comment",
				"http 80/tcp www www-http # WorldWideWeb HTTP",
				"domain 53/udp",
				"sctp-only 5000/sctp",
				"",
			}, "\n"),
			want: map[int]string{
				53: "domain",
				80: "http",
			},
		},
		{
			name:    "missing protocol separator",
			input:   "foo 123\n",
			wantErr: "malformed services entry",
		},
		{
			name:    "empty protocol",
			input:   "foo 123/\n",
			wantErr: "malformed services entry",
		},
		{
			name:    "empty response",
			input:   "",
			wantErr: "did not contain any tcp or udp entries",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseServices(strings.NewReader(tc.input))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d services, got %d", len(tc.want), len(got))
			}
			for port, service := range tc.want {
				if got[port] != service {
					t.Fatalf("expected port %d to map to %q, got %q", port, service, got[port])
				}
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestFetchServicesRejectsNonOKStatus(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     "502 Bad Gateway",
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader("bad gateway")),
				Request:    req,
			}, nil
		}),
	}

	_, err := fetchServices(client, "https://example.invalid/services")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected services response status") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchServicesRejectsMalformedOKBody(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     "200 OK",
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("bad 123\n")),
				Request:    req,
			}, nil
		}),
	}

	got, err := fetchServices(client, "https://example.invalid/services")
	if err == nil {
		t.Fatalf("expected error, got mapping %v", got)
	}
	if !strings.Contains(err.Error(), "malformed services entry") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReturnsErrorOnFetchFailure(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Status:     "200 OK",
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("bad 123\n")),
				Request:    req,
			}, nil
		}),
	}

	oldProtocolsFile := *protocolsFile
	*protocolsFile = filepath.Join(t.TempDir(), "protocol.go")
	t.Cleanup(func() {
		*protocolsFile = oldProtocolsFile
	})

	err := run(client, "https://example.invalid/services")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read services file") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(*protocolsFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected no output file to be created, stat err = %v", statErr)
	}
}

func TestRequiresRegenerationUsesConfiguredURL(t *testing.T) {
	t.Parallel()

	oldProtocolsFile := *protocolsFile
	*protocolsFile = filepath.Join(t.TempDir(), "protocol.go")
	t.Cleanup(func() {
		*protocolsFile = oldProtocolsFile
	})

	content := strings.Replace(fileTemplate, "{{ .ServicesURL }}", "https://example.invalid/services", 1)
	content = strings.Replace(content, "{{- range $port, $svc := .Services }}\n\t{{ $port }}: \"{{ $svc }}\",\n{{- end }}", "", 1)
	if err := os.WriteFile(*protocolsFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write protocol file: %v", err)
	}

	if requiresRegeneration("https://example.invalid/services") {
		t.Fatal("expected matching services URL to skip regeneration")
	}
	if !requiresRegeneration("https://example.invalid/other-services") {
		t.Fatal("expected different services URL to require regeneration")
	}
}
