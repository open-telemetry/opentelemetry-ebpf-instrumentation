// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/obi/internal/test/weavercheck"
)

func TestValidateReport(t *testing.T) {
	tests := []struct {
		name    string
		report  *weavercheck.Report
		wantErr string
	}{
		{
			name:   "valid report",
			report: &weavercheck.Report{Statistics: weavercheck.Statistics{TotalEntities: 1}},
		},
		{
			name:    "no telemetry",
			report:  &weavercheck.Report{},
			wantErr: "weaver received no telemetry",
		},
		{
			name: "violation",
			report: &weavercheck.Report{
				Statistics: weavercheck.Statistics{TotalEntities: 1},
				Findings:   []weavercheck.Finding{{Level: "violation", Count: 1, Message: "bad attribute"}},
			},
			wantErr: "weaver found 1 violation-level",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateReport(test.report)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateReport() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateReport() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestRunArchivesReportWhenTapDrainFails(t *testing.T) {
	dockerDir := t.TempDir()
	dockerStub := filepath.Join(dockerDir, "docker")
	if err := os.WriteFile(dockerStub, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dockerDir)

	var shutdown bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stop":
			w.WriteHeader(http.StatusOK)
		case "/report":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(weavercheck.Report{Statistics: weavercheck.Statistics{TotalEntities: 1}})
		case "/shutdown":
			shutdown = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	artifactDir := t.TempDir()
	err := run(server.URL, artifactDir, "http")
	if err == nil || !strings.Contains(err.Error(), "draining Weaver tap") {
		t.Fatalf("run() error = %v, want Weaver tap drain error", err)
	}
	if !shutdown {
		t.Fatal("Weaver shutdown endpoint was not called after tap drain failed")
	}
	if _, err := os.Stat(filepath.Join(artifactDir, "weaver-report-http.json")); err != nil {
		t.Fatalf("raw Weaver report was not archived after tap drain failed: %v", err)
	}
}
