// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPRAndReleaseResults(t *testing.T) {
	const original = "package public; func F(int) {}"
	const broken = "package public; func F(string) {}"
	const addition = original + "; func Added() {}"
	const anonymous = "package public; type Event struct { Pid struct { _ int; ID int } }"
	const named = "package public; type PID struct { _ int; ID int }; type Event struct { Pid PID }"
	for _, tc := range []struct {
		name, releaseAPI, targetAPI, candidateAPI, proposed string
		code                                                int
		prClass, releaseClass                               string
		introduced, existing                                int
	}{
		{name: "unchanged", releaseAPI: original, targetAPI: original, candidateAPI: original, prClass: "patch", releaseClass: "patch"},
		{name: "inherited break", releaseAPI: original, targetAPI: broken, candidateAPI: broken, prClass: "patch", releaseClass: "major", existing: 1},
		{name: "new break", releaseAPI: original, targetAPI: original, candidateAPI: broken, code: exitBreak, prClass: "major", releaseClass: "major", introduced: 1},
		{name: "worsened generic constraint", releaseAPI: "package public; func F[T any](v T) {}", targetAPI: "package public; func F[T ~int | ~string](v T) {}", candidateAPI: "package public; func F[T ~int](v T) {}", code: exitBreak, prClass: "major", releaseClass: "major", introduced: 1},
		{name: "new API", releaseAPI: original, targetAPI: original, candidateAPI: addition, prClass: "minor", releaseClass: "minor", introduced: 1},
		{name: "release rejects inherited break", releaseAPI: original, targetAPI: broken, candidateAPI: broken, proposed: "v1.1.0", code: exitBreak, prClass: "patch", releaseClass: "major", existing: 1},
		{name: "patch rejects new API", releaseAPI: original, targetAPI: original, candidateAPI: addition, proposed: "v1.0.1", code: exitBreak, prClass: "minor", releaseClass: "minor", introduced: 1},
		{name: "new unclassified change", releaseAPI: anonymous, targetAPI: anonymous, candidateAPI: named, code: exitError, prClass: "minor", releaseClass: "incomplete", introduced: 2},
		{name: "inherited unclassified change", releaseAPI: anonymous, targetAPI: named, candidateAPI: named, prClass: "patch", releaseClass: "incomplete", existing: 2},
		{name: "release rejects unclassified change", releaseAPI: anonymous, targetAPI: named, candidateAPI: named, proposed: "v1.1.0", code: exitError, prClass: "patch", releaseClass: "incomplete", existing: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockRelease(t, tc.releaseAPI)
			target := publicAPIFixture(t, tc.targetAPI, "")
			writeFile(t, filepath.Join(target, "versions.yaml"), "module-sets:\n  obi:\n    version: v1.0.0\n")
			for _, args := range [][]string{
				{"init", "--quiet"},
				{"add", "."},
				{"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Establish target"},
			} {
				if _, err := git(t.Context(), target, args...); err != nil {
					t.Fatal(err)
				}
			}
			candidate := filepath.Join(t.TempDir(), "candidate")
			if _, err := git(t.Context(), target, "clone", "--quiet", target, candidate); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(candidate, "pkg/public/api.go"), tc.candidateAPI)
			path := filepath.Join(t.TempDir(), "report.json")
			var output bytes.Buffer
			code := run(t.Context(), []string{"--repo-root", candidate, "--base-dir", target, "--arch", "amd64", "--release-version", tc.proposed, "--report", path}, &output, &output)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var r report
			if err := json.Unmarshal(data, &r); err != nil {
				t.Fatal(err)
			}
			if code != tc.code || r.RequiredRelease != tc.prClass || r.ReleaseRequired != tc.releaseClass || len(r.Findings) != tc.introduced || len(r.ExistingFindings) != tc.existing {
				t.Fatalf("exit=%d, want %d; report=%s\n%s", code, tc.code, data, &output)
			}
			if (r.Error != "") != (tc.code == exitError) {
				t.Fatalf("incomplete status mismatch: %s", data)
			}
			if tc.code == exitError && !strings.Contains(output.String(), "INCOMPLETE") {
				t.Fatalf("incomplete comparison looks successful: %s", &output)
			}
		})
	}
}

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Signature execution is stubbed here; release selection, checksum verification,
// extraction, type loading, comparison, attribution and exit handling are real.
func mockRelease(t *testing.T, source string) {
	t.Helper()
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "cosign"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(bin, "cosign"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"go.mod": "module " + coreModule + "\n\ngo 1.26.0\n", "pkg/public/api.go": source} {
		if err := tw.WriteHeader(&tar.Header{Name: "obi-v1.0.0-source-generated/" + name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := "obi-v1.0.0-source-generated.tar.gz"
	digest := sha256.Sum256(buf.Bytes())
	assets := map[string][]byte{archive: buf.Bytes(), archive + ".bundle.json": []byte("{}"), "SHA256SUMS": fmt.Appendf(nil, "%x  %s\n", digest, archive), "SHA256SUMS.bundle.json": []byte("{}")}
	release := release{Tag: "v1.0.0", Immutable: true}
	for name := range assets {
		release.Assets = append(release.Assets, releaseAsset{Name: name})
	}
	previous := http.DefaultTransport
	http.DefaultTransport = fixtureTransport(func(req *http.Request) (*http.Response, error) {
		var data []byte
		switch {
		case strings.HasSuffix(req.URL.Path, "/releases"):
			data, _ = json.Marshal([]any{release})
		case strings.Contains(req.URL.Path, "/git/ref/tags/"):
			data = []byte(`{"object":{"type":"commit","sha":"` + strings.Repeat("a", 40) + `"}}`)
		case strings.Contains(req.URL.Path, "/releases/download/v1.0.0/"):
			data = assets[filepath.Base(req.URL.Path)]
		default:
			return nil, fmt.Errorf("unexpected fixture request: %s", req.URL)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("missing fixture asset: %s", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
}
