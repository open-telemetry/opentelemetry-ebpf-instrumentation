// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplicableRelease(t *testing.T) {
	for _, tc := range []struct {
		tag    string
		target string
		want   bool
	}{
		{"v1.0.0", "v1.0.0", true},
		{"v1.0.4", "v1.0.0", true},
		{"v1.1.0", "v1.0.5", false},
		{"v1.1.0", "v1.1.0-rc.1", true},
		{"v1.0.0+build.123", "v1.0.0", true},
		{"v1.0.0-rc.2", "v1.0.0", false},
		{"v0.15.2", "v1.0.0", false},
		{"v2.0.0", "v1.0.0", false},
		{"v1.9.0", "v2.1.0", false},
		{"v2.0.0", "v2.1.0", true},
		{"v2.1.3", "v2.1.0", true},
		{"v2.2.0", "v2.1.0", false},
		{"v3.0.0", "v2.1.0", false},
		{"v10.0.0", "v10.0.1", true},
		{"collector/v1.0.0", "v1.0.0", false},
		{"v1.0", "v1.0.0", false},
		{"not-a-version", "v1.0.0", false},
	} {
		t.Run(tc.tag+"_"+tc.target, func(t *testing.T) {
			if got := applicableRelease(release{Tag: tc.tag}, tc.target); got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
	for _, r := range []release{{Tag: "v1.0.0", Draft: true}, {Tag: "v1.0.0", Pre: true}} {
		if applicableRelease(r, "v1.0.0") {
			t.Fatal("draft/prerelease must not be a protected baseline")
		}
	}
}

func TestReleasePaginationAndBootstrap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("API authorization is missing")
		}
		switch r.URL.Query().Get("page") {
		case "1":
			batch := make([]release, releasePageSize)
			for i := range batch {
				batch[i].Tag = fmt.Sprintf("v0.0.%d", i)
			}
			batch[0].Tag = "v1.1.0"
			_ = json.NewEncoder(w).Encode(batch)
		case "2":
			_ = json.NewEncoder(w).Encode([]release{{Tag: "v1.0.0"}, {Tag: "v1.0.2"}})
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	c := newReleaseClient()
	c.apiURL, c.client, c.token = server.URL, server.Client(), "test-token"
	got, err := c.releases(t.Context(), "v1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Tag != "v1.0.0" || got[1].Tag != "v1.0.2" {
		t.Fatalf("incomplete or incorrect baseline selection: %+v", got)
	}

	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer missing.Close()
	c.apiURL = missing.URL
	for _, target := range []string{"v1.0.0", "v2.1.0", "v10.0.1"} {
		if _, err := c.releases(t.Context(), target); err == nil {
			t.Fatalf("missing bootstrap for %s must fail", target)
		}
	}
}

func TestTagCommit(t *testing.T) {
	sha := strings.Repeat("a", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := "tag"
		if strings.Contains(r.URL.Path, "/git/tags/") {
			kind = "commit"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"type": kind, "sha": sha}})
	}))
	defer server.Close()
	c := newReleaseClient()
	c.apiURL, c.client = server.URL, server.Client()
	got, err := c.tagCommit(t.Context(), "v1.0.0")
	if err != nil || got != sha {
		t.Fatalf("commit=%q, err=%v", got, err)
	}
}

func TestVerifyChecksum(t *testing.T) {
	root := t.TempDir()
	archive, sums := filepath.Join(root, "source.tar.gz"), filepath.Join(root, "SHA256SUMS")
	body := "verified archive"
	digest := sha256.Sum256([]byte(body))
	hexDigest := hex.EncodeToString(digest[:])
	writeFile(t, archive, body)
	writeFile(t, sums, hexDigest+"  source.tar.gz\n")
	got, err := verifyChecksum(archive, sums)
	if err != nil || got != hexDigest {
		t.Fatalf("checksum=%q, err=%v", got, err)
	}
	writeFile(t, archive, "tampered cached archive")
	if _, err := verifyChecksum(archive, sums); err == nil {
		t.Fatal("cached assets must be reverified")
	}
	writeFile(t, sums, hexDigest+"  different-file.tar.gz\n")
	if _, err := verifyChecksum(archive, sums); err == nil {
		t.Fatal("missing checksum must fail")
	}
	writeFile(t, sums, strings.Repeat(hexDigest+"  source.tar.gz\n", 2))
	if _, err := verifyChecksum(archive, sums); err == nil {
		t.Fatal("duplicate checksum must fail")
	}
}

func TestExtractSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		kind byte
		ok   bool
	}{
		{"valid", "source/go.mod", tar.TypeReg, true},
		{"traversal", "source/../../escape", tar.TypeReg, false},
		{"outside prefix", "other/go.mod", tar.TypeReg, false},
		{"symlink", "source/link", tar.TypeSymlink, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "source.tar.gz")
			f, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			header := &tar.Header{Name: tc.path, Typeflag: tc.kind, Mode: 0o644}
			if tc.kind == tar.TypeReg {
				header.Size = 3
			}
			if err := tw.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if tc.kind == tar.TypeReg {
				_, _ = tw.Write([]byte("abc"))
			}
			for _, closer := range []io.Closer{tw, gz, f} {
				if err := closer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = extractSource(archive, filepath.Join(root, "unpacked"), "source")
			if (err == nil) != tc.ok {
				t.Fatalf("extract error=%v, expected success=%t", err, tc.ok)
			}
		})
	}
}

func TestMutableOrIncompleteReleaseFails(t *testing.T) {
	c := newReleaseClient()
	for _, r := range []release{{Tag: "v1.0.0"}, {Tag: "v1.0.0", Immutable: true}} {
		if _, _, err := c.source(t.Context(), r, t.TempDir(), t.TempDir()); err == nil {
			t.Fatal("unverifiable release must fail")
		}
	}
}

func TestMissingSignatureVerifierFails(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := verifySignature(t.Context(), filepath.Join(t.TempDir(), "archive"), "v1.0.0"); err == nil {
		t.Fatal("missing cosign must fail")
	}
}

func TestPrefetchedReleaseMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("prefetched metadata must not make API requests: %s", r.URL)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	sha := strings.Repeat("a", 40)
	metadata := filepath.Join(t.TempDir(), "release-metadata.json")
	responses := map[string]any{
		"/repos/" + repository + "/releases?per_page=100&page=1": []release{{Tag: "v1.0.0", Immutable: true}},
		"/repos/" + repository + "/git/ref/tags/v1.0.0":          map[string]any{"object": map[string]string{"type": "tag", "sha": sha}},
		"/repos/" + repository + "/git/tags/" + sha:              map[string]any{"object": map[string]string{"type": "commit", "sha": sha}},
	}
	data, err := json.Marshal(responses)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, metadata, string(data))
	c := newReleaseClient()
	c.apiURL, c.client, c.token, c.metadataPath = server.URL, server.Client(), "must-not-be-sent", metadata
	releases, err := c.releases(t.Context(), "v1.0.0")
	if err != nil || len(releases) != 1 || releases[0].Tag != "v1.0.0" {
		t.Fatalf("releases=%+v, err=%v", releases, err)
	}
	if commit, err := c.tagCommit(t.Context(), "v1.0.0"); err != nil || commit != sha {
		t.Fatalf("commit=%q, err=%v", commit, err)
	}
	if _, err := c.tagCommit(t.Context(), "v1.0.1"); err == nil {
		t.Fatal("missing prefetched response must fail without a live API fallback")
	}
	writeFile(t, metadata, "invalid JSON")
	if _, err := c.releases(t.Context(), "v1.0.0"); err == nil {
		t.Fatal("malformed metadata must fail without a live API fallback")
	}
	if err := os.Remove(metadata); err != nil {
		t.Fatal(err)
	}
	if _, err := c.releases(t.Context(), "v1.0.0"); err == nil {
		t.Fatal("missing metadata file must fail without a live API fallback")
	}
}
