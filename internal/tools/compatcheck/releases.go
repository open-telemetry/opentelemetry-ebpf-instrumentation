// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	releasePageSize = 100
	maxMetadataSize = 32 << 20
	maxArchiveSize  = 512 << 20
	maxExpandedSize = 2 << 30
	maxTagDepth     = 8
)

type release struct {
	Tag       string         `json:"tag_name"`
	Draft     bool           `json:"draft"`
	Pre       bool           `json:"prerelease"`
	Immutable bool           `json:"immutable"`
	Assets    []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name string `json:"name"`
}

type releaseSource struct {
	root string
	info baseline
}

type releaseClient struct {
	client  *http.Client
	apiURL  string
	token   string
	sources map[string]releaseSource
}

func newReleaseClient() *releaseClient {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	return &releaseClient{
		client: &http.Client{Timeout: 5 * time.Minute}, apiURL: "https://api.github.com",
		token: token, sources: map[string]releaseSource{},
	}
}

func (c *releaseClient) releases(ctx context.Context, target string) ([]release, error) {
	var result []release
	for page := 1; ; page++ {
		var batch []release
		path := fmt.Sprintf("/repos/%s/releases?per_page=%d&page=%d", repository, releasePageSize, page)
		if err := c.getJSON(ctx, path, &batch); err != nil {
			return nil, err
		}
		for _, r := range batch {
			if applicableRelease(r, target) {
				result = append(result, r)
			}
		}
		if len(batch) < releasePageSize {
			break
		}
	}
	slices.SortFunc(result, func(a, b release) int { return semver.Compare(a.Tag, b.Tag) })
	if semver.Major(target) == "v1" && !slices.ContainsFunc(result, func(r release) bool { return r.Tag == "v1.0.0" }) {
		return nil, errors.New("published v1.0.0 bootstrap baseline is missing")
	}
	return result, nil
}

func applicableRelease(r release, target string) bool {
	return !r.Draft && !r.Pre && semver.IsValid(r.Tag) && semver.Prerelease(r.Tag) == "" &&
		strings.Split(r.Tag, "+")[0] == semver.Canonical(r.Tag) &&
		semver.Compare(r.Tag, "v1.0.0") >= 0 && semver.Major(r.Tag) == semver.Major(target) &&
		semver.Compare(semver.MajorMinor(r.Tag), semver.MajorMinor(target)) <= 0
}

func (c *releaseClient) getJSON(ctx context.Context, path string, value any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+path, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub %s: HTTP %d", path, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxMetadataSize {
		return errors.New("GitHub metadata exceeds size limit")
	}
	return json.Unmarshal(data, value)
}

func (c *releaseClient) source(ctx context.Context, r release, cache, temp string) (string, baseline, error) {
	if source, ok := c.sources[r.Tag]; ok {
		return source.root, source.info, nil
	}
	if !r.Immutable {
		return "", baseline{}, errors.New("release is not immutable")
	}
	archive := "obi-" + r.Tag + "-source-generated.tar.gz"
	files := []string{archive, archive + ".bundle.json", "SHA256SUMS", "SHA256SUMS.bundle.json"}
	for _, name := range files {
		if !slices.ContainsFunc(r.Assets, func(a releaseAsset) bool {
			return a.Name == name
		}) {
			return "", baseline{}, fmt.Errorf("release asset %s is missing", name)
		}
	}
	dir := filepath.Join(cache, r.Tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", baseline{}, err
	}
	for _, name := range files {
		url := "https://github.com/" + repository + "/releases/download/" + r.Tag + "/" + name
		if err := c.download(ctx, url, filepath.Join(dir, name)); err != nil {
			return "", baseline{}, err
		}
	}
	for _, name := range []string{"SHA256SUMS", archive} {
		if err := verifySignature(ctx, filepath.Join(dir, name), r.Tag); err != nil {
			return "", baseline{}, err
		}
	}
	digest, err := verifyChecksum(filepath.Join(dir, archive), filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return "", baseline{}, err
	}
	commit, err := c.tagCommit(ctx, r.Tag)
	if err != nil {
		return "", baseline{}, err
	}
	root := filepath.Join(temp, r.Tag)
	if err := extractSource(filepath.Join(dir, archive), root, "obi-"+r.Tag+"-source-generated"); err != nil {
		return "", baseline{}, err
	}
	if _, err := modulePath(root); err != nil {
		return "", baseline{}, err
	}
	info := baseline{Version: r.Tag, Commit: commit, ArchiveSHA256: digest}
	c.sources[r.Tag] = releaseSource{root: root, info: info}
	return root, info, nil
}

func (c *releaseClient) tagCommit(ctx context.Context, tag string) (string, error) {
	type object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	var ref struct {
		Object object `json:"object"`
	}
	path := "/repos/" + repository + "/git/ref/tags/" + tag
	for range maxTagDepth {
		if err := c.getJSON(ctx, path, &ref); err != nil {
			return "", err
		}
		if len(ref.Object.SHA) != 40 {
			return "", fmt.Errorf("invalid commit identity for %s", tag)
		}
		if _, err := hex.DecodeString(ref.Object.SHA); err != nil {
			return "", fmt.Errorf("invalid commit identity for %s: %w", tag, err)
		}
		if ref.Object.Type == "commit" {
			return ref.Object.SHA, nil
		}
		if ref.Object.Type != "tag" {
			break
		}
		path = "/repos/" + repository + "/git/tags/" + ref.Object.SHA
	}
	return "", fmt.Errorf("cannot resolve release tag %s to a commit", tag)
}

func (c *releaseClient) download(ctx context.Context, url, dest string) error {
	if info, err := os.Stat(dest); err == nil && info.Mode().IsRegular() {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", filepath.Base(dest), resp.StatusCode)
	}
	f, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, maxArchiveSize+1))
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if n > maxArchiveSize {
		return fmt.Errorf("download %s exceeds size limit", filepath.Base(dest))
	}
	return os.Rename(f.Name(), dest)
}

func verifySignature(ctx context.Context, file, version string) error {
	identity := "https://github.com/" + repository + "/.github/workflows/release.yml@refs/tags/" + version
	cmd := exec.CommandContext(ctx, "cosign", "verify-blob", file,
		"--bundle", file+".bundle.json", "--certificate-identity", identity,
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("verify %s: %w: %s", filepath.Base(file), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func verifyChecksum(archive, sums string) (string, error) {
	f, err := os.Open(sums)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var expected string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == filepath.Base(archive) {
			if expected != "" {
				return "", fmt.Errorf("duplicate checksum for %s", filepath.Base(archive))
			}
			expected = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(expected) != sha256.Size*2 {
		return "", fmt.Errorf("missing or invalid checksum for %s", filepath.Base(archive))
	}
	file, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return "", fmt.Errorf("checksum mismatch for %s; remove the cached release assets and retry", filepath.Base(archive))
	}
	return actual, nil
}

func extractSource(archive, dest, prefix string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	reader := tar.NewReader(gz)
	var expanded int64
	for {
		h, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.TrimSuffix(h.Name, "/") == prefix && h.Typeflag == tar.TypeDir {
			continue
		}
		rel, ok := strings.CutPrefix(h.Name, prefix+"/")
		if !ok || !filepath.IsLocal(rel) {
			return fmt.Errorf("invalid source archive path %q", h.Name)
		}
		path := filepath.Join(dest, rel)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			expanded += h.Size
			if h.Size < 0 || expanded > maxExpandedSize {
				return errors.New("expanded source archive exceeds size limit")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, h.FileInfo().Mode().Perm())
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(out, reader, h.Size)
			if err := errors.Join(copyErr, out.Close()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported source archive entry %q (type %d)", h.Name, h.Typeflag)
		}
	}
}
