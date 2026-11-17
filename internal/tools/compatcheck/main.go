// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

const (
	coreModule = "go.opentelemetry.io/obi"
	repository = "open-telemetry/opentelemetry-ebpf-instrumentation"
	goAPIRule  = "VERSIONING.md#go-module-api"
	exitBreak  = 1
	exitError  = 2
)

type options struct {
	repoRoot       string
	baseRef        string
	baseDir        string
	headRef        string
	architectures  string
	releaseVersion string
	reportPath     string
	cacheDir       string
}

type finding struct {
	Baseline    string `json:"baseline"`
	Platform    string `json:"platform"`
	Package     string `json:"package"`
	Identifier  string `json:"identifier"`
	Before      string `json:"before,omitempty"`
	After       string `json:"after,omitempty"`
	Message     string `json:"message"`
	Compatible  bool   `json:"compatible"`
	Unsupported bool   `json:"unsupported,omitempty"`
	Rule        string `json:"rule"`
}

type baseline struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	ArchiveSHA256 string `json:"archive_sha256"`
	Platform      string `json:"platform"`
	Packages      int    `json:"packages"`
}

type report struct {
	FormatVersion    int        `json:"format_version"`
	Surface          string     `json:"surface"`
	BaseCommit       string     `json:"base_commit"`
	HeadCommit       string     `json:"head_commit"`
	WorkingTree      bool       `json:"working_tree_modified"`
	Platforms        []string   `json:"platforms"`
	Baselines        []baseline `json:"baselines"`
	Findings         []finding  `json:"findings"`
	ExistingFindings []finding  `json:"existing_findings"`
	ReleaseRequired  string     `json:"release_required"`
	RequiredRelease  string     `json:"required_release"`
	ReleaseBase      string     `json:"release_base,omitempty"`
	ProposedRelease  string     `json:"proposed_release,omitempty"`
	Error            string     `json:"error,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var opts options
	flags := flag.NewFlagSet("compatcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.repoRoot, "repo-root", ".", "checked-out candidate repository")
	flags.StringVar(&opts.baseDir, "base-dir", "", "clean target checkout with generated artifacts")
	flags.StringVar(&opts.baseRef, "base-ref", "HEAD", "trusted target revision selecting the release line")
	flags.StringVar(&opts.headRef, "head-ref", "HEAD", "candidate revision (must be checked out)")
	flags.StringVar(&opts.architectures, "arch", "amd64,arm64", "Linux architectures to compare")
	flags.StringVar(&opts.releaseVersion, "release-version", "", "optional proposed core release version")
	flags.StringVar(&opts.reportPath, "report", "", "JSON report destination")
	flags.StringVar(&opts.cacheDir, "cache-dir", "", "verified release asset cache (default: testoutput/compatibility-cache)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitError
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "compatcheck: unexpected positional arguments")
		return exitError
	}

	r := report{
		FormatVersion: 2, Surface: "go-api", RequiredRelease: "patch", ProposedRelease: opts.releaseVersion,
		Baselines: []baseline{}, Findings: []finding{}, ExistingFindings: []finding{},
	}
	err := check(ctx, opts, &r, stderr)
	if err != nil {
		r.Error = err.Error()
	}
	if opts.reportPath != "" {
		if writeErr := writeReport(opts.reportPath, &r); writeErr != nil {
			fmt.Fprintln(stderr, "compatcheck:", writeErr)
			return exitError
		}
	}
	printReport(stdout, &r)
	if err != nil {
		return exitError
	}
	if r.RequiredRelease == "major" || (opts.releaseVersion != "" && r.ReleaseRequired == "major") {
		return exitBreak
	}
	if opts.releaseVersion != "" && r.ReleaseRequired == "minor" {
		for _, b := range r.Baselines {
			if semver.MajorMinor(b.Version) == semver.MajorMinor(opts.releaseVersion) {
				fmt.Fprintln(stdout, "Proposed patch release contains additions requiring a minor release.")
				return exitBreak
			}
		}
	}
	return 0
}

func check(ctx context.Context, opts options, r *report, progress io.Writer) error {
	root, err := filepath.Abs(opts.repoRoot)
	if err != nil {
		return err
	}
	baseCommit, err := git(ctx, root, "rev-parse", "--verify", "--end-of-options", opts.baseRef+"^{commit}")
	if err != nil {
		return err
	}
	r.BaseCommit = baseCommit
	r.HeadCommit, err = git(ctx, root, "rev-parse", "--verify", "--end-of-options", opts.headRef+"^{commit}")
	if err != nil {
		return err
	}
	checkedOut, err := git(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if checkedOut != r.HeadCommit {
		return errors.New("head-ref must identify the checked-out candidate")
	}
	status, err := git(ctx, root, "status", "--porcelain")
	if err != nil {
		return err
	}
	r.WorkingTree = status != ""
	baseRoot := opts.baseDir
	if baseRoot == "" {
		if r.BaseCommit != r.HeadCommit || r.WorkingTree {
			return errors.New("--base-dir must identify a clean target checkout with generated artifacts")
		}
		baseRoot = root
	}
	baseHead, err := git(ctx, baseRoot, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("target checkout: %w", err)
	}
	if baseHead != baseCommit {
		return errors.New("base-dir does not match base-ref")
	}
	baseStatus, err := git(ctx, baseRoot, "status", "--porcelain")
	if err != nil {
		return err
	}
	if baseStatus != "" {
		return errors.New("base-dir must have a clean working tree")
	}

	version, err := targetVersion(ctx, root, baseCommit)
	if err != nil {
		return err
	}
	if err := validateProposed(opts.releaseVersion, version); err != nil {
		return err
	}
	archs, err := parseArchitectures(opts.architectures)
	if err != nil {
		return err
	}
	if opts.cacheDir == "" {
		opts.cacheDir = filepath.Join(root, "testoutput", "compatibility-cache")
	}
	client := newReleaseClient()
	releases, err := client.releases(ctx, version)
	if err != nil {
		return err
	}
	if len(releases) == 0 {
		return fmt.Errorf("no published core baselines found for %s", version)
	}
	r.ReleaseBase = releases[len(releases)-1].Tag
	temp, err := os.MkdirTemp("", "obi-compatcheck-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)

	for _, arch := range archs {
		platform := "linux/" + arch
		r.Platforms = append(r.Platforms, platform)
		fmt.Fprintln(progress, "Loading candidate Go API for", platform)
		candidate, err := loadAPI(ctx, root, arch)
		if err != nil {
			return fmt.Errorf("candidate %s: %w", platform, err)
		}
		fmt.Fprintln(progress, "Loading target Go API for", platform)
		target, err := loadAPI(ctx, baseRoot, arch)
		if err != nil {
			return fmt.Errorf("target %s: %w", platform, err)
		}
		for _, release := range releases {
			fmt.Fprintln(progress, "Comparing", release.Tag, "against candidate for", platform)
			source, info, err := client.source(ctx, release, opts.cacheDir, temp)
			if err != nil {
				return fmt.Errorf("baseline %s: %w", release.Tag, err)
			}
			old, err := loadAPI(ctx, source, arch)
			if err != nil {
				return fmt.Errorf("baseline %s %s: %w", release.Tag, platform, err)
			}
			info.Packages = len(old)
			info.Platform = platform
			r.Baselines = append(r.Baselines, info)
			headFindings, err := compareAPI(old, candidate, release.Tag, platform)
			if err != nil {
				return err
			}
			baseFindings, err := compareAPI(old, target, release.Tag, platform)
			if err != nil {
				return err
			}
			introduced, existing := attributeFindings(headFindings, baseFindings)
			r.Findings = append(r.Findings, introduced...)
			r.ExistingFindings = append(r.ExistingFindings, existing...)
		}
	}
	sortFindings(r.Findings)
	sortFindings(r.ExistingFindings)
	r.RequiredRelease = minimumRelease(r.Findings, r.ReleaseBase)
	all := append(slices.Clone(r.Findings), r.ExistingFindings...)
	r.ReleaseRequired = minimumRelease(all, r.ReleaseBase)
	for _, f := range all {
		if f.Unsupported {
			r.ReleaseRequired = "incomplete"
			break
		}
	}
	for _, f := range r.Findings {
		if f.Unsupported {
			return errors.New("PR contains an unclassified type identity change; see JSON findings")
		}
	}
	if opts.releaseVersion != "" && r.ReleaseRequired == "incomplete" {
		return errors.New("release contains unclassified type identity changes; see JSON findings")
	}

	if opts.releaseVersion != "" {
		for _, b := range r.Baselines {
			if semver.Compare(opts.releaseVersion, b.Version) <= 0 {
				return fmt.Errorf("proposed release %s must be newer than baseline %s", opts.releaseVersion, b.Version)
			}
		}
	}
	return nil
}

func targetVersion(ctx context.Context, root, ref string) (string, error) {
	data, err := git(ctx, root, "show", ref+":versions.yaml")
	if err != nil {
		return "", err
	}
	var versions struct {
		Sets map[string]struct {
			Version string `yaml:"version"`
		} `yaml:"module-sets"`
	}
	if err := yaml.Unmarshal([]byte(data), &versions); err != nil {
		return "", err
	}
	version := versions.Sets["obi"].Version
	if !semver.IsValid(version) || semver.Compare(version, "v1.0.0") < 0 {
		return "", fmt.Errorf("target revision must identify a stable core release line from v1.0.0; got %q", version)
	}
	return version, nil
}

func validateProposed(proposed, target string) error {
	if proposed == "" {
		return nil
	}
	if !semver.IsValid(proposed) || strings.Split(proposed, "+")[0] != semver.Canonical(proposed) || semver.Major(proposed) != semver.Major(target) {
		return fmt.Errorf("proposed release %q must be valid semver on the target's %s module line", proposed, semver.Major(target))
	}
	return nil
}

func minimumRelease(findings []finding, latest string) string {
	minimum := "patch"
	for _, f := range findings {
		if f.Unsupported {
			continue
		}
		if !f.Compatible {
			return "major"
		}
		if f.Baseline == latest {
			minimum = "minor"
		}
	}
	return minimum
}

func modulePath(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	path := modfile.ModulePath(data)
	if path != coreModule {
		return "", fmt.Errorf("expected core module %s, got %q", coreModule, path)
	}
	return path, nil
}

func parseArchitectures(value string) ([]string, error) {
	archs := strings.Split(value, ",")
	slices.Sort(archs)
	archs = slices.Compact(archs)
	for _, arch := range archs {
		if arch != "amd64" && arch != "arm64" {
			return nil, fmt.Errorf("unsupported architecture %q; use amd64 or arm64", arch)
		}
	}
	return archs, nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func writeReport(path string, r *report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func printReport(w io.Writer, r *report) {
	fmt.Fprintln(w, "Go API compatibility")
	fmt.Fprintf(w, "Candidate: %s; target: %s\n", r.HeadCommit, r.BaseCommit)
	if r.Error != "" {
		fmt.Fprintln(w, "INCOMPLETE:", r.Error)
		return
	}
	fmt.Fprintf(w, "PR changes: %d; minimum release: %s\n", len(r.Findings), r.RequiredRelease)
	for _, f := range r.Findings {
		kind := "addition"
		if !f.Compatible {
			kind = "incompatible"
		}
		fmt.Fprintf(w, "%s [%s %s] %s: %s\n", kind, f.Baseline, f.Platform, f.Package, f.Message)
	}
	fmt.Fprintf(w, "Existing findings on target: %d (see JSON report)\n", len(r.ExistingFindings))
	fmt.Fprintf(w, "Full candidate release requirement: %s\n", r.ReleaseRequired)
}

func attributeFindings(head, base []finding) ([]finding, []finding) {
	keys := map[string]bool{}
	for _, f := range base {
		keys[findingKey(f)] = true
	}
	var introduced, existing []finding
	for _, f := range head {
		if keys[findingKey(f)] {
			existing = append(existing, f)
		} else {
			introduced = append(introduced, f)
		}
	}
	return introduced, existing
}

func findingKey(f finding) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%t\x00%t\x00%s", f.Baseline, f.Platform, f.Package, f.Identifier, f.Compatible, f.Unsupported, f.Message)
}

func sortFindings(findings []finding) {
	slices.SortFunc(findings, func(a, b finding) int { return strings.Compare(findingKey(a), findingKey(b)) })
}
