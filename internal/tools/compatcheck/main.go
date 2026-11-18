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

type apiChange struct {
	TypeContext *apiSnapshot `json:"-"`
	Module      string       `json:"-"`
	Baseline    string       `json:"baseline"`
	Platform    string       `json:"platform"`
	Package     string       `json:"package"`
	Identifier  string       `json:"identifier"`
	Before      string       `json:"before,omitempty"`
	After       string       `json:"after,omitempty"`
	Message     string       `json:"message"`
	Compatible  bool         `json:"-"`
	Unsupported bool         `json:"-"`
	Rule        string       `json:"rule"`
	Reason      string       `json:"reason,omitempty"`
}

type baseline struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	ArchiveSHA256 string `json:"archive_sha256"`
	Platform      string `json:"platform"`
	Packages      int    `json:"packages"`
}

type report struct {
	FormatVersion        int         `json:"format_version"`
	Surface              string      `json:"surface"`
	BaseCommit           string      `json:"base_commit"`
	HeadCommit           string      `json:"head_commit"`
	WorkingTree          bool        `json:"working_tree_modified"`
	Platforms            []string    `json:"platforms"`
	Baselines            []baseline  `json:"baselines"`
	Findings             []apiChange `json:"findings"`
	ExistingFindings     []apiChange `json:"existing_findings"`
	Unclassified         []apiChange `json:"unclassified_changes"`
	ExistingUnclassified []apiChange `json:"existing_unclassified_changes"`
	ReleaseRequired      string      `json:"release_required"`
	RequiredRelease      string      `json:"required_release"`
	ReleaseBase          string      `json:"release_base,omitempty"`
	ProposedRelease      string      `json:"proposed_release,omitempty"`
	Error                string      `json:"error,omitempty"`
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
		FormatVersion: 2, Surface: "go-api", RequiredRelease: "incomplete", ReleaseRequired: "incomplete", ProposedRelease: opts.releaseVersion,
		Baselines: []baseline{}, Findings: []apiChange{}, ExistingFindings: []apiChange{}, Unclassified: []apiChange{}, ExistingUnclassified: []apiChange{},
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

	var introducedChanges, existingChanges []apiChange
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
			info.Packages = len(old.Packages)
			info.Platform = platform
			r.Baselines = append(r.Baselines, info)
			headChanges, err := compareAPI(old, candidate, release.Tag, platform)
			if err != nil {
				return err
			}
			baseChanges, err := compareAPI(old, target, release.Tag, platform)
			if err != nil {
				return err
			}
			introduced, existing := attributeChanges(headChanges, baseChanges)
			introducedChanges = append(introducedChanges, introduced...)
			existingChanges = append(existingChanges, existing...)
		}
	}
	r.RequiredRelease = minimumRelease(introducedChanges, r.ReleaseBase)
	all := append(slices.Clone(introducedChanges), existingChanges...)
	r.Findings, r.Unclassified = actionableChanges(introducedChanges)
	r.ExistingFindings, r.ExistingUnclassified = actionableChanges(existingChanges)
	for _, changes := range [][]apiChange{r.Findings, r.ExistingFindings, r.Unclassified, r.ExistingUnclassified} {
		sortAPIChanges(changes)
	}
	r.ReleaseRequired = minimumRelease(all, r.ReleaseBase)
	for _, f := range all {
		if f.Unsupported {
			r.ReleaseRequired = "incomplete"
			break
		}
	}
	if len(r.Unclassified) > 0 {
		r.RequiredRelease = "incomplete"
		return errors.New("source compatibility could not be determined for a PR change; see unclassified_changes in JSON")
	}
	if opts.releaseVersion != "" && r.ReleaseRequired == "incomplete" {
		return errors.New("release assessment is incomplete; see unclassified_changes and existing_unclassified_changes in JSON")
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

// minimumRelease applies the Go API release rules to classified changes.
// Only additions owned by the root module and absent from the latest release
// require a minor; compatible dependency updates remain patch-eligible.
func minimumRelease(changes []apiChange, latest string) string {
	minimum := "patch"
	for _, f := range changes {
		if f.Unsupported {
			continue
		}
		if !f.Compatible {
			return "major"
		}
		if f.Baseline == latest && f.Module == coreModule {
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
	} else {
		fmt.Fprintf(w, "Minimum Go API release class: %s\n", r.RequiredRelease)
	}
	if r.Error == "" && len(r.Findings) == 0 {
		fmt.Fprintln(w, "No incompatible public Go API changes introduced by this PR.")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "incompatible [%s %s] %s: %s\n", f.Baseline, f.Platform, f.Package, f.Message)
	}
	for _, c := range r.Unclassified {
		fmt.Fprintf(w, "unclassified [%s %s] %s.%s: %s\n", c.Baseline, c.Platform, c.Package, c.Identifier, c.Reason)
	}
	if r.ProposedRelease != "" {
		fmt.Fprintf(w, "Full candidate release assessment: %s\n", r.ReleaseRequired)
		for _, f := range r.ExistingFindings {
			fmt.Fprintf(w, "incompatible [%s %s] %s: %s\n", f.Baseline, f.Platform, f.Package, f.Message)
		}
		for _, c := range r.ExistingUnclassified {
			fmt.Fprintf(w, "unclassified [%s %s] %s.%s: %s\n", c.Baseline, c.Platform, c.Package, c.Identifier, c.Reason)
		}
	}
}

func actionableChanges(changes []apiChange) ([]apiChange, []apiChange) {
	incompatible, unclassified := []apiChange{}, []apiChange{}
	for _, c := range changes {
		if c.Unsupported {
			unclassified = append(unclassified, c)
		} else if !c.Compatible {
			incompatible = append(incompatible, c)
		}
	}
	return incompatible, unclassified
}

// attributeChanges compares candidate and target deltas from the same releases.
// An inherited unclassified type must also preserve its exposed contents: an
// unchanged outer diagnostic can otherwise hide a new API change.
func attributeChanges(head, base []apiChange) ([]apiChange, []apiChange) {
	keys := map[string]apiChange{}
	for _, f := range base {
		keys[changeKey(f)] = f
	}
	var introduced, existing []apiChange
	for _, f := range head {
		previous, inherited := keys[changeKey(f)]
		if inherited && f.TypeContext != nil {
			if detail := changedTypeContext(previous.TypeContext, f.TypeContext); detail != "" {
				inherited = false
				f.Reason += " Type context relative to the target: " + detail
			}
		}
		f.TypeContext = nil
		if inherited {
			existing = append(existing, f)
		} else {
			introduced = append(introduced, f)
		}
	}
	return introduced, existing
}

func changeKey(f apiChange) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%t\x00%t\x00%s", f.Baseline, f.Platform, f.Package, f.Identifier, f.Compatible, f.Unsupported, f.Message)
}

func sortAPIChanges(changes []apiChange) {
	slices.SortFunc(changes, func(a, b apiChange) int { return strings.Compare(changeKey(a), changeKey(b)) })
}
