// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// offsets.go defines the build identities, offset profiles, and database schema.
// It identifies compiler and crate versions from ELF metadata: compiler comments,
// source paths, and cargo-auditable dependency lists.

package rustabi // import "go.opentelemetry.io/obi/internal/rustabi"

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/semver"
)

type Layouts struct {
	VecPtr           uint32
	VecLen           uint32
	VecCap           uint32
	RequestHeaders   uint32
	HeaderEntries    uint32
	HeaderCount      uint32
	BucketSize       uint32
	NamePtr          uint32
	NameLen          uint32
	ValuePtr         uint32
	ValueLen         uint32
	ListHead         uint32
	ListIndex        uint32
	SlotMask         uint32
	MessageTxTag     uint32
	MessageTxSome    uint32
	MessageTxPointer uint32
	MessageRxTag     uint32
	MessageRxSome    uint32
	MessageRxPointer uint32
	MessageRxHeaders uint32
	HTTP1            uint8 `json:"Http1"`
	Inject           uint8
	Message          uint8
}

type MessageLayout struct {
	ListHead  uint32
	ListIndex uint32
	SlotMask  uint32
	TxTag     uint32
	TxSome    uint32
	TxPointer uint32
	RxTag     uint32
	RxSome    uint32
	RxPointer uint32
	RxHeaders uint32
	Request   bool `json:",omitempty"`
}

// CrateVersions records the versions of tracked crates seen together in one executable.
type CrateVersions map[string][]string

type Profile struct {
	Arch           string
	Rustc          string
	CrateSets      []CrateVersions `json:",omitempty"`
	Config         Layouts
	Channels       map[string]MessageLayout
	CompilerCommit string `json:",omitempty"`
}

type Database struct {
	Profiles     []Profile         `json:"profiles"`
	Measurements map[string]string `json:"measurements,omitempty"`
}

type Build struct {
	Arch           string
	Rustc          string
	Crates         map[string][]string
	CompilerCommit string
}

// cargo-auditable's embedded dependency list, see
// https://github.com/rust-secure-code/cargo-auditable/blob/master/PARSING.md
const (
	rustAuditableSection = ".dep-v0"
	// the decompressed size limit PARSING.md recommends against zip bombs
	rustAuditableMaxBytes = 8 << 20
)

var (
	rustTrackedCrates = []string{"tokio", "reqwest", "hyper", "h2", "rustls", "http", "bytes"}
	// Cargo registry and vendor directories follow a separator, Bazel rules_rust
	// repositories are named <hub>__<crate>-<version>
	rustCrateVersion = regexp.MustCompile(
		`(?:^|[/\\ ]|__)(` + strings.Join(rustTrackedCrates, "|") + `)-([0-9]+\.[0-9]+\.[0-9]+)[/\\]`)
	rustCompilerVersion = regexp.MustCompile(`rustc version ([0-9]+\.[0-9]+\.[0-9]+) \(`)
	rustCompilerCommit  = regexp.MustCompile(`[/\\]rustc[/\\]([0-9a-f]{40})[/\\]`)
)

type rustAuditablePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// a string, or an {"Other": ...} object for unrecognized sources
	Source json.RawMessage `json:"source"`
	Kind   string          `json:"kind"`
}

// ReadCompiler identifies the architecture and rustc independently of Cargo metadata.
func ReadCompiler(f *elf.File) (Build, error) {
	var b Build
	switch f.Machine {
	case elf.EM_X86_64:
		b.Arch = "amd64"
	case elf.EM_AARCH64:
		b.Arch = "arm64"
	default:
		return b, errors.New("unsupported Rust ELF architecture")
	}

	var readErr error
	for _, section := range f.Sections {
		if !hasRustSourcePaths(section) {
			continue
		}
		data, err := section.Data()
		if err != nil {
			readErr = err
			continue
		}

		if version := rustCompilerVersion.FindSubmatch(data); len(version) > 0 {
			b.Rustc = string(version[1])
		}

		if commit := rustCompilerCommit.FindSubmatch(data); len(commit) > 0 {
			b.CompilerCommit = string(commit[1])
		}
	}
	if b.Rustc == "" && b.CompilerCommit == "" {
		return b, readErr
	}
	return b, nil
}

// ReadCrates uses cargo-auditable metadata when present, falling back to source
// paths for binaries without it. Paths cannot establish a dependency's source or kind.
func ReadCrates(f *elf.File) (map[string][]string, error) {
	crates := map[string][]string{}

	sections := f.Sections
	if metadata := f.Section(rustAuditableSection); metadata != nil {
		sections = []*elf.Section{metadata}
	}

	for _, section := range sections {
		if section.Name != rustAuditableSection && !hasRustSourcePaths(section) {
			continue
		}

		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", section.Name, err)
		}
		if section.Name == rustAuditableSection {
			if err := addAuditableCrateVersions(crates, data); err != nil {
				return nil, fmt.Errorf("reading %s: %w", section.Name, err)
			}
		} else {
			addPathCrateVersions(crates, data)
		}
	}
	return crates, nil
}

func hasRustSourcePaths(section *elf.Section) bool {
	return section.Name == ".comment" || strings.HasPrefix(section.Name, ".rodata")
}

// ReadCrates records each version once. ELF section order can differ between builds.
func sameVersions(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, version := range a {
		if !slices.Contains(b, version) {
			return false
		}
	}
	return true
}

func addCrateVersion(crates map[string][]string, name, version string) {
	if !slices.Contains(crates[name], version) {
		crates[name] = append(crates[name], version)
	}
}

func addPathCrateVersions(crates map[string][]string, data []byte) {
	for _, match := range rustCrateVersion.FindAllSubmatch(data, -1) {
		addCrateVersion(crates, string(match[1]), string(match[2]))
	}
}

// Only registry packages linked at runtime are recorded: git and local packages
// can carry a published version number over different sources.
func addAuditableCrateVersions(crates map[string][]string, compressed []byte) error {
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return err
	}

	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, rustAuditableMaxBytes+1))
	if err != nil {
		return err
	}

	if len(data) > rustAuditableMaxBytes {
		return errors.New("dependency list exceeds the size limit")
	}

	var list struct {
		Packages []rustAuditablePackage `json:"packages"`
	}

	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	for _, pkg := range list.Packages {
		var source string
		if json.Unmarshal(pkg.Source, &source) != nil || source != "crates.io" && source != "registry" {
			continue
		}

		if pkg.Kind != "" && pkg.Kind != "runtime" {
			continue
		}

		if !slices.Contains(rustTrackedCrates, pkg.Name) {
			continue
		}

		addCrateVersion(crates, pkg.Name, pkg.Version)
	}

	return nil
}

var ErrUnsupportedCompiler = errors.New("unsupported Rust compiler")

// CheckCompiler checks whether the database supports the build's stable rustc minor version on its architecture.
func (d Database) CheckCompiler(build Build) error {
	build = d.InferBuild(build)
	if build.Rustc == "" {
		return fmt.Errorf("%w: could not identify rustc version on %s", ErrUnsupportedCompiler, build.Arch)
	}

	version := "v" + build.Rustc
	if minor := semver.MajorMinor(version); minor != "" && semver.Prerelease(version) == "" {
		for _, profile := range d.Profiles {
			if profile.Arch == build.Arch && semver.MajorMinor("v"+profile.Rustc) == minor {
				return nil
			}
		}
	}
	return fmt.Errorf("%w %q on %s", ErrUnsupportedCompiler, build.Rustc, build.Arch)
}

// InferBuild fills in a compiler version the binary's comment section omits.
// Toolchain builds share one standard-library commit, so its source paths
// identify the compiler of any binary built with that toolchain.
func (d Database) InferBuild(build Build) Build {
	if build.Rustc != "" || build.CompilerCommit == "" {
		return build
	}

	for _, profile := range d.Profiles {
		if profile.Arch == build.Arch && profile.CompilerCommit == build.CompilerCommit {
			build.Rustc = profile.Rustc
			break
		}
	}

	return build
}
