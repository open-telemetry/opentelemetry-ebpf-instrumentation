// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command gooffsets collects versioned Go field offsets and runtime ABI facts.
package main

import (
	"debug/elf"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/grafana/go-offsets-tracker/pkg/binary"
	"github.com/grafana/go-offsets-tracker/pkg/downloader"
	"github.com/grafana/go-offsets-tracker/pkg/offsets"
	"github.com/grafana/go-offsets-tracker/pkg/target"
	"github.com/grafana/go-offsets-tracker/pkg/versions"
	"github.com/grafana/go-offsets-tracker/pkg/writer"
	goversion "github.com/hashicorp/go-version"

	"go.opentelemetry.io/obi/internal/goabi"
)

type abiInput struct {
	Versions string `json:"versions"`
	Inspect  string `json:"inspect"`
}

func main() {
	inputFile := flag.String("i", "", "input JSON file describing required field offsets")
	abiInputFile := flag.String("abi", "", "input JSON file describing required ABI facts")
	flag.Parse()
	if *inputFile == "" || *abiInputFile == "" || flag.NArg() != 1 {
		log.Fatal("usage: gooffsets -i <input file> -abi <ABI input file> <output file>")
	}
	exitOnError(run(*inputFile, *abiInputFile, flag.Arg(0)))
}

func run(inputFile, abiInputFile, outputFile string) (retErr error) {
	restoreTemporaryDirectory, err := isolateTemporaryDirectory()
	if err != nil {
		return err
	}
	defer func() {
		if err := restoreTemporaryDirectory(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	restoreGoFlags := configureGoBuild()
	defer restoreGoFlags()

	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("reading field offset input: %w", err)
	}
	var libraries offsets.InputLibs
	if err := json.Unmarshal(inputData, &libraries); err != nil {
		return fmt.Errorf("parsing field offset input: %w", err)
	}

	abiInputData, err := os.ReadFile(abiInputFile)
	if err != nil {
		return fmt.Errorf("reading ABI input: %w", err)
	}
	var abiConfig abiInput
	if err := json.Unmarshal(abiInputData, &abiConfig); err != nil {
		return fmt.Errorf("parsing ABI input: %w", err)
	}
	if abiConfig.Inspect == "" {
		return errors.New("ABI inspect source is required")
	}

	results, err := collectFieldOffsets(libraries, outputFile)
	if err != nil {
		return err
	}
	abiResult, err := collectABIFacts(abiConfig, outputFile)
	if err != nil {
		return err
	}
	results = append(results, abiResult)

	if err := validateDistinctResults(results); err != nil {
		return err
	}
	return writeResultsAtomic(outputFile, results)
}

func isolateTemporaryDirectory() (func() error, error) {
	previous, existed := os.LookupEnv("TMPDIR")
	directory, err := os.MkdirTemp("", "obi-go-offsets-")
	if err != nil {
		return nil, fmt.Errorf("creating offsets temporary directory: %w", err)
	}
	if err := os.Setenv("TMPDIR", directory); err != nil {
		_ = os.RemoveAll(directory)
		return nil, fmt.Errorf("setting offsets temporary directory: %w", err)
	}

	return func() error {
		var restoreErr error
		if existed {
			restoreErr = os.Setenv("TMPDIR", previous)
		} else {
			restoreErr = os.Unsetenv("TMPDIR")
		}
		removeErr := os.RemoveAll(directory)
		if restoreErr != nil || removeErr != nil {
			return fmt.Errorf("cleaning offsets temporary directory: %w", errors.Join(restoreErr, removeErr))
		}
		return nil
	}, nil
}

func collectFieldOffsets(libraries offsets.InputLibs, cacheFile string) ([]*target.Result, error) {
	results := make([]*target.Result, 0, len(libraries))
	if standardLibrary, ok := libraries[offsets.GoStdLib]; ok {
		standardResults, err := collectStandardLibraryOffsets(standardLibrary, cacheFile)
		if err != nil {
			return nil, err
		}
		results = append(results, standardResults...)
	}

	names := make([]string, 0, len(libraries))
	for name := range libraries {
		if name != offsets.GoStdLib {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		library := libraries[name]
		targetData := target.New(name, cacheFile).Packages(library.Packages)
		if library.Branch != "" {
			targetData = targetData.Branch(library.Branch)
		} else if library.Versions != "" {
			constraint, err := goversion.NewConstraint(library.Versions)
			if err != nil {
				return nil, fmt.Errorf("invalid %s version constraint: %w", name, err)
			}
			targetData = targetData.VersionConstraint(&constraint)
		}

		result, err := targetData.FindOffsets(library)
		if err != nil {
			return nil, fmt.Errorf("collecting %s offsets: %w", name, err)
		}
		results = append(results, result)
	}
	return results, nil
}

type fieldGroup struct {
	minimum string
	maximum string
	fields  map[string][]string
}

func collectStandardLibraryOffsets(library offsets.LibQuery, cacheFile string) ([]*target.Result, error) {
	groups, err := groupFieldsByVersion(library.Fields)
	if err != nil {
		return nil, err
	}

	results := make([]*target.Result, 0, len(groups))
	for _, group := range groups {
		constraints := []string{library.Versions}
		if group.minimum != "" {
			constraints = append(constraints, ">= "+group.minimum)
		}
		if group.maximum != "" {
			constraints = append(constraints, "<= "+group.maximum)
		}
		constraint, err := goversion.NewConstraint(strings.Join(constraints, ", "))
		if err != nil {
			return nil, fmt.Errorf("invalid Go field version constraint: %w", err)
		}

		query := library
		query.Fields = group.fields
		result, err := target.New(offsets.GoStdLib, cacheFile).
			FindVersionsBy(target.GoDevFileVersionsStrategy).
			DownloadBinaryBy(target.DownloadPreCompiledBinaryFetchStrategy).
			VersionConstraint(&constraint).
			FindOffsets(query)
		if err != nil {
			return nil, fmt.Errorf("collecting Go standard library offsets: %w", err)
		}
		results = append(results, result)
	}
	return results, nil
}

func groupFieldsByVersion(fields map[string][]string) ([]fieldGroup, error) {
	groupMap := map[string]*fieldGroup{}
	for typeName, typeFields := range fields {
		for _, configuredField := range typeFields {
			field, minimum, maximum, err := parseVersionedField(configuredField)
			if err != nil {
				return nil, err
			}
			key := minimum + "\x00" + maximum
			group := groupMap[key]
			if group == nil {
				group = &fieldGroup{minimum: minimum, maximum: maximum, fields: map[string][]string{}}
				groupMap[key] = group
			}
			group.fields[typeName] = append(group.fields[typeName], field)
		}
	}

	keys := make([]string, 0, len(groupMap))
	for key := range groupMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	groups := make([]fieldGroup, 0, len(keys))
	for _, key := range keys {
		groups = append(groups, *groupMap[key])
	}
	return groups, nil
}

func parseVersionedField(configured string) (field, minimum, maximum string, err error) {
	if !strings.HasPrefix(configured, "[") {
		return configured, "", "", nil
	}
	closing := strings.IndexByte(configured, ']')
	if closing < 0 || closing == len(configured)-1 {
		return "", "", "", fmt.Errorf("invalid versioned field %q", configured)
	}
	versions := strings.Split(configured[1:closing], ",")
	if len(versions) == 0 || len(versions) > 2 || versions[0] == "" {
		return "", "", "", fmt.Errorf("invalid versioned field %q", configured)
	}
	if len(versions) == 2 {
		maximum = versions[1]
	}
	return configured[closing+1:], versions[0], maximum, nil
}

func collectABIFacts(config abiInput, cacheFile string) (*target.Result, error) {
	constraint, err := goversion.NewConstraint(config.Versions)
	if err != nil {
		return nil, fmt.Errorf("invalid ABI Go version constraint: %w", err)
	}

	available, err := versions.FindVersionsFromGoWebsite()
	if err != nil {
		return nil, err
	}
	sort.Slice(available, func(i, j int) bool {
		left, leftErr := goversion.NewVersion(available[i])
		right, rightErr := goversion.NewVersion(available[j])
		return leftErr == nil && rightErr == nil && left.LessThan(right)
	})

	var cache *offsets.Track
	if existing, openErr := offsets.Open(cacheFile); openErr == nil {
		cache = existing
	}

	result := &target.Result{ModuleName: offsets.GoStdLib}
	for _, release := range available {
		parsed, parseErr := goversion.NewVersion(release)
		if parseErr != nil || !constraint.Check(parsed) {
			continue
		}

		definitions, err := goabi.Definitions(release)
		if err != nil {
			return nil, err
		}
		facts, ok := cachedFacts(cache, release, definitions)
		if !ok {
			log.Printf("collecting Go %s runtime ABI facts", release)
			facts, err = collectRelease(release, config.Inspect)
			if err != nil {
				return nil, err
			}
		}
		result.ResultsByVersion = append(result.ResultsByVersion, &target.VersionedResult{
			Version:    release,
			OffsetData: &binary.Result{DataMembers: facts},
		})
	}
	if len(result.ResultsByVersion) == 0 {
		return nil, errors.New("no Go releases matched the ABI version constraint")
	}
	return result, nil
}

func validateDistinctResults(results []*target.Result) error {
	owners := map[string]int{}
	for resultIndex, result := range results {
		for _, versioned := range result.ResultsByVersion {
			for _, fact := range versioned.OffsetData.DataMembers {
				key := fact.StructName + "." + fact.Field
				if owner, ok := owners[key]; ok && owner != resultIndex {
					return fmt.Errorf("generated fact %s is produced by multiple collectors", key)
				}
				owners[key] = resultIndex
			}
		}
	}
	return nil
}

func writeResultsAtomic(outputFile string, results []*target.Result) (retErr error) {
	directory := filepath.Dir(outputFile)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(outputFile)+"-*")
	if err != nil {
		return fmt.Errorf("creating temporary offsets file: %w", err)
	}
	temporaryFile := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryFile); err != nil && !errors.Is(err, os.ErrNotExist) && retErr == nil {
			retErr = fmt.Errorf("removing temporary offsets file: %w", err)
		}
	}()
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("closing temporary offsets file: %w", err)
	}

	if current, err := os.Stat(outputFile); err == nil {
		if err := os.Chmod(temporaryFile, current.Mode().Perm()); err != nil {
			return fmt.Errorf("setting temporary offsets file permissions: %w", err)
		}
	}
	if err := writer.WriteResults(temporaryFile, results...); err != nil {
		return fmt.Errorf("writing generated offsets: %w", err)
	}
	generated, err := offsets.Open(temporaryFile)
	if err != nil {
		return fmt.Errorf("reading generated offsets: %w", err)
	}
	if err := validateCoverage(generated); err != nil {
		return err
	}
	if err := os.Rename(temporaryFile, outputFile); err != nil {
		return fmt.Errorf("publishing generated offsets: %w", err)
	}
	return nil
}

func validateCoverage(track *offsets.Track) error {
	definitions, err := goabi.Definitions("go999.0.0")
	if err != nil {
		return err
	}
	references := map[string]offsets.VersionInfo{}
	for _, definition := range definitions {
		coverage, err := factCoverage(track, definition.OutputType, definition.OutputField)
		if err != nil {
			return err
		}
		oldest, err := goversion.NewVersion(coverage.Oldest)
		if err != nil {
			return fmt.Errorf("invalid oldest version for ABI fact %s: %w", definition.Key(), err)
		}
		since, err := goversion.NewVersion(definition.Since)
		if err != nil {
			return fmt.Errorf("invalid minimum version for ABI fact %s: %w", definition.Key(), err)
		}
		if !oldest.Equal(since) {
			return fmt.Errorf("ABI fact %s starts at %s, expected %s", definition.Key(), coverage.Oldest, definition.Since)
		}
		if reference, ok := references[definition.Since]; ok && coverage != reference {
			return fmt.Errorf("ABI fact %s has coverage %v, expected %v", definition.Key(), coverage, reference)
		}
		references[definition.Since] = coverage
	}
	return nil
}

func factCoverage(track *offsets.Track, typeName, factName string) (offsets.VersionInfo, error) {
	fields, ok := track.Data[typeName]
	if !ok {
		return offsets.VersionInfo{}, fmt.Errorf("generated type %s is missing", typeName)
	}
	fact, ok := fields[factName]
	if !ok {
		return offsets.VersionInfo{}, fmt.Errorf("generated fact %s.%s is missing", typeName, factName)
	}
	return fact.Versions, nil
}

func cachedFacts(
	track *offsets.Track,
	release string,
	definitions []goabi.Definition,
) ([]*binary.DataMemberOffset, bool) {
	if track == nil {
		return nil, false
	}
	targetVersion, err := goversion.NewVersion(release)
	if err != nil {
		return nil, false
	}

	abi, err := goabi.FromLookup(release, func(definition goabi.Definition) (uint64, error) {
		fields, ok := track.Data[definition.OutputType]
		if !ok {
			return 0, errors.New("type not found")
		}
		field, ok := fields[definition.OutputField]
		if !ok {
			return 0, errors.New("fact not found")
		}
		newest, err := goversion.NewVersion(field.Versions.Newest)
		if err != nil || targetVersion.GreaterThan(newest) {
			return 0, errors.New("version not covered")
		}
		value, ok := track.Find(definition.OutputType, definition.OutputField, release)
		if !ok {
			return 0, errors.New("versioned fact not found")
		}
		return value, nil
	})
	if err != nil {
		return nil, false
	}

	facts := make([]*binary.DataMemberOffset, 0, len(definitions))
	for _, fact := range abi.Facts() {
		facts = append(facts, dataMember(fact))
	}
	return facts, true
}

func collectRelease(
	release string,
	inspectFile string,
) ([]*binary.DataMemberOffset, error) {
	executable, directory, err := downloader.DownloadBinaryFromRemote(inspectFile, release)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)

	file, err := elf.Open(executable)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	dwarfData, err := file.DWARF()
	if err != nil {
		return nil, err
	}
	abi, err := goabi.Extract(dwarfData, release)
	if err != nil {
		return nil, fmt.Errorf("reading Go %s ABI: %w", release, err)
	}

	facts := make([]*binary.DataMemberOffset, 0, len(abi.Facts()))
	for _, fact := range abi.Facts() {
		facts = append(facts, dataMember(fact))
	}
	return facts, nil
}

func configureGoBuild() func() {
	previous, existed := os.LookupEnv("GOFLAGS")
	// Go 1.27 makes x/net/http2 a wrapper. Inspect its legacy structs while the
	// standard-library query covers the replacement.
	_ = os.Setenv("GOFLAGS", strings.TrimSpace(previous+" -buildvcs=false -tags=http2legacy"))
	return func() {
		if existed {
			_ = os.Setenv("GOFLAGS", previous)
		} else {
			_ = os.Unsetenv("GOFLAGS")
		}
	}
}

func dataMember(fact goabi.Fact) *binary.DataMemberOffset {
	return &binary.DataMemberOffset{
		DataMember: &binary.DataMember{
			StructName: fact.Definition.OutputType,
			Field:      fact.Definition.OutputField,
		},
		Offset: fact.Value,
	}
}

func exitOnError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
