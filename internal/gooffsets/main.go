// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command gooffsets collects versioned Go field offsets and runtime ABI facts.
package main

import (
	"debug/dwarf"
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
)

const sizeField = "$size"

type abiInput struct {
	Versions  string              `json:"versions"`
	Inspect   string              `json:"inspect"`
	Fields    map[string][]string `json:"fields"`
	Sizes     []string            `json:"sizes"`
	Constants []string            `json:"constants"`
}

type queryKind uint8

const (
	queryField queryKind = iota
	querySize
	queryConstant
)

type query struct {
	kind        queryKind
	dwarfName   string
	dwarfField  string
	outputType  string
	outputField string
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
	abiResult, queries, err := collectABIFacts(abiConfig, outputFile)
	if err != nil {
		return err
	}
	results = append(results, abiResult)

	if err := validateDistinctResults(results); err != nil {
		return err
	}
	return writeResultsAtomic(outputFile, queries, results)
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

func collectABIFacts(config abiInput, cacheFile string) (*target.Result, []query, error) {
	constraint, err := goversion.NewConstraint(config.Versions)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid ABI Go version constraint: %w", err)
	}
	queries, err := buildQueries(config)
	if err != nil {
		return nil, nil, err
	}

	available, err := versions.FindVersionsFromGoWebsite()
	if err != nil {
		return nil, nil, err
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

		facts, ok := cachedFacts(cache, release, queries)
		if !ok {
			log.Printf("collecting Go %s runtime ABI facts", release)
			facts, err = collectRelease(release, config.Inspect, queries)
			if err != nil {
				return nil, nil, err
			}
		}
		result.ResultsByVersion = append(result.ResultsByVersion, &target.VersionedResult{
			Version:    release,
			OffsetData: &binary.Result{DataMembers: facts},
		})
	}
	if len(result.ResultsByVersion) == 0 {
		return nil, nil, errors.New("no Go releases matched the ABI version constraint")
	}
	return result, queries, nil
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

func writeResultsAtomic(outputFile string, queries []query, results []*target.Result) (retErr error) {
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
	if err := validateCoverage(generated, queries); err != nil {
		return err
	}
	if err := os.Rename(temporaryFile, outputFile); err != nil {
		return fmt.Errorf("publishing generated offsets: %w", err)
	}
	return nil
}

var moduledataABIFacts = [...]string{"types", "typedesclen", "itaboffset", "itabsize"}

func validateCoverage(track *offsets.Track, queries []query) error {
	if len(queries) == 0 {
		return errors.New("no ABI facts configured")
	}
	reference, err := factCoverage(track, queries[0].outputType, queries[0].outputField)
	if err != nil {
		return err
	}
	for _, q := range queries[1:] {
		coverage, err := factCoverage(track, q.outputType, q.outputField)
		if err != nil {
			return err
		}
		if coverage != reference {
			return fmt.Errorf("ABI fact %s has coverage %v, expected %v", queryKey(q), coverage, reference)
		}
	}
	for _, field := range moduledataABIFacts {
		coverage, err := factCoverage(track, "runtime.moduledata", field)
		if err != nil {
			return err
		}
		if coverage != reference {
			return fmt.Errorf("runtime.moduledata.%s has coverage %v, expected %v", field, coverage, reference)
		}
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

func buildQueries(config abiInput) ([]query, error) {
	queries := make([]query, 0, len(config.Sizes)+len(config.Constants))
	seen := map[string]struct{}{}
	for typeName, fields := range config.Fields {
		for _, field := range fields {
			q := query{
				kind:        queryField,
				dwarfName:   typeName,
				dwarfField:  field,
				outputType:  typeName,
				outputField: field,
			}
			if err := appendQuery(&queries, seen, q); err != nil {
				return nil, err
			}
		}
	}
	for _, typeName := range config.Sizes {
		q := query{
			kind:        querySize,
			dwarfName:   typeName,
			outputType:  typeName,
			outputField: sizeField,
		}
		if err := appendQuery(&queries, seen, q); err != nil {
			return nil, err
		}
	}
	for _, constant := range config.Constants {
		separator := strings.LastIndexByte(constant, '.')
		if separator < 0 {
			return nil, fmt.Errorf("constant %q is not package-qualified", constant)
		}
		q := query{
			kind:        queryConstant,
			dwarfName:   constant,
			outputType:  constant[:separator],
			outputField: constant[separator+1:],
		}
		if err := appendQuery(&queries, seen, q); err != nil {
			return nil, err
		}
	}
	sort.Slice(queries, func(i, j int) bool {
		if queries[i].outputType == queries[j].outputType {
			return queries[i].outputField < queries[j].outputField
		}
		return queries[i].outputType < queries[j].outputType
	})
	return queries, nil
}

func appendQuery(queries *[]query, seen map[string]struct{}, q query) error {
	key := queryKey(q)
	if _, ok := seen[key]; ok {
		return fmt.Errorf("ABI fact %s is configured more than once", key)
	}
	seen[key] = struct{}{}
	*queries = append(*queries, q)
	return nil
}

func cachedFacts(track *offsets.Track, release string, queries []query) ([]*binary.DataMemberOffset, bool) {
	if track == nil {
		return nil, false
	}
	targetVersion, err := goversion.NewVersion(release)
	if err != nil {
		return nil, false
	}

	facts := make([]*binary.DataMemberOffset, 0, len(queries))
	for _, q := range queries {
		fields, ok := track.Data[q.outputType]
		if !ok {
			return nil, false
		}
		field, ok := fields[q.outputField]
		if !ok {
			return nil, false
		}
		newest, err := goversion.NewVersion(field.Versions.Newest)
		if err != nil || targetVersion.GreaterThan(newest) {
			return nil, false
		}
		value, ok := track.Find(q.outputType, q.outputField, release)
		if !ok {
			return nil, false
		}
		facts = append(facts, dataMember(q, value))
	}
	return facts, true
}

func collectRelease(
	release string,
	inspectFile string,
	queries []query,
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
	values, err := readDWARF(dwarfData, queries)
	if err != nil {
		return nil, fmt.Errorf("reading Go %s ABI: %w", release, err)
	}

	facts := make([]*binary.DataMemberOffset, 0, len(queries))
	for _, q := range queries {
		value, ok := values[queryKey(q)]
		if !ok {
			return nil, fmt.Errorf("go %s ABI fact %s.%s not found", release, q.outputType, q.outputField)
		}
		facts = append(facts, dataMember(q, value))
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

func readDWARF(data *dwarf.Data, queries []query) (map[string]uint64, error) {
	typeQueries := map[string][]query{}
	constantQueries := map[string]query{}
	for _, q := range queries {
		if q.kind == queryConstant {
			constantQueries[q.dwarfName] = q
		} else {
			typeQueries[q.dwarfName] = append(typeQueries[q.dwarfName], q)
		}
	}

	values := map[string]uint64{}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		if q, ok := constantQueries[name]; ok && entry.Tag == dwarf.TagConstant {
			value, err := unsignedValue(entry.Val(dwarf.AttrConstValue))
			if err != nil {
				return nil, fmt.Errorf("reading constant %s: %w", name, err)
			}
			if err := storeValue(values, queryKey(q), value); err != nil {
				return nil, err
			}
		}

		requested := typeQueries[name]
		if len(requested) == 0 {
			continue
		}
		for _, q := range requested {
			switch q.kind {
			case querySize:
				value, err := unsignedValue(entry.Val(dwarf.AttrByteSize))
				if err != nil {
					continue
				}
				if err := storeValue(values, queryKey(q), value); err != nil {
					return nil, err
				}
			case queryField:
				typeInfo, err := data.Type(entry.Offset)
				if err != nil {
					continue
				}
				structInfo, ok := typeInfo.(*dwarf.StructType)
				if !ok {
					continue
				}
				for _, field := range structInfo.Field {
					if field.Name == q.dwarfField {
						if field.ByteOffset < 0 {
							return nil, fmt.Errorf("negative offset for %s.%s", name, q.dwarfField)
						}
						if err := storeValue(values, queryKey(q), uint64(field.ByteOffset)); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	return values, nil
}

func unsignedValue(value any) (uint64, error) {
	switch value := value.(type) {
	case int64:
		if value < 0 {
			return 0, errors.New("negative value")
		}
		return uint64(value), nil
	case uint64:
		return value, nil
	default:
		return 0, fmt.Errorf("unexpected DWARF value type %T", value)
	}
}

func storeValue(values map[string]uint64, key string, value uint64) error {
	if previous, ok := values[key]; ok && previous != value {
		return fmt.Errorf("conflicting values for %s: %d and %d", key, previous, value)
	}
	values[key] = value
	return nil
}

func queryKey(q query) string {
	return q.outputType + "." + q.outputField
}

func dataMember(q query, value uint64) *binary.DataMemberOffset {
	return &binary.DataMemberOffset{
		DataMember: &binary.DataMember{StructName: q.outputType, Field: q.outputField},
		Offset:     value,
	}
}

func exitOnError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
