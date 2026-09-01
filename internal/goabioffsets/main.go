// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Command goabioffsets collects versioned Go runtime ABI facts from DWARF.
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

type input struct {
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
	inputFile := flag.String("i", "", "input JSON file describing required ABI facts")
	flag.Parse()
	if *inputFile == "" || flag.NArg() != 1 {
		log.Fatal("usage: goabioffsets -i <input file> <output file>")
	}
	outputFile := flag.Arg(0)

	inputData, err := os.ReadFile(*inputFile)
	exitOnError(err)
	var config input
	exitOnError(json.Unmarshal(inputData, &config))
	if config.Inspect == "" {
		log.Fatal("inspect source is required")
	}

	constraint, err := goversion.NewConstraint(config.Versions)
	exitOnError(err)
	queries, err := buildQueries(config)
	exitOnError(err)

	available, err := versions.FindVersionsFromGoWebsite()
	exitOnError(err)
	sort.Slice(available, func(i, j int) bool {
		left, leftErr := goversion.NewVersion(available[i])
		right, rightErr := goversion.NewVersion(available[j])
		return leftErr == nil && rightErr == nil && left.LessThan(right)
	})

	var cache *offsets.Track
	if existing, openErr := offsets.Open(outputFile); openErr == nil {
		cache = existing
	}

	result := &target.Result{ModuleName: "go"}
	for _, release := range available {
		parsed, parseErr := goversion.NewVersion(release)
		if parseErr != nil || !constraint.Check(parsed) {
			continue
		}

		facts, ok := cachedFacts(cache, release, queries)
		if !ok {
			log.Printf("collecting Go %s runtime ABI facts", release)
			facts, err = collectRelease(release, config.Inspect, queries)
			exitOnError(err)
		}
		result.ResultsByVersion = append(result.ResultsByVersion, &target.VersionedResult{
			Version:    release,
			OffsetData: &binary.Result{DataMembers: facts},
		})
	}

	if len(result.ResultsByVersion) == 0 {
		log.Fatal("no Go releases matched the configured version constraint")
	}
	exitOnError(writer.WriteResults(outputFile, result))
}

func buildQueries(config input) ([]query, error) {
	queries := make([]query, 0, len(config.Sizes)+len(config.Constants))
	for typeName, fields := range config.Fields {
		for _, field := range fields {
			queries = append(queries, query{
				kind:        queryField,
				dwarfName:   typeName,
				dwarfField:  field,
				outputType:  typeName,
				outputField: field,
			})
		}
	}
	for _, typeName := range config.Sizes {
		queries = append(queries, query{
			kind:        querySize,
			dwarfName:   typeName,
			outputType:  typeName,
			outputField: sizeField,
		})
	}
	for _, constant := range config.Constants {
		separator := strings.LastIndexByte(constant, '.')
		if separator < 0 {
			return nil, fmt.Errorf("constant %q is not package-qualified", constant)
		}
		queries = append(queries, query{
			kind:        queryConstant,
			dwarfName:   constant,
			outputType:  constant[:separator],
			outputField: constant[separator+1:],
		})
	}
	sort.Slice(queries, func(i, j int) bool {
		if queries[i].outputType == queries[j].outputType {
			return queries[i].outputField < queries[j].outputField
		}
		return queries[i].outputType < queries[j].outputType
	})
	return queries, nil
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
	restoreGoFlags := disableVCSStamping()
	defer restoreGoFlags()

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

func disableVCSStamping() func() {
	previous, existed := os.LookupEnv("GOFLAGS")
	_ = os.Setenv("GOFLAGS", strings.TrimSpace(previous+" -buildvcs=false"))
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
