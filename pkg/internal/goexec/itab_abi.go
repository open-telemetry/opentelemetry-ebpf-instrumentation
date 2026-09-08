// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	trackeroffsets "github.com/grafana/go-offsets-tracker/pkg/offsets"

	"go.opentelemetry.io/obi/internal/goabi"
	"go.opentelemetry.io/obi/internal/goversion"
)

func loadGoRuntimeABI(ef *elf.File, goVersion goversion.Version) (goabi.ABI, error) {
	return resolveGoRuntimeABI(
		func() (goabi.ABI, error) {
			data, err := ef.DWARF()
			if err != nil {
				return goabi.ABI{}, err
			}
			return goabi.Extract(data, goVersion)
		},
		func() (goabi.ABI, error) {
			return loadGeneratedGoRuntimeABI(goVersion)
		},
	)
}

func resolveGoRuntimeABI(
	dynamic func() (goabi.ABI, error),
	generated func() (goabi.ABI, error),
) (goabi.ABI, error) {
	abi, dynamicErr := dynamic()
	if dynamicErr == nil {
		return abi, nil
	}
	abi, generatedErr := generated()
	if generatedErr == nil {
		return abi, nil
	}
	return goabi.ABI{}, fmt.Errorf(
		"go runtime ABI unavailable: %w",
		errors.Join(
			fmt.Errorf("DWARF discovery: %w", dynamicErr),
			fmt.Errorf("generated fallback: %w", generatedErr),
		),
	)
}

func loadGeneratedGoRuntimeABI(target goversion.Version) (goabi.ABI, error) {
	track, err := trackeroffsets.Read(bytes.NewBufferString(prefetchedOffsets))
	if err != nil {
		return goabi.ABI{}, fmt.Errorf("reading generated Go ABI facts: %w", err)
	}
	return goabi.FromLookup(target, func(requirement goabi.Requirement) (uint64, error) {
		return generatedABIFact(track, requirement.OutputType, requirement.OutputField, target)
	})
}

func generatedABIFact(
	track *trackeroffsets.Track,
	typeName string,
	factName string,
	target goversion.Version,
) (uint64, error) {
	fields, ok := track.Data[typeName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI type %s", typeName)
	}
	fact, ok := fields[factName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s", typeName, factName)
	}

	covered, err := generatedVersionCovered(target, fact.Versions.Oldest, fact.Versions.Newest)
	if err != nil {
		return 0, fmt.Errorf("invalid generated Go ABI coverage for %s.%s: %w", typeName, factName, err)
	}
	if !covered {
		return 0, fmt.Errorf("runtime ABI is not generated for %s", target.String())
	}

	value, ok := track.Find(typeName, factName, target.Release())
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s for %s", typeName, factName, target.String())
	}
	return value, nil
}

func generatedVersionCovered(target goversion.Version, oldestValue, newestValue string) (bool, error) {
	if strings.Contains(target.String(), "-") {
		return false, nil
	}
	oldest, err := goversion.Parse(oldestValue)
	if err != nil {
		return false, err
	}
	newest, err := goversion.Parse(newestValue)
	if err != nil {
		return false, err
	}
	return target.Compare(oldest) >= 0 && target.Compare(newest) <= 0, nil
}
