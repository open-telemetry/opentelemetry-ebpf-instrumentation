// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
)

type probeTarget struct {
	module string
	token  string
}

// The kernel counts data symbols too when it decides whether a name is ambiguous.
type symbolLocations struct {
	count     int
	functions []uint64
}

// The empty module in /proc/kallsyms denotes vmlinux.
type kallsyms map[string]map[string]symbolLocations

func readSymbols(path string, wanted map[string]bool) (kallsyms, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := kallsyms{}
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		address, rest := cutField(lines.Bytes())
		kind, rest := cutField(rest)
		name, owner := cutField(rest)

		if len(kind) != 1 || !wanted[string(name)] {
			continue
		}

		sym := string(name)
		if result[sym] == nil {
			result[sym] = map[string]symbolLocations{}
		}

		module := string(bytes.Trim(owner, "[] \t"))
		locations := result[sym][module]
		locations.count++

		// t, T covers code, w and W cover weak symbols
		if bytes.ContainsAny(kind, "tTwW") {
			addr, err := strconv.ParseUint(string(address), 16, 64)
			if err != nil {
				return nil, fmt.Errorf("reading address for %s: %w", name, err)
			}
			locations.functions = append(locations.functions, addr)
		}

		result[sym][module] = locations
	}

	return result, lines.Err()
}

// Avoid allocating a slice of fields for every line in /proc/kallsyms.
func cutField(line []byte) (field, rest []byte) {
	line = bytes.TrimLeft(line, " \t")
	if end := bytes.IndexAny(line, " \t"); end >= 0 {
		return line[:end], line[end+1:]
	}

	return line, nil
}

func (symbols kallsyms) resolveName(symbol string) string {
	for _, name := range [2]string{symbol, syscallPrefix() + symbol} {
		for _, locations := range symbols[name] {
			if len(locations.functions) > 0 {
				return name
			}
		}
	}

	return symbol
}

func (symbols kallsyms) ambiguousFunction(name string) bool {
	count := 0
	hasFunction := false
	for _, locations := range symbols[name] {
		count += locations.count
		hasFunction = hasFunction || len(locations.functions) > 0
		if count > 1 && hasFunction {
			return true
		}
	}
	return false
}

func (symbols kallsyms) targets(symbol string, modules map[string]bool) (map[probeTarget]bool, error) {
	owners := symbols[symbol]
	targets := map[probeTarget]bool{}
	var err error

	for module, locations := range owners {
		if len(locations.functions) == 0 || (modules != nil && !modules[module]) {
			continue
		}

		if module != "" && locations.count == 1 {
			// Qualified names follow the module across unload/reload and also work with kptr_restrict.
			targets[probeTarget{module, module + ":" + symbol}] = true
			continue
		}

		for _, addr := range locations.functions {
			switch {
			case addr != 0:
				targets[probeTarget{module, fmt.Sprintf("0x%x", addr)}] = true
			case len(owners) == 1 && locations.count == 1:
				targets[probeTarget{module, symbol}] = true
			default:
				err = fmt.Errorf("cannot disambiguate %s: kernel symbol addresses are hidden", symbol)
			}
		}
	}

	// The livepatch ABI names the original function. A replacement may have a different name.
	var missing []string
	for module := range modules {
		if len(owners[module].functions) == 0 {
			missing = append(missing, module)
		}
	}

	if len(missing) > 0 {
		slices.Sort(missing)
		err = errors.Join(err, fmt.Errorf("no symbol %q in livepatch modules %v", symbol, missing))
	}

	return targets, err
}
