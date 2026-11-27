// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
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

func (symbols kallsyms) target(symbol, patchDir string) (probeTarget, error) {
	owners := symbols[symbol]
	base := owners[""]
	if len(base.functions) != 1 {
		return probeTarget{}, fmt.Errorf("cannot identify a single vmlinux function for %q", symbol)
	}
	// The original entry can fire before livepatch redirects the call to its replacement.
	if addr := base.functions[0]; addr != 0 {
		return probeTarget{token: fmt.Sprintf("0x%x", addr)}, nil
	}
	if base.count != 1 {
		return probeTarget{}, fmt.Errorf("cannot disambiguate %q in vmlinux with hidden addresses", symbol)
	}
	if len(owners) == 1 {
		return probeTarget{token: symbol}, nil
	}

	module, err := activeLivepatch(patchDir, symbol)
	if err != nil || module == "" {
		return probeTarget{}, err
	}
	// Sysfs names the original function. Use a qualified name only if the patch defines that symbol.
	replacement := owners[module]
	if replacement.count != 1 || len(replacement.functions) != 1 {
		return probeTarget{}, fmt.Errorf("cannot identify function %q in livepatch %s", symbol, module)
	}
	return probeTarget{module: module, token: module + ":" + symbol}, nil
}
