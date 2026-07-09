// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"

	"golang.org/x/mod/semver"
)

type RuntimeMetricSymbols struct {
	MemstatsAddr                 uint64
	GCControllerAddr             uint64
	GOMAXPROCSAddr               uint64
	WorkAddr                     uint64
	SchedAddr                    uint64
	AllgLenAddr                  uint64
	AllpAddr                     uint64
	SizeClassToSizesAddr         uint64
	GoroutineCountIncludesSystem bool
}

const (
	runtimeMetricMemstatsSymbol                 = "runtime.memstats"
	runtimeMetricGCControllerSymbol             = "runtime.gcController"
	runtimeMetricGOMAXPROCSSymbol               = "runtime.gomaxprocs"
	runtimeMetricWorkSymbol                     = "runtime.work"
	runtimeMetricSchedSymbol                    = "runtime.sched"
	runtimeMetricAllgLenSymbol                  = "runtime.allglen"
	runtimeMetricAllpSymbol                     = "runtime.allp"
	runtimeMetricSizeClassToSizesSymbol         = "runtime.class_to_size"
	runtimeMetricInternalSizeClassToSizesSymbol = "internal/runtime/gc.SizeClassToSize"
)

var runtimeMetricGoVersionPattern = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// ResolveRuntimeMetricSymbols resolves Go runtime global variables to absolute
// process addresses. Userspace provides only this metadata; BPF still reads the
// actual runtime metric values from the target process memory.
func ResolveRuntimeMetricSymbols(file *exec.FileInfo, pid app.PID) (RuntimeMetricSymbols, error) {
	if file == nil || file.ELF() == nil {
		return RuntimeMetricSymbols{}, errors.New("missing executable file info")
	}

	loadBias, err := procs.FindExeLoadBias(pid)
	if err != nil {
		return RuntimeMetricSymbols{}, fmt.Errorf("reading executable load bias: %w", err)
	}

	symbols, err := resolveRuntimeMetricSymbols(file.ELF(), loadBias)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	// Go 1.26 changed the goroutine count semantics used by runtime metrics.
	// Pass only the version-derived mode to BPF.
	symbols.GoroutineCountIncludesSystem = runtimeMetricGoroutineCountIncludesSystem(file.ELF())
	return symbols, nil
}

func resolveRuntimeMetricSymbols(f *elf.File, loadBias uint64) (RuntimeMetricSymbols, error) {
	symbols, err := procs.FindExeSymbols(f, []string{
		runtimeMetricMemstatsSymbol,
		runtimeMetricGCControllerSymbol,
		runtimeMetricGOMAXPROCSSymbol,
		runtimeMetricWorkSymbol,
		runtimeMetricSchedSymbol,
		runtimeMetricAllgLenSymbol,
		runtimeMetricAllpSymbol,
		runtimeMetricSizeClassToSizesSymbol,
		runtimeMetricInternalSizeClassToSizesSymbol,
	}, elf.STT_OBJECT)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}

	memstats, ok := symbols[runtimeMetricMemstatsSymbol]
	if !ok {
		return RuntimeMetricSymbols{}, fmt.Errorf("runtime symbol %s not found", runtimeMetricMemstatsSymbol)
	}
	gcController, ok := symbols[runtimeMetricGCControllerSymbol]
	if !ok {
		return RuntimeMetricSymbols{}, fmt.Errorf("runtime symbol %s not found", runtimeMetricGCControllerSymbol)
	}
	gomaxprocs, ok := symbols[runtimeMetricGOMAXPROCSSymbol]
	if !ok {
		return RuntimeMetricSymbols{}, fmt.Errorf("runtime symbol %s not found", runtimeMetricGOMAXPROCSSymbol)
	}

	return RuntimeMetricSymbols{
		MemstatsAddr:         loadBias + memstats.Off,
		GCControllerAddr:     loadBias + gcController.Off,
		GOMAXPROCSAddr:       loadBias + gomaxprocs.Off,
		WorkAddr:             runtimeMetricSymbolAddr(symbols, runtimeMetricWorkSymbol, loadBias),
		SchedAddr:            runtimeMetricSymbolAddr(symbols, runtimeMetricSchedSymbol, loadBias),
		AllgLenAddr:          runtimeMetricSymbolAddr(symbols, runtimeMetricAllgLenSymbol, loadBias),
		AllpAddr:             runtimeMetricSymbolAddr(symbols, runtimeMetricAllpSymbol, loadBias),
		SizeClassToSizesAddr: runtimeMetricSymbolAddr(symbols, runtimeMetricSizeClassToSizesSymbol, loadBias),
	}, nil
}

func runtimeMetricSymbolAddr(symbols map[string]procs.Sym, name string, loadBias uint64) uint64 {
	if sym, ok := symbols[name]; ok {
		return loadBias + sym.Off
	}
	if name == runtimeMetricSizeClassToSizesSymbol {
		if sym, ok := symbols[runtimeMetricInternalSizeClassToSizesSymbol]; ok {
			return loadBias + sym.Off
		}
	}
	return 0
}

// runtimeMetricGoroutineCountIncludesSystem reports whether the target Go
// runtime's goroutine metric already includes system goroutines.
func runtimeMetricGoroutineCountIncludesSystem(f *elf.File) bool {
	goVersion, _, err := getGoDetails(f)
	if err != nil {
		return false
	}
	return runtimeMetricGoroutineCountIncludesSystemVersion(goVersion)
}

// runtimeMetricGoroutineCountIncludesSystemVersion applies the goroutine-count
// cutoff introduced in Go 1.26 to raw Go build-version strings.
func runtimeMetricGoroutineCountIncludesSystemVersion(goVersion string) bool {
	match := runtimeMetricGoVersionPattern.FindString(goVersion)
	if match == "" {
		return false
	}
	return semver.Compare("v"+strings.TrimPrefix(match, "v"), "v1.26.0") >= 0
}
