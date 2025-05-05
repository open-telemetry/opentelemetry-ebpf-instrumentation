package exec

import (
	"debug/elf"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/internal/svc"
)

func FindProcLanguage(_ int32) svc.InstrumentableType {
	return svc.InstrumentableGeneric
}

func FindExeSymbols(_ *elf.File, _ []string) (map[string]Sym, error) {
	return nil, nil
}
