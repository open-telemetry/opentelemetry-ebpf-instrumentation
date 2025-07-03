package goexec

import (
	"debug/elf"
	"fmt"
	"strings"
)

func findInterfaceImpls(ef *elf.File) (map[string]uint64, error) {
	implementations := map[string]uint64{}
	symbols, err := ef.Symbols()
	if err != nil {
		return nil, fmt.Errorf("accessing symbols table: %w", err)
	}
	for _, s := range symbols {
		// Name is in format: go:itab.*net/http.response,net/http.ResponseWriter
		if !strings.Contains(s.Name, "go:itab.") {
			continue
		}
		parts := strings.Split(s.Name[len("go:itab."):], ",")
		if len(parts) < 2 {
			continue
		}
		implementations[parts[0]] = s.Value
	}
	return implementations, nil
}
