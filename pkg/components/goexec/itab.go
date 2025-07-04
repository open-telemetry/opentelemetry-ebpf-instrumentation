package goexec

import (
	"debug/elf"
	"fmt"
	"strings"
)

const (
	prefixNew = "go:itab."
	prefixOld = "go.itab."
	prefixLen = len(prefixNew)
)

func findInterfaceImpls(ef *elf.File) (map[string]uint64, error) {
	implementations := map[string]uint64{}
	symbols, err := ef.Symbols()
	if err != nil {
		return nil, fmt.Errorf("accessing symbols table: %w", err)
	}
	for _, s := range symbols {
		// Name is in format: go:itab.*net/http.response,net/http.ResponseWriter or go.itab.*net/http.response,net/http.ResponseWriter on old versions
		if !strings.Contains(s.Name, prefixNew) && !strings.Contains(s.Name, prefixOld) {
			continue
		}
		parts := strings.Split(s.Name[prefixLen:], ",")
		if len(parts) < 2 {
			continue
		}
		implementations[parts[0]] = s.Value
	}
	return implementations, nil
}
