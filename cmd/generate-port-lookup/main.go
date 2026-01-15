// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"text/template"
)

const fileTemplate = `// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ../../../../../cmd/generate-port-lookup
//go:generate gofmt -w protocol.go

package transport

var generatedPortLookupTable = map[uint16]string{
{{- range $port, $svc := . }}
	{{ $port }}: "{{ $svc }}",
{{- end }}
}

func ApplicationPortToString(port uint16) string {
	svc := generatedPortLookupTable[port]
	if svc == "" {
		return "undefined"
	}
	return svc
}
`

func main() {
	f, err := os.Open("/etc/services")
	if err != nil {
		slog.Error("failed to open file", "err", err)
		return
	}
	defer f.Close()
	slog.Info("reading /etc/services")
	s := bufio.NewScanner(f)
	mapping := make(map[int]string)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if n, err := strconv.Atoi(strings.Split(fields[1], "/")[0]); err == nil {
			if n <= 1024 {
				mapping[n] = fields[0]
			}
		}
	}
	slog.Info("finished reading service file", "detected_services", len(mapping))

	tmpl, err := template.New("protocol.go").Parse(fileTemplate)
	if err != nil {
		slog.Error("failed to parse template", "err", err)
		return
	}

	out, err := os.Create("protocol.go")
	if err != nil {
		slog.Error("failed to open file for writing", "err", err)
		return
	}
	defer out.Close()
	if err := tmpl.Execute(out, mapping); err != nil {
		slog.Error("failed to execute template", "err", err)
		return
	}
	slog.Info("finished generating service lookup code")
}
