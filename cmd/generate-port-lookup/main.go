// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
)

const fileTemplate = `// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Generated using services definition from
// {{ .ServicesURL }}

//go:generate go run ../../../../../cmd/generate-port-lookup
//go:generate gofmt -w protocol.go

package transport // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow/transport"

var generatedPortLookupTable = map[uint16]string{
{{- range $port, $svc := .Services }}
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

// servicesUrl currently points to the /etc/services file of the OpenBSD project.
// It offers a stable base and is permissively licensed.
const ServicesURL = "https://raw.githubusercontent.com/openbsd/src/28304016fe9353c375bc53e9b3d5bb67585d6a2a/etc/services"

const protocolsFile = "protocol.go"

func requiresRegeneration() bool {
	existing, err := os.Open(protocolsFile)
	if err != nil {
		slog.Warn("unable to open existing file, forcing rebuild", "err", err)
		return true
	}
	defer existing.Close()
	content, err := io.ReadAll(existing)
	if err != nil {
		slog.Warn("unable to read contents of existing file, forcing rebuild", "err", err)
		return true
	}
	return !strings.Contains(string(content), ServicesURL)
}

func main() {
	if !requiresRegeneration() {
		slog.Info("protocol file is up to date, skipping generation")
		return
	}
	resp, err := http.Get(ServicesURL)
	if err != nil {
		slog.Error("failed to get services file", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("reading services file")
	s := bufio.NewScanner(resp.Body)
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
		portdef := strings.Split(fields[1], "/")
		if n, err := strconv.Atoi(portdef[0]); err == nil {
			if portdef[1] == "udp" || portdef[1] == "tcp" {
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

	out, err := os.Create(protocolsFile)
	if err != nil {
		slog.Error("failed to open file for writing", "err", err)
		return
	}
	defer out.Close()
	if err := tmpl.Execute(out, map[string]any{
		"ServicesURL": ServicesURL,
		"Services":    mapping,
	}); err != nil {
		slog.Error("failed to execute template", "err", err)
		return
	}
	slog.Info("finished generating service lookup code")
}
