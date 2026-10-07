// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools/jvmlanguage"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: jvmlang-poc PID [PID ...]")
		os.Exit(2)
	}
	failed := false
	for _, arg := range os.Args[1:] {
		pid, err := strconv.Atoi(arg)
		result := jvmlanguage.Result{}
		if err == nil {
			result, err = jvmlanguage.DetectPID(pid)
		}
		output := struct {
			PID       int                `json:"pid"`
			Detection jvmlanguage.Result `json:"detection"`
			Resource  map[string]string  `json:"resource"`
			Error     string             `json:"error,omitempty"`
		}{PID: pid, Detection: result, Resource: map[string]string{}}
		if err != nil {
			failed = true
			output.Error = err.Error()
		} else {
			service := svc.Attrs{SDKLanguage: svc.InstrumentableJava, JVMLanguage: result.Language}
			for _, attr := range otelcfg.GetAppResourceAttrs(&meta.NodeMeta{}, &service) {
				if attr.Key == "jvm.language" || attr.Key == "telemetry.sdk.language" {
					output.Resource[string(attr.Key)] = attr.Value.AsString()
				}
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if failed {
		os.Exit(1)
	}
}
