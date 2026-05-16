// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/obi"
)

func main() {
	encoder := yaml.NewEncoder(os.Stdout)

	if err := encoder.Encode(obi.DefaultConfig); err != nil {
		log.Fatalf("Error encoding YAML to stdout: %v", err)
	}
	if err := encoder.Close(); err != nil {
		log.Fatalf("Error closing encoder: %v", err)
	}
}
