// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// The NVML helper reads the state of the NVIDIA GPUs of the host through the
// NVIDIA Management Library and prints it as JSON, one sample per line.
//
// OBI is a statically linked binary and cannot load a shared library, so it
// embeds this program and runs it as a child process against the host's
// filesystem, where the NVIDIA driver installs the library.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

func main() {
	interval := flag.Duration("interval", 30*time.Second, "time between two samples")
	flag.Parse()

	if err := run(*interval); err != nil {
		fmt.Fprintln(os.Stderr, err)

		if errors.Is(err, errNoLibrary) {
			os.Exit(sample.ExitNoLibrary)
		}
		os.Exit(1)
	}
}

func run(interval time.Duration) error {
	lib, err := openLibrary()
	if err != nil {
		return err
	}

	if err := lib.check("initializing NVML", lib.Init()); err != nil {
		return err
	}
	defer lib.Shutdown()

	c, err := newCollector(lib)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(os.Stdout)
	for ticker := time.NewTicker(interval); ; <-ticker.C {
		if err := encoder.Encode(c.sample()); err != nil {
			return fmt.Errorf("writing sample: %w", err)
		}
	}
}
