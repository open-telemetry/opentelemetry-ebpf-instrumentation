// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/obi/internal/test/weavercheck"
)

type validationResult struct {
	errs []error
}

func (*validationResult) Helper() {}
func (r *validationResult) Logf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func (r *validationResult) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}
func (r *validationResult) FailNow() { panic(validationFailNow{}) }

type validationFailNow struct{}

func validateReport(report *weavercheck.Report) (err error) {
	validation := &validationResult{}
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ok := recovered.(validationFailNow); !ok {
				panic(recovered)
			}
		}
		err = errors.Join(validation.errs...)
	}()
	weavercheck.Validate(validation, report)
	return errors.Join(validation.errs...)
}

func main() {
	adminURL := flag.String("admin-url", "http://127.0.0.1:4320", "Weaver admin API URL")
	artifactDir := flag.String("artifact-dir", "build", "directory for raw Weaver JSON")
	name := flag.String("name", "oats", "Weaver report name")
	flag.Parse()

	if err := run(*adminURL, *artifactDir, *name); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(adminURL, artifactDir, name string) error {
	var errs []error
	if err := weavercheck.DrainDockerTap(context.Background(), func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}); err != nil {
		errs = append(errs, fmt.Errorf("draining Weaver tap: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	raw, err := weavercheck.FetchRawReport(ctx, adminURL)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("fetching Weaver report: %w", err))...)
	}
	path, err := weavercheck.ArchiveReport(artifactDir, name, raw)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("archiving Weaver report: %w", err))...)
	}
	fmt.Printf("weaver report saved to %s\n", path)
	report, err := weavercheck.Parse(raw)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	if err := validateReport(report); err != nil {
		errs = append(errs, fmt.Errorf("weaver validation: %w", err))
	}
	return errors.Join(errs...)
}
