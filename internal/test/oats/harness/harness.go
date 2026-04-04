// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness // import "go.opentelemetry.io/obi/internal/test/oats/harness"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/grafana/oats/model"
	"github.com/grafana/oats/testhelpers/remote"
	oatsyaml "github.com/grafana/oats/yaml"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
)

const suiteName = "Yaml Suite"

func RunSpecs(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, suiteName)
}

func RegisterSuite() bool {
	return ginkgo.Describe("test case", ginkgo.Label("docker", "integration", "slow"), func() {
		cases, base := readTestCases()
		if base != "" {
			ginkgo.It("should have at least one test case", func() {
				gomega.Expect(cases).ToNot(gomega.BeEmpty(), "expected at least one test case in %s", base)
			})
		}

		oatsyaml.VerboseLogging = true
		settings := testCaseSettings()

		for i := range cases {
			c := cases[i]
			ginkgo.It(c.Name, func() {
				runTestCase(&c, settings)
			})
		}
	})
}

func readTestCases() ([]model.TestCase, string) {
	base := os.Getenv("TESTCASE_BASE_PATH")
	if base == "" {
		return nil, ""
	}

	cases, err := oatsyaml.ReadTestCases([]string{base}, true)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	return cases, base
}

func runTestCase(c *model.TestCase, settings model.Settings) {
	format.MaxLength = 100000
	if settings.ManualDebug {
		oatsyaml.RunTestCase(c, settings)
		return
	}

	c.OutputDir = oatsyaml.PrepareBuildDir(c.Name)
	c.ValidateAndSetVariables(gomega.Default)

	logFile := filepath.Join(c.OutputDir, fmt.Sprintf("output-%s.log", c.Name))
	endpoint, err := startEndpoint(c, settings, logFile)
	gomega.Expect(err).ToNot(gomega.HaveOccurred(), "expected no error creating an observability endpoint")
	err = endpoint.Start(context.Background())
	gomega.Expect(err).ToNot(gomega.HaveOccurred(), "expected no error starting an observability endpoint")

	defer func() {
		stopErr := endpoint.Stop(context.Background())
		gomega.Expect(stopErr).ToNot(gomega.HaveOccurred(), "expected no error stopping the local observability endpoint")
	}()

	runner := oatsyaml.NewRunner(c, settings)
	setRunnerEndpoint(runner, endpoint)
	runner.ExecuteChecks()
}

func setRunnerEndpoint(runner *oatsyaml.Runner, endpoint *remote.Endpoint) {
	field := reflect.ValueOf(runner).Elem().FieldByName("endpoint")
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(endpoint))
}

func testCaseSettings() model.Settings {
	timeout := 30 * time.Second
	if value := os.Getenv("TESTCASE_TIMEOUT"); value != "" {
		var err error
		timeout, err = time.ParseDuration(value)
		gomega.Expect(err).ToNot(gomega.HaveOccurred())
	}

	return model.Settings{
		Host:          "localhost",
		Timeout:       timeout,
		AbsentTimeout: 10 * time.Second,
		LgtmVersion:   "latest",
		LgtmLogSettings: map[string]bool{
			"ENABLE_LOGS_ALL":        false,
			"ENABLE_LOGS_GRAFANA":    false,
			"ENABLE_LOGS_PROMETHEUS": false,
			"ENABLE_LOGS_LOKI":       false,
			"ENABLE_LOGS_TEMPO":      false,
			"ENABLE_LOGS_PYROSCOPE":  false,
			"ENABLE_LOGS_OTELCOL":    false,
		},
		ManualDebug: os.Getenv("TESTCASE_MANUAL_DEBUG") == "true",
		LogLimit:    1000,
	}
}
