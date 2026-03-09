// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oats

import (
	"testing"

	"github.com/grafana/oats/yaml"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestYaml(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Yaml Suite")
}

var _ = Describe("test case", Label("docker", "integration", "slow"), func() {
	cases, base := yaml.ReadTestCases()
	if base != "" {
		It("should have at least one test case", func() {
			Expect(cases).ToNot(BeEmpty(), "expected at least one test case in %s", base)
		})
	}

	configuration, _ := GinkgoConfiguration()
	if configuration.ParallelTotal > 1 {
		ports := yaml.NewPortAllocator(len(cases))
		for _, c := range cases {
			// Pre-allocate ports before parallel execution to avoid collisions.
			c.PortConfig = ports.AllocatePorts()
		}
	}

	for _, c := range cases {
		Describe(c.Name, Ordered, func() {
			yaml.RunTestCase(c)
		})
	}
})
