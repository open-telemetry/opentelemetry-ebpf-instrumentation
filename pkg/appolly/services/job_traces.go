// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

// JobTracesConfig roots a job's calls at the queue fetch that took it, see devdocs/queue-job-traces.md
type JobTracesConfig struct {
	Enabled bool `yaml:"enabled"`
}

func (c *JobTracesConfig) IsEnabled() bool {
	return c != nil && c.Enabled
}
