// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJobTracesV2Refinement(t *testing.T) {
	cfg := exceptionDocument(t, `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["*/worker"]
          refine:
            group_job_spans: false
        - action: include
          match:
            process:
              exe_path_glob: ["*/server"]
`)
	require.True(t, cfg.JobTracesEnabled())
	var worker, server int
	for _, s := range cfg.Discovery.Instrument {
		switch {
		case s.Path.MatchString("/srv/worker") && !s.Path.MatchString("/srv/server"):
			worker++
			require.False(t, s.JobTraces.IsEnabled(), "the refined rule turns it off")
		case s.Path.MatchString("/srv/server") && !s.Path.MatchString("/srv/worker"):
			server++
			require.True(t, s.JobTraces.IsEnabled(), "a rule without refine.group_job_spans keeps the default")
		}
	}
	require.Equal(t, 1, worker)
	require.Equal(t, 1, server)
}

func TestJobTracesV2EnabledByDefault(t *testing.T) {
	cfg := exceptionDocument(t, `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["*/worker"]
`)
	require.True(t, cfg.JobTracesEnabled())
}

func TestJobTracesV2DisabledByEveryRule(t *testing.T) {
	cfg := exceptionDocument(t, `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
      rules:
        - action: include
          match:
            process:
              exe_path_glob: ["*/worker"]
          refine:
            group_job_spans: false
`)
	require.False(t, cfg.JobTracesEnabled())
}
