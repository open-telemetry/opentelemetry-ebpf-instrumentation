// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

// nodejs.enabled is the global injection opt-out: with the flag off the
// injector stays disabled even when the application_runtime feature would
// otherwise trigger the agent for runtime metrics.
func TestEnabledFlagDisablesInjectionEntirely(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = false
	cfg.Metrics.Features = export.FeatureApplicationRuntime
	require.False(t, NewNodeInjector(&cfg).Enabled())

	cfg.NodeJS.Enabled = true
	require.True(t, NewNodeInjector(&cfg).Enabled())
}

func TestNewExecutableSkipsDeno(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.TracePrinter = debug.TracePrinterText

	injector := NewNodeInjector(&cfg)
	require.True(t, injector.Enabled())
	require.NotPanics(t, func() {
		injector.NewExecutable(&ebpf.Instrumentable{Type: svc.InstrumentableDeno})
	})
}

func newTestInjector() *NodeInjector {
	cfg := obi.DefaultConfig
	return NewNodeInjector(&cfg)
}

// OBI may only close an inspector it opened itself, so it has to recognize the
// ones the process asked for.
func TestProcessRequestedInspector(t *testing.T) {
	errUnreadable := errors.New("unreadable")

	for _, tc := range []struct {
		name       string
		args       []string
		env        map[string]string
		cmdlineErr error
		envErr     error
		want       bool
	}{
		{name: "no inspector requested", args: []string{"node", "app.js"}},
		{name: "command line flag", args: []string{"node", "--inspect", "app.js"}, want: true},
		{name: "command line flag with a value", args: []string{"node", "--inspect-brk=0.0.0.0:9229"}, want: true},
		{name: "node options", args: []string{"node", "app.js"}, env: map[string]string{"NODE_OPTIONS": "--inspect-port=9230"}, want: true},
		{name: "node options without the flag", args: []string{"node", "app.js"}, env: map[string]string{"NODE_OPTIONS": "--max-old-space-size=512"}},
		{name: "command line unreadable, node options answer", cmdlineErr: errUnreadable, env: map[string]string{"NODE_OPTIONS": "--inspect"}, want: true},
		{name: "nothing readable", cmdlineErr: errUnreadable, envErr: errUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmdlineForPID = func(app.PID) (string, []string, error) {
				return "node", tc.args, tc.cmdlineErr
			}
			envVarsForPID = func(app.PID) (map[string]string, error) {
				return tc.env, tc.envErr
			}
			t.Cleanup(func() {
				cmdlineForPID = ebpfcommon.CMDLineForPID
				envVarsForPID = procs.EnvVars
			})

			require.Equal(t, tc.want, processRequestedInspector(1))
		})
	}
}

// stubProcessWithoutInspectorFlag makes the ownership probe report a process
// that did not ask for the inspector, so OBI owns whatever is listening.
func stubProcessWithoutInspectorFlag(t *testing.T) {
	t.Helper()

	cmdlineForPID = func(app.PID) (string, []string, error) {
		return "node", []string{"node", "app.js"}, nil
	}
	envVarsForPID = func(app.PID) (map[string]string, error) {
		return nil, nil
	}

	t.Cleanup(func() {
		cmdlineForPID = ebpfcommon.CMDLineForPID
		envVarsForPID = procs.EnvVars
	})
}
