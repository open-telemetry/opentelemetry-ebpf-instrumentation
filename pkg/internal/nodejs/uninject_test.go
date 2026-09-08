// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
)

// The uninstall pass is both agent scripts with every gate left off: each
// prologue tears down the previous injection and the gated bodies are then
// skipped. A gate that ever defaults to on would turn the uninstall into a
// reinstall.
func TestUninstallCodeLeavesEveryGateOff(t *testing.T) {
	code := uninstallCode()

	require.Contains(t, code, rtEnabledPlaceholder)
	require.Contains(t, code, tracesEnabledPlaceholder)
	require.Contains(t, code, spansEnabledPlaceholder)
	require.NotContains(t, code, rtEnabledOn)
	require.NotContains(t, code, tracesEnabledOn)
	require.NotContains(t, code, spansEnabledOn)
}

// The uninstall pass must carry the bridge too, otherwise a manual-spans
// deployment leaves it resident.
func TestUninstallCodeIncludesSpanBridge(t *testing.T) {
	require.Contains(t, uninstallCode(), "__obiSpanBridge")
}

// The bridge only ships when manual spans are on, and it ships with its gate
// substituted: an unsubstituted gate would install nothing at all.
func TestAgentCodeGatesSpanBridge(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.ManualSpans = false
	require.NotContains(t, NewNodeInjector(&cfg).agentCode(), "__obiSpanBridge")

	cfg.NodeJS.ManualSpans = true
	code := NewNodeInjector(&cfg).agentCode()
	require.Contains(t, code, "__obiSpanBridge")
	require.Contains(t, code, spansEnabledOn)
	require.NotContains(t, code, spansEnabledPlaceholder)
}

// Every sentinel the agent emits must use the non-throwing fs API: fs.accessSync
// on the sentinel paths always fails, and building the rejection costs about six
// times the call itself on every async callback in request scope.
func TestAgentScriptsUseNonThrowingSentinel(t *testing.T) {
	for name, code := range map[string]string{
		"fdextractor.js": _extractorCode,
		"spanbridge.js":  _spanBridgeCode,
	} {
		require.NotContains(t, code, "fs.accessSync", name)
		require.Contains(t, code, "fs.existsSync", name)
	}
}

// The set is drained whatever happens to the individual processes, so a process
// that has since exited cannot be retried or signaled twice. Reopening the
// handle is what refuses it here: the recorded start time cannot match anything
// live.
func TestUninjectAllDrainsTheSetEvenWhenTheProcessIsGone(t *testing.T) {
	cfg := obi.DefaultConfig

	i := NewNodeInjector(&cfg)
	i.injected[4242] = 99

	i.UninjectAll()

	require.Empty(t, i.injected)
}

func TestForgetDropsProcess(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	i.injected[4242] = 99
	i.Forget(4242)

	require.Empty(t, i.injected)
}

func TestGatePlaceholdersMatchTheScript(t *testing.T) {
	require.Equal(t, 1, strings.Count(_extractorCode, rtEnabledPlaceholder))
	require.Equal(t, 1, strings.Count(_extractorCode, tracesEnabledPlaceholder))
	require.Equal(t, 1, strings.Count(_spanBridgeCode, spansEnabledPlaceholder))
}
