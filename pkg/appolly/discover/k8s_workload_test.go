// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/selection"
)

func TestParseK8sWorkload(t *testing.T) {
	ref, err := ParseK8sWorkload(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "checkout"},
	})
	require.NoError(t, err)
	assert.Equal(t, selection.K8sWorkloadRef{Kind: "Deployment", Namespace: "payments", Name: "checkout"}, ref)

	ref, err = ParseK8sWorkload(selection.K8sWorkloadRef{Kind: "CronJob", Namespace: "ns", Name: "backup"})
	require.NoError(t, err)
	assert.Equal(t, "CronJob", ref.Kind)

	_, err = ParseK8sWorkload(nil)
	require.Error(t, err)

	_, err = ParseK8sWorkload(selection.K8sWorkloadRef{Kind: "Deployment", Name: "x"})
	require.Error(t, err)

	_, err = ParseK8sWorkload(selection.K8sWorkloadRef{Kind: "Pod", Namespace: "ns", Name: "pod-a"})
	require.Error(t, err)

	_, err = ParseK8sWorkload(selection.K8sWorkloadRef{Kind: "Job", Namespace: "ns", Name: "job-a"})
	require.Error(t, err)

	_, err = ParseK8sWorkload(selection.K8sWorkloadRef{Kind: "ReplicaSet", Namespace: "ns", Name: "rs-a"})
	require.Error(t, err)
}

func TestDynamicSelector_AddRemoveK8sWorkload(t *testing.T) {
	d := NewDynamicSelector()
	require.Empty(t, d.GetK8sWorkloads())

	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "payments", Name: "checkout",
	}, selection.DynamicOptions{ServiceName: "checkout"}))

	got := d.GetK8sWorkloads()
	require.Len(t, got, 1)
	assert.Equal(t, "checkout", got[0].Name)

	require.NoError(t, d.RemoveK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "payments", Name: "checkout",
	}))
	assert.Empty(t, d.GetK8sWorkloads())
}

func TestDynamicSelector_MaterializeAppliesFullSignalMask(t *testing.T) {
	d := NewDynamicSelector()
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicOptions{ServiceName: "checkout"}))

	meta := map[string]string{
		services.AttrNamespace:      "ns",
		services.AttrDeploymentName: "checkout",
	}
	d.appSignals().materializeMatchingWorkloads(42, meta)
	require.True(t, d.IncludesPID(42))
	assert.True(t, d.NetworkMetrics().IncludesPID(42))
	assert.True(t, d.StatsMetrics().IncludesPID(42))

	require.NoError(t, d.RemoveK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}))
	assert.False(t, d.IncludesPID(42))
}

func TestDynamicSelector_ExplicitPIDSurvivesWorkloadRemoval(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPID(7, selection.DynamicOptions{ServiceName: "explicit"})
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicOptions{ServiceName: "from-deploy"}))

	meta := map[string]string{
		services.AttrNamespace:      "ns",
		services.AttrDeploymentName: "checkout",
	}
	d.appSignals().materializeMatchingWorkloads(7, meta)
	require.True(t, d.IncludesPID(7))

	require.NoError(t, d.RemoveK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}))
	assert.True(t, d.IncludesPID(7))
	entry, ok := d.GetPID(7)
	require.True(t, ok)
	assert.Equal(t, "from-deploy", entry.ServiceName)
}

func TestDynamicSelector_WorkloadOptsUpdatePropagatesToMaterializedPIDs(t *testing.T) {
	d := NewDynamicSelector()
	ref := selection.K8sWorkloadRef{Kind: "Deployment", Namespace: "ns", Name: "checkout"}
	require.NoError(t, d.AddK8sWorkload(ref, selection.DynamicOptions{ServiceName: "first"}))

	meta := map[string]string{
		services.AttrNamespace:      "ns",
		services.AttrDeploymentName: "checkout",
	}
	d.appSignals().materializeMatchingWorkloads(9, meta)
	require.True(t, d.IncludesPID(9))

	require.NoError(t, d.AddK8sWorkload(ref, selection.DynamicOptions{ServiceName: "updated"}))
	entry, ok := d.GetPID(9)
	require.True(t, ok)
	assert.Equal(t, "updated", entry.ServiceName)
}

func TestDynamicMatcher_MaterializesWorkloadWhenPIDAlreadySelected(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPID(11, selection.DynamicOptions{ServiceName: "explicit"})
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicOptions{ServiceName: "from-deploy"}))

	m := &DynamicMatcher{
		Log:             slog.Default(),
		DynamicSelector: d.appSignals(),
	}
	pm := m.matchDynamicCriteria(ProcessAttrs{
		pid: 11,
		metadata: map[string]string{
			services.AttrNamespace:      "ns",
			services.AttrDeploymentName: "checkout",
		},
	}, &services.ProcessInfo{Pid: 11, ExePath: "/bin/test"})
	require.NotNil(t, pm)

	require.NoError(t, d.RemoveK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}))
	assert.True(t, d.IncludesPID(11), "explicit AddPID must survive workload removal")
}

func TestDynamicMatcher_RematerializesOnProcessHistoryHit(t *testing.T) {
	d := NewDynamicSelector()
	d.appSignals().AddPID(23, selection.DynamicOptions{ServiceName: "explicit"})

	m := &DynamicMatcher{
		Log:             slog.Default(),
		DynamicSelector: d.appSignals(),
		ProcessHistory: map[app.PID]ProcessMatch{
			23: {Process: &services.ProcessInfo{Pid: 23, ExePath: "/bin/test"}},
		},
	}

	_, ok := m.filterCreated(ProcessAttrs{
		pid: 23,
		metadata: map[string]string{
			services.AttrNamespace:      "ns",
			services.AttrDeploymentName: "checkout",
		},
	})
	assert.False(t, ok, "already-instrumented PIDs must not emit another Created")
	assert.False(t, d.NetworkMetrics().IncludesPID(23), "no workload yet")

	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicOptions{ServiceName: "from-deploy"}))

	_, ok = m.filterCreated(ProcessAttrs{
		pid: 23,
		metadata: map[string]string{
			services.AttrNamespace:      "ns",
			services.AttrDeploymentName: "checkout",
		},
	})
	assert.False(t, ok)
	assert.True(t, d.NetworkMetrics().IncludesPID(23), "workload source must attach on history hit")
	entry, found := d.GetPID(23)
	require.True(t, found)
	assert.Equal(t, "from-deploy", entry.ServiceName)

	require.NoError(t, d.RemoveK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}))
	assert.True(t, d.appSignals().IncludesPID(23), "explicit AddPID must survive workload removal")
	assert.False(t, d.NetworkMetrics().IncludesPID(23), "workload-only net selection must clear")
}

func TestDynamicMatcher_ClearsWorkloadSourcesOnProcessExit(t *testing.T) {
	d := NewDynamicSelector()
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicOptions{ServiceName: "from-deploy"}))

	meta := map[string]string{
		services.AttrNamespace:      "ns",
		services.AttrDeploymentName: "checkout",
	}
	d.appSignals().materializeMatchingWorkloads(31, meta)
	require.True(t, d.IncludesPID(31))
	assert.True(t, d.NetworkMetrics().IncludesPID(31))

	m := &DynamicMatcher{
		Log:             slog.Default(),
		DynamicSelector: d.appSignals(),
		ProcessHistory: map[app.PID]ProcessMatch{
			31: {Process: &services.ProcessInfo{Pid: 31, ExePath: "/bin/test"}},
		},
	}
	ev, ok := m.filterDeleted(ProcessAttrs{pid: 31})
	require.True(t, ok)
	assert.Equal(t, EventDeleted, ev.Type)
	assert.False(t, d.IncludesPID(31), "workload-only PID must leave the selector on exit")
	_, stillTracked := m.ProcessHistory[31]
	assert.False(t, stillTracked)
}

func TestDynamicMatcher_ExecutableReplacementIgnoresStaleRemoval(t *testing.T) {
	for _, timing := range []string{"before_rescan", "after_rescan"} {
		t.Run(timing, func(t *testing.T) {
			originalProcessInfo := processInfo
			processInfo = func(attrs ProcessAttrs) (*services.ProcessInfo, error) {
				path := "/bin/launcher"
				if attrs.executable.Ino == 2 {
					path = "/bin/replacement"
				}
				return &services.ProcessInfo{Pid: attrs.pid, ExePath: path}, nil
			}
			t.Cleanup(func() { processInfo = originalProcessInfo })

			d := NewDynamicSelector()
			workload := selection.K8sWorkloadRef{Kind: "Deployment", Namespace: "ns", Name: "checkout"}
			require.NoError(t, d.AddK8sWorkload(workload, selection.DynamicOptions{}))
			added := d.appSignals().AddedPIDsNotifyContext(t.Context())
			removed := d.appSignals().RemovedNotifyContext(t.Context())
			m := DynamicMatcher{
				Log:             slog.Default(),
				DynamicSelector: d.appSignals(),
				ProcessHistory:  map[app.PID]ProcessMatch{},
			}
			acc := pollAccounter{
				cfg:             &obi.Config{},
				executableReady: func(app.PID) (string, bool) { return "", true },
			}
			original := ProcessAttrs{
				pid:        31,
				executable: cacheKey{Dev: 1, Ino: 1},
				metadata: map[string]string{
					services.AttrNamespace:      "ns",
					services.AttrDeploymentName: "checkout",
				},
			}
			require.Len(t, m.filter(acc.snapshot(map[app.PID]ProcessAttrs{original.pid: original})), 1)
			require.Equal(t, []app.PID{original.pid}, testutil.ReadChannel(t, added, testTimeout))

			replacement := original
			replacement.executable.Ino = 2
			processes := map[app.PID]ProcessAttrs{replacement.pid: replacement}
			matches := m.filter(acc.snapshot(processes))
			require.Len(t, matches, 2)
			require.Equal(t, EventDeleted, matches[0].Type)
			require.Equal(t, "/bin/launcher", matches[0].Obj.Process.ExePath)
			require.Equal(t, EventCreated, matches[1].Type)
			require.Equal(t, "/bin/replacement", matches[1].Obj.Process.ExePath)
			staleRemoval := testutil.ReadChannel(t, removed, testTimeout)
			readded := testutil.ReadChannel(t, added, testTimeout)
			require.Equal(t, []app.PID{replacement.pid}, staleRemoval)
			require.Equal(t, []app.PID{replacement.pid}, readded)
			require.True(t, d.appSignals().IncludesPID(replacement.pid))

			if timing == "after_rescan" {
				acc.forgetPIDs(readded)
				events := acc.snapshot(processes)
				require.Len(t, events, 1)
				require.Empty(t, m.filter(events))
			}
			require.Empty(t, m.syntheticDeletesForRemovedPIDs(staleRemoval))
			require.Same(t, matches[1].Obj.Process, m.ProcessHistory[replacement.pid].Process)
			require.Empty(t, acc.snapshot(processes))

			d.NetworkMetrics().AddPID(uint32(replacement.pid), selection.DynamicOptions{})
			require.NoError(t, d.RemoveK8sWorkload(workload))
			require.True(t, d.IncludesPID(replacement.pid))
			require.False(t, d.appSignals().IncludesPID(replacement.pid))
			deletes := m.syntheticDeletesForRemovedPIDs(testutil.ReadChannel(t, removed, testTimeout))
			require.Equal(t, []Event[ProcessMatch]{{Type: EventDeleted, Obj: matches[1].Obj}}, deletes)
			require.NotContains(t, m.ProcessHistory, replacement.pid)
		})
	}
}

func TestDynamicMatcher_ReselectedPIDWithNewOptionsIsRemoved(t *testing.T) {
	d := NewDynamicSelector()
	removed := d.appSignals().RemovedNotifyContext(t.Context())
	m := DynamicMatcher{
		Log:             slog.Default(),
		DynamicSelector: d.appSignals(),
		ProcessHistory:  map[app.PID]ProcessMatch{},
	}

	d.appSignals().AddPID(51, selection.DynamicOptions{ServiceName: "a"})
	tracked := ProcessMatch{
		Criteria: []services.Selector{d.appSignals().SelectorForPID(51)},
		Process:  &services.ProcessInfo{Pid: 51},
	}
	m.ProcessHistory[51] = tracked

	d.appSignals().RemovePIDs(51)
	d.appSignals().AddPID(51, selection.DynamicOptions{ServiceName: "b"})

	deletes := m.syntheticDeletesForRemovedPIDs(testutil.ReadChannel(t, removed, testTimeout))
	assert.Equal(t, []Event[ProcessMatch]{{Type: EventDeleted, Obj: tracked}}, deletes)
	assert.NotContains(t, m.ProcessHistory, app.PID(51))
}

func TestDynamicMatcher_ReselectedPIDWithSameOptionsIgnoresRemoval(t *testing.T) {
	d := NewDynamicSelector()
	removed := d.appSignals().RemovedNotifyContext(t.Context())
	m := DynamicMatcher{
		Log:             slog.Default(),
		DynamicSelector: d.appSignals(),
		ProcessHistory:  map[app.PID]ProcessMatch{},
	}

	opts := selection.DynamicOptions{ServiceName: "a", ResourceAttributes: map[string]string{"k": "v"}}
	d.appSignals().AddPID(52, opts)
	m.ProcessHistory[52] = ProcessMatch{
		Criteria: []services.Selector{d.appSignals().SelectorForPID(52)},
		Process:  &services.ProcessInfo{Pid: 52},
	}

	d.appSignals().RemovePIDs(52)
	d.appSignals().AddPID(52, opts)

	assert.Empty(t, m.syntheticDeletesForRemovedPIDs(testutil.ReadChannel(t, removed, testTimeout)))
	assert.Contains(t, m.ProcessHistory, app.PID(52))
}

func TestDynamicMatcher_ProcessExitKeepsExplicitPID(t *testing.T) {
	d := NewDynamicSelector()
	d.appSignals().AddPID(41, selection.DynamicOptions{ServiceName: "explicit"})
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicOptions{ServiceName: "from-deploy"}))
	d.appSignals().materializeMatchingWorkloads(41, map[string]string{
		services.AttrNamespace:      "ns",
		services.AttrDeploymentName: "checkout",
	})
	require.True(t, d.NetworkMetrics().IncludesPID(41))

	m := &DynamicMatcher{
		Log:             slog.Default(),
		DynamicSelector: d.appSignals(),
		ProcessHistory: map[app.PID]ProcessMatch{
			41: {Process: &services.ProcessInfo{Pid: 41, ExePath: "/bin/test"}},
		},
	}
	_, ok := m.filterDeleted(ProcessAttrs{pid: 41})
	require.True(t, ok)
	assert.True(t, d.appSignals().IncludesPID(41), "explicit AddPID must survive process exit")
	assert.False(t, d.NetworkMetrics().IncludesPID(41), "workload net/stats source must clear")
}
