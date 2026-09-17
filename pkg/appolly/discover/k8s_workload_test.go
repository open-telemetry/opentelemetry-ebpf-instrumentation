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

func TestDynamicPIDSelector_AddRemoveK8sWorkload(t *testing.T) {
	d := NewDynamicPIDSelector()
	require.Empty(t, d.GetK8sWorkloads())

	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "payments", Name: "checkout",
	}, selection.DynamicPIDOptions{ServiceName: "checkout"}))

	got := d.GetK8sWorkloads()
	require.Len(t, got, 1)
	assert.Equal(t, "checkout", got[0].Name)

	require.NoError(t, d.RemoveK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "payments", Name: "checkout",
	}))
	assert.Empty(t, d.GetK8sWorkloads())
}

func TestDynamicPIDSelector_MaterializeAppliesFullSignalMask(t *testing.T) {
	d := NewDynamicPIDSelector()
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicPIDOptions{ServiceName: "checkout"}))

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

func TestDynamicPIDSelector_ExplicitPIDSurvivesWorkloadRemoval(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPID(7, selection.DynamicPIDOptions{ServiceName: "explicit"})
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicPIDOptions{ServiceName: "from-deploy"}))

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

func TestDynamicPIDSelector_WorkloadOptsUpdatePropagatesToMaterializedPIDs(t *testing.T) {
	d := NewDynamicPIDSelector()
	ref := selection.K8sWorkloadRef{Kind: "Deployment", Namespace: "ns", Name: "checkout"}
	require.NoError(t, d.AddK8sWorkload(ref, selection.DynamicPIDOptions{ServiceName: "first"}))

	meta := map[string]string{
		services.AttrNamespace:      "ns",
		services.AttrDeploymentName: "checkout",
	}
	d.appSignals().materializeMatchingWorkloads(9, meta)
	require.True(t, d.IncludesPID(9))

	require.NoError(t, d.AddK8sWorkload(ref, selection.DynamicPIDOptions{ServiceName: "updated"}))
	entry, ok := d.GetPID(9)
	require.True(t, ok)
	assert.Equal(t, "updated", entry.ServiceName)
}

func TestDynamicMatcher_MaterializesWorkloadWhenPIDAlreadySelected(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPID(11, selection.DynamicPIDOptions{ServiceName: "explicit"})
	require.NoError(t, d.AddK8sWorkload(selection.K8sWorkloadRef{
		Kind: "Deployment", Namespace: "ns", Name: "checkout",
	}, selection.DynamicPIDOptions{ServiceName: "from-deploy"}))

	m := &DynamicMatcher{
		Log:             slog.Default(),
		DynamicPIDSelector: d.appSignals(),
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
	d := NewDynamicPIDSelector()
	d.appSignals().AddPID(23, selection.DynamicOptions{ServiceName: "explicit"})

	m := &DynamicMatcher{
		Log:             slog.Default(),
		DynamicPIDSelector: d.appSignals(),
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
	d := NewDynamicPIDSelector()
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
		DynamicPIDSelector: d.appSignals(),
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

func TestDynamicMatcher_ProcessExitKeepsExplicitPID(t *testing.T) {
	d := NewDynamicPIDSelector()
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
		DynamicPIDSelector: d.appSignals(),
		ProcessHistory: map[app.PID]ProcessMatch{
			41: {Process: &services.ProcessInfo{Pid: 41, ExePath: "/bin/test"}},
		},
	}
	_, ok := m.filterDeleted(ProcessAttrs{pid: 41})
	require.True(t, ok)
	assert.True(t, d.appSignals().IncludesPID(41), "explicit AddPID must survive process exit")
	assert.False(t, d.NetworkMetrics().IncludesPID(41), "workload net/stats source must clear")
}
