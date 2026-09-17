// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
