// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
