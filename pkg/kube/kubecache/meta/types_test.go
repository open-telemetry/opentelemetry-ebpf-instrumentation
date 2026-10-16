// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOwnersFrom(t *testing.T) {
	// the Job a CronJob "report" scheduled at Unix minute 29340000
	scheduled := time.Unix(29340000*60, 0)
	ownedBy := func(apiVersion, kind, name string) []metav1.OwnerReference {
		return []metav1.OwnerReference{{APIVersion: apiVersion, Kind: kind, Name: name}}
	}
	type owner struct{ kind, name string }
	for _, tc := range []struct {
		name string
		meta metav1.ObjectMeta
		want []owner
	}{
		{"deployment replicaset", metav1.ObjectMeta{
			Labels: map[string]string{"pod-template-hash": "7d4b9c6f5d"}, OwnerReferences: ownedBy("apps/v1", "ReplicaSet", "billing-7d4b9c6f5d"),
		}, []owner{{"ReplicaSet", "billing-7d4b9c6f5d"}, {"Deployment", "billing"}}},
		{"argo rollout replicaset", metav1.ObjectMeta{
			Labels: map[string]string{"rollouts-pod-template-hash": "6d4cf56db6"}, OwnerReferences: ownedBy("apps/v1", "ReplicaSet", "checkout-6d4cf56db6"),
		}, []owner{{"ReplicaSet", "checkout-6d4cf56db6"}, {"Deployment", "checkout"}}},
		{"standalone replicaset", metav1.ObjectMeta{
			OwnerReferences: ownedBy("apps/v1", "ReplicaSet", "legacy-rs"),
		}, []owner{{"ReplicaSet", "legacy-rs"}}},
		{"replicaset not ending in the pod hash", metav1.ObjectMeta{
			Labels: map[string]string{"pod-template-hash": "7d4b9c6f5d"}, OwnerReferences: ownedBy("apps/v1", "ReplicaSet", "web-abc"),
		}, []owner{{"ReplicaSet", "web-abc"}}},
		{"cronjob job", metav1.ObjectMeta{
			CreationTimestamp: metav1.NewTime(scheduled.Add(2 * time.Minute)), OwnerReferences: ownedBy("batch/v1", "Job", "report-29340000"),
		}, []owner{{"Job", "report-29340000"}, {"CronJob", "report"}}},
		{"standalone job", metav1.ObjectMeta{
			CreationTimestamp: metav1.NewTime(scheduled), OwnerReferences: ownedBy("batch/v1", "Job", "db-migrate"),
		}, []owner{{"Job", "db-migrate"}}},
		{"date-stamped standalone job", metav1.ObjectMeta{
			CreationTimestamp: metav1.NewTime(scheduled), OwnerReferences: ownedBy("batch/v1", "Job", "backup-20261014"),
		}, []owner{{"Job", "backup-20261014"}}},
		{"job scheduled over a day from its pod", metav1.ObjectMeta{
			CreationTimestamp: metav1.NewTime(scheduled.Add(25 * time.Hour)), OwnerReferences: ownedBy("batch/v1", "Job", "report-29340000"),
		}, []owner{{"Job", "report-29340000"}}},
		{"no owner", metav1.ObjectMeta{Name: "debug"}, []owner{{typePod, "debug"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []owner
			for _, o := range ownersFrom(&tc.meta) {
				got = append(got, owner{o.GetKind(), o.GetName()})
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
