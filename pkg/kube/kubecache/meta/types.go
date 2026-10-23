// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/kube/kubecache/meta"

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

type indexableEntity struct {
	// the informers library requires to embed this field
	metav1.ObjectMeta
	// the protobuf-encoded object Metadata that will be actually sent over the wire
	EncodedMeta *informer.ObjectMeta
}

// ownerFrom returns the owner references, as well as the owners from the owners. It might be
// null if the entity does not have any owner
func ownersFrom(meta *metav1.ObjectMeta) []*informer.Owner {
	if len(meta.OwnerReferences) == 0 {
		// If no owner references' found, return itself as owner
		return []*informer.Owner{{Kind: typePod, Name: meta.Name}}
	}
	owners := make([]*informer.Owner, 0, len(meta.OwnerReferences))
	for i := range meta.OwnerReferences {
		or := &meta.OwnerReferences[i]
		owners = append(owners, &informer.Owner{Kind: or.Kind, Name: or.Name})
		// ReplicaSets usually have a Deployment as owner too. Returning it as well
		if or.APIVersion == "apps/v1" && or.Kind == "ReplicaSet" {
			if name := deploymentOfReplicaSet(or.Name, meta.Labels); name != "" {
				owners = append(owners, &informer.Owner{Kind: "Deployment", Name: name})
				// we already have what we need for decoration and selection. Ignoring any other owner
				// it might hypothetically have (it would be a rare case)
				return owners
			}
		}
		if or.APIVersion == "batch/v1" && or.Kind == "Job" {
			if name := cronJobOfJob(or.Name, meta.CreationTimestamp.Time); name != "" {
				owners = append(owners, &informer.Owner{Kind: "CronJob", Name: name})
				// we already have what we need for decoration and selection. Ignoring any other owner
				// it might hypothetically have (it would be a rare case)
				return owners
			}
		}
	}
	return owners
}

// deploymentOfReplicaSet follows the OpenTelemetry Collector's k8sattributes
// processor: a Deployment's ReplicaSet is named <deployment>-<pod-template-hash>.
// Argo Rollouts name their ReplicaSets the same way with
// rollouts-pod-template-hash, and keep being reported as a Deployment.
func deploymentOfReplicaSet(replicaSet string, podLabels map[string]string) string {
	for _, label := range []string{"pod-template-hash", "rollouts-pod-template-hash"} {
		if hash := podLabels[label]; hash != "" && strings.HasSuffix(replicaSet, "-"+hash) {
			return strings.TrimSuffix(replicaSet, "-"+hash)
		}
	}
	return ""
}

// cronJobJobName matches the Jobs a CronJob creates: <cronjob>-<scheduled time
// in Unix minutes>.
var cronJobJobName = regexp.MustCompile(`^(.+)-(\d{8})$`)

// cronJobSkewMinutes is the k8sattributes processor's bound between that
// scheduled time and the pod's creation.
const cronJobSkewMinutes = 60 * 24

func cronJobOfJob(job string, podCreated time.Time) string {
	parts := cronJobJobName.FindStringSubmatch(job)
	if parts == nil {
		return ""
	}
	scheduled, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return ""
	}
	diff := podCreated.Unix()/60 - scheduled
	if diff < -cronJobSkewMinutes || diff > cronJobSkewMinutes {
		return ""
	}
	return parts[1]
}
