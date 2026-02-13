// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/appolly/meta"

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/kube"
)

func kubeNodeFetcher(k8sInformer *kube.MetadataProvider) fetcher {
	return func(ctx context.Context) (NodeStore, error) {
		if !k8sInformer.IsKubeEnabled() {
			return NodeStore{}, nil
		}
		nodeName, err := k8sInformer.CurrentNodeName(ctx)
		if err != nil {
			// forwarding an error will force the NodeStore to
			// retry until timeout
			return NodeStore{}, err
		}
		kubeClient, err := k8sInformer.KubeClient()
		if err != nil {
			return NodeStore{}, err
		}
		nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{
			FieldSelector: "metadata.name=" + nodeName,
		})
		if err != nil || len(nodes.Items) == 0 {
			return NodeStore{}, fmt.Errorf("can't get node %s: %w", nodeName, err)
		}
		return NodeStore{
			HostID: nodes.Items[0].Status.NodeInfo.MachineID,
		}, nil
	}
}
