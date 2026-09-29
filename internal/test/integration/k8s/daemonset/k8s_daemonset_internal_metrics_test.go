// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// prometheusHostPort is the host-mapped port of the suite's Prometheus
// (02-prometheus-otelscrape.yml), which scrapes the otelcol's exporter.
const prometheusHostPort = "localhost:39090"

const forwardLagServiceName = "forward-lag-test"

// The OBI daemonset exports its internal metrics via the otel exporter
// (06-obi-daemonset.yml), which the suite otelcol re-exports to Prometheus
// (03-otelcol-weaver.yml). This asserts obi.kube.cache.forward.lag — the
// in-process kube informer forward lag — reaches Prometheus, matched by name so
// the histogram suffix is not load-bearing.
func TestInternalMetrics_ForwardLag(t *testing.T) {
	feat := features.New("OBI exports the kube informer forward-lag internal metric").
		Assess("obi.kube.cache.forward.lag reaches Prometheus via the otelcol",
			func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
				pq := promtest.Client{HostPort: prometheusHostPort}
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					results, err := pq.Query("obi_internal_build_info")
					require.NoError(ct, err)
					require.NotEmpty(ct, results, "OBI internal metrics were not exported to Prometheus")
				}, testTimeout, time.Second)

				client, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
				require.NoError(t, err)
				services := client.CoreV1().Services("default")
				_, err = services.Create(ctx, &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: forwardLagServiceName},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{{Port: 80}},
					},
				}, metav1.CreateOptions{})
				require.NoError(t, err)
				defer func() {
					assert.NoError(t, services.Delete(context.Background(), forwardLagServiceName, metav1.DeleteOptions{}))
				}()

				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					results, err := pq.Query(`{__name__=~"obi_kube_cache_forward_lag.*"}`)
					require.NoError(ct, err)
					require.NotEmpty(ct, results,
						"obi.kube.cache.forward.lag was not exported to Prometheus by the otelcol")
				}, testTimeout, time.Second)
				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
