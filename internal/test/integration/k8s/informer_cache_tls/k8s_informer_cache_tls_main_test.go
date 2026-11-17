// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package informercachetls

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/kube"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
	"go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"
	"go.opentelemetry.io/obi/internal/test/tools"
)

const (
	prometheusHostPort = "localhost:39090"
)

var cluster *kube.Kind

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping integration tests in short mode")
		return
	}

	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
		docker.ImageBuild{Tag: "obi-k8s-cache:dev", Dockerfile: k8s.DockerfileK8sCache},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-external-cache-tls",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("obi:dev"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.LocalImage("obi-k8s-cache:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-service.yml"),
		kube.Deploy(testpath.Manifests+"/06-obi-external-informer-tls.yml"),
	)

	cluster.Run(m)
}

// Run it alphabetically first (AA-prefix), with a longer timeout, to wait until all the components are up and
// traces/metrics are flowing normally
func TestInformersCacheTLS_MetricsDecoration_AA_WaitForComponents(t *testing.T) {
	k8s.DoWaitForComponentsAvailable(t)
}

func TestInformersCacheTLS_MetricsDecoration_HTTP(t *testing.T) {
	cluster.TestEnv().Test(t, k8s.FeatureHTTPMetricsDecoration(k8s.UninstrumentedPingerManifest,
		map[string]string{
			"server_service_namespace": "overridden-testserver-namespace",
			"k8s_cluster_name":         "my-kube",
			"service_namespace":        "overridden-testserver-namespace",
			"service_instance_id":      "default.testserver-.+\\.testserver",
		}))
}

// Prometheus scrapes the cache through its Service, so a scrape can land on the replica OBI isn't connected to.
func TestInformersCacheTLS_ConnectedClientsOverTLS(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.NotZero(ct, metricVal(ct, `max_over_time(obi_kube_cache_connected_clients[1m])`))
	}, 2*time.Minute, 2*time.Second)
}

func metricVal(t require.TestingT, promQLQuery string) int {
	pq := promtest.Client{HostPort: prometheusHostPort}

	results, err := pq.Query(promQLQuery)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Len(t, results[0].Value, 2)
	n, err := strconv.Atoi(fmt.Sprint(results[0].Value[1]))
	require.NoError(t, err)
	return n
}
