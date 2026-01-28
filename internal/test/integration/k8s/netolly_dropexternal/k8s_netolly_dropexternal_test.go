// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/kube"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
	"go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"
	"go.opentelemetry.io/obi/internal/test/tools"
)

const (
	testTimeout        = 3 * time.Minute
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
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-netolly-dropexternal",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("obi:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-otelscrape.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-service.yml"),
		kube.Deploy(testpath.Manifests+"/06-obi-netolly-dropexternal.yml"),
	)

	cluster.Run(m)
}

func TestNetworkFlowBytes_DropExternal(t *testing.T) {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger",
			TargetURL: "http://testserver:8080/iping",
		},
	}
	cluster.TestEnv().Test(t, features.New("network flow bytes").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("catches internal but not external traffic", testNoFlowsForExternalTraffic).
		Feature(),
	)
}

func testNoFlowsForExternalTraffic(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// testing first that internal traffic is reported (this leaves room to populate Prometheus with
	// the inspected metrics)
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`obi_network_flow_bytes_total{src_name="internal-pinger",dst_name="testserver"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})

	// test that there isn't external traffic neither as source nor as a destination
	results, err := pq.Query(`obi_network_flow_bytes_total{k8s_src_owner_name=""}`)
	require.NoError(t, err)
	require.Empty(t, results)

	results, err = pq.Query(`obi_network_flow_bytes_total{k8s_dst_owner_name=""}`)
	require.NoError(t, err)
	require.Empty(t, results)
	return ctx
}
