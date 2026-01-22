// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
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
	testTimeout        = 3 * time.Minute
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
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-restrict-local-node",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-node.yml"),
		kube.LocalImage("obi:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-otelscrape-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-server-client-different-nodes.yml"),
		kube.Deploy(testpath.Manifests+"/06-obi-netolly.yml"),
	)

	cluster.Run(m)
}

func TestNoSourceAndDestAvailable(t *testing.T) {
	// Wait for some metrics available at Prometheus
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, args := range []string{
		`k8s_dst_name="httppinger"`,
		`k8s_src_name="httppinger"`,
		`k8s_dst_name=~"otherinstance.*"`,
		`k8s_src_name=~"otherinstance.*"`,
	} {
		t.Run("check "+args, func(t *testing.T) {
			test.Eventually(t, testTimeout, func(t require.TestingT) {
				var err error
				results, err := pq.Query(`obi_network_flow_bytes_total{` + args + `}`)
				require.NoError(t, err)
				require.NotEmpty(t, results)
			})
		})
	}

	// Verify that HTTP pinger/testserver metrics can't have both source and destination labels,
	// as the test client and server are in different nodes, and OBI is only getting information
	// from its local node
	results, err := pq.Query(`obi_network_flow_bytes_total{k8s_dst_name="httppinger",k8s_src_name=~"otherinstance.*",k8s_src_kind="Pod"}`)
	require.NoError(t, err)
	require.Empty(t, results)

	results, err = pq.Query(`obi_network_flow_bytes_total{k8s_src_name="httppinger",k8s_dst_name=~"otherinstance.*",k8s_dst_kind="Pod"}`)
	require.NoError(t, err)
	require.Empty(t, results)
}
