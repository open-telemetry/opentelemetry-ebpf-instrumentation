// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/kube"
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
	"go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"
	"go.opentelemetry.io/obi/internal/test/tools"
)

var cluster *kube.Kind

// TestMain is run once before all the tests in the package. If you need to mount a different cluster for
// a different test suite, you should add a new TestMain in a new package together with the new test suite
func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping integration tests in short mode")
		return
	}

	if err := docker.Build(os.Stdout, tools.ProjectDir(),
		docker.ImageBuild{Tag: "testserver:dev", Dockerfile: k8s.DockerfileTestServer},
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
		docker.ImageBuild{Tag: "grpcpinger:dev", Dockerfile: k8s.DockerfilePinger},
		docker.ImageBuild{Tag: "httppinger:dev", Dockerfile: k8s.DockerfileHTTPPinger},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-prom",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("obi:dev"),
		kube.LocalImage("grpcpinger:dev"),
		kube.LocalImage("httppinger:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/02-prometheus-promscrape.yml"),
		kube.Deploy(testpath.Manifests+"/05-instrumented-service-prometheus.yml"),
	)

	cluster.Run(m)
}
