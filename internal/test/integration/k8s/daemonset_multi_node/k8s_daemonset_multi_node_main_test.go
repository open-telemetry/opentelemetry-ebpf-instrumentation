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

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/kube"
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
	"go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"
	"go.opentelemetry.io/obi/internal/test/tools"
)

const (
	testTimeout = 3 * time.Minute

	jaegerQueryURL = "http://localhost:36686/api/traces"
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
		docker.ImageBuild{Tag: "pythontestserver:dev", Dockerfile: k8s.DockerfilePythonTestServer},
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-otel-multi",
		kube.KindConfig(testpath.Manifests+"/00-kind-multi-node.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("pythontestserver:dev"),
		kube.LocalImage("obi:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/04-jaeger-multi-node.yml"),
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-few-services.yml"),
		kube.Deploy(testpath.Manifests+"/06-obi-daemonset-multi-node.yml"),
	)

	cluster.Run(m)
}
