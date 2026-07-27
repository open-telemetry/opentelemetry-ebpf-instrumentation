// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package sharedpidns tests that spans from pods sharing the host PID namespace
// (hostPID=true) are correctly attributed to their respective pods, rather than
// being misattributed to an arbitrary pod that happens to share the same
// PID namespace inode.
package sharedpidns

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
	testTimeout    = 3 * time.Minute
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
		docker.ImageBuild{Tag: "obi:dev", Dockerfile: k8s.DockerfileOBI},
	); err != nil {
		slog.Error("can't build docker images", "error", err)
		os.Exit(-1)
	}

	cluster = kube.NewKind("test-kind-cluster-sharedpidns",
		kube.KindConfig(testpath.Manifests+"/00-kind.yml"),
		kube.LocalImage("testserver:dev"),
		kube.LocalImage("obi:dev"),
		kube.Deploy(testpath.Manifests+"/01-volumes.yml"),
		kube.Deploy(testpath.Manifests+"/01-serviceaccount.yml"),
		kube.Deploy(testpath.Manifests+"/03-otelcol.yml"),
		kube.Deploy(testpath.Manifests+"/04-jaeger.yml"),
		// Deploy a normal Deployment (no hostPID)
		kube.Deploy(testpath.Manifests+"/05-uninstrumented-service.yml"),
		// Deploy a DaemonSet with hostPID=true serving HTTP on port 8082
		kube.Deploy(testpath.Manifests+"/05-hostpid-daemonset.yml"),
		// Deploy OBI configured to instrument both
		kube.Deploy(testpath.Manifests+"/06-obi-daemonset-sharedpidns.yml"),
	)

	cluster.Run(m)
}
