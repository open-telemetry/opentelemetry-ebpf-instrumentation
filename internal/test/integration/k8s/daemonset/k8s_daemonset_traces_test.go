// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/kube"
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
	"go.opentelemetry.io/obi/internal/test/integration/k8s/common/testpath"
)

// For the DaemonSet scenario, we only check that OBI is able to instrument any
// process in the system. We just check that traces are properly generated without
// entering in too many details
func TestBasicTracing(t *testing.T) {
	feat := features.New("OBI is able to instrument an arbitrary process").
		Assess("it sends traces for that service",
			func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
				var podID string
				require.Eventually(t, func() bool {
					// Invoking both service instances, but we will expect that only one
					// is instrumented, according to the discovery mechanisms
					resp, err := http.Get("http://localhost:38080/pingpong")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get("http://localhost:38081/pingpong")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get(jaegerQueryURL + "?service=otherinstance")
					if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
						return false
					}
					var tq jaeger.TracesQuery
					if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
						return false
					}
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/pingpong"})
					if len(traces) == 0 {
						return false
					}
					trace := traces[0]
					if len(trace.Spans) == 0 {
						return false
					}

					// Check that the service.namespace is set from the K8s namespace
					if len(trace.Processes) != 1 {
						return false
					}
					for _, proc := range trace.Processes {
						sd := jaeger.DiffAsRegexp([]jaeger.Tag{
							{Key: "service.namespace", Type: "string", Value: "^default$"},
							{Key: "service.instance.id", Type: "string", Value: "^default\\.otherinstance-.+\\.otherinstance"},
						}, proc.Tags)
						if len(sd) > 0 {
							return false
						}
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /pingpong", "server")
					if len(res) != 1 {
						return false
					}
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^otherinstance-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "otherinstance"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.owner.name", Type: "string", Value: "^otherinstance$"},
						{Key: "k8s.deployment.name", Type: "string", Value: "^otherinstance$"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^obi-k8s-test-cluster$"},
					}, trace.Processes[parent.ProcessID].Tags)
					if len(sd) > 0 {
						return false
					}

					// Extract the pod id, so we can later check on restart of the pod that we have a different id
					tag, found := jaeger.FindIn(trace.Processes[parent.ProcessID].Tags, "k8s.pod.uid")
					if !found {
						return false
					}

					podID = tag.Value.(string)
					return podID != ""
				}, testTimeout, 100*time.Millisecond, "waiting for daemonset traces with metadata")

				// Check that the "testserver" service is never instrumented
				resp, err := http.Get(jaegerQueryURL + "?service=testserver")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var tq jaeger.TracesQuery
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
				assert.Empty(t, tq.Data)

				// Let's take down our services, keeping OBI alive and then redeploy them
				err = kube.DeleteExistingManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service.yml")
				require.NoError(t, err, "we should see no error when deleting the uninstrumented service manifest file")

				err = kube.DeployManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service.yml")
				require.NoError(t, err, "we should see no error when re-deploying the uninstrumented service manifest file")

				// We now use a different API, this ensures that after undeploying and redeploying the application we
				// can still monitor its data
				require.Eventually(t, func() bool {
					// Invoking both service instances, but we will expect that only one
					// is instrumented, according to the discovery mechanisms
					resp, err := http.Get("http://localhost:38080/pingpongtoo")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get("http://localhost:38081/pingpongtoo")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get(jaegerQueryURL + "?service=otherinstance")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}
					if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
						return false
					}
					var tq jaeger.TracesQuery
					if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
						return false
					}
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/pingpongtoo"})
					if len(traces) == 0 {
						return false
					}
					// get the last trace, to avoid that the old instance captured any request
					// before being restarted
					trace := traces[len(traces)-1]
					if len(trace.Spans) == 0 {
						return false
					}

					// Check that the service.namespace is set from the K8s namespace
					if len(trace.Processes) != 1 {
						return false
					}
					for _, proc := range trace.Processes {
						sd := jaeger.DiffAsRegexp([]jaeger.Tag{
							{Key: "service.namespace", Type: "string", Value: "^default$"},
							{Key: "service.instance.id", Type: "string", Value: "^default\\.otherinstance-.+\\.otherinstance"},
						}, proc.Tags)
						if len(sd) > 0 {
							return false
						}
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /pingpongtoo", "server")
					if len(res) != 1 {
						return false
					}
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^otherinstance-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "otherinstance"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.deployment.name", Type: "string", Value: "^otherinstance"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^obi-k8s-test-cluster$"},
					}, trace.Processes[parent.ProcessID].Tags)
					if len(sd) > 0 {
							return false
						}

					// ensure the pod really restarted, comparing the current uid with the previous pod uid
					tag, found := jaeger.FindIn(trace.Processes[parent.ProcessID].Tags, "k8s.pod.uid")
					if !found {
						return false
					}

					return podID != tag.Value.(string)
				}, testTimeout, 100*time.Millisecond, "waiting for restarted daemonset traces with metadata")

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
