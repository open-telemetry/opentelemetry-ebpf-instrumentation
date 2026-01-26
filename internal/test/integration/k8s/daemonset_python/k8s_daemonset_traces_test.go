// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

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
func TestPythonBasicTracing(t *testing.T) {
	feat := features.New("OBI is able to instrument an arbitrary process").
		Assess("it sends traces for that service",
			func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
				var trace jaeger.Trace
				var podID string
				require.Eventually(t, func() bool {
					resp, err := http.Get("http://localhost:7773/greeting")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get(jaegerQueryURL + "?service=mypythonapp&operation=GET%20%2Fgreeting")
					if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
						return false
					}
					var tq jaeger.TracesQuery
					if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
						return false
					}
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/greeting"})
					if len(traces) == 0 {
						return false
					}
					trace = traces[0]
					if len(trace.Spans) == 0 {
						return false
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /greeting", "server")
					if len(res) != 1 {
						return false
					}
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "service.namespace", Type: "string", Value: "^integration-test$"},
						{Key: "telemetry.sdk.language", Type: "string", Value: "^python$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver$"},
					}, trace.Processes[parent.ProcessID].Tags)
					if len(sd) > 0 {
						return false
					}

					// check the process information
					sd = jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^pytestserver-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "pytestserver"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^obi-k8s-test-cluster$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver"},
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
				}, testTimeout, 100*time.Millisecond, "waiting for python traces with metadata")

				// Let's take down our services, keeping OBI alive and then redeploy them
				err := kube.DeleteExistingManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service-python.yml")
				require.NoError(t, err, "we should see no error when deleting the uninstrumented service manifest file")

				err = kube.DeployManifestFile(cfg, testpath.Manifests+"/05-uninstrumented-service-python.yml")
				require.NoError(t, err, "we should see no error when re-deploying the uninstrumented service manifest file")

				// We now use /smoke instead of /greeting to ensure we see those APIs after a restart
				require.Eventually(t, func() bool {
					resp, err := http.Get("http://localhost:7773/smoke")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get(jaegerQueryURL + "?service=mypythonapp&operation=GET%20%2Fsmoke")
					if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
						return false
					}
					var tq jaeger.TracesQuery
					if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
						return false
					}
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/smoke"})
					if len(traces) == 0 {
						return false
					}
					trace = traces[0]
					if len(trace.Spans) == 0 {
						return false
					}

					// Check the information of the parent span
					res := trace.FindByOperationName("GET /smoke", "server")
					if len(res) != 1 {
						return false
					}
					parent := res[0]
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "service.namespace", Type: "string", Value: "^integration-test$"},
						{Key: "telemetry.sdk.language", Type: "string", Value: "^python$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver$"},
					}, trace.Processes[parent.ProcessID].Tags)
					if len(sd) > 0 {
						return false
					}

					// check the process information
					sd = jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^pytestserver-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "pytestserver"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^obi-k8s-test-cluster$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.pytestserver-.+\\.pytestserver"},
					}, trace.Processes[parent.ProcessID].Tags)
					if len(sd) > 0 {
						return false
					}

					// ensure the pod really restarted
					tag, found := jaeger.FindIn(trace.Processes[parent.ProcessID].Tags, "k8s.pod.uid")
					if !found {
						return false
					}

					return podID != tag.Value.(string)
				}, testTimeout, 100*time.Millisecond, "waiting for restarted python traces with metadata")

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
