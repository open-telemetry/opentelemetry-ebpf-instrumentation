// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package owners

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
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
)

// For the DaemonSet scenario, we only check that OBI is able to instrument any
// process in the system. We just check that traces are properly generated without
// entering in too many details
func TestStatefulSetMetadata(t *testing.T) {
	feat := features.New("OBI is able to decorate the metadata of a statefulset").
		Assess("it sends decorated traces for the statefulset",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				require.Eventually(t, func() bool {
					// Invoking both service instances, but we will expect that only one
					// is instrumented, according to the discovery mechanisms
					resp, err := http.Get("http://localhost:38080/pingpong")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get(jaegerQueryURL + "?service=statefulservice")
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
							{Key: "service.instance.id", Type: "string", Value: "^default\\.statefulservice-.+\\.statefulservice"},
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
						{Key: "k8s.pod.name", Type: "string", Value: "^statefulservice-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "statefulservice"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.statefulset.name", Type: "string", Value: "^statefulservice$"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^obi-k8s-test-cluster$"},
						{Key: "service.namespace", Type: "string", Value: "^default$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.statefulservice-.+\\.statefulservice"},
					}, trace.Processes[parent.ProcessID].Tags)
					if len(sd) > 0 {
						return false
					}

					// check that no other labels are added
					sd = jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.deployment.name", Type: "string"},
						{Key: "k8s.daemonset.name", Type: "string"},
						{Key: "k8s.job.name", Type: "string"},
						{Key: "k8s.cronjob.name", Type: "string"},
					}, trace.Processes[parent.ProcessID].Tags)
					return len(sd) == 4 && sd[0].ErrType == jaeger.ErrTypeMissing && sd[1].ErrType == jaeger.ErrTypeMissing && sd[2].ErrType == jaeger.ErrTypeMissing && sd[3].ErrType == jaeger.ErrTypeMissing
				}, testTimeout, 100*time.Millisecond, "waiting for statefulset traces with metadata")
				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
