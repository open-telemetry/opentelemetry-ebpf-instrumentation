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
)

// We only check that traces are decorated in an overall Pod2Service scenario, as the whole metadata
// composition process is shared too with the rest of metrics decoration
func TestTracesDecoration(t *testing.T) {
	pinger := kube.Template[k8s.Pinger]{
		TemplateFile: k8s.UninstrumentedPingerManifest,
		Data: k8s.Pinger{
			PodName:   "internal-pinger",
			TargetURL: "http://testserver:8080/traced-ping",
		},
	}
	feat := features.New("Decoration of server communications").
		Setup(pinger.Deploy()).
		Teardown(pinger.Delete()).
		Assess("all the traces are properly decorated",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var trace jaeger.Trace
				var parent jaeger.Span
				require.Eventually(t, func() bool {
					resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Ftraced-ping")
					if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
						return false
					}
					var tq jaeger.TracesQuery
					if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
						return false
					}
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/traced-ping"})
					if len(traces) == 0 {
						return false
					}

					// Check the K8s metadata information of the parent span's process
					trace = traces[0]
					res := trace.FindByOperationName("GET /traced-ping", "server")
					if len(res) != 1 {
						return false
					}
					parent = res[0]

					if len(trace.Spans) == 0 {
						return false
					}
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^testserver-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "testserver"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.deployment.name", Type: "string", Value: "^testserver$"},
						{Key: "k8s.cluster.name", Type: "string", Value: "^obi-k8s-test-cluster$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.testserver-.+\\.testserver"},
					}, trace.Processes[parent.ProcessID].Tags)
					return len(sd) == 0
				}, testTimeout, 100*time.Millisecond, "waiting for traces to be decorated properly")

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
