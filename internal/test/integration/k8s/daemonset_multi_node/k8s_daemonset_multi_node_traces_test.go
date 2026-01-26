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
)

// For the this scenario we run two worker nodes, with the following structure:
//   - worker 1:
//     testserver [go app] port: 8080
//     testserver [go jsonrpc app] port: 8088
//   - worker 2:
//     pythonserver [python app] port: 7773
//     ruby on rails [ruby app] port: 3040
//
// The call flow is as follows:
//
//	testserver [/gotracemetoo] -> go jsonrpc [/jsonrpc] -> Python server [/tracemetoo] -> Ruby server [/users]
//
// They should all have the same traceID. Across nodes the TCP context propagation (OTEL_EBPF_BPF_CONTEXT_PROPAGATION)
// connects the dots, while on the same node, the networking is optimized and we rely on black-box context propagation to
// connect the services.
func TestMultiNodeTracing(t *testing.T) {
	feat := features.New("OBI is able to generate distributed traces go->go jsonrpc->python->ruby").
		Assess("it sends connected traces for all services",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var trace jaeger.Trace
				var traceID string
				require.Eventually(t, func() bool {
					resp, err := http.Get("http://localhost:38080/gotracemetoo")
					if err != nil || resp.StatusCode != http.StatusOK {
						return false
					}

					resp, err = http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fgotracemetoo")
					if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
						return false
					}
					var tq jaeger.TracesQuery
					if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
						return false
					}
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/gotracemetoo"})
					if len(traces) == 0 {
						return false
					}
					trace = traces[0]
					if len(trace.Spans) == 0 {
						return false
					}

					// Check the information of the parent span (Go app)
					res := trace.FindByOperationName("GET /gotracemetoo", "server")
					if len(res) != 1 {
						return false
					}
					parent := res[0]
					if parent.TraceID == "" {
						return false
					}
					traceID = parent.TraceID
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "service.namespace", Type: "string", Value: "^integration-test$"},
						{Key: "telemetry.sdk.language", Type: "string", Value: "^go$"},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.testserver-.+\\.testserver$"},
					}, trace.Processes[parent.ProcessID].Tags)
					if len(sd) > 0 {
						return false
					}

					// Check the information of the Go jsonrpc span
					res = trace.FindByOperationName("Arith.T /jsonrpc", "server")
					if len(res) != 1 {
						return false
					}
					parent = res[0]
					if parent.TraceID == "" || parent.TraceID != traceID {
						return false
					}

					// Check the information of the Python span
					res = trace.FindByOperationName("GET /tracemetoo", "server")
					if len(res) != 1 {
						return false
					}
					parent = res[0]
					if parent.TraceID == "" || parent.TraceID != traceID {
						return false
					}

					// Check the information of the Ruby span
					res = trace.FindByOperationName("GET /users", "server")
					if len(res) != 1 {
						return false
					}
					parent = res[0]
					if parent.TraceID == "" || parent.TraceID != traceID {
						return false
					}
					return true
				}, testTimeout, 100*time.Millisecond, "waiting for multi-node distributed traces")

				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
