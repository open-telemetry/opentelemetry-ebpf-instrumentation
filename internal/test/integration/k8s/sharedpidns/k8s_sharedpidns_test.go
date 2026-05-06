// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sharedpidns

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
	k8s "go.opentelemetry.io/obi/internal/test/integration/k8s/common"
)

// TestSharedPIDNamespaceAttribution verifies that when a DaemonSet with
// hostPID=true runs alongside a normal Deployment, OBI correctly attributes
// spans to their respective pods. Before the fix in PodContainerByPIDNs,
// multiple containers sharing the host PID namespace (init_pid_ns inode
// 4026531836) would cause spans to be arbitrarily attributed to whichever
// pod happened to be iterated first in a Go map — leading to cross-pod
// misattribution of service.name, k8s.namespace.name, k8s.pod.name, etc.
func TestSharedPIDNamespaceAttribution(t *testing.T) {
	feat := features.New("Spans from hostPID pods are not misattributed to other pods").
		Assess("spans from the Deployment get the Deployment's k8s metadata",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					// Generate traffic to the Deployment's testserver (port 8080)
					resp, err := http.Get("http://localhost:38080/pingpong")
					require.NoError(ct, err)
					if resp == nil {
						return
					}

					func() {
						if resp.Body != nil {
							defer func() {
								require.NoError(ct, resp.Body.Close())
							}()
						}

						require.Equal(ct, http.StatusOK, resp.StatusCode)
					}()

					resp, err = http.Get(jaegerQueryURL + "?service=testserver")
					require.NoError(ct, err)
					if resp == nil {
						return
					}

					var tq jaeger.TracesQuery
					func() {
						if resp.Body != nil {
							defer func() {
								require.NoError(ct, resp.Body.Close())
							}()
						}

						require.Equal(ct, http.StatusOK, resp.StatusCode)
						require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
					}()
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/pingpong"})
					require.NotEmpty(ct, traces)
					trace := traces[0]
					require.NotEmpty(ct, trace.Spans)

					res := trace.FindByOperationName("GET /pingpong", "server")
					require.Len(ct, res, 1)
					parent := res[0]

					// The Deployment's spans must carry the Deployment's k8s metadata,
					// NOT the hostPID DaemonSet's metadata
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^testserver-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "testserver"},
						{Key: "k8s.deployment.name", Type: "string", Value: "^testserver$"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.testserver-.+\\.testserver"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(ct, sd, sd.String())
				}, testTimeout, 100*time.Millisecond)
				return ctx
			},
		).
		Assess("spans from the hostPID DaemonSet get the DaemonSet's k8s metadata",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					// Generate traffic to the hostPID DaemonSet's testserver (port 8082)
					trafficResp, err := http.Get("http://localhost:38082/pingpong")
					require.NoError(ct, err)
					if trafficResp == nil {
						return
					}
					defer trafficResp.Body.Close()
					require.Equal(ct, http.StatusOK, trafficResp.StatusCode)

					jaegerResp, err := http.Get(jaegerQueryURL + "?service=hostpid-httpserver")
					require.NoError(ct, err)
					if jaegerResp == nil {
						return
					}
					defer jaegerResp.Body.Close()
					require.Equal(ct, http.StatusOK, jaegerResp.StatusCode)
					var tq jaeger.TracesQuery
					require.NoError(ct, json.NewDecoder(jaegerResp.Body).Decode(&tq))
					traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/pingpong"})
					require.NotEmpty(ct, traces)
					trace := traces[0]
					require.NotEmpty(ct, trace.Spans)

					res := trace.FindByOperationName("GET /pingpong", "server")
					require.Len(ct, res, 1)
					parent := res[0]

					// The DaemonSet's spans must carry the DaemonSet's k8s metadata,
					// NOT the Deployment's metadata
					sd := jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.pod.name", Type: "string", Value: "^hostpid-httpserver-.*"},
						{Key: "k8s.container.name", Type: "string", Value: "hostpid-httpserver"},
						{Key: "k8s.daemonset.name", Type: "string", Value: "^hostpid-httpserver$"},
						{Key: "k8s.namespace.name", Type: "string", Value: "^default$"},
						{Key: "k8s.node.name", Type: "string", Value: ".+-control-plane$"},
						{Key: "k8s.pod.uid", Type: "string", Value: k8s.UUIDRegex},
						{Key: "k8s.pod.start_time", Type: "string", Value: k8s.TimeRegex},
						{Key: "service.instance.id", Type: "string", Value: "^default\\.hostpid-httpserver-.+\\.hostpid-httpserver"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Empty(ct, sd, sd.String())

					// Verify no deployment metadata leaks onto DaemonSet spans
					sd = jaeger.DiffAsRegexp([]jaeger.Tag{
						{Key: "k8s.deployment.name", Type: "string"},
					}, trace.Processes[parent.ProcessID].Tags)
					require.Equal(ct, jaeger.DiffResult{
						{ErrType: jaeger.ErrTypeMissing, Expected: jaeger.Tag{Key: "k8s.deployment.name", Type: "string"}},
					}, sd)
				}, testTimeout, 100*time.Millisecond)
				return ctx
			},
		).Feature()
	cluster.TestEnv().Test(t, feat)
}
