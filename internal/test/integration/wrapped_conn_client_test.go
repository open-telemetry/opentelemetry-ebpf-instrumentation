// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// enough scrapes that a per-request failure rate of a few percent shows up every run
const minWrappedConnTraces = 200

const minWrappedTLSConnTraces = 5

// OBI names the service after the executable, there being no k8s metadata here
const wrappedConnService = "vmagent-prod"

const wrappedTLSConnService = "httppinger"

// TestWrappedConnClientSpans covers a Go client whose net.Conn is wrapped by a struct
// that does not hold the connection as its first field, so it cannot be read off the
// request goroutine. With context propagation on, the generic kprobe pipeline then
// reports a request the Go uprobes already reported, leaving two parentless client
// spans for the same call.
func TestWrappedConnClientSpans(t *testing.T) {
	assertWrappedClientSpans(t, "docker-compose-wrapped-conn.yml", wrappedConnService, minWrappedConnTraces)
}

func TestWrappedTLSConnClientSpans(t *testing.T) {
	assertWrappedClientSpans(t, "docker-compose-wrapped-tls-conn.yml", wrappedTLSConnService, minWrappedTLSConnTraces)
}

func assertWrappedClientSpans(t *testing.T, composeFile, service string, minTraces int) {
	compose, err := docker.ComposeSuite(composeFile, path.Join(pathOutput, "test-suite-"+service+".log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	var traces []jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + service + "&limit=1500")
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.GreaterOrEqualf(ct, len(tq.Data), minTraces,
			"need at least %d request traces before judging duplication", minTraces)
		traces = tq.Data
	}, 3*time.Minute, time.Second)

	// Every scrape yields two client spans: one carrying the socket 4-tuple and one
	// with no connection info at all (server.port 0). They pair up 1:1, and land in
	// separate traces, so counting parentless spans within a trace misses them.
	unattributed := map[string]int{}
	attributed := map[string]int{}

	for _, trace := range traces {
		for _, span := range trace.Spans {
			if spanKind(span) != "client" {
				continue
			}

			target, _ := jaeger.FindIn(span.Tags, "server.address")
			port, _ := jaeger.FindIn(span.Tags, "server.port")

			key := fmt.Sprintf("%v", target.Value)
			if fmt.Sprintf("%v", port.Value) == "0" {
				unattributed[key]++
			} else {
				attributed[key]++
			}
		}
	}

	assert.Emptyf(t, unattributed, "client spans reported without connection info, one per "+
		"properly reported call, so every outgoing request was reported twice: "+
		"unattributed=%v attributed=%v", unattributed, attributed)

	// the other half of the check: dropping the duplicate must not drop the call
	assert.NotEmptyf(t, attributed, "no client span carries connection info, so the calls "+
		"stopped being reported at all: unattributed=%v", unattributed)

	for target, count := range attributed {
		assert.GreaterOrEqualf(t, count, 5,
			"only %d fully attributed client spans for %s, so calls went missing", count, target)
	}

	require.NoError(t, compose.Close())
}

func spanKind(s jaeger.Span) string {
	if tag, ok := jaeger.FindIn(s.Tags, "span.kind"); ok {
		if v, ok := tag.Value.(string); ok {
			return v
		}
	}
	return ""
}
