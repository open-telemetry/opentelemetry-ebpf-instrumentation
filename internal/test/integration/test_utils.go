// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

/*
TestCaseSpan represents a span that is expected to be produced by the instrumented service
- Name: the name of the span (example: HSET)
- Attributes: a list of attributes that are expected to be present in the span
*/
type TestCaseSpan struct {
	Name       string
	Attributes []attribute.KeyValue
}

func (span TestCaseSpan) FindAttribute(key string) *attribute.KeyValue {
	for _, attr := range span.Attributes {
		if strings.EqualFold(string(attr.Key), key) {
			return &attr
		}
	}
	return nil
}

/*
TestCase represents a test case for the RED metrics, where calling an endpoint is expected to produce spans
- Route: the URL of the instrumented service (example: http://localhost:8381)
- Subpath: the subpath of the endpoint to call (without leading /) (example: redis)
- Comm: the name of the instrumented service (example: python3.12)
- Namespace: the namespace of the service (example: integration-test)
- Spans: a list of spans that are expected to be produced by the instrumented service, each span has:
*/
type TestCase struct {
	Route     string
	Subpath   string
	Comm      string
	Namespace string
	Spans     []TestCaseSpan
}

const (
	nodeTestServerContainerName = "integration-ntestserver-1"
	nodeTestServerHostPort      = 33031
	nodeTestServerContainerPort = 3030
)

type loopbackTarget struct {
	containerName string
	containerPort int
}

var (
	loopbackTargetsByPort = map[string]loopbackTarget{
		"33031": {containerName: nodeTestServerContainerName, containerPort: nodeTestServerContainerPort},
		"3034":  {containerName: "integration-ntestserverssl-1", containerPort: 3033},
		"3041":  {containerName: "integration-utestserver-1", containerPort: 3040},
		"3044":  {containerName: "integration-utestserverssl-1", containerPort: 3043},
		"38080": {containerName: "integration-testserver-unused-1", containerPort: 8080},
		"7773":  {containerName: "integration-pytestserver-1", containerPort: 7773},
		"8080":  {containerName: "integration-testserver-1", containerPort: 8080},
		"8088":  {containerName: "integration-testserver-1", containerPort: 8088},
		"8086":  {containerName: "integration-jtestserver-1", containerPort: 8085},
		"8091":  {containerName: "integration-rtestserver-1", containerPort: 8090},
		"8900":  {containerName: "integration-testserver1-1", containerPort: 8900},
		"8999":  {containerName: "integration-obi-1", containerPort: 8999},
		"9090":  {containerName: "prometheus", containerPort: 9090},
		"8381":  {containerName: "integration-pytestserverssl-1", containerPort: 8380},
		"8491":  {containerName: "integration-rtestserverssl-1", containerPort: 8490},
		"18080": {containerName: "integration-testserver-duplicate-1", containerPort: 18080},
		"18090": {containerName: "integration-testserver-duplicate-1", containerPort: 18090},
		"16686": {containerName: "integration-jaeger-1", containerPort: 16686},
	}
	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer

			host, port, err := net.SplitHostPort(addr)
			if err == nil && host == "localhost" {
				loopbackAddr := net.JoinHostPort("127.0.0.1", port)
				if target, ok := loopbackTargetsByPort[port]; ok {
					conn, loopbackErr := d.DialContext(ctx, network, loopbackAddr)
					if loopbackErr == nil {
						return conn, nil
					}
					if resolved := resolveContainerAddr(target); resolved != "" {
						return d.DialContext(ctx, network, resolved)
					}
				}
				addr = loopbackAddr
			}

			return d.DialContext(ctx, network, addr)
		},
	}
	testHTTPClient = &http.Client{Transport: tr}
)

func init() {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := base.Clone()
		clone.DialContext = tr.DialContext
		http.DefaultTransport = clone
		http.DefaultClient.Transport = clone
	}
}

func setHTTPClientDisableKeepAlives(disableKeepAlives bool) {
	testHTTPClient.Transport.(*http.Transport).DisableKeepAlives = disableKeepAlives
}

func resolveContainerAddr(target loopbackTarget) string {
	cmd := exec.Command("docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", target.containerName)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return ""
	}

	return net.JoinHostPort(ip, strconv.Itoa(target.containerPort))
}

func nodeTestServerHTTPURL(tb testing.TB) string {
	tb.Helper()

	return fmt.Sprintf("http://localhost:%d", nodeTestServerHostPort)
}

func doHTTPPost(t *testing.T, path string, status int, jsonBody []byte) {
	req, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
}

//nolint:errcheck
func doHTTPGetWithTimeout(t *testing.T, path string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	testHTTPClient.Do(req)
}

func doHTTPGetIgnoreStatus(t *testing.T, path string) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, _ := testHTTPClient.Do(req)
	require.NotNil(t, r)
}

func doHTTPGetFullResponse(t *testing.T, path string, status int) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NotEmpty(t, body)
}

func doHTTPGetWithTraceparent(t *testing.T, path string, status int, traceparent string) {
	// Random fake body to cause the request to have some size (38 bytes)
	jsonBody := []byte(`{"productId": 123456, "quantity": 100}`)

	req, err := http.NewRequest(http.MethodGet, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Traceparent", traceparent)

	r, err := testHTTPClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
}

func createTraceID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "0123456789abcdef0123456789abcdef"
	}
	return hex.EncodeToString(bytes)
}

func createParentID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "0123456789abcdef"
	}
	return hex.EncodeToString(bytes)
}

func createTraceparent(traceID string, parentID string) string {
	return "00-" + traceID + "-" + parentID + "-01"
}

func waitForTestComponents(t *testing.T, url string) {
	waitForTestComponentsSub(t, url, "/smoke")
}

func waitForTestComponentsHTTP2(t *testing.T, url string) {
	waitForTestComponentsHTTP2Sub(t, url, "/smoke", 1)
}

func waitForTestComponentsSub(t *testing.T, url, subpath string) {
	waitForTestComponentsSubWithTime(t, url, subpath, 2)
}

func waitForTestComponentsSubStatus(t *testing.T, url, subpath string, status int) {
	waitForTestComponentsSubWithTimeAndCode(t, url, subpath, status, 2)
}

func waitForTestComponentsNoMetrics(t *testing.T, url string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(url)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, 2*time.Minute, time.Second)
}

// does a smoke test to verify that all the components that started
// asynchronously are up and communicating properly
func waitForTestComponentsSubWithTime(t *testing.T, url, subpath string, minutes int) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="` + subpath + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, time.Duration(minutes)*time.Minute, time.Second)
}

func waitForTestComponentsSubWithTimeAndCode(t *testing.T, url, subpath string, status, minutes int) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, status, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="` + subpath + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, time.Duration(minutes)*time.Minute, time.Second)
}

func waitForTestComponentsRoute(t *testing.T, url, route string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+route, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{http_route="` + route + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 1*time.Minute, time.Second)
}

func waitForSQLTestComponentsMySQL(t *testing.T, url, subpath string) {
	waitForSQLTestComponentsWithDB(t, url, subpath, "mysql")
}

func waitForSQLTestComponentsWithDB(t *testing.T, url, subpath, db string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="` + db + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 1*time.Minute, time.Second)
}

func enoughPromResults(t require.TestingT, results []promtest.Result) {
	require.GreaterOrEqual(t, len(results), 1)
}

func totalPromCount(t require.TestingT, results []promtest.Result) int {
	total := 0
	for _, res := range results {
		require.Len(t, res.Value, 2)
		val, err := strconv.Atoi(res.Value[1].(string))
		require.NoError(t, err)
		total += val
	}

	return total
}

func checkServerPromQueryResult(t require.TestingT, pq promtest.Client, query string, promCount int) {
	results, err := pq.Query(query)
	require.NoError(t, err)
	// check duration_count has 3 calls and all the arguments
	enoughPromResults(t, results)
	val := totalPromCount(t, results)
	assert.LessOrEqual(t, promCount, val)
	if len(results) > 0 {
		res := results[0]
		addr := res.Metric["client_address"]
		assert.NotNil(t, addr)
	}
}

func checkClientPromQueryResult(t require.TestingT, pq promtest.Client, query string, promCount int) {
	results, err := pq.Query(query)
	require.NoError(t, err)
	enoughPromResults(t, results)
	val := totalPromCount(t, results)
	assert.LessOrEqual(t, promCount, val)
}

func doHTTP2Post(t *testing.T, path string, status int, jsonBody []byte) {
	req, err := http.NewRequest(http.MethodPost, path, bytes.NewReader(jsonBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	tr := newHTTP2Transport()

	r, err := tr.RoundTrip(req)

	require.NoError(t, err)
	require.Equal(t, status, r.StatusCode)
	require.Equal(t, 2, r.ProtoMajor)
}

func waitForTestComponentsHTTP2Sub(t *testing.T, url, subpath string, minutes int) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		tr := newHTTP2Transport()

		r, err := tr.RoundTrip(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="` + subpath + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, time.Duration(minutes)*time.Minute, time.Second)
}

func otelAttributeToJaegerTag(attr attribute.KeyValue) jaeger.Tag {
	var value any
	value = attr.Value.AsInterface()
	if attr.Value.Type() == attribute.INT64 {
		// jaeger encodes int64 as float64
		value = float64(attr.Value.AsInt64())
	}
	return jaeger.Tag{
		Key:   string(attr.Key),
		Type:  strings.ToLower(attr.Value.Type().String()),
		Value: value,
	}
}

// newHTTP2Transport creates an HTTP transport configured
// to use HTTP/2 with TLS verification disabled.
func newHTTP2Transport() *http.Transport {
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Protocols = protocols
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return tr
}
