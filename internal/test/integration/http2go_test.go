// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	http2OwnedTraceparent = "00-11111111111111111111111111111111-2222222222222222-01"
	http2MuxTraceparent   = "00-33333333333333333333333333333333-4444444444444444-01"

	// testserver-burst, which runs with a single P
	http2BurstAddr      = "localhost:7383"
	http2BurstStreams   = 16
	http2BurstRounds    = 3
	http2BurstIOTimeout = time.Minute
)

var http2TraceparentPattern = regexp.MustCompile(`^00-[[:xdigit:]]{32}-[[:xdigit:]]{16}-[[:xdigit:]]{2}$`)

type http2HeaderObservation struct {
	Traceparents []string `json:"traceparents"`
	RemoteAddr   string   `json:"remote_addr"`
	Protocol     string   `json:"protocol"`
}

type http2BurstObservation struct {
	http2HeaderObservation
	Concurrent bool `json:"concurrent"`
}

type http2BurstStream struct {
	path        string
	traceID     string
	parentID    string
	traceparent string
}

type http2OwnershipResult struct {
	Transport  string                   `json:"transport"`
	Repeated   []http2HeaderObservation `json:"repeated"`
	Controls   []http2HeaderObservation `json:"controls"`
	LargeOwned http2HeaderObservation   `json:"large_owned"`
	LargePlain http2HeaderObservation   `json:"large_plain"`
	MultiPlain http2HeaderObservation   `json:"multi_plain"`
	MuxOwned   http2HeaderObservation   `json:"mux_owned"`
	MuxPlain   http2HeaderObservation   `json:"mux_plain"`
	Error      string                   `json:"error"`
}

func testREDMetricsForHTTP2Library(t *testing.T, route, svcNs string) {
	// Eventually, Prometheus would make this query visible
	var (
		pq           = promtest.Client{HostPort: prometheusHostPort}
		serverLabels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="server",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"`
		clientLabels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="client"`
	)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_request_duration_seconds_count{%s}", serverLabels)
		checkServerPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_request_body_size_bytes_count{%s}", serverLabels)
		checkServerPromQueryResult(ct, pq, query, 3)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_response_body_size_bytes_count{%s}", serverLabels)
		checkServerPromQueryResult(ct, pq, query, 3)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_request_duration_seconds_count{%s}", clientLabels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_request_body_size_bytes_count{%s}", clientLabels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_client_response_body_size_bytes_count{%s}", clientLabels)
		checkClientPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)
}

func testNestedHTTP2Traces(t *testing.T, url string) {
	var traceID string

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=client&operation=GET%20%2F" + url)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, 1*time.Minute, 100*time.Millisecond)

	// Check the information of the HTTP2 client span
	res := trace.FindByOperationName("GET /"+url, "client")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	traceID = parent.TraceID
	require.NotEmpty(t, parent.SpanID)

	// Find the same traceID on a server span
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerQueryURL + "?service=server&operation=GET%20%2F" + url + "&traceID=" + traceID)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, 1*time.Minute, 100*time.Millisecond)
}

func TestHTTP2Go(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2.yml", path.Join(pathOutput, "test-suite-http2.log"))
	require.NoError(t, err)

	testHTTP2GO(t, compose, false)
}

func testHTTP2GO(t *testing.T, compose *docker.Compose, useHTTPProtocols bool) {
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	if useHTTPProtocols {
		compose.Env = append(compose.Env, `TEST_HTTP2_PROTOCOLS=1`)
	}
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http2 service", func(t *testing.T) {
		testREDMetricsForHTTP2Library(t, "/ping", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingdo", "http2-go")
		testREDMetricsForHTTP2Library(t, "/pingrt", "http2-go")
	})

	if !lockdown {
		t.Run("Go RED metrics: http2 context propagation ", func(t *testing.T) {
			testNestedHTTP2Traces(t, "pingdo")
		})
	}

	t.Run("Go HTTP/2 server: concurrent streams on one connection", testHTTP2ServerConcurrentStreams)

	runWeaverValidation(t)

	if !lockdown {
		t.Run("Go HTTP/2 application traceparent ownership", func(t *testing.T) {
			testHTTP2TraceparentOwnership(t, compose)
		})
	}

	require.NoError(t, compose.Close())
}

func testHTTP2TraceparentOwnership(t *testing.T, compose *docker.Compose) {
	tests := []struct {
		name       string
		service    string
		url        string
		transports []string
	}{
		{
			name:       "current",
			service:    "testclient",
			url:        "http://localhost:7575/run",
			transports: []string{"tls", "plaintext"},
		},
		{
			name:       "legacy x/net",
			service:    "testclient-xnet-legacy",
			url:        "http://localhost:7576/run",
			transports: []string{"tls", "plaintext"},
		},
		{
			name:       "legacy stdlib",
			service:    "testclient-stdlib-legacy",
			url:        "http://localhost:7577/run",
			transports: []string{"tls"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testHTTP2TraceparentOwnershipClient(t, compose, test.service, test.url, test.transports)
		})
	}
}

func testHTTP2TraceparentOwnershipClient(
	t *testing.T,
	compose *docker.Compose,
	service string,
	url string,
	transports []string,
) {
	client := &http.Client{Timeout: time.Minute}

	for _, transport := range transports {
		t.Run(transport, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				resp, err := client.Get(url)
				require.NoError(ct, err)
				if err != nil {
					return
				}
				require.Equal(ct, http.StatusNoContent, resp.StatusCode)
				require.NoError(ct, resp.Body.Close())

				logs, err := compose.LogsTail(1000, service)
				require.NoError(ct, err)

				lastErr := fmt.Errorf("no %s ownership result logged", transport)
				for _, result := range parseHTTP2OwnershipResults(logs) {
					if result.Transport != transport {
						continue
					}
					if err := validateHTTP2OwnershipResult(result); err == nil {
						return
					} else {
						lastErr = err
					}
				}
				require.NoError(ct, lastErr, "no valid %s ownership result", transport)
			}, time.Minute, time.Second)
		})
	}
}

func parseHTTP2OwnershipResults(logs string) []http2OwnershipResult {
	const prefix = "HTTP2_OWNERSHIP_RESULT "
	var results []http2OwnershipResult
	for line := range strings.SplitSeq(logs, "\n") {
		_, payload, found := strings.Cut(line, prefix)
		if !found {
			continue
		}
		var result http2OwnershipResult
		if json.Unmarshal([]byte(payload), &result) == nil {
			results = append(results, result)
		}
	}
	return results
}

func validateHTTP2OwnershipResult(result http2OwnershipResult) error {
	if result.Error != "" {
		return fmt.Errorf("client error: %s", result.Error)
	}
	if len(result.Repeated) != 4 {
		return fmt.Errorf("repeated request count: got %d, want 4", len(result.Repeated))
	}

	remoteAddr := result.Repeated[0].RemoteAddr
	for i, observation := range result.Repeated {
		if err := validateHTTP2Observation(observation, http2OwnedTraceparent); err != nil {
			return fmt.Errorf("repeated request %d: %w", i, err)
		}
		if observation.RemoteAddr != remoteAddr {
			return fmt.Errorf("repeated request %d used %q, want persistent connection %q",
				i, observation.RemoteAddr, remoteAddr)
		}
	}

	if len(result.Controls) != 2 {
		return fmt.Errorf("control request count: got %d, want 2", len(result.Controls))
	}
	for i, observation := range result.Controls {
		if err := validateHTTP2InjectedObservation(observation); err != nil {
			return fmt.Errorf("control request %d: %w", i, err)
		}
	}
	if err := validateHTTP2Observation(result.LargeOwned, http2OwnedTraceparent); err != nil {
		return fmt.Errorf("owned CONTINUATION request: %w", err)
	}
	if err := validateHTTP2InjectedObservation(result.LargePlain); err != nil {
		return fmt.Errorf("plain CONTINUATION request: %w", err)
	}
	if err := validateHTTP2InjectedObservation(result.MultiPlain); err != nil {
		return fmt.Errorf("multi-CONTINUATION request: %w", err)
	}
	if result.LargeOwned.RemoteAddr != remoteAddr || result.LargePlain.RemoteAddr != remoteAddr ||
		result.MultiPlain.RemoteAddr != remoteAddr {
		return fmt.Errorf(
			"CONTINUATION requests did not use persistent connection %q: owned=%q plain=%q multi=%q",
			remoteAddr,
			result.LargeOwned.RemoteAddr,
			result.LargePlain.RemoteAddr,
			result.MultiPlain.RemoteAddr,
		)
	}

	if err := validateHTTP2Observation(result.MuxOwned, http2MuxTraceparent); err != nil {
		return fmt.Errorf("owned multiplexed request: %w", err)
	}
	if err := validateHTTP2InjectedObservation(result.MuxPlain); err != nil {
		return fmt.Errorf("plain multiplexed request: %w", err)
	}
	if result.MuxOwned.RemoteAddr != result.MuxPlain.RemoteAddr ||
		result.MuxOwned.RemoteAddr != remoteAddr {
		return fmt.Errorf("multiplexed requests did not share persistent connection %q: owned=%q plain=%q",
			remoteAddr, result.MuxOwned.RemoteAddr, result.MuxPlain.RemoteAddr)
	}
	return nil
}

func validateHTTP2Observation(observation http2HeaderObservation, want string) error {
	if observation.Protocol != "HTTP/2.0" {
		return fmt.Errorf("protocol: got %q, want HTTP/2.0", observation.Protocol)
	}
	if len(observation.Traceparents) != 1 || observation.Traceparents[0] != want {
		return fmt.Errorf("traceparents: got %q, want [%s]", observation.Traceparents, want)
	}
	return nil
}

func validateHTTP2InjectedObservation(observation http2HeaderObservation) error {
	if observation.Protocol != "HTTP/2.0" {
		return fmt.Errorf("protocol: got %q, want HTTP/2.0", observation.Protocol)
	}
	if len(observation.Traceparents) != 1 {
		return fmt.Errorf("traceparent count: got %d, want 1 (%q)",
			len(observation.Traceparents), observation.Traceparents)
	}
	traceparent := observation.Traceparents[0]
	if !http2TraceparentPattern.MatchString(traceparent) {
		return fmt.Errorf("invalid injected traceparent %q", traceparent)
	}
	if traceparent == http2OwnedTraceparent || traceparent == http2MuxTraceparent {
		return fmt.Errorf("owned traceparent leaked into unowned stream: %q", traceparent)
	}
	return nil
}

// testHTTP2ServerConcurrentStreams sends bursts of streams over one connection, with every
// HEADERS frame of a burst in a single write, and checks that each server span took its parent
// from the traceparent of its own stream (issue #3571).
func testHTTP2ServerConcurrentStreams(t *testing.T) {
	client := dialHTTP2Burst(t, http2BurstAddr)
	defer client.conn.Close()

	// a lone stream proves the server is instrumented before any burst is judged
	warmup := newHTTP2BurstStreams(createParentID(), 1)
	requireHTTP2BurstStimulus(t, warmup, client.send(t, warmup))
	assertHTTP2BurstParents(t, warmup)

	for range http2BurstRounds {
		streams := newHTTP2BurstStreams(createParentID(), http2BurstStreams)
		requireHTTP2BurstStimulus(t, streams, client.send(t, streams))
		assertHTTP2BurstParents(t, streams)
	}
}

type http2BurstClient struct {
	conn         *tls.Conn
	authority    string
	pending      bytes.Buffer
	writer       *http2.Framer
	block        bytes.Buffer
	encoder      *hpack.Encoder
	reader       *http2.Framer
	nextStreamID uint32
}

// TLS only: h2c skips net/http's serverHandler, where OBI starts Go server spans
func dialHTTP2Burst(t *testing.T, addr string) *http2BurstClient {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	require.NoError(t, err)
	require.Equal(t, http2.NextProtoTLS, conn.ConnectionState().NegotiatedProtocol)

	client := &http2BurstClient{conn: conn, authority: addr, nextStreamID: 1}
	client.pending.WriteString(http2.ClientPreface)
	client.writer = http2.NewFramer(&client.pending, nil)
	require.NoError(t, client.writer.WriteSettings())
	client.encoder = hpack.NewEncoder(&client.block)
	client.reader = http2.NewFramer(conn, conn)
	client.reader.ReadMetaHeaders = hpack.NewDecoder(http2InitialHeaderTableSize, nil)
	return client
}

// http2InitialHeaderTableSize is SETTINGS_HEADER_TABLE_SIZE before any SETTINGS frame
const http2InitialHeaderTableSize = 4096

// every fourth stream carries no traceparent, so its span must not adopt another stream's
const http2BurstUntracedEvery = 4

func newHTTP2BurstStreams(burstID string, count int) []http2BurstStream {
	streams := make([]http2BurstStream, count)
	for i := range streams {
		streams[i].path = fmt.Sprintf("/burst/%s/%d", burstID, i)
		if i%http2BurstUntracedEvery == http2BurstUntracedEvery-1 {
			continue
		}
		streams[i].traceID = createTraceID()
		streams[i].parentID = createParentID()
		streams[i].traceparent = createTraceparent(streams[i].traceID, streams[i].parentID)
	}
	return streams
}

// send writes one HEADERS frame per stream with a single write, so a server with one P decodes
// the whole burst before it runs any handler, and returns what each handler observed
func (c *http2BurstClient) send(t *testing.T, streams []http2BurstStream) []http2BurstObservation {
	firstStreamID := c.nextStreamID
	for _, stream := range streams {
		c.block.Reset()
		fields := []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: c.authority},
			{Name: ":path", Value: fmt.Sprintf("%s?size=%d", stream.path, len(streams))},
		}
		if stream.traceparent != "" {
			fields = append(fields, hpack.HeaderField{Name: "traceparent", Value: stream.traceparent})
		}
		for _, field := range fields {
			require.NoError(t, c.encoder.WriteField(field))
		}
		require.NoError(t, c.writer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      c.nextStreamID,
			BlockFragment: c.block.Bytes(),
			EndStream:     true,
			EndHeaders:    true,
		}))
		c.nextStreamID += 2 // client-initiated streams are odd
	}

	require.NoError(t, c.conn.SetDeadline(time.Now().Add(http2BurstIOTimeout)))
	_, err := c.conn.Write(c.pending.Bytes())
	require.NoError(t, err)
	c.pending.Reset()

	return c.readResponses(t, firstStreamID, len(streams))
}

func (c *http2BurstClient) readResponses(t *testing.T, firstStreamID uint32, count int) []http2BurstObservation {
	bodies := make([]bytes.Buffer, count)
	index := func(streamID uint32) int {
		i := int(streamID-firstStreamID) / 2
		require.Truef(t, streamID >= firstStreamID && i < count, "frame for unexpected stream %d", streamID)
		return i
	}

	for ended := 0; ended < count; {
		frame, err := c.reader.ReadFrame()
		require.NoError(t, err)
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				require.NoError(t, c.reader.WriteSettingsAck())
			}
		case *http2.MetaHeadersFrame:
			require.Equalf(t, "200", f.PseudoValue("status"), "stream %d", f.StreamID)
			index(f.StreamID)
			if f.StreamEnded() {
				ended++
			}
		case *http2.DataFrame:
			bodies[index(f.StreamID)].Write(f.Data())
			if f.StreamEnded() {
				ended++
			}
		case *http2.RSTStreamFrame:
			require.Failf(t, "stream reset by the server", "stream %d: %v", f.StreamID, f.ErrCode)
		case *http2.GoAwayFrame:
			require.Failf(t, "connection closed by the server", "%v", f.ErrCode)
		}
	}

	observations := make([]http2BurstObservation, count)
	for i := range bodies {
		require.NoErrorf(t, json.Unmarshal(bodies[i].Bytes(), &observations[i]), "stream %d: %q", i, bodies[i].String())
	}
	return observations
}

// requireHTTP2BurstStimulus fails the test unless every stream reached the server over the same
// connection with exactly the traceparent it was sent, while the whole burst was in flight
func requireHTTP2BurstStimulus(t *testing.T, streams []http2BurstStream, observations []http2BurstObservation) {
	for i, observation := range observations {
		require.Equalf(t, "HTTP/2.0", observation.Protocol, "stream %d", i)
		require.Truef(t, observation.Concurrent, "stream %d: the burst was not in flight at once", i)
		require.Equalf(t, observations[0].RemoteAddr, observation.RemoteAddr, "stream %d used another connection", i)

		var want []string
		if streams[i].traceparent != "" {
			want = []string{streams[i].traceparent}
		}
		require.Equalf(t, want, observation.Traceparents, "stream %d", i)
	}
}

func assertHTTP2BurstParents(t *testing.T, streams []http2BurstStream) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var problems []string
		for i, stream := range streams {
			span, found := http2BurstServerSpan(ct, "GET "+stream.path)
			if !found {
				problems = append(problems, fmt.Sprintf("stream %d: no server span", i))
				continue
			}
			if stream.traceparent == "" {
				if len(span.References) != 0 {
					problems = append(problems, fmt.Sprintf("stream %d sent no traceparent, got parent %v", i, span.References))
				}
				continue
			}
			want := jaeger.Reference{RefType: "CHILD_OF", TraceID: stream.traceID, SpanID: stream.parentID}
			if !slices.Contains(span.References, want) {
				problems = append(problems, fmt.Sprintf("stream %d: got parent %v, want %v", i, span.References, want))
			}
		}
		assert.Empty(ct, problems, "server spans must take the parent of their own stream")
	}, testTimeout, time.Second)
}

func http2BurstServerSpan(ct *assert.CollectT, operation string) (jaeger.Span, bool) {
	query := url.Values{"service": {"server"}, "operation": {operation}}
	resp, err := getJaeger(jaegerQueryURL + "?" + query.Encode())
	require.NoError(ct, err)
	defer resp.Body.Close()
	require.Equal(ct, http.StatusOK, resp.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
	for _, trace := range tq.Data {
		if spans := trace.FindByOperationName(operation, "server"); len(spans) > 0 {
			return spans[0], true
		}
	}
	return jaeger.Span{}, false
}

func TestHTTP2GoWithHTTPProtocols(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-http2.yml", path.Join(pathOutput, "test-suite-http2-protocols.log"))
	require.NoError(t, err)

	testHTTP2GO(t, compose, true)
}
