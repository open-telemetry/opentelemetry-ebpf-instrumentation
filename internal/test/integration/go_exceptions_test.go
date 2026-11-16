// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"errors"
	"fmt"
	"go/version"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// The ports and service names of docker-compose-go-exceptions.yml
var (
	goExceptionsDefault  = goExceptionsService{"go-exceptions-default", "http://127.0.0.1:18590"}
	goExceptionsDisabled = goExceptionsService{"go-exceptions-disabled", "http://127.0.0.1:18593"}
)

var goExceptionSelections = []struct {
	service                 goExceptionsService
	panics, formattedErrors bool
}{
	{goExceptionsService{"go-exceptions-panic-only", "http://127.0.0.1:18592"}, true, false},
	{goExceptionsService{"go-exceptions-errors-only", "http://127.0.0.1:18599"}, false, true},
	{goExceptionsService{"go-exceptions-neither", "http://127.0.0.1:18600"}, false, false},
}

// goExceptionsBuilds serve the fixture built in other modes. Before Go 1.26
// a PIE executable keeps its pclntab in .data.rel.ro.gopclntab, which Go
// discovery does not read, so OBI does not instrument it as Go at all.
var goExceptionsBuilds = []struct {
	service goExceptionsService
	pie     bool
}{
	{goExceptionsService{"go-exceptions-stripped", "http://127.0.0.1:18594"}, false},
	{goExceptionsService{"go-exceptions-pie", "http://127.0.0.1:18595"}, true},
	{goExceptionsService{"go-exceptions-stripped-pie", "http://127.0.0.1:18591"}, true},
	{goExceptionsService{"go-exceptions-cgo", "http://127.0.0.1:18596"}, false},
	{goExceptionsService{"go-exceptions-static-cgo", "http://127.0.0.1:18597"}, false},
	{goExceptionsService{"go-exceptions-trimpath", "http://127.0.0.1:18598"}, false},
}

// Without keep-alive, a connection that net/http closes unanswered fails its
// request instead of being retried.
var goExceptionsClient = &http.Client{
	Timeout:   5 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

type goExceptionsService struct{ name, url string }

type goRequest struct {
	service goExceptionsService
	name    string
	status  int
}

type goExpectedException struct {
	typ           string
	messagePrefix string
	owned         bool
}

type goExceptionCase struct {
	name   string
	status int // 0: net/http closes the connection without a response
	// records that must be present; every owned record must carry the trace
	// and span of the request's server span. None means none may be captured.
	expected []goExpectedException
	// OBI takes the status of the recovery's superfluous WriteHeader(500),
	// not the 202 already sent: a span issue outside exception capture
	anySpanStatus bool
}

type goExceptionLog struct {
	service, typ, message, stack string
	traceID, spanID              string
	severity                     plog.SeverityNumber
}

// processingSpanID is the request's own span, which owns its exceptions and
// its outgoing calls. OBI exports it as the "processing" child of the server
// span when the request queued, and as the server span otherwise.
type goServerSpan struct {
	service, path    string
	traceID, spanID  string
	processingSpanID string
	status           int64
}

// Go 1.17 is the oldest the Go tracer supports, 1.21 moved runtime types to
// internal/abi, and 1.26 split fmt.Errorf into a wrapper around fmt.errorf.
var goExceptionsBuilders = []struct {
	version string
	minor   int
	image   string
}{
	{"1.17", 17, "golang:1.17.13@sha256:87262e4a4c7db56158a80a18fefdc4fee5accc41b59cde821e691d05541bbb18"},
	{"1.21", 21, "golang:1.21.13@sha256:4746d26432a9117a5f58e95cb9f954ddf0de128e9d5816886514199316e4a2fb"},
	{"1.25", 25, runtimeMetricsGo125BuilderImage},
	{"1.26", 26, "golang:1.26.5@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647"},
	{"1.27", 27, "golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1"},
}

func TestGoExceptions(t *testing.T) {
	for _, builder := range goExceptionsBuilders {
		t.Run("go"+builder.version, func(t *testing.T) {
			var builds []goExceptionsService
			for _, build := range goExceptionsBuilds {
				if !build.pie || builder.minor >= 26 {
					builds = append(builds, build.service)
				}
			}
			testGoExceptions(t, builder.version, builder.image, builds)
		})
	}
}

func testGoExceptions(t *testing.T, goVersion, goImage string, builds []goExceptionsService) {
	conversionTarget := "pointer to array"
	if version.Compare("go"+goVersion, "go1.20") >= 0 {
		conversionTarget = "array or pointer to array"
	}
	out := path.Join(pathOutput, "go-exceptions")
	require.NoError(t, os.RemoveAll(out))
	require.NoError(t, os.MkdirAll(out, 0o777))
	// the collector writes as another user
	require.NoError(t, os.Chmod(out, 0o777))

	compose, err := docker.ComposeSuite("docker-compose-go-exceptions.yml",
		path.Join(pathOutput, "test-suite-go-exceptions-"+goVersion+".log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "GO_EXCEPTIONS_GO_IMAGE="+goImage, "GO_EXCEPTIONS_TAG="+goVersion)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	// Exceptions raised before OBI attaches to a process are not captured.
	for _, service := range append([]goExceptionsService{goExceptionsDefault}, builds...) {
		attempt := 0
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			attempt++
			goExceptionsGet(ct, service, "fmt", fmt.Sprintf("warmup-%d", attempt), http.StatusInternalServerError)
			logs, _ := readGoExceptionTelemetry(ct, out)
			assert.NotEmpty(ct, goLogsOfService(logs, service), "no exception log from %s yet", service.name)
		}, 3*testTimeout, time.Second)
	}
	attempt := 0
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		attempt++
		goExceptionsGet(ct, goExceptionsDisabled, "healthy", fmt.Sprintf("warmup-%d", attempt), http.StatusOK)
		_, spans := readGoExceptionTelemetry(ct, out)
		assert.True(ct, goHasSpanOfService(spans, goExceptionsDisabled), "no span from %s yet", goExceptionsDisabled.name)
	}, 3*testTimeout, time.Second)

	for _, selection := range goExceptionSelections {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			goExceptionsGet(ct, selection.service, "healthy", "selection-warmup", http.StatusOK)
			_, spans := readGoExceptionTelemetry(ct, out)
			assert.True(ct, goHasSpanOfService(spans, selection.service))
		}, 3*testTimeout, time.Second)
	}
	cases := []goExceptionCase{
		{name: "healthy", status: http.StatusOK},
		{name: "fmt", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.error", messagePrefix: "fmt:", owned: true},
		}},
		{name: "fmt-wrap", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.error", messagePrefix: "wrap:", owned: true},
		}},
		{name: "handled-fmt", status: http.StatusOK, expected: []goExpectedException{
			{typ: "go.error", messagePrefix: "handled:", owned: true},
		}},
		// errors are captured where fmt.Errorf builds them, not where they are rendered
		{name: "sentinel", status: http.StatusInternalServerError},
		// the child goroutine does not serve the request
		{name: "child-fmt", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.error", messagePrefix: "child:", owned: false},
		}},
		{name: "panic-string", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "panic:", owned: true},
		}},
		{name: "panic-after-write", status: http.StatusAccepted, anySpanStatus: true, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "panic:", owned: true},
		}},
		{name: "panic-nil-pointer", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: invalid memory address or nil pointer dereference", owned: true},
		}},
		// the fault is the first instruction of the method
		{name: "panic-nil-receiver", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: invalid memory address or nil pointer dereference", owned: true},
		}},
		{name: "panic-divide", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: integer divide by zero", owned: true},
		}},
		{name: "panic-nil-channel", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "close of nil channel", owned: true},
		}},
		{name: "panic-mapped-file", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: invalid memory address or nil pointer dereference", owned: true},
		}},
		{name: "panic-index", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: index out of range [5] with length 3", owned: true},
		}},
		{name: "panic-slice", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: slice bounds out of range [:5] with capacity 3", owned: true},
		}},
		{name: "panic-slice-three-index", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: slice bounds out of range [::5] with capacity 3", owned: true},
		}},
		{name: "panic-slice-conversion", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "runtime error: cannot convert slice with length 3 to " + conversionTarget + " with length 5", owned: true},
		}},
		{name: "panic-nethttp", status: 0, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "panic:", owned: true},
		}},
		{name: "panic-standard-error", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "boom", owned: true},
		}},
		{name: "panic-int", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "5", owned: true},
		}},
		{name: "panic-int8", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "-128", owned: true},
		}},
		{name: "panic-uint64", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "18446744073709551615", owned: true},
		}},
		{name: "panic-bool", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.panic", messagePrefix: "true", owned: true},
		}},
		{name: "panic-wrapped-error", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.error", messagePrefix: "failed: sentinel", owned: true},
			{typ: "go.panic", messagePrefix: "failed: sentinel", owned: true},
		}},
	}
	if version.Compare("go"+goVersion, "go1.20") >= 0 {
		cases = append(cases, goExceptionCase{name: "panic-multiple-errors", status: http.StatusInternalServerError, expected: []goExpectedException{
			{typ: "go.error", messagePrefix: "sentinel and second", owned: true},
			{typ: "go.panic", messagePrefix: "sentinel and second", owned: true},
		}})
	}
	// both probe kinds, an unowned record, and a runtime panic
	buildCases := goCasesNamed(cases, "fmt", "child-fmt", "panic-string", "panic-nil-pointer", "panic-nil-receiver", "panic-divide", "panic-nil-channel", "panic-mapped-file", "panic-index", "panic-slice", "panic-slice-three-index", "panic-slice-conversion", "panic-standard-error", "panic-wrapped-error", "panic-multiple-errors", "panic-int", "panic-int8", "panic-uint64", "panic-bool")
	var requests []goRequest
	for _, c := range cases {
		requests = append(requests, goRequest{goExceptionsDefault, c.name, c.status})
	}
	for _, build := range builds {
		for _, c := range buildCases {
			requests = append(requests, goRequest{build, c.name, c.status})
		}
	}
	requests = append(requests,
		goRequest{goExceptionsDisabled, "fmt", http.StatusInternalServerError})
	for _, selection := range goExceptionSelections {
		requests = append(requests,
			goRequest{selection.service, "fmt", http.StatusInternalServerError},
			goRequest{selection.service, "panic-string", http.StatusInternalServerError})
	}
	for _, r := range requests {
		goExceptionsGet(t, r.service, r.name, goCaseID(r.name), r.status)
	}

	var logs []goExceptionLog
	var spans []goServerSpan
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, spans = readGoExceptionTelemetry(ct, out)
		for _, r := range requests {
			_, ok := goSpanFor(spans, r.service, goCasePath(r.name, goCaseID(r.name)))
			assert.True(ct, ok, "no server span for %s %s", r.service.name, r.name)
		}
	}, testTimeout, time.Second)
	// records come through another ring than spans, and can arrive later
	time.Sleep(2 * time.Second)
	logs, spans = readGoExceptionTelemetry(t, out)

	runs := []struct {
		service goExceptionsService
		cases   []goExceptionCase
	}{{goExceptionsDefault, cases}}
	for _, build := range builds {
		runs = append(runs, struct {
			service goExceptionsService
			cases   []goExceptionCase
		}{build, buildCases})
	}
	for _, run := range runs {
		for _, c := range run.cases {
			t.Run(run.service.name+"/"+c.name, func(t *testing.T) {
				requireGoExceptionCase(t, logs, spans, run.service, c)
			})
		}
	}

	for _, selection := range goExceptionSelections {
		t.Run(selection.service.name, func(t *testing.T) {
			for _, c := range goCasesNamed(cases, "fmt", "panic-string") {
				if (c.name == "fmt" && !selection.formattedErrors) || (c.name == "panic-string" && !selection.panics) {
					c.expected = nil
				}
				requireGoExceptionCase(t, logs, spans, selection.service, c)
			}
		})
	}
	t.Run("disabled service", func(t *testing.T) {
		assert.Empty(t, goLogsOfService(logs, goExceptionsDisabled))
	})
	t.Run("goexit-cleanup", func(t *testing.T) {
		testGoExceptionGoexitCleanup(t, compose)
	})
}

func testGoExceptionGoexitCleanup(t *testing.T, compose *docker.Compose) {
	namespace, err := compose.ExecOutput("default", "readlink", "/proc/1/ns/pid")
	require.NoError(t, err)
	namespace = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(namespace), "pid:["), "]")
	pids := obiTestToolValues(t, compose, "host-pid", namespace, "1")
	require.Len(t, pids, 1)
	var pid string
	for value := range pids {
		pid = strconv.FormatUint(value, 10)
	}
	keys := func(ct require.TestingT) map[uint64]bool {
		return obiTestToolValues(ct, compose, "go-map-keys", "ongoing_http_server_requests", pid)
	}
	before := keys(t)
	response, err := goExceptionsClient.Get(goExceptionsDefault.url + "/case/goexit/cleanup")
	require.NoError(t, err)
	t.Cleanup(func() { response.Body.Close() })
	require.Equal(t, http.StatusOK, response.StatusCode)
	active := keys(t)
	for key := range before {
		delete(active, key)
	}
	require.Len(t, active, 1, "the blocked handler must have a request-map entry")
	var goroutine uint64
	for key := range active {
		goroutine = key
	}
	t.Logf("request entry before Goexit: pid=%s goroutine=%#x", pid, goroutine)
	_, err = compose.ExecOutput("default", "touch", "/tmp/goexit-release")
	require.NoError(t, err)
	_, err = io.ReadAll(response.Body)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "Goexit closes the unfinished response")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.NotContains(ct, keys(ct), goroutine, "dead goroutine still owns a request")
	}, 5*time.Second, 100*time.Millisecond)
}

func requireGoExceptionCase(t *testing.T, logs []goExceptionLog, spans []goServerSpan,
	service goExceptionsService, c goExceptionCase,
) {
	span, ok := goSpanFor(spans, service, goCasePath(c.name, goCaseID(c.name)))
	require.True(t, ok, "no server span")
	if !c.anySpanStatus {
		assert.EqualValues(t, c.status, span.status)
	}

	// owned records carry the span's trace, the others only the request id
	var records []goExceptionLog
	for _, l := range goLogsOfService(logs, service) {
		if l.traceID == span.traceID || strings.Contains(l.message, ":"+goCaseID(c.name)) {
			records = append(records, l)
		}
	}
	if len(c.expected) == 0 {
		assert.Empty(t, records, "requests that raise nothing capture nothing")
		return
	}

	for _, record := range records {
		requireGoStack(t, record)
		assert.Equal(t, plog.SeverityNumberError, record.severity)
		if record.traceID != "" {
			assert.Equal(t, span.traceID, record.traceID, "record %+v", record)
			assert.Equal(t, span.processingSpanID, record.spanID, "record %+v", record)
		}
	}
	for _, want := range c.expected {
		assert.True(t, goContainsException(records, want), "missing %+v in %+v", want, records)
	}
}

// requireGoStack checks the runtime.Stack layout: an optional "panic: msg"
// header and blank line, then "func(...)" / "\tfile:line" pairs, starting at
// the fixture function that raised the record.
func requireGoStack(t *testing.T, record goExceptionLog) {
	t.Helper()
	stack := record.stack
	if record.typ == "go.panic" {
		header, frames, ok := strings.Cut(stack, "\n\n")
		require.True(t, ok, "panic header and frames: %q", stack)
		require.Equal(t, strings.TrimRight("panic: "+record.message, " "), header)
		stack = frames
	}
	require.NotContains(t, stack, "runtime.goexit", "unexported runtime frames are hidden")
	require.NotContains(t, stack, "frames omitted", "the fixture's stacks are shorter than the capture limit")

	lines := strings.Split(stack, "\n")
	require.Zero(t, len(lines)%2, "function and location pairs: %q", stack)
	for i := 0; i < len(lines); i += 2 {
		require.Regexp(t, `^\S+\(\.\.\.\)$`, lines[i], "stack %q", stack)
		require.Regexp(t, `^\t\S+:\d+$`, lines[i+1], "stack %q", stack)
	}

	// error constructors and runtime frames above the application are dropped
	require.Regexp(t, `^main\.\S+\(\.\.\.\)$`, lines[0], "stack %q", stack)
	// A leaf method without a frame keeps no frame pointer, so the frame
	// pointer walk from its fault skips its caller
	if lines[0] != "main.(*store).Name(...)" {
		require.Contains(t, stack, "main.serveCase")
	}
}

func goContainsException(records []goExceptionLog, want goExpectedException) bool {
	for _, record := range records {
		if record.typ == want.typ && strings.HasPrefix(record.message, want.messagePrefix) &&
			(record.traceID != "") == want.owned {
			return true
		}
	}
	return false
}

func goCasePath(name, id string) string { return "/case/" + name + "/" + id }

func goCasesNamed(cases []goExceptionCase, names ...string) []goExceptionCase {
	var named []goExceptionCase
	for _, c := range cases {
		if slices.Contains(names, c.name) {
			named = append(named, c)
		}
	}
	return named
}

// goCaseID is the request id of a case: the fixture puts it in the message
// after a colon, and no id is the prefix of another.
func goCaseID(name string) string { return name + "-id" }

func goExceptionsGet(t require.TestingT, service goExceptionsService, name, id string, status int) {
	response, err := goExceptionsClient.Get(service.url + goCasePath(name, id))
	if status == 0 {
		require.Error(t, err, "net/http recovery closes the connection without a response")
		return
	}
	require.NoError(t, err)
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	require.Equal(t, status, response.StatusCode)
}

func goSpanFor(spans []goServerSpan, service goExceptionsService, urlPath string) (goServerSpan, bool) {
	for _, s := range spans {
		if s.service == service.name && s.path == urlPath {
			return s, true
		}
	}
	return goServerSpan{}, false
}

func goHasSpanOfService(spans []goServerSpan, service goExceptionsService) bool {
	for _, s := range spans {
		if s.service == service.name {
			return true
		}
	}
	return false
}

func goLogsOfService(logs []goExceptionLog, service goExceptionsService) []goExceptionLog {
	var out []goExceptionLog
	for _, l := range logs {
		if l.service == service.name {
			out = append(out, l)
		}
	}
	return out
}

// readGoExceptionTelemetry reads the exception log records and server spans
// that the collector wrote.
func readGoExceptionTelemetry(t require.TestingT, out string) ([]goExceptionLog, []goServerSpan) {
	var logs []goExceptionLog
	var logsUnmarshaler plog.JSONUnmarshaler
	for _, line := range goJSONLines(t, path.Join(out, "logs.jsonl")) {
		batch, err := logsUnmarshaler.UnmarshalLogs(line)
		require.NoError(t, err)
		for _, rl := range batch.ResourceLogs().All() {
			service := goAttr(rl.Resource().Attributes().Get("service.name"))
			for _, sl := range rl.ScopeLogs().All() {
				for _, record := range sl.LogRecords().All() {
					if record.EventName() != "exception" {
						continue
					}
					l := goExceptionLog{
						service:  service,
						typ:      goAttr(record.Attributes().Get("exception.type")),
						message:  goAttr(record.Attributes().Get("exception.message")),
						stack:    goAttr(record.Attributes().Get("exception.stacktrace")),
						severity: record.SeverityNumber(),
					}
					if !record.TraceID().IsEmpty() {
						l.traceID = record.TraceID().String()
						l.spanID = record.SpanID().String()
					}
					logs = append(logs, l)
				}
			}
		}
	}

	var spans []goServerSpan
	processing := map[string]string{} // server span ID -> processing span ID
	var tracesUnmarshaler ptrace.JSONUnmarshaler
	for _, line := range goJSONLines(t, path.Join(out, "traces.jsonl")) {
		batch, err := tracesUnmarshaler.UnmarshalTraces(line)
		require.NoError(t, err)
		for _, rs := range batch.ResourceSpans().All() {
			service := goAttr(rs.Resource().Attributes().Get("service.name"))
			for _, ss := range rs.ScopeSpans().All() {
				for _, span := range ss.Spans().All() {
					if span.Name() == "processing" {
						processing[span.ParentSpanID().String()] = span.SpanID().String()
					}
					if span.Kind() != ptrace.SpanKindServer {
						continue
					}
					s := goServerSpan{
						service: service,
						path:    goAttr(span.Attributes().Get("url.path")),
						traceID: span.TraceID().String(),
						spanID:  span.SpanID().String(),
					}
					if status, ok := span.Attributes().Get("http.response.status_code"); ok {
						s.status = status.Int()
					}
					spans = append(spans, s)
				}
			}
		}
	}
	for i := range spans {
		spans[i].processingSpanID = spans[i].spanID
		if id, ok := processing[spans[i].spanID]; ok {
			spans[i].processingSpanID = id
		}
	}
	return logs, spans
}

func goJSONLines(t require.TestingT, file string) [][]byte {
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	return bytes.Split(data, []byte("\n"))
}

func goAttr(value pcommon.Value, ok bool) string {
	if !ok {
		return ""
	}
	return value.AsString()
}
