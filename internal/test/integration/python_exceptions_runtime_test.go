// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && python_exceptions_integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"go.opentelemetry.io/obi/pkg/exceptions"
)

var pythonExceptionFrameLine = regexp.MustCompile(`^  (File "(.*)", line (\d+), in (.*)|\[Previous line repeated \d+ more times?\])$`)

// Exceptions that escape a Flask, FastAPI or http.server handler are compared
// with what CPython recorded in the fixture, request by request.
func TestPythonExceptions(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "Python exception integration tests require root")
	require.NoError(t, rlimit.RemoveMemlock())
	unsupported := os.Getenv("PYTHON_EXCEPTION_BUILD") == "free-threaded"

	modes := map[string][]string{"flask": {"sync"}, "fastapi": {"await", "task", "thread", "sync"}, "http": {"sync"}}
	cases := []string{
		"ascii", "empty", "unicode", "long", "key", "os", "custom", "multiarg",
		"native", "deep", "reraise", "raise_error", "latest", "chained",
	}
	if pythonMinor(t) >= 11 {
		cases = append(cases, "group")
	}
	for i, framework := range []string{"flask", "fastapi", "http"} {
		t.Run(framework, func(t *testing.T) {
			if reason := os.Getenv("PYTHON_EXCEPTION_ASYNC_SKIP_REASON"); framework == "fastapi" && reason != "" {
				t.Skip(reason)
			}
			port := 18700 + i
			startPythonExceptionFixture(t, framework, port)
			harness := startPythonExceptionTracer(t, port)
			fixture := pythonExceptionClient{t: t, port: port}

			if unsupported {
				traceID := fixture.get("/raise/sync/ascii/unsupported", http.StatusInternalServerError)
				harness.requireNone(t, traceID)
				require.False(t, harness.attached(), "unsupported builds must not attach")
				return
			}
			require.True(t, harness.attached(), "the exception probe did not attach")

			for _, mode := range modes[framework] {
				for _, name := range cases {
					t.Run(mode+"/"+name, func(t *testing.T) {
						token := fmt.Sprintf("%s-%s-%s", framework, mode, name)
						traceID := fixture.get("/raise/"+mode+"/"+name+"/"+token, http.StatusInternalServerError)
						assertPythonException(t, harness.wait(t, traceID), fixture.truth(token), name)
					})
				}
			}

			if framework == "http" {
				t.Run("direct/native", func(t *testing.T) {
					const token = "http-direct-native"
					traceID := fixture.get("/raise/direct/native/"+token, http.StatusInternalServerError)
					assertPythonException(t, harness.wait(t, traceID), fixture.truth(token), "native")
				})
			}

			// A handler that catches the exception and answers 500 itself reports
			// nothing.
			t.Run("handled-500", func(t *testing.T) {
				harness.requireNone(t, fixture.get("/handled/sync/ascii/"+framework+"-handled-500/500", http.StatusInternalServerError))
			})
			t.Run("handled-200", func(t *testing.T) {
				harness.requireNone(t, fixture.get("/handled/sync/ascii/"+framework+"-handled-200/200", http.StatusOK))
			})
			t.Run("healthy", func(t *testing.T) {
				harness.requireNone(t, fixture.get("/ok", http.StatusOK))
			})
			if framework == "flask" {
				t.Run("stop-iteration", func(t *testing.T) {
					harness.requireNone(t, fixture.get("/raise/sync/stop/flask-stop", http.StatusInternalServerError))
				})
			}
			t.Run("concurrent", func(t *testing.T) {
				const requests = 16
				mode := modes[framework][0]
				traces := make([]string, requests)
				var wg sync.WaitGroup
				for n := range requests {
					wg.Go(func() {
						traces[n] = fixture.get(fmt.Sprintf("/raise/%s/ascii/%s-concurrent-%d", mode, framework, n), http.StatusInternalServerError)
					})
				}
				wg.Wait()
				for n, traceID := range traces {
					event := harness.wait(t, traceID)
					assert.Equal(t, fmt.Sprintf("%s-concurrent-%d", framework, n), event.Message)
				}
			})
		})
	}
}

type pythonExceptionTruth struct {
	Type     string `json:"type"`
	LineType string `json:"line_type"`
	Message  string `json:"message"`
	Frames   []struct {
		File     string `json:"file"`
		Line     int    `json:"line"`
		Function string `json:"function"`
	} `json:"frames"`
}

type pythonExceptionClient struct {
	t        *testing.T
	port     int
	sequence atomic.Uint64
}

// get sends a request with a known trace ID and returns it.
func (c *pythonExceptionClient) get(path string, status int) string {
	c.t.Helper()
	sequence := c.sequence.Add(1)
	traceID := fmt.Sprintf("%016x%016x", time.Now().UnixNano(), sequence)
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", c.port, path), nil)
	require.NoError(c.t, err)
	request.Header.Set("Traceparent", "00-"+traceID+"-1234567890abcdef-01")
	response, err := http.DefaultClient.Do(request)
	require.NoError(c.t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	require.Equal(c.t, status, response.StatusCode, path)
	return traceID
}

func (c *pythonExceptionClient) truth(token string) pythonExceptionTruth {
	c.t.Helper()
	response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/truth/%s", c.port, token))
	require.NoError(c.t, err)
	defer response.Body.Close()
	truth := pythonExceptionTruth{}
	require.NoError(c.t, json.NewDecoder(response.Body).Decode(&truth))
	require.NotEmpty(c.t, truth.Type, "the fixture recorded no exception for %s", token)
	return truth
}

func assertPythonException(t *testing.T, event exceptions.Event, truth pythonExceptionTruth, scenario string) {
	t.Helper()
	assert.Equal(t, truth.Type, event.Type)
	assert.NotZero(t, event.SpanID)
	message := truth.Message
	if utf8.RuneCountInString(truth.Message)*utf8.UTFMax <= 256 {
		assert.Equal(t, truth.Message, event.Message)
	} else {
		message = event.Message
		assert.True(t, strings.HasSuffix(event.Message, "..."), "%q does not end in ...", event.Message)
		assert.True(t, strings.HasPrefix(truth.Message, strings.TrimSuffix(event.Message, "...")), "%q is not a prefix of the message", event.Message)
	}

	lines := strings.Split(strings.TrimSuffix(event.Stacktrace, "\n"), "\n")
	require.Equal(t, "Traceback (most recent call last):", lines[0])
	last := truth.LineType
	if message != "" {
		last += ": " + message
	}
	assert.Equal(t, last, lines[len(lines)-1])
	captured := lines[1 : len(lines)-1]
	// Outer frames beyond the 24 the probe keeps are dropped.
	if captured[0] == "  ... frames omitted" {
		captured = captured[1:]
	}
	var expected []string
	for _, frame := range truth.Frames {
		expected = append(expected, fmt.Sprintf("  File \"%s\", line %d, in %s", frame.File, frame.Line, frame.Function))
	}
	// `raise error` adds a frame for the re-raise; the capture keeps the first raise.
	if scenario == "raise_error" {
		expected = expected[len(expected)-4:]
	}
	expected = foldPythonFrames(expected)
	if scenario == "deep" {
		// The kept frames are all `recursive`, so their fold counts fewer repeats.
		expected, captured = expected[len(expected)-1:], captured[len(captured)-1:]
	}
	require.GreaterOrEqual(t, len(captured), len(expected), event.Stacktrace)
	assert.Equal(t, expected, captured[len(captured)-len(expected):], event.Stacktrace)
	for _, line := range captured {
		assert.Regexp(t, pythonExceptionFrameLine, line)
	}
}

// foldPythonFrames folds frames repeated more than three times in a row, as
// traceback does.
func foldPythonFrames(frames []string) []string {
	var folded []string
	flush := func(count int) {
		if count > 3 {
			plural := "s"
			if count-3 == 1 {
				plural = ""
			}
			folded = append(folded, fmt.Sprintf("  [Previous line repeated %d more time%s]", count-3, plural))
		}
	}
	count := 0
	for i, frame := range frames {
		if i > 0 && frame != frames[i-1] {
			flush(count)
			count = 0
		}
		count++
		if count <= 3 {
			folded = append(folded, frame)
		}
	}
	flush(count)
	return folded
}

type pythonExceptionHarness struct {
	logPath string
	mu      *sync.Mutex
	events  *[]exceptions.Event
}

func (h pythonExceptionHarness) find(traceID string) (exceptions.Event, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, event := range *h.events {
		if event.TraceID.String() == traceID {
			return event, true
		}
	}
	return exceptions.Event{}, false
}

func (h pythonExceptionHarness) wait(t *testing.T, traceID string) exceptions.Event {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if event, found := h.find(traceID); found {
			return event
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var captured strings.Builder
	for _, event := range *h.events {
		fmt.Fprintf(&captured, "\n  %s %s: %s %q", event.TraceID, event.SpanID, event.Type, event.Message)
	}
	require.FailNow(t, "no matching exception", "captured:%s", captured.String())
	return exceptions.Event{}
}

func (h pythonExceptionHarness) requireNone(t *testing.T, traceID string) {
	t.Helper()
	time.Sleep(time.Second)
	event, found := h.find(traceID)
	require.False(t, found, "unexpected exception %+v", event)
}

func (h pythonExceptionHarness) attached() bool {
	data, _ := os.ReadFile(h.logPath)
	return strings.Contains(string(data), "Python exception capture attached")
}

func pythonMinor(t *testing.T) int {
	t.Helper()
	output, err := osexec.Command("python3", "-c", "import sys; print(sys.version_info.minor)").Output()
	require.NoError(t, err)
	minor, err := strconv.Atoi(strings.TrimSpace(string(output)))
	require.NoError(t, err)
	return minor
}

func startPythonExceptionFixture(t *testing.T, framework string, port int) {
	t.Helper()
	fixture := os.Getenv("PYTHON_EXCEPTION_FIXTURE")
	require.NotEmpty(t, fixture, "PYTHON_EXCEPTION_FIXTURE must name server.py")
	logFile, err := os.Create(filepath.Join(t.TempDir(), "python.log"))
	require.NoError(t, err)
	cmd := osexec.Command("python3", "-u", fixture, framework, strconv.Itoa(port))
	cmd.Stdout, cmd.Stderr = logFile, logFile
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			output, _ := os.ReadFile(logFile.Name())
			t.Logf("Python fixture log:\n%s", output)
		}
	})
	// No keep-alive: a connection accepted before the tracer attached has no
	// request state for its first request.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	require.Eventually(t, func() bool {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		return response.StatusCode == http.StatusOK
	}, 20*time.Second, 100*time.Millisecond)
}

func startPythonExceptionTracer(t *testing.T, port int) pythonExceptionHarness {
	t.Helper()
	var mu sync.Mutex
	var events []exceptions.Event
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/logs" {
			w.WriteHeader(http.StatusOK)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		batch := plogotlp.NewExportRequest()
		if err := batch.UnmarshalProto(data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, resource := range batch.Logs().ResourceLogs().All() {
			for _, scope := range resource.ScopeLogs().All() {
				for _, record := range scope.LogRecords().All() {
					if record.EventName() != "exception" {
						continue
					}
					typ, _ := record.Attributes().Get("exception.type")
					message, _ := record.Attributes().Get("exception.message")
					stack, _ := record.Attributes().Get("exception.stacktrace")
					events = append(events, exceptions.Event{Type: typ.Str(), Message: message.Str(), Stacktrace: stack.Str(), TraceID: [16]byte(record.TraceID()), SpanID: [8]byte(record.SpanID())})
				}
			}
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "obi.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	cmd := osexec.Command("/tmp/obi", "-config", "configs/obi-config-python-exceptions.yml")
	cmd.Env = append(os.Environ(),
		"PYTHON_EXCEPTION_OTLP_ENDPOINT="+receiver.URL,
		"PYTHON_EXCEPTION_PORT="+strconv.Itoa(port))
	cmd.Stdout, cmd.Stderr = logFile, logFile
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Logf("OBI log:\n%s", data)
		}
	})
	harness := pythonExceptionHarness{logPath: logPath, mu: &mu, events: &events}
	require.Eventually(t, func() bool {
		data, _ := os.ReadFile(logPath)
		return strings.Contains(string(data), "Python exception capture attached") || strings.Contains(string(data), "Python exception capture unavailable")
	}, 30*time.Second, 100*time.Millisecond, "OBI did not attach to fixture")
	return harness
}
