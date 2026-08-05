// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package std // import "go.opentelemetry.io/obi/internal/test/integration/components/testserver/std"

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/auto/sdk"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/internal/test/integration/components/testserver/arg"
	pb "go.opentelemetry.io/obi/internal/test/integration/components/testserver/grpc/routeguide"
)

var y2k = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

var tracer = otel.Tracer("trace-example")

const (
	autoSDKRootSampledHeader        = "X-OBI-Auto-SDK-Root-Sampled"
	autoSDKRootRecordingHeader      = "X-OBI-Auto-SDK-Root-Recording"
	autoSDKRemoteSampledHeader      = "X-OBI-Auto-SDK-Remote-Sampled"
	autoSDKRemoteRecordingHeader    = "X-OBI-Auto-SDK-Remote-Recording"
	autoSDKRemoteNotSampledHeader   = "X-OBI-Auto-SDK-Remote-Not-Sampled"
	autoSDKRemoteNotRecordingHeader = "X-OBI-Auto-SDK-Remote-Not-Recording"
)

type autoSDKSamplingState struct {
	remoteSampled      bool
	remoteRecording    bool
	remoteNotSampled   bool
	remoteNotRecording bool
}

func HTTPHandler(log *slog.Logger, echoPort int) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Info("received request", "url", req.RequestURI)

		if req.RequestURI == "/echo" {
			echoAsync(rw, echoPort)
			return
		}

		if req.RequestURI == "/delay" {
			echoDelay(rw, echoPort)
			return
		}

		if req.RequestURI == "/gotracemetoo" {
			echoDist(rw)
			return
		}

		if req.RequestURI == "/echoCall" {
			echoCall(rw)
			return
		}

		if req.RequestURI == "/echoLowPort" {
			echoLowPort(rw)
			return
		}

		if req.RequestURI == "/manual" {
			manual(rw)
			return
		}

		if req.RequestURI == "/auto-sdk-sampling" {
			autoSDKSampling(rw, echoPort)
			return
		}

		status := arg.DefaultStatus
		for k, v := range req.URL.Query() {
			if len(v) == 0 {
				continue
			}
			switch k {
			case arg.Status:
				if s, err := strconv.Atoi(v[0]); err != nil {
					log.Debug("wrong status value. Ignoring", "error", err)
				} else {
					status = s
				}
			case arg.Delay:
				if d, err := time.ParseDuration(v[0]); err != nil {
					log.Debug("wrong delay value. Ignoring", "error", err)
				} else {
					time.Sleep(d)
				}
			}
		}
		rw.WriteHeader(status)
	}
}

func echoAsync(rw http.ResponseWriter, port int) {
	duration, err := time.ParseDuration("10s")
	if err != nil {
		slog.Error("can't parse duration", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	results := make(chan any)

	go func() {
		echo(rw, port)
		results <- rw
	}()

	for {
		select {
		case <-results:
			return
		case <-ctx.Done():
			slog.Warn("timeout while waiting for test to complete")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func echoDelay(rw http.ResponseWriter, port int) {
	time.Sleep(200 * time.Millisecond)
	echo(rw, port)
}

func echo(rw http.ResponseWriter, port int) {
	requestURL := "http://localhost:" + strconv.Itoa(port) + "/echoBack?delay=20ms&status=203"

	slog.Debug("calling", "url", requestURL)

	res, err := http.Get(requestURL)
	if err != nil {
		slog.Error("error making http request", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

func inner(id int) {
	ctx := context.Background()
	ts := y2k.Add(10 * time.Microsecond)

	t := tracer

	opts := []trace.SpanStartOption{
		trace.WithAttributes(
			attribute.String("user", "user"+strconv.Itoa(id)),
			attribute.Bool("admin", true),
		),
		trace.WithTimestamp(y2k.Add(500 * time.Microsecond)),
		trace.WithSpanKind(trace.SpanKindServer),
	}

	_, span := t.Start(ctx, fmt.Sprintf("sig_inner %d", id), opts...)
	defer span.End(trace.WithTimestamp(ts.Add(100 * time.Microsecond)))

	if id == 2 {
		span.SetName("changed name")
		span.SetAttributes(
			attribute.String("test", "append"),
		)
	}
}

func manualSpanLifecycle(ctx context.Context, echoPort int) error {
	parentCtx, parent := tracer.Start(ctx, "lifecycle parent")
	_, firstSibling := tracer.Start(parentCtx, "lifecycle sibling 1")
	_, secondSibling := tracer.Start(parentCtx, "lifecycle sibling 2")
	firstSibling.End()
	secondSibling.End()

	_, newRoot := tracer.Start(parentCtx, "lifecycle new root", trace.WithNewRoot())
	newRoot.End()

	requestURL := "http://localhost:" + strconv.Itoa(echoPort) + "/echoBack?status=204"
	res, err := http.Get(requestURL)
	if err != nil {
		parent.End()
		return err
	}
	res.Body.Close()

	parent.End()

	_, afterEnd := tracer.Start(parentCtx, "lifecycle context after end")
	afterEnd.End()
	return nil
}

func manualAutoSDKSampling(t trace.Tracer, echoPort int) autoSDKSamplingState {
	var samplingState autoSDKSamplingState
	startTime := time.Now()
	oversizedAttrs := make([]attribute.KeyValue, 0, 18)
	for i := 0; i < 16; i++ {
		oversizedAttrs = append(
			oversizedAttrs,
			attribute.String("test.filler."+strconv.Itoa(i), "value"),
		)
	}
	oversizedAttrs = append(
		oversizedAttrs,
		attribute.String("http.route", "/auto-sdk-oversized"),
		attribute.String("oversized.payload", strings.Repeat("x", 18*1024)),
	)
	_, oversized := t.Start(
		context.Background(),
		"auto-sdk-oversized-span",
		trace.WithTimestamp(startTime),
		trace.WithTimestamp(startTime),
		trace.WithTimestamp(startTime),
		trace.WithTimestamp(startTime),
		trace.WithTimestamp(startTime),
		trace.WithAttributes(oversizedAttrs...),
	)
	oversized.End()

	tooManyOptions := make([]trace.SpanStartOption, 17)
	for i := range tooManyOptions {
		tooManyOptions[i] = trace.WithTimestamp(startTime)
	}
	_, unsupportedOptions := t.Start(
		context.Background(),
		"auto-sdk-too-many-options",
		tooManyOptions...,
	)
	unsupportedOptions.End()

	type contextKey int
	deepContext := context.Background()
	for i := 0; i < 18; i++ {
		deepContext = context.WithValue(deepContext, contextKey(i), i)
	}
	_, deepContextSpan := t.Start(deepContext, "auto-sdk-deep-context")
	deepContextSpan.End()

	_, renamed := t.Start(context.Background(), "auto-sdk-name-before-update")
	renamed.SetName("auto-sdk-renamed")
	renamed.End()

	serviceGraphOptions := make([]trace.SpanStartOption, 30, 32)
	for i := range serviceGraphOptions {
		serviceGraphOptions[i] = trace.WithTimestamp(startTime)
	}
	serviceGraphOptions = append(
		serviceGraphOptions,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("server.address.extra", strings.Repeat("x", 18*1024)),
			attribute.String("server.address", "manual-remote"),
			attribute.String("service.peer.name", "manual-remote"),
		),
	)
	_, serviceGraphClient := t.Start(
		context.Background(),
		"auto-sdk-service-graph-client",
		serviceGraphOptions...,
	)
	serviceGraphClient.End()

	maxOptions := make([]trace.SpanStartOption, 126, 128)
	fillerOption := trace.WithAttributes(attribute.String("test.filler", "value"))
	for i := range maxOptions {
		maxOptions[i] = fillerOption
	}
	maxOptions = append(
		maxOptions,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("server.address", "manual-remote-max"),
			attribute.String("service.peer.name", "manual-remote-max"),
			attribute.String("http.route", "/auto-sdk-max-options"),
		),
	)
	_, maxOptionsClient := t.Start(
		context.Background(),
		"auto-sdk-max-options-client",
		maxOptions...,
	)
	maxOptionsClient.End()

	_, setAttributesClient := t.Start(
		context.Background(),
		"auto-sdk-set-attributes-client",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(oversizedAttrs[:16]...),
	)
	setAttributesClient.SetAttributes(
		attribute.String("server.address", "manual-remote-set"),
		attribute.String("service.peer.name", "manual-remote-set"),
	)
	setAttributesClient.End()

	_, lastOptions := t.Start(
		context.Background(),
		"auto-sdk-last-options",
		trace.WithTimestamp(y2k),
		trace.WithTimestamp(time.Time{}),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithSpanKind(trace.SpanKindUnspecified),
	)
	lastOptions.End(
		trace.WithTimestamp(y2k.Add(time.Second)),
		trace.WithTimestamp(time.Time{}),
	)

	unsampledParent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		},
		SpanID: trace.SpanID{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38},
	})
	unsampledCtx := trace.ContextWithRemoteSpanContext(context.Background(), unsampledParent)
	_, unsampledChild := t.Start(unsampledCtx, "auto-sdk-remote-unsampled-child")
	samplingState.remoteNotSampled = unsampledChild.SpanContext().IsSampled()
	samplingState.remoteNotRecording = unsampledChild.IsRecording()
	unsampledChild.End()

	boundaryOptions := make([]trace.SpanStartOption, 127, 128)
	for i := range boundaryOptions {
		boundaryOptions[i] = fillerOption
	}
	boundaryOptions = append(boundaryOptions, trace.WithNewRoot())
	_, boundaryNewRoot := t.Start(
		unsampledCtx,
		"auto-sdk-option-boundary-new-root",
		boundaryOptions...,
	)
	boundaryNewRoot.End()

	overflowOptions := make([]trace.SpanStartOption, 128, 129)
	for i := range overflowOptions {
		overflowOptions[i] = fillerOption
	}
	overflowOptions = append(overflowOptions, trace.WithNewRoot())
	_, overflowNewRoot := t.Start(
		unsampledCtx,
		"auto-sdk-option-overflow-new-root",
		overflowOptions...,
	)
	failClosedChildURL := "http://localhost:" + strconv.Itoa(echoPort) +
		"/auto-sdk-fail-closed-child?status=204"
	if response, err := http.Get(failClosedChildURL); err != nil {
		slog.Error("error exercising fail-closed Auto SDK child", "error", err)
	} else {
		response.Body.Close()
	}
	overflowNewRoot.End()

	for i := 0; i <= 128; i++ {
		unsampledCtx = context.WithValue(unsampledCtx, contextKey(i), i)
	}
	_, deepUnsampledChild := t.Start(unsampledCtx, "auto-sdk-deep-remote-unsampled-child")
	deepUnsampledChild.End()

	sampledParent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		},
		SpanID:     trace.SpanID{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
		TraceFlags: trace.FlagsSampled,
	})
	sampledCtx := trace.ContextWithRemoteSpanContext(context.Background(), sampledParent)
	_, sampledChild := t.Start(sampledCtx, "auto-sdk-remote-sampled-child")
	samplingState.remoteSampled = sampledChild.SpanContext().IsSampled()
	samplingState.remoteRecording = sampledChild.IsRecording()
	sampledChild.End()

	boundarySampledCtx := sampledCtx
	for i := 0; i < 127; i++ {
		boundarySampledCtx = context.WithValue(boundarySampledCtx, contextKey(i), i)
	}
	_, boundarySampledChild := t.Start(
		boundarySampledCtx,
		"auto-sdk-context-boundary-sampled-child",
	)
	boundarySampledChild.End()

	overflowSampledCtx := sampledCtx
	for i := 0; i < 128; i++ {
		overflowSampledCtx = context.WithValue(overflowSampledCtx, contextKey(i), i)
	}
	_, overflowSampledChild := t.Start(
		overflowSampledCtx,
		"auto-sdk-context-overflow-sampled-child",
	)
	overflowSampledChild.End()

	return samplingState
}

func autoSDKSampling(rw http.ResponseWriter, echoPort int) {
	slog.Debug("Auto SDK sampling spans")

	provider := sdk.TracerProvider()
	t := provider.Tracer(
		"sampling",
		trace.WithInstrumentationVersion("v0.0.1"),
		trace.WithSchemaURL("https://some_schema"),
	)
	ts := y2k.Add(10 * time.Microsecond)
	_, root := t.Start(
		context.Background(),
		"auto-sdk-sampling-root",
		trace.WithTimestamp(ts),
		trace.WithSpanKind(trace.SpanKindClient),
	)
	rootSampled := root.SpanContext().IsSampled()
	rootRecording := root.IsRecording()
	root.SetStatus(codes.Error, "application error")
	root.End(trace.WithTimestamp(ts.Add(100 * time.Microsecond)))

	samplingState := manualAutoSDKSampling(t, echoPort)
	rw.Header().Set(autoSDKRootSampledHeader, strconv.FormatBool(rootSampled))
	rw.Header().Set(autoSDKRootRecordingHeader, strconv.FormatBool(rootRecording))
	rw.Header().Set(
		autoSDKRemoteSampledHeader,
		strconv.FormatBool(samplingState.remoteSampled),
	)
	rw.Header().Set(
		autoSDKRemoteRecordingHeader,
		strconv.FormatBool(samplingState.remoteRecording),
	)
	rw.Header().Set(
		autoSDKRemoteNotSampledHeader,
		strconv.FormatBool(samplingState.remoteNotSampled),
	)
	rw.Header().Set(
		autoSDKRemoteNotRecordingHeader,
		strconv.FormatBool(samplingState.remoteNotRecording),
	)
	if err := manualSpanLifecycle(context.Background(), echoPort); err != nil {
		slog.Error("error exercising manual span lifecycle", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
}

func manual(rw http.ResponseWriter) {
	slog.Debug("manual spans")

	ctx := context.Background()
	ts := y2k.Add(10 * time.Microsecond)

	provider := sdk.TracerProvider()
	t := provider.Tracer(
		"main",
		trace.WithInstrumentationVersion("v0.0.1"),
		trace.WithSchemaURL("https://some_schema"),
	)

	_, span := t.Start(ctx, "sig", trace.WithTimestamp(ts))
	defer span.End(trace.WithTimestamp(ts.Add(100 * time.Microsecond)))

	inner(1)
	inner(2)

	span.SetStatus(codes.Error, "application error")
	span.RecordError(
		errors.New("some unknown error"),
		trace.WithTimestamp(y2k.Add(2*time.Second)),
		trace.WithStackTrace(true),
		trace.WithAttributes(attribute.Int("impact", 11)),
	)

	rw.WriteHeader(http.StatusOK)
}

var (
	addrLowPort = net.TCPAddr{Port: 7000}
	transport   = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			LocalAddr: &addrLowPort,
		}).DialContext,
	}
)
var httpClient = &http.Client{Transport: transport}

func echoLowPort(rw http.ResponseWriter) {
	requestURL := os.Getenv("TARGET_URL")

	slog.Debug("calling", "url", requestURL)

	res, err := httpClient.Get(requestURL)
	if err != nil {
		slog.Error("error making http request", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

func echoDist(rw http.ResponseWriter) {
	var requestURL string

	// Check if we should bypass the JSON-RPC hop for IP-only testing
	if os.Getenv("BYPASS_JSONRPC") == "true" {
		// Direct call to pytestserver - avoids loopback, enables IP option injection
		requestURL = "http://pytestserver:7773/tracemetoo"
		slog.Debug("bypassing JSON-RPC, calling directly", "url", requestURL)

		res, err := http.Get(requestURL)
		if err != nil {
			slog.Error("error making http request", "error", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()
		rw.WriteHeader(res.StatusCode)
	} else {
		// Normal flow: call JSON-RPC which then calls pytestserver
		requestURL = "http://testserver:8088/jsonrpc"
		slog.Debug("calling", "url", requestURL)

		res, err := http.Post(requestURL, "application/json", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"Arith.Traceme","params":[{"A":1,"B":2}],"id":1}`)))
		if err != nil {
			slog.Error("error making http request", "error", err)
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()
		rw.WriteHeader(res.StatusCode)
	}
}

func echoCall(rw http.ResponseWriter) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient("localhost:5051", opts...)
	if err != nil {
		slog.Error("fail to dial", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)

	point := &pb.Point{Latitude: 409146138, Longitude: -746188906}

	slog.Debug("Getting feature for point", "lat", point.Latitude, "long", point.Longitude)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.GetFeature(ctx, point)
	if err != nil {
		slog.Error("client.GetFeature failed", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

var rd = rand.New(rand.NewPCG(uint64(time.Now().Unix()), 0))

func rolldice(w http.ResponseWriter, r *http.Request) {
	// Print all headers
	for name, values := range r.Header {
		// Loop over all values for the name.
		for _, value := range values {
			fmt.Printf("%s: %s\n", name, value)
		}
	}

	id := r.PathValue("id")

	n := rd.IntN(6) + 1

	// Add response headers
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Dice-Roll", strconv.Itoa(n))

	slog.Info("rolldice called", "id", id, "dice", n)
	time.Sleep(200 * time.Millisecond)

	fmt.Fprintf(w, "%v", n)
}

// rolldicePost handles POST /rolldice/{id} and returns a JSON response body so
// that HTTP response-body extraction has non-empty JSON content to capture.
func rolldicePost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	n := rd.IntN(6) + 1

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Dice-Roll", strconv.Itoa(n))

	slog.Info("rolldice POST called", "id", id, "dice", n)

	fmt.Fprintf(w, `{"result":%d}`, n)
}

func Setup(port int) {
	log := slog.With("component", "std.Server")
	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /rolldice/{id}", rolldice)
	mux.HandleFunc("POST /rolldice/{id}", rolldicePost)
	mux.HandleFunc("/", HTTPHandler(log, port))

	err := http.ListenAndServe(address, mux)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}

func SetupTLS(port int) {
	log := slog.With("component", "std.Server")
	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTPS server", "address", address)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /rolldice/{id}", rolldice)
	mux.HandleFunc("POST /rolldice/{id}", rolldicePost)
	mux.HandleFunc("/", HTTPHandler(log, port))

	err := http.ListenAndServeTLS(address, "x509/server_test_cert.pem", "x509/server_test_key.pem", mux)
	log.Error("HTTPS server has unexpectedly stopped", "error", err)
}
