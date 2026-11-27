// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
)

const (
	traceMaxRequestBytes  = 64 * 1024 * 1024
	traceMaxResponseBytes = 4 * 1024 * 1024
	traceContentTypeProto = "application/x-protobuf"
	traceContentTypeJSON  = "application/json"
)

// The OTLP clients send the ExportTraceServiceRequest encoded straight from pdata,
// keeping the user agent of the otel-go exporters they replace.
var traceUserAgent = "OTel OTLP Exporter Go/" + otlptrace.Version()

type traceClient interface {
	UploadTraces(context.Context, ptrace.Traces) error
	Stop(context.Context) error
}

type traceRetry struct {
	initialInterval time.Duration
	maxInterval     time.Duration
	maxElapsedTime  time.Duration
}

// retryableTraceError marks a failed attempt that can be retried. A positive
// throttle is the delay the server asked for before the next attempt.
type retryableTraceError struct {
	err      error
	throttle time.Duration
}

func (e retryableTraceError) Error() string { return e.err.Error() }

func (e retryableTraceError) Unwrap() error { return e.err }

// do runs attempt until it succeeds, fails with an error that is not a
// retryableTraceError, or the retry budget is exhausted. A server-requested
// throttle is a lower bound on the wait, never a replacement for the backoff.
func (r traceRetry) do(ctx context.Context, attempt func(context.Context) error) error {
	policy := &backoff.ExponentialBackOff{
		InitialInterval:     r.initialInterval,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         r.maxInterval,
	}
	policy.Reset()
	start := time.Now()

	for {
		err := attempt(ctx)
		if err == nil {
			return nil
		}

		retryable, ok := errors.AsType[retryableTraceError](err)
		if !ok {
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w: %w", context.Cause(ctx), err)
		}

		elapsed := time.Since(start)
		if elapsed > r.maxElapsedTime {
			return fmt.Errorf("max retry time elapsed: %w", err)
		}
		if elapsed+retryable.throttle > r.maxElapsedTime {
			return fmt.Errorf("max retry time would elapse: %w", err)
		}

		delay := max(retryable.throttle, policy.NextBackOff())
		if waitErr := waitForRetry(ctx, delay); waitErr != nil {
			return fmt.Errorf("%w: %w", waitErr, err)
		}
	}
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func partialSuccessError(partialSuccess ptraceotlp.ExportPartialSuccess) error {
	rejected := partialSuccess.RejectedSpans()
	message := partialSuccess.ErrorMessage()
	if rejected == 0 && message == "" {
		return nil
	}
	if message == "" {
		message = "empty message"
	}
	return fmt.Errorf("OTLP partial success: %s (%d spans rejected)", message, rejected)
}

type grpcTraceClient struct {
	conn     *grpc.ClientConn
	client   ptraceotlp.GRPCClient
	metadata metadata.MD
	retry    traceRetry
}

func (c *grpcTraceClient) UploadTraces(ctx context.Context, traces ptrace.Traces) error {
	ctx, cancel := context.WithTimeout(ctx, c.retry.maxElapsedTime)
	defer cancel()
	if c.metadata.Len() > 0 {
		ctx = metadata.NewOutgoingContext(ctx, c.metadata)
	}

	// gRPC applies its own message size limit after compression, so the
	// uncompressed request is checked here, as for HTTP.
	if size := (&ptrace.ProtoMarshaler{}).TracesSize(traces); size > traceMaxRequestBytes {
		return fmt.Errorf("request message too large: exceeded %d bytes", traceMaxRequestBytes)
	}

	request := ptraceotlp.NewExportRequestFromTraces(traces)
	return c.retry.do(ctx, func(ctx context.Context) error {
		response, err := c.client.Export(ctx, request)
		if err != nil {
			return grpcRetryableError(err)
		}
		return partialSuccessError(response.PartialSuccess())
	})
}

func (c *grpcTraceClient) Stop(context.Context) error {
	return c.conn.Close()
}

func grpcRetryableError(err error) error {
	s := status.Convert(err)
	throttle, throttled := grpcRetryDelay(s)
	switch s.Code() {
	case codes.Canceled,
		codes.DeadlineExceeded,
		codes.Aborted,
		codes.OutOfRange,
		codes.Unavailable,
		codes.DataLoss:
		return retryableTraceError{err: err, throttle: throttle}
	case codes.ResourceExhausted:
		// The server signals a recoverable overload only by attaching a retry delay.
		if throttled {
			return retryableTraceError{err: err, throttle: throttle}
		}
	}
	return err
}

func grpcRetryDelay(s *status.Status) (time.Duration, bool) {
	for _, detail := range s.Details() {
		if info, ok := detail.(*errdetails.RetryInfo); ok {
			return info.RetryDelay.AsDuration(), true
		}
	}
	return 0, false
}

type httpTraceClient struct {
	client   *http.Client
	endpoint string
	headers  map[string]string
	json     bool
	gzip     bool
	retry    traceRetry
}

var traceGzipWriters = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

func (c *httpTraceClient) UploadTraces(ctx context.Context, traces ptrace.Traces) error {
	body, err := c.encode(traces)
	if err != nil {
		return err
	}
	return c.retry.do(ctx, func(ctx context.Context) error {
		return c.post(ctx, body)
	})
}

func (c *httpTraceClient) Stop(context.Context) error {
	c.client.CloseIdleConnections()
	return nil
}

func (c *httpTraceClient) encode(traces ptrace.Traces) ([]byte, error) {
	request := ptraceotlp.NewExportRequestFromTraces(traces)
	var body []byte
	var err error
	if c.json {
		body, err = request.MarshalJSON()
	} else {
		body, err = request.MarshalProto()
	}
	if err != nil {
		return nil, err
	}
	if len(body) > traceMaxRequestBytes {
		return nil, fmt.Errorf("request body too large: exceeded %d bytes", traceMaxRequestBytes)
	}
	if !c.gzip {
		return body, nil
	}
	return gzipBytes(body)
}

func gzipBytes(data []byte) ([]byte, error) {
	writer := traceGzipWriters.Get().(*gzip.Writer)
	defer func() {
		// Drop the reference to the compressed body before pooling the writer.
		writer.Reset(io.Discard)
		traceGzipWriters.Put(writer)
	}()

	var compressed bytes.Buffer
	writer.Reset(&compressed)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return compressed.Bytes(), nil
}

func (c *httpTraceClient) post(ctx context.Context, body []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setHeaders(request.Header)

	response, err := c.client.Do(request)
	if err != nil {
		return httpRetryableError(err)
	}
	defer response.Body.Close()

	data, err := readTraceResponse(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		return httpPartialSuccess(response.Header.Get("Content-Type"), data)
	}

	responseText := strings.TrimSpace(string(data))
	if responseText == "" {
		responseText = "(empty)"
	}
	bodyErr := fmt.Errorf("body: %s", responseText)
	switch response.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return retryableTraceError{err: bodyErr, throttle: retryAfter(response.Header.Get("Retry-After"))}
	}
	return fmt.Errorf("failed to send to %s: %s (%w)", c.endpoint, response.Status, bodyErr)
}

func (c *httpTraceClient) setHeaders(header http.Header) {
	header.Set("User-Agent", traceUserAgent)
	for key, value := range c.headers {
		header.Set(key, value)
	}
	if c.json {
		header.Set("Content-Type", traceContentTypeJSON)
	} else {
		header.Set("Content-Type", traceContentTypeProto)
	}
	if c.gzip {
		header.Set("Content-Encoding", "gzip")
	}
}

func httpRetryableError(err error) error {
	// Matches the otel-go exporter: only timeouts and transient network errors are retried.
	if urlErr, ok := errors.AsType[*url.Error](err); ok && urlErr.Temporary() {
		return retryableTraceError{err: err}
	}
	return err
}

func readTraceResponse(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, traceMaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > traceMaxResponseBytes {
		return nil, fmt.Errorf("response body too large: exceeded %d bytes", traceMaxResponseBytes)
	}
	return data, nil
}

func httpPartialSuccess(contentType string, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	response := ptraceotlp.NewExportResponse()
	var err error
	switch contentType {
	case traceContentTypeProto:
		err = response.UnmarshalProto(data)
	case traceContentTypeJSON:
		err = response.UnmarshalJSON(data)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	return partialSuccessError(response.PartialSuccess())
}

func retryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		const maxSeconds = int64(math.MaxInt64 / time.Second)
		return time.Duration(min(seconds, maxSeconds)) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return max(time.Until(date), 0)
	}
	return 0
}
