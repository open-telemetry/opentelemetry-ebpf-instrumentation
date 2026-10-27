// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/collector/pdata/pcommon"
	logdata "go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"go.opentelemetry.io/obi/pkg/exceptions"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

const (
	logsRequestTimeout  = 5 * time.Second
	logsRetryStart      = 5 * time.Second
	logsRetryMax        = 30 * time.Second
	logsRetryTotal      = 5 * time.Minute
	logsShutdownTimeout = 10 * time.Second
)

// logsSender delivers one batch of LogRecords.
type logsSender = otelcfg.LogsExportFunc

// ExceptionLogsReceiver exports exception observations independently of request spans.
func ExceptionLogsReceiver(info *global.ContextInfo, cfg otelcfg.LogsConfig, input *msg.Queue[[]exceptions.Event]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if input == nil || !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		send, closeSender, err := newLogsSender(cfg)
		if err != nil {
			return nil, err
		}
		subscription := input.Subscribe(msg.SubscriberName("otel.ExceptionLogsReceiver"))
		return func(ctx context.Context) {
			sendCtx, cancelSend := context.WithCancel(context.WithoutCancel(ctx))
			defer cancelSend()
			queue := make(chan exceptions.Event, cfg.QueueSize)
			done := make(chan struct{})
			go func() {
				defer close(done)
				batchExceptionLogs(sendCtx, info, cfg, queue, send)
			}()

			swarms.ForEachInput(ctx, subscription, slog.Debug, func(events []exceptions.Event) {
				enqueueExceptions(queue, events)
			})

			close(queue)
			select {
			case <-done:
			case <-time.After(logsShutdownTimeout):
				cancelSend()
				<-done
			}
			if err := closeSender(); err != nil {
				slog.Warn("exception logs shutdown failed", "error", err)
			}
		}, nil
	}
}

// enqueueExceptions never blocks: capture must not wait for the exporter.
func enqueueExceptions(queue chan<- exceptions.Event, events []exceptions.Event) {
	for i := range events {
		select {
		case queue <- events[i]:
		default:
			slog.Warn("exception logs queue is full, dropping records", "dropped", len(events)-i)
			return
		}
	}
}

func batchExceptionLogs(ctx context.Context, info *global.ContextInfo, cfg otelcfg.LogsConfig, queue <-chan exceptions.Event, send logsSender) {
	batch := make([]exceptions.Event, 0, cfg.BatchMaxSize)
	timer := time.NewTimer(cfg.BatchTimeout)
	timer.Stop()
	defer timer.Stop()

	flush := func() {
		timer.Stop()
		logs := exceptionLogs(info, batch)
		batch = batch[:0]
		if logs.LogRecordCount() == 0 {
			return
		}
		if err := send(ctx, logs); err != nil {
			slog.Warn("exception logs export failed", "error", err)
		}
	}

	for {
		select {
		case e, ok := <-queue:
			if !ok {
				flush()
				return
			}
			if len(batch) == 0 {
				timer.Reset(cfg.BatchTimeout)
			}
			batch = append(batch, e)
			if len(batch) == cfg.BatchMaxSize {
				flush()
			}
		case <-timer.C:
			flush()
		}
	}
}

func exceptionLogs(info *global.ContextInfo, events []exceptions.Event) logdata.Logs {
	logs := logdata.NewLogs()
	for i := range events {
		e := &events[i]
		if !e.Service.Exceptions.Enabled || !e.Service.ExportModes.CanExportLogs() || (e.Type == "" && e.Message == "") {
			continue
		}
		resource := logs.ResourceLogs().AppendEmpty()
		resource.SetSchemaUrl(attr.OBISchemaURL)
		attrs := otelcfg.GetAppResourceAttrs(&info.NodeMeta, &e.Service)
		attrs = append(attrs, otelcfg.ResourceAttrsFromEnv(&e.Service)...)
		attrs = append(attrs, info.ExtraResourceAttributes...)
		tracesgen.AttrsToMap(attrs).CopyTo(resource.Resource().Attributes())
		scope := resource.ScopeLogs().AppendEmpty()
		scope.Scope().SetName(reporterName)
		record := scope.LogRecords().AppendEmpty()
		record.SetEventName("exception")
		if !e.Timestamp.IsZero() {
			record.SetTimestamp(pcommon.NewTimestampFromTime(e.Timestamp))
		}
		observed := e.ObservedTimestamp
		if observed.IsZero() {
			observed = time.Now()
		}
		record.SetObservedTimestamp(pcommon.NewTimestampFromTime(observed))
		if e.SeverityNumber >= 1 && e.SeverityNumber <= 24 {
			severity := logdata.SeverityNumber(e.SeverityNumber)
			record.SetSeverityNumber(severity)
			record.SetSeverityText(strings.ToUpper(severity.String()))
		}
		// OBI discards its own spans for a process that exports traces itself
		// (tracesgen.SpanDiscarded), so its span context would link to nothing.
		if e.TraceID.IsValid() && !e.Service.ExportsOTelTraces() {
			record.SetTraceID(pcommon.TraceID(e.TraceID))
			record.SetFlags(logdata.LogRecordFlags(e.TraceFlags))
			if e.SpanID.IsValid() {
				record.SetSpanID(pcommon.SpanID(e.SpanID))
			}
		}
		if e.Type != "" {
			record.Attributes().PutStr("exception.type", e.Type)
		}
		if e.Message != "" {
			record.Attributes().PutStr("exception.message", e.Message)
		}
		if e.Stacktrace != "" {
			record.Attributes().PutStr("exception.stacktrace", e.Stacktrace)
		}
	}
	return logs
}

func newLogsSender(cfg otelcfg.LogsConfig) (logsSender, func() error, error) {
	if cfg.LogsExport != nil {
		return cfg.LogsExport, func() error { return nil }, nil
	}
	switch cfg.Protocol {
	case otelcfg.ProtocolDebug:
		return writeLogsJSON, func() error { return nil }, nil
	case otelcfg.ProtocolHTTPProtobuf, otelcfg.ProtocolHTTPJSON:
		send, client := newHTTPLogsSender(cfg)
		return send, func() error { client.CloseIdleConnections(); return nil }, nil
	case otelcfg.ProtocolGRPC:
		send, conn, err := newGRPCLogsSender(cfg)
		if err != nil {
			return nil, nil, err
		}
		return send, conn.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported logs protocol %q", cfg.Protocol)
	}
}

func writeLogsJSON(_ context.Context, logs logdata.Logs) error {
	data, err := (&logdata.JSONMarshaler{}).MarshalLogs(logs)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}

func newHTTPLogsSender(cfg otelcfg.LogsConfig) (logsSender, *http.Client) {
	endpoint := cfg.Endpoint
	client := &http.Client{}
	if addr, _ := cfg.UnixSocket(); addr != "" {
		endpoint = "http://localhost/v1/logs"
		client.Transport = otelcfg.UnixTransport(addr)
	}
	headers := cfg.Headers()
	contentType := "application/x-protobuf"
	if cfg.Protocol == otelcfg.ProtocolHTTPJSON {
		contentType = "application/json"
	}
	compress := cfg.Compression == "gzip"

	send := func(ctx context.Context, logs logdata.Logs) error {
		body, err := marshalLogsRequest(cfg.Protocol, logs, compress)
		if err != nil {
			return err
		}
		return retryLogsExport(ctx, func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
			if err != nil {
				return backoff.Permanent(err)
			}
			req.Header.Set("Content-Type", contentType)
			if compress {
				req.Header.Set("Content-Encoding", "gzip")
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			return httpLogsExportError(resp)
		})
	}
	return send, client
}

func marshalLogsRequest(protocol otelcfg.Protocol, logs logdata.Logs, compress bool) ([]byte, error) {
	req := plogotlp.NewExportRequestFromLogs(logs)
	var body []byte
	var err error
	if protocol == otelcfg.ProtocolHTTPJSON {
		body, err = req.MarshalJSON()
	} else {
		body, err = req.MarshalProto()
	}
	if err != nil || !compress {
		return body, err
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// httpLogsExportError retries the status codes that the OTLP specification marks as retryable.
func httpLogsExportError(resp *http.Response) error {
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	err := fmt.Errorf("logs export returned HTTP %d", resp.StatusCode)
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if seconds, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && seconds > 0 {
			return errors.Join(err, backoff.RetryAfter(seconds))
		}
		return err
	default:
		return backoff.Permanent(err)
	}
}

func newGRPCLogsSender(cfg otelcfg.LogsConfig) (logsSender, *grpc.ClientConn, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, nil, err
	}
	target := u.Host
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if u.Scheme == "http" {
		creds = insecure.NewCredentials()
	}
	if addr, unixTarget := cfg.UnixSocket(); addr != "" {
		target = unixTarget
		creds = insecure.NewCredentials()
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if cfg.Compression == "gzip" {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.UseCompressor(grpcgzip.Name)))
	}
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, nil, err
	}
	client := plogotlp.NewGRPCClient(conn)
	md := metadata.New(cfg.Headers())

	send := func(ctx context.Context, logs logdata.Logs) error {
		req := plogotlp.NewExportRequestFromLogs(logs)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return retryLogsExport(ctx, func(ctx context.Context) error {
			_, err := client.Export(ctx, req)
			return grpcLogsExportError(err)
		})
	}
	return send, conn, nil
}

// grpcLogsExportError retries the status codes that the OTLP specification marks as retryable.
func grpcLogsExportError(err error) error {
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.Canceled, codes.DeadlineExceeded, codes.Aborted, codes.OutOfRange, codes.Unavailable, codes.DataLoss:
		return err
	default:
		return backoff.Permanent(err)
	}
}

func retryLogsExport(ctx context.Context, attempt func(context.Context) error) error {
	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		attemptCtx, cancel := context.WithTimeout(ctx, logsRequestTimeout)
		defer cancel()
		return struct{}{}, attempt(attemptCtx)
	},
		backoff.WithBackOff(&backoff.ExponentialBackOff{
			InitialInterval:     logsRetryStart,
			RandomizationFactor: backoff.DefaultRandomizationFactor,
			Multiplier:          backoff.DefaultMultiplier,
			MaxInterval:         logsRetryMax,
		}),
		backoff.WithMaxElapsedTime(logsRetryTotal),
	)
	return err
}
